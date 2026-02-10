#!/usr/bin/env python3
import datetime
import json
import logging
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from typing import Optional

import vrnetlab
from scrapli.driver.core import IOSXEDriver

STARTUP_CONFIG_FILE = "/config/startup-config.cfg"


def handle_SIGCHLD(_signal, _frame):
    os.waitpid(-1, os.WNOHANG)


def handle_SIGTERM(_signal, _frame):
    sys.exit(0)


signal.signal(signal.SIGINT, handle_SIGTERM)
signal.signal(signal.SIGTERM, handle_SIGTERM)
signal.signal(signal.SIGCHLD, handle_SIGCHLD)

TRACE_LEVEL_NUM = 9
logging.addLevelName(TRACE_LEVEL_NUM, "TRACE")


def trace(self, message, *args, **kws):
    if self.isEnabledFor(TRACE_LEVEL_NUM):
        self._log(TRACE_LEVEL_NUM, message, args, **kws)


logging.Logger.trace = trace


class VIOS_vm(vrnetlab.VM):
    def __init__(self, hostname: str, username: str, password: str, conn_mode: str, device_type: str = None):
        self.logger = logging.getLogger()
        self.username = username
        self.password = password

        disk_image = None
        for e in os.listdir("/"):
            if re.search(".qcow2$", e):
                disk_image = "/" + e
        if not disk_image:
            raise Exception("No disk image found")

        if device_type is None:
            device_type = "switch" if re.search(r"(viosl2|vios_l2)", disk_image, re.IGNORECASE) else "router"
            self.logger.info(f"Auto-detected device type '{device_type}' from image: {disk_image}")

        match device_type:
            case "switch":
                ram = 768
                self.logger.info("Configuring switch with 768MB RAM")
            case "router":
                # IOSv can be unstable and have very slow crypto operations with too little RAM.
                ram = 1024
                self.logger.info("Configuring router with 1024MB RAM")
            case _:
                raise ValueError(f"Invalid device_type '{device_type}'. Must be 'router' or 'switch'")

        super(VIOS_vm, self).__init__(
            username=username,
            password=password,
            disk_image=disk_image,
            smp="1",
            ram=ram,
            driveif="virtio",
            use_scrapli=True,
        )

        self.hostname = hostname
        self.conn_mode = conn_mode
        self.device_type = device_type
        self.num_nics = 15
        self.running = False
        self.spins = 0

    def bootstrap_spin(self):
        if self.spins > 300:
            self.stop()
            self.start()
            return

        # IOSv/IOSvL2 sometimes land directly in privileged exec ("#") depending on
        # boot state / prior config. Accept both ">" and "#" prompts.
        device_prompt = rb"Switch[>#]" if self.device_type == "switch" else rb"Router[>#]"

        (ridx, match, res) = self.con_expect(
            [
                rb"Would you like to enter the initial configuration dialog\? \[yes/no\]:",
                # Some IOSv builds emit terminal control sequences around this line; match loosely.
                rb"Press[\s\S]*RETURN",
                device_prompt,
            ],
        )

        if match:
            if ridx == 0:
                self.logger.info("Skipping initial configuration dialog")
                self.wait_write("no", wait=None)
            elif ridx == 1:
                self.logger.info("Entering user EXEC mode")
                for _ in range(3):
                    # wait_write() appends "\r" itself; sending "\r" as cmd can result
                    # in doubled returns and occasionally misses the prompt.
                    self.wait_write("", wait=None)
            elif ridx == 2:
                self.apply_config()
                startup_time = datetime.datetime.now() - self.start_time
                self.logger.info(f"Startup complete in: {startup_time}")
                self.running = True
            return

        if res != b"":
            self.write_to_stdout(res)
            self.spins = 0

        self.spins += 1
        return

    def apply_config(self):
        scrapli_timeout = os.getenv("SCRAPLI_TIMEOUT", vrnetlab.DEFAULT_SCRAPLI_TIMEOUT)
        self.logger.info(
            f"Scrapli timeout is {scrapli_timeout}s (default {vrnetlab.DEFAULT_SCRAPLI_TIMEOUT}s)"
        )

        vios_scrapli_dev = {
            "host": "127.0.0.1",
            "auth_bypass": True,
            "auth_strict_key": False,
            "timeout_socket": scrapli_timeout,
            "timeout_transport": scrapli_timeout,
            "timeout_ops": scrapli_timeout,
        }

        con = IOSXEDriver(**vios_scrapli_dev)
        con.commandeer(conn=self.scrapli_tn)

        # VRNetlab QEMU user networking forwards host port 22 to 10.0.0.15:22 in the guest.
        # IOSvL2 is a switch and cannot assign an IP to Gi0/0; it must use an SVI (Vlan1).
        access_cfg = [
            # IOSv refuses RSA key generation until hostname is set to something other than the default "Router".
            f"hostname {self.hostname}",
            f"username {self.username} privilege 15 secret {self.password}",
            "ip domain-name lab",
        ]
        if self.device_type == "switch":
            access_cfg += [
                "interface GigabitEthernet0/0",
                "switchport access vlan 1",
                "no shutdown",
                "exit",
                "interface Vlan1",
                "ip address 10.0.0.15 255.255.255.0",
                "no shutdown",
                "exit",
            ]
        else:
            access_cfg += [
                "interface GigabitEthernet0/0",
                "ip address 10.0.0.15 255.255.255.0",
                "no shutdown",
                "exit",
            ]
        access_cfg += [
            "line vty 0 4",
            "login local",
            "transport input ssh",
            "exec-timeout 0 0",
            "exit",
        ]

        cfg_lines = []
        if os.path.exists(STARTUP_CONFIG_FILE):
            with open(STARTUP_CONFIG_FILE, "r") as config:
                cfg_lines = config.readlines()
        else:
            self.logger.warning(
                "Startup config %s not found; continuing with baseline SSH config only",
                STARTUP_CONFIG_FILE,
            )

        res = con.send_configs(cfg_lines + [l + "\n" for l in access_cfg])

        try:
            def ssh_banner_ready(timeout_sec: float = 1.0) -> bool:
                # The only thing we ultimately care about (for Skyforge readiness) is that the
                # guest-side SSH server produces a banner via the QEMU hostfwd path.
                #
                # When the guest SSH server is not listening, QEMU will often accept and then
                # immediately close the connection, producing EOF (no banner).
                s = None
                try:
                    s = socket.create_connection(("127.0.0.1", 22), timeout=timeout_sec)
                    s.settimeout(timeout_sec)
                    b = s.recv(4)
                    return b == b"SSH-"
                except Exception:
                    return False
                finally:
                    try:
                        if s is not None:
                            s.close()
                    except Exception:
                        pass

            def ssh_is_enabled() -> bool:
                r = con.send_command("show ip ssh")
                return "SSH Enabled" in (r.result or "")

            # Prefer checking whether SSH is enabled. Some IOSv builds return odd/no output from
            # key inspection commands even when key material exists (and vice versa).
            has_ssh = ssh_banner_ready()
            if not has_ssh:
                modulus = int(os.getenv("RSA_KEY_MODULUS", "1024"))
                self.logger.info("SSH not enabled; generating RSA keys (modulus %d)", modulus)

                # "crypto key generate rsa" is an exec-mode command on IOSv/IOSvL2.
                # We must not run it via send_configs() (config-mode), otherwise it can error out
                # and SSH will never come up.
                try:
                    _ = con.send_command("end")
                except Exception:
                    pass

                try:
                    def _invalid(out: str) -> bool:
                        return "invalid input" in (out or "").lower()

                    def _flatten(resps) -> str:
                        if resps is None:
                            return ""
                        if isinstance(resps, list):
                            return "\n".join([(r.result or "") for r in resps if r is not None])
                        # scrapli Response
                        return getattr(resps, "result", "") or ""

                    # IOS/IOSv keygen syntax varies. Prefer the non-interactive "general-keys modulus"
                    # form, which many IOSv images accept, and only fall back to interactive keygen
                    # if needed.
                    inline_ok = False

                    # Attempt 1: config-mode general-keys modulus (non-interactive when supported).
                    try:
                        resp = con.send_configs([f"crypto key generate rsa general-keys modulus {modulus}\n"])
                        out = _flatten(resp).strip().replace("\r", "")
                        if out:
                            self.logger.info("RSA keygen output (config general-keys): %s", out.replace("\n", " | ")[:500])
                        if not _invalid(out):
                            inline_ok = True
                    except Exception as e:
                        self.logger.warning("RSA keygen (config general-keys) failed: %s", e)

                    # Attempt 2: exec-mode general-keys modulus (some images only accept it in exec).
                    if not inline_ok:
                        try:
                            resp = con.send_command(
                                f"crypto key generate rsa general-keys modulus {modulus}",
                                timeout_ops=600,
                            )
                            out = _flatten(resp).strip().replace("\r", "")
                            if out:
                                self.logger.info("RSA keygen output (exec general-keys): %s", out.replace("\n", " | ")[:500])
                            if not _invalid(out):
                                inline_ok = True
                        except Exception as e:
                            self.logger.warning("RSA keygen (exec general-keys) failed: %s", e)

                    # Attempt 3: exec-mode "modulus" form (fails on some IOSv builds).
                    if not inline_ok:
                        try:
                            resp = con.send_command(
                                f"crypto key generate rsa modulus {modulus}",
                                timeout_ops=600,
                            )
                            out = _flatten(resp).strip().replace("\r", "")
                            if out:
                                self.logger.info("RSA keygen output (exec modulus): %s", out.replace("\n", " | ")[:500])
                            if not _invalid(out):
                                inline_ok = True
                        except Exception as e:
                            self.logger.warning("RSA keygen (exec modulus) failed: %s", e)

                    # Attempt 4: interactive keygen as last resort (can be prompt-variant and slow).
                    if not inline_ok:
                        if hasattr(con, "send_interactive"):
                            _ = con.send_interactive(
                                [
                                    ("crypto key generate rsa", r"(?i)(how many bits|modulus)"),
                                    (str(modulus), r"(?i)(#|>)"),
                                ],
                                interaction_complete_patterns=[r"(?i)(#|>)"],
                                timeout_ops=600,
                            )
                        else:
                            _ = con.send_command("crypto key generate rsa", timeout_ops=600)
                            _ = con.send_command(str(modulus), timeout_ops=30)
                except Exception as e:
                    self.logger.warning("RSA key generation command failed: %s", e)

                key_wait = int(os.getenv("RSA_KEY_WAIT_SECONDS", "900"))
                deadline = time.time() + key_wait
                last_log = 0.0
                while time.time() < deadline:
                    if ssh_banner_ready():
                        has_ssh = True
                        break
                    now = time.time()
                    if now-last_log >= 30:
                        try:
                            out = (con.send_command("show ip ssh").result or "").strip().replace("\r", "")
                            if out:
                                self.logger.info("Waiting for SSH (%ds left): show ip ssh: %s", int(deadline-now), out.replace("\n", " | ")[:200])
                        except Exception:
                            pass
                        last_log = now
                    time.sleep(2)
                if not has_ssh:
                    self.logger.warning("SSH did not become enabled within %ds after RSA key generation", key_wait)
        except Exception as e:
            self.logger.warning("RSA key check/generation failed: %s", e)

        res += con.send_configs(["ip ssh version 2\n"])
        res += con.send_commands(["write memory"])

        for response in res:
            self.logger.info(f"CONFIG:{response.channel_input}")
            self.logger.info(f"RESULT:{response.result}")

        con.close()


class VIOS(vrnetlab.VR):
    def __init__(self, hostname: str, username: str, password: str, conn_mode: str, device_type: str = None):
        super(VIOS, self).__init__(username, password)
        self.vms = [VIOS_vm(hostname, username, password, conn_mode, device_type)]


def _get_pod_ipv4() -> Optional[str]:
    # Prefer explicit env vars when available; fall back to `ip -j`.
    for k in ("POD_IP", "POD_IPV4", "MY_POD_IP"):
        v = (os.getenv(k) or "").strip()
        if v and v != "127.0.0.1":
            return v

    try:
        out = subprocess.check_output(["ip", "-j", "-4", "addr", "show", "dev", "eth0"], text=True)
        data = json.loads(out)
        if not data:
            return None
        for addr in data[0].get("addr_info", []):
            if addr.get("family") == "inet":
                ip = (addr.get("local") or "").strip()
                if ip and ip != "127.0.0.1":
                    return ip
    except Exception:
        return None
    return None


def _serve_tcp_proxy(
    bind_ip: str,
    bind_port: int,
    backend_ip: str,
    backend_port: int,
    logger: logging.Logger,
):
    backend = (backend_ip, backend_port)

    def _pipe(src: socket.socket, dst: socket.socket):
        try:
            while True:
                buf = src.recv(16 * 1024)
                if not buf:
                    break
                dst.sendall(buf)
        except Exception:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except Exception:
                pass

    def _handle_client(client: socket.socket, client_addr):
        b = None
        try:
            # Keep the backend connect timeout short so readiness probes don't pile up.
            b = socket.create_connection(backend, timeout=2.0)
            b.settimeout(None)
            client.settimeout(None)
            t1 = threading.Thread(target=_pipe, args=(client, b), daemon=True)
            t2 = threading.Thread(target=_pipe, args=(b, client), daemon=True)
            t1.start()
            t2.start()
            t1.join()
            t2.join()
        except Exception as e:
            logger.debug("podip ssh proxy: client=%s backend=%s error=%s", client_addr, backend, e)
        finally:
            try:
                client.close()
            except Exception:
                pass
            try:
                if b is not None:
                    b.close()
            except Exception:
                pass

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        # NOTE: bind to the pod IP specifically so we don't conflict with QEMU hostfwd on 127.0.0.1.
        s.bind((bind_ip, bind_port))
    except Exception as e:
        logger.error("podip ssh proxy: bind failed on %s:%d: %s", bind_ip, bind_port, e)
        return
    s.listen(64)
    logger.info("podip ssh proxy: listening on %s:%d -> %s:%d", bind_ip, bind_port, backend_ip, backend_port)

    while True:
        try:
            c, addr = s.accept()
            threading.Thread(target=_handle_client, args=(c, addr), daemon=True).start()
        except Exception:
            time.sleep(0.2)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="")
    parser.add_argument(
        "--trace",
        action="store_true",
        help="Enable trace level logging",
        default=os.getenv("TRACE", "false").lower() == "true",
    )
    parser.add_argument("--username", help="Username", default=os.getenv("USERNAME", "vagrant"))
    parser.add_argument("--password", help="Password", default=os.getenv("PASSWORD", "vagrant"))
    parser.add_argument("--hostname", help="Device hostname", default=os.getenv("HOSTNAME", "vios"))
    parser.add_argument(
        "--connection-mode",
        help="Connection mode to use in the datapath",
        default=os.getenv("CONNECTION_MODE", "tc"),
    )
    parser.add_argument(
        "--type",
        help="Device type (router or switch). If not specified, auto-detected from image filename.",
        default=os.getenv("DEVICE_TYPE", None),
        choices=["router", "switch"],
    )
    args = parser.parse_args()

    LOG_FORMAT = "%(asctime)s: %(module)-10s %(levelname)-8s %(message)s"
    logging.basicConfig(format=LOG_FORMAT)
    logger = logging.getLogger()

    logger.setLevel(logging.DEBUG)
    if args.trace:
        logger.setLevel(1)

    # Kubernetes-specific: QEMU usernet hostfwd for IOSv can accept TCP connections on the pod IP,
    # but the SSH banner/data path is unreliable unless the client is local to the namespace.
    # We bind QEMU hostfwd to 127.0.0.1 (see Dockerfile) and expose a pod-IP listener that proxies locally.
    pod_ip = _get_pod_ipv4()
    if pod_ip:
        threading.Thread(
            target=_serve_tcp_proxy,
            args=(pod_ip, 22, "127.0.0.1", 22, logger),
            daemon=True,
        ).start()
    else:
        logger.warning("podip ssh proxy: pod IPv4 not found; remote SSH readiness may fail")

    vr = VIOS(
        hostname=args.hostname,
        username=args.username,
        password=args.password,
        conn_mode=args.connection_mode,
        device_type=args.type,
    )
    vr.start()
