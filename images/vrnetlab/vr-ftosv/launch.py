#!/usr/bin/env python3

import datetime
import logging
import os
import re
import signal
import sys
import ipaddress
import time

import vrnetlab

STARTUP_CONFIG_FILE = "/config/startup-config.cfg"


def handle_SIGCHLD(signal, frame):
    os.waitpid(-1, os.WNOHANG)


def handle_SIGTERM(signal, frame):
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


class FTOS_vm(vrnetlab.VM):
    def __init__(self, hostname, username, password, conn_mode):
        disk_image = ""
        for e in os.listdir("/"):
            if re.search(".qcow2$", e):
                disk_image = "/" + e
        if disk_image == "":
            logging.getLogger().info("Disk image was not found")
            exit(1)
        super(FTOS_vm, self).__init__(
            username, password, disk_image=disk_image, ram=4096, smp="4"
        )
        self.credentials = [["admin", "admin"]]
        self.hostname = hostname
        self.conn_mode = conn_mode
        self.num_nics = 56
        self.nic_type = "e1000"

        overlay_disk_image = re.sub(r"(\.[^.]+$)", r"-overlay\1", disk_image)
        # boot harddrive first
        self.qemu_args.extend(["-boot", "c"])
        replace_index = self.qemu_args.index("if=ide,file={}".format(overlay_disk_image))
        self.qemu_args[replace_index] = (
            "file={},if=none,id=drive-sata-disk0,format=qcow2".format(overlay_disk_image)
        )
        self.qemu_args.extend(["-device", "ahci,id=ahci0,bus=pci.0"])
        self.qemu_args.extend(
            [
                "-device",
                "ide-hd,drive=drive-sata-disk0,bus=ahci0.0,id=drive-sata-disk0,bootindex=1",
            ]
        )

    def gen_mgmt(self):
        """
        Augment the parent class function to add gRPC port forwarding

        TCP ports forwarded:
        443 - OS10 REST API
        830 - Netconf
        """
        # OS10 expects the default QEMU user-mode network (10.0.2.0/24) and DHCP.
        self.mgmt_subnet = "10.0.2.0/24"
        self.mgmt_tcp_ports = [443, 830]

        res = super(FTOS_vm, self).gen_mgmt()

        # Append gRPC forwarding if it was not added by common lib.
        network = ipaddress.ip_network(self.mgmt_subnet)
        guest = str(network[self.mgmt_guest_ip])
        if f"hostfwd=tcp::50051-{guest}:50051" not in res[-1]:
            res[-1] = res[-1] + f",hostfwd=tcp::17051-{guest}:50051"
            vrnetlab.run_command(
                ["socat", "TCP-LISTEN:50051,fork", "TCP:127.0.0.1:17051"],
                background=True,
            )
        return res

    def _wait_for_any_prompt(self, prompts, timeout_s=20 * 60, con=None):
        """
        Wait for any of the provided prompt substrings to appear on the console.

        NOTE: vrnetlab's wait_write() uses telnetlib.read_until() with no timeout
        when a wait string is provided. Some OS10 images boot into a prompt that
        is not literally "OS10#" (for example, it can include the platform name
        or start in non-privileged exec mode with a '>').
        """
        if con is None:
            con = self.tn
        end = time.time() + max(1, int(timeout_s))
        buf = ""

        while time.time() < end:
            try:
                chunk = con.read_very_eager()
            except EOFError:
                chunk = b""
            if chunk:
                s = chunk.decode("utf-8", "ignore")
                buf += s
                # Keep the buffer bounded.
                if len(buf) > 8192:
                    buf = buf[-8192:]
                for p in prompts:
                    if p and p in buf:
                        self.logger.info("matched prompt '%s'", p)
                        return p

            # Poke the console to encourage a prompt.
            try:
                con.write(b"\r")
            except Exception:
                pass
            time.sleep(1)

        raise TimeoutError(f"timed out waiting for prompt in {prompts}")

    def bootstrap_spin(self):
        if self.spins > 300:
            self.stop()
            self.start()
            return

        (ridx, match, res) = self.tn.expect([b"login:"], 1)
        if match:
            if ridx == 0:
                self.logger.debug("matched login prompt")
                try:
                    username, password = self.credentials.pop(0)
                except IndexError:
                    self.logger.error("no more credentials to try")
                    return
                self.logger.debug("trying to log in with %s / %s", username, password)
                self.wait_write(username, wait=None)
                self.wait_write(password, wait="Password:")

                self.bootstrap_config()
                self.startup_config()

                self.tn.close()
                startup_time = datetime.datetime.now() - self.start_time
                self.logger.info("Startup complete in: %s", startup_time)
                self.running = True
                return

        if res != b"":
            self.logger.trace("OUTPUT: %s", res.decode())
            self.spins = 0

        self.spins += 1
        return

    def bootstrap_config(self):
        self.logger.info("applying bootstrap configuration once system is ready")
        self.wait_write("", None)

        # Wait for a usable CLI prompt. OS10 can present either exec (">") or
        # enable ("#") prompts and the hostname prefix varies by image/platform.
        prompt = self._wait_for_any_prompt(["#", ">"], timeout_s=20 * 60)
        if prompt == ">":
            self.wait_write("enable", wait=None)
            self._wait_for_any_prompt(["#"], timeout_s=5 * 60)

        # Enter config mode (prompt varies; '#' is present in all privileged modes).
        self.wait_write("configure terminal", wait=None)
        self._wait_for_any_prompt(["#"], timeout_s=60)

        self.wait_write(f"hostname {self.hostname}", wait="#")
        self.wait_write("service simple-password", wait="#")
        self.wait_write(
            f"username {self.username} password {self.password} role sysadmin priv-lv 15",
            wait="#",
        )

        # No need to reconfigure mgmt IP; causes issues with parallel Netlab provisioning.
        self.wait_write("copy running-configuration startup-configuration", wait="#")
        self.wait_write("", wait="#")

    def startup_config(self):
        if not os.path.exists(STARTUP_CONFIG_FILE):
            self.logger.trace("Startup config file %s is not found", STARTUP_CONFIG_FILE)
            return

        self.logger.trace("Startup config file %s exists", STARTUP_CONFIG_FILE)
        with open(STARTUP_CONFIG_FILE) as file:
            config_lines = file.readlines()
            config_lines = [line.rstrip() for line in config_lines]
            self.logger.trace("Parsed startup config file %s", STARTUP_CONFIG_FILE)

        self.logger.info("Writing lines from %s", STARTUP_CONFIG_FILE)

        self.wait_write("configure terminal")
        for line in config_lines:
            self.wait_write(line)
        self.wait_write("end")
        self.wait_write("copy running-config startup-config")
        self.wait_write("")


class FTOS(vrnetlab.VR):
    def __init__(self, hostname, username, password, conn_mode):
        super(FTOS, self).__init__(username, password)
        self.vms = [FTOS_vm(hostname, username, password, conn_mode)]


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="")
    parser.add_argument("--trace", action="store_true", help="enable trace level logging")
    parser.add_argument("--hostname", default="vr-ftosv", help="Router hostname")
    parser.add_argument("--username", default="admin", help="Username")
    parser.add_argument("--password", default="admin", help="Password")
    parser.add_argument(
        "--connection-mode",
        default="vrxcon",
        help="Connection mode to use in the datapath",
    )
    args = parser.parse_args()

    LOG_FORMAT = "%(asctime)s: %(module)-10s %(levelname)-8s %(message)s"
    logging.basicConfig(format=LOG_FORMAT)
    logger = logging.getLogger()

    if args.trace:
        logger.setLevel(TRACE_LEVEL_NUM)
    else:
        logger.setLevel(logging.DEBUG)

    vr = FTOS(args.hostname, args.username, args.password, args.connection_mode)
    vr.start()
