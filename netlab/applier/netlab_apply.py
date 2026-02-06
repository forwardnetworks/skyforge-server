#!/usr/bin/env python3

import base64
import json
import os
import pickle
import sys
import tarfile
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

from kubernetes import client, config


def stage(msg: str) -> None:
    print(f"stage: {msg}", flush=True)


def fatal(msg: str) -> None:
    print(f"ERROR: {msg}", flush=True)
    raise SystemExit(1)


def env(key: str, default: str = "") -> str:
    return str(os.environ.get(key, default) or "").strip()


def load_incluster() -> None:
    # We run as a Kubernetes Job, so in-cluster config should always work.
    config.load_incluster_config()


def get_configmap(api: client.CoreV1Api, namespace: str, name: str) -> client.V1ConfigMap:
    return api.read_namespaced_config_map(name=name, namespace=namespace)


def parse_set_overrides(raw: str) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip()
        if k and v != "":
            out.append((k, v))
    return out


def apply_device_group_vars(workdir: Path, overrides: List[Tuple[str, str]]) -> None:
    """
    Apply a restricted subset of netlab-style set overrides into extracted netlab output:
      devices.<device>.group_vars.<var>=<value>

    We deliberately keep this narrow; Skyforge should not reimplement netlab's full `--set`
    semantics, and `netlab initial` does not accept `--set` directly.
    """
    for key, value in overrides:
        parts = key.split(".")
        if len(parts) != 4:
            continue
        if parts[0] != "devices" or parts[2] != "group_vars":
            continue
        device = parts[1].strip()
        var = parts[3].strip()
        if not device or not var:
            continue

        gv_path = workdir / "group_vars" / device / "topology.yml"
        if not gv_path.exists():
            # Not all device keys have their own group_vars directory.
            continue
        try:
            data = gv_path.read_text(errors="ignore")
        except Exception:
            continue
        try:
            parsed = json.loads("{}")
            # YAML parse without PyYAML to keep the image small is not worth it; use netsim's YAML?
        except Exception:
            parsed = {}

        # We can safely treat group_vars/<device>/topology.yml as YAML, but we don't want
        # to add a full YAML parser dependency here. Netlab's group_vars files are small
        # and use simple "key: value" pairs for these vars, so do a minimal line-level patch:
        # - Remove any existing line that sets `var: ...`
        # - Append `var: value`
        #
        # This is intentionally minimal and only targets the variables we own (ansible_user, ansible_ssh_pass, netlab_check_*).
        lines = [ln.rstrip("\n") for ln in data.splitlines()]
        new_lines = []
        prefix = f"{var}:"
        for ln in lines:
            if ln.lstrip().startswith(prefix):
                continue
            new_lines.append(ln)
        # Keep YAML scalar quoting minimal; values here are simple.
        new_lines.append(f"{var}: {value}")
        try:
            gv_path.write_text("\n".join(new_lines).rstrip() + "\n")
        except Exception:
            continue


def reassemble_netlab_output(api: client.CoreV1Api, namespace: str, manifest: Dict[str, Any]) -> bytes:
    out = manifest.get("netlabOutput") or {}
    chunks = out.get("chunks") or []
    if not chunks:
        fatal("generator manifest missing netlabOutput chunks")
    parts: List[str] = []
    for ch in chunks:
        cm = str(ch.get("configMapName") or "").strip()
        key = str(ch.get("key") or "").strip()
        if not cm or not key:
            fatal(f"invalid netlabOutput chunk entry: {ch!r}")
        obj = get_configmap(api, namespace, cm)
        data = obj.data or {}
        if key not in data:
            fatal(f"netlabOutput chunk missing key {key} in {namespace}/{cm}")
        parts.append(str(data[key] or ""))
    b64 = "".join(parts).strip()
    if not b64:
        fatal("netlabOutput b64 is empty after chunk reassembly")
    try:
        return base64.b64decode(b64)
    except Exception as e:
        fatal(f"failed to base64-decode netlabOutput: {e}")
    raise AssertionError("unreachable")


def extract_tar_gz(blob: bytes, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    tgz = dest / "netlab-output.tgz"
    tgz.write_bytes(blob)
    with tarfile.open(tgz, "r:gz") as tar:
        tar.extractall(dest)


def reconstruct_node_files(api: client.CoreV1Api, namespace: str, workdir: Path, manifest: Dict[str, Any]) -> None:
    node_files_root = workdir / "node_files"
    node_files_root.mkdir(parents=True, exist_ok=True)

    nodes = manifest.get("nodes") or {}
    if not isinstance(nodes, dict):
        return

    for node, entry in nodes.items():
        node = str(node or "").strip()
        if not node:
            continue
        cm_name = str((entry or {}).get("configMapName") or "").strip()
        files = (entry or {}).get("files") or []
        if not cm_name or not files:
            continue

        cm = get_configmap(api, namespace, cm_name)
        data = cm.data or {}
        node_dir = node_files_root / node
        node_dir.mkdir(parents=True, exist_ok=True)

        for f in files:
            k = str((f or {}).get("key") or "").strip()
            rel = str((f or {}).get("rel") or "").strip()
            if not k or not rel:
                continue
            content = str(data.get(k, "") or "")
            out_path = node_dir / rel
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(content)

    shared = manifest.get("sharedFiles") or {}
    if isinstance(shared, dict) and shared.get("configMapName") and shared.get("files"):
        cm_name = str(shared.get("configMapName") or "").strip()
        files = shared.get("files") or []
        cm = get_configmap(api, namespace, cm_name)
        data = cm.data or {}
        for f in files:
            k = str((f or {}).get("key") or "").strip()
            rel = str((f or {}).get("rel") or "").strip()
            if not k or not rel:
                continue
            content = str(data.get(k, "") or "")
            out_path = node_files_root / rel
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(content)


def load_name_map(api: client.CoreV1Api, namespace: str, name: str) -> Dict[str, str]:
    if not name:
        return {}
    cm = get_configmap(api, namespace, name)
    raw = (cm.data or {}).get("mapping.json") or ""
    if not raw:
        return {}
    try:
        decoded = json.loads(raw)
        return decoded.get("originalToSanitized") or {}
    except Exception:
        return {}


def patch_hosts_yaml(workdir: Path, namespace: str, topology_name: str, original_to_sanitized: Dict[str, str]) -> None:
    hosts_path = workdir / "hosts.yml"
    if not hosts_path.exists():
        fatal("netlab output missing hosts.yml")
    # hosts.yml is small; do a lightweight YAML-ish patch: replace ansible_host lines.
    # This avoids adding a YAML dependency. Netlab inventory is deterministic:
    # <node>:\n  ansible_host: <ip>
    lines = hosts_path.read_text(errors="ignore").splitlines()
    out: List[str] = []
    current_host = ""
    for ln in lines:
        stripped = ln.strip()
        # Host keys are at indentation 4 in minimized inventory.
        if ln.startswith("    ") and not ln.startswith("      ") and stripped.endswith(":") and " " not in stripped[:-1]:
            current_host = stripped[:-1]
            out.append(ln)
            continue
        if stripped.startswith("ansible_host:") and current_host:
            sanitized = original_to_sanitized.get(current_host, current_host)
            svc = f"{topology_name}-{sanitized}.{namespace}.svc.cluster.local"
            out.append("      ansible_host: " + svc)
            continue
        out.append(ln)
    hosts_path.write_text("\n".join(out).rstrip() + "\n")


def patch_snapshot_pickle(workdir: Path, namespace: str, topology_name: str, original_to_sanitized: Dict[str, str]) -> None:
    snap_path = workdir / "netlab.snapshot.pickle"
    if not snap_path.exists():
        fatal("netlab output missing netlab.snapshot.pickle")
    topo = pickle.loads(snap_path.read_bytes())
    if not isinstance(topo, dict):
        fatal("netlab snapshot is not a dict")
    nodes = topo.get("nodes")
    if not isinstance(nodes, dict):
        fatal("netlab snapshot missing nodes dict")
    for orig, node in nodes.items():
        if not isinstance(node, dict):
            continue
        orig = str(orig)
        sanitized = original_to_sanitized.get(orig, orig)
        svc = f"{topology_name}-{sanitized}.{namespace}.svc.cluster.local"
        mgmt = node.get("mgmt")
        if isinstance(mgmt, dict):
            mgmt["ipv4"] = svc
    snap_path.write_bytes(pickle.dumps(topo))


def run_netlab_initial(workdir: Path) -> None:
    # Pure-python netlab initial.
    from netsim.cli import initial

    cwd = os.getcwd()
    try:
        os.chdir(str(workdir))
        initial.run([])
    finally:
        os.chdir(cwd)


def main() -> None:
    namespace = env("SKYFORGE_C9S_NAMESPACE")
    topology_name = env("SKYFORGE_C9S_TOPOLOGY_NAME")
    manifest_cm = env("SKYFORGE_C9S_MANIFEST_CM")
    name_map_cm = env("SKYFORGE_C9S_NAME_MAP_CM")
    if not namespace or not topology_name or not manifest_cm:
        fatal("missing required env: SKYFORGE_C9S_NAMESPACE / SKYFORGE_C9S_TOPOLOGY_NAME / SKYFORGE_C9S_MANIFEST_CM")

    stage("load kube config")
    load_incluster()
    api = client.CoreV1Api()

    stage("fetch generator manifest")
    cm = get_configmap(api, namespace, manifest_cm)
    raw_manifest = (cm.data or {}).get("manifest.json") or ""
    if not raw_manifest:
        fatal(f"manifest.json missing in {namespace}/{manifest_cm}")
    try:
        manifest = json.loads(raw_manifest)
    except Exception as e:
        fatal(f"manifest.json parse failed: {e}")

    stage("reassemble netlab output tarball")
    out_bytes = reassemble_netlab_output(api, namespace, manifest)

    stage("extract netlab output")
    workdir = Path("/work/netlab").resolve()
    if workdir.exists():
        # Clean from previous retries
        for p in workdir.iterdir():
            if p.is_dir():
                for _ in range(3):
                    try:
                        import shutil

                        shutil.rmtree(p)
                        break
                    except Exception:
                        time.sleep(0.2)
            else:
                try:
                    p.unlink()
                except Exception:
                    pass
    extract_tar_gz(out_bytes, workdir)

    stage("reconstruct node_files")
    reconstruct_node_files(api, namespace, workdir, manifest)

    stage("load node name mapping")
    original_to_sanitized = load_name_map(api, namespace, name_map_cm)

    stage("patch hosts.yml + snapshot for k8s service DNS")
    patch_hosts_yaml(workdir, namespace, topology_name, original_to_sanitized)
    patch_snapshot_pickle(workdir, namespace, topology_name, original_to_sanitized)

    # Apply derived `--set` overrides (credentials, readiness tuning) into group_vars.
    overrides_raw = env("SKYFORGE_NETLAB_SET_OVERRIDES")
    overrides = parse_set_overrides(overrides_raw)
    if overrides:
        stage("apply derived group_vars overrides")
        apply_device_group_vars(workdir, overrides)

    stage("netlab initial (apply configs)")
    try:
        run_netlab_initial(workdir)
    except SystemExit as e:
        fatal(f"netlab initial failed (SystemExit {e.code})")


if __name__ == "__main__":
    main()

