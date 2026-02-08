import base64
import json
import os
import re
import sys
import tarfile
import ipaddress
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from kubernetes import client, config
from kubernetes.client.rest import ApiException
from netsim.cli import create as netlab_create
import yaml


@dataclass(frozen=True)
class FileEntry:
    key: str
    rel: str
    content: str


def _env(name: str, default: str = "") -> str:
    return str(os.environ.get(name, default)).strip()

def _env_bool(name: str, default: bool = False) -> bool:
    v = _env(name, "")
    if v == "":
        return bool(default)
    return v.lower() in ("1", "true", "yes", "y", "on")


def _fatal(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    raise SystemExit(2)


_CM_KEY_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _cm_key_for(rel: str) -> str:
    rel = rel.strip().lstrip("/")
    rel = rel.replace("\\", "/")
    rel = rel.replace("/", "__")
    rel = _CM_KEY_SAFE.sub("_", rel)
    rel = rel.strip("._-")
    if not rel:
        rel = "file"
    if len(rel) > 200:
        rel = rel[:200]
    return rel


def _load_incluster() -> None:
    # Falls back to local kubeconfig for dev debugging.
    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config()


def _upsert_configmap(api: client.CoreV1Api, namespace: str, name: str, data: Dict[str, str], labels: Dict[str, str]) -> None:
    body = client.V1ConfigMap(
        metadata=client.V1ObjectMeta(name=name, namespace=namespace, labels=labels),
        data=data,
    )
    try:
        api.create_namespaced_config_map(namespace=namespace, body=body)
        return
    except ApiException as exc:
        if exc.status != 409:
            raise
    api.patch_namespaced_config_map(name=name, namespace=namespace, body=body)


def _read_bundle(bundle_path: Path) -> bytes:
    raw = bundle_path.read_text().strip()
    if not raw:
        _fatal(f"bundle is empty: {bundle_path}")
    try:
        return base64.b64decode(raw, validate=True)
    except Exception as exc:
        _fatal(f"bundle is not valid base64: {exc}")
    raise AssertionError("unreachable")


def _extract_bundle(bundle_bytes: bytes, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=BytesIO(bundle_bytes), mode="r:gz") as tar:
        members = tar.getmembers()
        for m in members:
            name = str(m.name or "").strip()
            if not name or name.startswith("/") or name.startswith("\\"):
                _fatal("bundle contains invalid member path")
            norm = name.replace("\\", "/")
            if norm.startswith("../") or "/../" in norm:
                _fatal("bundle contains path traversal member")
        # Python 3.14+ will default to filtering extracted tar archives; pass an explicit
        # filter where supported to keep behavior stable across runtimes.
        try:
            tar.extractall(dest, members=members, filter="data")  # type: ignore[call-arg]
        except TypeError:
            tar.extractall(dest, members=members)


def _sanitize_cm_name(name: str) -> str:
    name = str(name or "").strip().lower()
    name = re.sub(r"[^a-z0-9-]+", "-", name).strip("-")
    if not name:
        name = "cm"
    if len(name) > 253:
        name = name[:253].rstrip("-")
    return name


def _build_netlab_output_tar_gz(workdir: Path) -> bytes:
    """
    Build a tar.gz of the netlab-generated artifacts needed for post-deploy apply.

    We intentionally exclude node_files/ because those are already persisted per-node
    into ConfigMaps, and including them here can easily exceed Kubernetes object limits.
    """
    include = [
        "clab.yml",
        "topology.yml",
        "ansible.cfg",
        "hosts.yml",
        "netlab.snapshot.yml",
        "netlab.snapshot.pickle",
        "group_vars",
        "host_vars",
        "graphite",
        "config",
    ]

    buf = BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for rel in include:
            p = (workdir / rel).resolve()
            # Refuse to archive paths outside of workdir.
            if not str(p).startswith(str(workdir.resolve())):
                continue
            if not p.exists():
                continue
            tar.add(str(p), arcname=rel, recursive=True)
    return buf.getvalue()


def _persist_b64_chunks_to_configmaps(
    api: client.CoreV1Api,
    namespace: str,
    cm_prefix: str,
    b64: str,
    labels: Dict[str, str],
    *,
    chunk_size: int = 600_000,
) -> List[Dict[str, str]]:
    """
    Persist a large base64 blob as multiple ConfigMaps and return chunk references.

    Each chunk is written to:
      - ConfigMap: <cm_prefix>-<idx>
      - Key: chunk.b64
    """
    b64 = str(b64 or "").strip()
    if not b64:
        return []
    if chunk_size < 50_000:
        chunk_size = 50_000

    out: List[Dict[str, str]] = []
    idx = 0
    for off in range(0, len(b64), chunk_size):
        chunk = b64[off : off + chunk_size]
        cm_name = _sanitize_cm_name(f"{cm_prefix}-{idx}")
        _upsert_configmap(api, namespace, cm_name, {"chunk.b64": chunk}, labels)
        out.append({"configMapName": cm_name, "key": "chunk.b64"})
        idx += 1
    return out


def _run_netlab_create(
    workdir: Path,
    topology_path: str,
    *,
    plugins: Optional[Sequence[str]] = None,
    set_overrides: Optional[Sequence[str]] = None,
) -> None:
    topo = topology_path.strip()
    if not topo:
        topo = "topology.yml"
    cwd = Path.cwd()
    try:
        os.chdir(str(workdir))
        args: list[str] = []
        for p in plugins or []:
            v = str(p or "").strip()
            if not v:
                continue
            args.extend(["--plugin", v])
        for ov in set_overrides or []:
            v = str(ov or "").strip()
            if not v:
                continue
            args.extend(["--set", v])
        args.append(topo)
        netlab_create.run(args)
    except SystemExit as exc:
        _fatal(f"netlab create failed (SystemExit {exc.code})")
    except Exception as exc:
        _fatal(f"netlab create failed: {exc}")
    finally:
        os.chdir(str(cwd))


def _parse_set_overrides(raw: str) -> List[str]:
    items: List[str] = []
    for ln in str(raw or "").splitlines():
        v = str(ln or "").strip()
        if not v:
            continue
        items.append(v)
    return items

def _read_text_file(path: Path) -> str:
    try:
        return path.read_text()
    except Exception as exc:
        _fatal(f"failed reading {path}: {exc}")
    raise AssertionError("unreachable")


def _collect_node_files(node_files_root: Path) -> Dict[str, List[FileEntry]]:
    if not node_files_root.exists():
        _fatal(f"netlab output missing node_files directory: {node_files_root}")
    out: Dict[str, List[FileEntry]] = {}
    for node_dir in sorted(p for p in node_files_root.iterdir() if p.is_dir()):
        node = node_dir.name.strip()
        if not node:
            continue
        entries: List[FileEntry] = []
        for file_path in sorted(node_dir.rglob("*")):
            if not file_path.is_file():
                continue
            rel = file_path.relative_to(node_dir).as_posix()
            if not rel or rel.startswith(".."):
                continue
            key = _cm_key_for(rel)
            # Keep file text as-is; if we ever need binary, we can switch to base64+decode in initContainers.
            content = file_path.read_text()
            entries.append(FileEntry(key=key, rel=rel, content=content))
        if entries:
            out[node] = entries
    if not out:
        _fatal(f"node_files is empty: {node_files_root}")
    return out


def _collect_shared_node_files(node_files_root: Path) -> List[FileEntry]:
    """
    Netlab writes some shared bind sources directly under node_files/ (not under node_files/<node>/),
    for example: node_files/-shared-hosts used as a source for /etc/hosts binds.

    These files need to be available to every launcher pod, so we surface them separately.
    """
    if not node_files_root.exists():
        return []
    entries: List[FileEntry] = []
    for file_path in sorted(p for p in node_files_root.iterdir() if p.is_file()):
        name = file_path.name.strip()
        if not name or name.startswith("."):
            continue
        key = _cm_key_for(name)
        content = file_path.read_text()
        entries.append(FileEntry(key=key, rel=name, content=content))
    return entries


def _collect_startup_configs(config_root: Path) -> List[FileEntry]:
    """
    Collects generated startup configurations from the config/ directory.

    Newer netlab workflows increasingly rely on containerlab startup configs
    instead of post-deploy Ansible runs.
    """
    if not config_root.exists():
        return []
    entries: List[FileEntry] = []
    for file_path in sorted(config_root.glob("*")):
        if not file_path.is_file():
            continue
        name = file_path.name.strip()
        if not name or name.startswith("."):
            continue
        key = _cm_key_for(name)
        try:
            content = file_path.read_text()
        except Exception:
            continue
        entries.append(FileEntry(key=key, rel=name, content=content))
    return entries


def _mask_from_prefix(prefix: int) -> str:
    try:
        return str(ipaddress.IPv4Network(f"0.0.0.0/{int(prefix)}").netmask)
    except Exception:
        return ""


def _extract_ipv4_from_snapshot(node: Dict[str, object]) -> str:
    """
    Best-effort extraction of mgmt IPv4 from netlab snapshot structures.
    Returns a string like "172.31.255.2/24" or "".
    """
    mgmt = node.get("mgmt")
    if isinstance(mgmt, dict):
        for k in ("ipv4", "ipv4_address", "ip"):
            v = mgmt.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
    return ""


def _inject_ios_mgmt_vrf(workdir: Path) -> None:
    """
    For IOS/IOL devices (no dedicated Management0 port), move clab-mgmt (Eth0/0)
    into a dedicated management VRF so it does not interfere with lab routing.

    This is implemented as an additional node_files snippet so the device
    bootstrap can consume it without modifying netlab upstream templates.
    """
    snap_path = workdir / "netlab.snapshot.yml"
    if not snap_path.exists():
        return
    try:
        snap = yaml.safe_load(snap_path.read_text()) or {}
    except Exception:
        return

    nodes = snap.get("nodes")
    if not isinstance(nodes, dict):
        return

    node_files_root = workdir / "node_files"
    config_root = workdir / "config"

    for node_name, node_obj in nodes.items():
        if not isinstance(node_name, str) or not node_name.strip():
            continue
        if not isinstance(node_obj, dict):
            continue

        device = str(node_obj.get("device", "") or "").strip().lower()
        if device in ("cisco_iol", "iol", "ios", "iosxe", "ios_xe", "ios-xe"):
            pass
        else:
            continue

        ipv4 = _extract_ipv4_from_snapshot(node_obj)
        ip_addr = ""
        mask = ""
        if ipv4:
            # Accept "a.b.c.d/24" or "a.b.c.d" (assume /24).
            if "/" in ipv4:
                ip_addr, prefix = ipv4.split("/", 1)
                ip_addr = ip_addr.strip()
                mask = _mask_from_prefix(int(prefix.strip() or "24"))
            else:
                ip_addr = ipv4.strip()
                mask = _mask_from_prefix(24)

        # If snapshot didn't include the mgmt IP, try to scrape it from the generated config.
        if not ip_addr or not mask:
            cfg = config_root / f"{node_name}.cfg"
            if cfg.exists():
                txt = cfg.read_text(errors="ignore")
                m = re.search(r"interface\\s+Ethernet0/0[\\s\\S]*?\\nip address\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)", txt, re.MULTILINE)
                if m:
                    ip_addr = m.group(1).strip()
                    mask = m.group(2).strip()

        if not ip_addr or not mask:
            continue

        node_dir = node_files_root / node_name
        if not node_dir.exists():
            continue

        snippet = "\n".join(
            [
                "vrf definition MGMT",
                " !",
                " address-family ipv4",
                " exit-address-family",
                "!",
                "interface Ethernet0/0",
                " description clab-mgmt",
                " no ip address",
                " vrf forwarding MGMT",
                f" ip address {ip_addr} {mask}",
                " no cdp enable",
                " no lldp transmit",
                " no lldp receive",
                "!",
                "",
            ]
        )

        # Netlab module snippets are stored under node_files/<node>/<phase>. Use a stable
        # name so it gets mounted and applied with other snippets.
        try:
            (node_dir / "mgmt_vrf").write_text(snippet)
        except Exception:
            continue


def _ensure_unique_keys(entries: List[FileEntry]) -> List[FileEntry]:
    used: Dict[str, int] = {}
    out: List[FileEntry] = []
    for ent in entries:
        k = ent.key
        if k not in used:
            used[k] = 1
            out.append(ent)
            continue
        used[k] += 1
        suffix = used[k]
        k2 = f"{k}_{suffix}"
        out.append(FileEntry(key=k2, rel=ent.rel, content=ent.content))
    return out


def main() -> None:
    validate_only = _env_bool("SKYFORGE_VALIDATE_ONLY", False)

    bundle_path = Path(_env("SKYFORGE_NETLAB_BUNDLE_PATH"))
    topology_path = _env("SKYFORGE_NETLAB_TOPOLOGY_PATH", "topology.yml")

    if not bundle_path.exists():
        _fatal(f"bundle path does not exist: {bundle_path}")

    workdir = Path("/work")
    bundle_bytes = _read_bundle(bundle_path)
    _extract_bundle(bundle_bytes, workdir)

    topo_file = (workdir / topology_path).resolve()
    # Topology path should be inside workdir; reject traversal.
    if not str(topo_file).startswith(str(workdir.resolve())):
        _fatal("topology path escapes workdir")
    if not topo_file.exists():
        _fatal(f"topology file missing after extract: {topo_file}")

    # Skyforge relies on the netlab "files" plugin to reliably generate node_files/ and
    # other artifacts that we mount into pods. Enable it via CLI args rather than
    # mutating the template YAML.
    #
    # NOTE: Device/provider overrides should be passed as NETLAB_* env vars (native netlab feature).
    set_overrides = _parse_set_overrides(_env("SKYFORGE_NETLAB_SET_OVERRIDES") or "")
    _run_netlab_create(workdir, topology_path, plugins=["files"], set_overrides=set_overrides)

    if validate_only:
        # For template validation, we only need to ensure `netlab create` succeeds.
        # Do not require Kubernetes API access or write any ConfigMaps.
        print(
            "SKYFORGE_VALIDATE_RESULT "
            + json.dumps(
                {
                    "ok": True,
                    "topologyPath": topology_path,
                }
            ),
            flush=True,
        )
        return

    namespace = _env("SKYFORGE_C9S_NAMESPACE")
    topology_name = _env("SKYFORGE_C9S_TOPOLOGY_NAME")
    manifest_cm = _env("SKYFORGE_C9S_MANIFEST_CM")
    if not namespace:
        _fatal("SKYFORGE_C9S_NAMESPACE is required")
    if not topology_name:
        _fatal("SKYFORGE_C9S_TOPOLOGY_NAME is required")
    if not manifest_cm:
        _fatal("SKYFORGE_C9S_MANIFEST_CM is required")

    # Post-process netlab output to add Skyforge-specific snippets without patching
    # upstream netlab templates.
    _inject_ios_mgmt_vrf(workdir)

    clab_yml = workdir / "clab.yml"
    if not clab_yml.exists():
        _fatal("netlab create did not produce clab.yml")
    clab_yaml = _read_text_file(clab_yml).strip()
    if not clab_yaml:
        _fatal("clab.yml is empty")
    # Device/provider defaults are supplied via /etc/netlab/defaults.yml baked into
    # the generator image, so clab.yml should already contain GHCR-prefixed NOS images.

    node_files = _collect_node_files(workdir / "node_files")
    shared_files = _collect_shared_node_files(workdir / "node_files")
    startup_configs = _collect_startup_configs(workdir / "config")

    snapshot_yaml = ""
    snapshot_yml = workdir / "netlab.snapshot.yml"
    if snapshot_yml.exists():
        snapshot_yaml = _read_text_file(snapshot_yml).strip()

    graphite_json = ""
    graphite_default = workdir / "graphite" / "graphite-default.json"
    if graphite_default.exists():
        graphite_json = _read_text_file(graphite_default).strip()

    _load_incluster()
    api = client.CoreV1Api()

    labels = {"skyforge-c9s-topology": topology_name}

    manifest: Dict[str, object] = {"clabYAML": clab_yaml, "nodes": {}}
    if snapshot_yaml:
        manifest["netlabSnapshotYAML"] = snapshot_yaml
    if graphite_json:
        manifest["graphiteDefaultJSON"] = graphite_json
    nodes_out: Dict[str, Dict[str, object]] = {}

    for node, entries in node_files.items():
        # Keep configmaps reasonably sized; fail fast with a clear error rather than silently truncating.
        entries = _ensure_unique_keys(entries)
        data = {e.key: e.content for e in entries}
        size = sum(len(k) + len(v) for k, v in data.items())
        if size > 700_000:
            _fatal(f"node_files for {node} too large for single ConfigMap ({size} bytes). Split support not implemented yet.")

        cm_name = f"c9s-{topology_name}-{node}".lower()
        cm_name = re.sub(r"[^a-z0-9-]+", "-", cm_name).strip("-")
        if len(cm_name) > 253:
            cm_name = cm_name[:253].rstrip("-")

        _upsert_configmap(api, namespace, cm_name, data, labels)

        nodes_out[node] = {
            "configMapName": cm_name,
            "files": [{"key": e.key, "rel": e.rel} for e in entries],
        }

    if shared_files:
        shared_entries = _ensure_unique_keys(shared_files)
        data = {e.key: e.content for e in shared_entries}
        size = sum(len(k) + len(v) for k, v in data.items())
        if size > 700_000:
            _fatal(f"shared node_files too large for single ConfigMap ({size} bytes). Split support not implemented yet.")

        cm_name = f"c9s-{topology_name}-shared".lower()
        cm_name = re.sub(r"[^a-z0-9-]+", "-", cm_name).strip("-")
        if len(cm_name) > 253:
            cm_name = cm_name[:253].rstrip("-")
        _upsert_configmap(api, namespace, cm_name, data, labels)
        manifest["sharedFiles"] = {
            "configMapName": cm_name,
            "files": [{"key": e.key, "rel": e.rel} for e in shared_entries],
        }

    if startup_configs:
        config_entries = _ensure_unique_keys(startup_configs)
        data = {e.key: e.content for e in config_entries}
        size = sum(len(k) + len(v) for k, v in data.items())
        if size > 900_000:
            _fatal(f"startup configs too large for single ConfigMap ({size} bytes).")

        cm_name = f"c9s-{topology_name}-configs".lower()
        cm_name = re.sub(r"[^a-z0-9-]+", "-", cm_name).strip("-")
        if len(cm_name) > 253:
            cm_name = cm_name[:253].rstrip("-")
        _upsert_configmap(api, namespace, cm_name, data, labels)
        manifest["startupConfigs"] = {
            "configMapName": cm_name,
            "files": [{"key": e.key, "rel": e.rel} for e in config_entries],
        }

    # Persist netlab output required for post-deploy `netlab initial`.
    #
    # Skyforge's applier job reconstructs the output tarball from these chunks, patches
    # inventory/snapshot to use Kubernetes Service DNS, then runs `netlab initial`.
    out_bytes = _build_netlab_output_tar_gz(workdir)
    out_b64 = base64.b64encode(out_bytes).decode("ascii")
    out_chunks = _persist_b64_chunks_to_configmaps(
        api,
        namespace,
        cm_prefix=_sanitize_cm_name(f"c9s-{topology_name}-netlab-output"),
        b64=out_b64,
        labels=labels,
    )
    if out_chunks:
        manifest["netlabOutput"] = {
            "type": "tar.gz",
            "encoding": "base64",
            "chunks": out_chunks,
        }

    manifest["nodes"] = nodes_out
    _upsert_configmap(api, namespace, manifest_cm, {"manifest.json": json.dumps(manifest)}, labels)
    print(f"ok: wrote manifest to {namespace}/{manifest_cm}")


if __name__ == "__main__":
    main()
