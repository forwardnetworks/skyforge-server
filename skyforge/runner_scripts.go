package skyforge

func netlabAPIRunnerScript() string {
	return `#!/usr/bin/env python3
import argparse
import json
import os
import sys
import time
import urllib.request
from urllib.error import HTTPError, URLError


def getenv(name, default=""):
  return os.getenv(name, default)


def _set_env_if_missing(name, value):
  if value is None:
    return
  value = str(value).strip()
  if not value:
    return
  if getenv(name, "").strip():
    return
  os.environ[name] = value


def parse_args(argv):
  p = argparse.ArgumentParser(description="Skyforge Netlab API runner")
  p.add_argument("--api-url", dest="NETLAB_API_URL")
  p.add_argument("--api-insecure", dest="NETLAB_API_INSECURE")
  p.add_argument("--action", dest="NETLAB_ACTION")
  p.add_argument("--user", dest="NETLAB_USER")
  p.add_argument("--workspace", dest="NETLAB_WORKSPACE")
  p.add_argument("--deployment", dest="NETLAB_DEPLOYMENT")
  p.add_argument("--workspace-root", dest="NETLAB_WORKSPACE_ROOT")
  p.add_argument("--plugin", dest="NETLAB_PLUGIN")
  p.add_argument("--multilab-id", dest="NETLAB_MULTILAB_ID")
  p.add_argument("--state-root", dest="NETLAB_STATE_ROOT")
  p.add_argument("--topology", dest="NETLAB_TOPOLOGY")
  p.add_argument("--topology-url", dest="NETLAB_TOPOLOGY_URL")
  p.add_argument("--instance", dest="NETLAB_INSTANCE")
  p.add_argument("--collect-output", dest="NETLAB_COLLECT_OUTPUT")
  p.add_argument("--collect-tar", dest="NETLAB_COLLECT_TAR")
  p.add_argument("--collect-cleanup", dest="NETLAB_COLLECT_CLEANUP")
  p.add_argument("--cleanup", dest="NETLAB_CLEANUP")
  args, extra = p.parse_known_args(argv)
  return args, extra


def apply_env_assignments(args):
  for a in args:
    if not isinstance(a, str):
      continue
    a = a.strip()
    if not a:
      continue
    if "=" not in a:
      continue
    k, v = a.split("=", 1)
    k = k.strip()
    v = v.strip()
    if not k:
      continue
    _set_env_if_missing(k, v)


def build_payload():
  user = getenv("NETLAB_USER") or getenv("NETLAB_SSH_USER") or getenv("USER") or "netlab"
  workspace = getenv("NETLAB_WORKSPACE") or getenv("NETLAB_WORKSPACE_SLUG") or getenv("NETLAB_WORKSPACE_ID")
  if not workspace:
    workspace = getenv("NETLAB_PROJECT") or getenv("NETLAB_PROJECT_SLUG") or getenv("NETLAB_PROJECT_ID") or "workspace"
  deployment = getenv("NETLAB_DEPLOYMENT") or getenv("NETLAB_DEPLOYMENT_ID") or getenv("NETLAB_MULTILAB_ID") or "deployment"
  workspace_root = getenv("NETLAB_WORKSPACE_ROOT") or f"/home/{user}/netlab"
  action = (getenv("NETLAB_ACTION") or "up").lower()
  payload = {
    "action": action,
    "user": user,
    "workspace": workspace,
    "deployment": deployment,
    "workspaceRoot": workspace_root,
  }
  if getenv("NETLAB_PLUGIN"):
    payload["plugin"] = getenv("NETLAB_PLUGIN")
  if getenv("NETLAB_MULTILAB_ID"):
    payload["multilabId"] = getenv("NETLAB_MULTILAB_ID")
  if getenv("NETLAB_STATE_ROOT"):
    payload["stateRoot"] = getenv("NETLAB_STATE_ROOT")
  topology_path = getenv("NETLAB_TOPOLOGY")
  topology_url = getenv("NETLAB_TOPOLOGY_URL")
  if topology_path:
    payload["topologyPath"] = topology_path
  if topology_url:
    payload["topologyUrl"] = topology_url
  if getenv("NETLAB_COLLECT_OUTPUT"):
    payload["collectOutput"] = getenv("NETLAB_COLLECT_OUTPUT")
  if getenv("NETLAB_COLLECT_TAR"):
    payload["collectTar"] = getenv("NETLAB_COLLECT_TAR")
  if getenv("NETLAB_COLLECT_CLEANUP", "").lower() == "true":
    payload["collectCleanup"] = True
  if getenv("NETLAB_CLEANUP", "").lower() == "true":
    payload["cleanup"] = True
  if getenv("NETLAB_INSTANCE"):
    payload["instance"] = getenv("NETLAB_INSTANCE")
  return payload


def request_json(url, payload=None, insecure=False):
  data = None
  headers = {"Content-Type": "application/json"}
  if payload is not None:
    data = json.dumps(payload).encode("utf-8")
  req = urllib.request.Request(url, data=data, headers=headers)
  context = None
  if url.startswith("https") and insecure:
    import ssl

    context = ssl._create_unverified_context()
  timeout = float(getenv("NETLAB_API_TIMEOUT", "15"))
  with urllib.request.urlopen(req, context=context, timeout=timeout) as resp:
    return json.loads(resp.read().decode("utf-8"))


def main():
  args, extra = parse_args(sys.argv[1:])
  for k, v in vars(args).items():
    _set_env_if_missing(k, v)
  apply_env_assignments(extra)

  api_url = getenv("NETLAB_API_URL", "").rstrip("/")
  if not api_url:
    sys.stderr.write("ERROR: NETLAB_API_URL is required\n")
    sys.exit(2)
  insecure = getenv("NETLAB_API_INSECURE", "true").lower() == "true"
  poll_interval = float(getenv("NETLAB_API_POLL_SECONDS", "2"))
  max_seconds = float(getenv("NETLAB_API_MAX_SECONDS", "0"))
  started = time.time()
  payload = build_payload()
  try:
    job = request_json(f"{api_url}/jobs", payload=payload, insecure=insecure)
  except HTTPError as exc:
    sys.stderr.write(exc.read().decode("utf-8"))
    sys.exit(2)
  except URLError as exc:
    sys.stderr.write(f"ERROR: failed to reach netlab API: {exc}\n")
    sys.exit(2)
  job_id = job["id"]
  last_log = ""
  while True:
    if max_seconds and (time.time() - started) > max_seconds:
      sys.stderr.write("ERROR: netlab API timed out\n")
      sys.exit(1)
    job = request_json(f"{api_url}/jobs/{job_id}", insecure=insecure)
    log_resp = request_json(f"{api_url}/jobs/{job_id}/log", insecure=insecure)
    log_text = log_resp.get("log", "")
    if log_text and log_text != last_log:
      diff = log_text[len(last_log) :]
      sys.stdout.write(diff)
      sys.stdout.flush()
      last_log = log_text
    state = job.get("state") or job.get("status")
    if state in ("success", "failed", "canceled"):
      if state != "success":
        sys.exit(1)
      return
    time.sleep(poll_interval)


if __name__ == "__main__":
  main()
`
}

func labppAPIRunnerScript() string {
	return `#!/usr/bin/env python3
import argparse
import json
import os
import sys
import time
import urllib.request
from urllib.error import HTTPError, URLError


def getenv(name, default=""):
  return os.getenv(name, default)


def _set_env_if_missing(name, value):
  if value is None:
    return
  value = str(value).strip()
  if not value:
    return
  if getenv(name, "").strip():
    return
  os.environ[name] = value


def parse_args(argv):
  p = argparse.ArgumentParser(description="Skyforge LabPP API runner")
  p.add_argument("--api-url", dest="LABPP_API_URL")
  p.add_argument("--api-insecure", dest="LABPP_API_INSECURE")
  p.add_argument("--action", dest="LABPP_ACTION")
  p.add_argument("--workspace", dest="LABPP_WORKSPACE")
  p.add_argument("--deployment", dest="LABPP_DEPLOYMENT")
  p.add_argument("--templates-root", dest="LABPP_TEMPLATES_ROOT")
  p.add_argument("--template", dest="LABPP_TEMPLATE")
  p.add_argument("--lab-path", dest="LABPP_LAB_PATH")
  p.add_argument("--thread-count", dest="LABPP_THREAD_COUNT")
  p.add_argument("--eve-url", dest="LABPP_EVE_URL")
  p.add_argument("--eve-username", dest="LABPP_EVE_USERNAME")
  p.add_argument("--eve-password", dest="LABPP_EVE_PASSWORD")
  args, extra = p.parse_known_args(argv)
  return args, extra


def apply_env_assignments(args):
  for a in args:
    if not isinstance(a, str):
      continue
    a = a.strip()
    if not a:
      continue
    if "=" not in a:
      continue
    k, v = a.split("=", 1)
    k = k.strip()
    v = v.strip()
    if not k:
      continue
    _set_env_if_missing(k, v)


def request(url, payload=None, insecure=False, content_type="application/json"):
  data = None
  headers = {}
  if payload is not None:
    data = json.dumps(payload).encode("utf-8")
    headers["Content-Type"] = content_type
  req = urllib.request.Request(url, data=data, headers=headers)
  context = None
  if url.startswith("https") and insecure:
    import ssl

    context = ssl._create_unverified_context()
  timeout = float(getenv("LABPP_API_TIMEOUT", "30"))
  with urllib.request.urlopen(req, context=context, timeout=timeout) as resp:
    raw = resp.read()
    return raw.decode("utf-8", errors="replace")


def request_json(url, payload=None, insecure=False):
  raw = request(url, payload=payload, insecure=insecure)
  return json.loads(raw) if raw else {}


def build_payload():
  action = (getenv("LABPP_ACTION", "E2E") or "E2E").strip()
  action = action.upper()
  lab_path = (getenv("LABPP_LAB_PATH", "") or "").strip()
  if lab_path and not lab_path.startswith("/"):
    lab_path = "/" + lab_path
  payload = {
    "action": action,
    "workspace": (getenv("LABPP_WORKSPACE", "").strip()
                   or getenv("LABPP_PROJECT", "").strip()),
    "deployment": getenv("LABPP_DEPLOYMENT", "").strip(),
    "templatesRoot": getenv("LABPP_TEMPLATES_ROOT", "").strip(),
    "template": getenv("LABPP_TEMPLATE", "").strip(),
  }
  if lab_path:
    payload["labPath"] = lab_path
  if getenv("LABPP_THREAD_COUNT", "").strip():
    try:
      payload["threadCount"] = int(getenv("LABPP_THREAD_COUNT", "").strip())
    except ValueError:
      pass

  eve_url = getenv("LABPP_EVE_URL", "").strip()
  eve_user = getenv("LABPP_EVE_USERNAME", "").strip()
  eve_pass = getenv("LABPP_EVE_PASSWORD", "")
  payload["eve"] = {"url": eve_url, "username": eve_user, "password": eve_pass}
  return payload


def normalize_log(raw):
  # getLog currently returns plain text. Handle the case where it returns JSON.
  raw = (raw or "").strip("\n")
  if raw.startswith("{") and raw.endswith("}"):
    try:
      parsed = json.loads(raw)
      if isinstance(parsed, dict) and isinstance(parsed.get("log"), str):
        return parsed.get("log", "")
    except Exception:
      pass
  raw = raw.replace("Lab path: Users/", "Lab path: /Users/")
  return raw + ("\n" if raw and not raw.endswith("\n") else "")


def main():
  args, extra = parse_args(sys.argv[1:])
  for k, v in vars(args).items():
    _set_env_if_missing(k, v)
  apply_env_assignments(extra)

  api_url = getenv("LABPP_API_URL", "").rstrip("/")
  if not api_url:
    sys.stderr.write("ERROR: LABPP_API_URL is required\n")
    sys.exit(2)
  insecure = getenv("LABPP_API_INSECURE", "false").lower() == "true"

  payload = build_payload()
  for key in ("workspace", "deployment", "templatesRoot", "template"):
    if not str(payload.get(key, "")).strip():
      sys.stderr.write(f"ERROR: LABPP_{key.upper()} is required\n")
      sys.exit(2)
  eve = payload.get("eve") or {}
  if not str(eve.get("url", "")).strip() or not str(eve.get("username", "")).strip() or not str(eve.get("password", "")).strip():
    sys.stderr.write("ERROR: LABPP_EVE_URL/LABPP_EVE_USERNAME/LABPP_EVE_PASSWORD are required\n")
    sys.exit(2)

  poll_interval = float(getenv("LABPP_API_POLL_SECONDS", "2"))
  max_seconds = float(getenv("LABPP_API_MAX_SECONDS", "0"))
  started = time.time()

  try:
    job = request_json(f"{api_url}/jobs", payload=payload, insecure=insecure)
  except HTTPError as exc:
    sys.stderr.write(exc.read().decode("utf-8", errors="replace"))
    sys.exit(2)
  except URLError as exc:
    sys.stderr.write(f"ERROR: failed to reach labpp API: {exc}\n")
    sys.exit(2)
  job_id = (job or {}).get("id")
  if not job_id:
    sys.stderr.write(f"ERROR: labpp job create returned no id: {job}\n")
    sys.exit(2)

  last_log = ""
  while True:
    if max_seconds and (time.time() - started) > max_seconds:
      sys.stderr.write("ERROR: labpp API timed out\n")
      sys.exit(1)

    job = request_json(f"{api_url}/jobs/{job_id}", insecure=insecure)
    status = (job.get("status") or job.get("state") or "").lower()

    try:
      raw_log = request(f"{api_url}/jobs/{job_id}/log", insecure=insecure)
      log_text = normalize_log(raw_log)
      if log_text and log_text != last_log:
        diff = log_text[len(last_log) :]
        sys.stdout.write(diff)
        sys.stdout.flush()
        last_log = log_text
    except Exception:
      pass

    if status in ("success", "succeeded", "failed", "canceled", "cancelled"):
      if status not in ("success", "succeeded"):
        err = job.get("error") or ""
        if err:
          sys.stderr.write(str(err) + "\n")
        sys.exit(1)
      return
    time.sleep(poll_interval)


if __name__ == "__main__":
  main()
`
}

func containerlabAPIRunnerScript() string {
	return `#!/usr/bin/env python3
import argparse
import json
import os
import sys
import urllib.request
from urllib.error import HTTPError, URLError


def getenv(name, default=""):
  return os.getenv(name, default)


def _set_env_if_missing(name, value):
  if value is None:
    return
  value = str(value).strip()
  if not value:
    return
  if getenv(name, "").strip():
    return
  os.environ[name] = value


def parse_args(argv):
  p = argparse.ArgumentParser(description="Skyforge Containerlab API runner")
  p.add_argument("--api-url", dest="CONTAINERLAB_API_URL")
  p.add_argument("--api-insecure", dest="CONTAINERLAB_API_INSECURE")
  p.add_argument("--token", dest="CONTAINERLAB_TOKEN")
  p.add_argument("--action", dest="CONTAINERLAB_ACTION")
  p.add_argument("--lab-name", dest="CONTAINERLAB_LAB_NAME")
  p.add_argument("--topology-url", dest="CONTAINERLAB_TOPOLOGY_URL")
  p.add_argument("--topology-json", dest="CONTAINERLAB_TOPOLOGY_JSON")
  p.add_argument("--reconfigure", dest="CONTAINERLAB_RECONFIGURE")
  args, extra = p.parse_known_args(argv)
  return args, extra


def apply_env_assignments(args):
  for a in args:
    if not isinstance(a, str):
      continue
    a = a.strip()
    if not a:
      continue
    if "=" not in a:
      continue
    k, v = a.split("=", 1)
    k = k.strip()
    v = v.strip()
    if not k:
      continue
    _set_env_if_missing(k, v)


def request_json(url, payload=None, token=""):
  data = None
  headers = {"Content-Type": "application/json"}
  if token:
    headers["Authorization"] = "Bearer " + token
  if payload is not None:
    data = json.dumps(payload).encode("utf-8")
  req = urllib.request.Request(url, data=data, headers=headers)
  context = None
  if url.startswith("https") and getenv("CONTAINERLAB_API_INSECURE", "false").lower() == "true":
    import ssl
    context = ssl._create_unverified_context()
  timeout = float(getenv("CONTAINERLAB_API_TIMEOUT", "20"))
  with urllib.request.urlopen(req, context=context, timeout=timeout) as resp:
    body = resp.read().decode("utf-8")
    if not body:
      return {}
    return json.loads(body)


def main():
  args, extra = parse_args(sys.argv[1:])
  for k, v in vars(args).items():
    _set_env_if_missing(k, v)
  apply_env_assignments(extra)

  api_url = getenv("CONTAINERLAB_API_URL", "").rstrip("/")
  if not api_url:
    sys.stderr.write("ERROR: CONTAINERLAB_API_URL is required\n")
    sys.exit(2)
  token = getenv("CONTAINERLAB_TOKEN", "").strip()
  action = (getenv("CONTAINERLAB_ACTION") or "deploy").lower()
  lab_name = getenv("CONTAINERLAB_LAB_NAME", "").strip()
  topology_url = getenv("CONTAINERLAB_TOPOLOGY_URL", "").strip()
  topology_json = getenv("CONTAINERLAB_TOPOLOGY_JSON", "").strip()
  reconfigure = getenv("CONTAINERLAB_RECONFIGURE", "false").lower() == "true"

  try:
    if action in ("deploy", "create", "start", "up"):
      if topology_url and topology_json:
        sys.stderr.write("ERROR: both topology URL and JSON provided\n")
        sys.exit(2)
      if not topology_url and not topology_json:
        sys.stderr.write("ERROR: topology URL or JSON is required\n")
        sys.exit(2)
      payload = {}
      if topology_url:
        payload["topologySourceUrl"] = topology_url
      else:
        payload["topologyContent"] = json.loads(topology_json)
      url = f"{api_url}/api/v1/labs"
      if reconfigure:
        url += "?reconfigure=true"
      resp = request_json(url, payload=payload, token=token)
      sys.stdout.write(json.dumps(resp, indent=2, sort_keys=True) + "\n")
      return
    if action in ("destroy", "delete", "down", "stop"):
      if not lab_name:
        sys.stderr.write("ERROR: lab name is required for destroy\n")
        sys.exit(2)
      url = f"{api_url}/api/v1/labs/{lab_name}"
      resp = request_json(url, payload=None, token=token)
      sys.stdout.write(json.dumps(resp, indent=2, sort_keys=True) + "\n")
      return
    if action == "info":
      if not lab_name:
        sys.stderr.write("ERROR: lab name is required for info\n")
        sys.exit(2)
      url = f"{api_url}/api/v1/labs/{lab_name}"
      resp = request_json(url, payload=None, token=token)
      sys.stdout.write(json.dumps(resp, indent=2, sort_keys=True) + "\n")
      return
    sys.stderr.write("ERROR: unknown action\n")
    sys.exit(2)
  except HTTPError as exc:
    sys.stderr.write(exc.read().decode("utf-8"))
    sys.exit(2)
  except URLError as exc:
    sys.stderr.write(f"ERROR: failed to reach containerlab API: {exc}\n")
    sys.exit(2)


if __name__ == "__main__":
  main()
`
}
