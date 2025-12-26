package skyforge

func netlabAPIRunnerScript() string {
	return `#!/usr/bin/env python3
import json
import os
import sys
import time
import urllib.request
from urllib.error import HTTPError, URLError


def getenv(name, default=""):
  return os.getenv(name, default)


def build_payload():
  user = getenv("NETLAB_USER") or getenv("NETLAB_SSH_USER") or getenv("USER") or "netlab"
  project = getenv("NETLAB_PROJECT") or getenv("NETLAB_PROJECT_SLUG") or getenv("NETLAB_PROJECT_ID") or "project"
  deployment = getenv("NETLAB_DEPLOYMENT") or getenv("NETLAB_DEPLOYMENT_ID") or getenv("NETLAB_MULTILAB_ID") or "deployment"
  workspace_root = getenv("NETLAB_WORKSPACE_ROOT") or f"/home/{user}/netlab"
  action = (getenv("NETLAB_ACTION") or "up").lower()
  payload = {
    "action": action,
    "user": user,
    "project": project,
    "deployment": deployment,
    "workspaceRoot": workspace_root,
  }
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
