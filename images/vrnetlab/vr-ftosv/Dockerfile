# NOTE: we intentionally base on the amd64 :latest digest here.
# The "10.6.1.0.24V" tag in GHCR has historically been arm64-only.
FROM ghcr.io/forwardnetworks/vrnetlab/vr-ftosv:latest

COPY launch.py /launch.py
RUN chmod 755 /launch.py
