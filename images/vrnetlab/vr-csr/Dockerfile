FROM ghcr.io/forwardnetworks/vrnetlab/vr-csr:17.03.04

# Align launcher defaults with netlab/containerlab expectations.
RUN sed -i 's/default="vrnetlab"/default="vagrant"/' /launch.py \
 && sed -i 's/default="VR-netlab9"/default="vagrant"/' /launch.py
