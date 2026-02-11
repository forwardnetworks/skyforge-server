FROM ghcr.io/forwardnetworks/vrnetlab/vr-n9kv:9.3.8

# Align launcher defaults with netlab/containerlab expectations for N9Kv.
# Upstream image defaults may vary by build; pin to admin/admin for Skyforge.
RUN sed -i 's/default="vrnetlab"/default="admin"/' /launch.py \
 && sed -i 's/default="VR-netlab9"/default="admin"/' /launch.py
