FROM ghcr.io/forwardnetworks/vrnetlab/juniper_vjunosevolved:25.2R1.8-EVO

# Align launcher defaults with netlab/containerlab expectations.
RUN sed -i 's/default="vrnetlab"/default="admin"/' /launch.py \
 && sed -i 's/default="VR-netlab9"/default="admin@123"/' /launch.py
