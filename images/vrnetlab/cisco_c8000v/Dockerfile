FROM ghcr.io/forwardnetworks/vrnetlab/cisco_c8000v:17.16.01a

# Align launcher defaults with netlab/containerlab expectations.
RUN sed -i 's/default="vrnetlab"/default="vagrant"/' /launch.py \
 && sed -i 's/default="VR-netlab9"/default="vagrant"/' /launch.py
