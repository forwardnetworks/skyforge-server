FROM ghcr.io/forwardnetworks/vrnetlab/cisco_vios:15.9.3

COPY launch.py /launch.py
RUN chmod 755 /launch.py

# In Kubernetes, QEMU usernet hostfwd accepts connections on the pod IP, but the
# IOSv SSH banner often never arrives unless the client is local to the network
# namespace (localhost). Bind hostfwd listeners to 127.0.0.1 and let /launch.py
# expose a pod-IP listener that forwards locally.
RUN sed -i \
    -e 's/hostfwd=tcp:0\.0\.0\.0:/hostfwd=tcp:127\.0\.0\.1:/g' \
    -e 's/hostfwd=udp:0\.0\.0\.0:/hostfwd=udp:127\.0\.0\.1:/g' \
    /vrnetlab.py
