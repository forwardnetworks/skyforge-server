FROM ghcr.io/forwardnetworks/skyforge-netlab-generator:20260206-netlaboutput

ARG NETLAB_REF=00cadffe0d5ec999a81028e82bce913e2aa7d14b
RUN python3 -m pip install --no-cache-dir --upgrade "networklab @ git+https://github.com/forwardnetworks/netlab.git@${NETLAB_REF}"

COPY defaults.yml /etc/netlab/defaults.yml
COPY netlab_generator.py /app/netlab_generator.py
