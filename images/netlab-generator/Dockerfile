FROM ghcr.io/forwardnetworks/skyforge-netlab-generator:20260206-netlaboutput

ARG NETLAB_REF=0e06f20cdb0b39d659f4cb974b379042e11ca184
RUN python3 -m pip install --no-cache-dir --upgrade "networklab @ git+https://github.com/forwardnetworks/netlab.git@${NETLAB_REF}"

COPY defaults.yml /etc/netlab/defaults.yml
COPY netlab_generator.py /app/netlab_generator.py
