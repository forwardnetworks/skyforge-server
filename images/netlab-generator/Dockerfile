FROM ghcr.io/forwardnetworks/skyforge-netlab-generator:20260206-netlaboutput

# Install netlab from the vendored fork in this repo so Skyforge can carry
# k8s/clabernetes-specific fixes without depending on an external ref.
#
# IMPORTANT: build context must be the repo root (.) so this COPY works.
COPY vendor/netlab /tmp/netlab
RUN python3 -m pip install --no-cache-dir --upgrade /tmp/netlab

COPY components/server/images/netlab-generator/defaults.yml /etc/netlab/defaults.yml
COPY components/server/images/netlab-generator/netlab_generator.py /app/netlab_generator.py
