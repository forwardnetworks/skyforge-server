FROM ghcr.io/forwardnetworks/skyforge-netlab-generator:20260206-netlaboutput

COPY netlab_apply.py /app/netlab_apply.py

ENV ANSIBLE_COLLECTIONS_PATH=/opt/ansible/collections
ENV ANSIBLE_COLLECTIONS_PATHS=/opt/ansible/collections

# Netlab `initial` still relies on Ansible for many device types.
# Keep the applier image self-contained (no runtime installs).
RUN python3 -m pip install --no-cache-dir "ansible-core==2.17.8" \
  && ansible-galaxy collection install -p "${ANSIBLE_COLLECTIONS_PATH}" \
    ansible.netcommon \
    arista.eos \
    cisco.ios \
    cisco.nxos \
    junipernetworks.junos

ENTRYPOINT ["/usr/bin/env","python3","/app/netlab_apply.py"]
