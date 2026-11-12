# Pinned by digest: ubuntu:24.04 is a moving tag, the digest is the actual
# release this lab was verified against. This image is also the base for the
# domain-joined endpoint image, which is why client tools (smbclient,
# cifs-utils) are installed here instead of in a second apt layer.
FROM ubuntu:24.04@sha256:2198e4c65076e9cb0b3d695219df667c0e3b0072da64ca3c2648aca17dcecaf5

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      samba winbind samba-ad-provision samba-dsdb-modules samba-vfs-modules krb5-user \
      ldb-tools ldap-utils dnsutils iproute2 smbclient cifs-utils acl attr && \
    rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod 0555 /entrypoint.sh

HEALTHCHECK --interval=20s --timeout=10s --start-period=90s --retries=3 \
  CMD samba-tool domain info 127.0.0.1 >/dev/null 2>&1 || exit 1

ENTRYPOINT ["/entrypoint.sh"]
