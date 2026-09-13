FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      samba winbind samba-ad-provision samba-dsdb-modules samba-vfs-modules krb5-user \
      ldb-tools ldap-utils dnsutils iproute2 smbclient cifs-utils acl attr && \
    rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
