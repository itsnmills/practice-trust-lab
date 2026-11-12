# Endpoint image: domain-joined workstation built from the pinned DC image so
# the Samba client tools match the domain controller exactly.
FROM practice-lab-dc:0.1

COPY entrypoint.sh /endpoint-entrypoint.sh
RUN chmod 0555 /endpoint-entrypoint.sh

HEALTHCHECK --interval=20s --timeout=5s --start-period=60s --retries=3 \
  CMD test -f /var/lib/samba/.joined

ENTRYPOINT ["/endpoint-entrypoint.sh"]
