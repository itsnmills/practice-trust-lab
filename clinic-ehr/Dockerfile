# Syntax: the base image is pinned by digest so a rebuild gets the same Alpine
# release even after the tag moves. Keep the tag for readability.
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

RUN apk add --no-cache python3 \
 && addgroup -S -g 10001 app \
 && adduser -S -D -H -u 10001 -G app app \
 && mkdir -p /data \
 && chown 10001:10001 /data

WORKDIR /app
COPY app.py /app/app.py

USER 10001:10001
EXPOSE 8095

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8095/healthz', timeout=3).read()"

CMD ["python3", "/app/app.py"]
