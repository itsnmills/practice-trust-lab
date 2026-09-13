FROM alpine:3.20
RUN apk add --no-cache python3
WORKDIR /app
COPY app.py /app/app.py
EXPOSE 8095
CMD ["python3", "/app/app.py"]
