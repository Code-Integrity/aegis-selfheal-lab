FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
RUN pip install --no-cache-dir flask
COPY critical_data /app/clean_backup
COPY app.py /app/app.py
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh && mkdir -p /tmp/.cache
EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]
