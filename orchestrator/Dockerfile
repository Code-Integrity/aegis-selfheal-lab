FROM python:3.11-slim
WORKDIR /orchestrator
RUN pip install --no-cache-dir docker
COPY recover.py /orchestrator/recover.py
CMD ["python3", "-u", "/orchestrator/recover.py"]
