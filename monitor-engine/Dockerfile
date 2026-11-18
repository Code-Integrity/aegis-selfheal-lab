FROM python:3.11-slim
WORKDIR /monitor
RUN pip install --no-cache-dir inotify_simple
COPY ai_analyzer.py /monitor/ai_analyzer.py
COPY monitor.py /monitor/monitor.py
CMD ["python3", "-u", "/monitor/monitor.py"]
