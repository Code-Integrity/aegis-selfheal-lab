FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /sim
COPY mock_c2.py /sim/mock_c2.py
COPY payload.c /sim/payload.c
RUN gcc -O2 -Wall /sim/payload.c -o /sim/sys_updater_bin
CMD ["python3", "/sim/mock_c2.py"]
