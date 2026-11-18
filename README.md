# Aegis Self-Heal Lab 🛡️

**OS Low-Level Kernel Monitoring & Autonomous Cyber Resilience Sandbox**

> **⚠️ Disclaimer**
> This repository is designed strictly for security research, educational purposes, and cyber resilience validation inside an isolated local Docker network (`internal: true`). It contains **no real malware samples**—only benign, custom-written C programs simulating system call behaviors (process spawning, file modification, and internal socket connections).

---

## 1. Overview & Background

With the rapid rise of sophisticated system-hijacking attacks targeting enterprise and manufacturing (OT/IT) environments, traditional perimeter defenses (WAF/firewalls) are no longer sufficient once an attacker gains a foothold.

**Aegis Self-Heal Lab** demonstrates a complete, automated **Cyber Resilience Lifecycle** safely on a local machine:

1. **Compromise Simulation**: Exploits a simulated web-layer vulnerability to execute a native C binary, triggering kernel-level anomalies (unauthorized child processes, critical data tampering, and C2 socket beacons).
2. **Low-Level Kernel & Process Detection**: Monitors OS internals directly via Linux `/proc` filesystem inspection and kernel `inotify` events—correlating indicators of compromise (IoCs) with MITRE ATT&CK tactics.
3. **Autonomous Containment & Recovery**: Automatically isolates the compromised container from the network, terminates malicious processes (`SIGKILL`), restores tampered critical data from read-only backups, rebuilds the service, and generates a forensic incident report.

---

## 2. System Architecture

All components operate within a strictly isolated Docker bridge network (`172.28.1.0/24`, `internal: true`) with zero external internet routing and least-privilege container hardening (`cap_drop: ALL`, `no-new-privileges`).

```text
+-------------------------------------------------------------------+

| Isolated Docker Network (172.28.1.0/24 | internal: true)          |
|                                                                   |
|  [1. Target Node]  ---(C2 Beacon:4444)--->  [2. Mock C2 Server]   |
|  (172.28.1.10)                              (172.28.1.99)         |
|        |                                                          |
|        +-- Shared PID Namespace & Read-Only Volume                |
|        v                                                          |
|  [3. Low-Level Monitor & AI Analyzer] (network_mode: none)        |
|        |  (/proc scan + /proc/net/tcp + kernel inotify)           |
|        v  (JSONL Telemetry & Threat Reasoning)                    |
|  [4. Auto-Containment & Recovery Orchestrator]                    |
|           (Network Disconnect -> SIGKILL -> Restore -> Rebuild)   |
+-------------------------------------------------------------------+
```

### Core Components

- **`target-node`**: Simulated production control API holding critical manufacturing schedules (`production_schedule.csv`) and PLC configurations (`plc_config.json`).
- **`attacker-sim` (`mock-c2` / `payload.c`)**: Benign C-language payload reproducing `fork()`/`execve()` process spawning, file overwriting, and TCP socket C2 beacons to an internal mock server.
- **`monitor-engine`**: Network-airgapped observer (`network_mode: none`) sharing the target's PID namespace to detect process tree anomalies, socket inodes (`/proc/net/tcp`), and kernel `inotify` file events in real time.
- **`orchestrator`**: Automated response engine executing network disconnection, process termination, clean volume restoration, container rebuild, and Markdown incident report generation.

---

## 3. Proof of Concept (PoC) Results

Validated on a local Linux (Ubuntu / WSL2) + Docker Engine environment:

- **Real-Time Low-Level Detection**:
  - Kernel `inotify` immediately captured unauthorized write operations on critical manufacturing files (`CRITICAL_FILE_TAMPERING`).
  - `/proc` inspection detected abnormal child process execution (`SUSPICIOUS_PROCESS_SPAWN` / MITRE ATT&CK `T1059`), escalating multi-stage correlation confidence to `100%`.
- **Recovery Time Objective (RTO)**:
  - Full automated containment, clean data restoration, and container rebuild completed in **`0.72 seconds`**.
- **Data Integrity**:
  - Critical files overwritten with `ENCRYPTED_BY_SIMULATOR_DEMO_PAYLOAD_0xDEADBEAF` were automatically restored to their original clean state with zero data loss upon recovery.

---

## 4. Quick Start

```bash
# 1. Build and launch the isolated sandbox
docker compose up -d --build

# 2. Stream real-time low-level detection & recovery logs (in a separate terminal)
docker compose logs -f monitor-engine orchestrator

# 3. Trigger the benign attack simulation
docker cp demo-mock-c2:/sim/sys_updater_bin ./sys_updater_bin
docker cp ./sys_updater_bin demo-target-node:/tmp/.cache/sys_updater_bin
rm ./sys_updater_bin

docker exec demo-target-node curl -s -X POST http://localhost:8080/api/diag \
  -H "Content-Type: application/json" \
  -d '{"host": "127.0.0.1; /tmp/.cache/sys_updater_bin"}'

# 4. Verify data restoration and inspect the generated incident report
docker exec demo-target-node curl -s http://localhost:8080/data
cat shared-logs/INCIDENT_REPORT_*.md

# 5. Tear down the environment
docker compose down -v
```
