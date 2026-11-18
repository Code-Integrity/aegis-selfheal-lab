import os, time, json, shutil
from datetime import datetime, timezone
import docker

ALLOWED_TARGET_CONTAINER = os.environ.get("TARGET_CONTAINER", "demo-target-node")
ISOLATED_NETWORK_NAME = os.environ.get("ISOLATED_NETWORK", "aegis-selfheal-lab_isolated-net")
LOG_PATH = os.environ.get("LOG_PATH", "/logs/events.jsonl")
REPORT_DIR, BACKUP_DIR, RESTORE_DIR = "/logs", "/backup_data", "/restore_target"

client = docker.from_env()

def restore_clean_data():
    print("[Orchestrator] 3. Wiping tampered data and restoring from clean backup...", flush=True)
    for item in os.listdir(RESTORE_DIR):
        p = os.path.join(RESTORE_DIR, item)
        shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
    for item in os.listdir(BACKUP_DIR):
        s, d = os.path.join(BACKUP_DIR, item), os.path.join(RESTORE_DIR, item)
        shutil.copytree(s, d) if os.path.isdir(s) else shutil.copy2(s, d)

def generate_incident_report(events: list, start_time: float, end_time: float):
    rto = round(end_time - start_time, 2)
    now_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(REPORT_DIR, f"INCIDENT_REPORT_{now_str}.md")
    lines = [
        "# サイバーインシデント自動検知・隔離・復旧レポート", "",
        f"- **生成日時 (UTC)**: {datetime.now(timezone.utc).isoformat()}",
        f"- **対象システム**: `{ALLOWED_TARGET_CONTAINER}`",
        f"- **自動復旧所要時間 (RTO)**: **{rto} 秒**",
        "- **最終ステータス**: **RECOVERED（完全隔離・クリーン再構築完了）**", "",
        "## 1. 検知された低レイヤー侵害指標 (IoC) とAI推論結果", ""
    ]
    for idx, ev in enumerate(events, 1):
        lines.extend([
            f"### イベント #{idx}: `{ev.get('event_type')}`",
            f"- **発生時刻**: `{ev.get('timestamp')}`",
            f"- **MITRE ATT&CK**: `{ev.get('mitre_attck')}`",
            f"- **AI脅威分析**: {ev.get('ai_reasoning')}",
            f"- **生データ**: `{json.dumps(ev.get('raw_telemetry'), ensure_ascii=False)}`", ""
        ])
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"[Orchestrator] Incident Report generated: {report_path}", flush=True)

def execute_containment_and_recovery(trigger_events: list):
    start_time = time.time()
    print("\n" + "="*55, flush=True)
    print("🚨 [AUTO-RESPONSE TRIGGERED] Containment & Recovery!", flush=True)
    print("="*55, flush=True)
    try:
        c = client.containers.get(ALLOWED_TARGET_CONTAINER)
        print("[Orchestrator] 1. Disconnecting network...", flush=True)
        try:
            client.networks.get(ISOLATED_NETWORK_NAME).disconnect(c, force=True)
        except Exception:
            pass

        print("[Orchestrator] 2. Killing compromised container...", flush=True)
        c.kill()
        restore_clean_data()

        print("[Orchestrator] 4. Rebuilding & restarting container...", flush=True)
        c.restart()
        client.networks.get(ISOLATED_NETWORK_NAME).connect(c, ipv4_address="172.28.1.10")

        end_time = time.time()
        print(f"✅ [RECOVERY COMPLETE] Restored in {end_time - start_time:.2f}s!\n", flush=True)
        generate_incident_report(trigger_events, start_time, end_time)
    except Exception as e:
        print(f"[Orchestrator][ERROR] {e}", flush=True)

def watch_alerts():
    print(f"[Orchestrator] Watching {LOG_PATH}...", flush=True)
    processed_lines = 0
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH, "r", encoding="utf-8") as f:
            processed_lines = len(f.readlines())

    buf, last_t = [], 0
    while True:
        if os.path.exists(LOG_PATH):
            with open(LOG_PATH, "r", encoding="utf-8") as f:
                lines = f.readlines()
            if len(lines) > processed_lines:
                for line in lines[processed_lines:]:
                    try:
                        ev = json.loads(line.strip())
                        if ev.get("recommended_action") == "ISOLATE_AND_PURGE_CONTAINER":
                            buf.append(ev)
                            last_t = time.time()
                    except Exception:
                        pass
                processed_lines = len(lines)

        if buf and (time.time() - last_t > 1.5):
            execute_containment_and_recovery(buf)
            buf = []
        time.sleep(0.2)

if __name__ == "__main__":
    watch_alerts()
