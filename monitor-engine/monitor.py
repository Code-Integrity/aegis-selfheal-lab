import os, time, json, socket, struct, threading
from inotify_simple import INotify, flags
from ai_analyzer import SecurityAIAnalyzer

LOG_PATH = os.environ.get("LOG_PATH", "/logs/events.jsonl")
WATCH_DIR = "/watch/critical_data"
SUSPICIOUS_KEYWORDS = ["/bin/sh", "sys_updater_bin", "/tmp/.cache", "id;", "ps aux"]
C2_SUSPICIOUS_PORT = 4444

analyzer = SecurityAIAnalyzer()
log_lock = threading.Lock()
alerted_pids = set()
alerted_sockets = set()

def emit_alert(event_type: str, details: dict):
    report = analyzer.analyze_event(event_type, details)
    with log_lock:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(report, ensure_ascii=False) + "\n")
    print(f"\n[ALERT][{report['severity']}] {event_type} ({report['confidence_score']*100:.0f}%)", flush=True)
    print(f"  └─ AI推論: {report['ai_reasoning']}", flush=True)

def get_proc_info(pid: str):
    try:
        with open(f"/proc/{pid}/comm", "r") as f: comm = f.read().strip()
        with open(f"/proc/{pid}/cmdline", "rb") as f: cmdline = f.read().replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
        with open(f"/proc/{pid}/stat", "r") as f:
            parts = f.read().split()
            ppid = parts if len(parts) > 3 else "0"
        return comm, cmdline, ppid
    except Exception:
        return None, None, None

def monitor_processes():
    print("[Monitor] Starting /proc process tree sensor...", flush=True)
    while True:
        try:
            for pid in os.listdir("/proc"):
                if not pid.isdigit() or pid in alerted_pids: continue
                comm, cmdline, ppid = get_proc_info(pid)
                if not comm: continue
                if any(kw in f"{comm} {cmdline}" for kw in SUSPICIOUS_KEYWORDS):
                    parent_comm, _, _ = get_proc_info(ppid)
                    alerted_pids.add(pid)
                    emit_alert("SUSPICIOUS_PROCESS_SPAWN", {"pid": int(pid), "comm": comm, "parent_comm": parent_comm or "unknown", "cmdline": cmdline})
        except Exception: pass
        time.sleep(0.1)

def hex_to_ip_port(hex_addr: str):
    ip_hex, port_hex = hex_addr.split(":")
    return socket.inet_ntoa(struct.pack("<L", int(ip_hex, 16))), int(port_hex, 16)

def find_pid_by_inode(target_inode: str):
    for pid in os.listdir("/proc"):
        if not pid.isdigit(): continue
        try:
            for fd in os.listdir(f"/proc/{pid}/fd"):
                if f"socket:[{target_inode}]" in os.readlink(f"/proc/{pid}/fd/{fd}"):
                    comm, _, _ = get_proc_info(pid)
                    return pid, comm
        except Exception: continue
    return "unknown", "unknown"

def monitor_network():
    print("[Monitor] Starting /proc/net/tcp socket sensor...", flush=True)
    while True:
        try:
            with open("/proc/net/tcp", "r") as f: lines = f.readlines()[1:]
            for line in lines:
                parts = line.split()
                if len(parts) < 10: continue
                rem_ip, rem_port = hex_to_ip_port(parts)
                if rem_port == C2_SUSPICIOUS_PORT and parts in ("01", "02"):
                    sock_key = f"{rem_ip}:{rem_port}:{parts}"
                    if sock_key not in alerted_sockets:
                        alerted_sockets.add(sock_key)
                        pid, comm = find_pid_by_inode(parts)
                        emit_alert("UNAUTHORIZED_C2_CONNECTION", {"pid": pid, "process_comm": comm, "remote_ip": rem_ip, "remote_port": rem_port})
        except Exception: pass
        time.sleep(0.2)

def monitor_files():
    print(f"[Monitor] Starting kernel inotify sensor on {WATCH_DIR}...", flush=True)
    while not os.path.exists(WATCH_DIR): time.sleep(0.5)
    inotify = INotify()
    inotify.add_watch(WATCH_DIR, flags.MODIFY | flags.CREATE | flags.DELETE | flags.MOVED_TO)
    time.sleep(1.5)
    while True:
        for event in inotify.read(timeout=500):
            if event.name:
                emit_alert("CRITICAL_FILE_TAMPERING", {"directory": WATCH_DIR, "file": event.name})

if __name__ == "__main__":
    print("=== Low-Level Kernel & Process Monitor Engine Started ===", flush=True)
    threading.Thread(target=monitor_processes, daemon=True).start()
    threading.Thread(target=monitor_network, daemon=True).start()
    threading.Thread(target=monitor_files, daemon=True).start()
    while True: time.sleep(1)
