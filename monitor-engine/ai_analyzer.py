import json
from datetime import datetime, timezone

class SecurityAIAnalyzer:
    def __init__(self):
        self.incident_history = []

    def analyze_event(self, event_type: str, details: dict) -> dict:
        timestamp = datetime.now(timezone.utc).isoformat()
        severity = "CRITICAL"
        confidence = 0.96
        reasoning = ""
        mitre_tactic = ""

        if event_type == "SUSPICIOUS_PROCESS_SPAWN":
            parent = details.get("parent_comm", "unknown")
            child = details.get("cmdline", "unknown")
            mitre_tactic = "T1059 (Command and Scripting Interpreter)"
            reasoning = f"異常なプロセスツリーを検知: 業務プロセス({parent})から不審な子プロセス({child})が生成されました。"
        elif event_type == "CRITICAL_FILE_TAMPERING":
            filepath = details.get("file", "unknown")
            confidence = 0.99
            mitre_tactic = "T1486 (Data Encrypted for Impact / Tampering)"
            reasoning = f"重要業務データの不正書き換えを検知: inotifyにより '{filepath}' への直接書き込みを確認。"
        elif event_type == "UNAUTHORIZED_C2_CONNECTION":
            remote_ip = details.get("remote_ip", "unknown")
            remote_port = details.get("remote_port", "unknown")
            proc_name = details.get("process_comm", "unknown")
            confidence = 0.98
            mitre_tactic = "T1071 (Application Layer Protocol / C2 Beacon)"
            reasoning = f"不正アウトバウンド通信を検知: プロセス({proc_name})が未承認IP({remote_ip}:{remote_port})へ接続しました。"

        self.incident_history.append(event_type)
        if len(set(self.incident_history)) >= 2:
            confidence = 1.00
            reasoning += " 【複合攻撃判定】複数フェーズの連続発生によりシステム乗っ取りが確定しました。"

        return {
            "timestamp": timestamp,
            "event_type": event_type,
            "severity": severity,
            "confidence_score": confidence,
            "mitre_attck": mitre_tactic,
            "ai_reasoning": reasoning,
            "recommended_action": "ISOLATE_AND_PURGE_CONTAINER",
            "raw_telemetry": details
        }
