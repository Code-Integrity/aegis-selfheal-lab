import os, subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)
DATA_DIR = "/app/critical_data"

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy"})

@app.route("/data", methods=["GET"])
def read_data():
    files = {}
    for fname in os.listdir(DATA_DIR):
        fpath = os.path.join(DATA_DIR, fname)
        if os.path.isfile(fpath):
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                files[fname] = f.read()
    return jsonify(files)

@app.route("/api/diag", methods=["POST"])
def diagnostics():
    target = request.json.get("host", "127.0.0.1")
    cmd = f"ping -c 1 {target}"
    return jsonify({"executed": cmd, "output": subprocess.getoutput(cmd)})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
