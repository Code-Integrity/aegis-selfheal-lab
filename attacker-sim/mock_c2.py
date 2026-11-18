import socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 4444))
    s.listen()
    print("[Mock-C2] Listening on 4444...", flush=True)
    while True:
        conn, addr = s.accept()
        with conn:
            data = conn.recv(1024)
            if data: print(f"[Mock-C2] Beacon from {addr}: {data.decode().strip()}", flush=True)
