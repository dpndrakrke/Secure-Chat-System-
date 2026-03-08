import socket
import ssl
import threading
import json
import time
import os
import base64
import hashlib
from collections import deque

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = "0.0.0.0"
PORT = 5050

CERT_FILE = "server_cert.pem"
KEY_FILE  = "server_key.pem"

MAX_CLOCK_SKEW = 15
NONCE_TTL = 60
RATE_WINDOW = 10
RATE_MAX_MSGS = 25

USERS_FILE = "users.json"
SERVER_SALT = b"ST5062CEM_CHAT_SALT_v1"

# -------------------------
# Robust JSON line framing
# -------------------------
class LineJSON:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = b""

    def recv(self) -> dict | None:
        while b"\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                return None
            self.buf += chunk
        line, _, self.buf = self.buf.partition(b"\n")
        try:
            return json.loads(line.decode("utf-8"))
        except json.JSONDecodeError:
            return None

    def send(self, obj: dict) -> None:
        data = (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")
        self.sock.sendall(data)

# -------------------------
# Users
# -------------------------
def pbkdf2_hash_b64(password: str, salt: bytes, iters: int = 200_000) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
    return base64.b64encode(dk).decode("utf-8")

def load_users() -> dict:
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_users(users: dict) -> None:
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)

USERS = load_users()

def derive_session_key(password: str, user_salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        user_salt + SERVER_SALT,
        200_000
    )

# -------------------------
# Replay + rate limit
# -------------------------
nonce_seen: dict[str, float] = {}
nonce_lock = threading.Lock()

rate_map: dict[str, deque] = {}
rate_lock = threading.Lock()

def cleanup_nonce_cache():
    now = time.time()
    with nonce_lock:
        dead = [n for n, ts in nonce_seen.items() if now - ts > NONCE_TTL]
        for n in dead:
            del nonce_seen[n]

def rate_ok(addr: str) -> bool:
    now = time.time()
    with rate_lock:
        dq = rate_map.setdefault(addr, deque())
        while dq and now - dq[0] > RATE_WINDOW:
            dq.popleft()
        if len(dq) >= RATE_MAX_MSGS:
            return False
        dq.append(now)
        return True

# -------------------------
# AES-GCM decrypt
# -------------------------
def aesgcm_decrypt(key: bytes, nonce_b64: str, ct_b64: str, aad: bytes) -> str | None:
    try:
        nonce = base64.b64decode(nonce_b64)
        ct = base64.b64decode(ct_b64)
        pt = AESGCM(key).decrypt(nonce, ct, aad)
        return pt.decode("utf-8", errors="replace")
    except Exception:
        return None

# -------------------------
# Connected clients + single-session enforcement
# -------------------------
clients: list[tuple[LineJSON, str]] = []
clients_lock = threading.Lock()

active_users = set()
active_lock = threading.Lock()

def broadcast(sender: str, text: str):
    msg = {"type": "chat", "from": sender, "text": text, "ts": int(time.time())}
    with clients_lock:
        for lj, _u in list(clients):
            try:
                lj.send(msg)
            except Exception:
                pass

def handle_client(conn: socket.socket, addr):
    addr_str = f"{addr[0]}:{addr[1]}"
    lj = LineJSON(conn)

    username = None
    session_key = None

    try:
        first = lj.recv()
        if not first or first.get("type") not in {"register", "login"}:
            lj.send({"type": "error", "msg": "Invalid first request."})
            return

        req_type = first["type"]
        uname = (first.get("username") or "").strip()
        pwd = first.get("password") or ""

        if not uname or not pwd:
            lj.send({"type": "error", "msg": "Username/password required."})
            return

        global USERS

        if req_type == "register":
            if uname in USERS:
                lj.send({"type": "error", "msg": "User already exists."})
                return
            user_salt = os.urandom(16)
            USERS[uname] = {
                "salt": base64.b64encode(user_salt).decode("utf-8"),
                "hash": pbkdf2_hash_b64(pwd, user_salt),
            }
            save_users(USERS)
            lj.send({"type": "ok", "msg": "Registered. Now login."})
            return

        # login
        if uname not in USERS:
            lj.send({"type": "error", "msg": "Invalid login."})
            return

        user_salt = base64.b64decode(USERS[uname]["salt"])
        expected = USERS[uname]["hash"]
        if pbkdf2_hash_b64(pwd, user_salt) != expected:
            lj.send({"type": "error", "msg": "Invalid login."})
            return

        # ✅ single-session check
        with active_lock:
            if uname in active_users:
                lj.send({"type": "error", "msg": "User already logged in elsewhere."})
                return
            active_users.add(uname)

        session_key = derive_session_key(pwd, user_salt)
        username = uname

        # send salt to client for same key derivation
        lj.send({"type": "ok", "msg": "Logged in.", "salt": USERS[uname]["salt"]})

        with clients_lock:
            clients.append((lj, username))
        broadcast("SERVER", f"{username} joined the chat.")

        while True:
            cleanup_nonce_cache()

            if not rate_ok(addr_str):
                lj.send({"type": "error", "msg": "Rate limit exceeded. Slow down."})
                continue

            pkt = lj.recv()
            if not pkt:
                break

            if pkt.get("type") == "bye":
                break

            if pkt.get("type") != "enc":
                lj.send({"type": "error", "msg": "Expected encrypted packet."})
                continue

            ts = int(pkt.get("ts", 0))
            now = int(time.time())
            if abs(now - ts) > MAX_CLOCK_SKEW:
                lj.send({"type": "error", "msg": "Rejected: timestamp window (replay/clock skew)."})
                continue

            nonce_b64 = pkt.get("nonce")
            ct_b64 = pkt.get("ct")
            if not nonce_b64 or not ct_b64:
                lj.send({"type": "error", "msg": "Missing nonce/ciphertext."})
                continue

            with nonce_lock:
                if nonce_b64 in nonce_seen:
                    lj.send({"type": "error", "msg": "Rejected: nonce replay detected."})
                    continue
                nonce_seen[nonce_b64] = time.time()

            aad = f"{username}|{ts}".encode("utf-8")
            text = aesgcm_decrypt(session_key, nonce_b64, ct_b64, aad)
            if text is None:
                lj.send({"type": "error", "msg": "Decrypt failed."})
                continue

            if len(text) > 500:
                lj.send({"type": "error", "msg": "Message too long."})
                continue

            broadcast(username, text)

    finally:
        if username:
            with clients_lock:
                for i, (xlj, _u) in enumerate(list(clients)):
                    if xlj is lj:
                        clients.pop(i)
                        break
            broadcast("SERVER", f"{username} left the chat.")

            with active_lock:
                active_users.discard(username)

        try:
            conn.close()
        except Exception:
            pass

def main():
    if not (os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)):
        print("[!] Missing TLS cert/key. Generate them with:")
        print("    openssl req -x509 -newkey rsa:2048 -keyout server_key.pem -out server_cert.pem -days 365 -nodes")
        return

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    print(f"[+] Secure Chat TLS Server listening on {HOST}:{PORT}")
    print("[i] Register once, then login. TLS enabled.")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(50)

    while True:
        raw_conn, addr = srv.accept()
        try:
            conn = context.wrap_socket(raw_conn, server_side=True)
        except ssl.SSLError:
            raw_conn.close()
            continue
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()
