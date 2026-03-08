import socket
import ssl
import json
import time
import base64
import hashlib
import threading
import tkinter as tk
from tkinter import ttk, messagebox

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERVER_SALT = b"ST5062CEM_CHAT_SALT_v1"

# 🔒 Replace this with your server's SHA256 fingerprint from:
# openssl x509 -in server_cert.pem -noout -fingerprint -sha256
PINNED_CERT_SHA256 = "45:8B:FA:AB:0A:0E:8B:D4:29:D7:E2:C2:75:35:D9:9B:B1:D4:DC:03:D8:F1:96:E6:DF:CC:04:BE:67:9C:F5:57"

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

def derive_session_key(password: str, user_salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        user_salt + SERVER_SALT,
        200_000
    )

def aesgcm_encrypt(key: bytes, plaintext: str, aad: bytes) -> tuple[str, str]:
    # 12-byte nonce. Using time_ns() hashed is okay for demo; random os.urandom(12) is also fine.
    nonce = hashlib.sha256(f"{time.time_ns()}".encode()).digest()[:12]
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), aad)
    return base64.b64encode(nonce).decode("utf-8"), base64.b64encode(ct).decode("utf-8")

def normalize_fp(fp: str) -> str:
    return fp.strip().upper().replace("SHA256 FINGERPRINT=", "").replace("SHA256 FINGERPRINT", "").replace(" ", "")

class ChatClientGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Secure Chat (TLS + Pinned Cert)")
        self.root.geometry("720x520")

        self.sock = None
        self.lj = None
        self.session_key = None
        self.username = None

        # store current server target for UI labels
        self.connected_to = None  # "ip:port"

        self._build_login_ui()

    def _build_login_ui(self):
        self.frame = ttk.Frame(self.root, padding=12)
        self.frame.pack(fill="both", expand=True)

        ttk.Label(self.frame, text="Server IP").grid(row=0, column=0, sticky="w")
        self.server_ip = ttk.Entry(self.frame, width=30)
        self.server_ip.insert(0, "127.0.0.1")
        self.server_ip.grid(row=0, column=1, sticky="w", padx=8)

        ttk.Label(self.frame, text="Port").grid(row=0, column=2, sticky="w")
        self.server_port = ttk.Entry(self.frame, width=8)
        self.server_port.insert(0, "5050")
        self.server_port.grid(row=0, column=3, sticky="w")

        ttk.Separator(self.frame).grid(row=1, column=0, columnspan=4, sticky="ew", pady=10)

        ttk.Label(self.frame, text="Username").grid(row=2, column=0, sticky="w")
        self.username_e = ttk.Entry(self.frame, width=30)
        self.username_e.grid(row=2, column=1, sticky="w", padx=8)

        ttk.Label(self.frame, text="Password").grid(row=3, column=0, sticky="w")
        self.password_e = ttk.Entry(self.frame, width=30, show="*")
        self.password_e.grid(row=3, column=1, sticky="w", padx=8)

        btns = ttk.Frame(self.frame)
        btns.grid(row=4, column=0, columnspan=4, sticky="w", pady=10)

        ttk.Button(btns, text="Register", command=self.register).pack(side="left", padx=6)
        ttk.Button(btns, text="Login", command=self.login).pack(side="left", padx=6)

        ttk.Label(
            self.frame,
            text="TLS enabled. Client verifies pinned server certificate fingerprint."
        ).grid(row=5, column=0, columnspan=4, sticky="w")

        self.frame.columnconfigure(1, weight=1)

    def _tls_connect(self):
        if "REPLACE_ME" in PINNED_CERT_SHA256:
            raise RuntimeError("Set PINNED_CERT_SHA256 in client3.py (fingerprint pinning).")

        ip = self.server_ip.get().strip()
        port = int(self.server_port.get().strip())
        self.connected_to = f"{ip}:{port}"

        # TLS without CA validation, but we do fingerprint pinning ourselves
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tls_sock = context.wrap_socket(raw, server_hostname=ip)
        tls_sock.connect((ip, port))

        # fingerprint pinning
        cert_bin = tls_sock.getpeercert(binary_form=True)
        fp = hashlib.sha256(cert_bin).hexdigest().upper()
        fp_colon = ":".join(fp[i:i+2] for i in range(0, len(fp), 2))

        if normalize_fp(fp_colon) != normalize_fp(PINNED_CERT_SHA256):
            tls_sock.close()
            raise RuntimeError("MITM detected: server certificate fingerprint mismatch.")

        return tls_sock

    def register(self):
        uname = self.username_e.get().strip()
        pwd = self.password_e.get()
        if not uname or not pwd:
            messagebox.showerror("Error", "Username and password required.")
            return

        try:
            s = self._tls_connect()
            lj = LineJSON(s)
            lj.send({"type": "register", "username": uname, "password": pwd})
            resp = lj.recv()
            s.close()

            if not resp:
                messagebox.showerror("Error", "No server response.")
                return
            if resp.get("type") == "ok":
                messagebox.showinfo("Registered", resp.get("msg", "Registered. Now login."))
            else:
                messagebox.showerror("Error", resp.get("msg", "Register failed."))
        except Exception as e:
            messagebox.showerror("Error", f"Register failed: {e}")

    def login(self):
        uname = self.username_e.get().strip()
        pwd = self.password_e.get()
        if not uname or not pwd:
            messagebox.showerror("Error", "Username and password required.")
            return

        try:
            self.sock = self._tls_connect()
            self.lj = LineJSON(self.sock)

            self.lj.send({"type": "login", "username": uname, "password": pwd})
            resp = self.lj.recv()
            if not resp:
                raise RuntimeError("No server response.")
            if resp.get("type") != "ok":
                raise RuntimeError(resp.get("msg", "Login failed."))

            salt_b64 = resp.get("salt")
            if not salt_b64:
                raise RuntimeError("Server did not provide salt (cannot derive session key).")

            user_salt = base64.b64decode(salt_b64)
            self.session_key = derive_session_key(pwd, user_salt)
            self.username = uname

            self._open_chat_ui()
            threading.Thread(target=self._listen_loop, daemon=True).start()

        except Exception as e:
            self._hard_close()
            messagebox.showerror("Login Error", str(e))

    def _open_chat_ui(self):
        self.frame.destroy()
        self.chat = ttk.Frame(self.root, padding=10)
        self.chat.pack(fill="both", expand=True)

        # ✅ Top bar with connection + logged-in user
        top = ttk.Frame(self.chat)
        top.pack(fill="x", pady=(0, 6))

        self.conn_label = ttk.Label(top, text=f"Connected to: {self.connected_to}")
        self.conn_label.pack(side="left")

        self.user_label = ttk.Label(top, text=f"Logged in as: {self.username}")
        self.user_label.pack(side="right")

        self.text = tk.Text(self.chat, wrap="word", state="disabled")
        self.text.pack(fill="both", expand=True)

        bottom = ttk.Frame(self.chat)
        bottom.pack(fill="x", pady=6)

        self.msg_e = ttk.Entry(bottom)
        self.msg_e.pack(side="left", fill="x", expand=True)
        self.msg_e.bind("<Return>", lambda _e: self.send_msg())

        ttk.Button(bottom, text="Send", command=self.send_msg).pack(side="left", padx=6)
        ttk.Button(bottom, text="Logout", command=self.logout).pack(side="left", padx=6)
        ttk.Button(bottom, text="Quit", command=self.quit).pack(side="left")

        self._append("[SYSTEM] Logged in. TLS + AES-GCM message encryption enabled.\n")

    def _append(self, s: str):
        self.text.configure(state="normal")
        self.text.insert("end", s)
        self.text.see("end")
        self.text.configure(state="disabled")

    def send_msg(self):
        if not self.lj or not self.session_key:
            return
        msg = self.msg_e.get().strip()
        if not msg:
            return
        self.msg_e.delete(0, "end")

        ts = int(time.time())
        aad = f"{self.username}|{ts}".encode("utf-8")
        nonce_b64, ct_b64 = aesgcm_encrypt(self.session_key, msg, aad)

        pkt = {"type": "enc", "ts": ts, "nonce": nonce_b64, "ct": ct_b64}
        try:
            self.lj.send(pkt)
        except Exception as e:
            messagebox.showerror("Error", f"Send failed: {e}")

    def _listen_loop(self):
        while True:
            try:
                resp = self.lj.recv()
                if not resp:
                    self._append("[SYSTEM] Disconnected.\n")
                    return

                if resp.get("type") == "chat":
                    who = resp.get("from", "?")
                    text = resp.get("text", "")
                    self._append(f"[{who}] {text}\n")
                elif resp.get("type") == "error":
                    self._append(f"[ERROR] {resp.get('msg','')}\n")
            except Exception:
                self._append("[SYSTEM] Connection error.\n")
                return

    def logout(self):
        try:
            if self.lj:
                self.lj.send({"type": "bye"})
        except Exception:
            pass

        self._hard_close()

        try:
            self.chat.destroy()
        except Exception:
            pass

        self._build_login_ui()

    def _hard_close(self):
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
        self.sock = None
        self.lj = None
        self.session_key = None
        self.username = None
        self.connected_to = None

    def quit(self):
        self.logout()
        self.root.destroy()

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    ChatClientGUI().run()
