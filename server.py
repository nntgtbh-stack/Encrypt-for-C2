"""
server.py
---------
Server side: receives encrypted messages from the Agent, decrypts them,
processes, and sends back an encrypted response.

Run:
    python server.py
"""

import json
import socket
import threading
from crypto_aes_gcm import encrypt, decrypt, EncryptedMessage

# ── Shared secret (in production: exchange via TLS / key-agreement protocol) ─
SHARED_PASSWORD = "super-secret-passphrase-change-me"

HOST = "127.0.0.1"
PORT = 9000
BUFFER = 65536


def handle_client(conn: socket.socket, addr: tuple) -> None:
    print(f"\n[SERVER] New connection from {addr}")
    try:
        with conn:
            while True:
                raw = conn.recv(BUFFER)
                if not raw:
                    break

                # ── Decrypt incoming message ──────────────────────────────
                try:
                    packet      = json.loads(raw.decode())
                    enc_msg     = EncryptedMessage.from_dict(packet)
                    plaintext   = decrypt(enc_msg, SHARED_PASSWORD)

                    print(f"[SERVER] ✓ From [{enc_msg.sender}] @ {enc_msg.timestamp}")
                    print(f"[SERVER]   Plaintext  : {plaintext}")

                except Exception as exc:
                    print(f"[SERVER] ✗ Decryption failed: {exc}")
                    break

                # ── Process & respond ─────────────────────────────────────
                response_text = f"ACK: received your message — '{plaintext}'"
                enc_response  = encrypt(
                    response_text,
                    SHARED_PASSWORD,
                    sender="server",
                )
                conn.sendall(enc_response.to_json().encode())
                print(f"[SERVER]   Response sent (encrypted)\n")

    except ConnectionResetError:
        pass
    finally:
        print(f"[SERVER] Connection closed: {addr}")


def run_server() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(5)
        print(f"[SERVER] Listening on {HOST}:{PORT}  (AES-256-GCM)")
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle_client, args=(conn, addr),
                             daemon=True).start()


if __name__ == "__main__":
    run_server()
