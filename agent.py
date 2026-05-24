"""
agent.py
--------
Agent side: encrypts messages, sends them to the Server, and decrypts
the encrypted response.

Run (after starting server.py):
    python agent.py
"""

import json
import socket
from crypto_aes_gcm import encrypt, decrypt, EncryptedMessage

# ── Must match server ────────────────────────────────────────────────────────
SHARED_PASSWORD = "super-secret-passphrase-change-me"

HOST   = "127.0.0.1"
PORT   = 9000
BUFFER = 65536


class AgentSession:
    """Simple stateful session for an agent communicating with the server."""

    def __init__(self, agent_id: str = "agent-01"):
        self.agent_id = agent_id
        self._sock: socket.socket | None = None

    # ── Connection management ─────────────────────────────────────────────
    def connect(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.connect((HOST, PORT))
        print(f"[AGENT]  Connected to server {HOST}:{PORT}")

    def close(self) -> None:
        if self._sock:
            self._sock.close()
            self._sock = None
            print("[AGENT]  Connection closed")

    # ── Send / receive ────────────────────────────────────────────────────
    def send(self, plaintext: str) -> str:
        """Encrypt *plaintext*, send to server, decrypt and return response."""
        if not self._sock:
            raise RuntimeError("Not connected. Call connect() first.")

        # Encrypt
        enc_msg = encrypt(plaintext, SHARED_PASSWORD, sender=self.agent_id)
        payload = enc_msg.to_json().encode()

        print(f"\n[AGENT]  Sending  : {plaintext}")
        print(f"[AGENT]  Encrypted: {enc_msg.to_dict()['payload'][:60]}…")

        self._sock.sendall(payload)

        # Receive & decrypt response
        raw         = self._sock.recv(BUFFER)
        packet      = json.loads(raw.decode())
        enc_resp    = EncryptedMessage.from_dict(packet)
        response    = decrypt(enc_resp, SHARED_PASSWORD)

        print(f"[AGENT]  Response (decrypted): {response}")
        return response

    # ── Context manager support ───────────────────────────────────────────
    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.close()


# ── Demo ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    messages = [
        "Hello Server, agent reporting in.",
        "Requesting task list for zone-42.",
        "Sending sensor data: temp=36.7°C, humidity=78%",
    ]

    with AgentSession(agent_id="agent-01") as agent:
        for msg in messages:
            agent.send(msg)
