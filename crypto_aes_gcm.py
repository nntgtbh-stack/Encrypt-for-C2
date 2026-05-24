"""
crypto_aes_gcm.py
-----------------
Shared AES-GCM encrypt/decrypt utilities for Server ↔ Agent communication.

Wire format (all concatenated, base64-encoded for transport):
  [ salt (16B) | nonce (12B) | ciphertext | tag (16B) ]

Key derivation: PBKDF2-HMAC-SHA256 (or pass raw 32-byte key directly).
"""

import os
import base64
import json
import hashlib
import hmac
from dataclasses import dataclass, field
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ── Constants ────────────────────────────────────────────────────────────────
SALT_SIZE   = 16   # bytes
NONCE_SIZE  = 12   # bytes  (96-bit, GCM standard)
KEY_SIZE    = 32   # bytes  (AES-256)
TAG_SIZE    = 16   # bytes  (128-bit authentication tag, built into AESGCM)
KDF_ITERS   = 600_000


# ── Key derivation ────────────────────────────────────────────────────────────
def derive_key(password: str | bytes, salt: bytes) -> bytes:
    """Derive a 256-bit key from a shared password using PBKDF2-HMAC-SHA256."""
    if isinstance(password, str):
        password = password.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERS,
    )
    return kdf.derive(password)


def generate_key() -> bytes:
    """Generate a random 256-bit key for direct key exchange (e.g. via TLS)."""
    return os.urandom(KEY_SIZE)


# ── Core encrypt / decrypt ────────────────────────────────────────────────────
@dataclass
class EncryptedMessage:
    """Structured encrypted payload ready for transport."""
    salt:       bytes          # 16 B  – KDF salt (empty if raw key used)
    nonce:      bytes          # 12 B  – GCM nonce
    ciphertext: bytes          # variable length
    # NOTE: AESGCM appends the 16-byte tag to ciphertext automatically.

    # Optional cleartext metadata (not encrypted, but authenticated via AAD)
    sender:    str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # ── Serialisation ──────────────────────────────────────────────────────
    def to_bytes(self) -> bytes:
        """Pack into: salt | nonce | ciphertext (tag included at tail)."""
        return self.salt + self.nonce + self.ciphertext

    def to_dict(self) -> dict:
        """JSON-serialisable dict for network transport."""
        return {
            "payload":    base64.b64encode(self.to_bytes()).decode(),
            "sender":     self.sender,
            "timestamp":  self.timestamp,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_bytes(cls, raw: bytes, sender: str = "", timestamp: str = "") -> "EncryptedMessage":
        salt       = raw[:SALT_SIZE]
        nonce      = raw[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
        ciphertext = raw[SALT_SIZE + NONCE_SIZE :]
        return cls(salt=salt, nonce=nonce, ciphertext=ciphertext,
                   sender=sender, timestamp=timestamp)

    @classmethod
    def from_dict(cls, data: dict) -> "EncryptedMessage":
        raw = base64.b64decode(data["payload"])
        return cls.from_bytes(raw,
                              sender=data.get("sender", ""),
                              timestamp=data.get("timestamp", ""))

    @classmethod
    def from_json(cls, json_str: str) -> "EncryptedMessage":
        return cls.from_dict(json.loads(json_str))


def _build_aad(sender: str, timestamp: str) -> bytes:
    """Additional Authenticated Data – protects metadata against tampering."""
    return json.dumps({"sender": sender, "timestamp": timestamp},
                      separators=(",", ":")).encode()


def encrypt(
    plaintext:  str | bytes,
    key_or_password: bytes | str,
    sender: str = "",
    *,
    raw_key: bool = False,
) -> EncryptedMessage:
    """
    Encrypt *plaintext* with AES-256-GCM.

    Args:
        plaintext:        Message to encrypt (str or bytes).
        key_or_password:  Either a raw 32-byte key (raw_key=True)
                          or a shared password string (raw_key=False).
        sender:           Cleartext sender identity (included in AAD).
        raw_key:          Set True when passing a pre-shared raw key.

    Returns:
        EncryptedMessage ready for transport.
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()

    salt = os.urandom(SALT_SIZE)
    if raw_key:
        key  = key_or_password
        salt = b"\x00" * SALT_SIZE   # sentinel: no KDF used
    else:
        key = derive_key(key_or_password, salt)

    nonce     = os.urandom(NONCE_SIZE)
    timestamp = datetime.now(timezone.utc).isoformat()
    aad       = _build_aad(sender, timestamp)

    aesgcm     = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)   # tag appended automatically

    return EncryptedMessage(
        salt=salt, nonce=nonce, ciphertext=ciphertext,
        sender=sender, timestamp=timestamp,
    )


def decrypt(
    msg: EncryptedMessage | dict | str,
    key_or_password: bytes | str,
    *,
    raw_key: bool = False,
) -> str:
    """
    Decrypt an EncryptedMessage.

    Args:
        msg:              EncryptedMessage, dict, or JSON string.
        key_or_password:  Matching key/password used during encryption.
        raw_key:          Must match the flag used during encryption.

    Returns:
        Decrypted plaintext as str.

    Raises:
        cryptography.exceptions.InvalidTag  – if authentication fails
                                              (tampered/wrong key).
    """
    if isinstance(msg, (dict, str)):
        msg = (EncryptedMessage.from_json(msg)
               if isinstance(msg, str)
               else EncryptedMessage.from_dict(msg))

    if raw_key:
        key = key_or_password
    else:
        key = derive_key(key_or_password, msg.salt)

    aad    = _build_aad(msg.sender, msg.timestamp)
    aesgcm = AESGCM(key)
    plain  = aesgcm.decrypt(msg.nonce, msg.ciphertext, aad)
    return plain.decode()
