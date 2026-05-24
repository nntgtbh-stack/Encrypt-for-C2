"""
test_crypto.py
--------------
Unit tests + standalone demo — no network required.
Run:  python test_crypto.py
"""

import os
import pytest
from cryptography.exceptions import InvalidTag
from crypto_aes_gcm import (
    encrypt, decrypt, generate_key,
    EncryptedMessage, SALT_SIZE, NONCE_SIZE,
)


# ════════════════════════════════════════════════════════════════════════════
#  Helpers
# ════════════════════════════════════════════════════════════════════════════
PASSWORD = "correct-horse-battery-staple"
MESSAGE  = "Hello, secure world! 🔐"


# ════════════════════════════════════════════════════════════════════════════
#  Password-based (PBKDF2 + AES-GCM)
# ════════════════════════════════════════════════════════════════════════════
class TestPasswordBasedEncryption:

    def test_roundtrip(self):
        enc = encrypt(MESSAGE, PASSWORD, sender="agent")
        assert decrypt(enc, PASSWORD) == MESSAGE

    def test_roundtrip_bytes_plaintext(self):
        enc = encrypt(b"binary \x00 data", PASSWORD)
        assert decrypt(enc, PASSWORD) == "binary \x00 data"

    def test_wrong_password_raises(self):
        enc = encrypt(MESSAGE, PASSWORD)
        with pytest.raises(InvalidTag):
            decrypt(enc, "wrong-password")

    def test_tampered_ciphertext_raises(self):
        enc = encrypt(MESSAGE, PASSWORD)
        # Flip a byte in the ciphertext
        ct  = bytearray(enc.ciphertext)
        ct[0] ^= 0xFF
        enc.ciphertext = bytes(ct)
        with pytest.raises(InvalidTag):
            decrypt(enc, PASSWORD)

    def test_tampered_aad_raises(self):
        """Changing sender (AAD) after encryption must fail authentication."""
        enc = encrypt(MESSAGE, PASSWORD, sender="agent")
        enc.sender = "evil"                    # tamper with authenticated data
        with pytest.raises(InvalidTag):
            decrypt(enc, PASSWORD)

    def test_nonces_are_unique(self):
        n1 = encrypt(MESSAGE, PASSWORD).nonce
        n2 = encrypt(MESSAGE, PASSWORD).nonce
        assert n1 != n2, "Nonces must never repeat"

    def test_salts_are_unique(self):
        s1 = encrypt(MESSAGE, PASSWORD).salt
        s2 = encrypt(MESSAGE, PASSWORD).salt
        assert s1 != s2, "Salts must never repeat"


# ════════════════════════════════════════════════════════════════════════════
#  Raw-key mode (pre-shared 32-byte key)
# ════════════════════════════════════════════════════════════════════════════
class TestRawKeyEncryption:

    def test_roundtrip(self):
        key = generate_key()
        enc = encrypt(MESSAGE, key, raw_key=True)
        assert decrypt(enc, key, raw_key=True) == MESSAGE

    def test_wrong_key_raises(self):
        key      = generate_key()
        wrong    = generate_key()
        enc      = encrypt(MESSAGE, key, raw_key=True)
        with pytest.raises(InvalidTag):
            decrypt(enc, wrong, raw_key=True)


# ════════════════════════════════════════════════════════════════════════════
#  Serialisation
# ════════════════════════════════════════════════════════════════════════════
class TestSerialisation:

    def test_dict_roundtrip(self):
        enc  = encrypt(MESSAGE, PASSWORD, sender="server")
        d    = enc.to_dict()
        enc2 = EncryptedMessage.from_dict(d)
        assert decrypt(enc2, PASSWORD) == MESSAGE

    def test_json_roundtrip(self):
        enc  = encrypt(MESSAGE, PASSWORD, sender="agent-07")
        js   = enc.to_json()
        enc2 = EncryptedMessage.from_json(js)
        assert decrypt(enc2, PASSWORD) == MESSAGE

    def test_bytes_roundtrip(self):
        enc  = encrypt(MESSAGE, PASSWORD)
        raw  = enc.to_bytes()
        enc2 = EncryptedMessage.from_bytes(
            raw, sender=enc.sender, timestamp=enc.timestamp
        )
        assert decrypt(enc2, PASSWORD) == MESSAGE

    def test_payload_structure(self):
        enc = encrypt(MESSAGE, PASSWORD)
        raw = enc.to_bytes()
        assert len(raw) >= SALT_SIZE + NONCE_SIZE + 1


# ════════════════════════════════════════════════════════════════════════════
#  Standalone demo (no pytest needed)
# ════════════════════════════════════════════════════════════════════════════
def demo():
    sep = "─" * 60

    print(f"\n{sep}")
    print("  AES-256-GCM  ·  Server ↔ Agent message demo")
    print(sep)

    # ── Password-based ────────────────────────────────────────────────────
    print("\n① Password-based key derivation (PBKDF2 + AES-GCM)\n")
    plaintext = "Agent to Server: all systems nominal."
    enc       = encrypt(plaintext, PASSWORD, sender="agent-01")
    payload   = enc.to_dict()

    print(f"  Plaintext   : {plaintext}")
    print(f"  Sender      : {enc.sender}")
    print(f"  Timestamp   : {enc.timestamp}")
    print(f"  Salt (hex)  : {enc.salt.hex()}")
    print(f"  Nonce (hex) : {enc.nonce.hex()}")
    print(f"  Ciphertext  : {enc.ciphertext[:20].hex()}… ({len(enc.ciphertext)} B)")
    print(f"  JSON payload: {payload['payload'][:64]}…")

    recovered = decrypt(EncryptedMessage.from_dict(payload), PASSWORD)
    print(f"\n  Decrypted   : {recovered}")
    assert recovered == plaintext

    # ── Raw key ───────────────────────────────────────────────────────────
    print(f"\n{sep}")
    print("\n② Pre-shared raw key (AES-256-GCM, no KDF)\n")
    raw_key   = generate_key()
    enc2      = encrypt("Secret command: DEPLOY", raw_key, sender="server", raw_key=True)
    recovered2 = decrypt(enc2, raw_key, raw_key=True)
    print(f"  Raw key     : {raw_key.hex()}")
    print(f"  Decrypted   : {recovered2}")
    assert recovered2 == "Secret command: DEPLOY"

    # ── Tamper detection ──────────────────────────────────────────────────
    print(f"\n{sep}")
    print("\n③ Tamper detection\n")
    enc3 = encrypt("Sensitive payload", PASSWORD)
    ct   = bytearray(enc3.ciphertext)
    ct[5] ^= 0xAB                   # flip 1 bit
    enc3.ciphertext = bytes(ct)
    try:
        decrypt(enc3, PASSWORD)
        print("  ✗ FAILED: tamper not detected!")
    except Exception as e:
        print(f"  ✓ Tamper detected: {type(e).__name__}")

    print(f"\n{sep}\n  All checks passed ✓\n{sep}\n")


if __name__ == "__main__":
    demo()
