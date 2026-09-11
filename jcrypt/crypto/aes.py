"""
AES-GCM symmetric encryption (128 / 192 / 256 bit keys).

Only the authenticated AES-GCM mode is exposed. ECB is intentionally
never implemented because it leaks plaintext structure. All key and
nonce material is generated with `secrets`, never `random`.
"""
import base64
import binascii
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Key sizes in bytes, keyed by the label used in the UI.
KEY_SIZES = {
    "AES-128-GCM": 16,
    "AES-192-GCM": 24,
    "AES-256-GCM": 32,
}

NONCE_SIZE = 12  # 96-bit nonce, the recommended size for GCM


class CryptoError(Exception):
    """Raised for any user-facing cryptographic error."""


def generate_key(variant: str) -> str:
    """Return a base64-encoded, cryptographically secure random key."""
    if variant not in KEY_SIZES:
        raise CryptoError(f"Unknown AES variant: {variant}")
    key_bytes = secrets.token_bytes(KEY_SIZES[variant])
    return base64.b64encode(key_bytes).decode("ascii")


def _decode_key(key_b64: str, variant: str) -> bytes:
    if not key_b64:
        raise CryptoError("A key is required for AES-GCM.")
    try:
        key_bytes = base64.b64decode(key_b64, validate=True)
    except (binascii.Error, ValueError):
        raise CryptoError("Key must be valid Base64.")
    expected = KEY_SIZES[variant]
    if len(key_bytes) != expected:
        raise CryptoError(
            f"{variant} requires a {expected * 8}-bit key "
            f"({expected} bytes). Got {len(key_bytes)} bytes."
        )
    return key_bytes


def encrypt(plaintext: str, key_b64: str, variant: str) -> dict:
    """Encrypt plaintext with AES-GCM. Returns nonce, ciphertext (with tag) as base64."""
    if plaintext == "":
        raise CryptoError("Input text cannot be empty.")
    if variant not in KEY_SIZES:
        raise CryptoError(f"Unknown AES variant: {variant}")

    key_bytes = _decode_key(key_b64, variant)
    aesgcm = AESGCM(key_bytes)
    nonce = secrets.token_bytes(NONCE_SIZE)

    try:
        ct_and_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    except Exception as exc:  # defensive: library-level failure
        raise CryptoError(f"Encryption failed: {exc}")

    return {
        "ciphertext": base64.b64encode(ct_and_tag).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
    }


def decrypt(ciphertext_b64: str, key_b64: str, nonce_b64: str, variant: str) -> str:
    """Decrypt AES-GCM ciphertext. The auth tag is expected appended to the ciphertext."""
    if not ciphertext_b64:
        raise CryptoError("Ciphertext cannot be empty.")
    if not nonce_b64:
        raise CryptoError("A nonce is required to decrypt AES-GCM ciphertext.")
    if variant not in KEY_SIZES:
        raise CryptoError(f"Unknown AES variant: {variant}")

    key_bytes = _decode_key(key_b64, variant)

    try:
        ct_and_tag = base64.b64decode(ciphertext_b64, validate=True)
    except (binascii.Error, ValueError):
        raise CryptoError("Ciphertext must be valid Base64.")

    try:
        nonce = base64.b64decode(nonce_b64, validate=True)
    except (binascii.Error, ValueError):
        raise CryptoError("Nonce must be valid Base64.")

    if len(nonce) != NONCE_SIZE:
        raise CryptoError(f"Nonce must be {NONCE_SIZE} bytes (96 bits).")

    aesgcm = AESGCM(key_bytes)
    try:
        plaintext = aesgcm.decrypt(nonce, ct_and_tag, None)
    except InvalidTag:
        raise CryptoError(
            "Decryption failed: authentication tag mismatch. "
            "The key, nonce, or ciphertext is incorrect, or the data was tampered with."
        )
    except Exception as exc:
        raise CryptoError(f"Decryption failed: {exc}")

    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError:
        raise CryptoError("Decrypted data is not valid UTF-8 text.")
