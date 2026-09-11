"""
ChaCha20-Poly1305 authenticated symmetric encryption.

Uses a 256-bit key and a 96-bit nonce, exactly as specified by the
cryptography library's high-level AEAD implementation.
"""
import base64
import binascii
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

KEY_SIZE = 32     # 256-bit key
NONCE_SIZE = 12    # 96-bit nonce


class CryptoError(Exception):
    """Raised for any user-facing cryptographic error."""


def generate_key() -> str:
    return base64.b64encode(secrets.token_bytes(KEY_SIZE)).decode("ascii")


def _decode_key(key_b64: str) -> bytes:
    if not key_b64:
        raise CryptoError("A key is required for ChaCha20-Poly1305.")
    try:
        key_bytes = base64.b64decode(key_b64, validate=True)
    except (binascii.Error, ValueError):
        raise CryptoError("Key must be valid Base64.")
    if len(key_bytes) != KEY_SIZE:
        raise CryptoError(
            f"ChaCha20-Poly1305 requires a 256-bit key (32 bytes). "
            f"Got {len(key_bytes)} bytes."
        )
    return key_bytes


def encrypt(plaintext: str, key_b64: str) -> dict:
    if plaintext == "":
        raise CryptoError("Input text cannot be empty.")

    key_bytes = _decode_key(key_b64)
    chacha = ChaCha20Poly1305(key_bytes)
    nonce = secrets.token_bytes(NONCE_SIZE)

    try:
        ct_and_tag = chacha.encrypt(nonce, plaintext.encode("utf-8"), None)
    except Exception as exc:
        raise CryptoError(f"Encryption failed: {exc}")

    return {
        "ciphertext": base64.b64encode(ct_and_tag).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
    }


def decrypt(ciphertext_b64: str, key_b64: str, nonce_b64: str) -> str:
    if not ciphertext_b64:
        raise CryptoError("Ciphertext cannot be empty.")
    if not nonce_b64:
        raise CryptoError("A nonce is required to decrypt.")

    key_bytes = _decode_key(key_b64)

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

    chacha = ChaCha20Poly1305(key_bytes)
    try:
        plaintext = chacha.decrypt(nonce, ct_and_tag, None)
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
