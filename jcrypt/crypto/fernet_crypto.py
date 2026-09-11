"""
Fernet symmetric encryption — a high-level authenticated scheme
(AES-128-CBC + HMAC-SHA256) with a URL-safe base64 token format.
"""
from cryptography.fernet import Fernet, InvalidToken


class CryptoError(Exception):
    """Raised for any user-facing cryptographic error."""


def generate_key() -> str:
    return Fernet.generate_key().decode("ascii")


def _build(key_str: str) -> Fernet:
    if not key_str:
        raise CryptoError("A Fernet key is required.")
    try:
        return Fernet(key_str.encode("ascii"))
    except Exception:
        raise CryptoError(
            "Invalid Fernet key. Use 'Generate Secure Key' to create a valid one."
        )


def encrypt(plaintext: str, key_str: str) -> str:
    if plaintext == "":
        raise CryptoError("Input text cannot be empty.")
    fernet = _build(key_str)
    try:
        token = fernet.encrypt(plaintext.encode("utf-8"))
    except Exception as exc:
        raise CryptoError(f"Encryption failed: {exc}")
    return token.decode("ascii")


def decrypt(token_str: str, key_str: str) -> str:
    if not token_str:
        raise CryptoError("Ciphertext cannot be empty.")
    fernet = _build(key_str)
    try:
        plaintext = fernet.decrypt(token_str.encode("ascii"))
    except InvalidToken:
        raise CryptoError(
            "Decryption failed: invalid token. The key is wrong, the token is "
            "malformed, or it has expired."
        )
    except Exception as exc:
        raise CryptoError(f"Decryption failed: {exc}")

    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError:
        raise CryptoError("Decrypted data is not valid UTF-8 text.")
