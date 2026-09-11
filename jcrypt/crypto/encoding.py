"""
Reversible text encodings: Base64, Hex, URL encoding, Binary.

These are NOT encryption — they provide no confidentiality, only a
different representation of the same data.
"""
import base64
import binascii
import urllib.parse


class CryptoError(Exception):
    """Raised for any user-facing encoding error."""


def _require_input(text: str):
    if text == "":
        raise CryptoError("Input text cannot be empty.")


# --------------------------------------------------------------------------
# Base64
# --------------------------------------------------------------------------
def base64_encode(text: str) -> str:
    _require_input(text)
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def base64_decode(text: str) -> str:
    _require_input(text)
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise CryptoError("Input is not valid Base64.")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise CryptoError("Decoded Base64 data is not valid UTF-8 text.")


# --------------------------------------------------------------------------
# Hex
# --------------------------------------------------------------------------
def hex_encode(text: str) -> str:
    _require_input(text)
    return text.encode("utf-8").hex()


def hex_decode(text: str) -> str:
    _require_input(text)
    cleaned = text.replace(" ", "").replace("\n", "")
    try:
        raw = bytes.fromhex(cleaned)
    except ValueError:
        raise CryptoError("Input is not valid hexadecimal.")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise CryptoError("Decoded hex data is not valid UTF-8 text.")


# --------------------------------------------------------------------------
# URL Encoding
# --------------------------------------------------------------------------
def url_encode(text: str) -> str:
    _require_input(text)
    return urllib.parse.quote(text, safe="")


def url_decode(text: str) -> str:
    _require_input(text)
    try:
        return urllib.parse.unquote(text, errors="strict")
    except UnicodeDecodeError:
        raise CryptoError("Input is not validly URL-encoded UTF-8 text.")


# --------------------------------------------------------------------------
# Binary
# --------------------------------------------------------------------------
def binary_encode(text: str) -> str:
    _require_input(text)
    data = text.encode("utf-8")
    return " ".join(f"{byte:08b}" for byte in data)


def binary_decode(text: str) -> str:
    _require_input(text)
    chunks = text.split()
    if not chunks:
        raise CryptoError("Input is not valid binary.")
    byte_values = []
    for chunk in chunks:
        if not chunk or any(c not in "01" for c in chunk):
            raise CryptoError("Input must contain only 0s, 1s, and spaces between bytes.")
        if len(chunk) != 8:
            raise CryptoError("Each binary group must be exactly 8 bits (one byte).")
        byte_values.append(int(chunk, 2))
    try:
        return bytes(byte_values).decode("utf-8")
    except UnicodeDecodeError:
        raise CryptoError("Decoded binary data is not valid UTF-8 text.")
