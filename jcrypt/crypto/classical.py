"""
Educational classical ciphers: Caesar, ROT13, Atbash, Vigenere, Affine.

These are NOT secure and are implemented purely for educational display.
Only letters A-Z / a-z are shifted; all other characters (spaces,
punctuation, digits) pass through unchanged.
"""
import string

ALPHABET_SIZE = 26


class CryptoError(Exception):
    """Raised for any user-facing cryptographic error."""


def _require_input(text: str):
    if text == "":
        raise CryptoError("Input text cannot be empty.")


# --------------------------------------------------------------------------
# Caesar Cipher
# --------------------------------------------------------------------------
def caesar_encrypt(text: str, shift: int) -> str:
    _require_input(text)
    shift = shift % ALPHABET_SIZE
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            result.append(chr((ord(ch) - base + shift) % ALPHABET_SIZE + base))
        else:
            result.append(ch)
    return "".join(result)


def caesar_decrypt(text: str, shift: int) -> str:
    return caesar_encrypt(text, -shift)


# --------------------------------------------------------------------------
# ROT13
# --------------------------------------------------------------------------
def rot13(text: str) -> str:
    _require_input(text)
    return caesar_encrypt(text, 13)


# --------------------------------------------------------------------------
# Atbash Cipher
# --------------------------------------------------------------------------
def atbash(text: str) -> str:
    _require_input(text)
    result = []
    for ch in text:
        if ch.isupper():
            result.append(chr(ord("Z") - (ord(ch) - ord("A"))))
        elif ch.islower():
            result.append(chr(ord("z") - (ord(ch) - ord("a"))))
        else:
            result.append(ch)
    return "".join(result)


# --------------------------------------------------------------------------
# Vigenere Cipher
# --------------------------------------------------------------------------
def _clean_key(key: str) -> str:
    letters = [c for c in key if c.isalpha()]
    if not letters:
        raise CryptoError("Vigenere key must contain at least one letter.")
    return "".join(letters)


def vigenere_encrypt(text: str, key: str) -> str:
    _require_input(text)
    key = _clean_key(key)
    result = []
    key_index = 0
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            key_ch = key[key_index % len(key)].upper()
            shift = ord(key_ch) - ord("A")
            result.append(chr((ord(ch) - base + shift) % ALPHABET_SIZE + base))
            key_index += 1
        else:
            result.append(ch)
    return "".join(result)


def vigenere_decrypt(text: str, key: str) -> str:
    _require_input(text)
    key = _clean_key(key)
    result = []
    key_index = 0
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            key_ch = key[key_index % len(key)].upper()
            shift = ord(key_ch) - ord("A")
            result.append(chr((ord(ch) - base - shift) % ALPHABET_SIZE + base))
            key_index += 1
        else:
            result.append(ch)
    return "".join(result)


# --------------------------------------------------------------------------
# Affine Cipher: E(x) = (a*x + b) mod 26 ; D(y) = a^-1 * (y - b) mod 26
# --------------------------------------------------------------------------
def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def _mod_inverse(a: int, m: int) -> int:
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise CryptoError(f"No modular inverse exists for a={a} mod {m}.")


def _validate_affine(a: int, b: int):
    if _gcd(a, ALPHABET_SIZE) != 1:
        raise CryptoError(
            f"'a' must be coprime with {ALPHABET_SIZE} (the alphabet size). "
            f"a={a} is invalid — try values like 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25."
        )
    if not (0 <= b < ALPHABET_SIZE):
        raise CryptoError(f"'b' must be between 0 and {ALPHABET_SIZE - 1}.")


def affine_encrypt(text: str, a: int, b: int) -> str:
    _require_input(text)
    _validate_affine(a, b)
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            x = ord(ch) - base
            result.append(chr((a * x + b) % ALPHABET_SIZE + base))
        else:
            result.append(ch)
    return "".join(result)


def affine_decrypt(text: str, a: int, b: int) -> str:
    _require_input(text)
    _validate_affine(a, b)
    a_inv = _mod_inverse(a, ALPHABET_SIZE)
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            y = ord(ch) - base
            result.append(chr((a_inv * (y - b)) % ALPHABET_SIZE + base))
        else:
            result.append(ch)
    return "".join(result)
