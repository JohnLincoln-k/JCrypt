import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from crypto import classical


def test_caesar_roundtrip():
    ct = classical.caesar_encrypt("HELLO", 3)
    assert ct == "KHOOR"
    assert classical.caesar_decrypt(ct, 3) == "HELLO"


def test_caesar_preserves_case_and_punctuation():
    ct = classical.caesar_encrypt("Hello, World!", 3)
    assert ct == "Khoor, Zruog!"


def test_rot13_is_involution():
    text = "The Quick Brown Fox"
    assert classical.rot13(classical.rot13(text)) == text


def test_atbash_roundtrip():
    ct = classical.atbash("ATTACKATDAWN")
    assert classical.atbash(ct) == "ATTACKATDAWN"


def test_vigenere_roundtrip():
    ct = classical.vigenere_encrypt("ATTACKATDAWN", "LEMON")
    assert classical.vigenere_decrypt(ct, "LEMON") == "ATTACKATDAWN"


def test_vigenere_requires_alpha_key():
    with pytest.raises(classical.CryptoError):
        classical.vigenere_encrypt("HELLO", "1234")


def test_affine_roundtrip():
    ct = classical.affine_encrypt("HELLO", 5, 8)
    assert classical.affine_decrypt(ct, 5, 8) == "HELLO"


def test_affine_rejects_invalid_a():
    with pytest.raises(classical.CryptoError):
        classical.affine_encrypt("HELLO", 2, 8)  # gcd(2, 26) != 1


def test_empty_input_rejected():
    with pytest.raises(classical.CryptoError):
        classical.caesar_encrypt("", 3)
