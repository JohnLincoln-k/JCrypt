import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from crypto import encoding


def test_base64_roundtrip():
    encoded = encoding.base64_encode("Hello, JCRYPT!")
    assert encoding.base64_decode(encoded) == "Hello, JCRYPT!"


def test_base64_invalid_input():
    with pytest.raises(encoding.CryptoError):
        encoding.base64_decode("not valid base64 !!!")


def test_hex_roundtrip():
    encoded = encoding.hex_encode("Hello")
    assert encoded == "48656c6c6f"
    assert encoding.hex_decode(encoded) == "Hello"


def test_hex_invalid_input():
    with pytest.raises(encoding.CryptoError):
        encoding.hex_decode("zzzz")


def test_url_roundtrip():
    encoded = encoding.url_encode("a b/c?d=e")
    assert encoding.url_decode(encoded) == "a b/c?d=e"


def test_binary_roundtrip():
    encoded = encoding.binary_encode("Hi")
    assert encoded == "01001000 01101001"
    assert encoding.binary_decode(encoded) == "Hi"


def test_binary_invalid_length():
    with pytest.raises(encoding.CryptoError):
        encoding.binary_decode("101")


def test_empty_input_rejected():
    with pytest.raises(encoding.CryptoError):
        encoding.base64_encode("")
