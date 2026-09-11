import hashlib
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from crypto import hashing


def test_sha256_matches_hashlib():
    result = hashing.compute_hash("Hello World", "sha256")
    expected = hashlib.sha256(b"Hello World").hexdigest()
    assert result["digest"] == expected
    assert result["length_bits"] == 256
    assert result["status"] == "Recommended"


def test_md5_flagged_broken():
    result = hashing.compute_hash("test", "md5")
    assert result["status"] == "Broken"


def test_sha1_flagged_deprecated():
    result = hashing.compute_hash("test", "sha1")
    assert result["status"] == "Deprecated"


def test_all_registered_algorithms_compute():
    for algo in hashing.HASH_INFO:
        result = hashing.compute_hash("sample text", algo)
        assert len(result["digest"]) == result["length_bytes"] * 2


def test_empty_input_rejected():
    with pytest.raises(hashing.CryptoError):
        hashing.compute_hash("", "sha256")


def test_unknown_algorithm_rejected():
    with pytest.raises(hashing.CryptoError):
        hashing.compute_hash("test", "not-a-real-hash")
