"""
One-way cryptographic hashing.

Hashing is NOT encryption and cannot be reversed / "decrypted".
This module only ever produces digests; there is no decrypt path.
"""
import hashlib

HASH_INFO = {
    "md5": {
        "label": "MD5",
        "length_bits": 128,
        "status": "Broken",
        "description": (
            "MD5 produces a 128-bit digest. Practical collision attacks make it "
            "unsafe for any security purpose."
        ),
    },
    "sha1": {
        "label": "SHA-1",
        "length_bits": 160,
        "status": "Deprecated",
        "description": (
            "SHA-1 produces a 160-bit digest. Collision attacks have been "
            "demonstrated; avoid it for security-sensitive use."
        ),
    },
    "sha224": {
        "label": "SHA-224",
        "length_bits": 224,
        "status": "Recommended",
        "description": "SHA-224 is a truncated variant of SHA-256 from the SHA-2 family.",
    },
    "sha256": {
        "label": "SHA-256",
        "length_bits": 256,
        "status": "Recommended",
        "description": (
            "SHA-256 is a widely used member of the SHA-2 family, offering strong "
            "collision and preimage resistance."
        ),
    },
    "sha384": {
        "label": "SHA-384",
        "length_bits": 384,
        "status": "Recommended",
        "description": "SHA-384 is a truncated variant of SHA-512 from the SHA-2 family.",
    },
    "sha512": {
        "label": "SHA-512",
        "length_bits": 512,
        "status": "Recommended",
        "description": "SHA-512 offers a large digest size and strong security margins.",
    },
    "sha3_224": {
        "label": "SHA-3-224",
        "length_bits": 224,
        "status": "Recommended",
        "description": "SHA-3-224 is built on the Keccak sponge construction, distinct from SHA-2.",
    },
    "sha3_256": {
        "label": "SHA-3-256",
        "length_bits": 256,
        "status": "Recommended",
        "description": "SHA-3-256 is built on the Keccak sponge construction, distinct from SHA-2.",
    },
    "sha3_384": {
        "label": "SHA-3-384",
        "length_bits": 384,
        "status": "Recommended",
        "description": "SHA-3-384 is built on the Keccak sponge construction, distinct from SHA-2.",
    },
    "sha3_512": {
        "label": "SHA-3-512",
        "length_bits": 512,
        "status": "Recommended",
        "description": "SHA-3-512 is built on the Keccak sponge construction, distinct from SHA-2.",
    },
    "blake2b": {
        "label": "BLAKE2b",
        "length_bits": 512,
        "status": "Recommended",
        "description": (
            "BLAKE2b is optimized for 64-bit platforms and is faster than MD5/SHA-1/"
            "SHA-2 while remaining highly secure."
        ),
    },
    "blake2s": {
        "label": "BLAKE2s",
        "length_bits": 256,
        "status": "Recommended",
        "description": "BLAKE2s is optimized for 8- to 32-bit platforms, with a 256-bit digest.",
    },
}


class CryptoError(Exception):
    """Raised for any user-facing cryptographic error."""


def compute_hash(text: str, algorithm: str) -> dict:
    if text == "":
        raise CryptoError("Input text cannot be empty.")
    if algorithm not in HASH_INFO:
        raise CryptoError(f"Unknown hash algorithm: {algorithm}")

    data = text.encode("utf-8")
    try:
        h = hashlib.new(algorithm, data)
    except ValueError:
        raise CryptoError(f"Hash algorithm '{algorithm}' is not available on this system.")

    digest_hex = h.hexdigest()
    info = HASH_INFO[algorithm]

    return {
        "algorithm": info["label"],
        "digest": digest_hex,
        "length_bits": info["length_bits"],
        "length_bytes": info["length_bits"] // 8,
        "status": info["status"],
        "description": info["description"],
    }
