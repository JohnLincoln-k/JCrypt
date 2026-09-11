"""
JCRYPT — Encryption, Decryption, Encoding & Hashing Toolkit.

Stateless Flask application. No database, no accounts, no persistence.
Every request is processed in memory and nothing is logged or stored.

Run with:
    python app.py
"""
from flask import Flask, jsonify, render_template, request

from crypto import aes, chacha, classical, encoding, fernet_crypto, hashing
from crypto.registry import (
    ALGORITHMS_BY_ID,
    ALL_ALGORITHMS,
    CLASSICAL_CIPHERS,
    ENCODING_METHODS,
    HASH_ALGORITHMS,
    STATS,
    SYMMETRIC_ENCRYPTION,
)

app = Flask(__name__)

# Never log request bodies — they may contain plaintext, keys, or ciphertext.
app.config["JSON_SORT_KEYS"] = False


class ApiError(Exception):
    def __init__(self, message, status_code=400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


@app.errorhandler(ApiError)
def handle_api_error(err):
    return jsonify({"success": False, "error": err.message}), err.status_code


@app.errorhandler(404)
def handle_404(err):
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "error": "Unknown API endpoint."}), 404
    return render_template("about.html", not_found=True), 404


def _get_json():
    data = request.get_json(silent=True)
    if data is None:
        raise ApiError("Request body must be valid JSON.")
    return data


def _get_int_param(data, key, default=None, required=False):
    if key not in data or data[key] in (None, ""):
        if required:
            raise ApiError(f"'{key}' is required.")
        return default
    try:
        return int(data[key])
    except (TypeError, ValueError):
        raise ApiError(f"'{key}' must be an integer.")


# ---------------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template(
        "index.html",
        stats=STATS,
        symmetric=SYMMETRIC_ENCRYPTION,
        classical=CLASSICAL_CIPHERS,
        hashes=HASH_ALGORITHMS,
        encodings=ENCODING_METHODS,
    )


@app.route("/algorithms")
def algorithms_page():
    return render_template(
        "algorithms.html",
        stats=STATS,
        symmetric=SYMMETRIC_ENCRYPTION,
        classical=CLASSICAL_CIPHERS,
        hashes=HASH_ALGORITHMS,
        encodings=ENCODING_METHODS,
    )


@app.route("/about")
def about_page():
    return render_template("about.html", stats=STATS)


# ---------------------------------------------------------------------------
# API: Encrypt
# ---------------------------------------------------------------------------
@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    data = _get_json()
    algorithm = data.get("algorithm", "")
    text = data.get("text", "")

    try:
        if algorithm in ("aes-128-gcm", "aes-192-gcm", "aes-256-gcm"):
            variant = {"aes-128-gcm": "AES-128-GCM", "aes-192-gcm": "AES-192-GCM",
                       "aes-256-gcm": "AES-256-GCM"}[algorithm]
            key = data.get("key", "")
            out = aes.encrypt(text, key, variant)
            return jsonify({"success": True, "result": out["ciphertext"], "nonce": out["nonce"]})

        if algorithm == "chacha20-poly1305":
            key = data.get("key", "")
            out = chacha.encrypt(text, key)
            return jsonify({"success": True, "result": out["ciphertext"], "nonce": out["nonce"]})

        if algorithm == "fernet":
            key = data.get("key", "")
            result = fernet_crypto.encrypt(text, key)
            return jsonify({"success": True, "result": result})

        if algorithm == "caesar":
            shift = _get_int_param(data, "shift", required=True)
            result = classical.caesar_encrypt(text, shift)
            return jsonify({"success": True, "result": result})

        if algorithm == "rot13":
            result = classical.rot13(text)
            return jsonify({"success": True, "result": result})

        if algorithm == "atbash":
            result = classical.atbash(text)
            return jsonify({"success": True, "result": result})

        if algorithm == "vigenere":
            key = data.get("key", "")
            result = classical.vigenere_encrypt(text, key)
            return jsonify({"success": True, "result": result})

        if algorithm == "affine":
            a = _get_int_param(data, "a", required=True)
            b = _get_int_param(data, "b", required=True)
            result = classical.affine_encrypt(text, a, b)
            return jsonify({"success": True, "result": result})

        raise ApiError(f"Unknown or non-encryptable algorithm: '{algorithm}'.")

    except (aes.CryptoError, chacha.CryptoError, fernet_crypto.CryptoError,
            classical.CryptoError) as exc:
        raise ApiError(str(exc))


# ---------------------------------------------------------------------------
# API: Decrypt
# ---------------------------------------------------------------------------
@app.route("/api/decrypt", methods=["POST"])
def api_decrypt():
    data = _get_json()
    algorithm = data.get("algorithm", "")
    text = data.get("text", "")

    try:
        if algorithm in ("aes-128-gcm", "aes-192-gcm", "aes-256-gcm"):
            variant = {"aes-128-gcm": "AES-128-GCM", "aes-192-gcm": "AES-192-GCM",
                       "aes-256-gcm": "AES-256-GCM"}[algorithm]
            key = data.get("key", "")
            nonce = data.get("nonce", "")
            result = aes.decrypt(text, key, nonce, variant)
            return jsonify({"success": True, "result": result})

        if algorithm == "chacha20-poly1305":
            key = data.get("key", "")
            nonce = data.get("nonce", "")
            result = chacha.decrypt(text, key, nonce)
            return jsonify({"success": True, "result": result})

        if algorithm == "fernet":
            key = data.get("key", "")
            result = fernet_crypto.decrypt(text, key)
            return jsonify({"success": True, "result": result})

        if algorithm == "caesar":
            shift = _get_int_param(data, "shift", required=True)
            result = classical.caesar_decrypt(text, shift)
            return jsonify({"success": True, "result": result})

        if algorithm == "rot13":
            result = classical.rot13(text)
            return jsonify({"success": True, "result": result})

        if algorithm == "atbash":
            result = classical.atbash(text)
            return jsonify({"success": True, "result": result})

        if algorithm == "vigenere":
            key = data.get("key", "")
            result = classical.vigenere_decrypt(text, key)
            return jsonify({"success": True, "result": result})

        if algorithm == "affine":
            a = _get_int_param(data, "a", required=True)
            b = _get_int_param(data, "b", required=True)
            result = classical.affine_decrypt(text, a, b)
            return jsonify({"success": True, "result": result})

        raise ApiError(f"Unknown or non-decryptable algorithm: '{algorithm}'.")

    except (aes.CryptoError, chacha.CryptoError, fernet_crypto.CryptoError,
            classical.CryptoError) as exc:
        raise ApiError(str(exc))


# ---------------------------------------------------------------------------
# API: Hash
# ---------------------------------------------------------------------------
@app.route("/api/hash", methods=["POST"])
def api_hash():
    data = _get_json()
    algorithm = data.get("algorithm", "")
    text = data.get("text", "")

    try:
        result = hashing.compute_hash(text, algorithm)
        return jsonify({"success": True, "result": result["digest"], "details": result})
    except hashing.CryptoError as exc:
        raise ApiError(str(exc))


# ---------------------------------------------------------------------------
# API: Encode / Decode
# ---------------------------------------------------------------------------
@app.route("/api/encode", methods=["POST"])
def api_encode():
    data = _get_json()
    method = data.get("method", "")
    text = data.get("text", "")

    try:
        if method == "base64":
            result = encoding.base64_encode(text)
        elif method == "hex":
            result = encoding.hex_encode(text)
        elif method == "url":
            result = encoding.url_encode(text)
        elif method == "binary":
            result = encoding.binary_encode(text)
        else:
            raise ApiError(f"Unknown encoding method: '{method}'.")
        return jsonify({"success": True, "result": result})
    except encoding.CryptoError as exc:
        raise ApiError(str(exc))


@app.route("/api/decode", methods=["POST"])
def api_decode():
    data = _get_json()
    method = data.get("method", "")
    text = data.get("text", "")

    try:
        if method == "base64":
            result = encoding.base64_decode(text)
        elif method == "hex":
            result = encoding.hex_decode(text)
        elif method == "url":
            result = encoding.url_decode(text)
        elif method == "binary":
            result = encoding.binary_decode(text)
        else:
            raise ApiError(f"Unknown encoding method: '{method}'.")
        return jsonify({"success": True, "result": result})
    except encoding.CryptoError as exc:
        raise ApiError(str(exc))


# ---------------------------------------------------------------------------
# API: Generate Key
# ---------------------------------------------------------------------------
@app.route("/api/generate-key", methods=["POST"])
def api_generate_key():
    data = _get_json()
    algorithm = data.get("algorithm", "")

    try:
        if algorithm in ("aes-128-gcm", "aes-192-gcm", "aes-256-gcm"):
            variant = {"aes-128-gcm": "AES-128-GCM", "aes-192-gcm": "AES-192-GCM",
                       "aes-256-gcm": "AES-256-GCM"}[algorithm]
            key = aes.generate_key(variant)
        elif algorithm == "chacha20-poly1305":
            key = chacha.generate_key()
        elif algorithm == "fernet":
            key = fernet_crypto.generate_key()
        else:
            raise ApiError(f"'{algorithm}' does not use a generated key.")
        return jsonify({"success": True, "result": key})
    except (aes.CryptoError, chacha.CryptoError) as exc:
        raise ApiError(str(exc))


# ---------------------------------------------------------------------------
# API: Algorithm metadata (used by the frontend to build dynamic fields)
# ---------------------------------------------------------------------------
@app.route("/api/algorithms", methods=["GET"])
def api_algorithms():
    return jsonify({"success": True, "result": ALL_ALGORITHMS, "stats": STATS})


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
