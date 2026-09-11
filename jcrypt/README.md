# JCRYPT

**A Practical Encryption, Decryption & Hashing Toolkit**

JCRYPT is a local, stateless Flask web app for experimenting with modern
authenticated encryption, classical ciphers, cryptographic hashing, and
text encoding — all in your browser, all processed on your own machine.

## Features

- **Symmetric encryption:** AES-128/192/256-GCM, ChaCha20-Poly1305, Fernet
- **Classical ciphers:** Caesar, ROT13, Atbash, Vigenere, Affine
- **Hashing:** MD5, SHA-1, SHA-224/256/384/512, SHA-3-224/256/384/512, BLAKE2b, BLAKE2s
- **Encoding:** Base64, Hex, URL encoding, Binary
- **Secure key generation** using Python's `secrets` module
- **No database, no accounts, no persistence** — everything lives in memory for the life of a request

## Requirements

- Python 3.9+

## Setup

```bash
# from the jcrypt/ directory
python -m venv venv
source venv/bin/activate        # on Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```bash
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

## Run tests

```bash
pip install pytest
pytest tests/
```

## Project structure

```
jcrypt/
├── app.py                  # Flask app + routes
├── requirements.txt
├── crypto/
│   ├── aes.py               # AES-GCM
│   ├── chacha.py            # ChaCha20-Poly1305
│   ├── fernet_crypto.py     # Fernet
│   ├── classical.py         # Caesar, ROT13, Atbash, Vigenere, Affine
│   ├── hashing.py           # hashlib-backed digests
│   ├── encoding.py          # Base64, Hex, URL, Binary
│   └── registry.py          # Algorithm metadata used by routes + UI
├── templates/               # Jinja2 templates
├── static/
│   ├── css/style.css
│   └── js/app.js
└── tests/                   # pytest unit tests
```

## API

All endpoints accept and return JSON.

| Endpoint              | Method | Purpose                                   |
|------------------------|--------|--------------------------------------------|
| `/api/encrypt`         | POST   | Encrypt text with the chosen algorithm     |
| `/api/decrypt`         | POST   | Decrypt text with the chosen algorithm     |
| `/api/hash`             | POST   | Compute a digest                           |
| `/api/encode`           | POST   | Encode text (Base64 / Hex / URL / Binary)  |
| `/api/decode`           | POST   | Decode text                                |
| `/api/generate-key`     | POST   | Generate a secure key for AES/ChaCha/Fernet|
| `/api/algorithms`       | GET    | Full algorithm metadata used by the UI     |

Example:

```bash
curl -X POST http://127.0.0.1:5000/api/hash \
  -H "Content-Type: application/json" \
  -d '{"algorithm": "sha256", "text": "Hello World"}'
```

```json
{"success": true, "result": "a591a6d40bf420...", "details": {"...": "..."}}
```

## Security notes

- AES and ChaCha20-Poly1305 are used only in authenticated (AEAD) modes; ECB is never offered.
- No cryptographic primitive is implemented from scratch — everything routes through the
  `cryptography` package or Python's standard `hashlib`.
- Keys and nonces are generated with `secrets`, never `random`.
- Classical ciphers (Caesar, ROT13, Atbash, Vigenere, Affine) are clearly labeled
  as educational only — they provide no real confidentiality.
- Hashing is presented as one-way; the UI never implies a hash can be "decrypted".
- No plaintext, keys, or ciphertext are logged or written to disk.
