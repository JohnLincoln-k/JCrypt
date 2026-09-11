# 🔐 JCRYPT — Cryptography & Hashing Toolkit

> **A practical web-based cryptography toolkit for encryption, decryption, hashing, encoding, and classical cipher experimentation.**

JCRYPT is a lightweight cybersecurity and cryptography web application built with **Python Flask, HTML, CSS, and Vanilla JavaScript**.

It provides an easy-to-use interface where users can select a cryptographic algorithm, perform an operation on their text, and instantly view, copy, or download the result.

JCRYPT is designed primarily for **learning, experimentation, cybersecurity education, and portfolio demonstration**.

---

## ✨ Features

### 🔒 Encryption & Decryption

JCRYPT supports modern authenticated encryption algorithms including:

* AES-128-GCM
* AES-192-GCM
* AES-256-GCM
* ChaCha20-Poly1305
* Fernet

Features include:

* Encryption
* Decryption
* Secure key generation
* Nonce/IV handling
* Authentication tag handling
* Key validation
* Error handling

Modern cryptographic operations are implemented using the well-tested Python `cryptography` library rather than implementing cryptographic primitives from scratch.

---

### 🏛️ Classical Ciphers

JCRYPT also includes classical algorithms for educational purposes:

* Caesar Cipher
* ROT13
* Atbash Cipher
* Vigenère Cipher
* Affine Cipher

Supported operations include:

* Encryption
* Decryption
* Configurable keys/parameters

> ⚠️ Classical ciphers are provided for educational purposes and should **not** be used to protect sensitive information.

---

### #️⃣ Hashing

JCRYPT supports multiple cryptographic hash algorithms:

* MD5
* SHA-1
* SHA-224
* SHA-256
* SHA-384
* SHA-512
* SHA3-224
* SHA3-256
* SHA3-384
* SHA3-512
* BLAKE2b
* BLAKE2s

The application provides information about the selected hashing algorithm, including its security status and digest length.

Example:

```text
Algorithm: SHA-256
Type: Cryptographic Hash
Digest Length: 256 bits
```

Security indicators help users understand which algorithms are currently recommended and which are deprecated.

> ⚠️ MD5 and SHA-1 are included for learning and compatibility demonstrations. They are not recommended for modern security applications.

---

### 🔤 Encoding & Decoding

JCRYPT provides several encoding utilities:

* Base64
* Hexadecimal
* URL Encoding
* Binary

Each supported encoding provides both encoding and decoding operations where applicable.

---

## 🖥️ Interface

JCRYPT uses a modern cybersecurity-inspired interface with:

* Dark theme
* Responsive design
* Algorithm selector
* Dynamic parameter fields
* Input/output panels
* Copy-to-clipboard functionality
* Download results
* Operation status indicators
* Character counters
* Algorithm information
* Error notifications

The interface is built using **HTML, CSS, and Vanilla JavaScript**, without frontend frameworks.

---

## 🧰 Technology Stack

| Technology      | Purpose                  |
| --------------- | ------------------------ |
| 🐍 Python       | Backend programming      |
| 🌐 Flask        | Web framework            |
| 🔐 Cryptography | Modern encryption        |
| #️⃣ hashlib     | Cryptographic hashing    |
| 🎲 secrets      | Secure random generation |
| HTML5           | Web structure            |
| CSS3            | User interface           |
| JavaScript      | Frontend functionality   |
| Fetch API       | Backend communication    |

---

# 🚀 Installation

## 1. Clone the Repository

```bash
git clone https://github.com/YOUR-USERNAME/JCRYPT.git
```

Navigate into the project:

```bash
cd JCRYPT
```

---

## 2. Create a Virtual Environment

### Windows

```bash
python -m venv venv
```

Activate it:

```bash
venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv venv
```

Activate it:

```bash
source venv/bin/activate
```

---

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 4. Start JCRYPT

```bash
python app.py
```

The application will normally be available at:

```text
http://127.0.0.1:5000
```

Open the address in your browser.

---

# 🔑 Example Usage

## AES Encryption

Example input:

```text
Hello, JCRYPT!
```

Select:

```text
Category: Symmetric Encryption
Algorithm: AES-256-GCM
Operation: Encrypt
```

Provide or generate a valid AES-256 key.

JCRYPT will generate the encrypted ciphertext together with the information required for decryption.

---

## AES Decryption

Select:

```text
Algorithm: AES-256-GCM
Operation: Decrypt
```

Provide the required key and encrypted data.

JCRYPT will recover the original plaintext if the cryptographic parameters are correct.

---

## SHA-256 Hash

Input:

```text
Hello World
```

Select:

```text
Category: Hashing
Algorithm: SHA-256
Operation: Hash
```

JCRYPT generates the corresponding SHA-256 digest.

Example format:

```text
SHA-256

b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
```

---

## Caesar Cipher

Input:

```text
HELLO
```

Shift:

```text
3
```

Result:

```text
KHOOR
```

Decrypting the result with the same shift returns:

```text
HELLO
```

---

# 🧪 Testing

Run the test suite using:

```bash
python -m unittest discover -s tests
```

Or, if `pytest` is included in the project's development dependencies:

```bash
pytest
```

The tests cover important functionality such as:

* Encryption/decryption round trips
* Classical cipher operations
* Hash generation
* Encoding/decoding
* Invalid input handling

---

# 🔐 Security Design

JCRYPT follows several security-focused design principles.

### Modern Cryptography

Modern encryption algorithms are implemented using established cryptographic libraries.

JCRYPT does **not** manually implement AES, ChaCha20, or other complex cryptographic primitives.

---

### Secure Randomness

Cryptographic keys and random values use Python's secure randomness facilities such as:

```python
secrets
```

rather than the ordinary `random` module.

---

### Authenticated Encryption

Where supported, JCRYPT uses authenticated encryption such as:

```text
AES-GCM
ChaCha20-Poly1305
```

This provides both confidentiality and integrity protection.

---

### No Database

JCRYPT does not require:

* MySQL
* PostgreSQL
* SQLite
* MongoDB

User input is processed without persistent storage.

---

### No User Accounts

There is no:

* Login
* Registration
* Password database
* User profile
* Authentication system

JCRYPT can be used immediately after starting the Flask application.

---

### No External APIs

Cryptographic operations are performed by the application itself.

User input does not need to be sent to an external cryptography service.

---

# ⚠️ Security & Educational Disclaimer

JCRYPT is primarily an **educational and demonstration project**.

Although modern cryptographic libraries are used, this project should not automatically be considered a professionally audited cryptographic system.

Do not rely on JCRYPT as a replacement for established, security-audited solutions when protecting highly sensitive information.

In particular:

* Do not use MD5 for security.
* Do not use SHA-1 for modern collision-resistant security.
* Do not use Caesar, ROT13, Atbash, Vigenère, or Affine ciphers for real security.
* Never reuse nonces where the selected cryptographic algorithm prohibits nonce reuse.
* Protect cryptographic keys appropriately.
* Do not expose secret keys publicly.

---

# 📚 Learning Objectives

JCRYPT can be used to understand concepts such as:

* Symmetric cryptography
* Authenticated encryption
* AES
* GCM
* ChaCha20
* Poly1305
* Fernet
* Cryptographic hashing
* SHA-2
* SHA-3
* BLAKE2
* Encoding vs encryption
* Classical cryptography
* Keys
* IVs
* Nonces
* Authentication tags
* Ciphertext
* Plaintext
* Digest generation
* Cryptographic randomness

---

# 🗺️ Roadmap

Future versions of JCRYPT may include:

* [ ] File encryption/decryption
* [ ] Password-based key derivation
* [ ] PBKDF2
* [ ] Argon2
* [ ] HMAC generation and verification
* [ ] RSA encryption/decryption
* [ ] RSA key generation
* [ ] Digital signatures
* [ ] ECC demonstrations
* [ ] JWT encoding/decoding
* [ ] Password hashing demonstrations
* [ ] Hash comparison
* [ ] Hash identification
* [ ] Cryptographic playground
* [ ] Algorithm performance comparison
* [ ] Exportable operation history
* [ ] Command-line version
* [ ] Docker support
* [ ] Automated security testing

---

# 🤝 Contributing

Contributions are welcome!

If you would like to improve JCRYPT:

### 1. Fork the repository

```bash
git fork
```

### 2. Clone your fork

```bash
git clone https://github.com/YOUR-USERNAME/JCRYPT.git
```

### 3. Create a branch

```bash
git checkout -b feature/your-feature
```

### 4. Make your changes

Follow clean coding and security practices.

### 5. Run the tests

```bash
python -m unittest discover -s tests
```

### 6. Commit your changes

```bash
git add .
git commit -m "Add: your feature"
```

### 7. Push the branch

```bash
git push origin feature/your-feature
```

Then open a Pull Request.

---

# 📜 License

This project can be released under the **MIT License**.

If this repository uses a different license, replace this section with the appropriate license information.

---

# 👨‍💻 Author

**K. John Lincoln**

Cybersecurity Enthusiast | Ethical Hacking | Cryptography | Web Security | AI Security

---

## 🔐 JCRYPT

> **Encrypt. Decrypt. Hash. Encode. Learn.**

Built with ❤️ for cybersecurity and cryptography learning.
