# SecureCipher - Cryptographic Transaction Processing System

## 🚀 Project Overview

**SecureCipher** is a Django-based cryptographic middleware service that provides secure transaction processing between users and banking APIs using dual-signature authentication and client-side key generation.

### 🎯 Core Concept
SecureCipher acts as a secure "middleman" system that:
- Validates user transactions with cryptographic signatures
- Adds server-side co-signatures for dual authentication
- Encrypts payloads before forwarding to bank APIs
- Maintains tamper-proof audit logs for compliance

---

## 🧩 How It Works (Simple Explanation)

### Imagine This Scenario
Paul is a fintech developer who wants to securely send transaction details from his app to a banking service. He needs:
- 💬 **No interception** - Data can't be read by attackers
- 🧾 **Proof of origin** - Cryptographic proof Paul sent it
- 🔐 **Non-repudiation** - Even Paul can't deny sending it later

SecureCipher is like a **digital post office** that wraps your letter in a locked box, seals it with dual signatures, and guarantees it hasn't been tampered with.

### 🔄 Transaction Flow
```
[User Browser] → [SecureCipher Backend] → [Bank API]
     ↓                    ↓                    ↓
 WebCrypto Keys      Dual Signatures      Encrypted Payload
 Client Signing      Server Co-signing     AES-256-GCM
```

### Step-by-Step Process:

#### 🧑‍💻 1. User Onboarding (Getting Started)
- User (Paul) visits the web app
- SecureCipher helps generate ECDSA key pairs in browser using WebCrypto API
- **Public key** stored in database, **private key** stays in browser
- Think of private key as a digital signature stamp only Paul can use

#### 🔐 2. Sending a Secure Transaction
- Paul creates transaction: "Send ₦10,000 to Janet"
- SecureCipher performs three operations:
  1. **Signs** message with Paul's private key (proves origin)
  2. **Encrypts** message with AES-256-GCM (privacy)
  3. **Co-signs** with server key (dual authentication)

#### 🏦 3. Forwarding to Bank API
- Signed and encrypted transaction forwarded to bank's API
- Bank receives: `[Tx, Sig_P, Q_P, Sig_S, Q_S]`
- Response decrypted and returned to user

#### 🛡️ 4. Security Throughout Journey
- **TLS 1.3** for all communications
- **Tamper-proof audit logs** for every action
- **Cryptographic integrity** prevents forgery

---

## 🏗️ System Architecture

### Technology Stack
- **Backend**: Django + Django REST Framework
- **Cryptography**: Python `cryptography` library
- **Database**: PostgreSQL (SQLite for development)
- **Frontend**: JavaScript + WebCrypto API
- **Security**: TLS 1.3 with specific cipher suites

### Core Security Features
| 🔐 Security Feature | What it does |
|---------------------|--------------|
| **ECDSA Signatures** | Proves identity (digital signature) |
| **AES-GCM Encryption** | Keeps data private during transfer |
| **TLS 1.3 Enforcement** | Prevents man-in-the-middle attacks |
| **Public Key Infrastructure** | Identity verification without passwords |
| **Audit Logs** | Proves what happened, when, and by whom |

---

## 📊 Module Specifications

### 1. User Onboarding & Authentication Module
**📌 Purpose**: Register users, generate/store ECDSA public keys, link to virtual Opay accounts

**🔁 Core Functions**:
- `register_user()` - User registration with key validation
- `generate_keypair_client_side()` - WebCrypto key generation
- `store_public_key()` - Secure public key storage
- `authenticate_user()` - ECDSA signature verification

**🔐 Security**: Private keys never leave user device

### 2. Crypto Engine Module
**📌 Purpose**: Perform all cryptographic operations

**🔁 Core Functions**:
- `ecdsa_sign(message, private_key)` - Digital signature creation
- `ecdsa_verify(sig, message, public_key)` - Signature verification
- `aes256gcm_encrypt(data, key)` - Data encryption
- `aes256gcm_decrypt(ciphertext, key)` - Data decryption
- `derive_keys(shared_secret)` - HKDF-SHA384 key derivation
- `perform_ecdhe()` - Key exchange using secp384r1

**🔐 Security**: Keys zeroized after use, strong entropy sources

### 3. Transaction Processing Module
**📌 Purpose**: Handle dual-signature transaction validation and bank communication

**🔁 Core Functions**:
- `process_transaction(tx, sig_P)` - Transaction processing
- `validate_and_sign(tx, sig_P)` - Dual signature creation
- `encrypt_and_send_to_bank()` - Secure bank communication
- `handle_response_from_bank()` - Response processing

**🔐 Security**: Dual signature enforcement, encrypted payloads

### 4. TLS Middleware Module
**📌 Purpose**: Enforce TLS 1.3-only connections and security headers

**🔁 Core Functions**:
- `enforce_tls13_only(request)` - TLS version enforcement
- `inject_security_headers(response)` - Security header injection
- `validate_tls_handshake()` - Handshake validation

**🔐 Security**: ECDHE-ECDSA-AES256-GCM-SHA384 cipher suite only

### 5. Audit Log Module
**📌 Purpose**: Record cryptographic events for compliance

**🔁 Core Functions**:
- `log_event(event_type, user_id, timestamp)` - Event logging
- `retrieve_log(user_id)` - Log retrieval
- `hash_chain_append(log)` - Tamper-evident chaining

**🔐 Security**: Append-only logs with hash chaining

### 6. Client Services Module
**📌 Purpose**: Client-side cryptographic operations

**🔁 Core Functions**:
- `generate_ecdsa_keypair()` - Browser key generation
- `export_public_key()` - Public key extraction
- `sign_transaction(tx)` - Client-side signing

**🔐 Security**: Private keys stored in browser only

### 7. KeyManager Module
**📌 Purpose**: Cryptographic key lifecycle management

**🔁 Core Functions**:
- `store_public_key(user_id, public_key)` - Key storage
- `retrieve_public_key(user_id)` - Key retrieval
- `rotate_keys(user_id)` - Key rotation
- `revoke_key(user_id)` - Key revocation
- `derive_shared_secret(Q_peer, d_self)` - ECDHE operations

**🔐 Security**: Client/HSM storage only, key zeroization, rotation policies

---

## 🚀 Development Roadmap

### ✅ Phase 1: Foundation (Weeks 1-2)
- [x] Django project setup
- [x] User registration with public key validation
- [x] Basic ECDSA verification
- [x] Opay virtual account integration
- [ ] Complete authentication system

### 🎯 Phase 2: Transaction Processing (Weeks 3-4)
- [ ] Dual signature implementation
- [ ] AES-256-GCM encryption/decryption
- [ ] Bank API communication framework
- [ ] Transaction validation pipeline

### 🎯 Phase 3: Security Infrastructure (Weeks 5-6)
- [ ] TLS 1.3 middleware implementation
- [ ] Audit logging with hash chains
- [ ] Key rotation and management
- [ ] Security header enforcement

### 🎯 Phase 4: Client Integration (Weeks 7-8)
- [ ] WebCrypto frontend implementation
- [ ] ECDHE key exchange
- [ ] Complete end-to-end testing
- [ ] Performance optimization

---

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.9+
- Node.js 16+ (for frontend)
- PostgreSQL (production) / SQLite (development)

### Backend Setup
```bash
# Clone repository
git clone <repository-url>
cd securecipher

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Run migrations
python manage.py makemigrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Start development server
python manage.py runserver
```

### Required Packages
```
Django==5.2.2
djangorestframework==3.14.0
django-cors-headers==4.3.1
django-extensions==3.2.3
djangorestframework-simplejwt==5.3.0
cryptography==45.0.3
```

---

## 🔐 Cryptographic Specifications

### Key Parameters
- **Elliptic Curve**: secp384r1 (NIST P-384)
- **Signature Algorithm**: ECDSA with SHA-384
- **Encryption**: AES-256-GCM
- **Key Derivation**: HKDF-SHA384
- **TLS Version**: 1.3 only
- **Cipher Suite**: ECDHE-ECDSA-AES256-GCM-SHA384

### Security Architecture
```
Client-Side:                Server-Side:
- Private key d_P           - Private key d_S
- Public key Q_P            - Public key Q_S
- Signature Sig_P           - Co-signature Sig_S

Transaction Flow:
[Tx, Sig_P, Q_P] → SecureCipher → [Tx, Sig_P, Q_P, Sig_S, Q_S] → Bank
```

---

## 📚 API Documentation

### Authentication Endpoints
```
POST /api/users/register/     # User registration
POST /api/users/authenticate/ # ECDSA challenge-response auth
GET  /api/users/ping/         # Health check
```

### Transaction Endpoints (Planned)
```
POST /api/transactions/process/   # Process dual-signed transaction
GET  /api/transactions/history/   # Transaction history
GET  /api/transactions/{id}/      # Transaction details
```

### Key Management Endpoints (Planned)
```
POST /api/keys/rotate/       # Key rotation
POST /api/keys/revoke/       # Key revocation
GET  /api/keys/status/       # Key status
```

---

## 🧪 Testing

### Run Tests
```bash
# Run all tests
python manage.py test

# Run specific app tests
python manage.py test users
python manage.py test crypto_engine

# Run with coverage
coverage run --source='.' manage.py test
coverage report
```

### Test Categories
- **Unit Tests**: Individual function testing
- **Integration Tests**: Module interaction testing
- **Cryptographic Tests**: Security validation
- **API Tests**: Endpoint functionality

---

## 🔒 Security Considerations

### Critical Requirements
1. **Private Key Security**: Never transmitted or stored server-side
2. **Dual Signature Validation**: Both signatures required for transactions
3. **TLS 1.3 Enforcement**: Latest transport security only
4. **Audit Trail**: Tamper-evident logging for compliance
5. **Key Rotation**: Regular key updates for long-term security

### Compliance Features
- **Non-repudiation**: Cryptographic proof of transactions
- **Data Integrity**: Hash chaining prevents tampering
- **Access Control**: Role-based permissions
- **Audit Logging**: Complete transaction history

---

## 🤝 Contributing

### Development Workflow
1. Fork the repository
2. Create feature branch: `git checkout -b feature/module-name`
3. Implement with tests and documentation
4. Follow coding standards (PEP 8, docstrings)
5. Submit pull request with detailed description

### Code Standards
- All functions must have docstrings explaining "What it does"
- Maintain test coverage above 80%
- Use type hints where appropriate
- Follow Django best practices

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🆘 Support

For questions, issues, or contributions:
- **Documentation**: Check this README and inline code comments
- **Issues**: Open GitHub issues for bugs or feature requests
- **Security**: Email security@securecipher.com for security concerns

---

**SecureCipher** - Making cryptographic transaction processing simple, secure, and compliant.



Absolutely! Here’s a simple, beginner-friendly explanation of how the SecureCipher project works in real life — imagine you're explaining it to someone new to web or security development.
🧩 Imagine This Scenario

Paul is a fintech developer. He wants to securely send transaction details from his app (like money transfers or identity confirmations) to a banking service. But he wants:

    💬 No one to intercept or tamper with the data

    🧾 Proof that Paul actually sent it

    🔐 A system that even he himself can’t tamper with after sending

That’s where SecureCipher comes in. It's like a secure “middleman” system between the user and the bank.
🔐 What SecureCipher Does

    “SecureCipher is like a digital post office that wraps your letter in a locked box, seals it with a digital signature, and guarantees it hasn’t been opened or faked.”

Let’s break it down...
🧑‍💻 1. User Onboarding (Getting Started)

    A user (like Paul) goes to the web app.

    SecureCipher helps them generate a pair of digital keys in the browser (public & private).

    It stores only the public key in the database.

    The private key stays in their browser — like a personal signature stamp.

🧠 Think of the private key as a digital pen that only Paul can use to sign things.
🔐 2. Sending a Secure Transaction

    Paul creates a transaction (e.g., “send ₦10,000 to Janet”).

    SecureCipher does three things:

        Signs the message with Paul’s private key (to prove it came from him)

        Encrypts the message with strong encryption (so no one else can read it)

        Sends it to the SecureCipher backend

🔁 SecureCipher also adds its own signature to confirm that it has seen and approved the transaction (dual-signing).
🏦 3. Forwarding to the Bank API

    The signed and encrypted transaction is then forwarded to the bank's API.

    If the bank replies (e.g., “success”), SecureCipher decrypts the reply and returns it to the user.

🛡️ 4. Security Throughout the Journey

    All communication is over TLS 1.3, the latest web security protocol.

    Every action (e.g., “Paul signed transaction”) is logged in a tamper-proof log.

    Even if someone hacks into the system, they can’t fake the logs or keys — they’re cryptographically protected.

📋 5. Why It’s Special
🔐 Security Feature	What it does
ECDSA Signatures	Proves identity (like a digital signature)
AES-GCM Encryption	Keeps data private during transfer
TLS 1.3 Enforcement	Prevents Man-in-the-middle attacks
Public Key Infrastructure	Helps verify identity without passwords
Audit Logs	Prove what happened, when, and by whom
📦 In Simple Words:

    SecureCipher lets you send highly secure, verified transactions over the internet, and makes sure no one can lie about what happened.

Would you like me to create a one-page PDF or client-friendly pitch using this explanation — to help them grasp it instantly during a demo?
