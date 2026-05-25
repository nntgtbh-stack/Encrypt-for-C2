# Encrypt message

Small module for encrypt message between client and server

## Status
...

## Directory Layout

```txt
C2E/
├── crypto_aes_gcm.py     # Core AES-256-GCM encryption module
├── agent.py              # Simple encrypted client test
├── server.py             # Simple encrypted server test
├── test.py               # Local testing / experimentation
├── README.md             # Project documentation
└── venv/                 # Python virtual environment
```

## Features

* AES-256-GCM authenticated encryption
* Secure message encryption and decryption
* PBKDF2-HMAC-SHA256 key derivation
* Random salt generation for key strengthening
* Random nonce generation for every encryption operation
* Integrity verification using GCM authentication tag
* Base64 encoded payload format

## Setup 

Active virtual environment

    python3 -m venv venv
    source venv/bin/activate        # Linux/Mac
    .venv\Scripts\activate           # Windows

Dependencies 

    Install required package:
    pip install cryptography

## Example Workflow
    Agent 
    ↓ 
    Encrypt Message AES-256-GCM 
    ↓ 
    TCP Socket
    ↓ 
    Server 
    ↓ 
    Decrypt Process Request
    ↓ 
    Encrypt Response Agent

## Security Notes
    This project is intended for educational purposes.

    Current limitations:

    -Shared password is hardcoded
    -No TLS layer
    -No public/private key exchange
    -No authentication system

    Possible future improvements:

    -RSA/ECDH key exchange
    -TLS transport
    -Session tokens
    -Client authentication
    -Command execution framework
    -HTTP/WebSocket transport
