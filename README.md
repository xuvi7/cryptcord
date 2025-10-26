# CryptCord

A secure, end-to-end encrypted group chat application with real-time communication and access-controlled channels.
Built entirely in Go, with a lightweight HTML/JS frontend leveraging hybrid RSA + AES encryption.

> **Note**: This is not intended for production use.

## Overview

CryptCord demonstrates secure messaging and group chat functionality in a browser client, where:

* Only authorized users can access specific channels.
* Messages can be sent, edited, and deleted in real time.
* Communication remains confidential and tamper-resistant against a semi-honest server.
  Messages and keys are always encrypted client-side using AES-GCM, while RSA is used for key distribution.


## Architecture

| Component              | Description                                                                                                                     |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| **Backend (Go)**       | HTTP + WebSocket server (`cmd/server/`) handling authentication, message routing, and database operations.                      |
| **Frontend (HTML/JS)** | Pure JS client (`public/`) for login, chat UI, and cryptographic operations via Web Crypto API.                                 |
| **Database**           | SQLite database for users, channels, and encrypted message records.                                                             |
| **Communication**      | REST API for registration/login; WebSocket (`/ws/{token}`) for dynamic updates (message edits, deletes, user/channel changes).  |
| **Encryption**         | AES-GCM (symmetric) for data; RSA (asymmetric) for key exchange; PBKDF2-derived keys for password-based private-key protection. |

## Running Locally

### Prerequisites

* **Go 1.21+**
* **SQLite 3**
* Modern browser supporting Web Crypto API

### Build and Run

```bash
git clone https://github.com/xuvi7/cryptcord.git
cd cryptcord
go build -o cryptcord ./cmd/server
./cryptcord
```

Alternatively, you can use the MakeFile:
```bash
make build
make run
make clean
```

Default address:

```
http://localhost:8080
```

Visit:

* `/auth` → login/register
* `/chat` → main chat interface (after authentication)


## Cryptographic Protocol

1. **Registration**

   * Client generates:

     * Salt
     * RSA public/private keypair
     * AES key derived from password + salt (PBKDF)
   * Private key encrypted locally with password-derived AES key.
   * Server stores public key, salt, and encrypted private key.

2. **Login**

   * Server returns stored salt and encrypted private key.
   * Client decrypts locally and proves identity via challenge:

     * Server sends random code encrypted with user’s public key.
     * Client decrypts with private key and returns plaintext to server.

3. **Channel creation**

   * Channel owner generates a random AES key.
   * Key is RSA-encrypted for each channel member and sent via the server.

4. **Messaging**

   * Each message encrypted with channel’s AES key.
   * Server relays ciphertext; clients decrypt with their local AES key.


## Security Walkthrough

### 1. Threat Model

CryptCord is designed to be secure against **semi-honest servers** and **external attackers**:

* The server may relay or store data but cannot decrypt messages.
* Only clients possess plaintext AES keys or private RSA keys.

### 2. Key Protection

* **Private RSA keys** are encrypted client-side with a key derived from the password + salt.
  Even if the database leaks, attackers cannot decrypt private keys without knowing the password.
* **Channel AES keys** are encrypted using recipients’ public keys before storage or transmission.

### 3. Authentication and Session Security

* Login uses a challenge-response protocol: the server encrypts a random code with the user’s public key, requiring the private key to decrypt and respond.
* After successful authentication, a random 64-byte session token is issued as a cookie; this token authenticates subsequent API and WebSocket requests.
* Tokens are stored in-memory only and invalidated on server restart, preventing long-term hijacking.

### 4. Message Integrity and Confidentiality

* AES-GCM provides built-in authentication tags ensuring ciphertexts cannot be modified without detection.
* All cryptographic operations occur client-side; the server only forwards ciphertexts.

### 5. Replay and MITM Resistance

* WebSocket messages are authenticated through the active session token.
* Each user-specific session token and per-channel AES key ensures that replayed or intercepted ciphertexts are invalid outside their session context.
* Without the private key or symmetric key, intercepted packets remain undecipherable.

### 6. Limitations

* Password recovery is not supported (loss of password = loss of private key).
* Server restarts invalidate sessions (no persistent token storage).
* No formal audit; this is a proof-of-concept educational implementation.


## API Summary

| Endpoint        | Method    | Description                             |
| --------------- | --------- | --------------------------------------- |
| `/api/register` | POST      | Register new user, store encrypted keys |
| `/api/login`    | POST      | Verify user and issue session token     |
| `/api/getData`  | GET       | Fetch user’s channels and messages      |
| `/ws/{token}`   | WebSocket | Real-time chat, edit, and delete events |