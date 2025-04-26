# Secure Transfer Protocol Design (STX)

## Overview
STX is a secure file transfer protocol designed for reliable, authenticated, and confidential file transfers over TCP/IP networks. The protocol supports resilience against connection interruptions with resume capability.

## Handshake Sequence

The handshake process establishes a secure connection between Client and Server, exchanging cryptographic parameters needed for secure communication.

```
Client                                            Server
  |                                                 |
  |------------------ HELLO ----------------------->|
  |  (client_nonce, client_pubkey, cipher_suites)   |
  |                                                 |
  |<----------------- WELCOME ----------------------|
  |  (server_nonce, server_pubkey,                  |
  |   selected_cipher, server_signature)            |
  |                                                 |
  |------------------ VERIFY ---------------------->|
  |  (client_signature, encrypted_client_proof)     |
  |                                                 |
  |<----------------- READY ------------------------|
  |  (encrypted_server_proof)                       |
  |                                                 |
  |============= SECURE DATA EXCHANGE ==============|
  |                                                 |
```

### Step Details:

1. **HELLO**: 
   - Client initiates connection by sending:
     - `client_nonce`: Random value to prevent replay attacks
     - `client_pubkey`: Client's ephemeral public key
     - `cipher_suites`: List of supported encryption algorithms

2. **WELCOME**:
   - Server responds with:
     - `server_nonce`: Random value to prevent replay attacks
     - `server_pubkey`: Server's ephemeral public key
     - `selected_cipher`: Chosen encryption algorithm from client's list
     - `server_signature`: Digital signature proving server's identity
       (sig = sign(server_private_key, hash(client_nonce + server_nonce + server_pubkey)))

3. **VERIFY**:
   - Client authenticates itself by sending:
     - `client_signature`: Digital signature proving client's identity
       (sig = sign(client_private_key, hash(server_nonce + client_nonce + client_pubkey)))
     - `encrypted_client_proof`: Encrypted validation data to confirm key derivation
       (encrypted with the session key derived from both parties' ephemeral keys)

4. **READY**:
   - Server completes handshake by sending:
     - `encrypted_server_proof`: Encrypted validation data to confirm key derivation
       (encrypted with the shared session key)

5. **SECURE DATA EXCHANGE**:
   - Subsequent data is encrypted with the established session key

## Sequence Diagram for the whole process

```
Client (stx-send)                                        Server (stx-recv)
    |                                                              |
    |------------------------ Init Connection -------------------->|
    |                                                              |
    |<----------------------- Server Hello (server_nonce) ---------|
    |                                                              |
    |------------------------ Client Hello (client_nonce) -------->|
    |                                                              |
    |------------ Client Auth (HMAC(client_nonce+server_nonce)) -->|
    |                                                              |
    |<----------- Server Auth (HMAC(client_nonce+server_nonce)) ---|
    |                                                              |
    |----------- Session Key Negotiation (session_id, iv) -------->|
    |                                                              |
    |<----------------------- Session Key Confirmation ------------|
    |                                                              |
    |------------------------ File Metadata (encrypted) ---------->|
    |                                                              |
    |------------------------ File Blocks (encrypted) ------------>|
    |       ...                                                    |
    |<----------------------- Block Acknowledgments ---------------|
    |       ...                                                    |
```

## Protocol Specification

### File Transfer Protocol

1. **Block Structure**
   ```
   [4 bytes: Block Sequence Number]
   [4 bytes: Block Size]
   [N bytes: Encrypted Block Data]
   [16 bytes: Authentication Tag]
   [4 bytes: CRC32 Checksum]
   ```

2. **Resume Protocol**
   - Server maintains a record of received blocks
   - Upon reconnection, client requests last acknowledged block
   - Transfer resumes from next block

3. **Error Handling**
   - Connection failures trigger exponential backoff retry
   - Integrity failures trigger block retransmission
   - Authentication failures terminate the session

## Threat Model

### Security Considerations

1. **Nonce Reuse Prevention**
   - Each session uses unique nonces from both client and server
   - Nonces are combined with timestamps to prevent replay attacks
   - Session keys are derived using both nonces to ensure uniqueness

2. **Replay Attack Protection**
   - Message sequence numbers in encrypted payloads
   - Timestamped messages with limited validity window
   - Server maintains a record of recently processed message IDs

3. **Man-in-the-Middle Protection**
   - Mutual authentication using pre-shared keys
   - HMAC verification of handshake messages
   - Full verification of cryptographic parameters

4. **Data Confidentiality**
   - AES-256-GCM encryption for file content
   - Encrypted file metadata
   - Secure key derivation using HKDF

5. **Data Integrity**
   - Authenticated encryption with GCM mode
   - HMAC verification for control messages
   - CRC checksums for individual blocks

## Implementation Limitations

1. **Performance Considerations**:
   - Handshake process requires multiple round trips, increasing latency for new connections
   - Full cryptographic operations impose CPU overhead compared to unencrypted protocols
   - Small message size overhead due to nonces, sequence numbers, and authentication data

2. **Compatibility Constraints**:
   - Not compatible with systems requiring fixed-size headers
   - Requires support for modern cryptographic algorithms
   - May have higher power consumption on resource-constrained devices

3. **Deployment Considerations**:
   - Requires PKI or pre-shared key infrastructure for initial authentication
   - Key rotation procedures must be implemented separately
   - Certificate validation chain may add complexity

4. **Security Trade-offs**:
   - No built-in traffic analysis resistance
   - Side-channel attack protections must be implemented at the cryptographic library level
   - Default parameters balance security and performance, but may need adjustment for specific use cases

