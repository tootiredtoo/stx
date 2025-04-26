# Secure Transfer Protocol Design (STX)

## Overview
STX is a secure file transfer protocol designed for reliable, authenticated, and confidential file transfers over TCP/IP networks. The protocol supports resilience against connection interruptions with resume capability.

## Sequence Diagram for Handshake

```
Client (stx-send)                 Server (stx-recv)
    |                                  |
    |--- Init Connection ------------->|
    |                                  |
    |<-- Server Hello (nonce_s) -------|
    |                                  |
    |--- Client Hello (nonce_c) ------>|
    |                                  |
    |--- Client Auth (HMAC) ---------->|
    |                                  |
    |<-- Server Auth (HMAC) -----------|
    |                                  |
    |--- Session Key Negotiation ----->|
    |                                  |
    |<-- Session Key Confirmation -----|
    |                                  |
    |--- File Metadata (encrypted) --->|
    |                                  |
    |--- File Blocks (encrypted) ----->|
    |       ...                        |
    |<-- Block Acknowledgments --------|
    |       ...                        |
```

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

### Implementation Limitations

1. **Key Management**
   - Current implementation uses a pre-shared key approach
   - No certificate-based authentication in this version
   - Manual key distribution required

2. **Performance Considerations**
   - Block size affects throughput and resume granularity
   - Current implementation optimized for reliability over maximum speed
   - Memory usage increases with concurrent connections

3. **Platform Dependencies**
   - Relies on OpenSSL for cryptographic operations
   - POSIX socket API for networking (platform-specific adaptations may be needed)

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