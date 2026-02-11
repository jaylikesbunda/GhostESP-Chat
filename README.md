# GhostESP: Chat WIP

Standalone, serverless, peer-to-peer, end-to-end encrypted chat system running on ESP32 microcontrollers.

**A spin-off of GhostESP: Revival firmware.**


<img width="1391" height="739" alt="image" src="https://github.com/user-attachments/assets/b3287b8d-1fe8-4506-8733-f39cc0e262a2" />


## Disclaimer

**This is experimental software under active development.** While GhostESP: Chat implements cryptographic best practices you should be aware of current limitations:

- **Work in Progress**: This firmware has not undergone any professional security audit
- **TOFU Trust Model**: First connection accepts any public key - verify fingerprints out-of-band to detect MITM attacks
- **Physical Security**: No protection against attackers with physical device access
- **Metadata Leakage**: Connection metadata (IP addresses, timing, packet sizes) is visible on the network
- **No Multi-Device Sync**: Each ESP32 has its own identity; no shared state across devices

This project is intended for educational purposes, privacy enthusiasts, and experimentation.

## Security

- **Encryption**: ChaCha20-Poly1305 AEAD
- **Key Exchange**: X25519 (Curve25519 ECDH)
- **Key Derivation**: HKDF-SHA256
- **Forward Secrecy**: Signal Protocol Double Ratchet
- **Trust Model**: TOFU (Trust On First Use) with key pinning

## How It Works

### Network Architecture

GhostESP: Chat uses direct **TCP connections over WiFi** (port 8000 by default). Devices can communicate:

- **Local Network**: Direct P2P connections between ESP32 devices on the same WiFi network
- **Internet-Wide**: External connections using UPnP automatic port forwarding and public IP discovery
  - UPnP IGD protocol automatically configures router port mappings
  - Public IP discovered via external services (ipify, AWS checkip, icanhazip, wtfismyip)
  - No relay servers or central infrastructure required

### Initial Pairing

When two ESP32 devices connect for the first time:

1. **Key Generation**: Each device generates an X25519 (Curve25519) identity keypair on boot
2. **Handshake Exchange**:
   - Initiator sends `HANDSHAKE_INIT` containing their public key
   - Responder sends `HANDSHAKE_ACK` containing their public key
3. **Shared Secret**: Both devices perform ECDH to compute a shared secret
4. **Ratchet Initialization**: The shared secret initializes the Double Ratchet
   - Initiator becomes "Alice" in the ratchet protocol
   - Responder becomes "Bob" in the ratchet protocol
5. **TOFU Trust**: Public keys are pinned for future connections (Trust On First Use)

### Message Exchange

For each message sent:

1. **Ratchet Encryption**: Current chain key derives a unique message key
2. **AEAD Encryption**: Message encrypted with ChaCha20-Poly1305 using the message key
3. **Ratchet Header**: Each message includes DH public key, previous chain length (PN), and message counter (N)
4. **Wire Format**: Binary protocol with type, counter, length, ciphertext, and authentication tag
5. **Transmission**: Encrypted packet sent over TCP connection
6. **Decryption**: Receiver uses ratchet state to derive message key and decrypt
7. **Ratchet Advance**: Both sides update their ratchet state after each message

### Forward Secrecy

The Double Ratchet implementation provides:

- **Forward Secrecy**: Compromising a device cannot decrypt past messages (old keys are deleted)
- **Post-Compromise Security**: Security automatically recovers after a DH ratchet step
- **Per-Message Keys**: Each message uses a unique key derived from the chain key
- **Out-of-Order Support**: Skipped message keys are stored (up to 200) for delayed delivery


## Resources

- [ESP-IDF Documentation](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/)
- [mbedTLS API Reference](https://mbed-tls.readthedocs.io/)
- [Curve25519 Paper](https://cr.yp.to/ecdh.html)
- [ChaCha20-Poly1305 RFC 7539](https://tools.ietf.org/html/rfc7539)
