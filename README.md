# Secure File Exchange Using RSA + AES

## Overview
This project implements a hybrid encryption protocol combining RSA asymmetric encryption and AES symmetric encryption for secure file exchange between Alice and Bob.

## Encryption/Decryption Flow

Alice wants to send Bob a secret file securely. The process works as follows:

First, Bob generates an RSA key pair consisting of a public key and a private key. Bob shares his public key with Alice while keeping his private key secret.

Alice creates her plaintext message and saves it in alice_message.txt. She then generates a random AES-256 key and a random initialization vector. Alice uses this AES key to encrypt her message file using AES-256-CBC mode, producing encrypted_file.bin. 

Since AES is a symmetric encryption algorithm, Alice needs to securely share the AES key with Bob. She encrypts the AES key using Bob's RSA public key with OAEP padding, creating aes_key_encrypted.bin. Alice then transmits both the encrypted file and the encrypted AES key to Bob. The IV can be transmitted in plaintext.

On Bob's side, he first decrypts the AES key using his RSA private key. With the recovered AES key and the IV, Bob can now decrypt the encrypted file to recover Alice's original message, saving it as decrypted_message.txt.

Finally, the system computes a SHA-256 hash of the original file and compares it with the hash of the decrypted file to verify integrity and ensure the message was not tampered with during transmission.

## Files Generated
alice_message.txt contains the original plaintext message from Alice. encrypted_file.bin is the message encrypted with AES-256. aes_key_encrypted.bin holds the AES key encrypted with RSA-2048. decrypted_message.txt is the final decrypted message recovered by Bob. public.pem and private.pem are Bob's RSA public and private keys respectively.

## AES vs RSA Comparison

### Speed Performance

AES-256 is significantly faster than RSA-2048 in all operations. For encryption, AES can process data at speeds of 100 to 500 megabytes per second, while RSA can only manage approximately 0.1 to 1 megabyte per second. The difference is even more pronounced for decryption, where AES maintains its 100 to 500 megabytes per second speed, but RSA slows down to just 0.01 to 0.1 megabytes per second. Key generation also differs dramatically with AES keys being generated in less than one millisecond, while RSA key generation takes 100 to 500 milliseconds.

In practical terms, encrypting a one megabyte file with AES takes only 2 to 10 milliseconds, whereas RSA would theoretically take 1000 to 5000 milliseconds if it could handle such large files, which it cannot. This makes AES approximately 500 to 2500 times faster than RSA for data encryption.

### Use Cases

AES symmetric encryption is best suited for encrypting large files, real-time communication, disk encryption, and database encryption. Its main advantage is very high speed and efficiency for large amounts of data with no practical size limits. However, it requires secure key distribution beforehand since both parties must share the same secret key. Common examples include HTTPS data transfer after the initial handshake, encrypted databases, VPN connections, and full disk encryption systems like BitLocker and FileVault.

RSA asymmetric encryption excels at key exchange, digital signatures, authentication, and encrypting small amounts of data. Its primary advantage is that it eliminates the need for pre-shared secrets since the public key can be distributed freely while the private key remains secret. The main drawbacks are very slow performance and a strict data size limitation of approximately 190 bytes for 2048-bit RSA keys. RSA is commonly used in SSL/TLS handshakes, email encryption systems like PGP, SSH authentication, and digital certificates.

### Security Comparison

From a security perspective, AES-256 provides 256-bit symmetric security, while RSA-2048 provides approximately 112-bit equivalent security. AES has the advantage of being more resistant to quantum computing attacks compared to RSA, which is vulnerable to quantum algorithms like Shor's algorithm. However, RSA solves the key distribution problem elegantly since public keys can be shared openly, whereas AES requires a secure channel to distribute the shared secret key. AES can encrypt unlimited amounts of data, while RSA is limited to about 190 bytes for a 2048-bit key. Both algorithms have different computational costs, with AES being far less computationally expensive than RSA.

### Why Hybrid Encryption?

This project uses hybrid encryption to combine the strengths of both algorithms while avoiding their weaknesses. RSA solves AES's key distribution problem by providing a secure method to exchange the encryption key. AES solves RSA's speed and size limitations by handling the actual bulk data encryption efficiently.

This hybrid approach is not just theoretical but is the industry standard used in virtually all secure communication systems. SSL/TLS protocols used in HTTPS websites employ hybrid encryption. PGP and GPG email encryption systems use this approach. Modern messaging apps like Signal and WhatsApp use hybrid encryption for end-to-end encryption. VPN protocols including OpenVPN and IPSec also rely on this methodology.

The workflow in these systems is consistent: use asymmetric encryption like RSA for the initial key exchange, then switch to symmetric encryption like AES for encrypting the actual data. This provides both security and performance.

## Technical Details

The implementation uses RSA with 2048-bit keys and OAEP padding with SHA-256 for secure key encryption. AES uses 256-bit keys in CBC mode with PKCS#7 padding for data encryption. SHA-256 cryptographic hashing provides integrity verification. Each encryption operation uses a unique 128-bit random initialization vector to ensure security.

## Security Features

The system provides confidentiality through AES-256 encryption of the message content. Secure key exchange is ensured by RSA-2048 encryption of the AES key. Integrity verification uses SHA-256 hashing to detect any tampering. Each encryption uses a random IV to prevent pattern analysis. Strong padding schemes including OAEP for RSA and PKCS#7 for AES protect against various attacks.

This implementation demonstrates the fundamental principles of modern cryptographic systems used to secure internet communications, protect sensitive data, and enable secure file exchange.
