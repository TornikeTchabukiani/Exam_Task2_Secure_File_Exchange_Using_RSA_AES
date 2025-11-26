"""
Secure File Exchange Using RSA + AES Hybrid Encryption
"""

import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


class HybridEncryption:
    def __init__(self):
        self.backend = default_backend()

    def generate_rsa_keypair(self):
        """Generate RSA key pair for Bob"""
        print("[*] Generating RSA key pair for Bob...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        public_key = private_key.public_key()

        # Save private key
        with open('private.pem', 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Save public key
        with open('public.pem', 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        print("[✓] RSA keys generated: public.pem, private.pem")
        return private_key, public_key

    def generate_aes_key_iv(self):
        """Generate random AES-256 key and IV"""
        print("[*] Generating AES-256 key and IV...")
        aes_key = os.urandom(32)  # 256 bits
        iv = os.urandom(16)  # 128 bits
        print("[✓] AES key and IV generated")
        return aes_key, iv

    def encrypt_file_aes(self, filename, aes_key, iv):
        """Encrypt file using AES-256-CBC"""
        print(f"[*] Encrypting {filename} with AES-256...")

        # Read plaintext
        with open(filename, 'rb') as f:
            plaintext = f.read()

        # Calculate and store original hash
        original_hash = hashlib.sha256(plaintext).hexdigest()
        with open('original_hash.txt', 'w') as f:
            f.write(original_hash)
        print(f"[✓] Original SHA-256 hash: {original_hash}")

        # Pad plaintext
        padding_length = 16 - (len(plaintext) % 16)
        plaintext_padded = plaintext + bytes([padding_length] * padding_length)

        # Encrypt
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext_padded) + encryptor.finalize()

        # Save encrypted file
        with open('encrypted_file.bin', 'wb') as f:
            f.write(ciphertext)

        print("[✓] File encrypted: encrypted_file.bin")
        return original_hash

    def encrypt_aes_key_rsa(self, aes_key):
        """Encrypt AES key using RSA public key"""
        print("[*] Encrypting AES key with Bob's RSA public key...")

        # Load public key
        with open('public.pem', 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=self.backend)

        # Encrypt AES key
        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Save encrypted AES key
        with open('aes_key_encrypted.bin', 'wb') as f:
            f.write(encrypted_key)

        print("[✓] AES key encrypted: aes_key_encrypted.bin")

    def decrypt_aes_key_rsa(self):
        """Decrypt AES key using RSA private key"""
        print("[*] Bob decrypting AES key with his RSA private key...")

        # Load private key
        with open('private.pem', 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=self.backend
            )

        # Load encrypted AES key
        with open('aes_key_encrypted.bin', 'rb') as f:
            encrypted_key = f.read()

        # Decrypt AES key
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        print("[✓] AES key decrypted successfully")
        return aes_key

    def decrypt_file_aes(self, aes_key, iv):
        """Decrypt file using AES-256-CBC"""
        print("[*] Decrypting encrypted_file.bin with AES-256...")

        # Read encrypted file
        with open('encrypted_file.bin', 'rb') as f:
            ciphertext = f.read()

        # Decrypt
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding
        padding_length = plaintext_padded[-1]
        plaintext = plaintext_padded[:-padding_length]

        # Save decrypted file
        with open('decrypted_message.txt', 'wb') as f:
            f.write(plaintext)

        print("[✓] File decrypted: decrypted_message.txt")
        return plaintext

    def verify_integrity(self, decrypted_data):
        """Verify file integrity using SHA-256 hash"""
        print("[*] Verifying file integrity...")

        # Calculate hash of decrypted data
        decrypted_hash = hashlib.sha256(decrypted_data).hexdigest()

        # Load original hash
        with open('original_hash.txt', 'r') as f:
            original_hash = f.read().strip()

        print(f"[✓] Original hash:  {original_hash}")
        print(f"[✓] Decrypted hash: {decrypted_hash}")

        if original_hash == decrypted_hash:
            print("[✓] INTEGRITY VERIFIED: Hashes match!")
            return True
        else:
            print("[✗] INTEGRITY FAILED: Hashes do not match!")
            return False


def main():
    print("=" * 60)
    print("  Secure File Exchange: RSA + AES Hybrid Encryption")
    print("=" * 60)
    print()

    crypto = HybridEncryption()

    # Step 1: Generate RSA key pair for Bob
    print("STEP 1: Generate RSA Key Pair")
    print("-" * 60)
    private_key, public_key = crypto.generate_rsa_keypair()
    print()

    # Step 2: Create Alice's message
    print("STEP 2: Prepare Alice's Message")
    print("-" * 60)
    if not os.path.exists('alice_message.txt'):
        message = """Dear Bob,

This is a highly confidential message that demonstrates hybrid encryption.
We are using RSA to secure the AES key, and AES to encrypt this message.

This approach combines:
- RSA's strength for key exchange (asymmetric)
- AES's efficiency for data encryption (symmetric)

The message is signed with integrity verification using SHA-256.

Best regards,
Alice"""
        with open('alice_message.txt', 'w') as f:
            f.write(message)
        print("[✓] Created alice_message.txt")
    else:
        print("[✓] alice_message.txt already exists")
    print()

    # Step 3: Generate AES key and IV
    print("STEP 3: Generate AES-256 Key and IV")
    print("-" * 60)
    aes_key, iv = crypto.generate_aes_key_iv()
    print()

    # Step 4: Encrypt file with AES
    print("STEP 4: Encrypt File with AES-256")
    print("-" * 60)
    original_hash = crypto.encrypt_file_aes('alice_message.txt', aes_key, iv)
    print()

    # Step 5: Encrypt AES key with RSA
    print("STEP 5: Encrypt AES Key with RSA Public Key")
    print("-" * 60)
    crypto.encrypt_aes_key_rsa(aes_key)
    print()

    # Step 6: Bob decrypts AES key with RSA
    print("STEP 6: Bob Decrypts AES Key with RSA Private Key")
    print("-" * 60)
    decrypted_aes_key = crypto.decrypt_aes_key_rsa()
    print()

    # Step 7: Bob decrypts file with AES
    print("STEP 7: Bob Decrypts File with AES-256")
    print("-" * 60)
    decrypted_data = crypto.decrypt_file_aes(decrypted_aes_key, iv)
    print()

    # Step 8: Verify integrity
    print("STEP 8: Verify File Integrity")
    print("-" * 60)
    crypto.verify_integrity(decrypted_data)
    print()

    print("=" * 60)
    print("  Process Complete!")
    print("=" * 60)
    print("\nFiles created:")
    print("  - alice_message.txt")
    print("  - encrypted_file.bin")
    print("  - aes_key_encrypted.bin")
    print("  - decrypted_message.txt")
    print("  - public.pem")
    print("  - private.pem")


if __name__ == "__main__":
    main()