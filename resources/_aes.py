# !/usr/bin/env python3
# DLU : 27-Jul-2026

import os

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from resources.functions import Functions


class AESClass:


    def __init__(self) -> None:
        self.IV_LENGTH = 12
        self.TAG_LENGTH = 16
        self.SALT_LENGTH = 16


    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derives a cryptographically strong 256-bit key from a weak password
        using Scrypt.
        """
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        return kdf.derive(password.encode())


    def encrypt_with_aes(self, plaintext: str, mode: str) -> str:

        password = Functions.get_password()

        # Generate fresh, random cryptographic parameters
        salt = os.urandom(self.SALT_LENGTH)
        iv = os.urandom(self.IV_LENGTH)
        key = AESClass._derive_key(password, salt)

        # Default tag for non-authenticated modes like CBC
        tag = b""

        if mode == "AES.CBC":
            # Standardize CBC using 'cryptography'
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(plaintext) + padder.finalize()

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            # Payload structure for CBC: [ SALT ] [ IV ] [ CIPHERTEXT ]
            encrypted_data = salt + iv + ciphertext

        elif mode == "AES.GCM":
            # Encrypt configuration
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            tag = encryptor.tag

            # Construct payload header: [ SALT ] [ IV ] [ TAG ] [ CIPHERTEXT ]
            encrypted_data = salt + iv + tag + ciphertext

        return encrypted_data
