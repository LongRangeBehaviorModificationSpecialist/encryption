# !/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pathlib import Path
from typing import Union
from rich.console import Console

from resources.functions import Functions


# Make the console object
c = Console()


class AESDecryptor:

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derives a secure 256-bit key from a text password and binary salt.

        Args:
            password: The plain text password entered by the user.
            salt: Fresh binary salt bytes (typically 16 bytes).

        Returns:
            bytes: A 32-byte (256-bit) derived key.
        """
        # Validate input types
        if not isinstance(password, str):
            raise TypeError("Password must be a string.")
        if not isinstance(salt, bytes):
            raise TypeError("Salt must be bytes.")

        # Configure PBKDF2 Key Derivation Function
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 32 bytes = 256-bit AES key
            salt=salt,
            iterations=600_000,  # OWASP recommended minimum for PBKDF2-HMAC-SHA256
        )

        # Derive key by encoding the string password to bytes
        return kdf.derive(password.encode("utf-8"))


    def aes_decrypt_file(self,
            target_file_path: Union[str, Path],
            password: str
    ) -> Path:
        """
        Decrypt a file encrypted with AES-CBC.

        Assumes the file structure is:
        [ 16 bytes Salt ] + [ 16 bytes IV ] + [ Encrypted Data ]

        Args:
            target_file_path: Path -> Path to the encrypted file
            password: str -> Password to derive the decryption key

        Returns:
            Path -> The path to the decrypted file
        """

        target_file_path = Path(target_file_path)

        if not target_file_path.exists():
            raise FileNotFoundError(f"Target file not found: {target_file_path}")
        if not target_file_path.is_file():
            raise IsADirectoryError(
                f"Provided path is a directory, not a file: {target_file_path}"
            )

        c.print(f"\n[bright_white]Reading encrypted file : \
{target_file_path.name}...")

        raw_payload = target_file_path.read_bytes()

        salt_size = getattr("SALT_LENGTH", 16)
        iv_size = getattr("IV_LENGTH", 16)
        min_expected_size = salt_size + iv_size + 16  # Block size


        if len(raw_payload) < min_expected_size:
            raise ValueError(f"""
Payload invalid or corrupted: file length ({len(raw_payload)} bytes)
is less than minimum required structure ({min_expected_size} bytes)."""
            )

        salt = raw_payload[:salt_size]
        iv = raw_payload[salt_size : salt_size + iv_size]
        ciphertext = raw_payload[salt_size + iv_size :]

        c.print("\n[bright_white]Deriving key and decrypting...")

        key = self._derive_key(password, salt)

        # Decrypt and Unpad using `cryptography`
        try:
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        except Exception as e:
            raise ValueError(
                "Decryption failed. The password may be incorrect, or the file is corrupted."
            ) from e

        # Determine target output path safely
        if target_file_path.suffix == ".encrypted":
            dec_file_path = target_file_path.with_suffix("")
        else:
            dec_file_path = target_file_path.with_name(
                f"{target_file_path.name}.decrypted"
            )

        # Prevent accidental target overwrites by appending a marker if destination exists
        if dec_file_path.exists():
            dec_file_path = dec_file_path.with_name(
                f"{dec_file_path.stem}_restored{dec_file_path.suffix}"
            )

        dec_file_path.write_bytes(plaintext)

        c.print(
            f"[green]Success! [bright_white]File decrypted and saved as {dec_file_path.name}"
        )
        return dec_file_path











        key = PBKDF2(
            password=password,
            salt=salt,
            dkLen=32,
            count=100000,
            hmac_hash_module=SHA256
        )

        cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)

        try:
            decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
        except (ValueError, KeyError) as e:
            raise ValueError("Decryption failed. The password may be incorrect \
or the data is corrupted") from e

        if target_file_path.suffix == ".encrypted":
            dec_file_path = target_file_path.with_suffix("")
        else:
            dec_file_path = target_file_path.with_name(
                f"{target_file_path.name}.decrypted")

        dec_file_path.write_bytes(decrypted_data)

        c.print(f"[green]Success! [bright_white]File decrypted as saved as {dec_file_path.name}")
        return dec_file_path


    @staticmethod
    def aes_decrypt_all_files_in_dir(
            target_folder_path: Path,
            password: str,
            mode=AES.MODE_CBC) -> None:

        # Turn folder path string into Path object
        f = Path(target_folder_path)

        dirs = Functions.get_all_files(target_dir_path=f)

        for file in dirs:
            AESDecryptor.aes_decrypt_single_file(
                target_file_path=file,
                password=password,
                mode=mode)
