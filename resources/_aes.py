# !/usr/bin/env python3
# DLU : 30-Jul-2026

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import os
from pathlib import Path
from rich.prompt import Prompt
from typing import List

# Import the console object from the main __init__.py file
from . import console
from resources.functions import Functions
from resources.prompts import AES_ENCRYPTION_PROMPT


class AESClass:


    def __init__(self, app_instance) -> None:
        """Store a reference to the main app loop controller."""
        self.app = app_instance
        self.IV_LENGTH = 12  # Standard 96-bit IV for AES-GCM
        self.TAG_LENGTH = 16
        self.SALT_LENGTH = 16


    def return_to_main_menu(self) -> None:
        """Returns control cleanly back to the main menu processor."""
        self.app.main(self)


    @staticmethod
    def _derive_key(
        password: bytearray | bytes | str,
        salt: bytes
    ) -> bytes:
        """Derives a 256-bit key from a password buffer using Scrypt (N=2^17
        for improved GPU attack resistance).
        """
        # If a string gets passed, encode it; otherwise use raw buffer
        pwd_buffer = (
            password.encode("utf-8") if isinstance(password, str) else password
        )
        kdf = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1)
        return kdf.derive(pwd_buffer)


    def aes_encrypt_single_file(self, target_file_path: Path | str) -> Path:
        """Encrypts a single file using AES (GCM with native AEAD)."""
        target_file_path = Path(target_file_path)

        if not target_file_path.is_file():
            console.print(
                f"[bright_red][!] {target_file_path.name} does not exist or "
                "is a directory."
            )
            raise FileNotFoundError(
                f"Invalid target file : {target_file_path}"
            )

        password = Functions.get_password()

        try:
            console.print(
                f"[bright_white][-] Reading file : {target_file_path.name}..."
            )
            plaintext = target_file_path.read_bytes()
            console.print(
                "[bright_white][-] File content read successfully..."
            )

            # Generate fresh, random cryptographic parameters
            salt = os.urandom(self.SALT_LENGTH)
            iv = os.urandom(self.IV_LENGTH)  # 96-bit IV is standard for GCM
            key = AESClass._derive_key(password, salt)

            console.print(f"[bright_white][-] Encrypting file data...")

            aesgcm = AESGCM(key)

            ciphertext = aesgcm.encrypt(iv, plaintext, associated_data=None)

            # Construct payload header: [ SALT ] [ IV ] [ CIPHERTEXT ]
            encrypted_data = salt + iv + ciphertext

            encrypted_file_path = target_file_path.with_name(
                f"{target_file_path.name}.encrypted"
            )
            encrypted_file_path.write_bytes(encrypted_data)

            # UI Output
            console.print(
                f"[green3][-] Encrypted {target_file_path.name:34s}{'->':7s}"
                f"{encrypted_file_path.name}"
            )

            return encrypted_file_path

        except Exception as e:
            console.print(
                f"[bright_red][!] Failed to encrypt {target_file_path.name} "
                f": {e}"
            )


    def aes_encrypt_files_in_folder(
        self,
        target_dir_path: Path | str
    ) -> List[Path]:
        """Recursively encrypts all valid unencrypted files within a directory
        using safely using AES (GCM or CBC) and independent salt derivation.
        """
        target_dir_path = Path(target_dir_path)

        if not target_dir_path.is_dir():
            console.print(
                f"[bright_red][!] {target_dir_path} does not exist or is not "
                "a valid directory."
            )
            return []

        console.print(
            f"[green3][-] {target_dir_path} validated. Fetching targets..."
        )

        try:
            all_files = [
                f for f in target_dir_path.rglob("*")
                if f.is_file() and f.suffix != ".encrypted"
            ]
        except Exception as e:
            console.print(
                f"[bright_red][!] Failed to retrieve files from "
                f"{target_dir_path} : {e}"
            )
            return []

        if not all_files:
            console.print(
                f"[yellow][!] No valid files to encrypt in {target_dir_path}"
            )
            return []

        successful_encryptions: List[Path] = []
        failed_encryptions: List[Path] = []

        for file_path in all_files:
            try:
                encrypted_path = AESClass.aes_encrypt_single_file(
                    self,
                    target_file_path=file_path
                )
                successful_encryptions.append(encrypted_path)
            except Exception as e:
                console.print(
                    f"[bright_red][!] Error encrypting {file_path.name} : {e}"
                )
                failed_encryptions.append(file_path)

        if successful_encryptions:
            console.print(
                "[green][-] ** Action Completed **\nSuccessfully encrypted "
                f"{len(successful_encryptions)} files in {target_dir_path} :"
            )
            for encrypted_file in successful_encryptions:
                console.print(
                    f"[green]\t{encrypted_file.name}"
                )

        if failed_encryptions:
            console.print(
                f"[bright_red][!] ** Warning **\nFailed to encrypt "
                f"{len(failed_encryptions)} files :"
            )
            for failed_file in failed_encryptions:
                console.print(
                    f"[bright_red]\t{failed_file.name}"
                )

        return successful_encryptions


    def get_aes_encryption_choice(self) -> None:
        aes_encryption_choice = Prompt.ask(
            AES_ENCRYPTION_PROMPT,
            choices=["1", "2", "r", "q"],
            show_choices=False
        ).strip().lower()

        match aes_encryption_choice:
            case "1":
                target_file_path = Functions.get_file_path(text="encrypted")
                AESClass.aes_encrypt_single_file(
                    self,
                    target_file_path=target_file_path
                )
            case "2":
                target_dir_path = Functions.get_folder_path(text="encrypted")
                AESClass.aes_encrypt_files_in_folder(
                    self,
                    target_dir_path=target_dir_path
                )
            case "r":
                self.return_to_main_menu()
            case "q":
                Functions.exit_application()


    def aes_decrypt_single_file(self, target_file_path: Path | str) -> None:
        """Decrypts a single file encrypted with AES-GCM."""
        target_file_path = Path(target_file_path)

        # Ask for password using Rich (returns a str object)
        if not target_file_path.is_file():
            console.print(
                f"[bright_red][!] {target_file_path.name} does not exist or "
                "is a directory."
            )
            raise FileNotFoundError(
                f"Invalid target file : {target_file_path}"
            )


        password_str = Prompt.ask(
            "[bright_white][-] Enter the password to decrypt the file(s) ",
            password=True
        )
        # Convert string to mutable bytearray
        password_bytes = bytearray(password_str.encode("utf-8"))

        try:
            console.print(
                f"[bright_white][-] Reading encrypted file : "
                f"{target_file_path.name}..."
            )
            encrypted_data = target_file_path.read_bytes()

            min_length = self.SALT_LENGTH + self.IV_LENGTH + 16
            if len(encrypted_data) < min_length:
                raise ValueError(
                    "File is corrupted or too short to be a valid AES-GCM "
                    "payload."
                )

            try:
                # Parse payload layout: [ SALT ] [ IV ] [ CIPHERTEXT + TAG ]
                salt = encrypted_data[: self.SALT_LENGTH]
                iv = encrypted_data[
                    self.SALT_LENGTH : self.SALT_LENGTH + self.IV_LENGTH
                ]
                ciphertext_with_tag = encrypted_data[
                    self.SALT_LENGTH + self.IV_LENGTH :
                ]

                # Derive key and decrypt/verify
                key = self._derive_key(password_bytes, salt)
            finally:
                # Zero out the password memory immediately after derivation
                for i in range(len(password_bytes)):
                    password_bytes[i] = 0

            aesgcm = AESGCM(key)

            # Decrypts ciphertext and verifies authentication tag
            plaintext = aesgcm.decrypt(
                iv,
                ciphertext_with_tag,
                associated_data=None
            )

            # Determine output filename
            if target_file_path.suffix == ".encrypted":
                decrypted_file_path = target_file_path.with_suffix("")
            else:
                decrypted_file_path = target_file_path.with_name(
                    f"{target_file_path.name}_decrypted"
                )

            decrypted_file_path.write_bytes(plaintext)

            console.print(
                f"[green3][-] Decrypted {target_file_path.name:34s} {'->':7s} "
                f"{decrypted_file_path.name}"
                )
            return decrypted_file_path

        except InvalidTag:
            console.print(
                "[bright_red]\n[!] Decryption failed : Invalid "
                "password or corrupted payload (authentication tag check "
                "failed)."
            )
            raise ValueError(
                "Authentication failed : Wrong password or file tampered with."
            )
        except Exception as e:
            console.print(
                f"[bright_red]\n[!] Failed to decrypt {target_file_path.name} "
                f": {e}")
            raise


    def get_aes_decryption_choice(self) -> None:
        pass