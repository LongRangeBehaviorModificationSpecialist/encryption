# !/usr/bin/env python3
# DLU : 27-Jul-2026

import os

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from pathlib import Path
from rich.prompt import Prompt
from typing import List, Union


# Import the console object from the main __init__.py file
from . import console
from resources.functions import Functions
from resources.prompts import AES_ENCRYPTION_PROMPT


class AESClass:


    def __init__(self, app_instance) -> None:
        """Store a reference to the main app loop controller."""
        self.app = app_instance
        self.IV_LENGTH = 12
        self.TAG_LENGTH = 16
        self.SALT_LENGTH = 16


    def return_to_main_menu(self) -> None:
        """Returns control cleanly back to the main menu processor."""
        self.app.main(self)


    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        """Derives a cryptographically strong 256-bit key from a weak password
        using Scrypt.
        """
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        return kdf.derive(password.encode())


    def aes_encrypt_single_file(
        self, target_file_path: Union[Path, str], mode: str
    ) -> Path:
        """Encrypts a single file safely using AES (GCM or CBC) and independent
        salt derivation.
        """
        password = Functions.get_password()

        target_file_path = Path(target_file_path)

        if not target_file_path.is_file():
            console.print(f"""[bright_red]
[!] {target_file_path.name} does not exist or is a directory.""")
            raise FileNotFoundError(f"Invalid target file: {target_file_path}")

        try:
            console.print(f"""[bright_white]
[-] Reading file : {target_file_path.name}...""")
            plaintext = target_file_path.read_bytes()
            console.print("""[bright_white]
[-] File content read successfully...""")

            # Generate fresh, random cryptographic parameters
            salt = os.urandom(self.SALT_LENGTH)
            iv = os.urandom(self.IV_LENGTH)
            key = AESClass._derive_key(password, salt)

            # Default tag for non-authenticated modes like CBC
            tag = b""

            console.print(f"""[bright_white]
[-] Encrypting file data...""")
            encrypted_file_path = target_file_path.with_name(
                f"{target_file_path.name}.encrypted")

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

            encrypted_file_path.write_bytes(encrypted_data)

            # UI Output
            console.print(f"""[green3]
[-] Encrypted {target_file_path.name:34s}{'->':7s}{encrypted_file_path.name}""")

            return encrypted_file_path

        except Exception as e:
            console.print(f"""[bright_red]
[!] Failed to encrypt {target_file_path.name} : {e}""")


    def aes_encrypt_files_in_folder(
        self, target_dir_path: Union[Path, str], mode: str
    ) -> List[Path]:
        """Recursively encrypts all valid unencrypted files within a directory
        using safely using AES (GCM or CBC) and independent salt derivation.
        """
        target_dir_path = Path(target_dir_path)

        if not target_dir_path.is_dir():
            console.print(f"""[bright_red]
[!] {target_dir_path} does not exist or is not a valid directory.""")
            return []

        console.print(f"""[green3]
[-] {target_dir_path} validated. Fetching targets...""")

        try:
            all_files = [
                f for f in target_dir_path.rglob("*")
                if f.is_file() and f.suffix != ".encrypted"
            ]
        except Exception as e:
            console.print(f"""[bright_red]
[!] Failed to retrieve files from {target_dir_path} : {e}""")
            return []

        if not all_files:
            console.print(f"""[yellow]
[!] No valid files to encrypt in {target_dir_path}""")
            return []

        successful_encryptions: List[Path] = []
        failed_encryptions: List[Path] = []

        for file_path in all_files:
            try:
                encrypted_path = AESClass.aes_encrypt_single_file(
                    self,
                    target_file_path=file_path,
                    mode=mode
                )
                successful_encryptions.append(encrypted_path)
            except Exception as e:
                console.print(f"""[bright_red]
[!] Error encrypting {file_path.name} : {e}""")
                failed_encryptions.append(file_path)

        if successful_encryptions:
            console.print(f"""[green]
** Action Completed **
Successfully encrypted {len(successful_encryptions)} files in \
{target_dir_path} :""")
            for encrypted_file in successful_encryptions:
                console.print(f"""[green]
    {encrypted_file.name}""")

        if failed_encryptions:
            console.print(f"""[bright_red]
** Warning **
Failed to encrypt {len(failed_encryptions)} files :""")
            for failed_file in failed_encryptions:
                console.print(f"""[bright_red]
    {failed_file.name}""")

        return successful_encryptions


    def get_aes_encryption_choice(self) -> None:
        aes_encryption_choice = (
            Prompt.ask(
                AES_ENCRYPTION_PROMPT,
                choices=["1", "2", "3", "4", "r", "q"],
                show_choices=False,)
            .strip()
            .lower()
        )

        if aes_encryption_choice == "r":
            self.return_to_main_menu()
            return

        if aes_encryption_choice == "q":
            Functions.exit_application()
            return

        if aes_encryption_choice == "1":
            target_file_path = Functions.get_file_path(text="encrypted")
            AESClass.aes_encrypt_single_file(
                self,
                target_file_path=target_file_path,
                mode="AES.CBC"
            )

        elif aes_encryption_choice == "2":
            target_dir_path = Functions.get_folder_path(text="encrypted")
            AESClass.aes_encrypt_files_in_folder(
                self,
                target_dir_path=target_dir_path,
                mode="AES.CBC"
            )

        elif aes_encryption_choice == "3":
            target_file_path = Functions.get_file_path(text="encrypted")
            AESClass.aes_encrypt_single_file(
                self,
                target_file_path=target_file_path,
                mode="AES.GCM"
            )

        elif aes_encryption_choice == "4":
            target_dir_path = Functions.get_folder_path(text="encrypted")
            AESClass.aes_encrypt_files_in_folder(
                self,
                target_dir_path=target_dir_path,
                mode="AES.GCM"
            )