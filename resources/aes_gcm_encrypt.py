# !/usr/bin/env python3

import os
from pathlib import Path
from typing import Union
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from rich.console import Console
from rich.prompt import Prompt

from resources.functions import Functions


# Make the console object
c = Console()


class AESGCMDataEncryptor:
    """
    Keep the encryption key secure as it will be needed for decryption.
    Also, this program overwrites the original files with encrypted content.
    Make sure to have proper backups before running it.
    """

    def __init__(self, app_instance):
        """Store a reference to the main app loop controller."""
        self.app = app_instance
        self.IV_LENGTH = 12
        self.TAG_LENGTH = 16
        self.SALT_LENGTH = 16


    def return_to_main_menu(self) -> None:
        """Returns control cleanly back to the main menu processor."""
        self.app.main(self)


    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derives a cryptographically strong 256-bit key from a weak password
        using Scrypt.
        """
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        return kdf.derive(password.encode())


    def aes_gcm_encrypt_file(self,
            file_path: Union[str, Path],
            password: str) -> Path:
        """
        Encrypts a single file safely using AES-GCM and independent salt
        derivation.
        """
        file_path = Path(file_path)
        if not file_path.is_file():
            raise FileNotFoundError(f"Target file not found: {file_path}")

        # Read plaintext data
        plaintext = file_path.read_bytes()

        # Generate fresh, random cryptographic parameters for *this* file
        salt = os.urandom(self.SALT_LENGTH)
        iv = os.urandom(self.IV_LENGTH)

        # Secure key derivation
        key = self._derive_key(password, salt)

        # Encrypt configuration
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
        encryptor = cipher.encryptor()

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag

        # Construct payload header: [ SALT ] [ IV ] [ TAG ] [ CIPHERTEXT ]
        encrypted_file = file_path.with_suffix(f"{file_path.suffix}.encrypted")

        with encrypted_file.open("wb") as f:
            f.write(salt + iv + tag + ciphertext)

        c.print(f"""[green3]
{file_path.name:34s}{"->":7s}{encrypted_file.name}""")
        c.print(f"""[dim]
{"":34s}{"":7s}Salt : {salt.hex().upper()}
{"":34s}{"":7s}IV   : {iv.hex().upper()}
{"":34s}{"":7s}Tag  : {tag.hex().upper()}
{"":34s}{"":7s}cipherText: {ciphertext[0:16]}...""")

        return encrypted_file


    def aes_gcm_encrypt_directory(self,
            folder_path: Union[str, Path],
            password: str) -> None:
        """
        Safely processes and encrypts an entire directory of files.
        """
        folder = Path(folder_path)
        if not folder.is_dir():
            c.print(f"[red1][!] Error: Directory {folder} does not exist.")
            return

        while True:
            choice = Prompt.ask("[khaki3]Delete original files after \
successful encryption? (y/n)").strip().lower()
            if choice in ["y", "n"]:
                break
            c.print("[red1]Please enter 'y' or 'n'.")

        # Gather files using pathlib
        target_files = [item for item in folder.iterdir() if item.is_file() and item.suffix != ".encrypted"]

        # Track successfully processed files to prevent premature data deletion
        successful_encryptions = []

        for file in target_files:
            try:
                self.aes_gcm_encrypt_directory(file_path=file, password=password)
                successful_encryptions.append(file)
            except Exception as e:
                c.print(f"[red]CRITICAL: Failed to encrypt {file.name}. Error: {e}")
                continue

        if choice == "y":
            for original_file in successful_encryptions:
                original_file.unlink()
            c.print("[orange_red1]Original files cleanly purged from directory.")
        else:
            c.print("[green3]Encryption complete. Original files retained.")


    def get_target_choice(self) -> None:
            """Main routing controller for encryption jobs."""
            Functions.clear_screen()
            while True:
                target_option = Prompt.ask("""[dodger_blue1]
------------------------------------------
USE PASSWORD TO ENCRYPT FILE(S) [AES-GCM]
------------------------------------------\n
[khaki3]Choose an option :[bright_white]\n
[1] Encrypt a single file using a password
[2] Encrypt all files in a directory using a password\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """,
                choices=["1", "2", "r", "q"],
                show_choices=False).strip().lower()

                # Global exits
                if target_option == "r":
                    self.return_to_main_menu()
                    return
                if target_option == "q":
                    Functions.exit_application()
                    return

                # If option 1 or 2, determine the workflow type
                is_single_file = (target_option == "1")

                if is_single_file:
                    target_file_path = Path(Functions.get_file_path(text="ENCRYPTED"))
                    # target_file_path = Path(r"C:\Users\mikes\Desktop\test\OSHA.docx")
                    password = Functions.get_password()
                    # password = "Password1!"
                    self.aes_gcm_encrypt_file(
                        target_file_path=target_file_path,
                        password=password
                    )
                else:
                    target_dir_path = Path(Functions.get_folder_path(text="ENCRYPT"))
                    password = Functions.get_password()
                    self.aes_gcm_encrypt_directory(
                        folder_path=target_dir_path,
                        password=password
                    )

                # Clean work completion exit
                break
