# !/usr/bin/env python3

import logging
import os
import sys
from pathlib import Path
from typing import List, Union
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from rich.console import Console
from rich.prompt import Prompt

from resources.functions import Functions


# Make the console object
c = Console()


class AESEncryptor:
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


    def aes_encrypt_file(self,
            target_file_path: Union[str, Path],
            password: str,
            mode: str) -> Path:
        """
        Encrypts a single file safely using AES (GCM or CBC) and independent
        salt derivation.
        """
        target_file_path = Path(target_file_path)
        if not target_file_path.is_file():
            raise FileNotFoundError(f"Target file not found: {target_file_path}")

        valid_modes = {"AES.GCM", "AES.CBC"}
        if mode not in valid_modes:
            raise ValueError(
                f"Invalid mode: {mode}. Expected one of {valid_modes}"
            )

        c.print(f"\n[bright_white]Reading file : {target_file_path.name}...")
        # Read plaintext data
        plaintext = target_file_path.read_bytes()

        # Generate fresh, random cryptographic parameters
        salt = os.urandom(self.SALT_LENGTH)
        iv = os.urandom(self.IV_LENGTH)
        key = self._derive_key(password, salt)

        c.print(f"\n[bright_white]Encrypting data...")
        enc_file_path = target_file_path.with_name(
            f"{target_file_path.name}.encrypted"
        )

        # Default tag for non-authenticated modes like CBC
        tag = b""

        if mode == "AES.CBC":
            # Standardize CBC using `cryptography`
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(plaintext) + padder.finalize()

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            # Payload structure for CBC: [ SALT ] [ IV ] [ CIPHERTEXT ]
            combined_payload = salt + iv + ciphertext

        elif mode == "AES.GCM":
            # Encrypt configuration
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            tag = encryptor.tag

            # Construct payload header: [ SALT ] [ IV ] [ TAG ] [ CIPHERTEXT ]
            combined_payload = salt + iv + tag + ciphertext

        enc_file_path.write_bytes(combined_payload)

        # UI Output
        c.print(f"""[green3]
{target_file_path.name:34s}{'->':7s}{enc_file_path.name}"""
        )
        c.print(f"""[dim]
{"":34s}{"":7s}Salt : {salt.hex().upper()}
{"":34s}{"":7s}IV   : {iv.hex().upper()}
{"":34s}{"":7s}Tag  : {tag.hex().upper() if tag else 'N/A'}
{"":34s}{"":7s}ciphertext: {ciphertext[:16].hex()}..."""
        )

        Functions.print_confirm_file_action(
            file_name=enc_file_path, text="ENCRYPTED"
        )

        return enc_file_path


    def aes_encrypt_directory(self,
            target_folder_path: Union[str, Path],
            password: str,
            mode: str) -> List[Path]:
        """
        Encrypts all valid files in a given directory, skipping already
        encrypted files and gracefully handling individual file errors.
        """

        # Set up logging for non-UI diagnostics
        logger = logging.getLogger(__name__)

        target_dir = Path(target_folder_path)

        if not target_dir.exists():
            raise FileNotFoundError(
                f"Target directory does not exist: {target_dir}"
            )
        if not target_dir.is_dir():
            raise NotADirectoryError(
                f"The provided path is not a directory: {target_dir}"
            )

        try:
            all_files = Functions.get_all_files(target_dir_path=target_dir)
        except Exception as e:
            c.print(f"[bright_red][!] Failed to retrieve files from \
{target_dir}: {e}"
            )
            return []

        files_to_encrypt = [
            Path(f) for f in all_files if not str(f).endswith(".encrypted")
        ]

        if not files_to_encrypt:
            c.print(f"[yellow][!] No valid files to encrypt in {target_dir}")
            return []

        successful_encryptions: List[Path] = []
        failed_encryptions: List[Path] = []

        for file_path in files_to_encrypt:
            try:
                encrypted_path = self.aes_encrypt_file(
                    target_file_path=file_path,
                    password=password,
                    mode=mode
                )
                successful_encryptions.append(encrypted_path)
            except Exception as e:
                logger.error(
                    f"Failed to encrypt file: {file_path}", exc_info=True
                )
                c.print(
                    f"[bright_red][!] Error encrypting {file_path.name}: {e}"
                )
                failed_encryptions.append(file_path)

        if successful_encryptions:
            c.print(
                f"\n[green]Successfully encrypted {len(successful_encryptions)} \
files in {target_dir}:"
            )
            for enc_file in successful_encryptions:
                c.print(f"[green]  {enc_file.name}")

        if failed_encryptions:
            c.print(
                f"[bright_red]**WARNING**: Failed to encrypt \
{len(failed_encryptions)} files:"
            )
            for failed_file in failed_encryptions:
                c.print(f"[bright_red]  {failed_file.name}")

        return successful_encryptions


    def get_target_choice(self) -> None:
        """Main routing controller for encryption jobs."""
        while True:
            try:
                Functions.clear_screen()
                target_option = (
                    Prompt.ask("""[dodger_blue1]
----------------------------------------------------
USE PASSWORD TO ENCRYPT FILE(S) [AES-CBC / AES-GCM]
----------------------------------------------------\n
[khaki3]Choose an option :[bright_white]\n
[1] Encrypt a single file using a password
[2] Encrypt all files in a directory using a password\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """,
                        choices=["1", "2", "r", "q"],
                        show_choices=False
                    )
                    .strip()
                    .lower()
                )

                # Global exits
                if target_option == "r":
                    self.return_to_main_menu()
                    return
                if target_option == "q":
                    Functions.exit_application()
                    return

                enc_option = (
                    Prompt.ask("""[bright_white]
[-] Select encryption method (1=AES-CBC, 2=AES-GCM, R=Back): """,
                        choices=["1", "2", "r"],
                        show_choices=False
                    )
                    .strip()
                    .lower()
                )

                if enc_option == "r":
                    continue

                mode = "AES.CBC" if enc_option == "1" else "AES.GCM"
                is_single_file = target_option == "1"

                if is_single_file:
                    target_file_path = Path(
                        Functions.get_file_path(text="ENCRYPTED")
                    )
                    if not target_file_path:  # User cancelled input
                        continue

                    password = Functions.get_password()
                    if not password:  # User cancelled password entry
                        continue

                    self.aes_encrypt_file(
                        target_file_path=target_file_path,
                        password=password,
                        mode=mode
                    )
                else:
                    target_dir_path = Path(
                        Functions.get_folder_path(text="ENCRYPT")
                    )
                    if not target_dir_path:
                        continue

                    password = Functions.get_password()
                    if not password:
                        continue

                    self.aes_encrypt_directory(
                        targer_folder_path=target_dir_path,
                        password=password,
                        mode=mode
                    )

                # Pause after task completion so user can read output before screen clears
                Prompt.ask("\n[bright_white]Press Enter to return to the menu...")

            except KeyboardInterrupt:
                c.print("\n[yellow]Operation cancelled by user.")
                break
            except Exception as e:
                c.print(
                    f"[bright_red][!] An error occured during processing: {e}"
                )
                Prompt.ask("\n[bright_white]Press Enter to continue...")
