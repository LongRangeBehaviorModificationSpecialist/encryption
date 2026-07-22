# !/usr/bin/env python3
# DLU : 22-Jul-2026

import logging
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pathlib import Path
from typing import List, Union

from rich.console import Console
from rich.prompt import Prompt

from resources.functions import Functions


# Make the console object
c = Console()


class AESDecryptor:

    def __init__(self, app_instance):
        """Store a reference to the main app loop controller."""
        self.app = app_instance


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


    def aes_decrypt_file(
        self, target_file_path: Union[str, Path], password: str, mode: str
    ) -> Path:
        """
        Decrypts a single file using AES-GCM or AES-CBC and handles safe writing.

        For AES-CBC, assumes the file structure is:
        [ 16 bytes Salt ] + [ 16 bytes IV ] + [ Encrypted Data ]

        Args:
            target_file_path: Path -> Path to the encrypted file
            password: str -> Password to derive the decryption key
            mode: str -> AES mode to use

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

        # Mode validation
        valid_modes = {"AES.GCM", "AES.CBC"}
        if mode not in valid_modes:
            raise ValueError(
                f"Invalid mode: {mode}. Expected one of {valid_modes}"
            )

        c.print(
            f"\n[bright_white]Reading encrypted file : \
{target_file_path.name}..."
        )
        encrypted_data = target_file_path.read_bytes()

        salt_size = getattr(self, "SALT_LENGTH", 16)
        iv_size = getattr(self, "IV_LENGTH", 16)
        tag_size = getattr(self, "TAG_LENGTH", 16) if mode == "AES.GCM" else 0

        min_expected_size = salt_size + iv_size + tag_size+ 16  # Block size

        if len(encrypted_data) < min_expected_size:
            raise ValueError(
                f"""
Payload invalid or corrupted: file length ({len(encrypted_data)} bytes)
is less than minimum required structure ({min_expected_size} bytes)."""
            )

        c.print("\n[bright_white]Deriving key and decrypting...")

        try:
            if mode == "AES.CBC":
                # Decrypt and Unpad using `cryptography`
                salt = encrypted_data[:salt_size]
                iv = encrypted_data[salt_size : salt_size + iv_size]
                ciphertext = encrypted_data[salt_size + iv_size :]

                key = self._derive_key(password, salt)

                cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
                decryptor = cipher.decryptor()
                padded_plaintext = (
                    decryptor.update(ciphertext) + decryptor.finalize()
                )

                # Unpad PKCS7 data
                unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
                plaintext = (
                    unpadder.update(padded_plaintext) + unpadder.finalize()
                )

            elif mode == "AES.GCM":
                salt = encrypted_data[:salt_size]
                iv = encrypted_data[salt_size : salt_size + iv_size]
                tag = encrypted_data[
                    salt_size + iv_size : salt_size + iv_size + tag_size
                ]
                ciphertext = encrypted_data[salt_size + iv_size + tag_size :]

                key = self._derive_key(password, salt)

                cipher = Cipher(algorithms.AES(key),modes.GCM(iv, tag))
                decryptor = cipher.decryptor()
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        except (ValueError, InvalidTag) as e:
                raise ValueError (
                    "Decryption failed. The password may be incorrect, or the \
file is corrupted."
                ) from e

        # Handle output path creation
        if target_file_path.suffix == ".encrypted":
            decrypted_file_path = target_file_path.with_suffix("")
        else:
            decrypted_file_path = target_file_path.with_name(
                f"{target_file_path.name}.decrypted"
            )

        if decrypted_file_path.exists():
            decrypted_file_path = decrypted_file_path.with_name(
                f"{decrypted_file_path.stem}_decrypted{decrypted_file_path.suffix}"
            )

        decrypted_file_path.write_bytes(plaintext)

        c.print(
            "[green3]>>> File decrypted successfully. Thank you. Come again."
        )

        return decrypted_file_path


    def aes_decrypt_directory(
        self, target_folder_path: Union[Path, str], password: str, mode: str
    ) ->  List[Path]:
        """
        Decrypts all `.encrypted` files in a directory, returning a list
        of successfully decrypted file paths.
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
            c.print(
                f"[bright_red][!] Failed to retrieve files from {target_dir}: {e}"
            )
            return []

        files_to_decrypt = [
            Path(f) for f in all_files if Path(f).suffix.lower() == ".encrypted"
        ]

        if not files_to_decrypt:
            c.print(
                f"[yellow][!] No valid files to decrypt in {target_dir}"
            )
            return []

        successful_decryptions: List[Path] = []
        failed_decryptions: List[Path] = []

        for file_path in files_to_decrypt:
            try:
                decrypted_path = self.aes_decrypt_file(
                    target_file_path=file_path,
                    password=password,
                    mode=mode
                )
                successful_decryptions.append(decrypted_path)
            except Exception as e:
                logger.error(
                    f"Failed to decrypt file: {file_path}", exc_info=True
                )
                c.print(
                    f"[bright_red][!] Error decrypting {file_path.name}: {e}"
                )
                failed_decryptions.append(file_path)

        if successful_decryptions:
            c.print(
                f"\n[green]Successfully decrypted \
{len(successful_decryptions)} files in {target_dir}:"
            )
            for decrypted_file in successful_decryptions:
                c.print(f"[green]  {decrypted_file.name}")

        if failed_decryptions:
            c.print(
                f"[bright_red]**WARNING**: Failed to decrypt \
{len(failed_decryptions)} files:"
            )
            for failed_file in failed_decryptions:
                c.print(f"[bright_red]  {failed_file.name}")

        return successful_decryptions


    def get_target_choice(self) -> None:
        """Main routing controller for decryption jobs."""
        while True:
            try:
                Functions.clear_screen()
                target_option = (
                    Prompt.ask("""[dodger_blue1]
----------------------------------------------------
USE PASSWORD TO DECRYPT FILE(S) [AES-CBC / AES-GCM]
----------------------------------------------------\n
[khaki3]Choose an option :[bright_white]\n
[1] Decrypt a single file using a password
[2] Decrypt all files in a directory using a password\n
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

                decryption_option = (
                    Prompt.ask(
"""[bright_white] [-] Select decryption method (1=AES-CBC, 2=AES-GCM, \
R=Back): """,
                        choices=["1", "2", "r"],
                        show_choices=False
                    )
                    .strip()
                    .lower()
                )

                if decryption_option == "r":
                    continue

                mode = "AES.CBC" if decryption_option == "1" else "AES.GCM"
                is_single_file = target_option == "1"

                if is_single_file:
                    target_file_path = Path(
                        Functions.get_file_path(text="DECRYPTED")
                    )
                    if not target_file_path:  # User cancelled input
                        continue

                    password = Functions.get_password()
                    if not password:  # User cancelled password entry
                        continue

                    self.aes_decrypt_file(
                        target_file_path=target_file_path,
                        password=password,
                        mode=mode
                    )
                else:
                    target_dir_path = Path(
                        Functions.get_folder_path(text="DECRYPT")
                    )
                    if not target_dir_path:
                        continue

                    password = Functions.get_password()
                    if not password:
                        continue

                    self.aes_decrypt_directory(
                        targer_folder_path=target_dir_path,
                        password=password,
                        mode=mode
                    )

                # Pause after task completion so user can read output before
                # screen clears
                Prompt.ask(
                    "\n[bright_white]Press Enter to return to the menu..."
                )

            except KeyboardInterrupt:
                c.print(
                    "\n[yellow]Operation cancelled by user."
                )
                break
            except Exception as e:
                c.print(
                    f"[bright_red][!] An error occured during processing: {e}"
                )
                Prompt.ask(
                    "\n[bright_white]Press Enter to continue..."
                )

