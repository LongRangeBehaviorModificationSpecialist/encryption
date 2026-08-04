# !/usr/bin/env python3
# DLU : 04-Aug-2026


HAS_CRYPTO = False
try:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    HAS_CRYPTO = True
except ImportError:
    pass

from enum import StrEnum
import os
from pathlib import Path

# Import the console object from the main __init__.py file
from . import console
from resources.vars import ENCRYPTED_EXT_LIST
from resources.functions import Functions
from resources.prompts import (
    show_main_menu,
    show_aes_menu
)


class Action(StrEnum):
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"


class AES:

    _ACTION_MAP = {
        "1": (Action.ENCRYPT, "single"),
        "2": (Action.DECRYPT, "single"),
        "3": (Action.ENCRYPT, "folder"),
        "4": (Action.DECRYPT, "folder")
    }


    def __init__(self) -> None:
        # Standard 96-bit IV for AES-GCM
        self.IV_LENGTH = 12
        self.TAG_LENGTH = 16
        self.SALT_LENGTH = 16


    def _derive_key(
            self,
            password: bytearray | bytes | str,
            salt: bytes
    ) -> bytes:
        """Derives a 256-bit key from a password buffer using Scrypt (N=2^17
        for improved GPU attack resistance).
        """
        # If a string gets passed, encode it; otherwise use raw buffer
        pwd_buffer = (
            password.encode("utf-8")
            if isinstance(password, str) else password)
        kdf = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1)
        return kdf.derive(pwd_buffer)


    def _handle_aes_process_file(self, action: Action) -> None:
        """Collect user inputs and call aes_process_file."""
        target_file = Functions.get_file_path(sction=action.value)
        password = Functions.get_password()
        self.aes_process_file(
            action=action.value,
            target_file=target_file,
            password=password,
        )


    def aes_process_file(
            self,
            target_file: Path | str,
            password: str,
            action: str
    ) -> Path:
        """Reads and either encrypts or decrypts a single file using AES
        (GCM with native AEAD).

        Args:
            file_path: Path of the file to be encrypted or decrypted
            action: Operational mode, either 'encrypt' or 'decrypt'.

        Returns:
            Path: Path to the resulting encrypted or decrypted file.

        Raises:
            FileNotFoundError: If target file or key file does not exist.
            ValueError: If action is invalid or key file matches target file.
        """
        action = action.lower().strip()
        target_file = Path(target_file).resolve()

        if not Functions.verify_is_file(target_file=target_file):
            self.logger.debug(
                f"File validation for {target_file.name} failed : the "
                "file does not exist or is not a file"
            )
            return

        if not Functions.verify_file_access(target_file=target_file):
            self.logger.debug(
                f"Validation for {target_file.name} failed : insufficient "
                "file access permission"
            )
            return

        try:
            console.print(
                f"[bright_white][-] Reading file : {target_file.name}..."
            )

            original_file_data = target_file.read_bytes()
            console.print(
                "[bright_white][-] File content read successfully..."
            )

            console.print(
                f"[bright_white][-] {action.capitalize()}ing file data..."
            )

            if action == "encrypt":
                FILE_EXT = "encrypted"
                output_file = target_file.with_name(
                    f"{target_file.name}.{FILE_EXT}"
                )
                # Generate fresh, random cryptographic parameters
                salt = os.urandom(self.SALT_LENGTH)
                iv = os.urandom(self)  # 96-bit IV is standard for GCM
                key = self._derive_key(password, salt)

                console.print(
                    f"[bright_white][-] Encrypting file data..."
                )

                aesgcm = AESGCM(key)

                encrypted_file_data = aesgcm.encrypt(
                    iv,
                    original_file_data,
                    associated_data=None,
                )

                # Construct payload header: [ SALT ] [ IV ] [ CIPHERTEXT ]
                encrypted_data = salt + iv + encrypted_file_data

                output_file.write_bytes(encrypted_data)

            else:
                FILE_EXT = "decrypted"
                if target_file.suffix == ".encrypted":
                    output_file = target_file.with_suffix("")
                else:
                    output_file = target_file.with_name(
                        f"{target_file.name}.{FILE_EXT}"
                    )
                # Convert string to mutable bytearray
                password_bytes = bytearray(password.encode("utf-8"))

                min_length = self.SALT_LENGTH + self.IV_LENGTH + 16
                if len(original_file_data) < min_length:
                    raise ValueError(
                        "File is corrupted or too short to be a valid AES-GCM "
                        "payload."
                    )

                try:
                    # Parse payload layout:
                    # [ SALT ] [ IV ] [ CIPHERTEXT + TAG ]
                    salt = original_file_data[: self.SALT_LENGTH]
                    iv = original_file_data[
                        self.SALT_LENGTH : self.SALT_LENGTH + self.IV_LENGTH
                    ]
                    ciphertext_with_tag = original_file_data[
                        self.SALT_LENGTH + self.IV_LENGTH :
                    ]

                    # Derive key and decrypt/verify
                    key = self._derive_key(password_bytes, salt)

                    aesgcm = AESGCM(key)

                    # Decrypts ciphertext and verifies authentication tag
                    decrypted_data = aesgcm.decrypt(
                        iv,
                        ciphertext_with_tag,
                        associated_data=None,
                    )

                    output_file.write_bytes(decrypted_data)

                except InvalidTag:
                    console.print(
                        "\n[bright_red]\n[!] Decryption failed : Invalid "
                        "password or corrupted payload (authentication tag "
                        "check failed)."
                    )
                    raise ValueError(
                        "\nAuthentication failed : Wrong password or file has "
                        "been altered."
                    )
                finally:
                    # Zero out the password memory immediately after derivation
                    for i in range(len(password_bytes)):
                        password_bytes[i] = 0

            console.print(
                f"[green][-] {action.capitalize()}ed "
                f"{target_file.name:34s}{'->':7s}{output_file.name}"
            )

            return output_file

        except Exception as e:
            console.print(
                f"[bright_red][!] Failed to {action} {target_file.name} "
                f": {e}"
            )


    def _handle_aes_process_folder(self, action: Action) -> None:
        target_dir = Functions.get_directory_path()
        password = Functions.get_password()
        recursive = Functions.select_recursive_option()
        self.aes_process_folder(
            target_dir=target_dir,
            password=password,
            action=action,
            recursive=recursive,
        )


    def aes_process_folder(
            self,
            target_dir: Path | str,
            password: str,
            action: str,
            recursive: bool = True
    ) -> Path:
        """Recursively encrypt or decrypt all valid  files within a directory
        using safely using AES.GCM and independent salt derivation.

        Args:
            target_dir: Path of the directory containing the files to be
                encrypted or decrypted
            action: Operational mode, either 'encrypt' or 'decrypt'.
            password: password to use to either encrypt or decrypt the files
            recursive: conduct the encryption or decryption operation
                recursively (True or False)

        Returns:
            Path: Path to the resulting encrypted or decrypted files.

        Raises:
            FileNotFoundError: If target file or key file does not exist.
            ValueError: If action is invalid or key file matches target file.

        """
        results = {"success": [], "failed": [], "skipped": []}
        action = action.lower().strip()
        target_dir = Path(target_dir).resolve()

        if not Functions.verify_is_directory(target_dir=target_dir):
            console.print(
                f"\n[yellow][!] {target_dir} does not exist or is not a "
                "valid directory"
            )
            return

        console.print(
            f"\n[green][*] {target_dir} validated. Fetching targets for "
            f"{action}ion...")

        try:
            # Dynamically filter files based on the requested action
            files_iterator = (
                target_dir.rglob("*")
                if recursive else target_dir.iterdir()
            )

            if action == "decrypt":
                # Decrypt only files with .encrypted extension
                all_files = [
                    f for f in files_iterator
                    if f.is_file() and f.suffix in ENCRYPTED_EXT_LIST
                ]
            else:
                # Encrypt files EXCEPT those ending with excluded extensions
                all_files = [
                    f for f in files_iterator
                    if f.is_file()
                    and f.suffix.lower() not in ENCRYPTED_EXT_LIST
                ]
        except Exception as e:
            console.print(
                "[bright_red][!] Failed to retrieve files from "
                f"{target_dir} : {e}"
            )

        if not all_files:
            console.print(
                f"[yellow][!] No valid files to {action} in {target_dir}"
            )
            return

        for file_path in all_files:
            try:
                processed_path = self.aes_process_file(
                    target_file=file_path,
                    password=password,
                    action=action)
                results['success'].append({
                    "original": str(file_path),
                    f"{action}ed": str(processed_path)}
                )
            except Exception as e:
                console.print(
                    f"[bright_red][!] Error {action}ing {file_path.name} "
                    f"-> {e}"
                )
                results['failed'].append({
                    "path": str(file_path),
                    "error": str(e)}
                )

        if results['success']:
            console.print(
                f"\n[green][*] Action Completed \nSuccessfully {action}ed "
                f"{len(results['success'])} files in {target_dir} :"
            )
            processed_paths = [
                item['path'] for item in results['success']
            ]
            for path in processed_paths:
                console.print(
                    f"[green]  {str(path)}")

        if results['failed']:
            console.print(
                f"\n[bright_red][!] ** Warning **\nFailed to {action} "
                f"{len(results['failed'])} files :"
            )
            failed_paths = [
                item['path'] for item in results['failed']
            ]
            for path in failed_paths:
                console.print(f"[bright_red]  {str(path)}")

        console.print(results)

        return results


    def get_aes_action(self, action: str) -> None:
        """Gets input from the user on what action to start next."""
        aes_choice = show_aes_menu()
        match aes_choice:
            case "1" | "2" | "3" | "4":
                action, scope = self._ACTION_MAP[aes_choice]
                if scope == "single":
                    self._handle_aes_process_file(action)
                else:
                    self._handle_aes_process_folder(action)
            case "r":
                show_main_menu()
            case "q":
                Functions.exit_application()



        if action == "encrypt":
            aes_encryption_choice = show_aes_encryption_menu()
            match aes_encryption_choice:
                case "1":
                    target_file = Functions.get_file_path(text="encrypted")
                    password = Functions.get_password()
                    self.aes_process_file(
                        action=action,
                        target_file=target_file,
                        password=password)
                case "2":
                    target_dir = Functions.get_directory_path(text="encrypted")
                    password = Functions.get_password()
                    recursive = Functions.select_recursive_option()
                    self.aes_process_folder(
                        action=action,
                        target_dir=target_dir,
                        password=password,
                        recursive=recursive)

        elif action == "decrypt":
            aes_decryption_choice = show_aes_decryption_menu()
            match aes_decryption_choice:
                case "1":
                    target_file = Functions.get_file_path(text="decrypted")
                    password = Functions.get_password()
                    AES.aes_process_file(
                        action=action,
                        target_file=target_file,
                        password=password)
                case "2":
                    target_dir = Functions.get_directory_path(text="decrypted")
                    password = Functions.get_password()
                    recursive = Functions.select_recursive_option()
                    AES.aes_process_folder(
                        action=action,
                        target_dir=target_dir,
                        password=password,
                        recursive=recursive)
                case "r":
                    Functions.clear_screen()
                    show_main_app_menu()
                case "q":
                    Functions.exit_application()
