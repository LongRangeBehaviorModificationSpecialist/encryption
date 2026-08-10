# !/usr/bin/env python3
"""AES encryption/decryption module."""

# Import the console object from the main __init__.py file
from . import c
from ui.log_config import get_logger
from ui.config import GLOBAL_CONFIG
from rich.traceback import install
from resources.vars import ENCRYPTED_EXT_LIST
from resources.utils import Utils
from typing import List

HAS_CRYPTO = False
try:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    HAS_CRYPTO = True
except ImportError:
    c.print(
        f"{GLOBAL_CONFIG.yellow_line} Missing "
        "dependency: currently missing the 'cryptography' package.\n"
        "It can be installed using the 'pip install cryptography' command"
    )

import os
from pathlib import Path


install(show_locals=True, console=c)
logger = get_logger("aes")  # Creates "encryption_app.aes" logger

class AES:

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
        # Log at START of important operations
        logger.debug(
            f"Deriving key from password (length: "
            f"{len(password) if isinstance(password, str) else len(bytes(password))})"
        )
        # If a string gets passed, encode it; otherwise use raw buffer
        # Convert string to bytes
        if isinstance(password, str):
            pwd_buffer = password.encode("utf-8")
        elif isinstance(password, bytearray):
            # Convert bytearray to immutable bytes
            pwd_buffer = bytes(password)
        else:
            pwd_buffer = password

        kdf = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1)

        logger.debug("Key derived successfully")
        return kdf.derive(pwd_buffer)


    def _handle_aes_process_file(self, action: str) -> None:
        """Collect user inputs and call aes_process_file."""
        target_file = Utils.get_file_path()
        password = Utils.get_confirmed_password()
        self.aes_process_file(
            target_file=target_file,
            password=password,
            action=action,
        )


    def _handle_aes_process_folder(self, action: str) -> None:
        target_dir = Utils.get_directory_path()
        password = Utils.get_confirmed_password()
        recursive = Utils.select_recursive_option()
        self.aes_process_folder(
            target_dir=target_dir,
            password=password,
            action=action,
            recursive=recursive,
        )


    def aes_process_file(
            self,
            target_file: Path | str,
            password: str,
            action: str
    ) -> Path | None:
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
        logger.info(f"Starting {action} for file: {target_file}")

        if not target_file.is_file():
            Utils.print_not_file_error(target_file=target_file)
            raise FileNotFoundError(f"Invalid target file : {target_file}")

        if not Utils.verify_file_access(target_file=target_file):
            return

        try:
            c.print(
                f"[cyan][{Utils.get_current_time()}][white]"
                f"Reading file : {target_file.name}..."
            )

            original_file_data = target_file.read_bytes()
            c.print(
                f"[cyan][{Utils.get_current_time()}][white] File "
                "content read successfully..."
            )

            c.print(
                f"[cyan][{Utils.get_current_time()}][white] "
                f"{action.capitalize()}ing file data..."
            )

            if action == "encrypt":
                FILE_EXT = "encrypted"
                output_file = target_file.with_name(
                    f"{target_file.name}.{FILE_EXT}"
                )
                # Generate fresh, random cryptographic parameters
                salt = os.urandom(self.SALT_LENGTH)
                # 96-bit IV is standard for GCM
                iv = os.urandom(self.IV_LENGTH)
                key = self._derive_key(password, salt)

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

                min_length = self.SALT_LENGTH + self.IV_LENGTH + 16
                if len(original_file_data) < min_length:
                    c.print(
                        f"[cyan][{Utils.get_current_time()}][red1] "
                        f"File is corrupted or too short to be a valid "
                        "AES-GCM payload."
                    )
                    raise ValueError("File corrupted or too short")

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

                    key = self._derive_key(password, salt)

                    aesgcm = AESGCM(key)

                    # Decrypt and verify authentication tag
                    decrypted_data = aesgcm.decrypt(
                        iv,
                        ciphertext_with_tag,
                        associated_data=None,
                    )

                    output_file.write_bytes(decrypted_data)

                except InvalidTag:
                    c.print(
                        f"[cyan][{Utils.get_current_time()}][red1] "
                        "Decryption failed: Invalid password or corrupted "
                        "payload (authentication tag check failed) "
                        "(Invalid tag)."
                    )
                    raise ValueError(
                        "Authentication failed : Wrong password or file has "
                        "been altered."
                    )

            c.print(
                f"[cyan][{Utils.get_current_time()}][green3] "
                f"{action.capitalize()}ed {target_file.name}  ->  "
                f"{output_file.name}"
            )

            return output_file

        except Exception as e:
            c.print(
                f"[cyan][{Utils.get_current_time()}][red1] "
                f"Failed to {action} {target_file.name} -> {e}"
            )
            return None


    def aes_process_folder(
            self,
            target_dir: Path | str,
            password: str,
            action: str,
            recursive: bool = True
    ) -> List[Path]:
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
        action = action.lower().strip()
        target_dir = Path(target_dir).resolve()

        if not Utils.verify_is_directory(target_dir=target_dir):
            return []

        c.print(
            f"[cyan][{Utils.get_current_time()}][green3] "
            f"Target directory '{target_dir}' validated."
        )
        c.print(
            f"[cyan][{Utils.get_current_time()}][white] Fetching "
            f"targets for {action}ion..."
        )

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
            c.print(
                f"[cyan][{Utils.get_current_time()}][red1] Failed "
                f"to retrieve files from {target_dir} -> {e}"
            )

        if not all_files:
            c.print(
                f"[cyan][{Utils.get_current_time()}][yellow3] No "
                f"valid files to {action} in {target_dir}"
            )
            return []

        successful_files: List[Path] = []
        failed_files: List[Path] = []

        for file_path in all_files:
            try:
                processed_path = self.aes_process_file(
                    target_file=file_path,
                    password=password,
                    action=action,
                )
                successful_files.append(processed_path)
            except Exception as e:
                c.print(
                    f"[cyan][{Utils.get_current_time()}][red1] "
                    f"Error during {action}ing {file_path.name}  ->  {e}"
                )
                failed_files.append(file_path)

        if successful_files:
            c.print(
                "\n" + "[green]-" * 45 + "\n",
                f"[green3]** Action Completed **\n"
                f"    Successfully {action}ed {len(successful_files)} files "
                f"in {target_dir}:"
            )
            for processed_file in successful_files:
                c.print(f"[green3]        {processed_file.name}")

        if failed_files:
            c.print(
                "\n" + "-" * 45 + "\n",
                f"[red1]** Warning **\n"
                f"    Failed to {action} {len(failed_files)} files:"
            )
            for failed_file in failed_files:
                c.print(f"[red1]        {failed_file.name}")

        return successful_files
