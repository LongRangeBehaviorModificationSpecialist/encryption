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
        f"[cyan][{Utils.get_current_time()}][yellow3] Missing "
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
        logger.info(f"The target_file was entered as '{target_file}'")
        output_dir = Utils.get_output_path(
            target_path=target_file
        )
        password = Utils.get_confirmed_password()
        logger.info(f"User entered password '{password}'")
        logger.info(f"Action was input as '{action}'")
        self.aes_process_file(
            target_file=target_file,
            output_dir=output_dir,
            password=password,
            action=action,
        )


    def _handle_aes_process_folder(self, action: str) -> None:
        target_dir = Utils.get_directory_path()
        logger.info(f"The target_dir was entered as '{target_dir}'")
        output_dir = Utils.get_output_path(
            target_path=target_dir
        )
        logger.info(f"The output_dir was entered as '{output_dir}'")
        password = Utils.get_confirmed_password()
        logger.info(f"User entered password '{password}'")
        logger.info(f"Action was input as '{action}'")
        recursive = Utils.select_recursive_option()
        logger.info(f"The recursive option was set to '{recursive}'")
        self.aes_process_folder(
            target_dir=target_dir,
            output_dir=output_dir,
            password=password,
            action=action,
            recursive=recursive,
        )


    def aes_process_file(
            self,
            target_file: Path | str,
            output_dir: Path | str,
            password: str,
            action: str
    ) -> Path | None:
        """Reads and either encrypts or decrypts a single file using AES
        (GCM with native AEAD).

        Args:
            file_path: Path of the file to be encrypted or decrypted
            output_dir: Path to where the processed files will be saved. If
                empty, processed files will be saved in the same folder as
                the original files.
            password: password to use for the encryption or decryption.
            action: Operational mode, either 'encrypt' or 'decrypt'.

        Returns:
            Path: Path to the resulting encrypted or decrypted file.

        Raises:
            FileNotFoundError: If target file or key file does not exist.
            ValueError: If action is invalid or key file matches target file.
        """
        action = action.lower().strip()
        target_file = Path(target_file).resolve()
        logger.info(f"Starting {action}ion for file '{target_file}'")

        if not target_file.is_file():
            invalid_target_file_msg = (
                f"File validation for '{target_file.name}' failed -> the file "
                "does not exist or is not a file."
            )
            c.print(
                f"[cyan][{Utils.get_current_time()}][red1] "
                f"{invalid_target_file_msg}"
            )
            logger.error(f"{invalid_target_file_msg}")
            raise FileNotFoundError(f"{invalid_target_file_msg}")

        if not Utils.verify_file_access(target_file=target_file):
            return

        try:
            c.print(
                f"[cyan][{Utils.get_current_time()}][white] "
                f"Reading file : {target_file.name}..."
            )
            logger.info(f"Reading file '{target_file.name}'")

            original_file_data = target_file.read_bytes()
            c.print(
                f"[cyan][{Utils.get_current_time()}][white] File "
                "content read successfully..."
            )
            logger.info(
                f"Content of '{target_file.name}' read successfully"
            )

            c.print(
                f"[cyan][{Utils.get_current_time()}][white] "
                f"{action.capitalize()}ing file data..."
            )
            logger.info(
                f"{action.capitalize()}ing file data of '{target_file.name}'"
            )

            if action == "encrypt":
                FILE_EXT = "encrypted"
                output_file = output_dir / target_file.with_name(
                    f"{target_file.name}.{FILE_EXT}"
                )
                logger.info(
                    f"Encrypted file name will be: {target_file.name}.{FILE_EXT}"
                )
                # Generate fresh, random cryptographic parameters
                salt = os.urandom(self.SALT_LENGTH)
                logger.info(f"Encryption salt is '{salt}'")
                # 96-bit IV is standard for GCM
                iv = os.urandom(self.IV_LENGTH)
                logger.info(f"Encryption IV value is '{iv}'")
                key = self._derive_key(password, salt)
                logger.info(f"Encryption key value is '{key}'")
                logger.info(f"File encryption started...")

                aesgcm = AESGCM(key)

                encrypted_file_data = aesgcm.encrypt(
                    iv,
                    original_file_data,
                    associated_data=None,
                )

                # Construct payload header: [ SALT ] [ IV ] [ CIPHERTEXT ]
                encrypted_data = salt + iv + encrypted_file_data

                output_file.write_bytes(encrypted_data)
                logger.info(
                    f"Encrypted data written successfully for {target_file.name}"
                )

            else:
                FILE_EXT = "decrypted"
                if target_file.suffix == ".encrypted":
                    output_file = output_dir / target_file.with_suffix("")
                else:
                    output_file = output_dir / target_file.with_name(
                        f"{target_file.name}.{FILE_EXT}"
                    )
                logger.info(
                    f"Decrypted file name will be '{output_file.name}'"
                )

                min_length = self.SALT_LENGTH + self.IV_LENGTH + 16
                if len(original_file_data) < min_length:
                    min_length_msg = (
                        f"'{target_file.name}' is corrupted or too short to "
                        "be a valid AES-GCM payload."
                    )
                    c.print(
                        f"[cyan][{Utils.get_current_time()}][red1] "
                        f"{min_length_msg}"
                    )
                    logger.error(f"{min_length_msg}")
                    raise ValueError(f"{min_length_msg}")

                try:
                    # Parse payload layout:
                    # [ SALT ] [ IV ] [ CIPHERTEXT + TAG ]
                    salt = original_file_data[: self.SALT_LENGTH]
                    logger.info(f"Decryption salt value is '{salt}'")
                    iv = original_file_data[
                        self.SALT_LENGTH : self.SALT_LENGTH + self.IV_LENGTH
                    ]
                    logger.info(f"Decryption IV value is '{iv}'")
                    ciphertext_with_tag = original_file_data[
                        self.SALT_LENGTH + self.IV_LENGTH :
                    ]

                    key = self._derive_key(password, salt)
                    logger.info(f"Decryption key value is '{key}'")
                    logger.info(f"File decryption started...")

                    aesgcm = AESGCM(key)

                    # Decrypt and verify authentication tag
                    decrypted_data = aesgcm.decrypt(
                        iv,
                        ciphertext_with_tag,
                        associated_data=None,
                    )

                    output_file.write_bytes(decrypted_data)
                    logger.info(
                        f"Decrypted data written to {output_file.name} "
                        "successfully"
                    )

                except InvalidTag:
                    invalid_tag_msg = (
                        f"Decryption of {target_file.name} failed due to an "
                        "invalid password or corrupted payload (authentication "
                        "tag check failed) (Invalid tag)"
                    )
                    c.print(
                        f"[cyan][{Utils.get_current_time()}][red1] "
                        f"{invalid_tag_msg}"
                    )
                    logger.error(f"{invalid_tag_msg}")
                    raise ValueError(f"{invalid_tag_msg}")

            success_msg = (
                f"{action.capitalize()}ed {target_file.name}  ->  "
                f"{output_file.name}"
            )
            c.print(
                f"[cyan][{Utils.get_current_time()}][green3] {success_msg}"
            )
            logger.info(f"{success_msg}")

            return output_file

        except Exception as e:
            other_error_msg = f"Failed to {action} {target_file.name} -> {e}"
            c.print(
                f"[cyan][{Utils.get_current_time()}][red1] {other_error_msg}"
            )
            logger.error(f"{other_error_msg}")
            return None


    def aes_process_folder(
            self,
            target_dir: Path | str,
            output_dir: Path | str,
            password: str,
            action: str,
            recursive: bool = True
    ) -> List[Path]:
        """Recursively encrypt or decrypt all valid  files within a directory
        using safely using AES.GCM and independent salt derivation.

        Args:
            target_dir: Path of the directory containing the files to be
                encrypted or decrypted
            output_dir: Path to where the processed files will be saved. If
                empty, processed files will be saved in the same folder as
                the original files.
            password: password to use for the encryption or decryption.
            action: Operational mode, either 'encrypt' or 'decrypt'.
            recursive: conduct the encryption or decryption operation
                recursively (True or False).

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

        dir_validated_msg = f"Target directory '{target_dir}' validated."
        c.print(
            f"[cyan][{Utils.get_current_time()}][green3] "
            f"{dir_validated_msg}"
        )
        logger.info(f"{dir_validated_msg}")

        fetch_targets_msg = f"Fetching targets for {action}ion..."
        c.print(
            f"[cyan][{Utils.get_current_time()}][white] {fetch_targets_msg}"
        )
        logger.info(f"{fetch_targets_msg}")

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
            failed_retrieve_files_msg = (
                f"Failed to retrieve files from {target_dir} -> {e}"
            )
            c.print(
                f"[cyan][{Utils.get_current_time()}][red1] "
                f"{failed_retrieve_files_msg}"
            )
            logger.error(f"{failed_retrieve_files_msg}")

        if not all_files:
            no_files_msg = f"No valid files to {action} in {target_dir}"
            c.print(
                f"[cyan][{Utils.get_current_time()}][yellow3] {no_files_msg}"
            )
            logger.error(f"{no_files_msg}")
            return []

        successful_files: List[Path] = []
        failed_files: List[Path] = []

        for file_path in all_files:
            try:
                processed_path = self.aes_process_file(
                    target_file=file_path,
                    output_dir=output_dir,
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
