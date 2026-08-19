# !/usr/bin/env python3

import os
from pathlib import Path
from typing import List, Literal

# Imports from the main __init__.py file
from .. import console, install
from config.log_config import get_logger
from resources.vars import ENCRYPTED_EXT_LIST
from utils import Utils, UIHandlerProtocol, RichUIHandler, get_time

HAS_CRYPTO = False
try:

    # from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    HAS_CRYPTO = True
except ImportError:
    console.print(
        f"[cyan][{get_time()}][yellow] Missing "
        "dependency: currently missing the 'cryptography' package.\n"
        "It can be installed using the 'pip install cryptography' command"
    )


logger = get_logger("aes")
install()


class AES:

    def __init__(self, ui: UIHandlerProtocol | None = None) -> None:
        # Standard 96-bit IV for AES-GCM
        self.IV_LENGTH = 12
        self.TAG_LENGTH = 16
        self.SALT_LENGTH = 16
        self.ui = ui or RichUIHandler(get_time=get_time)


    def _handle_aes_process_file(self, action: str) -> None:
        """Collect user inputs and call aes_process_file."""
        target_file = Utils.get_file_path(self)
        logger.info(f"The target_file was entered as → '{target_file}'")

        output_dir = Utils.get_output_path(self, target_path=target_file)
        logger.info(f"The output_dir was entered as → '{output_dir}'")

        password = Utils.get_confirmed_password(self)
        logger.info(f"User entered password → '{password}'")

        logger.info(f"Action was input as → '{action}'")

        self.aes_process_file(
            target_file=target_file,
            output_dir=output_dir,
            password=password,
            action=action,
        )


    def _handle_aes_process_folder(self, action: str) -> None:
        target_dir = Utils.get_directory_path(self)
        logger.info(f"The target_dir was entered as → '{target_dir}'")

        output_dir = Utils.get_output_path(self, target_path=target_dir)
        logger.info(f"The output_dir was entered as → '{output_dir}'")

        password = Utils.get_confirmed_password(self)
        logger.info(f"User entered password → '{password}'")

        logger.info(f"Action was input as → '{action}'")

        recursive = Utils.select_recursive_option(self)
        logger.info(f"The recursive option was set to → '{recursive}'")

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
            output_dir: Path | str | None,
            password: str,
            action: Literal["encrypt", "decrypt"]
    ) -> Path | None:
        """Reads and either encrypts or decrypts a single file using AES
        (GCM with native AEAD).

        Args:
            target_file: Path of the file to be encrypted or decrypted
            output_dir: Destination directory. Defaults to target file's
                directory if None.
            password: password to use for the encryption or decryption.
            action: Operational mode ('encrypt' or 'decrypt').

        Returns:
            Path: Path to the processed output file.

        Raises:
            FileNotFoundError: If target file or key file does not exist.
            ValueError: If action is invalid or key file matches target file.
            PermissionError: If file access is restricted.
        """
        action = action.lower().strip()
        if action not in ("encrypt", "decrypt"):
            raise ValueError(
                f"Invalid action '{action}'. Must be 'encrypt' or 'decrypt'."
            )
        target_path = Path(target_file).resolve()
        logger.info(f"Starting {action}ion for file '{target_path}'")

        if not target_path.is_file():
            msg = (
                f"File validation for '{target_path.name}' failed → the file "
                "does not exist or is not a file."
            )
            self.ui.error(msg)
            logger.error(msg)
            raise FileNotFoundError(msg)

        if not Utils.verify_file_access(self, target_file=target_path):
            msg = f"Access denied for file → '{target_path.name}'"
            self.ui.error(msg)
            raise PermissionError(msg)

        # Resolve destination directory
        destination_dir = (
            Path(output_dir).resolve() if output_dir else target_path.parent
        )
        destination_dir.mkdir(parents=True, exist_ok=True)

        try:
            if action == "encrypt":
                in_color, out_color = "bright_green", "bright_red"
            else:
                in_color, out_color = "bright_red", "bright_green"

            self.ui.info(
                f"Reading the [{in_color}][i]{target_path.name}[/i][/] file..."
            )
            logger.info(f"Reading file → '{target_path.name}'")

            original_data = target_path.read_bytes()

            read_success_msg = (
                f"Content of '{target_path.name}' read successfully"
            )
            self.ui.info(read_success_msg)
            logger.info(read_success_msg)

            action_msg = (
                f"{action.capitalize()}ing file data of '{target_path.name}'"
            )
            self.ui.info(action_msg)
            logger.info(action_msg)

            if action == "encrypt":
                FILE_EXT = "encrypted"
                output_file = destination_dir / f"{target_path.name}.{FILE_EXT}"
                logger.info(
                    f"Encrypted file name will be → "
                    f"{target_path.name}.{FILE_EXT}"
                )
                # Generate fresh, random cryptographic parameters
                salt = os.urandom(self.SALT_LENGTH)
                logger.debug(f"Encryption salt is → [ {salt} ]")

                # 96-bit IV is standard for GCM
                iv = os.urandom(self.IV_LENGTH)
                logger.debug(f"Encryption IV value is → [ {iv} ]")

                key = Utils._derive_key(self, password, salt)
                logger.debug(f"Encryption key value is → [ {key} ]")

                logger.info(f"File encryption started...")

                aesgcm = AESGCM(key)

                ciphertext = aesgcm.encrypt(
                    iv,
                    original_data,
                    associated_data=None,
                )

                # Construct payload header: [ SALT ] [ IV ] [ CIPHERTEXT ]
                payload = salt + iv + ciphertext

                output_file.write_bytes(payload)
                logger.info(
                    f"Encrypted data written successfully for "
                    f"'{target_path.name}'"
                )

            else:
                FILE_EXT = "decrypted"
                output_file = (
                    destination_dir / target_path.stem
                    if target_path.suffix.lower() == ".encrypted"
                    else destination_dir / f"decrypted_{target_path.name}"
                )
                logger.info(
                    f"Decrypted file name will be → '{output_file.name}'"
                )

                min_length = self.SALT_LENGTH + self.IV_LENGTH + 16

                if len(original_data) < min_length:
                    msg = (
                        f"'{target_path.name}' is too short to be a valid "
                        "AES-GCM payload."
                    )
                    self.ui.error(msg)
                    logger.error(msg)
                    raise ValueError(msg)

                try:
                    # Parse payload layout:
                    # [ SALT ] [ IV ] [ CIPHERTEXT + TAG ]
                    salt = original_data[: self.SALT_LENGTH]
                    logger.debug(f"Decryption salt value is → [ {salt} ]")

                    iv = original_data[
                        self.SALT_LENGTH : self.SALT_LENGTH + self.IV_LENGTH
                    ]
                    logger.debug(f"Decryption IV value is → [ {iv} ]")

                    ciphertext = original_data[
                        self.SALT_LENGTH + self.IV_LENGTH :
                    ]

                    key = Utils._derive_key(self, password, salt)
                    logger.debug(f"Decryption key value is → [ {key} ]")

                    logger.info("File decryption started...")

                    aesgcm = AESGCM(key)

                    # Decrypt and verify authentication tag
                    decrypted_data = aesgcm.decrypt(
                        iv,
                        ciphertext,
                        associated_data=None,
                    )

                    output_file.write_bytes(decrypted_data)
                    logger.info(
                        f"Decrypted data written to '{output_file.name}' "
                        "successfully",

                    )

                except InvalidTag as err:
                    msg = (
                        f"Decryption of {target_path.name} failed due to an "
                        "invalid password or corrupted payload (authentication "
                        "tag check failed) (Invalid tag)"
                    )
                    self.ui.error(msg)
                    logger.error(msg)
                    raise ValueError(msg) from err

            self.ui.success(
                f"{action.capitalize()}ed [{in_color}]"
                f"[i]{target_path.name}[/i]  [grey74]→  "
                f"[{out_color}][i]{output_file.name}"
            )
            logger.info(
                f"{action.capitalize()}ed '{target_path.name}'  →  "
                f"'{output_file.name}'"
            )

            return output_file

        except Exception as err:
            msg = f"Failed to {action} {target_path.name} → {err}"
            self.ui.error(msg)
            logger.error(msg)
            raise RuntimeError(msg) from err


    def aes_process_folder(
            self,
            target_dir: Path | str,
            output_dir: Path | str | None,
            password: str,
            action: Literal["encrypt", "decrypt"],
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
            action: Operational mode ('encrypt' or 'decrypt').
            recursive: conduct the encryption or decryption operation
                recursively (True or False).

        Returns:
            list[Path]: Paths of successfully processed output files.

        Raises:
            ValueError: If action parameter is invalid.
            RuntimeError: If directory reading fails.
        """
        action = action.lower().strip()
        if action not in ("encrypt", "decrypt"):
            raise ValueError(
                f"Invalid action '{action}'. Must be 'encrypt' or 'decrypt'."
            )
        target_path = Path(target_dir).resolve()

        if not Utils.verify_is_directory(self, target_dir=target_path):
            return []

        self.ui.info(f"Target directory '{target_path}' validated.")
        logger.info(f"Target directory {target_path} validated")

        self.ui.info(f"Fetching targets for {action}ion...")
        logger.info(f"Fetching targets for {action}ion in {target_path}")

        try:
            # Dynamically filter files based on the requested action
            files_iterator = (
                target_path.rglob("*")
                if recursive else target_path.iterdir()
            )

            if action == "decrypt":
                # Decrypt only files with .encrypted extension
                all_files = [
                    f for f in files_iterator
                    if f.is_file() and f.suffix.lower() in ENCRYPTED_EXT_LIST
                ]
            else:
                # Encrypt files EXCEPT those ending with excluded extensions
                all_files = [
                    f for f in files_iterator
                    if f.is_file()
                    and f.suffix.lower() not in ENCRYPTED_EXT_LIST
                ]
        except Exception as err:
            msg = f"Failed to retrieve files from {target_path} → {err}"
            self.ui.error(msg)
            logger.error(msg)
            raise RuntimeError(msg) from err

        if not all_files:
            msg = f"No valid files to {action} in {target_path}"
            self.ui.warning(msg)
            logger.warning(msg)
            return []

        base_output_path = Path(output_dir).resolve() if output_dir else None
        successful_files: List[Path] = []
        failed_files: List[Path] = []

        for file_path in all_files:
            try:
                file_output_dir = None
                if base_output_path:
                    relative_subpath = file_path.parent.relative_to(target_path)
                    file_output_dir = base_output_path / relative_subpath

                processed_path = self.aes_process_file(
                    target_file=file_path,
                    output_dir=file_output_dir,
                    password=password,
                    action=action,
                )
                successful_files.append(processed_path)
            except Exception as err:
                msg = f"Error during {action}ing {file_path.name} → {err}"
                self.ui.error(msg)
                logger.error(msg)
                failed_files.append(file_path)

        if successful_files:
            self.ui.success(
                f"Successfully {action}ed {len(successful_files)} files in"
                f"{target_path}:"
            )
            for processed_file in successful_files:
                self.ui.info(f"        {processed_file.name}")

        if failed_files:
            self.ui.warning(
                f"Warning -- failed to {action} {len(failed_files)} files:"
            )
            for failed_file in failed_files:
                self.ui.error(f"        {failed_file.name}")

        return successful_files
