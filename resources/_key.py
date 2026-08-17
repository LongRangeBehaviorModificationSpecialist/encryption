# !/usr/bin/env python3

from datetime import datetime
import hashlib
from pathlib import Path
from rich.prompt import Prompt, Confirm
from rich.traceback import install
from typing import List, Literal

# Imports from the main __init__.py file
from . import console, install
from config.log_config import get_logger
from resources.vars import ENCRYPTED_EXT_LIST
from utils import Utils, UIHandlerProtocol, RichUIHandler

HAS_CRYPTO = False
try:
    from cryptography.fernet import Fernet, InvalidToken
    HAS_CRYPTO = True
except ImportError:
    console.print(
        f"[cyan][{Utils.get_time()}][yellow] Missing "
        "dependency: currently missing the 'cryptography' package.\n"
        "It can be installed using the 'pip install cryptography' command"
    )


logger = get_logger("key")
install()


class KEY:

    def __init__(self, ui: UIHandlerProtocol | None = None) -> None:
        self.ui = ui or RichUIHandler(get_time=Utils.get_time)


    def _load_fernet(self, key_file_path: Path | str) -> Fernet:
        """Load and initialize a Fernet instance from a key file.

        Args:
            key_file_path: Path to the key file containing the Fernet key.

        Returns:
            Fernet: Initialized Fernet encryption/decryption instance.

        Raises:
            FileNotFoundError: If the key file does not exist.
            ValueError: If the key is invalid or malformed.
        """
        logger.debug("The _load_fernet() method was called")
        return Fernet(key_file_path.read_bytes())


    def generate_and_save_key(self) -> bytes:
        """Generates a secure Fernet key, saves it, and generates a SHA-256
        metadata log.

        Returns:
            bytes: The generated key.
        """
        key_file_dir = Path(
            Prompt.ask(
                f"\n[cyan][{Utils.get_time()}][grey66] Where "
                "do you want to save the key file (folder path)?"
            ).strip().strip('"\'')
        )
        key_file_dir = key_file_dir.resolve()

        logger.info(f"The key file directory was input as [ '{key_file_dir}' ]")

        key_file_name = Prompt.ask(
            f"[cyan][{Utils.get_time()}][grey66] Enter a name for "
            f"the key file (w/o file extension)"
        ).strip()
        logger.info(
            f"The key file name was entered as [ '{key_file_name}' ]"
        )

        # Ensure target directory exists before writing
        key_file_dir.mkdir(parents=True, exist_ok=True)

        dt = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        full_key_path = key_file_dir / f"{dt}_{key_file_name}.key"
        logger.info(f"Full path to the .key file is [ '{full_key_path}' ]")

        key = Fernet.generate_key()
        logger.info(
            "The key was generated successfully using 'Fernet.generate_key()'"
        )
        logger.info(f"Key value is [ {key} ]")

        try:
            full_key_path.write_bytes(key)
            logger.info("Key file created successfully")

            key_file_hash_value = hashlib.sha256(key).hexdigest().upper()
            logger.info(
                f"Key file hash value was calculated to be "
                f"[ '{key_file_hash_value}' ]"
            )

            console.print(
                f"[cyan][{Utils.get_time()}][green] Key file "
                f"created successfully\n"
                f"[cyan][{Utils.get_time()}][grey66] Key file saved "
                f"as: [blue][i]{key_file_dir}\{full_key_path.name}[/i]\n"
                f"[cyan][{Utils.get_time()}][grey66] Key file hash "
                f"value (SHA256): [blue][i]{key_file_hash_value}"
            )

            make_key_verify_file = Confirm.ask(
                f"[cyan][{Utils.get_time()}][grey66] Save a "
                f"verification file in the same folder as the .key file?"
            )

            if make_key_verify_file:
                key_file_hash_file = full_key_path.with_suffix(".key.sha256")
                log_content = Utils.format_key_file_log(
                    timestamp= Utils.get_date_time(format="display"),
                    key_path=full_key_path,
                    hash_value=key_file_hash_value,
                )
                key_file_hash_file.write_text(log_content, encoding="utf-8")
                key_verify_msg = (f"The key file verification was saved as:")
                console.print(
                    f"[cyan][{Utils.get_time()}][grey66] "
                    f"{key_verify_msg}[blue][i]{key_file_hash_file}"
                )
                logger.info(f"{key_verify_msg} [ '{key_file_hash_file}' ]")

            return full_key_path

        except IOError as e:
            console.print(
                f"[cyan][{Utils.get_time()}][red] Failed "
                f"to write key data to file → {e}"
            )
            logger.error(f"IOError: Failed to write key data to file → {e}")
            raise RuntimeError(f"Failed to write key data to file → {e}") from e


    def get_existing_key_file_path(self) -> Path:
        """Prompts for a key file path and loop-validates its existence."""
        return Prompt.ask(
            f"[cyan][{Utils.get_time()}][grey66] Enter the path of "
            "the .key file to use"
        ).strip("\"'")


    def _handle_key_process_file(self, action: str) -> None:
        """Helper function to process encryption or decryption of a file."""
        logger.info("The '_handle_key_process_file()' method was called")

        target_file = Utils.get_file_path()
        logger.info(f"The target file was entered as '{target_file}'")

        key_file_path = self.get_existing_key_file_path()
        logger.info(f"The key file path was entered as '{key_file_path}'")

        logger.info(f"The action was entered as '{action}'")

        self.key_process_file(
            key_file_path=key_file_path,
            target_file=target_file,
            action=action,
        )


    def _handle_key_process_folder(self, action: str) -> None:
        """Helper function to process encryption or decryption of files
        in a folder.
        """
        logger.info("The '_handle_key_process_folder()' method was called")

        key_file_path = self.get_existing_key_file_path()
        logger.info(f"The key_file_path was entered as '{key_file_path}'")

        target_dir = Utils.get_directory_path()
        logger.info(f"The target_dir was entered as '{target_dir}'")

        recursive = Utils.select_recursive_option()
        logger.info(f"The recursive variable was entered as '{recursive}'")

        logger.info(f"The action was entered as '{action}'")

        self.key_process_folder(
            target_dir=target_dir,
            key_file_path=key_file_path,
            action=action,
            recursive=recursive,
        )


    def key_process_file(
        self,
        key_file_path: Path | str,
        target_file: Path | str,
        action: Literal["encrypt", "decrypt"],
        ui: UIHandlerProtocol | None = None
    ) -> Path:
        """Reads and either encrypts or decrypts a single file using Fernet
        symmetric encryption.

        Args:
            key_file_path: Path to the key_file
            target_file: Path of the file to be encrypted or decrypted
            action: Operational mode, either 'encrypt' or 'decrypt'.

        Returns:
            Path: Path to the resulting encrypted or decrypted file.

        Raises:
            ValueError: If action is invalid or paths target the same file.
            FileNotFoundError: If the target or key file does not exist.
            PermissionError: If read/write access to target file is restricted.
            InvalidToken: If decryption fails due to an incorrect key.
        """
        logger.info("The 'key_process_file()' method was called")

        action = action.lower().strip()
        if action not in ("encrypt", "decrypt"):
            raise ValueError(
                f"Invalid action '{action}'. Must be 'encrypt' or 'decrypt'."
        )

        target_path = Path(target_file).resolve()
        key_path = Path(key_file_path).resolve()

        logger.info(f"Processing '{target_path.name}' (action: '{action})'")

        if not target_path.is_file():
            Utils.print_not_file_error(target_file=target_path)
            raise FileNotFoundError(f"Invalid target file → {target_path}")

        if not Utils.verify_file_access(target_file=target_path):
            raise PermissionError(
                f"Access denied for target file → {target_path}"
            )

        if not key_path.is_file():
            self.ui.warning(f"Key file not found → {key_path}")
            logger.error(f"Key file was not found → {key_path}")
            raise FileNotFoundError(
                f"Invalid .key file path → {key_path}"
            )

        # Prevent self-encryption guard
        if target_path == key_path:
            self.ui.warning("Target file is the active key file. Aborting.")
            logger.error("Target and key file paths were identical. Aborted.")
            raise ValueError("Cannot encrypt or decrypt the active key file.")

        try:
            self.ui.info(f"Reading file → {target_path.name}")

            file_data = target_path.read_bytes()

            fernet_obj = self._load_fernet(
                key_file_path=key_path,
            )

            self.ui.info("File content read successfully...")
            self.ui.info(f"{action.capitalize()}ing file data...")

            if action == "encrypt":
                processed_data = fernet_obj.encrypt(file_data)
                output_path = target_path.with_name(
                    f"{target_path.name}.encrypted"
                )
            else:
                processed_data =fernet_obj.decrypt(file_data)
                output_path = (
                    target_path.with_suffix("")
                    if target_path.suffix.lower() == ".encrypted"
                    else target_path.with_name(f"decrypted_{target_path.name}")
                )

            output_path.write_bytes(processed_data)

            self.ui.success(
                f"{action.capitalize()}ed {target_path.name}  →  "
                f"{output_path.name}"
            )

            return output_path

        except InvalidToken:
            self.ui.error(
                f"Decryption failed! Invalid key for '{target_path.name}'"
            )
            raise
        except OSError as err:
            failed_msg = (
                f"I/O failure processing file {target_path.name} → {err}"
            )
            self.ui.error(f"{failed_msg}")
            raise RuntimeError(f"{failed_msg}") from err


    def key_process_folder(
            self,
            key_file_path: Path | str,
            target_dir: Path | str,
            action: str,
            recursive: bool = True
    ) -> List[Path]:
        """Encrypts or decrypts all discovered assets within a target
        directory.

        Args:
            key_file_path: Path to the key file.
            target_dir: Path to the directory containing files.
            action: Either 'encrypt' or 'decrypt'.
            recursive: Traverse the target_dir and process all files in
                sub-folders.

        Returns:
            List[Path]: List of successfully processed file paths.
        """
        action = action.lower().strip()
        target_dir = Path(target_dir).resolve()
        key_file_path = Path(key_file_path).resolve()

        if not Utils.verify_is_directory(target_dir=target_dir):
            return []

        console.print(
            f"[cyan][{Utils.get_time()}][green] "
            f"Target directory '{target_dir}' validated."
        )

        console.print(
            f"[cyan][{Utils.get_time()}][grey66] Fetching "
            f"targets for {action}ion..."
        )

        # Ensure key_file_path is resolved to prevent key self-encryption
        if key_file_path:
            key_file_path = Path(key_file_path).resolve()
        else:
            key_file_path = Path(
                self.get_existing_key_file_path()
            ).resolve()

        try:
            # Dynamically filter files based on the requested action
            files_iterator = (
                target_dir.rglob("*")
                if recursive else target_dir.iterdir()
            )

            if action == "decrypt":
                all_files = [
                    f for f in files_iterator
                    if f.is_file() and f.suffix in {".encrypted", ".enc"}
                ]
            else:
                # Encrypt files EXCEPT those ending with certain extensions
                all_files = [
                    f for f in files_iterator
                    if f.is_file()
                    and f.suffix.lower() not in ENCRYPTED_EXT_LIST
                    and f.resolve() != key_file_path
                ]
        except Exception as e:
            console.print(
                f"[cyan][{Utils.get_time()}][red] Failed "
                f"to retrieve files from {target_dir} → {e}"
            )
            return []

        if not all_files:
            console.print(
                f"[cyan][{Utils.get_time()}][yellow] No "
                f"valid files to {action} in {target_dir}"
            )
            return []

        successful_files: List[Path] = []
        failed_files: List[Path] = []

        for file_path in all_files:
            try:
                processed_path = self.key_process_file(
                    key_file_path=key_file_path,
                    target_file=file_path,
                    action=action,
                )
                successful_files.append(processed_path)
            except Exception as e:
                console.print(
                    f"[cyan][{Utils.get_time()}][red] "
                    f"Error during {action}ing {file_path.name} → {e}"
                )
                failed_files.append(file_path)

        # Summary reporting
        if successful_files:
            console.print(
                "\n" + "[grey58]-" * 35 + "\n",
                f"[green]** Action Completed **\n"
                f"    Successfully {action}ed {len(successful_files)} files "
                f"in {target_dir}:"
            )
            for processed_file in successful_files:
                console.print(f"[green]        {processed_file.name}")

        if failed_files:
            console.print(
                "\n" + "[grey58]-" * 35 + "\n",
                f"[red]** Warning **\n"
                f"    Failed to {action} {len(failed_files)} files:"
            )
            for failed_file in failed_files:
                console.print(f"[red]        {failed_file.name}")

        return successful_files
