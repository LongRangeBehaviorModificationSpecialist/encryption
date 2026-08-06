# !/usr/bin/env python3
# DLU : 06-Aug-2026


# Import the console object from the main __init__.py file
from . import console
from resources.vars import ENCRYPTED_EXT_LIST, STATUS_ICONS
from resources.functions import Functions
from resources.prompts import (
    show_main_menu,
    show_key_menu
)

HAS_CRYPTO = False
try:
    from cryptography.fernet import Fernet, InvalidToken
    HAS_CRYPTO = True
except ImportError:
    console.print(
        f"{STATUS_ICONS['warning']}[yellow3] Missing dependency: "
        "currently missing the 'cryptography' package.\n"
        "It can be installed using the 'pip install cryptography' command"
    )

from datetime import datetime
from enum import StrEnum
import hashlib
from pathlib import Path
from rich.prompt import Prompt
from rich.traceback import install
from typing import List


install(show_locals=True)


class Action(StrEnum):
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"


class KEY:

    _KEY_ACTION_MAP = {
        "2": (Action.ENCRYPT, "file"),
        "3": (Action.DECRYPT, "file"),
        "4": (Action.ENCRYPT, "folder"),
        "5": (Action.DECRYPT, "folder")
    }


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
        return Fernet(key_file_path.read_bytes())


    def generate_and_save_key(self) -> bytes:
        """Generates a secure Fernet key, saves it, and generates a SHA-256
        metadata log.

        Returns:
            bytes: The generated key.
        """
        key_file_dir = Path(
            Prompt.ask(
                f"{STATUS_ICONS['question']}[white] Where do you want to "
                "save the key file? "
            ).strip().strip('"\'')
        )

        key_file_name = Prompt.ask(
            f"{STATUS_ICONS['key']}[white] Enter a name for the key "
            "file (w/o file extension) "
        ).strip()

        # Ensure target directory exists before writing
        key_file_dir.mkdir(parents=True, exist_ok=True)

        dt = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        full_key_path = key_file_dir / f"{dt}_{key_file_name}.key"

        key = Fernet.generate_key()

        try:
            full_key_path.write_bytes(key)

            key_file_hash_value = hashlib.sha256(key).hexdigest().upper()
            key_file_hash_file = full_key_path.with_suffix(".key.sha256")

            log_content = Functions.format_key_file_log(
                timestamp= Functions.get_date_time(format="display"),
                key_path=full_key_path,
                hash_value=key_file_hash_value,
            )

            key_file_hash_file.write_text(log_content, encoding="utf-8")

            console.print(
                Functions.format_key_file_verification(
                    key_file_dir=key_file_dir,
                    full_key_path=full_key_path,
                    key_file_hash_file=key_file_hash_file,
                    key_file_hash_value=key_file_hash_value,
                )
            )

            return full_key_path

        except IOError as e:
            console.print(
                f"{STATUS_ICONS['failure']}[red] Failed to write key data "
                f"to file : {e}"
            )
            raise


    def get_existing_key_file_path(self) -> Path:
        """Prompts for a key file path and loop-validates its existence."""
        return Prompt.ask(
            f"{STATUS_ICONS['key']}[white] Enter the path of the .key "
            "file to use "
        ).strip("\"'")


    def _handle_key_process_file(self, action: Action) -> None:
        """Helper function to process encryption or decryption of a file."""
        key_file_path = self.get_existing_key_file_path()
        target_file = Functions.get_file_path()
        self.key_process_file(
            key_file_path=key_file_path,
            target_file=target_file,
            action=action.value,
        )


    def _handle_key_process_folder(self, action: Action) -> None:
        """Helper function to process encryption or decryption of files
        in a folder.
        """
        key_file_path = self.get_existing_key_file_path()
        target_dir = Functions.get_directory_path()
        recursive = Functions.select_recursive_option()
        self.key_process_folder(
            target_dir=target_dir,
            key_file_path=key_file_path,
            action=action.value,
            recursive=recursive,
        )


    def key_process_file(
            self,
            key_file_path: Path | str,
            target_file: Path | str,
            action: str
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
            FileNotFoundError: If target file or key file does not exist.
            ValueError: If action is invalid or key file matches target file.
        """
        action = action.lower().strip()
        target_file = Path(target_file).resolve()
        key_file_path = Path(key_file_path).resolve()

        if not target_file.is_file():
            Functions.print_not_file_error(target_file=target_file)
            raise FileNotFoundError(f"Invalid target file : {target_file}")

        if not Functions.verify_file_access(target_file=target_file):
            return

        # Ensure key_file_path is resolved to prevent key self-encryption
        # if key_file_path:
        #     resolved_key_file_path = Path(key_file_path).resolve()
        # else:
        #     resolved_key_file_path = Path(
        #         self.get_existing_key_file_path(self)
        #     ).resolve()

        if not key_file_path.is_file():
            console.print(
                f"{STATUS_ICONS['failure']}[red] Key file not found : "
                f"{key_file_path}"
            )
            raise FileNotFoundError(
                f"Invalid .key file : {key_file_path}"
            )

        # Prevent self-encryption guard
        if target_file == key_file_path:
            console.print(
                f"{STATUS_ICONS['warning']}[yellow3] Target file is the "
                "active key file. Aborting."
            )
            raise ValueError("Cannot encrypt or decrypt the active key file.")

        try:
            console.print(
                f"{STATUS_ICONS['file']}[white] Reading file : "
                f"{target_file.name}..."
            )
            original_file_data = target_file.read_bytes()

            fernet_obj = self._load_fernet(
                key_file_path=key_file_path,
            )

            console.print(
                f"{STATUS_ICONS['success']}[white] File content read "
                "successfully..."
            )
            console.print(
                f"{STATUS_ICONS['processing']}[white] {action.capitalize()}ing "
                "file data..."
            )

            if action == "encrypt":
                encrypted_data = fernet_obj.encrypt(original_file_data)
                output_file = target_file.with_name(
                    f"{target_file.name}.encrypted"
                )
                output_file.write_bytes(encrypted_data)
            else:
                # Will throw an InvalidToken exception if the key is wrong
                decrypted_data = fernet_obj.decrypt(original_file_data)
                if target_file.suffix.lower() == ".encrypted":
                    output_file = target_file.with_suffix("")
                else:
                    output_file = target_file.with_name(
                        f"decrypted_{target_file.name}"
                    )
                output_file.write_bytes(decrypted_data)

            console.print(
                f"{STATUS_ICONS['success']}[green3] {action.capitalize()}ed "
                f"{target_file.name}  ->  {output_file.name}"
            )

            return output_file

        except InvalidToken:
            console.print(
                f"{STATUS_ICONS['failure']}[red] Decryption failed! The key "
                f"provided is invalid for {target_file.name}"
            )
            raise
        except Exception as e:
            console.print(
                f"{STATUS_ICONS['failure']}[red] Failed to {action} "
                f"{target_file.name} : {e}"
            )
            raise


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

        if not Functions.verify_is_directory(target_dir=target_dir):
            return []

        console.print(
            f"{STATUS_ICONS['success']}[green3] {target_dir} validated."
        )
        console.print(
            f"{STATUS_ICONS['processing']}[white] Fetching targets for "
            f"{action}ion..."
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
                f"{STATUS_ICONS['failure']}[red] Failed to retrieve files "
                f"from {target_dir} : {e}"
            )
            return []

        if not all_files:
            console.print(
                f"{STATUS_ICONS['warning']}[yellow3] No valid files to "
                f"{action} in {target_dir}"
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
                    f"{STATUS_ICONS['failure']}[red] Error during "
                    f"{action}ing {file_path.name} : {e}"
                )
                failed_files.append(file_path)

        # Summary reporting
        if successful_files:
            console.print(
                "\n" + "[green]-" * 45 + "\n",
                f"[green3]** Action Completed **\n"
                f"    Successfully {action}ed {len(successful_files)} files "
                f"in {target_dir}:"
            )
            for processed_file in successful_files:
                console.print(f"[green3]        {processed_file.name}")

        if failed_files:
            console.print(
                "\n" + "-" * 45 + "\n",
                f"[red]** Warning **\n"
                f"    Failed to {action} {len(failed_files)} files:"
            )
            for failed_file in failed_files:
                console.print(f"[red]        {failed_file.name}")

        return successful_files


    def get_key_action(self) -> None:
        """Gets input from the user on what action to start next."""
        key_choice = show_key_menu()
        match key_choice:
            case "1":
                self.generate_and_save_key()
            case "2" | "3" | "4" | "5":
                action, scope = self._KEY_ACTION_MAP[key_choice]
                if scope == "file":
                    self._handle_key_process_file(action=action)
                else:
                    self._handle_key_process_folder(action=action)
            case "r":
                Functions.clear_screen()
                show_main_menu()
            case "q":
                Functions.exit_application()
            case _:
                console.print(
                    f"{STATUS_ICONS['warning']}[yellow] An invalid option "
                    "was entered"
                )


#! ------------------------------------
#!  VERIFICATIONS CHECKS
#!
#!  Option "1" --
#!  Option "2" --
#!  Option "3" --
#!  Option "4" --
#!  Option "5" --
#!  OPTION "r" -- NEED TO FIX.  Returns to the main menu, but when an
#!                option is entered, the program exits.
#!  OPTION "q" -- working 08-05-26
