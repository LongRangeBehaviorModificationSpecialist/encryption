# !/usr/bin/env python3
# DLU : 30-Jul-2026


from cryptography.fernet import Fernet, InvalidToken
from datetime import datetime
import hashlib
from pathlib import Path
from rich.prompt import Prompt
from typing import List

# Import the console object from the main __init__.py file
from . import console
from resources.functions import Functions
from resources.prompts import KEY_ENCRYPTION_PROMPT, KEY_DECRYPTION_PROMPT


class KEYClass:


    def __init__(self, app_instance) -> None:
        """Store a reference to the main app loop controller."""
        self.app = app_instance


    def return_to_main_menu(self) -> None:
        """Returns control cleanly back to the main menu processor."""
        self.app.main(self)


    def _load_fernet(self, key_file_path: Path | str) -> bytes:
        """Load the fernet key"""
        return Fernet(key_file_path.read_bytes())


    def generate_and_save_key(self) -> bytes:
        """Generates a secure Fernet key, saves it, and generates a SHA-256
        metadata log.

        Returns:
            bytes: The generated key.
        """
        key_file_dir = Path(
            Prompt.ask(
                "[bright_white][-] Where do you want to save the key file? "
                ).strip().strip('"\''))

        key_file_name = Prompt.ask(
            "[bright_white][-] Enter a name for the key file (w/o file "
            "extension) "
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
                timestamp=Functions.get_date_time(),
                key_path=full_key_path,
                hash_value=key_file_hash_value
            )

            key_file_hash_file.write_text(log_content, encoding="utf-8")

            console.print(Functions.format_key_file_verification(
                key_file_dir=key_file_dir,
                full_key_path=full_key_path,
                key_file_hash_file=key_file_hash_file,
                key_file_hash_value=key_file_hash_value))

            return full_key_path

        except IOError as e:
            console.print(
                f"[bright_red][!] Failed to write key data to file : {e}"
                )
            raise


    def get_existing_key_file_path(self) -> Path:
        """Prompts for a key file path and loop-validates its existence."""
        while True:
            key_file = Prompt.ask(
                "[bright_white][-] Enter the path of the .key file to use "
                )
            path = Path(key_file)
            if path.is_file():
                return path


    def key_process_single_file(
        self,
        key_file_path: Path | str,
        target_file_path: Path | str,
        action: str
    ) -> None:
        """Reads and either encrypts or decrypts a single file using Fernet
        symmetric encryption.

        Args:
            key_file: Path to the key_file
            file_path: Path of the file to be encrypted or decrypted
            action: Operational mode, either 'encrypt' or 'decrypt'.

        Returns:
            Path: Path to the resulting encrypted or decrypted file.

        Raises:
            FileNotFoundError: If target file or key file does not exist.
            ValueError: If action is invalid or key file matches target file.
        """
        action = action.lower().strip()
        target_file_path = Path(target_file_path).resolve()

        if not target_file_path.is_file():
            console.print(
                f"[bright_red][!] {target_file_path.name} does not exist or "
                "is a directory."
                )
            raise FileNotFoundError(
                f"Invalid target file : {target_file_path}"
                )

        # Ensure key_file_path is resolved to prevent key self-encryption
        if key_file_path:
            resolved_key_file_path = Path(key_file_path).resolve()
        else:
            resolved_key_file_path = Path(
                KEYClass.get_existing_key_file_path(self)
                ).resolve()

        if not resolved_key_file_path.is_file():
            console.print(
                "[bright_red][!] Key file not found : "
                f"{resolved_key_file_path}"
                )
            raise FileNotFoundError(
                f"Invalid .key file : {resolved_key_file_path}"
                )

        # Prevent self-encryption guard
        if target_file_path == resolved_key_file_path:
            console.print(
                "[bright_red][!] Target file is the active key file. Aborting."
                )
            raise ValueError(
                "Cannot encrypt or decrypt the active key file."
                )

        try:
            console.print(
                f"[bright_white][-] Reading file : {target_file_path.name}..."
                )
            original_file_data = target_file_path.read_bytes()

            fernet = KEYClass._load_fernet(
                self,
                key_file_path=resolved_key_file_path
                )
            fernet_obj = (
                fernet if isinstance(fernet, Fernet) else Fernet(fernet)
                )

            console.print(
                "[bright_white][-] File content read successfully..."
                )

            console.print(
                f"[bright_white][-] {action.capitalize()}ing file data..."
                )

            if action == "encrypt":
                encrypted_data = fernet_obj.encrypt(original_file_data)
                processed_file = target_file_path.with_name(
                    f"{target_file_path.name}.encrypted"
                )

                processed_file.write_bytes(encrypted_data)
            else:
                # Will throw an InvalidToken exception if the key is wrong
                decrypted_data = fernet_obj.decrypt(original_file_data)

                if target_file_path.suffix.lower() == ".encrypted":
                    processed_file = target_file_path.with_suffix("")
                else:
                    processed_file = target_file_path.with_name(
                        f"decrypted_{target_file_path.name}"
                    )

                # Save the decrypted file
                processed_file.write_bytes(decrypted_data)

            console.print(
                f"[green3][-] {action.capitalize()}ed "
                f"{target_file_path.name:34s}{'->':7s}{processed_file.name}"
                )

            return processed_file

        except InvalidToken:
            console.print(
                f"[bright_red][!] Decryption failed! The key provided is "
                f"invalid for {target_file_path.name}"
                )
            raise
        except Exception as e:
            console.print(
                f"[bright_red][!] Failed to {action} {target_file_path.name} "
                f": {e}"
                )
            raise


    def key_process_files_in_folder(
        self,
        key_file_path: Path | str,
        target_dir_path: Path | str,
        action: str = "encrypt",
        recursive: bool = True
    ) -> List[Path]:
        """Encrypts or decrypts all discovered assets within a target
        directory.

        Args:
            key_file_path: Path to the key file.
            target_dir_path: Path to the directory containing files.
            action: Either 'encrypt' or 'decrypt'.
        """
        action = action.lower().strip()
        target_dir_path = Path(target_dir_path)

        if not target_dir_path.is_dir():
            console.print(
                f"[bright_red][!] {target_dir_path} does not exist or is not "
                "a valid directory."
                )
            return []

        # Ensure key_file_path is resolved to prevent key self-encryption
        if key_file_path:
            key_file_path = Path(key_file_path).resolve()
        else:
            key_file_path = Path(
                KEYClass.get_existing_key_file_path(self)
                ).resolve()

        console.print(
            f"[green3][-] {target_dir_path} validated. Fetching targets "
            f"for {action}ion..."
            )

        try:
            # Dynamically filter files based on the requested action
            if action == "decrypt":
                if recursive:
                    # Decrypt only files with .encrypted extension
                    all_files = [
                        f for f in target_dir_path.rglob("*")
                        if f.is_file() and f.suffix == ".encrypted"
                        ]
                else:
                    all_files = [
                        f for f in target_dir_path.iterdir()
                        if f.is_file() and f.suffix == ".encrypted"
                        ]
            else:
                if recursive:
                    # Encrypt files EXCEPT those ending in .encrypted or .key
                    all_files = [
                        f for f in target_dir_path.rglob("*")
                        if f.is_file()
                        and f.suffix.lower() not in {".encrypted", ".key"}
                        and f.resolve() != key_file_path
                        ]
                else:
                    all_files = [
                        f for f in target_dir_path.iterdir()
                        if f.is_file()
                        and f.suffix.lower() not in {".encrypted", ".key"}
                        and f.resolve() != key_file_path
                        ]
        except Exception as e:
            console.print(
                "[bright_red][!] Failed to retrieve files from "
                f"{target_dir_path} : {e}"
                )
            return []

        if not all_files:
            console.print(
                f"[yellow][!] No valid files to {action} in {target_dir_path}"
                )
            return []

        successful_files: List[Path] = []
        failed_files: List[Path] = []

        for file_path in all_files:
            try:
                if action == "encrypt":
                    processed_path = KEYClass.key_process_single_file(
                        self,
                        key_file_path=key_file_path,
                        target_file_path=file_path,
                        action="encrypt"
                        )
                else:
                    processed_path = KEYClass.key_process_single_file(
                        self,
                        key_file_path=key_file_path,
                        target_file_path=file_path,
                        action="decrypt"
                        )

                successful_files.append(processed_path)

            except Exception as e:
                console.print(
                    f"[bright_red][!] Error during {action}ing "
                    f"{file_path.name} : {e}"
                    )
                failed_files.append(file_path)

        # Summary reporting
        if successful_files:
            console.print(
                f"[green][-] ** Action Completed **\nSuccessfully {action}ed "
                f"{len(successful_files)} files in {target_dir_path} :"
                )
            for processed_file in successful_files:
                console.print(
                    f"[green]\t{processed_file.name}"
                    )

        if failed_files:
            console.print(
                f"[bright_red][!] ** Warning **\nFailed to {action} "
                f"{len(failed_files)} files :"
                )
            for failed_file in failed_files:
                console.print(
                    f"[bright_red]\t{failed_file.name}"
                    )

        return successful_files


    def get_key_action_choice(self, action: str) -> None:
        """Gets input from the user on what action to start next."""
        action = action.lower().strip()

        if action == "encrypt":
            key_encryption_choice = Prompt.ask(
                KEY_ENCRYPTION_PROMPT,
                choices=["1", "2", "3", "r", "q"],
                show_choices=False
                ).strip().lower()

            match key_encryption_choice:
                case "r":
                    self.return_to_main_menu()
                case "q":
                    Functions.exit_application()
                case "1":
                    KEYClass.generate_and_save_key(self)
                case "2":
                    key_file_path = KEYClass.get_existing_key_file_path(self)
                    target_file_path = Functions.get_file_path(
                        text="encrypted"
                        )
                    KEYClass.key_process_single_file(
                        self,
                        key_file_path=key_file_path,
                        target_file_path=target_file_path,
                        action="encrypt"
                        )
                case "3":
                    key_file_path = KEYClass.get_existing_key_file_path(self)
                    target_dir_path = Functions.get_folder_path(
                        text="encrypted"
                        )
                    recursive = Functions.select_recursive_option()
                    KEYClass.key_process_files_in_folder(
                        self,
                        target_dir_path=target_dir_path,
                        key_file_path=key_file_path,
                        action="encrypt",
                        recursive=recursive
                        )

        elif action == "decrypt":
            key_decryption_choice = Prompt.ask(
                KEY_DECRYPTION_PROMPT,
                choices=["1", "2", "r", "q"],
                show_choices=False
                ).strip().lower()

            match key_decryption_choice:
                case "r":
                    self.return_to_main_menu()
                case "q":
                    Functions.exit_application()
                case "1" | "2":
                    key_file_path = KEYClass.get_existing_key_file_path()

                    if key_decryption_choice == "1":
                        target_file_path = Functions.get_file_path(
                            text="decrypt"
                            )
                        KEYClass.key_process_single_file(
                            self,
                            key_file_path=key_file_path,
                            target_file_path=target_file_path,
                            action="decrypt"
                            )
                    else:
                        target_dir_path = Functions.get_folder_path(
                            text="decrypted"
                            )
                        recursive = Functions.select_recursive_option()
                        KEYClass.key_process_files_in_folder(
                            self,
                            target_dir_path=target_dir_path,
                            key_file_path=key_file_path,
                            action="decrypt",
                            recursive=recursive
                            )
