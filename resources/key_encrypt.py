# !/usr/bin/env python3
# DLU : 27-Jul-2026

from cryptography.fernet import Fernet
from datetime import datetime
import hashlib
import logging
from pathlib import Path
from typing import List, Union

from rich.console import Console
from rich.prompt import Prompt

from resources.functions import Functions


# Make the console object
c = Console()


class KeyFileEncryptor:


    def __init__(self, app_instance) -> None:
        """Store a reference to the main app loop controller."""
        self.app = app_instance


    # def return_to_main_menu(self) -> None:
    #     """Returns control cleanly back to the main menu processor."""
    #     self.app.main(self)


    def _load_fernet(self, key_file_path: Path | str) -> bytes:

        if not key_file_path.is_file():
            c.print(f"""[bright_red]
[!] Key file not found : {key_file_path}"""
            )
            # self.return_to_main_menu()

        return Fernet(key_file_path.read_bytes())


    def generate_and_save_key(self) -> bytes:
        """Generates a secure Fernet key, saves it, and generates a SHA-256
        metadata log.

        Returns:
            bytes: The generated key.
        """
        key_file_dir = Path(
            Prompt.ask("""[bright_white]
[-] Where do you want to save the key file? """
            )
            .strip()
            .strip('"\'')
        )

        key_file_name = (
            Prompt.ask("""[bright_white]
[-] Enter a name for the key file (w/o file extension) """
            )
            .strip()
        )

        # Ensure target directory exists before writing
        key_file_dir.mkdir(parents=True, exist_ok=True)

        dt = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        full_key_path = key_file_dir / f"{dt}_{key_file_name}.key"

        key = Fernet.generate_key()

        try:
            full_key_path.write_bytes(key)

            key_file_hash_value = hashlib.sha256(key).hexdigest().upper()
            key_file_hash_file = full_key_path.with_suffix(".key.sha256")

            log_content = (
                "------------------------------------------\n"
                f"[{Functions.get_date_time()}]\n"
                f"Key file name : {full_key_path.name}\n"
                f"Key file hash value (SHA-256) : {key_file_hash_value}\n"
                "------------------------------------------"
            )

            key_file_hash_file.write_text(log_content, encoding="utf-8")

            c.print(f"""[bright_white]
------------------------------------------\n
[green][-] Key file created\n[bright_white]
[-] Key file saved in : [khaki3]{key_file_dir}[bright_white]
[-] Key file name : [khaki3]{full_key_path.name}\n
[green][-] Key file hashed\n[bright_white]
[-] Key file hash verification saved in : [khaki3]\
{key_file_hash_file.parent}[bright_white]
[-] Key file hash file name : [khaki3]\
{key_file_hash_file.name}[bright_white]
[-] Key file hash value (SHA256) : [khaki3]{key_file_hash_value}
------------------------------------------"""
            )

            return full_key_path

        except IOError as e:
            c.print(f"""[bright_red]
[!] Failed to write key data to file : {e}"""
            )
            raise


    def get_existing_key_file_path(self) -> Path:
        """Prompts for a key file path and loop-validates its existence."""
        while True:
            key_file = (
                Prompt.ask("""[bright_white]
[-] Enter the path to the .key file to use to encrypt the file """
                )
            )
            path = Path(key_file)
            if path.is_file():
                return path


    def encrypt_file_with_key(
        self,
        fernet: bytes,
        target_file: Path | str
    ) -> None:
        """Reads an existing key and encrypts a single target file."""

        target_file = Path(target_file)

        # Validation checks
        if not target_file.is_file():
            c.print(f"""[bright_red]
[!] Target file not found : {target_file}"""
            )
            # self.return_to_main_menu()
            return

        try:
            c.print(f"""[bright_white]
[-] Reading file : {target_file.name}..."""
                )
            file_data = target_file.read_bytes()

            c.print(f"""[bright_white]
[-] Encrypting file data..."""
            )
            encrypted_data = fernet.encrypt(file_data)

            encrypted_file_path = target_file.with_name(
                f"{target_file.name}.encrypted"
            )

            c.print("""[bright_white]
[-] Writing encrypted data to file..."""
            )
            encrypted_file_path.write_bytes(encrypted_data)

            c.print(f"""[bright_white]
[-] Encrypted {target_file.name:34s}{'->':7s}{encrypted_file_path.name}"""
            )

        except Exception as e:
            c.print(f"""[bright_red]
[!] An error occured during encryption : {e}"""
            )


    def encrypt_files_in_dir_with_key(
        self,
        fernet: bytes,
        target_dir: Path | str
    ) -> None:
        """Encrypts all discovered assets within a target directory."""

        target_dir = Path(target_dir)

        if not target_dir.exists():
            raise FileNotFoundError(
                f"[!] The target directory does not exist : {target_dir}"
            )
        if not target_dir.is_dir():
            raise NotADirectoryError(
                f"[!] The provided path is not a directory : {target_dir}"
            )

        try:
            all_files = [
                f for f in target_dir.rglob("*")
                if f.is_file() and not f.suffix == ".encrypted"
            ]
        except Exception as e:
                c.print(f"""[bright_red]
[!] Failed to retrieve files from {target_dir} : {e}"""
                )
                return []

        if not all_files:
            c.print(f"""[yellow]
[!] No valid files to encrypt in {target_dir}"""
            )
            return []

        successful_encryptions: List[Path] = []
        failed_encryptions: List[Path] = []

        for file_path in all_files:
            c.print(f"""[bright_white]
[-] Reading file : {file_path.name}..."""
                )

            encrypted_path = self.encrypt_file_with_key(
                fernet=fernet,
                target_file=file_path
            )
            successful_encryptions.append(encrypted_path)

            c.print(f"""[bright_red]
[!] Error encrypting {file_path.name} : {e}."""
            )
            failed_encryptions.append(file_path)

        if successful_encryptions:
            c.print(f"""[green]
** Action Completed **
Successfully encrypted {len(successful_encryptions)} files in \
{target_dir} :"""
            )
            for encrypted_file in successful_encryptions:
                c.print(f"""[green]
    {encrypted_file.name}"""
                )

        if failed_encryptions:
            c.print(f"""[bright_red]
** Warning **
Failed to encrypt {len(failed_encryptions)} files :"""
            )
            for failed_file in failed_encryptions:
                c.print(
                    f"""[bright_red]
    {failed_file.name}"""
                )

        return successful_encryptions


    def ask_key_choice(self) -> str:
        """Prompts user for key choice."""

        # Functions.clear_screen()
        return (
            Prompt.ask("""[dodger_blue1]
----------------------------------------
ENCRYPT FILE(S) WITH A .KEY FILE
----------------------------------------\n
[khaki3]Choose an option :[bright_white]\n
[1] Create a [bold]new[/bold] .key then encrypt
[2] Use [bold]existing[/bold] .key to encrypt\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """,
                choices=["1", "2", "r", "q"],
                show_choices=False,
            )
            .strip()
            .lower()
        )


    def get_target_choice(self) -> None:
        """Main routing controller for encryption jobs."""

        # Functions.clear_screen()
        while True:
            target_option = (
                Prompt.ask("""[dodger_blue1]
---------------------------------
ENCRYPT FILE(S) WITH A .KEY FILE
---------------------------------\n
[khaki3]Choose an option :[bright_white]\n
[1] Encrypt a single file using a .key file
[2] Encrypt all files in a directory using a .key file\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """,
                    choices=["1", "2", "r", "q"],
                    show_choices=False,
                )
                .strip()
                .lower()
            )

            # Global exits
            if target_option == "r":
                # self.return_to_main_menu()
                # return
                pass
            if target_option == "q":
                Functions.exit_application()
                return

            # If option 1 or 2, determine the workflow type
            is_single_file = (target_option == "1")

            # Fetch key selection strategy
            key_choice = self.ask_key_choice()

            if key_choice == "r":
                # self.return_to_main_menu()
                # continue
                pass
            if key_choice == "q":
                Functions.exit_application()
                return

            # Resolve key dependency path
            if key_choice == "1":
                key_file_path = self.generate_and_save_key()
            else:
                key_file_path = self.get_existing_key_file_path()

            fernet = self._load_fernet(key_file_path=key_file_path)

            if is_single_file:
                target_file = Functions.get_file_path(text="encrypted")
                self.encrypt_file_with_key(
                    fernet=fernet,
                    target_file=Path(target_file)
                )
            else:
                target_dir = Functions.get_directory_path(text="encrypted")
                self.encrypt_files_in_dir_with_key(
                    fernet=fernet,
                    target_dir=Path(target_dir)
                )

            # Clean work completion exit
            break
