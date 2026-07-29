# !/usr/bin/env python3
# DLU : 29-Jul-2026


from datetime import datetime
import hashlib
from pathlib import Path
from typing import Union, List
from cryptography.fernet import Fernet

from rich.prompt import Prompt

# Import the console object from the main __init__.py file
from . import console
from resources.functions import Functions
from resources.prompts import (
    KEY_ENCRYPTION_PROMPT,
    format_key_file_log,
    format_key_file_verification,
)


class KEYClass:


    def __init__(self, app_instance) -> None:
        """Store a reference to the main app loop controller."""
        self.app = app_instance


    def return_to_main_menu(self) -> None:
        """Returns control cleanly back to the main menu processor."""
        self.app.main(self)


    def _load_fernet(self, key_file_path: Union[Path, str]) -> bytes:
        """Load the fernet key"""
        if not key_file_path.is_file():
            console.print(
                f"""[bright_red]
[!] Key file not found : {key_file_path}"""
            )
            self.return_to_main_menu()

        return Fernet(key_file_path.read_bytes())


    def generate_and_save_key(self) -> bytes:
        """Generates a secure Fernet key, saves it, and generates a SHA-256
        metadata log.

        Returns:
            bytes: The generated key.
        """
        key_file_dir = Path(
            Prompt.ask("""[bright_white]
[-] Where do you want to save the key file? """)
            .strip()
            .strip('"\'')
        )

        key_file_name = (
            Prompt.ask("""[bright_white]
[-] Enter a name for the key file (w/o file extension) """)
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

            log_content = format_key_file_log(
                key_path=full_key_path,
                hash_value=key_file_hash_value,
                timestamp=Functions.get_date_time()
            )

            key_file_hash_file.write_text(log_content, encoding="utf-8")

            console.print(
                format_key_file_verification(
                    key_file_dir=key_file_dir,
                    full_key_path=full_key_path,
                    key_file_hash_file=key_file_hash_file,
                    key_file_hash_value=key_file_hash_value
                )
            )

            return full_key_path

        except IOError as e:
            console.print(f"""[bright_red]
[!] Failed to write key data to file : {e}""")
            raise


    def get_existing_key_file_path(self) -> Path:
        """Prompts for a key file path and loop-validates its existence."""
        while True:
            key_file = (
                Prompt.ask("""[bright_white]
[-] Enter the path of the .key file to use for file encryption """)
            )
            path = Path(key_file)
            if path.is_file():
                return path


    def key_encrypt_single_file(
        self, target_file_path: Union[Path, str], fernet: Union[Fernet, bytes]
    ) -> Path:
        """Reads, encrypts, and writes a single file using Fernet symmetric
        encryption.
        """
        target_file_path = Path(target_file_path)

        if not target_file_path.is_file():
            console.print(f"""[bright_red]
[!] {target_file_path.name} does not exist or is a directory.""")
            raise FileNotFoundError(f"Invalid target file: {target_file_path}")

        fernet_obj = fernet if isinstance(fernet, Fernet) else Fernet(fernet)

        try:
            console.print(f"""[bright_white]
[-] Reading file : {target_file_path.name}...""")
            plaintext = target_file_path.read_bytes()
            console.print("""[bright_white]
[-] File content read successfully...""")

            console.print(f"""[bright_white]
[-] Encrypting file data...""")

            encrypted_data = fernet_obj.encrypt(plaintext)

            encrypted_file_path = target_file_path.with_name(
                f"{target_file_path.name}.encrypted")

            encrypted_file_path.write_bytes(encrypted_data)

            console.print(f"""[green3]
[-] Encrypted {target_file_path.name:34s}{'->':7s}{encrypted_file_path.name}""")

            return encrypted_file_path

        except Exception as e:
            console.print(f"""[bright_red]
[!] Failed to encrypt {target_file_path.name} : {e}""")
            raise


    def key_encrypt_files_in_folder(
        self, target_dir_path: Union[Path, str], fernet: Union[Fernet, bytes]
    ) -> List[Path]:
        """Recursively encrypts all valid unencrypted files within a directory
        using Fernet.
        """
        target_dir_path = Path(target_dir_path)

        if not target_dir_path.is_dir():
            console.print(f"""[bright_red]
[!] {target_dir_path} does not exist or is not a valid directory.""")
            return []

        console.print(f"""[green3]
[-] {target_dir_path} validated. Fetching targets...""")

        try:
            all_files = [
                f for f in target_dir_path.rglob("*")
                if f.is_file() and f.suffix != ".encrypted"
            ]
        except Exception as e:
            console.print(f"""[bright_red]
[!] Failed to retrieve files from {target_dir_path} : {e}""")
            return []

        if not all_files:
            console.print(f"""[yellow]
[!] No valid files to encrypt in {target_dir_path}""")
            return []

        successful_encryptions: List[Path] = []
        failed_encryptions: List[Path] = []

        for file_path in all_files:
            try:
                encrypted_path = KEYClass.key_encrypt_single_file(
                    self,
                    fernet=fernet,
                    target_file_path=file_path)
                successful_encryptions.append(encrypted_path)
            except Exception as e:
                console.print(f"""[bright_red]
[!] Error encrypting {file_path.name} : {e}""")
                failed_encryptions.append(file_path)

        if successful_encryptions:
            console.print(f"""[green]
** Action Completed **
Successfully encrypted {len(successful_encryptions)} files in \
{target_dir_path} :""")
            for encrypted_file in successful_encryptions:
                console.print(f"""[green]
    {encrypted_file.name}""")

        if failed_encryptions:
            console.print(f"""[bright_red]
** Warning **
Failed to encrypt {len(failed_encryptions)} files :""")
            for failed_file in failed_encryptions:
                console.print(f"""[bright_red]
    {failed_file.name}""")

            return successful_encryptions


    def get_key_encryption_choice(self) -> None:
        """Gets input from the user on what action to start next."""
        key_encryption_choice = (
            Prompt.ask(
                KEY_ENCRYPTION_PROMPT,
                choices=["1", "2", "3", "r", "q"],
                show_choices=False,)
            .strip()
            .lower())

        if key_encryption_choice == "r":
            self.return_to_main_menu()
            return

        if key_encryption_choice == "q":
            Functions.exit_application()
            return

        if key_encryption_choice == "1":
            KEYClass.generate_and_save_key(self)

        key_file_path = KEYClass.get_existing_key_file_path(self)
        fernet = KEYClass._load_fernet(self, key_file_path=key_file_path)

        if key_encryption_choice == "2":
            target_file_path = Functions.get_file_path(text="encrypted")
            KEYClass.key_encrypt_single_file(
                self,
                target_file_path=target_file_path,
                fernet=fernet,)

        elif key_encryption_choice == "3":
            target_dir_path = Functions.get_folder_path(text="encrypted")
            KEYClass.key_encrypt_files_in_folder(
                self,
                target_dir_path=target_dir_path,
                fernet=fernet,)
