# !/usr/bin/env python3
# DLU : 27-Jul-2026


from datetime import datetime
import hashlib
from pathlib import Path
from typing import Union
from cryptography.fernet import Fernet

from rich.console import Console
from rich.prompt import Prompt

from resources.functions import Functions


c = Console()


class KEYClass:

    def _load_fernet(self, key_file_path: Union[Path, str]) -> bytes:

        if not key_file_path.is_file():
            c.print(f"""[bright_red]
[!] Key file not found : {key_file_path}"""
            )
            self.return_to_main_menu()

        return Fernet(key_file_path.read_bytes())


    def ask_key_choice(self) -> str:
        """Prompts user for key choice."""

        Functions.clear_screen()
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
[green3][-] Key file created\n[bright_white]
[-] Key file saved in : [khaki3]{key_file_dir}[bright_white]
[-] Key file name : [khaki3]{full_key_path.name}\n
[green3][-] Key file hashed\n[bright_white]
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


    def encrypt_file_with_key(self, fernet: bytes, plaintext: str) -> str:
        return fernet.encrypt(plaintext)