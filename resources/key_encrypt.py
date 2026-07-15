# !/usr/bin/env python3

from cryptography.fernet import Fernet
from datetime import datetime
import hashlib
import os
from pathlib import Path

from rich.console import Console
from rich.prompt import Prompt
from resources.functions import Functions


# Make the console object
c = Console()


class KeyFileEncryptor:
    def __init__(self, app_instance) -> None:
        """Store a reference to the main app loop controller."""
        self.app = app_instance


    def return_to_main_menu(self) -> None:
        """Returns control cleanly back to the main menu processor."""
        self.app.main()


    def generate_and_save_key(self) -> bytes:
        """
        Generates a secure Fernet key, saves it, and generates a SHA-256
        metadata log.

        Returns:
        bytes: The generated key.
    """
        key_file_dir = Path(Prompt.ask("\n[bright_white]Where do you want to \
save the key file? ").strip().strip('"\''))
        key_file_name = Prompt.ask("\n[bright_white]Enter a name for the key \
file (w/o file extension) ").strip()

        # Ensure target directory exists before writing
        key_file_dir.mkdir(parents=True, exist_ok=True)

        dt = datetime.now().strftime("%Y%m%d_%H%M%S")
        full_key_path = key_file_dir / f"{dt}_{key_file_name}.key"

        key = Fernet.generate_key()

        try:
            full_key_path.write_bytes(key)

            key_file_hash_value = hashlib.sha256(key).hexdigest().upper()
            key_file_hash_file = full_key_path.with_suffix(".key.sha256")

            log_content = (
                "------------------------------------------\n"
                f"[{Functions.get_date_time(self)}]\n"
                f"Key File Name : {full_key_path.name}\n"
                f"Key File Hash Value (SHA-256) : {key_file_hash_value}\n"
                "------------------------------------------"
            )

            key_file_hash_file.write_text(log_content, encoding="utf-8")

            c.print(f"""[bright_white]
------------------------------------------\n
[green3]Key File created successfully\n[bright_white]
[-] Key File saved in : [khaki3]{key_file_dir}[bright_white]
[-] Key File Name : [khaki3]{full_key_path.name}\n
[green3]Key File hashed successfully\n[bright_white]
[-] Key File Hash verification saved in : [khaki3]\
{key_file_hash_file.parent}[bright_white]
[-] Key File Hash File Name : [khaki3]\
{key_file_hash_file.name}[bright_white]
[-] Key File Hash value : [khaki3]{key_file_hash_value}
------------------------------------------""")

            return full_key_path

        except IOError as e:
            c.print(f"[red][ERROR] Failed to write key data to file: {e}")
            raise


    def get_existing_key_file_path(self) -> Path:
        """Prompts for a key file path and loop-validates its existence."""
        while True:
            key_file = Prompt.ask("""[bright_white]
[-] Enter the path to the .key file to use """)
            path = Path(key_file)
            if path.is_file():
                return path


    def encrypt_file_with_key(self,
            key_file_path: Path,
            target_file_path: Path) -> None:
        """Reads an existing key and encrypts a single target file."""
        target_file_path = Path(target_file_path)
        # key_path = Path(key_file_path)

        # Validation checks
        if not target_file_path.is_file():
            c.print(f"\n[red][ERROR] Target file not found : {target_file_path}")
            self.return_to_main_menu()
            return

        if not key_file_path.is_file():
            c.print(f"\n[red][ERROR] Key file not found : {key_file_path}")
            self.return_to_main_menu()
            return

        try:
            # Load the encryption key
            fernet = Fernet(key_file_path.read_bytes())
            c.print(f"\n[bright_white][-] Key file ({key_file_path.name}) loaded successfully.")

            c.print(f"\n[bright_white]Reading file : {target_file_path.name}...")
            file_data = target_file_path.read_bytes()

            c.print(f"\n[bright_white]Encrypting data...")
            encrypted_data = fernet.encrypt(file_data)

            enc_file_path = target_file_path.with_name(f"{target_file_path.name}.encrypted")
            enc_file_path.write_bytes(encrypted_data)

            Functions.print_confirm_file_action(self,
                file_name=enc_file_path,
                text="ENCRYPTED"
            )

        except Exception as e:
            c.print(f"\n[red][ERROR] An error occured during encryption: {e}")


    def encrypt_files_in_dir_with_key(self,
            key_file_path: Path,
            target_dir_path: Path) -> None:
        """Encrypts all discovered assets within a target directory directory."""

        if not key_file_path.is_file():
            c.print(f"\n[red][ERROR] Key file not found : {key_file_path}")
            self.return_to_main_menu()
            return

        if not target_dir_path.is_dir():
            c.print(f"\n[red][ERROR] Target directory not found : {target_dir_path}")
            self.return_to_main_menu()
            return

        try:
            # Load the encryption key
            fernet = Fernet(key_file_path.read_bytes())
            c.print(f"\n[bright_white][-] Key file ({key_file_path.name}) loaded successfully.")

            files = [f for f in target_dir_path.rglob('*') if f.is_file() and not f.suffix == '.encrypted']

            for file in files:
                c.print(f"[bright_white]Processing : {file.name}")
                original_data = file.read()
                encrypted_data = fernet.encrypt(original_data)

                enc_file_path = file.with_name(f"{file.name}.encrypted")
                enc_file_path.write_bytes(encrypted_data)
                c.print(f"\n[bright_white][-] Encrypted {file.name} -> {enc_file_path.name}")

            c.print(f"\n[green][+] Successfully encrypted {len(files)} files.")

        except Exception as e:
            c.print(f"\n[red][ERROR] Failed processing directory batch encryption: {e}")


    def ask_key_choice(self) -> str:
        """Prompts user for key lifecycle preferences using Rich validation rules."""
        return Prompt.ask("""[dodger_blue1]
----------------------------------------
    ENCRYPT A FILE USING A .KEY FILE
----------------------------------------\n
[khaki3]Choose an option ->[bright_white]\n
[1] Create a **new** .key then encrypt
[2] Use **existing** .key to encrypt\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """, choices=["1", "2", "r", "q"], show_choices=False).strip().lower()


    def get_target_choice(self) -> None:
        """Main routing controller for encryption jobs."""
        while True:
            target_option = Prompt.ask("""[dodger_blue1]
---------------------------------
    ENCRYPT FILE(S) WITH .KEY
---------------------------------\n
[khaki3]Choose an option ->[bright_white]\n
[1] Encrypt a single file using a .key file
[2] Encrypt all files in a directory using a .key file\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """,
                choices=["1", "2", "r", "q"],
                show_choices=False).strip().lower()

            # Global exits
            if target_option == "r":
                self.return_to_main_menu()
                return
            if target_option == "q":
                Functions.exit_application(self)
                return

            # If option 1 or 2, determine the workflow type
            is_single_file = (target_option == "1")

            # Fetch key selection strategy
            key_choice = self.ask_key_choice()

            if key_choice == "r":
                continue  # Drops back to target choice layout loop
            if key_choice == "q":
                Functions.exit_application(self)
                return

            # Resolve key dependency path
            if key_choice == "1":
                key_file_path = self.generate_and_save_key()
            else:
                key_file_path = self.get_existing_key_file_path()

            if is_single_file:
                target_file_path = Path(Functions.get_file_path(text="ENCRYPT"))
                self.encrypt_file_with_key(
                    key_file_path=key_file_path,
                    target_file_path=target_file_path)
            else:
                target_dir_path = Path(Functions.get_folder_path(text="ENCRYPT"))
                self.encrypt_files_in_dir_with_key(
                    key_file_path=key_file_path,
                    target_dir_path=target_dir_path)

            # Clean work completion exit
            break
