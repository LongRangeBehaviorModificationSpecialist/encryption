# !/usr/bin/env python3
# DLU : 27-Jul-2026

from cryptography.fernet import Fernet, InvalidToken
from pathlib import Path
from typing import Union

from rich.console import Console
from rich.prompt import Prompt

from resources.functions import Functions


# Make the console object
c = Console()


class KeyFileDecryptor:


    def __init__(self, app_instance) -> None:
        """Store a reference to the main app loop controller."""
        self.app = app_instance


    def return_to_main_menu(self) -> None:
        """Returns control cleanly back to the main menu processor."""
        self.app.main()


    def get_decryption_key_file_path(self) -> Path:
        """Prompts for a key file path and loop-validates its existence."""
        while True:
            key_file = Prompt.ask("""[bright_white]
[-] Enter the path to the .key file to use """
            )
            path = Path(key_file)
            if path.is_file():
                return path


    @Functions.timeit
    def decrypt_file_with_key(
        self, key_file_path: Path, target_file_path: Path
    ) -> None:
        """Reads a key from key_file_path and decrypts target_file_path.
        Removes the '.encrypted' extension from the file name.

        Args:
            key_file: Path to the key_file
            file_path: Path of the file to be decrypted

        Returns:
            None
        """

        # Validation checks
        if not target_file_path.is_file():
            c.print(f"""[bright_red]
[!] Target file not found : {target_file_path}"""
            )
            self.return_to_main_menu()
            return

        if not key_file_path.is_file():
            c.print(f"""[bright_red]
[!] Key file not found : {key_file_path}"""
            )
            self.return_to_main_menu()
            return

        # Prevent decrypting a file that isn't marked as encrypted
        if target_file_path.suffix != ".encrypted":
            c.print(f"""[bright_red]
[!] The target file does not appear to be an .encrypted file."""
            )
            self.return_to_main_menu()
            return

        try:
            # Load the key and initialize Fernet
            fernet = Fernet(key_file_path.read_bytes())
            c.print(f"""[bright_white]
[-] Key file ({key_file_path.name}) loaded successfully."""
            )

            c.print(f"""[bright_white]
[-] Reading encrypted file : {target_file_path.name}..."""
            )
            encrypted_data = target_file_path.read_bytes()

            c.print("""[bright_white]
[-] Decrypting data..."""
            )
            # This will throw an InvalidToken exception if the key is wrong
            decrypted_data = fernet.decrypt(encrypted_data)

            # Determine output path (e.g., "data.txt.encrypted" -> "data.txt")
            # '.with_suffix("")' strips away the LAST extension (.encrypted)
            decrypted_file_path = target_file_path.with_suffix("")

            # Save the decrypted file
            decrypted_file_path.write_bytes(decrypted_data)

            Functions.print_confirm_file_action(
                self,
                file_name=decrypted_file_path,
                text="Decryption"
            )

        except InvalidToken:
            c.print("""[bright_red]
[!] Decryption failed! The key provided is invalid for this file."""
            )
        except Exception as e:
            c.print(f"""[bright_red]
[!] An error occurred during decryption : {e}"""
            )


    @Functions.timeit
    def decrypt_files_in_dir_with_key(
        self, key_file_path: Union[str, Path], target_dir_path: Union[str, Path]
    ) -> None:
        """Decrypts all discovered assets within a target directory directory."""

        # Validation checks
        if not target_dir_path.is_dir():
            c.print(f"""[bright_red]
[!] Target directory not found : {target_dir_path}"""
            )
            self.return_to_main_menu()
            return

        if not key_file_path.is_file():
            c.print(f"""[bright_red]
[!] Key file not found : {key_file_path}"""
            )
            self.return_to_main_menu()
            return

        try:
            # Load the key and initialize Fernet
            fernet = Fernet(key_file_path.read_bytes())
            c.print(f"""[bright_white]
[-] Key file ({key_file_path.name}) loaded successfully"""
            )

            files = [
                f for f in target_dir_path.rglob("*")
                if f.is_file() and f.suffix == ".encrypted"
            ]

            for file in files:
                c.print(f"""[bright_white]
[-] Reading file : {file.name}"""
                )
                encrypted_data = file.read_bytes()

                c.print(f"""[bright_white]
[-] Decrypting {file.name} data..."""
                )
                # This will throw an InvalidToken exception if the key is wrong
                decrypted_data = fernet.decrypt(encrypted_data)

                # Determine output path (e.g., "data.txt.encrypted" -> "data.txt")
                # '.with_suffix("")' strips away the LAST extension (.encrypted)
                decrypted_file_path = file.with_suffix("")

                # Save the decrypted file
                decrypted_file_path.write_bytes(decrypted_data)
                c.print(f"""[bright_white]
[-] Decrypted {file.name} -> {decrypted_file_path.name}"""
                )

            c.print(f"""[green3]
[+] Successfully decrypted {len(files)} files"""
            )

        except InvalidToken:
            c.print(f"""[bright_red]
[!] Decryption Failed! The key provided is invalid for {file.name}"""
            )
        except Exception as e:
            c.print(f"""[bright_red]
[!] Failed processing directory batch encryption : {e}"""
            )


    def get_target_choice(self) -> None:
        """Main routing controller for decryption jobs."""
        while True:
            target_option = (
                Prompt.ask("""[dodger_blue1]
---------------------------------------
DECRYPT FILE WITH PROVIDED .KEY
---------------------------------------\n
[khaki3]Choose an option :[bright_white]\n
[1] Decrypt a file using a .key file
[2] Decrypt files in a folder using a .key file\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """,
                    choices=["1", "2", "r", "q"],
                    show_choices=False,
                )
                .strip()
                .lower()
            )

            if target_option == "r":
                self.return_to_main_menu()
                return
            if target_option == "q":
                Functions.exit_application()
                return

            key_file_path = self.get_decryption_key_file_path()

            is_single_file = (target_option == "1")

            if is_single_file:
                target_file_path = Functions.get_file_path(text="DECRYPT")
                self.decrypt_file_with_key(
                    key_file_path=key_file_path,
                    target_file_path=Path(target_file_path)
                )
            else:
                target_dir_path = Functions.get_folder_path(text="DECRYPT")
                self.decrypt_files_in_dir_with_key(
                    key_file_path=key_file_path,
                    target_dir_path=Path(target_dir_path)
                )

            break

