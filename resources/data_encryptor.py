# !/usr/bin/env python3
# DLU : 27-Jul-2026

import logging
from pathlib import Path
from typing import Union

from rich.console import Console
from rich.prompt import Prompt

from resources.functions import Functions
from resources._aes import AESClass
from resources._key import KEYClass
from resources._pgp import PGPClass
from resources._xor import XORClass


# Make the console object
c = Console()


logger = logging.getLogger(__name__)


class Encryptor:


    def __init__(self, app_instance) -> None:
        """Store a reference to the main app loop controller."""
        self.app = app_instance


    def return_to_main_menu(self) -> None:
        """Returns control cleanly back to the main menu processor."""
        self.app.main(self)


    def encrypt_single_file(
            self,
            encryption_type: str,
            target_file_path: Union[Path, str]
    ) -> Path:

        valid_encryption_types = {"AES.CBC", "AES.GCM", "KEY", "PGP", "XOR"}

        if encryption_type not in valid_encryption_types:
            raise ValueError(
                f"Invalid encryption type : {encryption_type}. Expected \
one of the following values : {valid_encryption_types}"
            )

        target_file_path = Path(target_file_path)

        if not target_file_path.exists():
            raise FileNotFoundError(
                f"Target file not found : {target_file_path}"
            )
        if not target_file_path.is_file():
            raise IsADirectoryError(
                f"Provided path is a directory, not a file : {target_file_path}"
            )

        try:
            c.print(f"""[bright_white]
[-] Reading file : {target_file_path.name}..."""
            )
            # Read plaintext data
            plaintext = target_file_path.read_bytes()

            c.print(f"""[bright_white]
[-] Encrypting file data...""")
            # Set the name of the encrypted file
            encrypted_file_path = target_file_path.with_name(
                f"{target_file_path.name}.encrypted"
            )

            # ---------------------------
            #
            # CHOOSE ENCRYPTION METHOD
            #
            # ---------------------------

            if encryption_type == "AES.CBC":
                encrypted_data = AESClass.encrypt_with_aes(
                    plaintext=plaintext, mode="AES.CBC"
                )

            elif encryption_type == "AES.GCM":
                encrypted_data = AESClass.encrypt_with_aes(
                    plaintext=plaintext, mode="AES.GCM"
                )

            elif encryption_type == "KEY":
                # Fetch key selection strategy
                key_choice = KEYClass.ask_key_choice()

                if key_choice == "r":
                    self.return_to_main_menu()
                    return
                if key_choice == "q":
                    Functions.exit_application()
                    return

                # Resolve key dependency path
                if key_choice == "1":
                    key_file_path = KEYClass.generate_and_save_key()
                else:
                    key_file_path = KEYClass.get_existing_key_file_path()

                fernet = KEYClass._load_fernet(key_file_path=key_file_path)

                encrypted_data = KEYClass.encrypt_file_with_key(
                    fernet=fernet,
                    plaintext=plaintext
                )

            elif encryption_type == "PGP":
                pgp_key_choice = PGPClass.ask_pgp_key_choice()

                if pgp_key_choice == "r":
                    self.return_to_main_menu()
                    return
                if pgp_key_choice == "q":
                    Functions.exit_application()
                    return

                if pgp_key_choice == "1":
                    password = Functions.get_password()
                    email_address = Functions.get_email_address()

                    if not password.strip() or not email_address.strip():
                        c.print("""[yellow]
[!] Key generation cancelled : Missing password or email."""
                        )
                        Prompt.ask("""[bright_white]
Press Enter to return to menu..."""
                        )
                        return
                    PGPClass.generate_pgp_key(
                        password=password, email_address=email_address
                    )
                elif pgp_key_choice == "2":
                    raw_path = Functions.get_file_path(text="ENCRYPTED")
                    # User cancelled input
                    if not raw_path or not raw_path.strip():
                        return

                    recipient = Prompt.ask("""[bright_white]
[-] Enter recipient email or Key ID: """
                    ).strip()
                    if not recipient:
                        c.print("""[yellow]
[!] Encryption cancelled: No recipient specified."""
                        )
                        Prompt.ask("""[bright_white]
Press Enter to continue..."""
                        )
                        return

                    PGPClass.pgp_encrypt_file(
                        target_file_path=Path(raw_path),
                        recipients=[recipient]
                    )

            c.print("""[bright_white]
[-] Writing encrypted data to file..."""
            )
            encrypted_file_path.write_bytes(encrypted_data)

            c.print(f"""[green3]
[-] Encrypted {target_file_path.name:34s}{'->':7s}{encrypted_file_path.name}"""
                )


            if encryption_type == "XOR":
                xor_choice = XORClass.get_xor_choice()

                # Global exits
                if xor_choice == "r":
                    self.return_to_main_menu()
                    return
                if xor_choice == "q":
                    Functions.exit_application()
                    return

                if xor_choice == "1":
                    xor_key = XORClass.get_xor_key()
                    message = XORClass.get_message_to_xor()
                    XORClass.encrypt_msg_with_xor(
                        xor_key=xor_key, message=message
                    )
                else:
                    pass


        except Exception as e:
            c.print(f"""[bright_red]
[!] An error occured during encryption : {e}"""
            )






















    def encrypt_files_in_directory():
        pass


    def get_target_choice(self) -> None:
        """Main routing controller for encryption jobs."""
        pass

