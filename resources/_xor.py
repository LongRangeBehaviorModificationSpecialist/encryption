# !/usr/bin/env python3
# DLU : 27-Jul-2026

import base64
import logging
from pathlib import Path
from typing import Union

from rich.prompt import Prompt

from .. import console
from resources.functions import Functions
from resources.prompts import GET_XOR_ENCRYPTION_CHOICE_TEXT



class XORClass:


    def __init__(self, app_instance) -> None:
        """Store a reference to the main app loop controller."""
        self.app = app_instance


    def return_to_main_menu(self) -> None:
        """Returns control cleanly back to the main menu processor."""
        self.app.main(self)


    def get_xor_key_prompt() -> str:
        return Prompt.ask("""[khaki3]
[-] Enter the key you want to use for the XOR encryption """)


    def get_message_to_xor() -> str:
        return Prompt.ask("""[khaki3]
[-] Enter the message string you want to XOR encrypt """)


    def _xor_bytes(self, data: bytes, key: bytes) -> bytes:
        """Helper method to execute fast, byte-level XOR operations."""
        key_len = len(key)
        return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


    def encrypt_msg_with_xor(
        self,
        message: str,
        xor_key: str,
        output_file: Union[Path, str] = "encrypted_msg.txt",
    ) -> str:
        """XOR encrypts a text string, outputs Base64 representation, and saves
        raw bytes to disk.
        """

        # Validation checks
        if not message:
            raise ValueError(
                "The message to encrypt cannot be empty.")
        if not xor_key:
            raise ValueError(
                "The XOR encryption key cannot be empty.")

        message_bytes = message.encode("utf-8")
        key_bytes = xor_key.encode("utf-8")

        # Fast byte-level XOR processing
        encrypted_bytes = self._xor_bytes(message_bytes, key_bytes)

        # Encode to Base64 for safe terminal display and transport
        b64_encoded_msg = base64.b64encode(encrypted_bytes).decode("ascii")

        # Write raw encrypted bytes safely
        out_path = Path(output_file)

        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "wb") as f:
                f.write(encrypted_bytes)
        except Exception as e:
                console.print(
                    f"Could not write encrypted message to {out_path} : {e}")

        console.print(f"""[green3]
[-] ** Action successful **\n
The Base64-encoded encrypted message is:\n
    [bright_white]{b64_encoded_msg}\n
    [dim]Raw encrypted bytes saved to : {out_path.resolve()}""")

        return b64_encoded_msg


    def encrypt_file_with_xor(
        # self, target_file_path: Union[Path, str], xor_key: bytes
        self, plaintext: str, xor_key:bytes
    ) -> None:
        """XOR encrypts a file by reading/writing raw binary streams."""

        target_file_path = Path(target_file_path)

        if not target_file_path.exists():
            raise FileNotFoundError(
                f"Target file not found : {target_file_path}")
        if not target_file_path.is_file():
            raise IsADirectoryError(
                f"Provided path is a directory, not a file : {target_file_path}")

        key_bytes = xor_key.encode("utf-8")

        # Return the encrypted bytes
        return self._xor_bytes(plaintext, key_bytes)

        # destination_path = target_file_path.with_suffix(
        #     target_file_path.suffix + ".encrypted"
        # )

        # # Binary stream read/write processing
        # try:
        #     with open(target_file_path, "rb") as f_in:
        #         raw_data = f_in.read()

        #     encrypted_bytes = self._xor_bytes(raw_data, key_bytes)

        #     with open(destination_path, "wb") as f_out:
        #         f_out.write(encrypted_bytes)

#         except Exception as e:
#             console.print(
#                 f"""[bright_red]
# [!] Error encrypting file "{target_file_path.name}" : {e}"""
#             )
#             # Clean up potentially broken destination output file
#             if destination_path.exists():
#                 destination_path.unlink(missing_ok=True)

#         console.print(
#             f"""[green3]
# [-] ** Action successful **
# [dim]File Encrypted with XOR key.
# Output saved to : {destination_path.name}"""
#         )

        # return destination_path


    def xor_encryption_workflow(
        self, plaintext: str
    ) -> None:
            xor_choice = self.get_xor_encryption_choice()

            if xor_choice == "r":
                self.return_to_main_menu()
                return

            if xor_choice == "q":
                Functions.exit_application()
                return

            xor_key = self.get_xor_key_prompt()

            if xor_choice == "1":
                message = self.get_message_to_xor()
                encrypted_data = self.encrypt_msg_with_xor(
                    xor_key=xor_key, message=message
                )

            elif xor_choice == "2":
                encrypted_data = self.encrypt_file_with_xor(
                    xor_key=xor_key, plaintext=plaintext
                )

            return encrypted_data






    @staticmethod
    def get_xor_message_to_decrypt() -> str:
        return Prompt.ask("""[khaki3]
[-] Enter the message string you want to decrypt """)


    @staticmethod
    def get_xor_file_to_decrypt() -> Path:
        return Path(
            Functions.get_file_path(text="you want to decrypt"))


    def get_xor_encryption_choice(self) -> None:
        """Main routing controller for encryption jobs."""
        while True:
            Functions.clear_screen()
            try:
                return (
                    Prompt.ask(
                        GET_XOR_ENCRYPTION_CHOICE_TEXT,
                        choices=["1", "2", "r", "q"],
                        show_choices=False,
                    )
                    .strip()
                    .lower()
                )

            except KeyboardInterrupt:
                console.print("""[yellow]
[!] Operation cancelled by user.""")
                break

            except Exception as e:
                console.print(f"""[bright_red]
[!] An error occured during processing : {e}""")
                Prompt.ask("""[bright_white]
Press Enter to continue...""")
