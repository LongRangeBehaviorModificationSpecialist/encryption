# !/usr/bin/env python3
# DLU : 30-Jul-2026

import base64
from pathlib import Path
from rich.prompt import Prompt
from typing import List

from . import console
from resources.functions import Functions
from resources.prompts import XOR_ENCRYPTION_PROMPT


class XORClass:


    def __init__(self, app_instance) -> None:
        """Store a reference to the main app loop controller."""
        self.app = app_instance


    def return_to_main_menu(self) -> None:
        """Returns control cleanly back to the main menu processor."""
        self.app.main(self)


    def get_xor_key_prompt() -> str:
        return Prompt.ask(
            "[bright_white][-] Enter the key you want to use for the XOR "
            "encryption "
            )


    def get_message_to_xor() -> str:
        return Prompt.ask(
            "[bright_white][-] Enter the message string you want to XOR "
            "encrypt "
            )


    def _xor_bytes(self, data: bytes, key: bytes) -> bytes:
        """Helper method to execute fast, byte-level XOR operations."""
        key_len = len(key)
        return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


    def xor_encrypt_msg(
        self,
        message: str,
        xor_key: str,
        output_file: Path | str = "encrypted_msg.txt"
    ) -> str:
        """XOR encrypts a text string, outputs Base64 representation, and
        saves raw bytes to disk.
        """

        # Validation checks
        if not message:
            raise ValueError("The message to encrypt cannot be empty.")
        if not xor_key:
            raise ValueError("The XOR encryption key cannot be empty.")

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
                    f"Could not write encrypted message to {out_path} : {e}"
                    )

        console.print(
            "[green3][-] ** Action successful **\nThe Base64-encoded "
            f"encrypted message is:\n\t[bright_white]{b64_encoded_msg}\n\t"
            f"[dim]Raw encrypted bytes saved to : {out_path.resolve()}"
            )

        return b64_encoded_msg


    def xor_encrypt_single_file(
        self,
        target_file_path: Path | str,
        xor_key: bytes
    ) -> None:
        """XOR encrypts a file by reading/writing raw binary streams."""

        target_file_path = Path(target_file_path)

        if not xor_key:
            raise ValueError("XOR encryption key cannot be empty.")

        if not target_file_path.is_file():
            console.print(
                f"[bright_red][!] {target_file_path.name} does not exist "
                "or is a directory."
                )
            raise FileNotFoundError(
                f"Invalid target file: {target_file_path}"
                )

        key_bytes = xor_key.encode("utf-8")

        try:
            console.print(
                f"[bright_white][-] Reading file : {target_file_path.name}..."
                )
            plaintext = target_file_path.read_bytes()
            console.print(
                "[bright_white][-] File content read successfully..."
                )

            console.print(
                f"[bright_white][-] Encrypting file data..."
                )

            encrypted_data = self._xor_bytes(plaintext, key_bytes)
            encrypted_file_path = target_file_path.with_suffix(
                target_file_path.suffix + ".encrypted")
            encrypted_file_path.write_bytes(encrypted_data)

            console.print(
                f"[green3][-] Encrypted {target_file_path.name:34s}{'->':7s}"
                f"{encrypted_file_path.name}"
                )

            return encrypted_file_path

        except Exception as e:
            console.print(
                f"[bright_red][!] Failed to encrypt {target_file_path.name} "
                f": {e}"
                )


    def xor_encrypt_files_in_folder(
        self,
        target_dir_path: Path | str,
        xor_key: str
    ) -> List[Path]:
        """XOR encrypts all files within a directory by reading/writing raw
        binary streams.
        """
        target_dir_path = Path(target_dir_path)

        if not target_dir_path.is_dir():
            console.print(
                f"[bright_red][!] {target_dir_path} does not exist or is "
                "not a valid directory."
                )
            return []

        console.print(
            f"[green3][-] {target_dir_path} validated. Fetching targets..."
            )

        try:
            all_files = [
                f for f in target_dir_path.rglob("*")
                if f.is_file() and f.suffix != ".encrypted"
                ]
        except Exception as e:
            console.print(
                "[bright_red][!] Failed to retrieve files from "
                f"{target_dir_path} : {e}"
                )
            return []

        if not all_files:
            console.print(
                f"[yellow][!] No valid files to encrypt in {target_dir_path}"
                )
            return []

        successful_encryptions: List[Path] = []
        failed_encryptions: List[Path] = []

        for file_path in all_files:
            try:
                encrypted_path = XORClass.xor_encrypt_single_file(
                    self,
                    target_file_path=file_path,
                    xor_key=xor_key
                    )
                successful_encryptions.append(encrypted_path)
            except Exception as e:
                console.print(
                    f"[bright_red][!] Error encrypting {file_path.name} : {e}"
                    )
                failed_encryptions.append(file_path)

        if successful_encryptions:
            console.print(
                f"[green][-] ** Action Completed **\nSuccessfully encrypted "
                f"{len(successful_encryptions)} files in {target_dir_path} :"
                )
            for encrypted_file in successful_encryptions:
                console.print(
                    f"[green]\t{encrypted_file.name}"
                    )

        if failed_encryptions:
            console.print(
                "[bright_red][!] ** Warning **\nFailed to encrypt "
                f"{len(failed_encryptions)} files :"
                )
            for failed_file in failed_encryptions:
                console.print(
                    f"[bright_red]\t{failed_file.name}"
                    )

        return successful_encryptions


    @staticmethod
    def get_xor_message_to_decrypt() -> str:
        return Prompt.ask(
            "[khaki3][-] Enter the message string you want to decrypt "
            )


    @staticmethod
    def get_xor_file_to_decrypt() -> Path:
        return Path(
            Functions.get_file_path(text="you want to decrypt")
            )


    def get_xor_encryption_choice(self) -> None:
        """Main routing controller for encryption jobs."""
        while True:
            Functions.clear_screen()
            try:
                xor_encryption_choice = Prompt.ask(
                    XOR_ENCRYPTION_PROMPT,
                    choices=["1", "2", "3", "r", "q"],
                    show_choices=False
                    ).strip().lower()

                match xor_encryption_choice:
                    case "1":
                        message = self.get_message_to_xor()
                        xor_key = XORClass.get_xor_key_prompt(self)
                        XORClass.xor_encrypt_msg(
                            self,
                            xor_key=xor_key,
                            message=message
                            )
                    case "2":
                        target_file_path = Functions.get_file_path(
                            text="encrypted"
                            )
                        xor_key = XORClass.get_xor_key_prompt(self)
                        XORClass.xor_encrypt_single_file(
                            self,
                            target_file_path=target_file_path,
                            xor_key=xor_key
                            )
                    case "3":
                        target_dir_path = Functions.get_folder_path(
                            text="encrypted"
                            )
                        xor_key = XORClass.get_xor_key_prompt(self)
                        XORClass.xor_encrypt_files_in_folder(
                            self,
                            target_dir_path=target_dir_path,
                            xor_key=xor_key
                            )
                    case "r":
                        self.return_to_main_menu()
                    case "q":
                        Functions.exit_application()

            except KeyboardInterrupt:
                console.print(
                    "[yellow][!] Operation cancelled by user."
                    )
                break

            except Exception as e:
                console.print(
                    f"[bright_red][!] An error occured when processing : {e}"
                    )
                Prompt.ask(
                    "[bright_white][-] Press Enter to continue..."
                    )





    def get_xor_decryption_choice(self) -> None:
        pass