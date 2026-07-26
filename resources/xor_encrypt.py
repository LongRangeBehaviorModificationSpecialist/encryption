# !/usr/bin/env python3
# DLU : 23-Jul-2026

from pathlib import Path
import base64
import logging
from pathlib import Path
from typing import Union

from rich.console import Console
from rich.prompt import Prompt

from resources.functions import Functions


# Make the console object
c = Console()


class XOREncryptor:


    def __init__(self, app_instance):
            """Store a reference to the main app loop controller."""
            self.app = app_instance


    @staticmethod
    def _xor_bytes(data: bytes, key: bytes) -> bytes:
        """Helper method to execute fast, byte-level XOR operations."""
        key_len = len(key)
        return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


    def encrypt_msg_with_xor(
        self,
        message: str,
        xor_key: str,
        output_file: Union[str, Path] = "encrypted_msg.txt",
    ) -> str:
        """XOR encrypts a text string, outputs Base64 representation, and
        saves raw bytes to disk.
        """

        logger = logging.getLogger(__name__)

        # Validation checks
        if not message:
            raise ValueError("Message to encrypt cannot be empty.")
        if not xor_key:
            raise ValueError("XOR encryption key cannot be empty.")

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
            logger.error(
                f"Failed to write encrypted message file : {e}.",
                exc_info=True
            )
            raise IOError(
                f"""Could not write encrypted message to "{out_path}" : {e}."""
            ) from e

        c.print(
            f"""[green3]
[-] ** Action successful **\n
The Base64-encoded encrypted message is:\n
    [bright_white]{b64_encoded_msg}\n
    [dim]Raw encrypted bytes saved to : {out_path.resolve()}"""
        )

        return b64_encoded_msg


    def encrypt_file_with_xor(
        self, file_path: Union[str, Path], xor_key: str
    ) -> None:
        """XOR encrypts a file by reading/writing raw binary streams."""

        logger = logging.getLogger(__name__)

        target_path = Path(file_path)

        # 1. Path & Key Validation
        if not xor_key:
            raise ValueError("XOR encryption key cannot be empty.")
        if not target_path.exists():
            raise FileNotFoundError(f"Target file not found : {target_path}.")
        if not target_path.is_file():
            raise IsADirectoryError(
                f"Provided path is a directory, not a file : {target_path}."
            )

        key_bytes = xor_key.encode("utf-8")
        destination_path = target_path.with_suffix(
            target_path.suffix + ".encrypted"
        )

        # Binary stream read/write processing
        try:
            with open(target_path, "rb") as f_in:
                raw_data = f_in.read()

            encrypted_bytes = self._xor_bytes(raw_data, key_bytes)

            with open(destination_path, "wb") as f_out:
                f_out.write(encrypted_bytes)

        except Exception as e:
            logger.error(
                f"Failed XOR file encryption on {target_path}: {e}",
                exc_info=True,
            )
            c.print(
                f"""[bright_red]
[!] Error encrypting file "{target_path.name}": {e}."""
            )
            # Clean up potentially broken destination output file
            if destination_path.exists():
                destination_path.unlink(missing_ok=True)
            raise RuntimeError(
                f"""Error encrypting file "{target_path.name}": {e}."""
            ) from e

        c.print(
            f"""[green3]
[-] ** Action successful ** File Encrypted with XOR key.\n
[dim]Output saved to: {destination_path.name}"""
        )

        return destination_path


    def get_target_choice(self) -> None:
        """Main routing controller for encryption jobs."""
        while True:
            try:
                Functions.clear_screen()
                target_option = (
                    Prompt.ask(
                        """[dodger_blue1]
---------------------------------------
ENCRYPT FILE(S) USING AN XOR KEY
---------------------------------------\n
[khaki3]Choose an option :[bright_white]\n
[1] Encrypt a single message string
[2] Encrypt a file\n
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
                    self.return_to_main_menu()
                    return
                if target_option == "q":
                    Functions.exit_application()
                    return

                if target_option == "1":
                    xor_key = Functions.get_xor_key()
                    message = Functions.get_message_to_xor()
                    self.encrypt_msg_with_xor(
                        xor_key=xor_key, message=message
                    )
                else:
                    pass

            except KeyboardInterrupt:
                c.print(
                    """[yellow]
[!] Operation cancelled by user."""
                )
                break
            except Exception as e:
                c.print(
                    f"""[bright_red]
[!] An error occured during processing: {e}"""
                )
                Prompt.ask(
                    """[bright_white]
Press Enter to continue..."""
                )
