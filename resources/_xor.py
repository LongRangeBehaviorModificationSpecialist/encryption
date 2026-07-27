# !/usr/bin/env python3
# DLU : 27-Jul-2026

import base64
import logging
from pathlib import Path
from typing import Union

from rich.console import Console
from rich.prompt import Prompt

from resources.functions import Functions


c = Console()


class XORClass:


    def get_xor_key() -> str:
        return Prompt.ask("""[khaki3]
[-] Enter the key you want to use for the encryption """
        )


    def get_message_to_xor() -> str:
        return Prompt.ask("""[khaki3]
[-] Enter the message string you want to encrypt """
        )


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
        """XOR encrypts a text string, outputs Base64 representation, and
        saves raw bytes to disk.
        """

        logger = logging.getLogger(__name__)

        # Validation checks
        if not message:
            raise ValueError(
                "The message to encrypt cannot be empty."
            )
        if not xor_key:
            raise ValueError(
                "The XOR encryption key cannot be empty."
            )

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
                f"Failed to write encrypted message file : {e}",
                exc_info=True
            )
            raise IOError(
                f"Could not write encrypted message to {out_path} : {e}"
            ) from e

        c.print(f"""[green3]
[-] ** Action successful **\n
The Base64-encoded encrypted message is:\n
    [bright_white]{b64_encoded_msg}\n
    [dim]Raw encrypted bytes saved to : {out_path.resolve()}"""
        )

        return b64_encoded_msg






    def get_xor_choice(self) -> None:
        """Main routing controller for encryption jobs."""
        while True:
            try:
                Functions.clear_screen()
                target_option = (Prompt.ask("""[dodger_blue1]
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

                    # # Global exits
                    # if target_option == "r":
                    #     self.return_to_main_menu()
                    #     return
                    # if target_option == "q":
                    #     Functions.exit_application()
                    #     return

                    # if target_option == "1":
                    #     xor_key = Functions.get_xor_key()
                    #     message = Functions.get_message_to_xor()
                    #     self.encrypt_msg_with_xor(
                    #         xor_key=xor_key, message=message
                    #     )
                    # else:
                    #     pass

            except KeyboardInterrupt:
                c.print("""[yellow]
[!] Operation cancelled by user."""
                )
                break
            except Exception as e:
                c.print(f"""[bright_red]
[!] An error occured during processing: {e}"""
                )
                Prompt.ask("""[bright_white]
Press Enter to continue..."""
                )

            return target_option

