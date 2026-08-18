# !/usr/bin/env python3

import base64
from pathlib import Path

from . import install
from config.log_config import get_logger
from utils import Utils, UIHandlerProtocol, RichUIHandler, get_time


logger = get_logger("xor")
install()


class XOR:

    """XOR-based file encryption/decryption class.

    Provides single-file and directory-wide processing with automatic
    output naming based on file suffix detection (.xor = encrypted).
    """

    def __init__(self,
        default_chunk_size: int = 64 * 1024,
        ui: UIHandlerProtocol | None = None
    ) -> None:
        """Initialize the XOR processor.

        Args:
            default_chunk_size: Bytes to read/write per iteration for large
            file handling.
        """
        self.ui = ui or RichUIHandler(get_time=get_time)
        self.default_chunk_size = default_chunk_size


    def get_xor_key(self) -> str:
        """Returns a UTF-8 encoded XOR key."""
        xor_key = self.ui.prompt(
            "Enter the key you want to use for the XOR operation",
            password=True
        )

        if not xor_key:
            self.ui.warning("The XOR key cannot be empty")
            raise ValueError("The XOR key cannot be empty.")

        return xor_key.encode("utf-8")


    def _xor_bytes(self, data: bytes, key: bytes) -> bytes:
        """Helper method to execute fast, byte-level XOR operations."""
        key_len = len(key)
        return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


    def _handle_xor_process_msg(self, action: str) -> None:
        message = self.ui.prompt("Enter the message you want to XOR")

        if not message:
            self.ui.warning("The message to process cannot be empty")
            raise ValueError("The message cannot be empty.")

        xor_key = self.get_xor_key()

        self.xor_process_msg(
            xor_key=xor_key,
            message=message,
            action=action,
        )


    def _handle_xor_process_file(self, action: str) -> None:
        target_file = Utils.get_file_path(self)
        xor_key = self.get_xor_key()
        self.xor_process_file(
            target_file=target_file,
            xor_key=xor_key,
            action=action,
        )


    def _handle_xor_process_folder(self, action: str) -> None:
        target_dir = Utils.get_directory_path(self)
        xor_key = self.get_xor_key()
        recursive = Utils.select_recursive_option(self)
        self.xor_process_folder(
            target_dir=target_dir,
            xor_key=xor_key,
            recursive=recursive,
            action=action,
        )


    def xor_process_msg(
            self,
            message: str,
            xor_key: str,
            action: str
    ) -> str:
        """XOR encrypts or decrypts a text string.

        For encryption: plaintext → XOR → Base64-encoded output
        For decryption: Base64-encoded input → XOR → plaintext

        Args:
            message: The text to process (plaintext for encrypt, Base64
                for decrypt).
            xor_key: The XOR key as a string.
            action: Either 'encrypt' or 'decrypt'.

        Returns:
            str: The processed result (Base64 string for encrypt, plaintext
                for decrypt).

        Raises:
            ValueError: If action is invalid or decryption fails (bad
                Base64/encoding).
        """
        action = action.lower().strip()

        if action not in ("encrypt", "decrypt"):
            raise ValueError(
                f"Invalid action '{action}'. Must be 'encrypt' or 'decrypt'."
            )

        try:
            if action == "encrypt":
                # Plaintext → UTF-8 bytes → XOR → Base64
                message_bytes = message.encode("utf-8")
                # Fast byte-level XOR processing
                processed_bytes = self._xor_bytes(message_bytes, xor_key)
                # Encode to Base64 for safe terminal display and transport
                processed_data = base64.b64encode(
                    processed_bytes).decode("ascii")
            else:
                # Base64 → decode → XOR → UTF-8 plaintext
                try:
                    decoded_bytes = base64.b64decode(message, validate=True)
                except (base64.binascii.Error, ValueError) as err:
                    raise ValueError(
                        "Input is not valid Base64 -- cannot decrypt."
                    ) from err

                processed_bytes = self._xor_bytes(decoded_bytes, xor_key)

                try:
                    processed_data = processed_bytes.decode("utf-8")
                except UnicodeDecodeError as err:
                    raise ValueError(
                        "Decryption produced invalid text → wrong key or "
                        f"corrupted data → {err}"
                    ) from err

        except ValueError:
            raise
        except Exception as err:
            self.ui.error(f"An error during {action}ion → {err}")
            raise RuntimeError(f"Error during {action}ion → {err}") from err

        save_output = self.ui.confirm(
            f"Do you want to save the {action}ed message to a file?"
        )

        if save_output:
            output_file_input = self.ui.prompt(
                "Enter the file path to save the message"
            )
            output_file = Path(output_file_input).resolve()

            try:
                output_file.parent.mkdir(parents=True, exist_ok=True)
                with open(
                    output_file,
                    "w",
                    encoding="utf-8",
                    newline="\n"
                ) as f:
                    f.write(processed_data)

                self.ui.success(
                    f"{action.capitalize()}ed message saved to → {output_file}"
                )

            except Exception as err:
                msg = (
                    f"Could not write processed message to {output_file} → "
                    f"{err}"
                )
                self.ui.error(msg)
                raise RuntimeError(msg) from err

        else:
            msg = (
                f"Action successful. [grey74]The {action}ed message is → "
                f"[bright_blue]'{processed_data}'"
            )
            self.ui.success(msg)
            logger.info(msg)
        return processed_data
