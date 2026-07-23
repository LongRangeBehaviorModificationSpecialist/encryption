# !/usr/bin/env python3
# DLU : 23-Jul-2026

from pathlib import Path
import base64
import logging
from pathlib import Path
from typing import Union

from rich.console import Console

from resources.functions import Functions


# Make the console object
c = Console()


class XORDecryptor:


    def __init__(self, app_instance):
        """Store a reference to the main app loop controller."""
        self.app = app_instance


    @staticmethod
    def _xor_bytes(data: bytes, key: bytes) -> bytes:
        """Helper method to perform fast, byte-level XOR operations."""
        key_len = len(key)
        return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


    def decrypt_msg_with_xor(self, message: str, xor_key: str) -> str:
        """Decrypts a Base64-encoded XOR message back into plain text."""

        logger = logging.getLogger(__name__)

        # Input validations
        if not message or not message.strip():
            raise ValueError("Message to decrypt cannot be empty.")
        if not xor_key:
            raise ValueError("XOR key cannot be empty.")

        try:
            # Decode Base64 string back into raw encrypted bytes
            encrypted_bytes = base64.b64decode(message.strip())
            key_bytes = xor_key.encode("utf-8")

            # 2. XOR Decryption
            decrypted_bytes = self._xor_bytes(encrypted_bytes, key_bytes)
            decrypted_text = decrypted_bytes.decode("utf-8")

        except base64.binascii.Error as e:
            logger.error(
                f"Invalid Base64 string supplied for decryption: {e}"
            )
            raise ValueError("Invalid Base64-encoded message input.") from e
        except UnicodeDecodeError as e:
            logger.error(
                f"Failed to decode decrypted bytes to UTF-8: {e}",
                exc_info=True
            )
            raise ValueError(
                "Decryption failed or incorrect key provided (invalid output \
encoding)."
            ) from e

        c.print(
            f"""[green3]
[-] ** Action successful **\n
The original message is:
    [bright_white]{decrypted_text}"""
        )

        return decrypted_text


    def decrypt_file_with_xor(
        self, file_path: Union[str, Path], xor_key: str
    ) -> Path:
        """Decrypts an XOR-encrypted file safely using binary path operations."""

        logger = logging.getLogger(__name__)

        target_path = Path(file_path)

        # Path & Key Validation
        if not xor_key:
            raise ValueError("XOR key cannot be empty.")
        if not target_path.exists():
            raise FileNotFoundError(f"Target file not found: {target_path}")
        if not target_path.is_file():
            raise IsADirectoryError(
                f"Provided path is a directory, not a file: {target_path}"
            )

        # Determine output path (e.g., "data.txt.encrypted" -> "data.txt")
        # `.with_suffix("")` strips away the LAST extension (.encrypted)
        if target_path.suffix == ".encrypted":
            destination_path = target_path.with_suffix("")
        else:
            destination_path = target_path.with_suffix(
                target_path.suffix + ".decrypted"
            )

        key_bytes = xor_key.encode("utf-8")

        # Read and write raw bytes via pathlib convenience methods
        try:
            encrypted_bytes = target_path.read_bytes()
            decrypted_bytes = self._xor_bytes(encrypted_bytes, key_bytes)

            destination_path.write_bytes(decrypted_bytes)

        except Exception as e:
            logger.error(
                f"Failed XOR file decryption on {target_path}: {e}",
                exc_info=True,
            )
            if destination_path.exists():
                destination_path.unlink(missing_ok=True)
            raise RuntimeError(
                f"Error decrypting file '{target_path.name}': {e}"
            ) from e

        c.print(
            f"""[green3]
[-] ** Action successful ** File Decrypted with XOR key.
[bright_white][-] Output saved to: {destination_path.name}"""
        )

        return destination_path
