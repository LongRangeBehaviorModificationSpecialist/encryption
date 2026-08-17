# !/usr/bin/env python3

import base64
from pathlib import Path
from rich.prompt import Prompt, Confirm
from typing import List

from . import console, install
from config.log_config import get_logger
from resources.vars import ENCRYPTED_EXT_LIST
from utils import Utils, UIHandlerProtocol, RichUIHandler


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
        self.ui = ui or RichUIHandler(get_time=Utils.get_time)
        self.default_chunk_size = default_chunk_size


    def get_xor_key(self) -> str:
        """Returns a UTF-8 encoded XOR key."""
        xor_key = Prompt.ask(
            f"[cyan][{Utils.get_time()}][grey66] Enter "
            "the key you want to use for the XOR operation",
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
        target_file = Utils.get_file_path()
        xor_key = self.get_xor_key()
        self.xor_process_file(
            target_file=target_file,
            xor_key=xor_key,
            action=action,
        )


    def _handle_xor_process_folder(self, action: str) -> None:
        target_dir = Utils.get_directory_path()
        xor_key = self.get_xor_key()
        recursive = Utils.select_recursive_option()
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
                        "corrupted data."
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
                "Enter the file path to save the results"
            )
            output_file = Path(output_file_input)

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
                    f"{action.capitalize()}ed message saved to → "
                    f"{output_file.resolve()}"
                )

            except Exception as err:
                msg = (
                    f"Could not write processed message to "
                    f"{output_file} → {err}"
                )
                self.ui.error(msg)
                raise RuntimeError(msg) from err

        else:
            self.ui.success(
                f"Action successful. [grey66]The {action}ed message is → "
                f"[blue]{processed_data}"
            )

        return processed_data


    def xor_process_file(
            self,
            target_file: Path | str,
            xor_key: bytes,
            action: str,
            output_path: Path | str | None = None,
            chunk_size: int | None = None,
    ) -> Path:
        """Encrypts or decrypts a file using XOR with a repeating key.

        Since XOR is symmetric, encryption and decryption use the same
        operation. Output naming is determined by the presence of .xor suffix.

        Args:
            target_file: Path to the file to process.
            xor_key: The XOR key as bytes.
            action: Either 'encrypt' or 'decrypt'.
            output_path: Custom output path. If None, derived from the input.
            chunk_size: Bytes to read/write per iteration (default: 64 KB).

        Returns:
            Path: Path to the resulting processed file.

        Raises:
            FileNotFoundError: If the target file does not exist.
            ValueError: If the key is empty.
        """

        # console.print(f"\n\nThe random XOR key is → {xor_key}\n\n")

        target_file = Path(target_file).resolve()

        if not target_file.is_file():
            Utils.print_not_file_error(target_file=target_file)
            raise FileNotFoundError(f"Invalid target file → {target_file}")

        if not Utils.verify_file_access(target_file=target_file):
            return

        if not xor_key:
            console.print(
                f"[cyan][{Utils.get_time()}][yellow] The XOR "
                "key must not be empty"
            )
            raise ValueError("XOR key must not be empty.")

        key_len = len(xor_key)
        chunk_size = chunk_size or self.default_chunk_size

        # --- Determine output path ---
        if output_path:
            output_file = Path(output_path).resolve()
        elif target_file.suffix.lower() == ".xor":
            # File looks encrypted → decrypt → strip .xor
            output_file = target_file.with_suffix("")
        else:
            # File looks unencrypted → encrypt → add .xor
            output_file = target_file.with_name(f"{target_file.name}.xor")

        try:
            file_size = target_file.stat().st_size
            console.print(
                f"[cyan][{Utils.get_time()}][grey66] Processing file → "
                f"[blue]{target_file.name} ({file_size:,} bytes)..."
            )

            bytes_processed = 0

            with open(target_file, "rb") as fin, open(output_file, "wb") as fout:
                while True:
                    chunk = fin.read(chunk_size)
                    if not chunk:
                        break

                    offset = bytes_processed % key_len
        # return bytes(b ^ key[i % key_len] for i, b in enumerate(data))
                    xor_result = bytes(
                        byte ^ xor_key[(offset + i) % key_len]
                        for i, byte in enumerate(chunk)
                    )

                    fout.write(xor_result)
                    bytes_processed += len(chunk)

                    progress = (bytes_processed / file_size) * 100
                    console.print(
                        f"[cyan][{Utils.get_time()}][grey66] Progress: "
                        f"{progress:.1f}%",
                        end=""
                    )
            console.print(
                f"[cyan][{Utils.get_time()}][green] Processed "
                f"{target_file.name}  →  {output_file.name}"
            )

            return output_file

        except Exception as e:
            # Clean up partial output on failure
            if output_file.exists():
                output_file.unlink(missing_ok=True)
            console.print(
                f"[cyan][{Utils.get_time()}][red] Failed to process "
                f"{target_file.name} → {e}")
            raise RuntimeError(
                f"Failed to process {target_file.name} → {e}"
            ) from e


    def xor_process_folder(
            self,
            target_dir: Path | str,
            xor_key: bytes | str,
            recursive: bool = False,
            chunk_size: int | None = None,
    ) -> List[Path]:
        """Processes all files in a directory using XOR.

        Encryption and decryption use the same operation. Files with .xor
        suffix are automatically detected and stripped during decryption.

        Args:
            target_dir: Path to the directory containing files.
            xor_key: The XOR key as bytes.
            recursive: Traverse subdirectories if True.
            chunk_size: Bytes to read/write per iteration (for handling
                large files).

        Returns:
            List[Path]: List of successfully processed file paths.

        Raises:
            FileNotFoundError: If target directory does not exist.
            ValueError: If the action is invalid.
        """
        target_dir = Path(target_dir).resolve()

        if not Utils.verify_is_directory(target_dir=target_dir):
            return

        console.print(
            f"[cyan][{Utils.get_time()}][green] {target_dir} validated. "
            "Fetching files to process..."
        )

        try:
            # Build file iterator based on recursion flag
            files_iterator = (
                target_dir.rglob("*") if recursive else target_dir.iterdir()
            )

            all_files = [
                f for f in files_iterator
                if f.is_file()
                and f.suffix not in ENCRYPTED_EXT_LIST
            ]

        except Exception as e:
            console.print(
                f"[cyan][{Utils.get_time()}][red] Failed to "
                f"retrieve files from {target_dir} → {e}"
            )
            return []

        if not all_files:
            console.print(
                f"[cyan][{Utils.get_time()}][yellow] No valid "
                f"files to encrypt in {target_dir}"
            )
            return []

        successful_files: List[Path] = []
        failed_files: List[Path] = []
        total_files = len(all_files)


        for idx, file_path in enumerate(all_files, start=1):
            # Progress indicator
            progress_bar = f"{idx}/{total_files} [{idx/total_files*100:.0f}%]"
            console.print(
                f"[cyan][{Utils.get_time()}][grey66] "
                f"[{progress_bar}] "
                f"Processing: {file_path.name}...",
                end=""
            )

            try:
                result_path = self.xor_process_file(
                    target_file=file_path,
                    xor_key=xor_key,
                    chunk_size=chunk_size,
                )
                successful_files.append(result_path)

            except Exception as e:
                console.print(
                    f"[cyan][{Utils.get_time()}][red] Error during "
                    f"processing {file_path.name} → {e}"
                )
                failed_files.append(file_path)

        # Summary reporting
        console.print("\n" + "-" * 35)

        if successful_files:
            console.print(
                f"[cyan][{Utils.get_time()}][green] Action Completed. "
                f"[grey66]Successfully processed {len(successful_files)} "
                f"files in {target_dir}:"
            )
            for file in successful_files:
                console.print(f"[green]  {file.name}")

        if failed_files:
            console.print(
                f"[cyan][{Utils.get_time()}][red] Warning: "
                f"Failed to process {len(failed_files)} files:"
            )
            for file in failed_files:
                console.print(f"[red]  {file.name}")

        return successful_files
