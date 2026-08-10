# !/usr/bin/env python3

import base64
from pathlib import Path
from rich.prompt import Prompt
from rich.traceback import install
from typing import List

from . import c
from resources.vars import ENCRYPTED_EXT_LIST
from resources.utils import Utils


install(show_locals=True, console=c)


class XOR:

    """XOR-based file encryption/decryption class.

    Provides single-file and directory-wide processing with automatic
    output naming based on file suffix detection (.xor = encrypted).
    """

    def __init__(self, default_chunk_size: int = 64 * 1024):
        """Initialize the XOR processor.

        Args:
            default_chunk_size: Bytes to read/write per iteration for large
            file handling.
        """
        self.default_chunk_size = default_chunk_size


    def get_xor_key(self) -> str:
        """Returns a UTF-8 encoded XOR key."""
        xor_key = Prompt.ask(
            f"[cyan][{Utils.get_current_time()}][white] Enter "
            "the key you want to use for the XOR operation",
            password=True
        )
        return xor_key.encode("utf-8")


    def _xor_bytes(self, data: bytes, key: bytes) -> bytes:
        """Helper method to execute fast, byte-level XOR operations."""
        key_len = len(key)
        return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


    def _handle_xor_process_msg(self, action: str) -> None:
        message = Prompt.ask(
            f"\n[cyan][{Utils.get_current_time()}][white] Enter "
            "the message you want to XOR"
        )

        if not message:
            c.print(
                f"[cyan][{Utils.get_current_time()}][yellow3] The "
                "message to process cannot be empty"
            )
            raise ValueError("The message cannot be empty.")

        xor_key = self.get_xor_key()

        if not xor_key:
            c.print(
                f"[cyan][{Utils.get_current_time()}][yellow3] The "
                "XOR key cannot be empty"
            )
            raise ValueError("The XOR key cannot be empty.")

        self.xor_process_msg(xor_key=xor_key,
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
                except (base64.binascii.Error, ValueError) as e:
                    raise ValueError(
                        "Input is not valid Base64 -- cannot decrypt."
                    ) from e

                processed_bytes = self._xor_bytes(decoded_bytes, xor_key)

                try:
                    processed_data = processed_bytes.decode("utf-8")
                except UnicodeDecodeError as e:
                    raise ValueError(
                        "Decryption produced invalid text - wrong key or "
                        "corrupted data."
                    ) from e

        except ValueError:
            raise
        except Exception as e:
            c.print(
                f"[cyan][{Utils.get_current_time()}][red1] Error "
                f"during {action}ion -> {e}"
            )
            raise

        save_output = Prompt.ask(
            f"[cyan][{Utils.get_current_time()}][white] Do you "
            f"want to save the {action}ed message to a file?",
            choices=["y", "n"],
            show_choices=True
        )

        if save_output == "y":
            output_file_input = Prompt.ask(
                f"[cyan][{Utils.get_current_time()}][white] Enter "
                "the file path to save the results"
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

                c.print(
                    f"[cyan][{Utils.get_current_time()}][green3] "
                    f"{action.capitalize()}ed message saved to -> "
                    f"{output_file.resolve()}"
                )

            except Exception as e:
                c.print(
                    f"[cyan][{Utils.get_current_time()}][red1] "
                    f"Could not write processed message to {output_file} "
                    f"-> {e}"
                )

        else:
            c.print(
                f"\n[cyan][{Utils.get_current_time()}][green3] "
                f"Action Successful\n"
                f"\nThe {action}ed message is:\n"
                f"\n    [white]{processed_data}\n"
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

        c.print(f"\n\nThe random XOR key is -> {xor_key}\n\n")

        target_file = Path(target_file).resolve()

        if not target_file.is_file():
            Utils.print_not_file_error(target_file=target_file)
            raise FileNotFoundError(f"Invalid target file : {target_file}")

        if not Utils.verify_file_access(target_file=target_file):
            return

        if not xor_key:
            c.print(
                f"[cyan][{Utils.get_current_time()}][yellow3] The XOR key must not be empty"
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
            c.print(
                f"[cyan][{Utils.get_current_time()}][white] Processing file -> "
                f"{target_file.name} ({file_size:,} bytes)..."
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
                    c.print(
                        f"[cyan][{Utils.get_current_time()}][white] Progress : "
                        f"{progress:.1f}%",
                        end=""
                    )
            c.print(
                f"\n[cyan][{Utils.get_current_time()}][green3] Processed "
                f"{target_file.name}  ->'  {output_file.name}"
            )

            return output_file

        except Exception as e:
            # Clean up partial output on failure
            if output_file.exists():
                output_file.unlink(missing_ok=True)
            c.print(
                f"[cyan][{Utils.get_current_time()}][red1] Failed to process "
                f"{target_file.name} : {e}")
            raise


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

        c.print(
            f"[cyan][{Utils.get_current_time()}][green3] {target_dir} validated. "
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
            c.print(
                f"[cyan][{Utils.get_current_time()}][red1] Failed to retrieve files "
                f"from {target_dir} : {e}"
            )
            return []

        if not all_files:
            c.print(
                f"[cyan][{Utils.get_current_time()}][yellow3] No valid files to encrypt "
                f"in {target_dir}"
            )
            return []

        successful_files: List[Path] = []
        failed_files: List[Path] = []
        total_files = len(all_files)


        for idx, file_path in enumerate(all_files, start=1):
            # Progress indicator
            progress_bar = f"{idx}/{total_files} [{idx/total_files*100:.0f}%]"
            c.print(
                f"[dim][cyan][{Utils.get_current_time()}][/di][white] "
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
                c.print(
                    f"[cyan][{Utils.get_current_time()}][red1] Error during processing "
                    f"{file_path.name} : {e}"
                )
                failed_files.append(file_path)

        # Summary reporting
        c.print("\n" + "-" * 35)

        if successful_files:
            c.print(
                f"[cyan][{Utils.get_current_time()}][green3] Action Completed\n"
                f"Successfully processed {len(successful_files)} files in "
                f"{target_dir}:"
            )
            for file in successful_files:
                c.print(f"[green]  {file.name}")

        if failed_files:
            c.print(
                f"[cyan][{Utils.get_current_time()}][red1] Warning:\n"
                f"Failed to process {len(failed_files)} files :"
            )
            for file in failed_files:
                c.print(f"[red1]  {file.name}")

        return successful_files
