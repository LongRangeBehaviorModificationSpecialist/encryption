# !/usr/bin/env python3
# DLU : 05-Aug-2026


import base64
from enum import StrEnum
from pathlib import Path
from rich.prompt import Prompt
from typing import List

from . import console
from resources.vars import ENCRYPTED_EXT_LIST, STATUS_ICONS
from resources.functions import Functions
from resources.prompts import (
    show_main_menu,
    show_xor_menu
)


class Action(StrEnum):
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"


class XOR:

    """XOR-based file encryption/decryption class.

    Provides single-file and directory-wide processing with automatic
    output naming based on file suffix detection (.xor = encrypted).
    """

    # Class-level constant for menu routing
    _XOR_ACTION_MAP = {
        "1": "message",
        "2": "message",
        "3": "file",
        "4": "file",
        "5": "folder",
        "6": "folder"
    }

    def __init__(self, default_chunk_size: int = 64 * 1024):
        """Initialize the XOR processor.

        Args:
            default_chunk_size: Bytes to read/write per iteration for large file handling.
        """
        self.default_chunk_size = default_chunk_size


    def get_xor_key(self) -> str:
        """Returns a UTF-8 encoded XOR key."""
        xor_key = Prompt.ask(
            f"{STATUS_ICONS['info']}[white] Enter the key you want to use for "
            "the XOR operation ",
            password=True
        )
        return xor_key.encode("utf-8")


    def _xor_bytes(self, data: bytes, key: bytes) -> bytes:
        """Helper method to execute fast, byte-level XOR operations."""
        key_len = len(key)
        return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


    def _handle_xor_process_msg(self) -> None:
        message = Prompt.ask(
            f"{STATUS_ICONS['info']}[white] Enter the message you want to "
            "process with XOR "
        )
        xor_key = self.get_xor_key()
        self.xor_process_msg(
            xor_key=xor_key,
            message=message,
        )


    def xor_process_msg(
            self,
            message: str,
            xor_key: str,
            action: str,
            output_file: Path | str = "processed_msg.txt",
    ) -> str:
        """XOR encrypts or decrypts a text string, outputs Base64
        representation, and saves raw bytes to disk.
        """
        if not message:
            raise ValueError("The message to process cannot be empty.")
        if not xor_key:
            raise ValueError("The XOR key cannot be empty.")

        # Write raw encrypted bytes safely
        output_file = Path(output_file)

        if action == "encrypt":
            message_bytes = message.encode("utf-8")
            key_bytes = xor_key.encode("utf-8")

            # Fast byte-level XOR processing
            encrypted_bytes = XOR._xor_bytes(message_bytes, key_bytes)

            # Encode to Base64 for safe terminal display and transport
            processed_data = base64.b64encode(encrypted_bytes).decode("ascii")
        else:
            # Decode Base64 string back into raw encrypted bytes
            encrypted_bytes = base64.b64decode(message.strip())
            key_bytes = xor_key.encode("utf-8")

            # 2. XOR Decryption
            decrypted_bytes = self._xor_bytes(encrypted_bytes, key_bytes)
            processed_data = decrypted_bytes.decode("utf-8")

        try:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, "wb") as f:
                f.write(processed_data)

            console.print(
                "[green3][*] Action successful\nThe Base64-encoded "
                f"processed message is:\n  [white]{processed_data}\n  "
                f"[dim]Raw encrypted bytes saved to : {output_file.resolve()}"
            )

            return output_file

        except Exception as e:
            console.print(
                "[red][!] Could not write encrypted message to "
                f"{output_file} : {e}"
            )


    def _handle_xor_process_file(self) -> None:
        target_file = Functions.get_file_path()
        xor_key = self.get_xor_key()
        self.xor_process_file(
            target_file=target_file,
            xor_key=xor_key,
        )


    def xor_process_file(
            self,
            target_file: Path | str,
            xor_key: bytes,
            output_path: Path | str | None = None,
            chunk_size: int | None = None,
    ) -> Path:
        """Encrypts or decrypts a file using XOR with a repeating key.

        Since XOR is symmetric, encryption and decryption use the same
        operation. Output naming is determined by the presence of .xor suffix.

        Args:
            target_file: Path to the file to process.
            xor_key: The XOR key as bytes.
            output_path: Custom output path. If None, derived from the input.
            chunk_size: Bytes to read/write per iteration (default: 64 KB).

        Returns:
            Path: Path to the resulting processed file.

        Raises:
            FileNotFoundError: If the target file does not exist.
            ValueError: If the key is empty.
        """
        target_file = Path(target_file).resolve()

        if not target_file.is_file():
            console.print(
                f"[red]✗ {target_file.name} does not exist or is a "
                "directory."
            )
            raise FileNotFoundError(f"Invalid target file : {target_file}")

        if not xor_key:
            console.print("The XOR key must not be empty.")
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
                f"[white][-] Processing file : {target_file.name} "
                f"({file_size:,} bytes)..."
            )

            bytes_processed = 0

            with open(target_file, "rb") as fin, open(output_file, "wb") as fout:
                while True:
                    chunk = fin.read(chunk_size)
                    if not chunk:
                        break

                    offset =bytes_processed % key_len
                    xor_result = bytes(
                        byte ^ xor_key[(offset + i) % key_len]
                        for i, byte in enumerate(chunk)
                    )

                    fout.write(xor_result)
                    bytes_processed += len(chunk)

                    progress = (bytes_processed / file_size) * 100
                    console.print(
                        f"[white][-] Progress : {progress:.1f}%",
                        end=""
                    )
            console.print(
                f"\n[green3][*] Processed {target_file.name:34s}{'->':7s}"
                f"{output_file.name}"
            )

            return output_file

        except Exception as e:
            # Clean up partial output on failure
            if output_file.exists():
                output_file.unlink(missing_ok=True)
            console.print(
                f"[red][!] Failed to process {target_file.name} : {e}")
            raise


    def _handle_xor_process_folder(self) -> None:
        target_dir = Functions.get_directory_path()
        xor_key = self.get_xor_key()
        recursive = Functions.select_recursive_option()
        self.xor_process_folder(
            target_dir=target_dir,
            xor_key=xor_key,
            recursive=recursive,

        )

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

        if not Functions.verify_is_directory(target_dir=target_dir):
            console.print(
                f"[red]✗ {target_dir} does not exist or is not a "
                "valid directory"
            )
            return

        console.print(
            f"[green3]✓ {target_dir} validated. Fetching files to process..."
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
                f"[red]✗ Failed to retrieve files from {target_dir} : {e}"
            )
            return []

        if not all_files:
            console.print(
                f"[yellow3]⚠️ No valid files to encrypt in {target_dir}"
            )
            return []

        successful_files: List[Path] = []
        failed_files: List[Path] = []
        total_files = len(all_files)


        for idx, file_path in enumerate(all_files, start=1):
            # Progress indicator
            progress_bar = f"{idx}/{total_files} [{idx/total_files*100:.0f}%]"
            console.print(
                f"[cyan][{progress_bar}] Processing: {file_path.name}...",
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
                    f"[red]✗ Error during processing {file_path.name} : {e}"
                )
                failed_files.append(file_path)

        # Summary reporting
        console.print("\n" + "-" * 35)

        if successful_files:
            console.print(
                f"[green3]✓ Action Completed\n"
                f"[green3] Successfully processed {len(successful_files)} "
                f"files in {target_dir}:"
            )
            for file in successful_files:
                console.print(f"[green]  {file.name}")

        if failed_files:
            console.print(
                f"[red][!] ** Warning **"
                f"[red]Failed to process {len(failed_files)} files:"
            )
            for file in failed_files:
                console.print(f"[red]  {file.name}")

        return successful_files


    @classmethod
    def get_xor_action(cls) -> None:
        """Gets input from the user on what action to start next."""
        xor_choice = show_xor_menu()
        match xor_choice:
            case "1" | "2" | "3" | "4" | "5" | "6":
                scope = cls._XOR_ACTION_MAP[xor_choice]
                if scope == "message":
                    cls._handle_xor_process_msg(XOR)
                elif scope == "file":
                    cls._handle_xor_process_file(XOR)
                else:
                    cls._handle_xor_process_folder(XOR)
            case "r":
                Functions.clear_screen()
                show_main_menu()
            case "q":
                Functions.exit_application()
            case _:
                console.print("[yellow3]⚠️ An invalid option was entered")
