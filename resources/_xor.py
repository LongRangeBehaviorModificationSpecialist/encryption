# !/usr/bin/env python3
# DLU : 04-Aug-2026


import base64
from enum import StrEnum
from pathlib import Path
from rich.prompt import Prompt
from typing import List

from . import console
from resources.vars import ENCRYPTED_EXT_LIST
from resources.functions import Functions
from resources.prompts import (
    show_main_menu,
    show_xor_menu
)


class Action(StrEnum):
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"


class XOR:

    _ACTION_MAP = {
        "1": (Action.ENCRYPT, "message"),
        "2": (Action.DECRYPT, "message"),
        "3": (Action.ENCRYPT, "single"),
        "4": (Action.DECRYPT, "single"),
        "5": (Action.ENCRYPT, "folder"),
        "6": (Action.DECRYPT, "folder")
    }


    def get_xor_key_prompt(self) -> str:
        """Returns prompt for user input of the XOR key."""
        return Prompt.ask(
            "\n[bright_white][-] Enter the key you want to use for the XOR "
            "operation ",
            password=True
        )


    def _xor_bytes(self, data: bytes, key: bytes) -> bytes:
        """Helper method to execute fast, byte-level XOR operations."""
        key_len = len(key)
        return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


    def _handle_xor_process_msg(self, action: Action) -> None:
        message = Prompt.ask(
            "\n[bright_white][-] Enter the message string you "
            "want to process with XOR ")
        xor_key = self.get_xor_key_prompt()
        self.xor_process_msg(
            xor_key=xor_key,
            message=message,
            action=action.value,
        )


    def xor_process_msg(
            self,
            message: str,
            xor_key: str,
            action: str,
            output_file: Path | str = "encrypted_msg.txt"
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
                "[green][-] ** Action successful **\nThe Base64-encoded "
                f"processed message is:\n\t[bright_white]{processed_data}\n\t"
                f"[dim]Raw encrypted bytes saved to : {output_file.resolve()}"
            )

            return output_file

        except Exception as e:
            console.print(
                f"Could not write encrypted message to {output_file} : {e}"
            )


    def xor_process_file(
            self,
            target_file: Path | str,
            xor_key: bytes,
            full_dir: bool = False
    ) -> None:
        """XOR encrypts a file by reading/writing raw binary streams."""
        target_file = Path(target_file)

        if not xor_key:
            raise ValueError("XOR encryption key cannot be empty.")

        if not target_file.is_file():
            console.print(
                f"\n[bright_red][!] {target_file.name} does not exist or "
                "is a directory.")
            raise FileNotFoundError(
                f"Invalid target file: {target_file}")

        if not full_dir:
            output_file_path = target_file.with_name(
                target_file.name + ".encrypted")
        else:
            parent_dir_path = target_file.parents[1]
            current_dir_name = target_file.parent.stem
            encrypted_dir_path = parent_dir_path/ f"{current_dir_name}_encrypted"
            # Create directory if it doesn't exist
            encrypted_dir_path.mkdir(parents=True, exist_ok=True)
            output_file_path = encrypted_dir_path / (target_file.name + ".encrypted")


        # key_bytes = xor_key.encode("utf-8")
        key_bytes = xor_key

        try:
            console.print(
                "\n[bright_white][-] Reading file : [khaki3]"
                f"{target_file.name}")

            plaintext = target_file.read_bytes()
            console.print(
                "[bright_white][-] File content read successfully")

            console.print(
                f"[bright_white][-] Encrypting file data...")

            encrypted_data = XOR._xor_bytes(plaintext, key_bytes)

            output_file_path.write_bytes(encrypted_data)

            console.print(
                f"[green][*] Success : [khaki3]"
                f"{target_file.name} -> {output_file_path.name}")

            return output_file_path

        except Exception as e:
            console.print(
                f"\n[bright_red][!] Failed to encrypt {target_file.name} "
                f": {e}")


    def xor_process_folder(
            self,
            target_dir: Path | str,
            xor_key: str,
            action: str
    ) -> List[Path]:
        """XOR encrypts all files within a directory by reading/writing raw
        binary streams.
        """
        results = {"success": [], "failed": [], "skipped": []}
        target_dir = Path(target_dir).resolve()

        if not Functions.verify_is_directory(target_dir=target_dir):
            console.print(
                f"{target_dir} does not exist or is not a valid directory"
            )
            return

        console.print(
            f"\n[green][*] {target_dir} validated. Fetching targets..."
        )

        try:
            all_files = [
                f for f in target_dir.rglob("*")
                if f.is_file() and f.suffix != ".encrypted"
            ]
        except Exception as e:
            console.print(
                "\n[bright_red][!] Failed to retrieve files from "
                f"{target_dir} : {e}"
            )
            return

        if not all_files:
            console.print(
                f"\n[yellow][!] No valid files to encrypt in {target_dir}"
            )
            return

        for file_path in all_files:
            try:
                encrypted_path = XOR.xor_process_file(
                    target_file=file_path,
                    xor_key=xor_key,
                    full_dir=True)
                results['success'].append({
                    "original": str(file_path),
                    "encrypted": str(encrypted_path)}
                )
            except Exception as e:
                console.print(
                    f"[bright_red][!] Error encrypting {file_path.name} -> {e}"
                )
                results['failed'].append({
                    "path": str(file_path),
                    "error": str(e)}
                )

        if results['success']:
            console.print(
                f"\n[green][*] Action Completed \nSuccessfully {action}ed "
                f"{len(results['success'])} files in {target_dir} :"
            )
            encrypted_paths = [
                item['path'] for item in results['success']
            ]
            for path in encrypted_paths:
                console.print(
                    f"[green]  {str(path)}")

        if results['failed']:
            console.print(
                "\n[bright_red][!] ** Warning **\nFailed to encrypt "
                f"{len(results['failed'])} files :"
            )
            failed_paths = [
                item['path'] for item in results['failed']
            ]
            for path in failed_paths:
                console.print(f"[bright_red]  {str(path)}")

        console.print(results)

        return results


    def get_xor_message_to_decrypt(self) -> str:
        return Prompt.ask(
            "\n[bright_white][-] Enter the message string you want to decrypt "
        )


    def get_xor_file_to_decrypt(self) -> Path:
        return Path(
            Functions.get_file_path()
        )


    def get_xor_action(self, action: str) -> None:
        """Gets input from the user on what action to start next."""
        xor_choice = show_xor_menu()
        match xor_choice:
            case "1" | "2" | "3" | "4" | "5" | "6":
                action, scope = self._ACTION_MAP[xor_choice]
                if scope == "message":
                    self._handle_xor_process_msg(action)
                elif scope == "single":
                    self._handle_xor_process_file(action)
                else:
                    self._handle_xor_process_folder(action)
            case "r":
                show_main_menu()
            case "q":
                Functions.exit_application()








        while True:
            Functions.clear_screen()
            try:
                action = action.lower().strip()

                if action == "encrypt":
                    xor_encryption_choice = show_xor_encryption_menu()
                    match xor_encryption_choice:
                        case "1":
                            message = Prompt.ask(
                                "\n[bright_white][-] Enter the message string you "
                                "want to XOR encrypt ")
                            xor_key = XOR.get_xor_key_prompt()
                            XOR.xor_encrypt_msg(
                                xor_key=xor_key,
                                message=message)
                        case "2":
                            target_file = Functions.get_file_path(
                                text="encrypted")
                            xor_key = XOR.get_xor_key_prompt()
                            XOR.xor_process_file(
                                target_file=target_file,
                                xor_key=xor_key)
                        case "3":
                            target_dir = Functions.get_directory_path(
                                text="encrypted")
                            xor_key = XOR.get_xor_key_prompt()
                            XOR.xor_process_folder(
                                target_dir=target_dir,
                                xor_key=xor_key)


                elif action == "decrypt":
                    xor_decryption_choice = show_xor_decryption_menu()
                    match xor_decryption_choice:
                        case "1":
                            pass
                        case "2":
                            pass
                        case "3":
                            pass
                        case "r":
                            Functions.clear_screen()
                            show_main_app_menu()
                        case "q":
                            Functions.exit_application()

            except KeyboardInterrupt:
                console.print(
                    "\n[yellow][!] Operation cancelled by user.")
                break

            except Exception as e:
                console.print(
                    f"\n[bright_red][!] An error occured when processing : {e}")
                Prompt.ask(
                    "\n[bright_white][-] Press Enter to continue...")
