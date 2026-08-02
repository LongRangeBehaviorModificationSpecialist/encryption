# !/usr/bin/env python3
# DLU : 02-Aug-2026

import base64
from pathlib import Path
from rich.prompt import Prompt
from typing import List

from . import console
from resources.functions import (
    clear_screen,
    exit_application,
    get_file_path,
    get_folder_path
)
from resources.prompts import (
    show_main_app_menu,
    show_xor_encryption_menu
)


class XORClass:

    @staticmethod
    def get_xor_key_prompt() -> str:
        """Returns prompt for user input of the XOR key."""
        return Prompt.ask(
            "\n[bright_white][-] Enter the key you want to use for the XOR "
            "encryption ",
            password=True
            )


    @staticmethod
    def _xor_bytes(data: bytes, key: bytes) -> bytes:
        """Helper method to execute fast, byte-level XOR operations."""
        key_len = len(key)
        return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


    @staticmethod
    def xor_encrypt_msg(
            message: str,
            xor_key: str,
            output_file: Path | str = "encrypted_msg.txt"
    ) -> str:
        """XOR encrypts a text string, outputs Base64 representation, and
        saves raw bytes to disk.
        """
        if not message:
            raise ValueError("The message to encrypt cannot be empty.")
        if not xor_key:
            raise ValueError("The XOR encryption key cannot be empty.")

        message_bytes = message.encode("utf-8")
        key_bytes = xor_key.encode("utf-8")

        # Fast byte-level XOR processing
        encrypted_bytes = XORClass._xor_bytes(message_bytes, key_bytes)

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
            "[green][-] ** Action successful **\nThe Base64-encoded "
            f"encrypted message is:\n\t[bright_white]{b64_encoded_msg}\n\t"
            f"[dim]Raw encrypted bytes saved to : {out_path.resolve()}"
            )

        return b64_encoded_msg


    @staticmethod
    def xor_encrypt_single_file(
            target_file_path: Path | str,
            xor_key: bytes,
            full_dir: bool = False
    ) -> None:
        """XOR encrypts a file by reading/writing raw binary streams."""
        target_file_path = Path(target_file_path)

        if not xor_key:
            raise ValueError("XOR encryption key cannot be empty.")

        if not target_file_path.is_file():
            console.print(
                f"\n[bright_red][!] {target_file_path.name} does not exist or "
                "is a directory."
                )
            raise FileNotFoundError(
                f"Invalid target file: {target_file_path}"
                )

        if not full_dir:
            output_file_path = target_file_path.with_name(
                target_file_path.name + ".encrypted"
                )
        else:
            parent_dir_path = target_file_path.parents[1]
            current_dir_name = target_file_path.parent.stem
            encrypted_dir_path = parent_dir_path/ f"{current_dir_name}_encrypted"
            # Create directory if it doesn't exist
            encrypted_dir_path.mkdir(parents=True, exist_ok=True)
            output_file_path = encrypted_dir_path / (target_file_path.name + ".encrypted")


        # key_bytes = xor_key.encode("utf-8")
        key_bytes = xor_key

        try:
            console.print(
                "\n[bright_white][-] Reading file : [khaki3]"
                f"{target_file_path.name}"
                )
            plaintext = target_file_path.read_bytes()
            console.print(
                "[bright_white][-] File content read successfully"
                )

            console.print(
                f"[bright_white][-] Encrypting file data..."
                )

            encrypted_data = XORClass._xor_bytes(plaintext, key_bytes)

            output_file_path.write_bytes(encrypted_data)

            console.print(
                f"[green][*] Success : [khaki3]"
                f"{target_file_path.name} -> {output_file_path.name}"
                )

            return output_file_path

        except Exception as e:
            console.print(
                f"\n[bright_red][!] Failed to encrypt {target_file_path.name} "
                f": {e}"
                )


    @staticmethod
    def xor_encrypt_files_in_folder(
            target_dir_path: Path | str,
            xor_key: str
    ) -> dict[str: List[dict]]:
        """XOR encrypts all files within a directory by reading/writing raw
        binary streams.
        """
        results = {"success": [], "failed": [], "skipped": []}
        target_dir_path = Path(target_dir_path)

        if not target_dir_path.is_dir():
            console.print(
                f"\n[bright_red][!] {target_dir_path} does not exist or is "
                "not a valid directory."
                )
            # return []

        console.print(
            f"\n[green][*] {target_dir_path} validated. Fetching targets..."
            )

        try:
            all_files = [
                f for f in target_dir_path.rglob("*")
                if f.is_file() and f.suffix != ".encrypted"
                ]
        except Exception as e:
            console.print(
                "\n[bright_red][!] Failed to retrieve files from "
                f"{target_dir_path} : {e}"
                )
            # return []

        if not all_files:
            console.print(
                f"\n[yellow][!] No valid files to encrypt in {target_dir_path}"
                )
            # return []

        for file_path in all_files:
            try:
                encrypted_path = XORClass.xor_encrypt_single_file(
                    target_file_path=file_path,
                    xor_key=xor_key,
                    full_dir=True
                    )
                results['success'].append({
                    "original": str(file_path),
                    "encrypted": str(encrypted_path)
                    })
            except Exception as e:
                console.print(
                    f"[bright_red][!] Error encrypting {file_path.name} -> {e}"
                    )
                results['failed'].append({
                    "path": str(file_path),
                    "error": str(e)
                    })

        if results['success']:
            console.print(
                f"\n[green][*] Action Completed \nSuccessfully encrypted "
                f"{len(results['success'])} files in {target_dir_path} :"
                )
            encrypted_paths = [item['encrypted'] for item in results['success']]
            for path in encrypted_paths:
                console.print(
                    f"[green]    {str(path)}"
                    )

        if results['failed']:
            console.print(
                "\n[bright_red][!] ** Warning **\nFailed to encrypt "
                f"{len(results['failed'])} files :"
                )
            failed_paths = [item['path'] for item in results['failed']]
            for path in failed_paths:
                console.print(
                    f"[bright_red]    {path.name}"
                    )

        console.print(results)

        return results


    @staticmethod
    def get_xor_message_to_decrypt() -> str:
        return Prompt.ask(
            "\n[bright_white][-] Enter the message string you want to decrypt "
            )


    @staticmethod
    def get_xor_file_to_decrypt() -> Path:
        return Path(
            get_file_path(text="decrypted")
            )


    @staticmethod
    # def get_xor_encryption_choice(return_to_menu_callback=None) -> None:
    def get_xor_encryption_choice() -> None:
        """Main routing controller for encryption jobs."""
        while True:
            clear_screen()
            try:
                xor_encryption_choice = show_xor_encryption_menu()

                match xor_encryption_choice:
                    case "1":
                        message = Prompt.ask(
                            "\n[bright_white][-] Enter the message string you "
                            "want to XOR encrypt "
                            )
                        xor_key = XORClass.get_xor_key_prompt()
                        XORClass.xor_encrypt_msg(
                            xor_key=xor_key,
                            message=message
                            )
                    case "2":
                        target_file_path = get_file_path(
                            text="encrypted"
                            )
                        xor_key = XORClass.get_xor_key_prompt()
                        XORClass.xor_encrypt_single_file(
                            target_file_path=target_file_path,
                            xor_key=xor_key
                            )
                    case "3":
                        target_dir_path = get_folder_path(
                            text="encrypted"
                            )
                        xor_key = XORClass.get_xor_key_prompt()
                        XORClass.xor_encrypt_files_in_folder(
                            target_dir_path=target_dir_path,
                            xor_key=xor_key
                            )
                    case "r":
                        clear_screen()
                        show_main_app_menu()
                    case "q":
                        exit_application()

            except KeyboardInterrupt:
                console.print(
                    "\n[yellow][!] Operation cancelled by user."
                    )
                break

            except Exception as e:
                console.print(
                    f"\n[bright_red][!] An error occured when processing : {e}"
                    )
                Prompt.ask(
                    "\n[bright_white][-] Press Enter to continue..."
                    )




    @staticmethod
    def get_xor_decryption_choice() -> None:
        pass



"""
# --- NEW MENU PROMPT ---
        while True:
            choice = Prompt.ask(
                "\nPress [Enter] to return to main menu or [bold red]q[/bold red] to quit"
            ).strip().lower()

            if choice == "" or choice == "e":  # Enter or 'e' for enter
                console.print("\n[bright_yellow][i]Returning to main menu...[/i][/bright_yellow]")
                if return_to_menu_callback:
                    return_to_menu_callback()  # Call menu function
                return  # Exit encryption function, return to caller
            elif choice == "q":
                console.print("\n[bright_red][!] Quitting program...[/bright_red]")
                exit(0)
            else:
                console.print("[bright_red][!] Invalid input. Press Enter or q.[/bright_red]")
                continue

        # If using built-in input() instead of Rich Prompt:
        # choice = input("\nPress Enter to return to main menu or 'q' to quit: ").strip().lower()
        # if choice == "q":
        #     exit(0)
        # return

    except Exception as e:
        console.print(
            f"\n[bright_red][!] Failed to encrypt {target_file_path.name}: {e}"
            )
        raise


"""