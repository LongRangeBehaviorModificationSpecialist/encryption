# !/usr/bin/env python3
# DLU : 30-Jul-2026

from datetime import datetime
from functools import wraps
import getpass
import os
from pathlib import Path
import re
from rich.prompt import Prompt
import subprocess
import sys
import time

# Import the console object from the main __init__.py file
from . import console


class Functions:


    def timeit(func):
        @wraps(func)
        def timeit_wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            result = func(*args, **kwargs)
            end_time = time.perf_counter()
            total_time = end_time - start_time
            console.print(f"[dodger_blue1][-] Operation [ {func.__name__}() ] was completed in {total_time:.4f} seconds")
            # console.print(f"\nFunction {func.__name__}{args} {kwargs} Took {total_time:.4f} seconds")
            return result
        return timeit_wrapper


    @staticmethod
    def clear_screen() -> None:
        command = "cls" if os.name == "nt" else "clear"
        subprocess.run(command, shell=True)


    @staticmethod
    def exit_application() -> None:
        console.print(
            "[green3][!] Exiting the application. Goodbye..."
            )
        sys.exit(0)


    @staticmethod
    def get_date_time() -> str:
        local_time = datetime.now().astimezone()
        offset = local_time.strftime("%z")
        formatted_offset = f"UTC{offset[0]}{int(offset[1:3])}"
        current_time = local_time.strftime(
            f"%d-%b-%Y %H:%M:%S.%f ({formatted_offset})"
            )
        return current_time


    @staticmethod
    def get_email_address() -> str:
        return Prompt.ask(
            "[bright_white][-] Enter email address of the PGP key owner "
            ).strip().lower()


    @staticmethod
    def get_file_path(text: str) -> Path:
        return Path(Prompt.ask(
            f"[bright_white][-] Enter the path of the file to be {text} ")
            )


    @staticmethod
    def get_folder_path(text: str) -> Path:
        return Path(
            Prompt.ask(
                f"[bright_white][-] Path of the directory containing the "
                f"files to be {text} ")
                )


    @staticmethod
    def select_recursive_option(default: bool = True) -> bool:
        """Prompts the user for a yes/no answer and returns a boolean."""
        while True:
            recursive_input =Prompt.ask(
                "[bright_white]Encrypt subdirectories recursively? ",
                choices=["y", "n"],
                show_choices=True
                ).strip().lower()
            match recursive_input:
                case "y":
                    return True
                case "n":
                    return False
            console.print(
                "[bright_red][!] Invalid input.  Enter either 'y' or 'n'."
                )


    @staticmethod
    def get_password() -> bytearray:
        """Prompts the user for a password until they provide one that
        passes strength validation, returning a mutable bytearray.
        """
        while True:
            # Prompt user and convert directly to a mutable bytearray
            raw_password = getpass.getpass(
                "Enter the PASSWORD you want to use : "
                ).encode("utf-8")
            password_bytes = bytearray(raw_password)

            # If the password passes validation, break the loop and return it
            if Functions.validate_password(password_bytes):
                return password_bytes

            # If invalid, clear memory of the attempt before prompting again
            for i in range(len(password_bytes)):
                password_bytes[i] = 0

            console.print(
                "[bright_red][!] Not a valid password. Please try again."
            )


    @staticmethod
    def validate_password(password: bytearray|bytes|str) -> bool:
        """Validates if a password meets the strength requirements.

        Args:
            password: The password to validate as a bytearray, bytes, or str.

        Returns:
            True if valid, False otherwise.
        """
        # Byte-level symbol definitions
        symbols_bytes = b"!@#%&*()?<>-+=[]~^|"

        # Convert string to bytes if passed as string,
        # preserving bytearray if provided
        if isinstance(password, str):
            pwd_bytes = password.encode("utf-8")
        else:
            pwd_bytes = password

        # Perform byte-compatible validation checks
        has_min_length = len(pwd_bytes) >= 10

        # Use byte-compiled regex (prefix patterns with b"...")
        has_digit = re.search(rb"\d", pwd_bytes) is not None
        has_upper = re.search(rb"[A-Z]", pwd_bytes) is not None
        has_lower = re.search(rb"[a-z]", pwd_bytes) is not None

        # Check if any byte in pwd_bytes exists in our byte symbols set
        has_symbol = any(
            byte_char in symbols_bytes for byte_char in pwd_bytes
            )

        # If the criteria are not satisfied, print message to screen
        if not (has_min_length
                and has_digit
                and has_upper
                and has_lower
                and has_symbol):
            console.print("""[bright_red]
Your password did not meet the minimun requirements. Please try again.\n
Your password must meet the following criteria :\n
    [-] Is at least ten (10) characters long
    [-] Contain at least one number
    [-] Contain at least one capital letter
    [-] Contain at least one lowercase letter and
    [-] Contain at least one of the following symbols :
        ! @ # % & * ( ) ? < > - + = [ ] ~ ^ |""")
            return False
        else:
            console.print(
                f"[bright_white][-] Your password meets the minimum "
                "requirements. Continuing..."
                )
            return True


    @staticmethod
    def print_confirm_file_action(file_name: Path | str, text: str) -> str:
        return console.print(
            f"[green3][-] ** Action Successful **\n[khaki3]The {text} file "
            f"was saved as : {file_name}"
            )


    @staticmethod
    def format_key_file_log(
        timestamp: str,
        key_path: Path | str,
        hash_value: str
    ) -> str:
        return (
        "------------------------------------------\n"
        f"[{timestamp}]\n"
        f"Key file name : {key_path.name}\n"
        f"Key file hash value (SHA-256) : {hash_value}\n"
        "------------------------------------------"
        )


    @staticmethod
    def format_key_file_verification(
        key_file_dir: Path | str,
        full_key_path: Path | str,
        key_file_hash_file: Path | str,
        key_file_hash_value: str
        ) -> str:
        return ("[bright_white]------------------------------------------\n"
f"[green3][-] ** Key file created **\n"
f"[bright_white][-] Key file saved in : [khaki3]{key_file_dir}"
f"[bright_white][-] Key file name     : [khaki3]{full_key_path.name}\n"
f"[green3][-] ** Key file hashed **\n"
f"[bright_white][-] Key file hash verification saved in : [khaki3]{key_file_hash_file.parent}"
f"[bright_white][-] Key file hash file name             : [khaki3]{key_file_hash_file.name}"
f"[bright_white][-] Key file hash value (SHA256)        : [khaki3]{key_file_hash_value}\n"
"[bright_white]------------------------------------------")
