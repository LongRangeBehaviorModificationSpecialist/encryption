# !/usr/bin/env python3

from datetime import datetime
from functools import wraps
import os
from pathlib import Path
import re
from rich.prompt import Prompt
import subprocess
import sys
import time

# Import the console object from the main __init__.py file
from . import c
from resources.vars import ICONS


class Utils:

    @staticmethod
    def timeit(func):
        @wraps(func)
        def timeit_wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            result = func(*args, **kwargs)
            end_time = time.perf_counter()
            total_time = end_time - start_time
            c.print(
                f"{ICONS['success']}[green3] Operation [ "
                f"{func.__name__}() ] was completed in {total_time:.4f} seconds"
            )
            return result
        return timeit_wrapper


    @staticmethod
    def clear_screen() -> None:
        command = "cls" if os.name == "nt" else "clear"
        subprocess.run(command, shell=True)


    @staticmethod
    def exit_application() -> None:
        """Print message to screen then exit the application."""
        c.print(
            f"\n\n{ICONS['arrow_right']}[green3]  Exiting the "
            "application...\n"
        )
        sys.exit(0)


    @staticmethod
    def get_date_time(format: str) -> str:
        """Gets local date/time info."""
        date_time_formats = {
            "display": "%d-%b-%Y %H:%M:%S",
            "file": "%Y-%m-%d_%H.%M.%S"
        }
        local_time = datetime.now().astimezone()
        # offset = local_time.strftime("%z")
        # formatted_offset = f"UTC{offset[0]}{int(offset[1:3])}"
        dt_format = date_time_formats[f'{format}']
        current_time = local_time.strftime(
            # f"{dt_format} ({local_time})"
            f"{dt_format}"
        )

        return current_time


    @staticmethod
    def get_file_path() -> str:
        return Prompt.ask(
            f"{ICONS['keyboard']}[white] Enter the path of the "
            "file to be processed "
        ).strip("\"'")


    @staticmethod
    def get_directory_path() -> str:
        return Prompt.ask(
            f"{ICONS['keyboard']}[white] Enter the full path of the "
            "directory containing the files to be processed "
        ).strip("\"'")


    @staticmethod
    def select_recursive_option() -> bool:
        """Prompts the user for a yes/no answer and returns a boolean."""
        while True:
            recursive_input =Prompt.ask(
                f"{ICONS['question']}[white] Process subdirectories "
                "recursively? ",
                choices=["y", "n"],
                show_choices=True
            ).strip().lower()
            match recursive_input:
                case "y":
                    return True
                case "n":
                    return False
            c.print(
                f"{ICONS['failure']}[red] Invalid input. Enter either "
                "'y' or 'n'."
            )


    @staticmethod
    def get_password() -> bytearray:
        """Prompts the user for a password until they provide one that
        passes strength validation, returning a mutable bytearray.
        """
        while True:
            # Prompt user and convert directly to a mutable bytearray
            raw_password = Prompt.ask(
                f"{ICONS['keyboard']}[white] Enter the PASSWORD you want "
                "to use ",
                password=True
            ).encode("utf-8")
            password_bytes = bytearray(raw_password)

            # If the password passes validation, break the loop and return it
            if Utils.validate_password(password_bytes):
                return password_bytes

            # If invalid, clear memory of the attempt before prompting again
            for i in range(len(password_bytes)):
                password_bytes[i] = 0

            c.print(
                f"{ICONS['failure']}[red] Not a valid password. "
                "Please try again."
            )


    @staticmethod
    def validate_password(password: bytearray | bytes | str) -> bool:
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
            c.print(f"""{ICONS['failure']}[red]
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
            c.print(
                f"{ICONS['success']}[white] Your password meets "
                "the minimum requirements. Continuing..."
            )
            return True


    @staticmethod
    def get_email_address() -> str:
        return Prompt.ask(
            f"{ICONS['keyboard']}[white] Enter email address of the "
            "PGP key owner "
        ).strip().lower()


    @staticmethod
    def print_confirm_file_action(file_name: Path | str, text: str) -> str:
        return c.print(
            f"{ICONS['success']}[green3] Action Successful\n"
            f"[white]The {text} file was saved as : {file_name}"
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
        return (
            "\n[white][dim]" + "-" * 45 +"[/dim]\n"
            f"[bold green3][-] ** Key file created **\n\n"
            f"[white][-] Key file saved as:\n"
            f"    [bold yellow3]{key_file_dir}\{full_key_path.name}\n"
            f"[white][-] Key file hash verification saved as:\n"
            f"    [bold yellow3]{key_file_hash_file}\n"
            f"[white][-] Key file hash value (SHA256):\n"
            f"    [bold yellow3]{key_file_hash_value}\n\n"
            "[white][dim]" + "-" * 45 +"[/dim]"
    )


    @staticmethod
    def print_not_file_error(target_file: Path) -> str:
        return ( c.print(
            f"{ICONS['failure']}[red] File validation for "
            f"{target_file.name} failed : the file does not exist or is "
            "not a file."
            )
        )


    @staticmethod
    def verify_file_access(target_file: Path | str) -> bool:
        """Returns True if the user has permission to read the file."""
        if not os.access(target_file, os.R_OK):
            c.print(
                f"{ICONS['failure']}[red] The current user does "
                f"not have the correct permissions to process {target_file.name}"
            )
            return False
        else:
            return True


    @staticmethod
    def verify_is_directory(target_dir: Path | str) -> bool:
        """Returns true if target_dir points to a directory."""
        if not target_dir.is_dir():
            c.print(
                f"{ICONS['failure']}[red] {target_dir} does not exist "
                "or is not a valid directory."
            )
            return False
        else:
            return True


    @staticmethod
    def get_pgp_key_expire_date() -> str | None:
        """Get expiration from user, return as GNU format string."""
        expire_option = Prompt.ask(
            f"{ICONS['question']}[white] Do you want to set an "
            "expiration date?",
            choices=["y", "n"],
            show_choices=True
        )

        if expire_option == "y":
            expire_type = Prompt.ask(
                f"{ICONS['question']}[white] Expiration type (1 = "
                "Days, 2 = Date)",
                choices=["1", "2"],
                show_choices=True
            )

            if expire_type == "1":
                # GNU format: "365d", "1y", "6m" - most compatible!
                days = Prompt.ask(
                    f"{ICONS['keyboard']}[white] Enter number of days"
                ).strip()
                if days.isdigit() and int(days) > 0:
                    num_days = int(days)
                    # Convert to appropriate unit for shorter strings
                    if num_days >= 365:
                        years = num_days // 365
                        remainder = num_days % 365
                        if remainder == 0:
                            return f"{years}y"
                        else:
                            return f"{years}y{remainder}d"
                    elif num_days >= 30:
                        months = num_days // 30
                        remainder = num_days % 30
                        if remainder == 0:
                            return f"{months}m"
                        else:
                            return f"{months}m{remainder}d"
                    else:
                        return f"{num_days}d"
                else:
                    c.print(
                        f"{ICONS['warning']}[yellow] Invalid number."
                    )
                    return None
            else:
                date_str = Prompt.ask(
                    f"{ICONS['keyboard']}[white] Enter date (YYYYMMDD)"
                ).strip()
                try:
                    from datetime import datetime
                    parsed = datetime.strptime(date_str, "%Y%m%d").date()
                    if parsed <= datetime.now().date():
                        c.print(
                            f"{ICONS['warning']}[yellow] Date "
                            "must be in future."
                        )
                        return None
                    # Add time with "T" separator
                    return f"{date_str}T000000"
                except ValueError:
                    c.print(
                        f"{ICONS['warning']}[yellow] Invalid date "
                        "format."
                    )
                    return None
        return None


    @staticmethod
    def get_confirmed_password() -> str | None:
        """Prompt user for passphrase until confirmation matches."""
        max_attempts = 3  # prevent infinite loops
        attempts = 0

        while True:
            attempts += 1

            if attempts > max_attempts:
                c.print(
                    f"{ICONS['failure']}[red] Too many failed attempts. "
                    "Exiting..."
                )
                raise ValueError("Max passphrase attempts exceeded.")

            password = Prompt.ask(
                f"{ICONS['keyboard']}[white] Enter passphrase ",
                password=True
            )

            if not password:
                c.print(
                    f"{ICONS['warning']}[yellow] Passphrase cannot be "
                    "empty."
                )
                continue

            # Confirmation entry
            confirm_password = Prompt.ask(
                f"{ICONS['keyboard']}[white] Re-enter passphrase to "
                "confirm",
                password=True
            )

            if not confirm_password:
                c.print(
                    f"{ICONS['warning']}[yellow] Passphrase cannot be "
                    "empty."
                )
                continue

            # Check if they match
            if password == confirm_password:
                c.print(
                    f"{ICONS['success']}[green] Passphrases confirmed!"
                )
                return password
            else:
                c.print(
                    f"{ICONS['failure']}[red] Passphrases do not match! "
                    f"Try again (attempt {attempts}/{max_attempts})"
                )


    @staticmethod
    def get_pgp_full_name() -> str:
        """Get full name of the PGP key owner."""
        full_name = Prompt.ask(
            f"{ICONS['input']}[white] Enter full name of the PGP "
            "key owner "
        ).strip()

        if not full_name:
            c.print(
                f"{ICONS['warning']}[yellow3] A valid name is required."
            )
            raise ValueError("Full name must be provided.")
        return full_name


    @ staticmethod
    def get_pgp_email_address() -> str:
        """Get email address of the PGP key owner."""
        email_address = Prompt.ask(
            f"{ICONS['email']}[white] Enter email address of the "
            "PGP key owner "
        ).strip().lower()

        if not email_address or "@" not in email_address:
            c.print(
                f"{ICONS['warning']}[yellow3] Invalid or missing "
                f"email address provided : {email_address}"
            )
            raise ValueError(
                f"Invalid or missing email address provided : {email_address}"
            )
        return email_address
