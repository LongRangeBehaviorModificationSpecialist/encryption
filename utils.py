# !/usr/bin/env python3

from datetime import datetime
from functools import wraps
import os
from pathlib import Path
import re
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.traceback import install
import subprocess
import sys
import time
from typing import Callable, Protocol, Sequence

from config.config import GLOBAL_CONFIG
from config.log_config import get_logger
# Imports from the main __init__.py file
from resources import console, install


logger = get_logger("utils")
install()


class UIHandlerProtocol(Protocol):
    """Protocol defining the interface for UI message formatting."""

    def info(self, msg: str) -> None: ...
    def success(self, msg: str) -> None: ...
    def warning(self, msg: str) -> None: ...
    def error(self, msg: str) -> None: ...


class Utils:

    def __init__(self, ui: UIHandlerProtocol | None = None) -> None:
        self.ui = ui or RichUIHandler(get_time=Utils.get_time)

    @staticmethod
    def timeit(function):
        @wraps(function)
        def timeit_wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            result = function(*args, **kwargs)
            end_time = time.perf_counter()
            total_time = end_time - start_time
            console.print(
                f"[cyan][{Utils.get_time()}][green] "
                f"Operation [{function.__name__}()] was completed in "
                f"{total_time:.4f} seconds"
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
        Utils.ui.warning("Exiting the application...\n")
        sys.exit(0)


    @staticmethod
    def get_date_time(format: str) -> str:
        """Gets local date/time info.

        Args:
            format: either "display" or "file" (safe for file naming).

        Returns:
            Current date/time formatted in the requested style.
        """
        date_time_formats = {
            "display": "%d-%b-%Y %H:%M:%S",
            "file": "%Y-%m-%d_%H.%M.%S"
        }
        local_time = datetime.now().astimezone()
        dt_format = date_time_formats[f'{format}']
        current_time = local_time.strftime(
            f"{dt_format}"
        )

        return current_time


    @staticmethod
    def get_time() -> str:
        dt = datetime.now()
        time = dt.strftime("%H:%M:%S")
        # Pad to 6 then slice to 4
        microseconds = str(dt.microsecond).zfill(6)[:4]

        return f"{time}.{microseconds}"


    @staticmethod
    def get_file_path() -> str:
        return Prompt.ask(
            f"[cyan][{Utils.get_time()}][grey66] Enter the "
            "path of the file to be processed"
        ).strip("\"'")


    @staticmethod
    def get_directory_path() -> str:
        return Prompt.ask(
            f"[cyan][{Utils.get_time()}][grey66] Enter the "
            f"full path of the directory containing the files to be "
            f"processed"
        ).strip("\"'")


    @staticmethod
    def get_output_path(
            target_path: Path | str,
            prompt_text: str = None,
            force_same_directory: bool = True
    ) -> Path:
        """Ask user for output path, defaulting to target file's directory
        if left blank.

        Args:
            target_file: Source/target file whose directory will be used as
                default
            prompt_text: Custom prompt message (optional)
            force_same_directory: If True, always use target's parent
                as default

        Returns:
            Path object for the output destination
        """
        # Resolve to absolute path
        resolved_target = Path(target_path).resolve()

        # Determine default directory (SAME folder as target)
        if resolved_target.is_file():
            default_dir = str(resolved_target.parent)
        elif resolved_target.is_dir():
            default_dir = str(resolved_target)
        else:
            # Doesn't exist yet, use parent of whatever path was given
            default_dir = (
                str(resolved_target.parent)
                if resolved_target.parent != resolved_target
                else str(Path.cwd())
            )

        # Build helpful prompt text
        if prompt_text:
            base_prompt = prompt_text
        else:
            base_prompt = (
                f"[cyan][{Utils.get_time()}][grey66][-] Enter the "
                "directory where you want to save the processed files "
                "(press [Enter] to use the same folder)"
            )

        # Show default location clearly in the prompt
        prompt_display = f"{base_prompt} [dim](default: {default_dir})[/dim]"

        # Ask user for input
        output_input = Prompt.ask(
            prompt_display,
            default=default_dir,  # ← Makes [Enter] use the same directory
            show_default=True
        ).strip("\"'")

        # Handle empty/whitespace input
        if not output_input or output_input.strip() == "":
            output_path = Path(default_dir)
            console.print(
                f"[cyan][{Utils.get_time()}][green] ✓ Using same "
                f"directory: {output_path}"
            )
        else:
            output_path = Path(output_input).resolve()
            console.print(
                f"[cyan][{Utils.get_time()}] Output directory: "
                f"{output_path}"
            )

        # Ensure output directory exists
        if not output_path.exists():
            console.print(
                f"[cyan][{Utils.get_time()}][yellow] Creating output "
                f"directory: {output_path}"
            )
            try:
                output_path.mkdir(parents=True, exist_ok=True)
                logger.info(f"Output directory '{output_path}' was created")
            except Exception as e:
                failed_make_dir_msg = f"Failed to create {output_path} ← {e}"
                console.print(
                    f"[cyan][{Utils.get_time()}][red] "
                    f"{failed_make_dir_msg}"
                )
                logger.error(f"{failed_make_dir_msg}")
                raise RuntimeError(
                    f"{failed_make_dir_msg}"
                ) from e

        return output_path


    @staticmethod
    def select_recursive_option() -> bool:
        """Prompts the user for a yes/no answer and returns a boolean."""
        while True:
            recursive_input = Confirm.ask(
                f"[cyan][{Utils.get_time()}][grey66] "
                "Process subdirectories recursively?"
            )
            if not recursive_input:
                return False
            else:
                return True


    @staticmethod
    def get_password() -> bytearray:
        """Prompts the user for a password until they provide one that
        passes strength validation, returning a mutable bytearray.
        """
        while True:
            # Prompt user and convert directly to a mutable bytearray
            raw_password = Prompt.ask(
                f"[cyan][{Utils.get_time()}][grey66] Enter "
                "the PASSWORD you want to use",
                password=True
            ).encode("utf-8")
            password_bytes = bytearray(raw_password)

            # If the password passes validation, break the loop and return it
            if Utils.validate_password(password_bytes):
                return password_bytes

            # If invalid, clear memory of the attempt before prompting again
            for i in range(len(password_bytes)):
                password_bytes[i] = 0

            console.print(
                f"[cyan][{Utils.get_time()}][red] Not a "
                "valid password. Please try again."
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
            console.print(
                f"{GLOBAL_CONFIG.red_line}\n"
                "Your password did not meet the minimun requirements. "
                "Please try again.\n"
                "Your password must meet the following criteria:\n\n"
                "    [-] Is at least ten (10) characters long\n"
                "    [-] Contain at least one number\n"
                "    [-] Contain at least one capital letter\n"
                "    [-] Contain at least one lowercase letter and\n"
                "    [-] Contain at least one of the following symbols:\n"
                "        ! @ # % & * ( ) ? < > - + = [ ] ~ ^ |"
            )
            return False
        else:
            console.print(
                f"[cyan][{Utils.get_time()}][grey66] Your "
                "password meets the minimum requirements. Continuing..."
            )
            return True


    @staticmethod
    def get_email_address() -> str:
        return Prompt.ask(
            f"[cyan][{Utils.get_time()}][grey66] Enter "
            "the email address of the PGP key owner"
        ).strip().lower()


    @staticmethod
    def print_confirm_file_action(
                file_name: Path | str,
                text: str
        ) -> str:
        return console.print(
            f"[cyan][{Utils.get_time()}][green] Action "
            "successful\n"
            f"[grey66]The {text} file was saved as: {file_name}"
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
    def show_key_file_verification(
            key_file_dir: Path | str,
            full_key_path: Path | str,
            key_file_hash_value: str
    ) -> str:
        return (
            console.print(
                f"[cyan][{Utils.get_time()}][green] ** Key file "
                f"created successfully\n"
                f"[cyan][{Utils.get_time()}][grey66] Key file saved "
                f"as: [blue][i]{key_file_dir}\{full_key_path.name}[/i]\n"
                f"[cyan][{Utils.get_time()}][grey66] Key file hash "
                f"value (SHA256): [blue][i]{key_file_hash_value}\n"
            )
        )


    @staticmethod
    def print_not_file_error(target_file: Path) -> str:
        return ( console.print(
            f"[cyan][{Utils.get_time()}][red] Validation "
            f"for {target_file.name} failed → the file does not "
            "exist or is not a file."
            )
        )


    @staticmethod
    def verify_file_access(target_file: Path | str) -> bool:
        """Returns True if the user has permission to read the file."""
        target_path = Path(target_file)
        if not os.access(target_path, os.R_OK):
            Utils.ui.error(
                f"The current user does not have permission to access {target_path.name}"
            )
            return False
        return True


    @staticmethod
    def verify_is_directory(target_dir: Path | str) -> Path:
        """Validates target_dir and returns its resolved Path object.

        Raises:
            FileNotFoundError: If the path does not exist.
            NotADirectoryError: If the path exists but is a file.
        """
        path = Path(target_dir).resolve()

        if not path.exists():
            msg = f"Directory not found → '{path}'"
            Utils.ui.error(msg)
            raise FileNotFoundError(msg)

        if not path.is_dir():
            msg = f"Expected a directory, but found a file → '{path}'"
            Utils.ui.error(msg)
            raise NotADirectoryError(msg)

        return path


    @staticmethod
    def get_pgp_key_expire_date() -> str | None:
        """Get expiration from user, return as GNU format string."""
        expire_option = Confirm.ask(
            f"[cyan][{Utils.get_time()}][grey66] Do you "
            "want to set an expiration date for the new key?",
        )

        if expire_option:
            expire_type = Prompt.ask(
                f"[cyan][{Utils.get_time()}][grey66] "
                "Enter the expiration type (1=Days, 2=Date)",
                choices=["1", "2"],
                show_choices=True
            )

            if expire_type == "1":
                # GNU format: "365d", "1y", "6m" - most compatible!
                days = Prompt.ask(
                    f"[cyan][{Utils.get_time()}][grey66] "
                    "Enter number of days (e.g., '365d', '1y', '6m')"
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
                    console.print(
                        f"[cyan][{Utils.get_time()}][yellow] "
                        "Invalid number."
                    )
                    return None
            else:
                date_str = Prompt.ask(
                    f"[cyan][{Utils.get_time()}][grey66] "
                    "Enter date (in 'YYYYMMDD' format)"
                ).strip()
                try:
                    from datetime import datetime
                    parsed = datetime.strptime(date_str, "%Y%m%d").date()
                    if parsed <= datetime.now().date():
                        console.print(
                            f"[cyan][{Utils.get_time()}][yellow] The "
                            "date must be in future"
                        )
                        return None
                    # Add time with "T" separator
                    return f"{date_str}T000000"
                except ValueError:
                    console.print(
                        f"[cyan][{Utils.get_time()}][yellow] An "
                        "invalid date format was entered"
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
                console.print(
                    f"[cyan][{Utils.get_time()}][red] Too many "
                    "failed attempts. Exiting..."
                )
                raise ValueError("Max passphrase attempts exceeded.")

            password = Prompt.ask(
                f"[cyan][{Utils.get_time()}][grey66] Enter passphrase",
                password=True
            )

            if not password:
                console.print(
                    f"[cyan][{Utils.get_time()}][yellow] Passphrase "
                    "cannot be empty."
                )
                continue

            # Confirmation entry
            confirm_password = Prompt.ask(
                f"[cyan][{Utils.get_time()}][grey66] Re-enter "
                f"passphrase to confirm",
                password=True
            )

            if not confirm_password:
                console.print(
                    f"[cyan][{Utils.get_time()}][yellow] "
                    f"Passphrase cannot be empty"
                )
                continue

            # Check if they match
            if password == confirm_password:
                console.print(
                    f"[cyan][{Utils.get_time()}][green] Passphrases "
                    "confirmed!"
                )
                return password
            else:
                console.print(
                    f"[cyan][{Utils.get_time()}][red] Passphrases "
                    f"do not match! Try again (attempt {attempts}/"
                    f"{max_attempts})"
                )


    @staticmethod
    def get_pgp_full_name() -> str:
        """Get full name of the PGP key owner."""
        full_name = Prompt.ask(
            f"[cyan][{Utils.get_time()}][grey66] Enter full "
            "name of the PGP key owner"
        ).strip()

        if not full_name:
            console.print(
                f"[cyan][{Utils.get_time()}][yellow] A valid name "
                "is required."
            )
            raise ValueError("Full name must be provided.")
        return full_name


    @ staticmethod
    def get_pgp_email_address() -> str:
        """Get email address of the PGP key owner."""
        email_address = Prompt.ask(
            f"[cyan][{Utils.get_time()}][grey66] Enter email "
            f"address of the PGP key owner"
        ).strip().lower()

        if not email_address or "@" not in email_address:
            console.print(
                f"[cyan][{Utils.get_time()}][yellow] Invalid or "
                f"missing email address provided → {email_address}"
            )
            raise ValueError(
                f"Invalid or missing email address provided → {email_address}"
            )
        return email_address


class RichUIHandler:
    """Handles Rich console outputs with standardized timestamping and color themes."""

    def __init__(
        self,
        console: Console | None = None,
        get_time: Callable[[], str] = Utils.get_time
    ):
        self.console = console or Console()
        self.get_time = get_time

    def _format(self, message: str, color: str) -> str:
        timestamp = f"[cyan][{self.get_time()}][/cyan]"
        return f"{timestamp} [{color}]{message}[/{color}]"

    def info(self, message: str) -> None:
        self.console.print(self._format(message, "grey66"))

    def success(self, message: str) -> None:
        self.console.print(self._format(message, "green"))

    def warning(self, message: str) -> None:
        self.console.print(self._format(message, "yellow"))

    def error(self, message: str) -> None:
        self.console.print(self._format(message, "red"))

    def confirm(self, message: str) -> bool:
        """Asks a boolean yes/no question in the console."""
        formatted_prompt = self._format(message, "grey66")
        return Confirm.ask(
            formatted_prompt, console=self.console
        )

    def prompt(
        self,
        message: str,
        choices: Sequence[str] | None = None,
        default: str | None = None,
        password: bool = False,
        show_choices: bool = False
    ) -> str:
        """Prompts the user for text input."""
        formatted_prompt = self._format(message, "grey66")
        return Prompt.ask(
            formatted_prompt,
            console=self.console,
            choices=choices,
            default=default,
            password=password,
            show_choices=show_choices
        )

