# !/usr/bin/env python3

from argon2.low_level import hash_secret_raw, Type
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


def get_time() -> str:
    dt = datetime.now()
    time = dt.strftime("%H:%M:%S")
    # Pad to 6 then slice to 4
    microseconds = str(dt.microsecond).zfill(6)[:4]

    return f"{time}.{microseconds}"


class UIHandlerProtocol(Protocol):
    """Protocol defining the interface for UI message formatting."""

    def info(self, msg: str) -> None: ...
    def success(self, msg: str) -> None: ...
    def warning(self, msg: str) -> None: ...
    def error(self, msg: str) -> None: ...


class RichUIHandler:
    """Handles Rich console outputs with standardized timestamping and color themes."""

    def __init__(
            self,
            console: Console | None = None,
            get_time: Callable[[], str] = get_time
    ) -> None:
        self.console = console or Console()
        self.get_time = get_time
        self.default_color = "grey74"
        self.success_color = "bright_green"
        self.warning_color = "bright_yellow"
        self.error_color = "bright_red"
        self.menu_prompt_color = "light_goldenrod1"

    def _format(self, message: str, color: str) -> str:
        timestamp = f"[cyan][{self.get_time()}][/cyan]"
        return f"{timestamp} [{color}]{message}[/{color}]"

    def info(self, message: str) -> None:
        self.console.print(self._format(message, self.default_color))

    def success(self, message: str) -> None:
        self.console.print(self._format(message, self.success_color))

    def warning(self, message: str) -> None:
        self.console.print(self._format(message, self.warning_color))

    def error(self, message: str) -> None:
        self.console.print(self._format(message, self.error_color))

    def confirm(self, message: str) -> bool:
        """Asks a boolean yes/no question in the console."""
        formatted_prompt = self._format(message, self.default_color)
        return Confirm.ask(
            formatted_prompt,
            console=self.console,
        )

    def prompt(
            self,
            message: str,
            choices: Sequence[str] | None = None,
            default: str | None = None,
            password: bool = False,
            show_choices: bool = False,
            menu_prompt: bool = False
    ) -> str:
        """Prompts the user for text input."""
        if not menu_prompt:
            formatted_prompt = self._format(message, self.default_color)
        else:
            formatted_prompt = self._format(message, self.menu_prompt_color)

        return Prompt.ask(
            formatted_prompt,
            console=self.console,
            choices=choices,
            default=default,
            password=password,
            show_choices=show_choices,
        )


class Utils:

    def __init__(self, ui: UIHandlerProtocol | None = None) -> None:
        self.ui = ui or RichUIHandler(get_time=get_time)


    def timeit(self, function):
        @wraps(function)
        def timeit_wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            result = function(*args, **kwargs)
            end_time = time.perf_counter()
            total_time = end_time - start_time
            self.ui.success(
                f"Operation [{function.__name__}()] was completed in "
                f"{total_time:.4f} seconds"
            )
            return result
        return timeit_wrapper


    def _derive_key(
            self,
            password: bytearray | bytes | str,
            salt: bytes
    ) -> bytes:
        """Derives a 256-bit key from a password buffer using Argon2id
        (memory-hard, side-channel resistant KDF).

        Uses recommended OWASP parameters:
        - time_cost = 3 (iterations)
        - memory_cost = 65536 (64 MB)
        - parallelism = 4

        Args:
            password: password from which the key will be derived
            salt: value of the salt to use when deriving the key

        Returns:
            The key as a byte string
        """
        # Log at START of important operations
        logger.info(
            f"Deriving key from password (length → "
            f"{len(password) if isinstance(password, str) else len(bytes(password))} characters)"
        )
        # If a string gets passed, encode it; otherwise use raw buffer
        # Convert string to bytes
        if isinstance(password, str):
            pwd_buffer = password.encode("utf-8")
        elif isinstance(password, bytearray):
            # Convert bytearray to immutable bytes
            pwd_buffer = bytes(password)
        else:
            pwd_buffer = password

        key = hash_secret_raw(
            secret=pwd_buffer,
            salt=salt,
            time_cost=3,           # Number of iterations
            memory_cost=65536,     # 64 MB memory requirement
            parallelism=4,         # Utilize 4 threads
            hash_len=32,           # 256-bit key for Fernet
            type=Type.ID,          # Argon2id (hybrid side-channel resistance)
        )

        # kdf = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1)

        logger.info("Key derived successfully")
        # return kdf.derive(pwd_buffer)
        return key


    def clear_screen(self) -> None:
        command = "cls" if os.name == "nt" else "clear"
        subprocess.run(command, shell=True)


    def exit_application(self) -> None:
        """Print message to screen then exit the application."""
        self.ui.success(f"Exiting the application...\n")
        sys.exit(0)


    def get_date_time(self, format: str) -> str:
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
        dt_format = date_time_formats[format]
        current_time = local_time.strftime(
            f"{dt_format}"
        )

        return current_time


    def get_file_path(self) -> str:
        return self.ui.prompt("Path of the file to be processed").strip("\"'")


    def get_directory_path(self) -> str:
        return self.ui.prompt("Path of the directory to be processed").strip("\"'")


    def get_output_path(
            self,
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
                "Enter the directory where you want to save the processed "
                "files (press [Enter] to use the current folder)"
            )

        # Show default location clearly in the prompt
        prompt_display = (
            f"{base_prompt} [dim](current → [i]{default_dir}[/i])"
        )

        # Ask user for input
        output_input = self.ui.prompt(
            prompt_display,
        )

        # Handle empty/whitespace input
        if not output_input or output_input.strip("\"'") == "":
            output_path = Path(default_dir)
            self.ui.info(
                f"Using same directory → [bright_blue][i]{output_path}"
                )
        else:
            output_path = Path(output_input).resolve()
            self.ui.info(f"Output directory → {output_path}")

        # Ensure output directory exists
        if not output_path.exists():
            msg = f"Creating output directory → '{output_path}'"
            self.ui.info(msg)
            logger.info(msg)
            try:
                output_path.mkdir(parents=True, exist_ok=True)
                dir_made_msg = f"Output directory '{output_path}' was created"
                self.ui.success(dir_made_msg)
                logger.info(dir_made_msg)
            except Exception as err:
                failed_make_dir_msg = (
                    f"Failed to create output folder '{output_path}' → '{err}'"
                )
                self.ui.error(failed_make_dir_msg)
                logger.error(failed_make_dir_msg)
                raise RuntimeError(failed_make_dir_msg) from err

        return output_path


    def select_recursive_option(self) -> bool:
        """Prompts the user for a yes/no answer

        Returns:
            boolean (True or False).
        """
        while True:
            recursive = self.ui.confirm("Process sub-directories recursively?")
            if not recursive:
                return False
            else:
                return True


    def get_password(self) -> bytearray:
        """Prompts the user for a password until they provide one that
        passes strength validation, returning a mutable bytearray.
        """
        while True:
            # Prompt user and convert directly to a mutable bytearray
            raw_password = self.ui.prompt(
                "Enter the PASSWORD you want to use",
                password=True
            ).encode("utf-8")
            password_bytes = bytearray(raw_password)

            # If the password passes validation, break the loop and return it
            if self.validate_password(password_bytes):
                return password_bytes

            # If invalid, clear memory of the attempt before prompting again
            for i in range(len(password_bytes)):
                password_bytes[i] = 0

            self.ui.error("Not a valid password. Please try again.")


    def validate_password(self, password: bytearray | bytes | str) -> bool:
        """Validates if a password meets the strength requirements.

        Args:
            password: The password to validate as a bytearray, bytes, or str.

        Returns:
            True if valid, False otherwise.
        """
        # Byte-level symbol definitions
        symbols_bytes = b"!@#%&*()?<>-+=[]~^|"

        # Convert string to bytes if passed as string, preserving
        # bytearray if provided
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
        if not (
            has_min_length
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
            self.ui.info("Password meets the requirements. Continuing...")
            return True


    def get_email_address(self) -> str:
        return self.ui.prompt("Enter the email of the key owner").strip().lower()


    def print_confirm_file_action(
                self,
                file_name: Path | str,
                text: str
        ) -> str:
        return self.ui.success(
            "Action successful. "
            f"[grey74]The '{text}' file was saved as → '{file_name}'"
        )


    def format_key_file_log(
            self,
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


    def show_key_file_verification(
            self,
            key_file_dir: Path | str,
            full_key_path: Path | str,
            key_file_hash_value: str
    ) -> str:
        return (
            self.ui.success("** Key file created successfully"),
            self.ui.info(
                f"Key file saved as: [bright_blue][i]"
                f"{key_file_dir}\{full_key_path.name}[/i]\n"
            ),
            self.ui.info(
                f"Key file hash value (SHA256): "
                f"[bright_blue][i]{key_file_hash_value}\n"
            )
        )


    def print_not_file_error(self, target_file: Path) -> str:
        return self.ui.error(
            f"Validation for {target_file.name} failed → the file does not "
            "exist or is not a file."
        )


    def verify_file_access(self, target_file: Path | str) -> bool:
        """Returns True if the user has permission to read the file."""
        target_path = Path(target_file)
        if not os.access(target_path, os.R_OK):
            self.ui.error(
                f"The current user does not have permission to access the "
                f"file → {target_path.name}"
            )
            logger.warning(f"The user did not have valid file permissions.")
            return False
        return True


    def verify_is_directory(self, target_dir: Path | str) -> Path:
        """Validates target_dir and returns its resolved Path object.

        Raises:
            FileNotFoundError: If the path does not exist.
            NotADirectoryError: If the path exists but is a file.
        """
        path = Path(target_dir).resolve()

        if not path.exists():
            msg = f"Directory not found → '{path}'"
            self.ui.error(msg)
            raise FileNotFoundError(msg)

        if not path.is_dir():
            msg = f"Expected a directory, but found a file → '{path}'"
            self.ui.error(msg)
            raise NotADirectoryError(msg)

        return path


    def get_pgp_key_expire_date(self) -> str | None:
        """Get expiration from user, return as GNU format string."""
        expire_option = self.ui.confirm(
            "Do you want to set an expiration date for the new key?"
        )

        if expire_option:
            expire_type = self.ui.prompt(
                "Enter the expiration type (1=Days, 2=Date)",
                choices=["1", "2"],
                show_choices=True
            )

            if expire_type == "1":
                # GNU format: "365d", "1y", "6m" - most compatible!
                days = self.ui.prompt(
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
                    self.ui.warning("Invalid number.")
                    return None
            else:
                date_str = self.ui.prompt(
                    "Enter date (in 'YYYYMMDD' format)"
                ).strip()
                try:
                    from datetime import datetime
                    parsed = datetime.strptime(date_str, "%Y%m%d").date()
                    if parsed <= datetime.now().date():
                        self.ui.warning("The date must be in future")
                        return None
                    # Add time with "T" separator
                    return f"{date_str}T000000"
                except ValueError:
                    self.ui.warning("An invalid date format was entered")
                    return None
        return None


    def get_confirmed_password(self) -> str | None:
        """Prompt user for passphrase until confirmation matches.

        Returns:
            The password as a string.
        """
        max_attempts = 3  # prevent infinite loops
        attempts = 0

        while True:
            attempts += 1

            if attempts > max_attempts:
                self.ui.error("Too many failed attempts. Exiting...")
                raise ValueError("Max passphrase attempts exceeded.")

            password = self.ui.prompt(
                "Enter passphrase",
                password=True
            )

            if not password:
                self.ui.warning("Passphrase cannot be empty.")
                continue

            # Confirmation entry
            confirm_password = self.ui.prompt(
                "Re-enter passphrase to confirm",
                password=True
            )

            if not confirm_password:
                self.ui.warning("Passphrase cannot be empty")
                continue

            # Check if they match
            if password == confirm_password:
                self.ui.success("Passphrases match. Continuing...")
                return password
            else:
                self.ui.error(
                    f"Passphrases do not match! Try again (attempt {attempts}/"
                    f"{max_attempts})"
                )


    def get_pgp_full_name(self) -> str:
        """Get full name of the PGP key owner."""
        full_name = self.ui.prompt(
            "Enter full name of the PGP key owner"
        ).strip()

        if not full_name:
            self.ui.warning("A valid name is required.")
            logger.warning("The name of the PGP key owner was not provided")
            raise ValueError("A name must be provided.")
        return full_name


    def get_pgp_email_address(self) -> str:
        """Get email address of the PGP key owner."""
        email_address = self.ui.prompt(
            "Enter email address of the PGP key owner"
        ).strip().lower()

        if not email_address or "@" not in email_address:
            self.ui.warning(
                f"Invalid or missing email address provided → {email_address}"
            )
            raise ValueError(
                f"Invalid or missing email address provided → {email_address}"
            )
        return email_address
