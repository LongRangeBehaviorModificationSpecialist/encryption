# !/usr/bin/env python3
# DLU : 23-Jul-2026

from datetime import datetime
from rich.prompt import Prompt
from functools import wraps
import os
import subprocess
from pathlib import Path
import re
import sys
import time
from typing import Union

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
            console.print(
                f"""[dodger_blue1]
[-] Operation [ {func.__name__}() ] was completed in {total_time:.4f} seconds"""
            )
            # console.print(f"\nFunction {func.__name__}{args} {kwargs} Took {total_time:.4f} seconds")
            return result
        return timeit_wrapper


    @staticmethod
    def clear_screen() -> None:
        command = "cls" if os.name == "nt" else "clear"
        subprocess.run(command, shell=True)


    @staticmethod
    def exit_application() -> None:
        console.print("""[green3]
[!] Exiting the application. Goodbye...\n""")
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


    def get_email_address(self) -> str:
        return (
            Prompt.ask("""[bright_white]
[-] Enter email address of the PGP key owner """)
            .strip()
            .lower()
        )


    @staticmethod
    def get_file_path(text: str) -> Path:
        target_file_path = Prompt.ask(f"""[bright_white]
[-] Enter the path of the file to be {text} """)
        return Path(target_file_path)


    @staticmethod
    def get_folder_path(text: str) -> Path:
        folder_path = Prompt.ask(f"""[bright_white]
[-] Enter the path of the directory containing the files to be {text} """)
        return Path(folder_path)


    @staticmethod
    def get_password() -> str:
        """Prompts the user for a password until they provide one that
        passes the strength validation.
        """
        while True:
            password = Prompt.ask("""[bright_white]
[-] Enter the PASSWORD you want to use """, password=True)

            # If the password passes validation, break the loop and return it
            if Functions.validate_password(password):
                return password

            console.print("""[bright_red]
[!] Not a valid password. Please try again.""")


    @staticmethod
    def validate_password(password: str) -> bool:
        """Validates if a password meets the strength requirements.

        Args:
            str -> password to be validated

        Returns:
            True if valid, False otherwise.
        """
        symbols = "!@#%&*()?<>-+=[]~^|"

        has_min_length = len(password) >= 10
        has_digit = re.search(r"\d", password) is not None
        has_upper = re.search(r"[A-Z]", password) is not None
        has_lower = re.search(r"[a-z]", password) is not None
        has_symbol = any(char in symbols for char in password)

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
            console.print(f"""[bright_white]
[-] Your password meets the minimum requirements. Continuing...""")
            return True


    @staticmethod
    def print_confirm_file_action(
        file_name: Union[Path, str], text: str
    ) -> str:

        file_name = Path(file_name)
        return (
            console.print(f"""[green3]
[-] ** Action Successful **
[khaki3]The {text} file was saved as : {file_name}""")
        )
