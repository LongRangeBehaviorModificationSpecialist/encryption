# !/usr/bin/env python3
# DLU : 23-Jul-2026

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from datetime import datetime
from rich.console import Console
from rich.prompt import Prompt
from functools import wraps
import hashlib
import os
import subprocess
from pathlib import Path
import re
import sys
import time
import typing
from typing import Union


# Make the console object
c = Console()


class Functions:


    def timeit(func):
        @wraps(func)
        def timeit_wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            result = func(*args, **kwargs)
            end_time = time.perf_counter()
            total_time = end_time - start_time
            c.print(f"""[dodger_blue1]
Operation [ {func.__name__}() ] was completed in \
{total_time:.4f} seconds""")
            # c.print(f"\nFunction {func.__name__}{args} {kwargs} Took {total_time:.4f} seconds")
            return result
        return timeit_wrapper


    @staticmethod
    def generate_salt() -> bytes:
        """Generate a cryptographically secure random 16-byte salt."""
        return os.urandom(16)


    @staticmethod
    def encode_key(password: str, salt: bytes) -> bytes:
        """Derive a secure 256-bit (32-byte) AES key from a password and salt
        using PBKDF2 with SHA-256.
        """
        key = PBKDF2(
            password=password,
            salt=salt,
            dkLen=32,
            count=100000,
            hmac_hash_module=SHA256
        )
        return key


    @staticmethod
    def get_aes_iv() -> bytes:
        """Generate a cryptographically secure random 16-byte IV."""
        return os.urandom(16)


    @staticmethod
    def ask_delete_original_enc_files() -> str:
        delete_original_encrypted_files = (
            Prompt.ask(
            """[bright_white]
[-] Do you want to delete the original encrypted files from the directory \
after decryption? """,
                choices=["y", "n"],
                show_choices=True,
            )
            .strip()
            .lower()
        )
        return delete_original_encrypted_files


    @staticmethod
    def clear_screen() -> None:
        command = "cls" if os.name == "nt" else "clear"
        subprocess.run(command, shell=True)


    @staticmethod
    def confirm_delete_original_files() -> str:
        confirm_delete_originals = (
            Prompt.ask(
                """[bright_white]
[-] Do you want to delete the original files after they are encrypted? \
[orange_red1][THIS ACTION CANNOT BE UNDONE!] """,
                choices=["y", "n"],
                show_choices=True,
            )
            .strip()
            .lower()
        )
        return confirm_delete_originals


    @staticmethod
    def exit_application() -> None:
        c.print(
            """\n\n[bright_white]
[-] Exiting the application. Goodbye...\n\n"""
        )
        sys.exit(0)


    @staticmethod
    def get_all_files(target_dir_path: Path) -> list[str]:
        dirs = []
        for dir_name, sub_dirs, file_list in os.walk(target_dir_path):
            for file in file_list:
                dirs.append(dir_name + "\\" + file)
        return dirs


    @staticmethod
    def get_date_time() -> str:
        local_time = datetime.now().astimezone()
        offset = local_time.strftime("%z")
        formatted_offset = f"UTC{offset[0]}{int(offset[1:3])}"
        current_time = local_time.strftime(f"%d-%b-%Y %H:%M:%S.%f ({formatted_offset})")
        return current_time


    def get_encrypted_file_name(self, file_path: Path) -> Path:
        encrypted_file = f"{file_path}.encrypted"
        return Path(encrypted_file)


    def get_decrypted_file_name(self, file_to_decrypt: Path) -> Path:
        decrypted_file_name = f"{file_to_decrypt}.decrypted"
        return Path(decrypted_file_name)


    def get_email_address(self) -> str:
        email_address = (
            Prompt.ask(
                """[bright_white]
[-] Enter email address of the PGP key owner """
            )
            .strip()
            .lower()
        )
        return email_address


    @staticmethod
    def get_file_path(text: str) -> Path:
        target_file_path = (
            Prompt.ask(
                f"""[bright_white]
[-] Enter the path of the file to be {text} """
            )
        )
        return Path(target_file_path)


    @staticmethod
    def get_folder_path(text: str) -> Path:
        folder_path = (
            Prompt.ask(
                f"""[bright_white]
[-] Enter the path of the directory containing the files to be {text} """
            )
        )
        return Path(folder_path)


    @staticmethod
    def get_password() -> str:
        """Prompts the user for a password until they provide one that
        passes the strength validation.
        """
        while True:
            password = (
                Prompt.ask(
                    """[bright_white]
[-] Enter the PASSWORD you want to use """,
                password=True
                )
            )

            # If the password passes validation, break the loop and return it
            if Functions.validate_password(password):
                return password

            c.print(
                """[bright_red]
[!] Not a valid password. Please try again.\n"""
            )


    @staticmethod
    def validate_password(password: str) -> bool:
        """Validates if a password meets the strength requirements.
        Returns True if valid, False otherwise.
        """
        symbols = "!@#%&*()?<>-+=[]~^|"

        has_min_length = len(password) >= 10
        has_digit = re.search(r"\d", password) is not None
        has_upper = re.search(r"[A-Z]", password) is not None
        has_symbol = any(char in symbols for char in password)

        if not (has_min_length and has_digit and has_upper and has_symbol):
            c.print(
                """[red1]
Your password did not meet the minimun requirements. Please try again.\n
Your password must meet the following criteria\n
    [-] Is at least ten characters long
    [-] Contain at least one number
    [-] Contain at least one capital letter and
    [-] Contain at least one of the following symbols: \
! @ # % & * ( ) ? < > - + = [ ] ~ ^ |"""
            )
            return False
        else:
            c.print(
                f"""[bright_white]
[-] Your password meets the minimum requirements. Continuing..."""
            )
            return True


    def get_pgp_password(self) -> str:
        password = Prompt.ask(
            """[khaki3]
[-] Enter a password to use for the PGP private key """
        )
        Functions.validate_password(password=password)
        return password


    def hash_new_key_file(self, key_file: Path) -> str:
        sha256_hash = hashlib.sha256()
        kf = key_file
        with open(kf, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest().upper()


    def load_key(self, key_file: Path) -> bytes:
        """Load the data from the .key file into memory to use it to either
        encrypt or decrypt a file.

        Returns the value stored in the .key file.
        """
        with open(key_file, "rb") as mykey:
            key_to_load = mykey.read()
        return key_to_load


    @staticmethod
    def no_valid_yn_option() -> str:
        no_valid_yn_option = c.print(
            """[red1]
[!] You did not enter a valid option ("y" or "n"). Please try again."""
        )
        return no_valid_yn_option


    @staticmethod
    def print_confirm_file_action(
        file_name: Union[Path, str], text: str
    ) -> None:
        file_name = Path(file_name)
        confirm = (
            c.print(
                f"""[green3]
[-] **Action Successful**[khaki3]
The {text} file was saved as : {file_name}"""
            )
        )
        return confirm


    @staticmethod
    def print_original_files_deleted(
        folder_path: Union[Path, str], action: str
    ) -> None:

        confirm = (
            c.print(
                f"""[green3]
------------------------------------------
** ACTION SUCCESSFUL **\n
Files in the '{folder_path}' directory have been {action}\n
The original files HAVE BEEN DELETED
------------------------------------------"""
            )
        )
        return confirm


    @staticmethod
    def print_original_files_not_deleted(
        folder_path: Union[Path, str], action: str
    ) -> None:

        confirm = (
            c.print(
                f"""[green3]
------------------------------------------
** ACTION SUCCESSFUL **\n
Files in the '{folder_path}' directory have been {action}\n
The original files were NOT DELETED
------------------------------------------"""
            )
        )
        return confirm


    @staticmethod
    def write_key_hash_to_file(
        key_file_path: Path, key_file_hash_value: str
    ) -> None:

        key_file_path = Path(key_file_path)
        key_file_hash_file = f"{key_file_path}.sha256"

        with open(key_file_hash_file, "w", encoding="utf-8") as f:
            f.write(f"""
------------------------------------------
[{Functions.get_date_time()}]
Key File Name : {key_file_path.name}\n
Key File Hash Value (SHA-256) : {key_file_hash_value}
------------------------------------------""")

        c.print(
            f"""[bright_white]
------------------------------------------
[{Functions.get_date_time()}]
[-] Key File hashed successfully
[-] Key File Hash verification saved in : \
'{os.path.dirname(key_file_path)}' directory
[-] Key File Hash File Name : \
'{os.path.basename(key_file_hash_file)}
[-] Key File Hash value : {key_file_hash_value}
------------------------------------------"""
        )


    def write_to_file(self, file: typing.TextIO, message: str) -> None:
        file.write(message)


# ==================================
# XOR Functions
# ==================================

    @staticmethod
    def get_xor_key() -> str:
        xor_key = (
            Prompt.ask(
                """[khaki3]
[-] Enter the key you want to use for the encryption """
            )
        )
        return xor_key


    @staticmethod
    def get_message_to_xor() -> str:
        message = (
            Prompt.ask(
                """[khaki3]
[-] Enter the message string you want to encrypt """
            )
        )
        return message


    @staticmethod
    def get_file_to_xor() -> Path:
        return Path(Functions.get_file_path(text="you want to encrypt"))


    @staticmethod
    def get_xor_message_to_decrypt() -> str:
        message = (
            Prompt.ask(
                """[khaki3]
[-] Enter the message string you want to decrypt """
            )
        )
        return message


    @staticmethod
    def get_xor_file_to_decrypt() -> Path:
        return Path(Functions.get_file_path(text="you want to decrypt"))
