# !/usr/bin/env python3

import binascii
from datetime import datetime
from rich.console import Console
from rich.prompt import Prompt
from functools import wraps
import hashlib
import os
from pathlib import Path
import re
import sys
import time
import typing


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
    def ask_delete_original_enc_files() -> str:
        ask_delete_original_enc_files = Prompt.ask("""[bright_white]
[-] Do you want to delete the original encrypted files from the directory \
after decryption? """, choices=["y", "n"], show_choices=True)
        return ask_delete_original_enc_files


    @staticmethod
    def clear_screen() -> None:
        os.system("cls" if os.name == "nt" else "clear")


    @staticmethod
    def confirm_delete_original_files() -> str:
        confirm_delete_originals = Prompt.ask("""[bright_white]
[-] Do you want to delete the original files after they are encrypted? \
[orange_red1][THIS ACTION CANNOT BE UNDONE!] """,
                choices=["y", "n"],
                show_choices=True
        )
        return confirm_delete_originals


    def encode_key(self, password: str) -> bytes:
        pswd_hash = hashlib.sha256(
            password.encode("utf-8")).hexdigest()
        # Convert the sha-256 value of the password string to a byte string
        key = binascii.unhexlify(pswd_hash)
        return key


    @staticmethod
    def exit_application() -> None:
        c.print("""\n\n[Bright_white][-] Exiting the application. Goodbye...\n\n""")
        sys.exit(0)


    def get_aes_iv(self) -> bytes:
        iv = os.urandom(16)
        return iv


    def get_all_files(self, dir_path: Path) -> list[str]:
        dirs = []
        for dir_name, sub_dirs, file_list in os.walk(dir_path):
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
        email_address = Prompt.ask("""[bright_white]
[-] Enter email address of the PGP key owner """)
        return email_address


    @staticmethod
    def get_file_path(text: str) -> Path:
        file_path = Prompt.ask(f"""[bright_white]
[-] Enter the path of the file to be {text} """)
        # file_path = "I:\\encryption\\aaa\\File_2_Folder_2_for_AES.txt"
        return Path(file_path)


    @staticmethod
    def get_folder_path(text: str) -> Path:
        folder_path = Prompt.ask(f"""[bright_white]
[-] Enter the path of the directory containing the files to be {text} """)
        # folder_path = "I:\\encryption\\aaa\\txtfiles_AES"
        return Path(folder_path)

    def get_password(self) -> str:

        password = Prompt.ask(f"""[bright_white]
[-] Enter the PASSWORD you want to use """)
        valid = Functions.validate_password(
            password=password)

        if valid != password:
            c.print("""[red]Please try again.\n""")
            Functions.get_password(self)
        else:
            c.print("""[bright_white]Your password checks out. Continuing...""")
            return str(password)


    def validate_password(self, password: str) -> str:
        symbols = [
            "!", "@", "#", "%", "&", "*", "(",
            ")", "?", "<", ">", "-", "+", "=",
            "[", "]", "~", "^", "|"
        ]
        if (len(password) < 10 or
            re.search("[0-9]", password) is None or
            re.search("[A-Z]", password) is None or
            not any(char in symbols for char in password)):
            c.print("""[red1]
Your password did not meet the minimun requirements. Please try again.\n
Your password must meet the following criteria\n
    [-] Is at least ten characters long
    [-] Contain at least one number
    [-] Contain at least one capital letter and
    [-] Contain at least one of the following symbols: \
! @ # % & * ( ) ? < > - + = [ ] ~ ^ |""")
            Functions.get_password(self)
        else:
            c.print(f"Returned `password` = {password}")

            return password


    def get_pgp_password(self) -> str:
        password = Prompt.ask("""[khaki3]
[-] Enter a password to use for the PGP private key """)
        Functions.validate_password(self, password=password)
        return password


    def hash_new_key_file(self, key_file: Path) -> str:

        sha256_hash = hashlib.sha256()
        kf = key_file

        with open(kf, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)

        return sha256_hash.hexdigest().upper()


    def load_key(self, key_file: Path) -> bytes:
        """
        Load the data from the .key file into memory to use it to either
        encrypt or decrypt a file.

        Returns the value stored in the .key file.
        """
        with open(key_file, "rb") as mykey:
            key_to_load = mykey.read()
        return key_to_load


    def no_valid_yn_option(self) -> None:
        no_valid_yn_option = c.print("""[red1]
[!] You did not enter a valid option ("y" or "n"). Please try again.""")
        return no_valid_yn_option


    @staticmethod
    def print_confirm_file_action(file_name: Path, text: str) -> None:
        file_name = Path(file_name)
        confirm = c.print(f"""[green3]
------------------------------------------
[{Functions.get_date_time()}]
** ACTION SUCCESSFUL **\n
{text} file name:
    {file_name.name}\n
{text} file was saved in directory:
    {file_name.parent}
------------------------------------------""")
        return confirm


    def print_original_files_deleted(self,
            folder_path: Path,
            action: str) -> None:

        confirm = c.print(f"""[green3]
------------------------------------------
[{Functions.get_date_time()}]
** ACTION SUCCESSFUL **\n
Files in the '{folder_path}' directory have been {action}\n
The original files HAVE BEEN DELETED
------------------------------------------""")
        return confirm


    def print_original_files_not_deleted(self,
            folder_path: Path,
            action: str) -> None:

        confirm = c.print(f"""[green3]
------------------------------------------
[{Functions.get_date_time()}]
** ACTION SUCCESSFUL **\n
Files in the '{folder_path}' directory have been {action}\n
The original files were NOT DELETED
------------------------------------------""")
        return confirm


    def write_key_hash_to_file(self,
            key_file_path: Path,
            key_file_hash_value: str) -> None:

        key_file_path = Path(key_file_path)
        key_file_hash_file = f"{key_file_path}.sha256"

        with open(key_file_hash_file, "w", encoding="utf-8") as f:
            f.write(f"""
------------------------------------------
[{Functions.get_date_time()}]
Key File Name : {key_file_path.name}\n
Key File Hash Value (SHA-256) : {key_file_hash_value}
------------------------------------------""")

        c.print(f"""[bright_white]
------------------------------------------
[{Functions.get_date_time()}]
[-] Key File hashed successfully
[-] Key File Hash verification saved in : \
'{os.path.dirname(key_file_path)}' directory
[-] Key File Hash File Name : \
'{os.path.basename(key_file_hash_file)}
[-] Key File Hash value : {key_file_hash_value}
------------------------------------------""")


    def write_to_file(self, file: typing.TextIO, message: str) -> None:
        file.write(message)


# ==================================
# XOR Functions
# ==================================


    def get_xor_key(self) -> str:
        xor_key = Prompt.ask("""[khaki3]
[-] Enter the key you want to use for the encryption """)
        return xor_key


    def get_message_to_xor(self) -> str:
        message = Prompt.ask("""[khaki3]
[-] Enter the message string you want to encrypt """)
        return message


    def get_file_to_xor(self) -> Path:
        return Path(Functions.get_file_path(self, text="you want to encrypt"))


    def get_xor_message_to_decrypt(self) -> str:
        message = Prompt.ask("""[khaki3]
[-] Enter the message string you want to decrypt """)
        return message


    def get_xor_file_to_decrypt(self) -> Path:
        return Path(Functions.get_file_path(self, text="you want to decrypt"))
