# !/usr/bin/env python3

import binascii
from rich.console import Console
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
            c.print(f'''[dodger_blue1]
Operation [ {func.__name__}() ] was completed in \
{total_time:.4f} seconds''')
            # c.print(f"\nFunction {func.__name__}{args} {kwargs} Took {total_time:.4f} seconds")
            return result
        return timeit_wrapper


    def ask_delete_original_enc_files(self) -> str:
        ask_delete_original_enc_files = c.input('''[khaki3]
[-] Do you want to delete the original encrypted files from the directory \
after decryption (y/n)? >>> ''')
        return ask_delete_original_enc_files


    def clear_screen(self) -> None:
        os.system('cls' if os.name == 'nt' else 'clear')


    def confirm_delete_original_files(self) -> str:
        confirm_delete_originals = c.input('''[khaki3]
[-] Do you want to delete the original files after they are encrypted (y/n)? \
[orange_red1][THIS ACTION CANNOT BE UNDONE!][khaki3] >>> ''')
        return confirm_delete_originals


    def encode_key(self, password: str) -> bytes:
        pswd_hash = hashlib.sha256(
            password.encode('utf-8')).hexdigest()
        # Convert the sha-256 value of the password string to a byte string
        key = binascii.unhexlify(pswd_hash)
        return key


    def exit_application(self) -> None:
        c.print('''[dodger_blue1]>>> Exiting the application. Goodbye...''')
        sys.exit(0)


    def get_aes_iv(self) -> bytes:
        iv = os.urandom(16)
        return iv


    def get_all_files(self, folder_path: Path) -> list[str]:
        dirs = []
        for dir_name, sub_dirs, file_list in os.walk(folder_path):
            for file in file_list:
                dirs.append(dir_name + '\\' + file)
        return dirs


    def get_date_time(self) -> str:
        t = time.localtime()
        current_time = time.strftime('%Y%m%d %H%M%S', t)
        return current_time


    def get_decrypted_file_name(self, file_to_decrypt: Path) -> Path:
        decrypted_file_name = f'{file_to_decrypt}.decrypted'
        return Path(decrypted_file_name)


    def get_email_address(self) -> str:
        email_address = c.input('''[khaki3]
[-] Enter email address of the PGP key owner
>>> ''')
        return email_address


    def get_encrypted_file_name(self, file_path: Path) -> Path:
        encrypted_file = f'{file_path}.encrypted'
        return Path(encrypted_file)


    def get_file_path(self, text: str) -> Path:
        file_path = c.input(f'''[khaki3]
[-] Enter the path of the file to be {text}
>>> ''')
        # file_path = 'I:\\encryption\\aaa\\File_2_Folder_2_for_AES.txt'
        return Path(file_path)


    def get_folder_path(self, text: str) -> Path:
        folder_path = c.input(f'''[khaki3]
[-] Enter the path of the directory containing the files to be {text}
>>> ''')
        # folder_path = 'I:\\encryption\\aaa\\txtfiles_AES'
        return Path(folder_path)


    def get_key_file_path(self) -> Path:
        key_file = c.input('''[khaki3]
[-] Enter the path to the KEY FILE you want to use
>>> ''')
        # key_file = 'I:\\encryption\\aaa\\2024-01-24_105425_key.key'
        return Path(key_file)


    def get_password(self) -> str:
        password = c.input(f'''[khaki3]
[-] Enter the PASSWORD you want to use >>> ''')
        valid = Functions.validate_password(self,
            password=password)
        if valid != password:
            c.print('''[blue]Please try again.\n''')
            Functions.get_password(self)
        else:
            c.print('''[khaki3]Your password checks out. Continuing...''')
            return str(password)


    def validate_password(self, password: str) -> str:
        symbols = [
            '!', '@', '#', '%', '&', '*', '(',
            ')', '?', '<', '>', '-', '+', '=',
            '[', ']', '~', '^', '|'
        ]
        if (len(password) < 10 or
            re.search('[0-9]', password) is None or
            re.search('[A-Z]', password) is None or
            not any(char in symbols for char in password)):
            c.print('''[red1]
Your password did not meet the minimun requirements. Please try again.\n
Your password must meet the following criteria\n
  [-] Is at least ten characters long
  [-] Contain at least one number
  [-] Contain at least one capital letter and
  [-] Contain at least one of the following symbols: \
! @ # % & * ( ) ? < > - + = [ ] ~ ^ |''')
            Functions.get_password(self)
        else:
<<<<<<< HEAD
            c.print(f"Returned `password` = {password}")
=======
            print(f'Returned `password` = {password}')
>>>>>>> 1503b9bc772601ae7213d5816e7b7da8d871e09c
            return password


    def get_pgp_password(self) -> str:
        password = c.input('''[khaki3]
[-] Enter a password to use for the PGP private key
>>> ''')
        Functions.validate_password(self,password=password)
        return password


    def hash_new_key_file(self, new_key_file: Path) -> str:
        sha256_hash = hashlib.sha256()
        kf = new_key_file
        with open(kf, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b''):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest().upper()


    def load_key(self, key_file: Path) -> bytes:
        '''Load the data from the .key file into memory to use it to either
        encrypt or decrypt a file.

        Returns the value stored in the .key file.
        '''
        with open(key_file, 'rb') as mykey:
            key_to_load = mykey.read()
        return key_to_load


    def no_valid_yn_option(self) -> None:
        no_valid_yn_option = c.print('''[red1]
!!! You did not enter a valid option. The valid options are either 'y' OR \
'n'. Please try again.''')
        return no_valid_yn_option


    def print_confirm_file_action(self,
                                  file_name: Path,
                                  text: str) -> None:
        confirm = c.print(f'''[green3]
==========================================
**ACTION SUCCESSFUL**\n
{text} file name:
  {file_name.name}\n
{text} file was saved in directory:
  {file_name.parent}
==========================================''')
        return confirm


    def print_original_files_deleted(self,
                                     folder_path: Path,
                                     action: str) -> None:
        confirm = c.print(f'''[green3]
==========================================
**ACTION SUCCESSFUL**\n
Files in the `{folder_path}` directory have been {action}\n
The original files HAVE BEEN DELETED
==========================================''')
        return confirm


    def print_original_files_not_deleted(self,
                                         folder_path: Path,
                                         action: str) -> None:
        confirm = c.print(f'''[green3]
==========================================
**ACTION SUCCESSFUL**\n
Files in the `{folder_path}` directory have been {action}\n
The original files were NOT DELETED
==========================================''')
        return confirm


    def write_hash_to_file(self,
                           key_file_path: Path,
                           key_file_hash_value: str) -> None:
        key_file_path = Path(key_file_path)
        key_file_hash_file = f'{key_file_path}.sha256'
        with open(key_file_hash_file, 'w', encoding='utf-8') as f:
            f.write(f'''Key File Name: {key_file_path.name}\n
Key File Hash Value (SHA-256): {key_file_hash_value}''')
        c.print(f'''[bright_white]
[{Functions.get_date_time(self)}] Key File hashed successfully
[{Functions.get_date_time(self)}] Key File Hash verification saved in \
`{os.path.dirname(key_file_path)}` directory
[{Functions.get_date_time(self)}] Key File Hash File Name \
`{os.path.basename(key_file_hash_file)}`
[{Functions.get_date_time(self)}] Key File Hash value: {key_file_hash_value}''')


    def write_to_file(self,
                      file: typing.TextIO,
                      message: str) -> None:
        file.write(message)


# ==================================
# XOR Functions
# ==================================


    def get_xor_key(self) -> str:
        xor_key = c.input('''[khaki3]
Enter the key you want to use for the encryption >>> ''')
        return xor_key


    def get_message_to_xor(self) -> str:
        message = c.input('''[khaki3]
Enter the message string you want to encrypt
>>> ''')
        return message


    def get_file_to_xor(self) -> Path:
        file_path = Functions.get_file_path(self,
            text='you want to encrypt')
        return Path(file_path)


    def get_xor_message_to_decrypt(self) -> str:
        message = c.input('''[khaki3]
Enter the message string you want to decrypt
>>> ''')
        return message


    def get_xor_file_to_decrypt(self) -> str:
        file_path = Functions.get_file_path(self,
            text='you want to decrypt')
        return file_path
