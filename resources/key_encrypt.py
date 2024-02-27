# !/usr/bin/env python3
# -*- coding: utf-8 -*-

from cryptography.fernet import Fernet
from datetime import datetime
import os
from pathlib import Path
from rich.console import Console

from resources.functions import Functions
from vars import (key_file,
                  file_for_key_test,
                  file_for_new_key_test,
                  folder_path_for_key_test)

# Make the console object
console = Console()


class KeyFileEncryptor:


    def generate_new_key_file(self,
                              key_file_path: Path) -> str:
        """Generate a new key file (with the date & time appended to the file
        name) to be used to encrypt the message or file of the user's choice

            Args:
                key_file_path (str): path to new .key file that was created

            Returns:
                file (str): new .key file used to encrypt a message or file
        """
        now = datetime.now()
        dt = now.strftime('%Y%m%d_%H%M%S')
        key = Fernet.generate_key()
        key_file_name = Path(f'{key_file_path}').joinpath(f'{dt}_key.key')
        with open(key_file_name, 'wb') as f:
            Functions.write_to_file(
                self,
                file=f,
                message=key
            )
        key_file_hash_value = Functions.hash_new_key_file(
            self,
            new_key_file=key_file_name
        )
        console.print(f"""[bright_white]
[{Functions.get_date_time(self)}] Key File created successfully
[{Functions.get_date_time(self)}] Key File saved in `{key_file_path}` directory
[{Functions.get_date_time(self)}] Key File Name: {os.path.basename(key_file_name)}"""
        )
        Functions.write_hash_to_file(
            self,
            key_file_name,
            key_file_hash_value
        )
        return key_file_name


    def get_key_data_to_encrypt_file(self,
                                     key_file: Path,
                                     file_path: Path) -> None:

        key_to_load = Functions.load_key(
            self,
            key_file=key_file
        )
        key = Fernet(key_to_load)

        console.print(f"""[blue]
[{Functions.get_date_time(self)}] [bright_white]Key file \
`{os.path.basename(key_file)}` loaded successfully"""
        )

        encrypted_file = Functions.get_encrypted_file_name(
            self,
            file_path=file_path
        )
        KeyFileEncryptor.encrypt_file_with_key(
            self,
            key=key,
            file_to_encrypt=file_path,
            encrypted_file=encrypted_file
        )


    def encrypt_file_with_new_key(self,
                                  file_path: Path) -> None:
        """Generate a new .key file which will be saved in the same directory
        as the file to be encrypted

        Args:
            str: Path to .key file used to encrypt the file
            str: Path to file to be encrypted

        Returns:
            file: Encrypted file
        """
        console.print("""[dodger_blue1]
=============================================
ENCRYPT A FILE USING NEWLY CREATED .KEY FILE
============================================="""
        )

        # file_path = Functions.get_file_path(self, text='ENCRYPT')
        # file_path = 'I:\\encryption\\aaa\\Falcon_OneDrive_Backup.py'

        encrypted_file = Functions.get_encrypted_file_name(
            self,
            file_path=file_path
        )
        # Get the directory in which the file to be decrypted is stored
        key_file_path = file_path.parent
        # Generate a new encryption key
        key_file = KeyFileEncryptor.generate_new_key_file(
            self,
            key_file_path=key_file_path
        )
        key_to_load = Functions.load_key(
            self,
            key_file=key_file
        )
        key = Fernet(key_to_load)
        # Run the function to encrypt the file with the newly created .key
        KeyFileEncryptor.encrypt_file_with_key(
            self,
            key=key,
            file_to_encrypt=file_path,
            encrypted_file=encrypted_file
        )


    def encrypt_file_with_key(self,
                              key: str,
                              file_to_encrypt: str,
                              encrypted_file: str) -> None:
        """Encrypts a file using a provided .key

            Args:
                str: Path to the .key file to be used for encryption
                str: Path of the file to be encrypted

            Returns:
                file: Encrypted file in the same directory as the original file
        """
        with open(file_to_encrypt, 'rb') as of:
            original_data = of.read()

        encrypted_data = key.encrypt(original_data)

        with open(encrypted_file, 'wb') as f:
            Functions.write_to_file(
                self,
                file=f,
                message=encrypted_data
            )

        Functions.print_confirm_file_action(
            self,
            file_name=encrypted_file,
            text='Encrypted'
        )


    #TODO: Print list of files to be encrypted to the console
    def encrypt_files_in_dir_with_key(self,
                                      key_file: Path,
                                      folder_path: Path) -> None:
        while True:
            console.print("""[dodger_blue1]
=====================================================
ENCRYPT FILES IN A DIRECTORY USING A KNOWN .KEY FILE
====================================================="""
            )

            key_to_load = Functions.load_key(
                self,
                key_file=key_file
            )
            key = Fernet(key_to_load)

            delete_choice = Functions.confirm_delete_original_files(self)

            dirs = Functions.get_all_files(
                self,
                folder_path=folder_path
            )
            for file in dirs:
                with open(file, 'rb') as original_file:
                    original_file_data = original_file.read()
                encrypted_data = key.encrypt(original_file_data)
                with open(f'{file}.encrypted', 'wb') as encrypted_file:
                    Functions.write_to_file(
                        self,
                        file=encrypted_file,
                        message=encrypted_data
                    )

            if delete_choice.lower().strip() == 'y':
                for file in dirs:
                    os.remove(file)
                Functions.print_original_files_deleted(
                    self,
                    folder_path=folder_path,
                    action='ENCRYPTED'
                )
                return False

            elif delete_choice.lower().strip() == 'n':
                Functions.print_original_files_not_deleted(
                    self,
                    folder_path=folder_path,
                    action='ENCRYPTED'
                )
                return False

            else:
                Functions.no_valid_yn_option(self)
                KeyFileEncryptor.encrypt_files_in_dir_with_key(self)
