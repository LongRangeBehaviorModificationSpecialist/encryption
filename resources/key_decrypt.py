# !/usr/bin/env python3
# -*- coding: utf-8 -*-

from cryptography.fernet import Fernet
import os
from pathlib import Path
from rich.console import Console

from resources.functions import Functions
from vars import (key_file,
                  folder_path_for_key_test,
                  file_to_decrypt_with_key)

# Make the console object
console = Console()


class KeyFileDecryptor:

    @Functions.timeit
    def decrypt_file_with_key(self):
        """Decrypts a file using a provided .key file

            Args:
                str: Path to the key_file
                str: Path of the file to be decrypted

            Returns:
                file: Decrypted file in the same directory as the original file
        """
        console.print("""[dodger_blue1]
=======================================
DECRYPT A FILE USING A KNOWN .KEY FILE
=======================================""")

        # key_file = Functions.get_key_file_path(self)

        key_to_load = Functions.load_key(self, key_file)
        f = Fernet(key_to_load)

        console.print(f"""[bright_white]
[{Functions.get_date_time(self)}] Key file: \
`{os.path.basename(key_file)}` loaded successfully""")

        # file_to_decrypt_with_key = Functions.get_file_path(
        #     self,
        #     text='DECRYPT')

        file_name, file_ext = os.path.splitext(file_to_decrypt_with_key)
        if file_ext == '.encrypted':
            decrypted_file_name = Path(file_name)
        else:
            decrypted_file_name = Functions.get_decrypted_file_name(self,
                                                                    file_to_decrypt_with_key)

        with open(file_to_decrypt_with_key, 'rb') as ef:
            encrypted_data = ef.read()
        decrypted_data = f.decrypt(encrypted_data)
        with open(decrypted_file_name, 'wb') as df:
            df.write(decrypted_data)

        Functions.print_confirm_file_action(self,
                                            file_name=decrypted_file_name,
                                            text="Decryption")


    @Functions.timeit
    def decrypt_all_files_in_folder_with_key(self):
        console.print("""[dodger_blue1]
=====================================================
DECRYPT FILES IN A DIRECTORY USING A KNOWN .KEY FILE
=====================================================""")

        # key_file = Functions.get_key_file_path(self)
        # key_file = 'L:\\encryption\\aaa\\2024-01-24_105425_key.key'

        key_to_load = Functions.load_key(self, key_file)
        f = Fernet(key_to_load)

        # folder_path = Functions.get_folder_path(
        #     self,
        #     text='containing the files to be decrypted')
        # folder_path = 'L:\\encryption\\aaa\\txtfiles02'

        dirs = Functions.get_all_files(self, folder_path_for_key_test)
        for file in dirs:
            file_name, file_ext = os.path.splitext(file)

            if file_ext == '.encrypted':
                decrypted_file_name = file_name
            else:
                decrypted_file_name = f'{file}.decrypted'

            with open(file, 'rb') as ef:
                encrypted_data = ef.read()

            decrypted_data = f.decrypt(encrypted_data)

            with open(decrypted_file_name, 'wb') as df:
                df.write(decrypted_data)

        # ASK USER IF THEY WANT TO DELETE THE ORIGINAL ENCRYPTED FILES
        delete_original_enc_files = Functions.ask_delete_original_enc_files(self)

        # IF USER CHOOSES `NO`, THE ORIGINALS FILES **NOT** DELETED
        if delete_original_enc_files.lower().strip() == 'n':
            Functions.print_original_files_not_deleted(self,
                                                       folder_path_for_key_test,
                                                       action='decrypted')

        # IF THE USER CHOOSES `YES` WILL DELETE ORIGINAL FILES
        elif delete_original_enc_files.lower().strip() == 'y':
            for file in dirs:
                if file_ext == '.encrypted':
                    os.remove(file)
            Functions.print_original_files_deleted(self,
                                                   folder_path_for_key_test,
                                                   action='decrypted')

        # IF THE USER DID NOT CHOOSE EITHER `Y` OR `N`
        else:
            Functions.no_valid_yn_option(self)
            KeyFileDecryptor.decrypt_all_files_in_folder_with_key(self)