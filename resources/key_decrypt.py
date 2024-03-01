# !/usr/bin/env python3

from cryptography.fernet import Fernet
import os
from pathlib import Path
from rich.console import Console
from rich import print

from resources.functions import Functions

# Make the console object
console = Console()


class KeyFileDecryptor:

    @Functions.timeit
    def decrypt_file_with_key(self,
                              key_file: Path,
                              file_path: Path) -> None:
        '''Decrypts a file using a provided .key file

            Args:
                str: Path to the key_file
                str: Path of the file to be decrypted

            Returns:
                file: Decrypted file in the same directory as the original
                      file
        '''
        print('''[dodger_blue1]
=======================================
DECRYPT A FILE USING A KNOWN .KEY FILE
=======================================''')

        key_to_load = Functions.load_key(self, key_file=key_file)
        f = Fernet(key_to_load)

        print(f'''[bright_white]
[{Functions.get_date_time(self)}] Key file: \
`{os.path.basename(key_file)}` loaded successfully''')

        file_name, file_ext = os.path.splitext(file_path)

        if file_ext == '.encrypted':
            decrypted_file = Path(file_name)
        else:
            decrypted_file = Functions.get_decrypted_file_name(self,
                file_path)

        with open(file_path, 'rb') as ef:
            encrypted_data = ef.read()

        decrypted_data = f.decrypt(encrypted_data)

        with open(decrypted_file, 'wb') as df:
            Functions.write_to_file(self, file=df, message=decrypted_data)

        Functions.print_confirm_file_action(self,
            file_name=decrypted_file,
            text='Decryption')


    def decrypt_files_in_folder_with_key(self,
                                         key_file: Path,
                                         folder_path: Path) -> None:
        print('''[dodger_blue1]
=====================================================
DECRYPT FILES IN A DIRECTORY USING A KNOWN .KEY FILE
=====================================================''')

        key_to_load = Functions.load_key(self, key_file=key_file)
        f = Fernet(key_to_load)

        dirs = Functions.get_all_files(self, folder_path=folder_path)

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
                Functions.write_to_file(self,
                    file=df,
                    message=decrypted_data)

        # ASK USER IF THEY WANT TO DELETE THE ORIGINAL ENCRYPTED FILES
        delete_original_enc_files = Functions.ask_delete_original_enc_files(self)

        # IF USER CHOOSES 'NO', THE ORIGINALS FILES **NOT** DELETED
        if delete_original_enc_files.lower().strip() == 'n':
            Functions.print_original_files_not_deleted(self,
                folder_path,
                action='decrypted')

        # IF THE USER CHOOSES 'YES', THIS WILL DELETE ORIGINAL FILES
        elif delete_original_enc_files.lower().strip() == 'y':
            for file in dirs:
                if file_ext == '.encrypted':
                    os.remove(file)
            Functions.print_original_files_deleted(self,
                folder_path,
                action='decrypted')

        # IF THE USER DID NOT CHOOSE EITHER `Y` OR `N`
        else:
            Functions.no_valid_yn_option(self)
            KeyFileDecryptor.decrypt_files_in_folder_with_key(self)
