# !/usr/bin/env python3
# -*- coding: utf-8 -*-

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

import os
from rich.console import Console
from pathlib import Path
import shutil

from resources.functions import Functions

# Make the console object
console = Console()


class AESEncryptor:


    def aes_encrypt_single_file(self,
                                file_path: Path,
                                password: str) -> None:
        """Encrypt a file with a user-provided password

            Args:
                str: Path to the file to be encrypted
                str: Password used to encrypt the file

            Returns:
                file: AES-CBC encrypted file
        """

        # Convert the password string into bytes to use as a key to encrypt data
        key = Functions.encode_key(self,
                                   password=password)
        iv = Functions.get_aes_iv(self)
        mode = AES.MODE_CBC

        with open(file_path, 'rb') as f:
            orig_file_data = f.read()

        cipher = AES.new(key=key, mode=mode, iv=iv)
        cipher_data = cipher.encrypt(pad(orig_file_data, AES.block_size))
        encrypted_file_name = Path(f'{file_path}.encrypted')

        with open(encrypted_file_name, 'wb') as f:
            f.write(cipher.iv)
            f.write(cipher_data)

        Functions.print_confirm_file_action(self,
                                            file_name=encrypted_file_name,
                                            text='Encrypted')


    def aes_encrypt_multi_file(self,
                               file_to_encrypt: Path,
                               password: str) -> None:
        """Encrypt a file with a user-provided password

            Args:
                str: Path to the file to be encrypted
                str: Password used to encrypt the file

            Returns:
                file: AES-CBC encrypted file
        """
        # Convert the password string into bytes to use as a key to encrypt data
        key = Functions.encode_key(self, password=password)

        iv = Functions.get_aes_iv(self)
        mode = AES.MODE_CBC
        with open(file_to_encrypt, 'rb') as f:
            orig_file_data = f.read()
        cipher = AES.new(key=key, mode=mode, iv=iv)
        cipher_data = cipher.encrypt(pad(orig_file_data, AES.block_size))
        encrypted_file_name = Path(f'{file_to_encrypt}.encrypted')
        with open(encrypted_file_name, 'wb') as f:
            f.write(cipher.iv)
            f.write(cipher_data)



    def aes_encrypt_all_files_in_dir(self,
                                     folder_path: Path,
                                     password: str) -> None:
        console.print("""[dodger_blue1]
===========================================================
ENCRYPT FILES WITH A DIRECTORY WITH USER-PROVIDED PASSWORD
===========================================================""")

        # Turn folder path string into Path object
        f = Path(folder_path)

        dirs = Functions.get_all_files(self, folder_path=f)
        choice = Functions.confirm_delete_original_files(self)

        if choice.lower().strip() == 'y':
            for file in dirs:
                AESEncryptor.aes_encrypt_multi_file(self,
                                                    file_to_encrypt=file,
                                                    password=password)
                os.remove(file)
            console.print(f"""[green3]
==========================================
**ACTION SUCCESSFUL**\n
The following files in `{f}` were encrypted\n""")
            for file in dirs:
                console.print(
f"""[green3]{os.path.basename(
    file):34s}{'--->':7s}{os.path.basename(file)}.encrypted""")
            console.print(f"""[green3]
The original files HAVE BEEN DELETED
==========================================""")

        elif choice.lower().strip() == 'n':
            for file_to_encrypt in dirs:
                AESEncryptor.aes_encrypt_multi_file(self,
                                                    file_to_encrypt=file_to_encrypt,
                                                    password=password)
            console.print(f"""[green3]
==========================================
**ACTION SUCCESSFUL**\n
The following files in `{f}` were encrypted\n""")
            for file in dirs:
                console.print(
f"""[green3]{os.path.basename(
    file):34s}{'--->':7s}{os.path.basename(file)}.encrypted""")
            console.print(f"""[green3]
The original files HAVE NOT BEEN DELETED
==========================================""")

        else:
            Functions.no_valid_yn_option(self)
            Functions.confirm_delete_original_files(self)


    def ask_delete_original_zip(self,
                                file_to_encrypt: Path) -> None:
        delete_unencrypted_zip = console.input("""[khaki3]
[-] Do you want to delete the unencrypted .zip file (y/n)? \
[orange_red1][THIS ACTION CANNOT BE UNDONE!][khaki3] >>> """)
        if delete_unencrypted_zip.lower().strip() == 'y':
            os.remove(file_to_encrypt)
            Functions.print_confirm_file_action(self,
                                                file_name = Path(
                                                    f'{file_to_encrypt}.encrypted'),
                                                text="Encrypted")
        elif delete_unencrypted_zip.lower().strip() == 'n':
            Functions.print_confirm_file_action(self,
                                                file_name = Path(
                                                    f'{file_to_encrypt}.encrypted'),
                                                text="Encrypted")
        else:
            Functions.no_valid_yn_option(self)
            AESEncryptor.ask_delete_original_zip(self, file_to_encrypt)


    def aes_zip_files_then_encrypt(self,
                                   folder_path: Path,
                                   password: bytes) -> None:

        f = Path(folder_path)

        shutil.make_archive(
            base_name=f,
            format='zip',
            root_dir=f)
        zip_file_name = f'{f.stem}.zip'
        zip_file_to_encrypt = Path(f.parent).joinpath(f'{zip_file_name}')
        AESEncryptor.aes_encrypt_multi_file(self,
                                            file_to_encrypt=zip_file_to_encrypt,
                                            password=password)
        AESEncryptor.ask_delete_original_zip(self,
                                             file_to_encrypt=zip_file_to_encrypt)


    def aes_encrypt_files_then_zip(self,
                                   folder_path: Path,
                                   password: bytes):

        choice = Functions.confirm_delete_original_files(self)

        # Turn folder path string into Path object
        f = Path(folder_path)

        if choice.lower().strip() == 'y':

            dirs = Functions.get_all_files(self, f)
            for file in dirs:
                AESEncryptor.aes_encrypt_multi_file(self,
                                                    file_to_encrypt=file,
                                                    password=password)
                os.remove(file)
            shutil.make_archive(base_name=f,
                                format='zip',
                                root_dir=f)
            shutil.rmtree(f)
            console.print(f"""[green3]
==========================================
**ACTION SUCCESSFUL**\n
The files in the `{f}` directory have been encrypted
The output file is `{f.name}.zip`
The output file was saved in `{f.parent}`\n
The directory and the original files HAVE BEEN DELETED
==========================================""")

        elif choice.lower().strip() == 'n':

            dirs = Functions.get_all_files(self, f)
            for file in dirs:
                AESEncryptor.aes_encrypt_multi_file(self,
                                                    file_to_encrypt=file,
                                                    password=password)
            shutil.make_archive(base_name=f,
                                format='zip',
                                root_dir=f)
            console.print(f"""[green3]
==========================================
**ACTION SUCCESSFUL**\n
The files in the `{f}` directory have been encrypted
The output file is `{f.name}.zip`
The output file was saved in `{f.parent}`\n
The directory and the original files HAVE NOT BEEN DELETED
==========================================""")

        else:
            Functions.no_valid_yn_option(self)
            AESEncryptor.aes_encrypt_files_then_zip(self)
