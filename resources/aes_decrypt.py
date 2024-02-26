# !/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import os
from pathlib import Path
import sys
from rich.console import Console

from resources.functions import Functions

# Make the console object
console = Console()


class AESDecryptor:


    def aes_decrypt_file(self,
                         file_path: Path,
                         password: str,
                         mode=AES.MODE_CBC) -> None:
        console.print("""[dodger_blue1]
=================================================
DECRYPT A FILE WITH USER-PROVIDED PASSWORD (AES)
=================================================""")

        key = Functions.encode_key(self,
                                   password=password)

        file_path = Path(file_path)

        file_name = file_path.stem
        file_ext = file_path.suffix

        if file_ext == '.encrypted':
            decrypted_file = file_name
        else:
            decrypted_file = Functions.get_decrypted_file_name(
                self,
                file_path
            )

        decrypted_file = Path(decrypted_file)

        with open(file_path, 'rb') as f:
            iv = f.read(16)
            enc_file_data = f.read()

        cipher = AES.new(key=key, mode=mode, iv=iv)
        decrypted_data = unpad(
            cipher.decrypt(enc_file_data),
            AES.block_size)

        with open(decrypted_file, 'wb') as f:
            Functions.write_to_file(
                self,
                file=f,
                message=decrypted_data
            )

        Functions.print_confirm_file_action(
            self,
            file_name=decrypted_file,
            text='Decrypted'
        )


    def _return_dir_data(self,
                         folder_path: Path) -> tuple:

        dirs = Functions.get_all_files(
            self,
            folder_path=folder_path
        )
        for file_to_decrypt in dirs:
            file_name, file_ext = os.path.splitext(file_to_decrypt)
            if file_ext == '.encrypted':
                decrypted_file = file_name
            else:
                decrypted_file = f'{file_to_decrypt}.decrypted'

        return file_to_decrypt, file_ext, decrypted_file


    def _aes_decrypt_all_files(
            self,
            folder_path: Path,
            key: bytes,
            mode: str) -> None:
        file_to_decrypt = Path(
            AESDecryptor._return_dir_data(
                self,
                folder_path)[0]
            )
        decrypted_file = Path(
            AESDecryptor._return_dir_data(
                self,
                folder_path)[2])
            

        # Open the file and read the iv value and the encrypted file data
        with open(file_to_decrypt, 'rb') as f:
            iv = f.read(16)
            encrypted_data = f.read()

        cipher = AES.new(key=key, mode=mode, iv=iv)
        decrypted_data = unpad(
            cipher.decrypt(
                encrypted_data
            ), 
            AES.block_size
        )

        with open(decrypted_file, 'wb') as f:
            Functions.write_to_file(
                self,
                file=f,
                message=decrypted_data
            )


    def aes_decrypt_all_files_in_dir(
            self,
            folder_path: Path,
            password: str,
            mode=AES.MODE_CBC) -> None:
        console.print("""[dodger_blue1]
=============================================
DECRYPT FILES IN FOLDER USING PASSWORD (AES)
=============================================""")

        dirs = Functions.get_all_files(
            self,
            folder_path=folder_path
        )
        key = Functions.encode_key(
            self,
            password=password
        )
        # ASK USER IF THEY WANT TO DELETE THE ORIGINAL ENCRYPTED FILES
        delete_encrypted_files = Functions.ask_delete_original_enc_files(self)

        # IF USER CHOOSES `N` THE ORIGINALS FILES **NOT** DELETED
        if delete_encrypted_files.lower().strip() == 'n':
            AESDecryptor._aes_decrypt_all_files(
                self,
                folder_path=dirs,
                key=key,
                mode=mode
            )
            Functions.print_original_files_not_deleted(
                self,
                folder_path,
                action='decrypted'
            )
        # IF THE USER CHOOSES `Y` WILL DELETE ORIGINAL FILES
        elif delete_encrypted_files.lower().strip() == 'y':
            file_ext = AESDecryptor._return_dir_data(
                self, 
                folder_path)[1]
            for file_to_decrypt in dirs:
                if file_ext == '.encrypted':
                    os.remove(file_to_decrypt)
            Functions.print_original_files_deleted(
                self,
                folder_path,
                action='decrypted'
            )
        else:
            # THE USER DID NOT CHOOSE EITHER `Y` OR `N`
            Functions.no_valid_yn_option(self)
            sys.exit(0)
