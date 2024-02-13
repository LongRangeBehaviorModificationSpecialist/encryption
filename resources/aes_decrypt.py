# !/usr/bin/env python3
# -*- coding: utf-8 -*-

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import os
from pathlib import Path
import sys
from rich.console import Console

from resources.functions import Functions
from vars import (password, aes_file_to_decrypt, aes_folder)

# Make the console object
console = Console()


class AESDecryptor:

    @Functions.timeit
    def aes_decrypt_file(self, mode=AES.MODE_CBC) -> None:
        console.print("""[dodger_blue1]
=================================================
DECRYPT A FILE WITH USER-PROVIDED PASSWORD (AES)
=================================================""")

        # password = Functions.get_aes_decryption_password(self).encode()
        # key = hashlib.sha256(password).digest()
        key = Functions.encode_key(self, password=password)

        # aes_file_to_decrypt = Functions.get_file_path(
        #     self,
        #     text='DECRYPT')
        # aes_file_to_decrypt = Path(aes_file_to_decrypt)

        file_name = aes_file_to_decrypt.stem
        file_ext = aes_file_to_decrypt.suffix

        if file_ext == '.encrypted':
            decrypted_file_name = file_name
        else:
            decrypted_file_name = Functions.get_decrypted_file_name(self,
                                                                aes_file_to_decrypt)

        decrypted_file_name = Path(decrypted_file_name)

        with open(aes_file_to_decrypt, 'rb') as f:
            iv = f.read(16)
            enc_file_data = f.read()

        cipher = AES.new(key=key, mode=mode, iv=iv)
        decrypted_data = unpad(
            cipher.decrypt(enc_file_data),
            AES.block_size)

        with open(decrypted_file_name, 'wb') as f:
            f.write(decrypted_data)

        Functions.print_confirm_file_action(self,
                                        file_name=decrypted_file_name,
                                        text="Decrypted")


    def _return_dir_data(self, folder_path: Path) -> tuple:
        dirs = Functions.get_all_files(self, folder_path)
        for file_to_decrypt in dirs:
            file_name, file_ext = os.path.splitext(file_to_decrypt)
            if file_ext == '.encrypted':
                decrypted_file_name = file_name
            else:
                decrypted_file_name = f'{file_to_decrypt}.decrypted'
        return file_to_decrypt, file_ext, decrypted_file_name


    def _aes_decrypt_all_files(self,
                               folder_path: Path,
                               key: bytes,
                               mode: str) -> None:
        file_to_decrypt = Path(
            AESDecryptor._return_dir_data(self, folder_path)[0])
        decrypted_file_name = Path(
            AESDecryptor._return_dir_data(self, folder_path)[2])

        # Open the file and read the iv value and the encrypted file data
        with open(file_to_decrypt, 'rb') as f:
            iv = f.read(16)
            enc_file_data = f.read()

        cipher = AES.new(key=key, mode=mode, iv=iv)
        clear_file_data = unpad(cipher.decrypt(enc_file_data), AES.block_size)

        with open(decrypted_file_name, 'wb') as f:
            f.write(clear_file_data)


    @Functions.timeit
    def aes_decrypt_all_files_in_dir(self, mode=AES.MODE_CBC):
        console.print("""[dodger_blue1]
=============================================
DECRYPT FILES IN FOLDER USING PASSWORD (AES)
=============================================""")

        # aes_folder = Functions.get_folder_path(
        #     self,
        #     text='containing the files to be decrypted')
        # aes_folder = 'I:\\encryption\\aaa\\txtfiles_AES'

        dirs = Functions.get_all_files(self, aes_folder)

        # password = Functions.get_aes_encryption_password(self).encode()
        # password = 'mysecretpassword34'.encode()

        # key = hashlib.sha256(password.encode()).digest()
        key = Functions.encode_key(self, password=password)


        # ASK USER IF THEY WANT TO DELETE THE ORIGINAL ENCRYPTED FILES
        delete_original_enc_files = Functions.ask_delete_original_enc_files(self)

        # IF USER CHOOSES `N` THE ORIGINALS FILES **NOT** DELETED
        if delete_original_enc_files.lower().strip() == 'n':
            AESDecryptor._aes_decrypt_all_files(self,
                                                dirs=dirs,
                                                key=key,
                                                mode=mode)
            Functions.print_original_files_not_deleted(self,
                                                   aes_folder,
                                                   action='decrypted')

        # IF THE USER CHOOSES `Y` WILL DELETE ORIGINAL FILES
        elif delete_original_enc_files.lower().strip() == 'y':
            file_ext = AESDecryptor._return_dir_data(self, aes_folder)[1]
            for file_to_decrypt in dirs:
                if file_ext == '.encrypted':
                    os.remove(file_to_decrypt)
            Functions.print_original_files_deleted(self,
                                               aes_folder,
                                               action='decrypted')

        else:
            # THE USER DID NOT CHOOSE EITHER `Y` OR `N`
            Functions.no_valid_yn_option(self)
            sys.exit(0)
