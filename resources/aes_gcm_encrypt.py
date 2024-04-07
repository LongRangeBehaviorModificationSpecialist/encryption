# !/usr/bin/env python3

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from pathlib import Path
from rich.console import Console

from resources.functions import Functions


# Make the console object
c = Console()


class AESGCMDataEncryptor:
    '''Keep the encryption key secure as it will be needed for decryption.
    Also, this program overwrites the original files with encrypted content.
    Make sure to have proper backups before running it.
    '''

    def aes_gcm_encrypt_file(self,
                             file_path: Path,
                             password: str) -> None:
        '''Encrypts a single file using AES GCM encryption.'''

        key = Functions.encode_key(self, password=password)

        with open(file_path, 'rb') as f:
            plaintext = f.read()

        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        encrypted_file = Path(f'{file_path}.encrypted')

        with open(encrypted_file, 'wb') as f:
            f.write(iv + encryptor.tag + ciphertext)

        c.print(f'''[green3]
{file_path.name:34s}{'->':7s}{encrypted_file.name}
{'':34s}{'':7s}iv: {iv.hex().upper()}
{'':34s}{'':7s}tag: {encryptor.tag.hex().upper()}
{'':34s}{'':7s}cipherText: {ciphertext[0:16]}...''')

        return f


    def aes_gcm_encrypt_directory(self,
                                  folder_path: Path,
                                  password: str) -> None:
        '''Encrypts all files in a directory using AES GCM encryption.'''

        choice = Functions.confirm_delete_original_files(self)
        choice = choice.lower().strip()

        dirs = Functions.get_all_files(self, folder_path=folder_path)

        for file in dirs:
            file = Path(file)
            AESGCMDataEncryptor.aes_gcm_encrypt_file(self,
                file_path=file,
                password=password)

        if choice == 'y':
            # Optionally, you can remove the original file
            for file in dirs:
                os.remove(file)
            Functions.print_original_files_deleted(self,
                folder_path=folder_path,
                action='ENCRYPTED')

        elif choice == 'n':
            Functions.print_original_files_not_deleted(self,
                folder_path=folder_path,
                action='ENCRYPTED')

        else:
            Functions.no_valid_yn_option(self)
            AESGCMDataEncryptor.aes_gcm_encrypt_directory(self)
