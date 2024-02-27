# !/usr/bin/env python3

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from rich.console import Console
from pathlib import Path

from resources.functions import Functions

# Make the console object
console = Console()


class AESGCMDataDecryptor:


    def aes_gcm_decrypt_file(self,
                             file_path: Path,
                             password: str) -> None:

        key = Functions.encode_key(
            self,
            password=password
        )

        file = Path(file_path)

        with open(file, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()

        iv = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        # Remove the '.encrypted' file extension
        if file.endswith('.encrypted'):
            decrypted_file = file[:-10]
        else:
            decrypted_file = f'{file}.decrypted'

        with open(decrypted_file, 'wb') as f:
            Functions.write_to_file(
                self,
                file=f,
                message=decrypted_data
            )
        console.print('''[green3]
>>> File decrypted successfully. Thank you. Come again.''')
        return decrypted_file


    def aes_gcm_decrypt_directory(self,
                                  folder_path: Path,
                                  password: str) -> None:
        f = Path(folder_path)
        dirs = Functions.get_all_files(
            self,
            folder_path=f
        )
        for file in dirs:
            if file.endswith('.encrypted'):
                AESGCMDataDecryptor.aes_gcm_decrypt_file(
                    self,
                    file_path=file,
                    password=password
                )
