# !/usr/bin/env python3
# -*- coding: utf-8 -*-

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from rich.console import Console
from pathlib import Path

from resources.functions import Functions
from vars import password, gcm_folder_path, gcm_file_to_decrypt

# Make the console object
console = Console()


class AESGCMDataDecryptor:

#     def aes_gcm_decryptor(self) -> None:
#         choice = console.input("""[khaki3]
# =================
# Choose an option
# =================[bright_white]\n
# 1)  Decrypt a single file using a password
# 2)  Decrypt all files in a directory using a password\n
# R)  Return to the main menu
# Q)  Quit the application[bold khaki3]\n
# ENTER CHOICE >>> """)

#         # password = Functions.get_password(self)
#         # password = 'mysecretpassword34'

#         pswd_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
#         # Convert the sha-256 value of the password string to a byte string
#         key = binascii.unhexlify(pswd_hash)

#         if choice.strip() == '1':
#             AESGCMDataDecryptor.aes_gcm_decrypt_file(self,
#                                                      key=key)
#         elif choice.strip() == '2':
#             AESGCMDataDecryptor.aes_gcm_decrypt_directory(self,
#                                                           key=key)
#         elif choice.strip().lower() == 'r':
#             pass
#         elif choice.strip().lower() == 'q':
#             Functions.exit_application(self)
#         else:
#             console.print("""[bold red1]!!! You did not enter a valid option. Try again.""")
#             AESGCMDataDecryptor.aes_gcm_decryptor(self)


    def aes_gcm_decrypt_file(self,
                             file_path: Path,
                             password: str) -> None:

        key = Functions.encode_key(self,
                                   password=password)

        file = Path(file_path)

        with open(file, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()

        iv = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        # Remove the '.encrypted' file extension
        if file.endswith('.encrypted'):
            decrypted_file = file[:-10]
        else:
            decrypted_file = f'{file}.decrypted'

        with open(decrypted_file, 'wb') as decrypted_file:
            decrypted_file.write(plaintext)
        console.print("""[green3]
>>> File decrypted successfully. Thank you. Come again.""")
        return decrypted_file


    def aes_gcm_decrypt_directory(self,
                                  folder_path: Path,
                                  password: str) -> None:

        f = Path(folder_path)

        dirs = Functions.get_all_files(self, f)
        for file in dirs:
            if file.endswith('.encrypted'):
                AESGCMDataDecryptor.aes_gcm_decrypt_file(self,
                                                         file_path=file,
                                                         password=password)

#     def aes_gcm_decrypt_file(self):

#         # URL: https://pycryptodome.readthedocs.io/en/latest/src/cipher/modern.html#eax-mode
