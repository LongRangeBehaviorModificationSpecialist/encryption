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

#         # password = Functions.get_aes_encryption_password(self)
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


    # def get_key(self) -> bytes:
    #     pswd_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    #     # Convert the sha-256 value of the password string to a byte string
    #     key = binascii.unhexlify(pswd_hash)
    #     return key


    def aes_gcm_decrypt_file(self) -> None:

        # encrypted_file_path = Functions.get_folder_path(
        #     self,
        #     text='containing the files to be decrypted')
        # encrypted_file_path = 'L:\\encryption\\aaa\\Falcon_OneDrive_Backup.py.encrypted'
        key = Functions.encode_key(self, password=password)

        with open(gcm_file_to_decrypt, 'rb') as encrypted_file:
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
        decrypted_file = gcm_file_to_decrypt[:-10]

        with open(decrypted_file, 'wb') as decrypted_file:
            decrypted_file.write(plaintext)
        console.print("""[green3]
>>> File decrypted successfully. Thank you. Come again.""")
        return decrypted_file


    def aes_gcm_decrypt_directory(self) -> None:

        # gcm_folder_path = Functions.get_folder_path(
        #     self,
        #     text='containing the files to be decrypted')
        # gcm_folder_path = 'L:\\encryption\\aaa\\txtfiles02'
        key = AESGCMDataDecryptor.get_key(self)

        f = Path(gcm_folder_path)

        dirs = Functions.get_all_files(self, f)
        for file in dirs:
            if file.endswith('.encrypted'):
                AESGCMDataDecryptor.aes_gcm_decrypt_file(self,
                                                         encrypted_file_path=f,
                                                         key=key)

#     def aes_gcm_decrypt_file(self):

#         # URL: https://pycryptodome.readthedocs.io/en/latest/src/cipher/modern.html#eax-mode
