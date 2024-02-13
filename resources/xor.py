# !/usr/bin/env python3
# -*- coding: utf-8 -*-

from rich.console import Console
from pathlib import Path

from resources.functions import Functions

# Make the console object
console = Console()

class XOREncryption:


    def get_xor_key_to_encrypt(self) -> str:
#         xor_key = console.input("""[khaki3]
# Enter the key you want to use for the encryption:
# >>> """)
        xor_key = '12345'
        return xor_key


    def get_message_to_xor(self) -> str:
#         message = console.input("""[khaki3]
# Enter the message string you want to encrypt:
# >>> """)
        message = 'This is a super secret message. The launch code is: 456F8A1C453EF92BEFAA23.'
        xor_key = XOREncryption.get_xor_key_to_encrypt(self)
        XOREncryption.encrypt_msg_with_xor(self,
                                           message=message,
                                           xor_key=xor_key)


    def get_file_to_xor(self) -> str:
        # file = Functions.get_file_path(self, text='you want to encrypt')
        file = r'C:\Users\mikes\Desktop\encryption\aaa\test_for_XOR.py'
        xor_key = XOREncryption.get_xor_key_to_encrypt(self)
        XOREncryption.encrypt_file_with_xor(self,
                                            file=file,
                                            xor_key=xor_key)


    def encrypt_msg_with_xor(self,
                             message: str,
                             xor_key: str) -> None:
        encrypted_text = ''
        xor_enc_msg_file = 'C:\\Users\\mikes\\Desktop\\encryption\\aaa\\xor_enc_msg.txt'

        for i in range(len(message)):
            c = message[i]
            key_to_encrypt = xor_key[i % len(xor_key)]
            encrypted_text += chr(ord(c) ^ ord(key_to_encrypt))

        with open(xor_enc_msg_file, 'w') as f:
            f.write(encrypted_text)

        console.print(f"""[green3]
==========================================
**ACTION SUCCESSFUL**\n
The encrypted message is:\n
    [bright_white]{encrypted_text}[green3]\n
==========================================""")


    def encrypt_file_with_xor(self,
                              file: Path,
                              xor_key: str) -> None:
        encrypted_data = ''
        file = Path(file)
        xor_enc_file = f'{file}.encrypted'

        with open(file, 'r') as f:
            plain_text = f.read()
            for i in range(len(plain_text)):
                c = plain_text[i]
                key_to_encrypt = xor_key[i % len(xor_key)]
                encrypted_data += chr(ord(c) ^ ord(key_to_encrypt))

        with open(xor_enc_file, 'w', encoding='utf-8') as f:
            f.write(encrypted_data)

        console.print("""[green3]
==========================================
**ACTION SUCCESSFUL**\n
File Encrypted with XOR key
==========================================""")


class XORDecryption:


    def get_xor_key_to_decrypt(self) -> str:
#         xor_key = console.input("""[khaki3]
# Enter the key to decrypt the message:
# >>> """)
        xor_key = '12345'
        return xor_key


    def get_xor_message_to_decrypt(self) -> str:
#         message = console.input("""[khaki3]
# Enter the message string you want to decrypt:
# >>> """)
        message = """eZZG\x15XA\x13U\x15BGCQG\x11AVWGTF\x13YPBARSP\x1f\x12g\\P\x11^RA[RZ\x13WZUW\x13]F\x0b\x12\x07\x01\x03w\nr\x05v\x05\x07\x00qs\x08\x00qqsps\x01\x07\x1b"""
        xor_key = XORDecryption.get_xor_key_to_decrypt(self)
        XORDecryption.decrypt_msg_with_xor(self,
                                           message=message,
                                           xor_key=xor_key)


    def get_xor_file_to_decrypt(self) -> str:
        # encrypted_file = Functions.get_file_path(self, text='you want to decrypt')
        encrypted_file = r'C:\Users\mikes\Desktop\encryption\aaa\test_for_XOR.py.encrypted'
        xor_key = XORDecryption.get_xor_key_to_decrypt(self)
        XORDecryption.decrypt_file_with_xor(self,
                                            encrypted_file=encrypted_file,
                                            xor_key=xor_key)


    def decrypt_msg_with_xor(self,
                             message: str,
                             xor_key: str) -> None:

        decrypted_message = ''

        for i in range(len(message)):
            text_to_decrypt = message[i]
            key_to_decrypt = xor_key[i % len(xor_key)]
            decrypted_message += chr(ord(text_to_decrypt) ^ ord(key_to_decrypt))

        console.print(f"""[green3]
==========================================
**ACTION SUCCESSFUL**\n
The original message is:\n
    [bright_white]{decrypted_message}[green3]\n
==========================================""")


    def decrypt_file_with_xor(self,
                              encrypted_file: Path,
                              xor_key: str) -> None:

        if encrypted_file.endswith('.encrypted'):
            decrypted_file = encrypted_file[:-10]
        else:
            decrypted_file = f'{encrypted_file}.decrypted'

        with open(encrypted_file, 'r') as f:
            encrypted_data = f.read()
            decrypted_data = ''
            for i in range(len(encrypted_data)):
                text_to_decrypt = encrypted_data[i]
                key_to_decrypt = xor_key[i % len(xor_key)]
                decrypted_data += chr(ord(text_to_decrypt) ^ ord(key_to_decrypt))

        with open(decrypted_file, 'w') as f:
            f.write(decrypted_data)

        console.print("""[green3]
==========================================
**ACTION SUCCESSFUL**\n
File Decrypted with XOR key
==========================================""")
