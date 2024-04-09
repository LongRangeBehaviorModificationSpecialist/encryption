# !/usr/bin/env python3

from rich.console import Console
from pathlib import Path

from resources.functions import Functions

# Make the console object
c = Console()

class XOREncryption:


    def encrypt_msg_with_xor(self,
                             message: str,
                             xor_key: str) -> None:
        encrypted_text = ''
        xor_enc_msg_file = 'C:\\Users\\user\\encryption\\enc_msg.txt'

        for i in range(len(message)):
            c = message[i]
            key_to_encrypt = xor_key[i % len(xor_key)]
            encrypted_text += chr(
                ord(c) ^ ord(key_to_encrypt))

        with open(xor_enc_msg_file, 'w') as f:
            f.write(encrypted_text)

        c.print(f'''[green3]
==========================================
** ACTION SUCCESSFUL **\n
The encrypted message is:\n
  [bright_white]{encrypted_text}[green3]\n
==========================================''')


    def encrypt_file_with_xor(self,
                              file_path: Path,
                              xor_key: str) -> None:
        encrypted_data = ''
        file = Path(file_path)
        xor_enc_file = f'{file}.encrypted'

        with open(file, 'r') as f:
            plain_text = f.read()

            for i in range(len(plain_text)):
                c = plain_text[i]
                key_to_encrypt = xor_key[i % len(xor_key)]
                encrypted_data += chr(
                    ord(c) ^ ord(key_to_encrypt))

        with open(xor_enc_file, 'w', encoding='utf-8') as f:
            f.write(encrypted_data)

        c.print('''[green3]
==========================================
** ACTION SUCCESSFUL **\n
  File Encrypted with XOR key
==========================================''')


class XORDecryption:


    def decrypt_msg_with_xor(self,
                             message: str,
                             xor_key: str) -> None:

        decrypted_message = ''

        for i in range(len(message)):
            text_to_decrypt = message[i]
            key_to_decrypt = xor_key[i % len(xor_key)]
            decrypted_message += chr(
                ord(text_to_decrypt) ^ ord(key_to_decrypt))

        c.print(f'''[green3]
==========================================
** ACTION SUCCESSFUL **\n
The original message is:\n
  [bright_white]{decrypted_message}[green3]\n
==========================================''')


    def decrypt_file_with_xor(self,
                              file_path: Path,
                              xor_key: str) -> None:

        if file_path.endswith('.encrypted'):
            decrypted_file = file_path[:-10]
        else:
            decrypted_file = f'{file_path}.decrypted'

        with open(file_path, 'r') as f:
            encrypted_data = f.read()
            decrypted_data = ''

            for i in range(len(encrypted_data)):
                text_to_decrypt = encrypted_data[i]
                key_to_decrypt = xor_key[i % len(xor_key)]
                decrypted_data += chr(
                    ord(text_to_decrypt) ^ ord(key_to_decrypt))

        with open(decrypted_file, 'w') as f:
            f.write(decrypted_data)

        c.print('''[green3]
==========================================
** ACTION SUCCESSFUL **\n
  File Decrypted with XOR key
==========================================''')
