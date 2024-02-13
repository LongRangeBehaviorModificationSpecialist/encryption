from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
import os
from pathlib import Path
from rich.console import Console

"""
Keep the encryption key secure as it will be needed for decryption. Also, this program overwrites the original files with encrypted content. Make sure to have proper backups before running it.
"""

# Make the console object
console = Console()



def encrypt_file(file_path: Path, key: str) -> None:
    with open(file_path, 'rb') as file:
        plaintext = file.read()
    iv = os.urandom(16)
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    encrypted_file_path = f'{file_path}.encrypted'
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(iv + encryptor.tag + ciphertext)
    return encrypted_file_path


def encrypt_directory(self, directory_path, key):
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            self.encrypt_file(self, file_path, key)
            # # Optionally, you can remove the original file
            # os.remove(file_path)


if __name__ == '__main__':
    # enc = AESGCMDataEncryptor()
    # directory_path = console.input("""[khaki1]
    # [-] Enter the directory path:
    # >>  """)
    file_path = Path('C:\\Users\\mikes\\Desktop\\encryption\\aaa\\compare_dirs_GCM.py')
    # Get 256-bit key for AES
    key = os.urandom(32)
    encrypt_file(file_path, key)
    console.print(f"""[khaki1]Encryption Key used: {key}""")
    console.print("""[bright_blue]Encryption complete""")