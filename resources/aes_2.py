from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
import os
import shutil
from rich.console import Console
import binascii
import hashlib


# Make the console object
console = Console()


class AESGCMDataEncryptor:
    """
    Keep the encryption key secure as it will be needed for decryption. Also, this
    program overwrites the original files with encrypted content. Make sure to
    have proper backups before running it.
    """

    def encrypt_file(self, file_path, key):
        with open(file_path, 'rb') as file:
            plaintext = file.read()
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        encrypted_file_path = file_path + '.encrypted'
        with open(encrypted_file_path, 'wb') as encrypted_file:
            encrypted_file.write(iv + encryptor.tag + ciphertext)
        console.print(f"""[khaki3]
    FileName: {os.path.basename(file.name)}
    iv: {iv.hex().upper()}
    tag: {encryptor.tag.hex().upper()}
    cipherText: {ciphertext[32:48]}...""")
        return encrypted_file_path


    def encrypt_directory(self, directory_path, key):
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                self.encrypt_file(file_path, key)
                # Optionally, you can remove the original file
                os.remove(file_path)


class AESGCMDataDecryptor:
    """
    Make sure to use the correct encryption key that was used during encryption.
    Keep the key secure and do not share it with unauthorized users. Also, this
    program removes the '.enc' extension after decryption; if you want to keep the
    encrypted files, you may want to adjust the logic accordingly [from ChatGPT].
    """

    def decrypt_file(self, encrypted_file_path, key):
        with open(encrypted_file_path, 'rb') as encrypted_file:
            data = encrypted_file.read()
        iv = data[:16]
        tag = data[16:32]
        ciphertext = data[32:]
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        # Remove the '.encrypted' file extension
        decrypted_file_path = encrypted_file_path[:-10]
        with open(decrypted_file_path, 'wb') as decrypted_file:
            decrypted_file.write(plaintext)
        return decrypted_file_path


    def decrypt_directory(self, directory_path, key):
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if file.endswith('.encrypted'):
                    encrypted_file_path = os.path.join(root, file)
                    self.decrypt_file(encrypted_file_path, key)
                    # Optionally, you can remove the encrypted file
                    os.remove(encrypted_file_path)


if __name__ == '__main__':

    enc = AESGCMDataEncryptor()
    # dec = AESGCMDataDecryptor()

    directory_path = 'I:\\encryption\\aaa\\txtfiles02'

    """If encrypting a directory"""
    # directory_path = console.input("""[khaki3]
# [-] Enter the directory path:
# >>> """)

    # Get 256-bit key for AES
    password = console.input("""[khaki3]
[-] Enter a password to encrypt the files:
>>> """)
    pswd_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    key = binascii.unhexlify(pswd_hash)
    enc.encrypt_directory(directory_path, key)
    console.print(f"""[khaki3]
[-] Encryption Key used:
    {key}""")
    console.print(f"""[khaki3]
[-] Encryption Key used:
    {key.hex().upper()}""")
    console.print("""[khaki3][-] Encryption complete. Exiting...""")

    """If decrypting a directory"""
    # directory_path = console.input("""[khaki3]
# [-] Enter the directory path:
# >>> """)

    # password = console.input("""[khaki3]
# [-] Enter the decryption password:
# >>> """)
    # pswd_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    # key = binascii.unhexlify(pswd_hash)
    # dec.decrypt_directory(directory_path, key)
    # console.print("""[khaki3][-] Decryption complete. Exiting...""")


    # I:\encryption\aaa\txtfiles02
    # b'\xf3/\xa0\xc1\xcf\xefP:\xe5:\xd2\xd3\xd1\xfa\t\xbf\x8fS\xe0\xa7\x18\x8a\x1e\xba\xca~f$\xcf\xc0\xbc\xa9'
    # F32FA0C1CFEF503AE53AD2D3D1FA09BF8F53E0A7188A1EBACA7E6624CFC0BCA9
    # 6a5066968ea97127401bdbc5826f2639d5c8732eadcec8787b9aa1817165f020