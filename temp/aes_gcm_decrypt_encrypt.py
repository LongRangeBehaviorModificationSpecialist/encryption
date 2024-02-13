import os
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import GCM



def aes_gcm_authenticated_decryption():
    key = b'\x87\xab;\xf7\xfcd\x91\xda{\x8a\x0b\x85\x95\xfb\xe3\x05\xba3Fc\xfcU$\xd0\xdb"\xb5^\xf4+t\xc4'
    iv = b'\xb8\xc7\xf8\x83I\xb4^\xed|\x1f\x00l'
    associated_data = b'Context of using AES GCM'
    auth_tag = b"\xaa'\x8f\xec\xb3\xaa\xad\xc8Qfm.P\xcdKK"
    cipher_text = b'6W\xf4\xa8\x10\xf1;^8(\x9b\xb8\x06\xc0P\xffw\x14N@\xf0\x89\xc8\xdcQ\xa00\x86M\x1aBS\xd3\x18'
    aes_gcm_decryptor = Cipher(AES(key), GCM(iv, auth_tag)).decryptor()
    aes_gcm_decryptor.authenticate_additional_data(associated_data)
    recovered_plaintext = aes_gcm_decryptor.update(cipher_text) + aes_gcm_decryptor.finalize()
    print(f'recovered_plaintext = {recovered_plaintext.decode()}')


def aes_gcm_authenticated_encryption():
    key = os.urandom(32)
    print(f'Key = {key}')
    iv = os.urandom(12)
    plain_text = b'Fundamental Cryptography in Python'
    associated_data = b'Context of using AES GCM'
    # Encrypt the plaintext (no padding required for GCM)
    aes_gcm_encryptor = Cipher(AES(key), GCM(iv)).encryptor()
    aes_gcm_encryptor.authenticate_additional_data(associated_data)
    cipher_text = aes_gcm_encryptor.update(plain_text) + aes_gcm_encryptor.finalize()
    auth_tag = aes_gcm_encryptor.tag

    with open('gcm_key_file.key', 'wb') as f:
        f.write(key)

    print('Key File written successfully')

    with open('gcm_msg_file.txt', 'w') as f:
        f.write(f'iv = {iv}\n')
        f.write(f'associated_data = {associated_data}\n')
        f.write(f'auth_tag = {auth_tag}\n')
        f.write(f'cipher_text = {cipher_text}\n')

    print('Encrypted message data written to file successfully')


if __name__ == '__main__':
    # aes_gcm_authenticated_decryption()
    aes_gcm_authenticated_encryption()
