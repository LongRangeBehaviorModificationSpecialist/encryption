# !/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import os
from pathlib import Path
import sys
from rich.console import Console

from resources.functions import Functions


# Make the console object
c = Console()


class AESDecryptor:

    @staticmethod
    def aes_decrypt_single_file(
            target_file_path: Path,
            password: str
    ) -> Path:
        """
        Decrypt a file encrypted with AES-CBC.

        Assumes the file structure is:
        [ 16 bytes Salt ] + [ 16 bytes IV ] + [ Encrypted Data ]

        Args:
            target_file_path: Path -> Path to the encrypted file
            password: str -> Password to derive the decryption key

        Returns:
            Path -> The path to the decrypted file
        """

        c.print(f"\n[bright_white]Reading encrypted file : \
{target_file_path.name}...")

        raw_payload = target_file_path.read_bytes()

        salt_size = 16
        iv_size = 16
        minimum_expected_size = salt_size + iv_size + AES.block_size

        if len(raw_payload) < minimum_expected_size:
            raise ValueError(
f"The file is too small ({len(raw_payload)} bytes). "
f"A valid encrypted file must be at least {minimum_expected_size} bytes "
f"(16-byte salt + 16-byte IV + at least 16 bytes of encrypted data)."
            )

        salt = raw_payload[:salt_size]
        iv = raw_payload[salt_size : salt_size + iv_size]
        ciphertext = raw_payload[salt_size + iv_size:]

        c.print("\n[bright_white]Deriving key and decrypting...")

        key = PBKDF2(
            password=password,
            salt=salt,
            dkLen=32,
            count=100000,
            hmac_hash_module=SHA256
        )

        cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)

        try:
            decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
        except (ValueError, KeyError) as e:
            raise ValueError("Decryption failed. The password may be incorrect \
or the data is corrupted") from e

        if target_file_path.suffix == ".encrypted":
            dec_file_path = target_file_path.with_suffix("")
        else:
            dec_file_path = target_file_path.with_name(
                f"{target_file_path.name}.decrypted")

        dec_file_path.write_bytes(decrypted_data)

        c.print(f"[green]Success! [bright_white]File decrypted as saved as {dec_file_path.name}")
        return dec_file_path


    @staticmethod
    def aes_decrypt_all_files_in_dir(
            target_folder_path: Path,
            password: str,
            mode=AES.MODE_CBC) -> None:

        # Turn folder path string into Path object
        f = Path(target_folder_path)

        dirs = Functions.get_all_files(target_dir_path=f)

        for file in dirs:
            AESDecryptor.aes_decrypt_single_file(
                target_file_path=file,
                password=password,
                mode=mode)

#         c.print(f"""[green3]
#         **ACTION SUCCESSFUL**\n
# The following files in {f} directory were decrypted\n""")
#         for file in dirs:
#             c.print(f"""[green3]
# {os.path.basename(file):34s}{"--->":7s}{os.path.basename(file)}.encrypted""")


# ---------------------------------------------------------------------------

    # def _return_dir_data(self, folder_path: Path) -> tuple:

    #     dirs = Functions.get_all_files(self, folder_path=folder_path)

    #     for file_to_decrypt in dirs:
    #         file_name, file_ext = os.path.splitext(file_to_decrypt)

    #         if file_ext == ".encrypted":
    #             decrypted_file = file_name
    #         else:
    #             decrypted_file = f"{file_to_decrypt}.decrypted"

    #     return file_to_decrypt, file_ext, decrypted_file


    # def _aes_decrypt_all_files(self,
    #         folder_path: Path,
    #         key: bytes,
    #         mode: str) -> None:

    #     file_to_decrypt = Path(
    #         AESDecryptor._return_dir_data(self, folder_path)[0])

    #     decrypted_file = Path(
    #         AESDecryptor._return_dir_data(self, folder_path)[2])

    #     # Open the file and read the iv value and the encrypted file data
    #     with open(file_to_decrypt, "rb") as f:
    #         iv = f.read(16)
    #         encrypted_data = f.read()

    #     cipher = AES.new(key=key, mode=mode, iv=iv)
    #     decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

    #     with open(decrypted_file, "wb") as f:
    #         Functions.write_to_file(self, file=f, message=decrypted_data)
