# !/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

import os
from rich.console import Console
from rich.prompt import Prompt
from pathlib import Path
import shutil

from resources.functions import Functions


# Make the console object
c = Console()


class AESEncryptor:


    @staticmethod
    def aes_encrypt_single_file(
            target_file_path: Path,
            password: str
    ) -> None:
        """
        Encrypt a file with a user-provided password

            Args:
                target_file_path: Path -> Path to the file to be encrypted
                password: str -> Password used to encrypt the file

            Returns:
                None (write encrypted file to disk)
        """

        # Convert the password string into bytes to use as a key to encrypt data
        salt = Functions.generate_salt()
        iv = Functions.get_aes_iv()

        key = Functions.encode_key(password=password, salt=salt)
        mode = AES.MODE_CBC

        c.print(f"\n[bright_white]Reading file : {target_file_path.name}...")
        file_data = target_file_path.read_bytes()

        c.print(f"\n[bright_white]Encrypting data...")

        enc_file_path = target_file_path.with_name(f"{target_file_path.name}.encrypted")

        cipher = AES.new(key=key, mode=mode, iv=iv)
        encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))

        combined_payload = salt + iv + encrypted_data

        enc_file_path.write_bytes(combined_payload)

        Functions.print_confirm_file_action(
            file_name=enc_file_path,
            text="ENCRYPTED"
        )


    @staticmethod
    def aes_encrypt_all_files_in_dir(
            target_folder_path: Path,
            password: str) -> None:

        # Turn folder path string into Path object
        f = Path(target_folder_path)

        dirs = Functions.get_all_files(target_dir_path=f)

        for file in dirs:
            AESEncryptor.aes_encrypt_single_file(
                target_file_path=file,
                password=password)

        c.print(f"""[green3]
**ACTION SUCCESSFUL**\n
The following files in {f} directory were encrypted\n""")
        for file in dirs:
            c.print(f"""[green3]
{os.path.basename(file):34s}{"--->":7s}{os.path.basename(file)}.encrypted""")


    # @staticmethod
    # def aes_encrypt_multi_file(
    #         target_file_path: Path,
    #         password: str,
    #         mode=AES.MODE_CBC) -> None:
    #     """
    #     Encrypt a file with a user-provided password

    #         Args:
    #             file_path: Path -> Path to the file to be encrypted
    #             password: str -> Password used to encrypt the file

    #         Returns:
    #             file: AES-CBC encrypted file
    #     """
    #     # Convert the password string into bytes to use as a key to
    #     # encrypt the data
    #     salt = Functions.generate_salt()
    #     iv = Functions.get_aes_iv()

    #     key = Functions.encode_key(password=password, salt=salt)

    #     c.print(f"\n[bright_white]Reading file : {target_file_path.name}...")
    #     file_data = target_file_path.read_bytes()

    #     cipher = AES.new(key=key, mode=mode, iv=iv)
    #     encrypted_data = cipher.encrypt(
    #         pad(orig_file_data, AES.block_size))
    #     encrypted_file = Path(f"{target_file_path}.encrypted")

    #     with open(encrypted_file, "wb") as f:
    #         Functions.write_to_file(file=f, message=cipher.iv)
    #         Functions.write_to_file(file=f, message=encrypted_data)


#     def ask_delete_original_zip(self,
#             file_path: Path) -> None:

#         delete_unencrypted_zip = Prompt.ask("""[khaki3]
# [-] Do you want to delete the unencrypted .zip file (y/n)? \
# [orange_red1][THIS ACTION CANNOT BE UNDONE!] """)

#         delete_unencrypted_zip = delete_unencrypted_zip.lower().strip()

#         if delete_unencrypted_zip == "y":
#             os.remove(file_path)
#             Functions.print_confirm_file_action(self,
#                 file_name = Path(
#                     f"{file_path}.encrypted"),
#                 text="Encrypted")

#         elif delete_unencrypted_zip == "n":
#             Functions.print_confirm_file_action(self,
#                 file_name = Path(
#                     f"{file_path}.encrypted"),
#                 text="Encrypted")

#         else:
#             Functions.no_valid_yn_option()
#             AESEncryptor.ask_delete_original_zip(self, file_path)


    # def aes_zip_files_then_encrypt(self,
    #         folder_path: Path,
    #         password: bytes) -> None:

    #     f = Path(folder_path)

    #     shutil.make_archive(base_name=f, format="zip", root_dir=f)
    #     zip_file_name = f"{f.stem}.zip"
    #     zip_file_to_encrypt = Path(f.parent).joinpath(f"{zip_file_name}")

    #     AESEncryptor.aes_encrypt_multi_file(self,
    #         file_path=zip_file_to_encrypt,
    #         password=password)

    #     AESEncryptor.ask_delete_original_zip(self,
    #         file_path=zip_file_to_encrypt)


#     def aes_encrypt_files_then_zip(self,
#             folder_path: Path,
#             password: bytes) -> None:

#         choice = Functions.confirm_delete_original_files(self)

#         choice = choice.lower().strip()

#         # Turn folder path string into Path object
#         f = Path(folder_path)

#         if choice == "y":

#             dirs = Functions.get_all_files(self, folder_path=f)

#             for file in dirs:
#                 AESEncryptor.aes_encrypt_multi_file(self,
#                     file_path=file,
#                     password=password)
#                 os.remove(file)

#             shutil.make_archive(base_name=f, format="zip", root_dir=f)
#             shutil.rmtree(f)
#             c.print(f"""[green3]
# -------------------------------------------------
# [{Functions.get_date_time(self)}]
# **ACTION SUCCESSFUL**\n
# The files in the `{f}` directory have been encrypted
# The output file is `{f.name}.zip`
# The output file was saved in `{f.parent}`\n
# The directory and the original files HAVE BEEN DELETED
# -------------------------------------------------""")

#         elif choice == "n":

#             dirs = Functions.get_all_files(self, folder_path=f)

#             for file in dirs:
#                 AESEncryptor.aes_encrypt_multi_file(self,
#                     file_path=file,
#                     password=password)

#             shutil.make_archive(base_name=f, format="zip", root_dir=f)
#             c.print(f"""[green3]
# -------------------------------------------------
# [{Functions.get_date_time(self)}]
# **ACTION SUCCESSFUL**\n
# The files in the `{f}` directory have been encrypted
# The output file is `{f.name}.zip`
# The output file was saved in `{f.parent}`\n
# The directory and the original files HAVE NOT BEEN DELETED
# -------------------------------------------------""")

#         else:
#             Functions.no_valid_yn_option()
#             AESEncryptor.aes_encrypt_files_then_zip(self)
