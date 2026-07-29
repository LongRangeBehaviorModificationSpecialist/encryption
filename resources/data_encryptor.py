# !/usr/bin/env python3
# DLU : 29-Jul-2026

from pathlib import Path
from typing import Union

from rich.prompt import Prompt

# Import the console object from the primary __init__.py file
from . import console
from resources.functions import Functions
from resources._aes import AESClass
from resources._key import KEYClass
from resources._pgp import PGPClass
from resources._xor import XORClass


class DataEncryptor:


    def __init__(self, app_instance) -> None:
        """Store a reference to the main app loop controller."""
        self.app = app_instance


    def return_to_main_menu(self) -> None:
        """Returns control cleanly back to the main menu processor."""
        self.app.main(self)


    def run_single_file_encryption(self, encryption_type: str) -> Path:
        while True:
            # valid_encryption_types = {
            #     "KEY.FILE",
            #     "KEY.FOLDER",
            #     "AES.CBC.FILE",
            #     "AES.CBC.FOLDER",
            #     "AES.GCM.FILE",
            #     "AES.GCM.FOLDER",
            #     "PGP.FILE",
            #     "PGP.FOLDER",
            #     "XOR.FILE",
            #     "XOR.FOLDER"
            # }

#             if encryption_type not in valid_encryption_types:
#                 raise ValueError(
#                     f"Invalid encryption type : {encryption_type}. Expected \
# one of the following values : {valid_encryption_types}"
#                     )

            try:
                if "FILE" in encryption_type:

                    target_file_path = Functions.get_file_path(text="encrypted")

                    target_file_path = Path(target_file_path)

                    if not target_file_path.exists():
                        raise FileNotFoundError(
                            f"Target file not found : {target_file_path}"
                        )
                    if not target_file_path.is_file():
                        raise IsADirectoryError(
                            f"Provided path is a directory, not a file : {target_file_path}"
                        )

                    console.print(
                        f"""[bright_white]
[-] Reading file : {target_file_path.name}..."""
                    )
                    # Read plaintext data
                    plaintext = target_file_path.read_bytes()

                    console.print(
                        f"""[bright_white]
[-] Encrypting file data...""")

                    if "KEY" in encryption_type:
                        encrypted_data = KEYClass.key_encryption_workflow(
                            plaintext=plaintext
                        )

                    elif "AES.CBC" in encryption_type:
                        encrypted_data = AESClass.aes_encrypt_single_file(
                            plaintext=plaintext, mode="AES.CBC"
                        )

                    elif "AES.GCM" in encryption_type:
                        encrypted_data = AESClass.aes_encrypt_single_file(
                            plaintext=plaintext, mode="AES.GCM"
                        )



                    elif "PGP" in encryption_type:
                        PGPClass.pgp_encryption_workflow()

                    elif "XOR" in encryption_type:
                        encrypted_data = XORClass.xor_encryption_workflow(
                            plaintext=plaintext
                        )

                    console.print(
                        """[bright_white]
[-] Writing encrypted data to file..."""
                    )

                    if encrypted_data:
                        # Set the name of the encrypted file
                        encrypted_file_path = target_file_path.with_name(
                            f"{target_file_path.name}.encrypted"
                        )
                        encrypted_file_path.write_bytes(encrypted_data)
                        console.print(
                            f"""[green3]
[-] Encrypted {target_file_path.name:34s}{'->':7s}{encrypted_file_path.name}"""
                        )
                    else:
                        continue

                if "FOLDER" in encryption_type and "KEY" in encryption_type:
                    pass

                if "FOLDER" in encryption_type and "AES.CBC" in encryption_type:
                    pass

                if "FOLDER" in encryption_type and "AES.GCM" in encryption_type:
                    pass

                if "FOLDER" in encryption_type and "PGP" in encryption_type:
                    pass

                if "FOLDER" in encryption_type and "XOR" in encryption_type:
                    pass

            except Exception as e:
                console.print(
                    f"""[bright_red]
[!] An unexpected error occured during encryption : {e}"""
                )






















    def encrypt_files_in_directory():
        pass


    def get_target_choice(self) -> None:
        """Main routing controller for encryption jobs."""
        pass

