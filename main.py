# !/usr/bin/env python3
# -*- coding: utf-8 -*-

from rich.console import Console
from resources import (AESDecryptor,
                       AESEncryptor,
                       AESGCMDataDecryptor,
                       AESGCMDataEncryptor,
                       KeyFileDecryptor,
                       KeyFileEncryptor,
                       PGPClass,
                       XOREncryption,
                       XORDecryption,
                       Functions)

__author__ = "mikespon"
__last_updated__ = "2024-02-13"

# Make the console object
console = Console()

# password = 'mysecretpassword34'
email_address = 'testaddress@email.com'


class App:


    def no_valid_option(self) -> None:
        """When a valid opetion is not entered, the user will be prompted to
        try again and enter a valid option.
        """
        console.print("""[red1]
You did not enter a valid option. Please try again.""")
        App.main(self)


    def return_to_main_menu(self) -> None:
        """Returns the user to the main application menu"""
        Functions.clear_screen(self)
        App.main(self)


    def main(self) -> None:
        Functions.clear_screen(self)
        """Main function where the user can pick what option they want"""
        choice = console.input(f"""[dodger_blue1]
=============================================\n
ENCRYPTION APPLICATION MENU, v.0.3.17076096\n
=============================================[bright_white]\n
ENCRYPTION\n
A)  Use a .key file to encrypt file/files
B)  Use a password to encrypt file/files (AES-CBC Mode)
C)  Use a password to encrypt file/files (AES-GCM Mode)
D)  Encrypt file/files using PGP
E)  Encrypt message/file using XOR\n
DECRYPTION\n
F)  Decrypt file/files using a .key file
G)  Decrypt file/files using a password (AES-CBC Mode)
H)  Decrypt file/files using a password (AES-GCM Mode)
I)  Decrypt file/files using a PGP key file
J)  Decrypt message/file using XOR\n
Q)  Quit the Application[khaki3]\n
ENTER CHOICE >>> """)

        Functions.clear_screen(self)

        choice = choice.strip().lower()

        if choice == 'a':
            option = console.input("""[dodger_blue1]
=======================================
ENCRYPT FILE WITH PROVIDED .KEY FILE
=======================================[khaki3]\n
-------------------
Choose an option
-------------------[bright_white]\n
1)  Encrypt a file using an existing .key file
2)  Encrypt a file using a newly created .key file
3)  Encrypt all files in a directory using a .key file\n
R)  Return to the main menu
Q)  Quit the application[khaki3]\n
ENTER CHOICE >>> """)

            Functions.clear_screen(self)

            option = option.strip()

            if option == '1':
                key_file = Functions.get_key_file_path(self)
                file_path = Functions.get_file_path(
                    self,
                    text='ENCRYPT'
                )
                KeyFileEncryptor.get_key_data_to_encrypt_file(
                    self,
                    key_file=key_file,
                    file_path=file_path
                )
            elif option == '2':
                file_path = Functions.get_file_path(
                    self,
                    text='ENCRYPT'
                )
                KeyFileEncryptor.encrypt_file_with_new_key(
                    self,
                    file_path=file_path
                )
            elif option == '3':
                key_file = Functions.get_key_file_path(self)
                folder_path = Functions.get_folder_path(
                    self,
                    text='ENCRYPT'
                )
                KeyFileEncryptor.encrypt_files_in_dir_with_key(
                    self,
                    key_file=key_file,
                    folder_path=folder_path
                )
            elif option.lower() == 'r':
                App.return_to_main_menu(App)
            elif option.lower() == 'q':
                Functions.exit_application(self)
            else:
                App.no_valid_option(self)


        elif choice == 'b':
            option = console.input("""[dodger_blue1]
=======================================
USE PASSWORD TO ENCRYPT FILE(S) [AES]
=======================================[khaki3]\n
-------------------
Choose an option
-------------------[bright_white]\n
1)  Encrypt a single file using a password
2)  Encrypt all files in a directory using a password\n
R)  Return to the main menu
Q)  Quit the application[khaki3]\n
ENTER CHOICE >>> """)

            Functions.clear_screen(self)

            option = option.strip()

# I:\encryption\aaa\File_2_Folder_2_for_AES.txt

# I:\encryption\aaa\txtfiles_AES
# Mysecretpassword123!


            if option == '1':
                file_path = Functions.get_file_path(
                    self,
                    text='ENCRYPTED'
                )
                password = Functions.get_password(self)
                AESEncryptor.aes_encrypt_single_file(
                    self,
                    file_path=file_path,
                    password=password
                )
            elif option == '2':
                make_aes_dir_choice = console.input("""[khaki3]
-------------------
Choose an option
-------------------[bright_white]\n
1)  Encrypt all files in a directory
2)  Place original files in .zip container then encrypt the .zip file
3)  Encrypt all files in directory then add to unencrypted .zip file \
(file size may be larger)\n
R)  Return to the main menu
Q)  Quit the application[khaki3]\n
ENTER CHOICE >>> """)

                Functions.clear_screen(self)

                make_aes_dir_choice = make_aes_dir_choice.strip()

                folder_path = Functions.get_folder_path(
                    self,
                    text='ENCRYPTED'
                )
                # password = Functions.get_password(self)

                if make_aes_dir_choice== '1':
                    AESEncryptor.aes_encrypt_all_files_in_dir(
                        self,
                        folder_path=folder_path,
                        password=password
                    )
                elif make_aes_dir_choice == '2':
                    AESEncryptor.aes_zip_files_then_encrypt(
                        self,
                        folder_path=folder_path,
                        password=password
                    )
                elif make_aes_dir_choice == '3':
                    AESEncryptor.aes_encrypt_files_then_zip(
                        self,
                        folder_path=folder_path,
                        password=password
                    )
                elif make_aes_dir_choice.lower() == 'r':
                    App.return_to_main_menu(self)
                elif make_aes_dir_choice.lower() == 'q':
                    Functions.exit_application(self)
                else:
                    App.no_valid_option(self)

            elif option.lower() == 'r':
                App.return_to_main_menu(self)
            elif option.lower() == 'q':
                Functions.exit_application(self)
            else:
                App.no_valid_option(self)


        elif choice == 'c':
            option = console.input("""[dodger_blue1]
=======================================
USE PASSWORD TO ENCRYPT FILE(S) [GCM]
=======================================[khaki3]\n
-------------------
Choose an option
-------------------[bright_white]\n
1)  Encrypt a single file using a password (AES-GCM)
2)  Encrypt all files in a directory using a password (AES-GCM)\n
R)  Return to main menu
Q)  Quit the application[khaki3]\n
ENTER CHOICE >>> """)

            Functions.clear_screen(self)

            option = option.strip()

            if option == '1':
                file_path = Functions.get_file_path(self)
                # password = Functions.get_password(self)
                AESGCMDataEncryptor.aes_gcm_encrypt_file(
                    self,
                    file_path=file_path,
                    password=password
                )
            elif option == '2':
                folder_path = Functions.get_folder_path(
                    self,
                    text='ENCRYPT'
                )
                # password = Functions.get_password(self)
                AESGCMDataEncryptor.aes_gcm_encrypt_directory(
                    self,
                    folder_path=folder_path,
                    password=password
                )
            elif option.lower() == 'r':
                App.return_to_main_menu(self)
            elif option.lower() == 'q':
                Functions.exit_application(self)
            else:
                App.no_valid_option(self)


        elif choice == 'd':
            option = console.input("""[dodger_blue1]
=======================================
ENCRYPT FILE(S) USING PGP KEY
=======================================[khaki3]\n
-------------------
Choose an option
-------------------[bright_white]\n
1)  Generate new PGP key pair
2)  Encrypt files using PGP encryption
3)  Encrypt all files in a directory using PGP keys\n
R)  Return to the main menu
Q)  Quit the application[khaki3]\n
ENTER CHOICE >>> """)

            Functions.clear_screen(self)

            option = option.strip()

            if option == '1':
                # password = Functions.get_password(self)
                # email_address = Functions.get_email_address(self)
                PGPClass.generate_pgp_key(
                    self,
                    password=password,
                    email_address=email_address
                )
            elif option == '2':
                file_path = Functions.get_file_path(self)
                PGPClass.pgp_encrypt_file(
                    self,
                    file_path=file_path
                )
            elif option == '3':
                folder_path = Functions.get_folder_path(
                    self,
                    text='ENCRYPT'
                )
                PGPClass.pgp_encrypt_folder(
                    self,
                    folder_path=folder_path
                )
            elif option.lower() == 'r':
                App.return_to_main_menu(self)
            elif option.lower() == 'q':
                Functions.exit_application(self)
            else:
                App.no_valid_option(self)


        elif choice == 'e':
            option = console.input("""[dodger_blue1]
=======================================
ENCRYPT FILE(S) USING AN XOR KEY
=======================================[khaki3]\n
-------------------
Choose an option
-------------------[bright_white]\n
1)  Encrypt a single message string
2)  Encrypt a file\n
R)  Return to the main menu
Q)  Quit the application[khaki3]\n
ENTER CHOICE >>> """)

            Functions.clear_screen(self)

            option = option.strip()

            if option == '1':
                message = Functions.get_message_to_xor(self)
                xor_key = Functions.get_xor_key(self)
                XOREncryption.encrypt_msg_with_xor(
                    self,
                    message=message,
                    xor_key=xor_key
                )
            elif option == '2':
                file_path = Functions.get_file_path(self)
                xor_key = Functions.get_xor_key(self)
                XOREncryption.encrypt_file_with_xor(
                    self,
                    file_path=file_path,
                    xor_key=xor_key
                )
            elif option.lower() == 'r':
                App.return_to_main_menu(self)
            elif option.lower() == 'q':
                Functions.exit_application(self)
            else:
                App.no_valid_option(self)


#! ====================
#! DECRYPTION OPTIONS
#! ====================


        elif choice == 'f':
            option = console.input("""[dodger_blue1]
=======================================
DECRYPT FILE WITH PROVIDED .KEY FILE
=======================================[khaki3]\n
-------------------
Choose an option
-------------------[bright_white]\n
1)  Decrypt a file using a .key file
2)  Decrypt all files in a folder using a .key file\n
R)  Return to the main menu
Q)  Quit the application[khaki3]\n
ENTER CHOICE >>> """)

            Functions.clear_screen(self)

            option = option.strip()

            if option == '1':
                key_file = Functions.get_key_file_path(self)
                file_path = Functions.get_file_path(
                    self,
                    text='DECRYPT'
                )
                KeyFileDecryptor.decrypt_file_with_key(
                    self,
                    key_file=key_file,
                    file_path=file_path
                )
            elif option == '2':
                key_file = Functions.get_key_file_path(self)
                file_path = Functions.get_file_path(
                    self,
                    text='DECRYPT'
                )
                KeyFileDecryptor.decrypt_files_in_folder_with_key(
                    self,
                    key_file=key_file,
                    file_path=file_path
                )
            elif option.lower() == 'r':
                App.return_to_main_menu(self)
            elif option.lower() == 'q':
                Functions.exit_application(self)
            else:
                App.no_valid_option(self)


        elif choice == 'g':
            option = console.input("""[dodger_blue1]
=======================================
USE PASSWORD TO DECRYPT FILE(S) [AES]
=======================================[khaki3]\n
-------------------
Choose an option
-------------------[bright_white]\n
1)  Decrypt a file using a password (AES encrypted)
2)  Decrypt all files in a folder using a password\n
R)  Return to the main menu
Q)  Quit the application[khaki3]\n
ENTER CHOICE >>> """)

            Functions.clear_screen(self)

            option = option.strip()

            if option == '1':
                file_path = Functions.get_file_path(self)
                # password = Functions.get_password(self)
                AESDecryptor.aes_decrypt_file(
                    self,
                    file_path=file_path,
                    password=password
                )
            elif option == '2':
                folder_path = Functions.get_folder_path(
                    self,
                    text='DECRYPT'
                )
                # password = Functions.get_password(self)
                AESDecryptor.aes_decrypt_all_files_in_dir(
                    self,
                    folder_path=folder_path,
                    password=password
                )
            elif option.lower() == 'r':
                App.return_to_main_menu()
            elif option.lower() == 'q':
                Functions.exit_application(self)
            else:
                App.no_valid_option(self)


        elif choice == 'h':
            option = console.input("""[dodger_blue1]
=======================================
USE PASSWORD TO DECRYPT FILE(S) [GCM]
=======================================[khaki3]\n
-------------------
Choose an option
-------------------[bright_white]\n
1)  Decrypt a single file using a password
2)  Decrypt all files in a directory using a password\n
R)  Return to the main menu
Q)  Quit the application[khaki3]\n
ENTER CHOICE >>> """)

            Functions.clear_screen(self)

            option = option.strip()

            if choice == '1':
                file_path = Functions.get_file_path(
                    self,
                    text='DECRYPTED'
                )
                # password = Functions.get_password(self)
                AESGCMDataDecryptor.aes_gcm_decrypt_file(
                    self,
                    file_path=file_path,
                    password=password
                )
            elif choice == '2':
                folder_path = Functions.get_folder_path(
                    self,
                    text='DECRYPTED'
                )
                AESGCMDataDecryptor.aes_gcm_decrypt_directory(
                    self,
                    folder_path=folder_path
                )
            elif option.lower() == 'r':
                App.return_to_main_menu(self)
            elif option.lower() == 'q':
                Functions.exit_application(self)
            else:
                App.no_valid_option(self)


        elif choice == 'i':
            option = console.input("""[dodger_blue1]
=======================================
DECRYPT FILE(S) USING PGP KEY
=======================================[khaki3]\n
-------------------
Choose an option
-------------------[bright_white]\n
1)  Decrypt a file using PGP key
2)  -- Decrypt all files in a folder using PGP key --\n
R)  Return to the main menu
Q)  Quit the application[khaki3]\n
ENTER CHOICE >>> """)

            Functions.clear_screen(self)

            option = option.strip()

            if option == '1':
                file_path = Functions.get_file_path(self)
                # password = Functions.get_password(self)
                PGPClass.pgp_decrypt_file(
                    self,
                    file_path=file_path,
                    password=password
                )
            elif option == '2':
                pass
            elif option.lower() == 'r':
                App.return_to_main_menu(self)
            elif option.lower() == 'q':
                Functions.exit_application(self)
            else:
                App.no_valid_option(self)


        elif choice == 'j':
            option = console.input("""[dodger_blue1]
=======================================
DECRYPT FILE(S) USING AN XOR KEY
=======================================[khaki3]\n
-------------------
Choose an option
-------------------[bright_white]\n
1)  Decrypt a single message
2)  Decrypt a file\n
R)  Return to the main menu
Q)  Quit the application[khaki3]\n
ENTER CHOICE >>> """)

            Functions.clear_screen(self)

            option = option.strip()

            if option == '1':
                message = Functions.get_xor_message_to_decrypt(self)
                xor_key = Functions.get_xor_key(self)
                XORDecryption.decrypt_msg_with_xor(
                    self,
                    message=message,
                    xor_key=xor_key
                )
            elif option == '2':
                file_path = Functions.get_file_path(self)
                xor_key = Functions.get_xor_key(self)
                XORDecryption.decrypt_file_with_xor(
                    self,
                    file_path=file_path,
                    xor_key=xor_key
                )
            elif option.lower() == 'r':
                App.return_to_main_menu(self)
            elif option.lower() == 'q':
                Functions.exit_application(self)
            else:
                App.no_valid_option(self)


        elif choice.lower() == 'q':
           Functions.clear_screen(self)
           Functions.exit_application(self)


        else:
            Functions.clear_screen(self)
            App.no_valid_option(self)


if __name__ == '__main__':
    App.main(App)
