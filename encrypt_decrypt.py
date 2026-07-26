# !/usr/bin/env python3
# DLU : 26-Jul-2026

from rich.console import Console
from rich.prompt import Prompt

from resources import (AESEncryptor,
        AESDecryptor,
        KeyFileDecryptor,
        KeyFileEncryptor,
        PGPEncrypt,
        PGPClass,
        XOREncryptor,
        XORDecryptor,
        Functions)

__author__ = "[@mikespon]"
__last_updated__ = "15-Jul-2026"


# Make the console object
c = Console()


# password = "mysecretpassword34"
email_address = "testaddress@email.com"


class App:

    def no_valid_option(self) -> None:
        """When a valid option is not entered, the user will be prompted to
        try again and enter a valid option.
        """
        c.print(
            """[bright_red]
[!] You did not enter a valid option. Please try again."""
        )
        App.main(self)


    def return_to_main_menu(self) -> None:
        """Returns the user to the main application menu."""
        Functions.clear_screen()
        App.main(self)


    def main(self) -> None:
        Functions.clear_screen()
        """Main function where the user can pick what option they want."""

        choice = (
            Prompt.ask(f"""[dodger_blue1]
----------------------------------------
ENCRYPT/DECRYPT APPLICATION MENU
v.0.3.17076096
----------------------------------------[bright_white]

ENCRYPTION

[A] Use a .key file to encrypt file/files
[B] Use a password to encrypt file/files
[C] Encrypt file/files using PGP
[D] Encrypt message/file using XOR

DECRYPTION

[E] Decrypt file/files using a .key file
[F] Decrypt file/files using a password
[G] Decrypt file/files using a PGP key file
[H] Decrypt message/file using XOR

[Q] Quit the Application[khaki3]


ENTER CHOICE """,
                choices=["a", "b", "c", "d", "e", "f", "g", "h", "q"],
                show_choices=False)
            .strip()
            .lower()
        )


        if choice == "a":
            Functions.clear_screen()
            KeyFileEncryptor(app_instance=self).get_target_choice()


        elif choice == "b":
            Functions.clear_screen()
            AESEncryptor(app_instance=self).get_target_choice()


        elif choice == "c":
            Functions.clear_screen()
            PGPEncrypt(app_instance=self).get_target_choice()


        elif choice == "d":
            Functions.clear_screen()
            XOREncryptor(app_instance=self).get_target_choice()



            option = Prompt.ask("""[dodger_blue1]
---------------------------------------
ENCRYPT FILE(S) USING AN XOR KEY
---------------------------------------\n
[khaki3]Choose an option ->[bright_white]\n
[1] Encrypt a single message string
[2] Encrypt a file\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """,
                choices=["1", "2", "r", "q"],
                show_choices=False).strip().lower()



#! ====================
#! DECRYPTION OPTIONS
#! ====================


        elif choice == "e":
            Functions.clear_screen()
            KeyFileDecryptor(app_instance=self).get_target_choice()


        elif choice == "f":
            Functions.clear_screen()
            AESDecryptor(app_instance=self).get_target_choice()



        elif choice == "g":
            option = Prompt.ask("""[dodger_blue1]
---------------------------------------
DECRYPT FILE(S) USING PGP KEY
---------------------------------------\n
[khaki3]Choose an option ->[bright_white]\n
[1] Decrypt a file using PGP key
[2] -- Decrypt all files in a folder using PGP key --\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """,
                choices=["1", "2", "r", "q"],
                show_choices=False).strip().lower()

            Functions.clear_screen()

            if option == "1":
                file_path = Functions.get_file_path()
                password = Functions.get_password()
                PGPClass.pgp_decrypt_file(self,
                    file_path=file_path,
                    password=password)

            elif option == "2":
                pass

            elif option == "r":
                App.return_to_main_menu(self)

            elif option == "q":
                Functions.exit_application()

            else:
                App.no_valid_option(self)


        elif choice == "h":
            option = Prompt.ask("""[dodger_blue1]
---------------------------------------
DECRYPT FILE(S) USING AN XOR KEY
---------------------------------------\n
[khaki3]Choose an option ->[bright_white]\n
[1] Decrypt a single message
[2] Decrypt a file\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """,
                choices=["1", "2", "r", "q"],
                show_choices=False).strip().lower()

            Functions.clear_screen()

            if option == "1":
                message = Functions.get_xor_message_to_decrypt()
                xor_key = Functions.get_xor_key()
                XORDecryption.decrypt_msg_with_xor(self,
                    message=message,
                    xor_key=xor_key)

            elif option == "2":
                file_path = Functions.get_file_path()
                xor_key = Functions.get_xor_key()
                XORDecryption.decrypt_file_with_xor(self,
                    file_path=file_path,
                    xor_key=xor_key)

            elif option == "r":
                App.return_to_main_menu(self)

            elif option == "q":
                Functions.exit_application()

            else:
                App.no_valid_option(self)


        elif choice.lower() == "q":
            Functions.clear_screen()
            Functions.exit_application()

        else:
            Functions.clear_screen()
            App.no_valid_option()


if __name__ == "__main__":
    App.main(App)
