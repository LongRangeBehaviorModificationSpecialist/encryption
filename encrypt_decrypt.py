# !/usr/bin/env python3
# DLU : 29-Jul-2026

from rich.prompt import Prompt

# Import the console object from the __init__.py file
from . import console
from resources import (
    DataEncryptor,
    KEYClass,
    AESClass,
    PGPClass,
    XORClass,
    AESDecryptor,
    KeyFileDecryptor,
    Functions,
    INITIAL_MENU_PROMPT,
    TOP_LEVEL_ENCRYPTION_MENU_PROMPT,
    PASSWORD_ENCRYPTION_PROMPT,
    PGP_ENCRYPTION_PROMPT,
    XOR_ENCRYPTION_PROMPT,
)

__author__ = "[@mikespon]"
__last_updated__ = "29-Jul-2026"


# password = "mysecretpassword34"
email_address = "testaddress@email.com"


class App:

    def no_valid_option(self) -> None:
        """When a valid option is not entered, the user will be prompted to
        try again and enter a valid option.
        """
        console.print("""[bright_red]
[!] You did not enter a valid option. Please try again.""")
        App.main(self)


    def return_to_main_menu(self) -> None:
        """Returns the user to the main application menu."""
        Functions.clear_screen()
        App.main(self)


    def main(self) -> None:
        Functions.clear_screen()
        """Main function where the user can pick what option they want."""

        initial_choice = (
            Prompt.ask(
                INITIAL_MENU_PROMPT,
                choices=["1", "2", "q"],
                show_choices=False
            )
            .strip()
            .lower()
        )

        if initial_choice == "q":
            Functions.exit_application()
            return

        if initial_choice == "1":
            encryption_choice = (
                Prompt.ask(
                    TOP_LEVEL_ENCRYPTION_MENU_PROMPT,
                    choices=["a", "b", "c", "d", "q"],
                    show_choices=False,
                )
            ).strip().lower()


            if encryption_choice == "q":
                Functions.exit_application()
                return

            if encryption_choice == "a":
                Functions.clear_screen()
                XORClass.get_key_target_choice()

            elif encryption_choice == "b":
                Functions.clear_screen()
                #TODO -- create this function and move logic into it
                AESClass.get_aes_target_choice()

            elif encryption_choice == "c":
                Functions.clear_screen()
                #TODO -- create this function and move logic into it
                PGPClass.get_pgp_target_choice()

            elif encryption_choice == "d":
                Functions.clear_screen()
                #TODO -- create this function and move logic into it
                XORClass.get_xor_target_choice()



#!
#! LEFT OFF HERE -- FIX THINGS BELOW THIS LINE
#!

            elif encryption_choice == "b":
                Functions.clear_screen()
                password_encryption_choice = (
                    Prompt.ask(
                        PASSWORD_ENCRYPTION_PROMPT,
                        choices=["1", "2", "3", "4", "r", "q"],
                        show_choices=False,
                    )
                    .strip()
                    .lower()
                )

            elif encryption_choice == "c":
                Functions.clear_screen()
                pgp_encryption_choice = (
                    Prompt.ask(
                        PGP_ENCRYPTION_PROMPT,
                        choices=["1", "2", "3", "r", "q"],
                        show_choices=False,
                    )
                    .strip()
                    .lower()
                )

            elif encryption_choice == "d":
                Functions.clear_screen()
                xor_encryption_choice = (
                    Prompt.ask(
                        XOR_ENCRYPTION_PROMPT,
                        choices=["1", "2", "3", "r", "q"],
                        show_choices=False,
                    )
                    .strip()
                    .lower()
                )









        elif initial_choice == "2":
            pass


#









        # if choice == "a":
        #     Functions.clear_screen()
        #     DataEncryptor(app_instance=self).run_single_file_encryption(encryption_type=)
        #     # KeyFileEncryptor(app_instance=self).get_target_choice()


        # elif choice == "b":
        #     Functions.clear_screen()
        #     AESEncryptor(app_instance=self).get_target_choice()

        # elif choice == "c":
        #     pass


        # elif choice == "d":
        #     Functions.clear_screen()
        #     PGPEncrypt(app_instance=self).get_target_choice()


        # elif choice == "e":
        #     Functions.clear_screen()
        #     XOREncryptor(app_instance=self).get_target_choice()

            # option = Prompt.ask(
            #     XOR_PROMPT,
            #     choices=["1", "2", "r", "q"],
            #     show_choices=False).strip().lower()



#! ====================
#! DECRYPTION OPTIONS
#! ====================


        elif choice == "f":
            Functions.clear_screen()
            KeyFileDecryptor(app_instance=self).get_target_choice()


        elif choice == "g":
            Functions.clear_screen()
            AESDecryptor(app_instance=self).get_target_choice()



        elif choice == "h":
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


        elif choice == "i":
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
                xor_key = Functions.get_xor_key_prompt()
                XORDecryption.decrypt_msg_with_xor(self,
                    message=message,
                    xor_key=xor_key)

            elif option == "2":
                file_path = Functions.get_file_path()
                xor_key = Functions.get_xor_key_prompt()
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
