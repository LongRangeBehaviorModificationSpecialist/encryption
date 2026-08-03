from rich.prompt import Prompt

# Import the console object from the main __init__.py file
from . import console


VERSION = "0.3.17076096"


def show_main_app_menu() -> str:
    MAIN_APP_MENU = f"""[dodger_blue1]
----------------------------
ENCRYPT/DECRYPT
APPLICATION MENU
v.{VERSION}
----------------------------\n
[khaki3]What do you want to do? (select one) :[bright_white]\n
[1] Run ENCRYPTION
[2] Run DECRYPTION\n
[Q] Quit the Application\n\n
[khaki3]ENTER CHOICE """
    return (Prompt.ask(MAIN_APP_MENU,
        choices=["1", "2", "q"],
        show_choices=False).strip().lower())


def show_main_encryption_menu() -> str:
    MAIN_ENCRYPTION_MENU = f"""[dodger_blue1]
----------------------------
MAIN ENCRYPTION MENU
v.{VERSION}
----------------------------\n
[khaki3]Select the ENCRYPTION method you want to use :[bright_white]\n
[1] Use a .key file
[2] Use a password
[3] Use PGP keys
[4] Use XOR\n
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """
    return (Prompt.ask(MAIN_ENCRYPTION_MENU,
        choices=["1", "2", "3", "4", "q"],
        show_choices=False).strip().lower())


def show_key_encryption_menu() -> str:
    KEY_ENCRYPTION_MENU = """[dodger_blue1]
----------------------------
ENCRYPT FILE(S)
WITH A .KEY FILE
----------------------------\n
[khaki3]Options :[bright_white]\n
[1] Create a [bold]new[/bold] .key file
[2] Encrypt a single file using a .key
[3] Erypt all files in a folder using a .key\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """
    return (Prompt.ask(KEY_ENCRYPTION_MENU,
        choices=["1", "2", "3", "r", "q"],
        show_choices=False).strip().lower())


def show_aes_encryption_menu() -> str:
    AES_ENCRYPTION_MENU = """[dodger_blue1]
----------------------------
ENCRYPT FILE(S) WITH A
PASSWORD [AES-GCM mode]
----------------------------\n
[khaki3]Options :[bright_white]\n
[1] Encrypt a single file
[2] Encrypt all files in a folder\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """
    return (Prompt.ask(AES_ENCRYPTION_MENU,
        choices=["1", "2", "r", "q"],
        show_choices=False).strip().lower())


def show_pgp_encryption_menu() -> str:
    PGP_ENCRYPTION_MENU = """[dodger_blue1]
----------------------------
ENCRYPT FILE(S) WITH PGP KEY
----------------------------\n
[khaki3]Options :[bright_white]\n
[1] Create new PGP key pair
[2] Encrypt a file using PGP
[3] Encrypt all files in a folder using PGP\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """
    return (Prompt.ask(PGP_ENCRYPTION_MENU,
        choices=["1", "2", "3", "r", "q"],
        show_choices=False).strip().lower())


def show_pgp_encryption_type_menu() -> str:
    PGP_ENCRYPTION_TYPE_MENU = """[dodger_blue1]
----------------------------
SELECT PGP ENCRYPTION TYPE
----------------------------\n
[khaki3]Options :[bright_white]\n
[1] Asymmetric (using a public key)
[2] Symmetric (password only, no key needed)\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """
    return (Prompt.ask(PGP_ENCRYPTION_TYPE_MENU,
        choices=["1", "2", "r", "q"],
        show_choices=False).strip().lower())


def show_pgp_armor_choice() -> str:
    PGP_ARMOUR_CHOICE_MENU = """[dodger_blue1]
--------------------------------------------
SELECT PGP ARMOR OUTPUT FORMAT
--------------------------------------------\n
[khaki3]Options :[bright_white]\n
[1] Binary output (.gpg)
[2] ASCII-armored output (.asc)\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """
    return (Prompt.ask(PGP_ARMOUR_CHOICE_MENU,
            choices=["1", "2", "r", "q"],
            show_choices=False).strip().lower())


def show_xor_encryption_menu() -> str:
    XOR_ENCRYPTION_MENU = """[dodger_blue1]
----------------------------
ENCRYPT MESSAGE OR FILE(S)
USING AN XOR KEY
----------------------------\n
[khaki3]Options :[bright_white]\n
[1] Encrypt a single message string
[2] Encrypt a file
[3] Encrypt all files in a folder\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """
    return (Prompt.ask(XOR_ENCRYPTION_MENU,
        choices=["1", "2", "3", "r", "q"],
        show_choices=False).strip().lower())


def show_main_decryption_menu() -> str:
    MAIN_DECRYPTION_MENU = f"""[dodger_blue1]
----------------------------
MAIN DECRYPTION MENU
v.{VERSION}
----------------------------\n
[khaki3]Select the DECRYPTION method you want to use :[bright_white]\n
[1] Decrypt file(s) using a .key file
[2] Decrypt file(s) using a password
[3] Decrypt file(s) using a PGP key
[4] Decrypt message/file(s) using XOR\n
[Q] Quit the Application\n\n
[khaki3]ENTER CHOICE """
    return (Prompt.ask(MAIN_DECRYPTION_MENU,
        choices=["1", "2", "3", "4", "q"],
        show_choices=False).strip().lower())


def show_key_decryption_menu() -> str:
    KEY_DECRYPTION_MENU = """[dodger_blue1]
--------------------------------------------
DECRYPT FILE(S) WITH PROVIDED .KEY
--------------------------------------------\n
[khaki3]Options :[bright_white]\n
[1] Decrypt a file using a .key
[2] Decrypt files in a folder using a .key\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """
    return (Prompt.ask(KEY_DECRYPTION_MENU,
        choices=["1", "2", "r", "q"],
        show_choices=False).strip().lower())


def show_aes_decryption_menu() -> str:
    AES_DECRYPTION_MENU = """[dodger_blue1]
--------------------------------------------
DECRYPT FILE(S) WITH PASSWORD [AES-GCM mode]
--------------------------------------------\n
[khaki3]Options :[bright_white]\n
[1] Decrypt a single file using a password
[2] Decrypt all files in a directory using a password\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """
    return (Prompt.ask(AES_DECRYPTION_MENU,
        choices=["1", "2", "r", "q"],
        show_choices=False).strip().lower())


def show_pgp_decryption_menu() -> str:
    PGP_DECRYPTION_MENU = """[dodger_blue1]
--------------------------------------------
DECRYPT FILE(S) USING PGP KEY
--------------------------------------------\n
[khaki3]Options :[bright_white]\n
[1] Decrypt a file using PGP
[2] Decrypt all files in a folder using PGP\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """
    return (Prompt.ask(PGP_DECRYPTION_MENU,
        choices=["1", "2", "r", "q"],
        show_choices=False).strip().lower())


def show_pgp_decryption_type_menu() -> str:
    PGP_DECRYPTION_TYPE_MENU = """[dodger_blue1]
----------------------------
SELECT PGP DECRYPTION TYPE
----------------------------\n
[khaki3]Options :[bright_white]\n
[1] Asymmetric (using a private key)
[2] Symmetric (password only)\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """
    return (Prompt.ask(PGP_DECRYPTION_TYPE_MENU,
        choices=["1", "2", "r", "q"],
        show_choices=False).strip().lower())


def show_xor_decryption_menu() -> str:
    XOR_DECRYPTION_MENU = """[dodger_blue1]
--------------------------------------------
ENCRYPT MESSAGE OR FILE(S) USING AN XOR KEY
--------------------------------------------\n
[khaki3]Options :[bright_white]\n
[1] Decrypt a single message
[2] Decrypt a file
[3] Decrypt all files in a folder using XOR\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """
    return (Prompt.ask(XOR_DECRYPTION_MENU,
        choices=["1", "2", "3", "r", "q"],
        show_choices=False).strip().lower())