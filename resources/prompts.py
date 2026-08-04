from rich.prompt import Prompt
from functions import Functions


VERSION = "0.3.17076096"


def show_main_menu() -> str:
    Functions.clear_screen()
    MAIN_MENU = f"""[dodger_blue1]
----------------------------
ENCRYPT/DECRYPT APP MENU
v.{VERSION}
----------------------------\n
[khaki3]What method do you want to use? (select one) :[bright_white]\n
[1] Use a .key file
[2] Use a password
[3] Use PGP
[4] Use XOR\n
[Q] Quit the Application\n\n
[khaki3]ENTER CHOICE """
    return (Prompt.ask(MAIN_MENU,
        choices=["1", "2", "3", "4", "q"],
        show_choices=False).strip().lower())


def show_key_menu() -> str:
    KEY_MENU = """[dodger_blue1]
----------------------------
ENCRYPT/DECRYPT FILE(S)
WITH A .KEY FILE
----------------------------\n
[khaki3]Options :[bright_white]\n
[1] Create a [bold]new[/bold] .key file\n
[2] ENCRYPT a single file using a .key
[3] DECRYPT a single file using a .key\n
[4] ENCRYPT all files in a folder using a .key
[5] DECRYPT all files in a folder using a .key\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """
    return (Prompt.ask(KEY_MENU,
        choices=["1", "2", "3", "4", "5", "r", "q"],
        show_choices=False).strip().lower())


def show_aes_menu() -> str:
    AES_MENU = """[dodger_blue1]
----------------------------
ENCRYPT/DECRYPT FILE(S)
WITH A PASSWORD [AES-GCM]
----------------------------\n
[khaki3]Options :[bright_white]\n
[1] ENCRYPT a single file
[2] DECRYPT a single file\n
[3] ENCRYPT all files in a folder
[4] DECRYPT all files in a folder\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """
    return (Prompt.ask(AES_MENU,
        choices=["1", "2", "3", "4", "r", "q"],
        show_choices=False).strip().lower())


def show_pgp_menu() -> str:
    PGP_MENU = """[dodger_blue1]
----------------------------
ENCRYPT/DECRYPT FILE(S)
WITH PGP KEY
----------------------------\n
[khaki3]Options :[bright_white]\n
[1] Create new PGP key pair\n
[2] ENCRYPT a file using PGP
[3] DECRYPT a file using PGP\n
[4] ENCRYPT all files in a folder using PGP
[5] DECRYPT all files in a folder using PGP\n
[6] Sign a document with PGP
[7] Verify a PGP signature\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """
    return (Prompt.ask(PGP_MENU,
        choices=["1", "2", "3", "4", "5", "6", "7" "r", "q"],
        show_choices=False).strip().lower())


def show_xor_menu() -> str:
    XOR_MENU = """[dodger_blue1]
----------------------------
ENCRYPT/DECRYPT A MESSAGE OR
FILE(S) USING AN XOR KEY
----------------------------\n
[khaki3]Options :[bright_white]\n
[1] ENCRYPT a single message string
[2] DECRYPT a single message string\n
[3] ENCRYPT a file
[4] DECRYPT a file\n
[5] ENCRYPT all files in a folder
[6] DECRYPT all files in a folder\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """
    return (Prompt.ask(XOR_MENU,
        choices=["1", "2", "3", "4", "5", "6", "r", "q"],
        show_choices=False).strip().lower())


# def show_main_encryption_menu() -> str:
#     MAIN_ENCRYPTION_MENU = f"""[dodger_blue1]
# ----------------------------
# MAIN ENCRYPTION MENU
# v.{VERSION}
# ----------------------------\n
# [khaki3]Select the ENCRYPTION method you want to use :[bright_white]\n
# [1] Use a .key file
# [2] Use a password
# [3] Use PGP keys
# [4] Use XOR\n
# [Q] Quit the application\n\n
# [khaki3]ENTER CHOICE """
#     return (Prompt.ask(MAIN_ENCRYPTION_MENU,
#         choices=["1", "2", "3", "4", "q"],
#         show_choices=False).strip().lower())


# def show_pgp_encryption_type_menu() -> str:
#     PGP_ENCRYPTION_TYPE_MENU = """[dodger_blue1]
# ----------------------------
# SELECT PGP ENCRYPTION TYPE
# ----------------------------\n
# [khaki3]Options :[bright_white]\n
# [1] Asymmetric (using a public key)
# [2] Symmetric (password only, no key needed)\n
# [R] Return to the main menu
# [Q] Quit the application\n\n
# [khaki3]ENTER CHOICE """
#     return (Prompt.ask(PGP_ENCRYPTION_TYPE_MENU,
#         choices=["1", "2", "r", "q"],
#         show_choices=False).strip().lower())


# def show_pgp_armor_choice() -> str:
#     PGP_ARMOUR_CHOICE_MENU = """[dodger_blue1]
# --------------------------------------------
# SELECT PGP ARMOR OUTPUT FORMAT
# --------------------------------------------\n
# [khaki3]Options :[bright_white]\n
# [1] Binary output (.gpg)
# [2] ASCII-armored output (.asc)\n
# [R] Return to the main menu
# [Q] Quit the application\n\n
# [khaki3]ENTER CHOICE """
#     return (Prompt.ask(PGP_ARMOUR_CHOICE_MENU,
#             choices=["1", "2", "r", "q"],
#             show_choices=False).strip().lower())


# def show_main_decryption_menu() -> str:
#     MAIN_DECRYPTION_MENU = f"""[dodger_blue1]
# ----------------------------
# MAIN DECRYPTION MENU
# v.{VERSION}
# ----------------------------\n
# [khaki3]Select the DECRYPTION method you want to use :[bright_white]\n
# [1] Decrypt file(s) using a .key file
# [2] Decrypt file(s) using a password
# [3] Decrypt file(s) using a PGP key
# [4] Decrypt message/file(s) using XOR\n
# [Q] Quit the Application\n\n
# [khaki3]ENTER CHOICE """
#     return (Prompt.ask(MAIN_DECRYPTION_MENU,
#         choices=["1", "2", "3", "4", "q"],
#         show_choices=False).strip().lower())


# def show_key_decryption_menu() -> str:
#     KEY_DECRYPTION_MENU = """[dodger_blue1]
# --------------------------------------------
# DECRYPT FILE(S) WITH PROVIDED .KEY
# --------------------------------------------\n
# [khaki3]Options :[bright_white]\n
# [1] Decrypt a file using a .key
# [2] Decrypt files in a folder using a .key\n
# [R] Return to the main menu
# [Q] Quit the application\n\n
# [khaki3]ENTER CHOICE """
#     return (Prompt.ask(KEY_DECRYPTION_MENU,
#         choices=["1", "2", "r", "q"],
#         show_choices=False).strip().lower())


# def show_aes_decryption_menu() -> str:
#     AES_DECRYPTION_MENU = """[dodger_blue1]
# --------------------------------------------
# DECRYPT FILE(S) WITH PASSWORD [AES-GCM mode]
# --------------------------------------------\n
# [khaki3]Options :[bright_white]\n
# [1] Decrypt a single file using a password
# [2] Decrypt all files in a directory using a password\n
# [R] Return to the main menu
# [Q] Quit the application\n\n
# [khaki3]ENTER CHOICE """
#     return (Prompt.ask(AES_DECRYPTION_MENU,
#         choices=["1", "2", "r", "q"],
#         show_choices=False).strip().lower())


# def show_pgp_decryption_menu() -> str:
#     PGP_DECRYPTION_MENU = """[dodger_blue1]
# --------------------------------------------
# DECRYPT FILE(S) USING PGP KEY
# --------------------------------------------\n
# [khaki3]Options :[bright_white]\n
# [1] Decrypt a file using PGP
# [2] Decrypt all files in a folder using PGP\n
# [R] Return to the main menu
# [Q] Quit the application\n\n
# [khaki3]ENTER CHOICE """
#     return (Prompt.ask(PGP_DECRYPTION_MENU,
#         choices=["1", "2", "r", "q"],
#         show_choices=False).strip().lower())


# def show_pgp_decryption_type_menu() -> str:
#     PGP_DECRYPTION_TYPE_MENU = """[dodger_blue1]
# ----------------------------
# SELECT PGP DECRYPTION TYPE
# ----------------------------\n
# [khaki3]Options :[bright_white]\n
# [1] Asymmetric (using a private key)
# [2] Symmetric (password only)\n
# [R] Return to the main menu
# [Q] Quit the application\n\n
# [khaki3]ENTER CHOICE """
#     return (Prompt.ask(PGP_DECRYPTION_TYPE_MENU,
#         choices=["1", "2", "r", "q"],
#         show_choices=False).strip().lower())


# def show_xor_decryption_menu() -> str:
#     XOR_DECRYPTION_MENU = """[dodger_blue1]
# --------------------------------------------
# ENCRYPT MESSAGE OR FILE(S) USING AN XOR KEY
# --------------------------------------------\n
# [khaki3]Options :[bright_white]\n
# [1] Decrypt a single message
# [2] Decrypt a file
# [3] Decrypt all files in a folder using XOR\n
# [R] Return to the main menu
# [Q] Quit the application\n\n
# [khaki3]ENTER CHOICE """
#     return (Prompt.ask(XOR_DECRYPTION_MENU,
#         choices=["1", "2", "3", "r", "q"],
#         show_choices=False).strip().lower())