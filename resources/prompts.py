# !/usr/bin/env python3

from rich.prompt import Prompt

# Import the console object from the main __init__.py file
from . import console
from utils import Utils
from ui.config import GLOBAL_CONFIG


VERSION = "0.4.1785974400"


def display_menu(
        choices: set,
        menu_text: str,
        clear_on_invalid: bool = True
) -> str:
    """Reusable menu handler with validation loop."""
    while True:
        user_input = Prompt.ask(menu_text, show_choices=False).strip().lower()

        if user_input in choices:
            return user_input

        if clear_on_invalid:
            Utils.clear_screen()
        console.print(
            f"\n\n[cyan][{Utils.get_current_time()}][yellow] \"{user_input}\" is not "
            "a valid option. [/]"
            f"""[white]Valid options for this menu are: {', '.join(
                f"'{c}'" for c in sorted(choices))}.\n\n"""
        )


def show_main_menu() -> str:
    MAIN_MENU_CHOICES = {"1","2","3","4","q"}

    MAIN_MENU = (f"""[dodger_blue1]
----------------------------
ENCRYPT/DECRYPT APP MENU
v.{VERSION}
----------------------------\n
[yellow]What method do you want to use? (select one):[white]\n
[1] Use a .key file
[2] Use a password (AES.GCM)
[3] Use PGP
[4] Use XOR\n
[Q] Quit the Application\n
[yellow]ENTER CHOICE""")

    return display_menu(choices=MAIN_MENU_CHOICES, menu_text=MAIN_MENU)


def show_key_menu() -> str:
    KEY_MENU_CHOICES = {"1","2","3","4","5","r","q"}

    KEY_MENU = """[dodger_blue1]
----------------------------
ENCRYPT/DECRYPT FILE(S)
WITH A .KEY FILE
----------------------------\n
[yellow]Options:[white]\n
[1] Create a [bold]new[/bold] .key file\n
[2] ENCRYPT a single file using a .key
[3] DECRYPT a single file using a .key\n
[4] ENCRYPT all files in a folder using a .key
[5] DECRYPT all files in a folder using a .key\n
[R] Return to the main menu
[Q] Quit the application\n
[yellow]ENTER CHOICE"""

    return display_menu(choices=KEY_MENU_CHOICES, menu_text=KEY_MENU)


def show_aes_menu() -> str:
    AES_MENU_CHOICES = {"1","2","3","4","r","q"}

    AES_MENU = """[dodger_blue1]
----------------------------
ENCRYPT/DECRYPT FILE(S)
WITH A PASSWORD [AES-GCM]
----------------------------\n
[yellow]Options:[white]\n
[1] ENCRYPT a single file
[2] DECRYPT a single file\n
[3] ENCRYPT all files in a folder
[4] DECRYPT all files in a folder\n
[R] Return to the main menu
[Q] Quit the application\n
[yellow]ENTER CHOICE"""

    return display_menu(choices=AES_MENU_CHOICES, menu_text=AES_MENU)


def show_pgp_menu() -> str:
    PGP_MENU_CHOICES = {"1","2","3","4","5","6","7","8","a","r","q"}

    PGP_MENU = """[dodger_blue1]
----------------------------
ENCRYPT/DECRYPT FILE(S)
WITH PGP KEY
----------------------------\n
[yellow]Options:[white]\n
[A] Debug PGP setup\n
[1] Create new PGP key pair
[2] Import a PGP key\n
[3] ENCRYPT a file using PGP
[4] DECRYPT a file using PGP\n
[5] ENCRYPT all files in a folder using PGP
[6] DECRYPT all files in a folder using PGP\n
[7] Sign a document with PGP
[8] Verify a PGP signature\n
[R] Return to the main menu
[Q] Quit the application\n
[yellow]ENTER CHOICE"""

    return display_menu(choices=PGP_MENU_CHOICES, menu_text=PGP_MENU)


def show_xor_menu() -> str:
    XOR_MENU_CHOICES = {"1","2","r","q"}

    XOR_MENU = """[dodger_blue1]
----------------------------
ENCRYPT/DECRYPT A MESSAGE OR
FILE(S) USING AN XOR KEY
----------------------------\n
[yellow]Options:[white]\n
[1] ENCRYPT a single message string
[2] DECRYPT a single message string\n
[R] Return to the main menu
[Q] Quit the application\n
[yellow]ENTER CHOICE"""

    return display_menu(choices=XOR_MENU_CHOICES, menu_text=XOR_MENU)
