# !/usr/bin/env python3
# DLU : 30-Jul-2026

import signal
import sys
import traceback

from rich.prompt import Prompt
from rich.console import Console

from resources.functions import Functions
from resources._aes import AESClass
from resources._pgp import PGPClass
from resources._key import KEYClass
from resources._xor import XORClass
from resources.prompts import (
    INITIAL_MENU_PROMPT,
    TOP_LEVEL_ENCRYPTION_MENU_PROMPT,
    TOP_LEVEL_DECRYPTION_MENU_PROMPT
)

__author__ = "[@mikespon]"
__last_updated__ = "30-Jul-2026"


console = Console()


class App:

    # def __init__(self) -> None:
        # self.temp_files = []

        # Register using a lambda to bind 'self' while satisfying (sig, frame)
        # signal.signal(signal.SIGINT, lambda sig, frame: self.handle_sigint(sig, frame))


    @staticmethod
    def handle_sigint(sig, frame) -> None:
        """Gracefully handles Ctrl+C signals across the entire application."""
        console.print(
            f"[!] Interrupted at line {frame.f_lineno} in "
            f"{frame.f_code.co_filename}"
            )
        console.print(
            "\n[bright_yellow][!] Operation cancelled by user. Exiting..."
        )
        sys.exit(0)


    # def return_to_main_menu(self) -> None:
    #     """Returns the user to the main application menu."""
    #     Functions.clear_screen()
    #     App.main(self)


    @staticmethod
    def main() -> None:
        Functions.clear_screen()
        """Main function where the user can pick what option they want."""

        initial_choice = Prompt.ask(
            INITIAL_MENU_PROMPT,
            choices=["1", "2", "q"],
            show_choices=False
            ).strip().lower()

        match initial_choice:
            case "1":
                Functions.clear_screen()
                encryption_choice = Prompt.ask(
                    TOP_LEVEL_ENCRYPTION_MENU_PROMPT,
                    choices=["1", "2", "3", "4", "q"],
                    show_choices=False
                    ).strip().lower()

                match encryption_choice:
                    case "1":
                        Functions.clear_screen()
                        KEYClass.get_key_action_choice(action="encrypt")
                    case "2":
                        Functions.clear_screen()
                        AESClass.get_aes_encryption_choice()
                    case "3":
                        Functions.clear_screen()
                        PGPClass.get_pgp_encryption_choice()
                    case "4":
                        Functions.clear_screen()
                        XORClass.get_xor_encryption_choice()
                    case "q":
                        Functions.exit_application()

            case "2":
                Functions.clear_screen()
                decryption_choice = Prompt.ask(
                    TOP_LEVEL_DECRYPTION_MENU_PROMPT,
                    choices=["1", "2", "3", "4", "q"],
                    show_choices=False
                    ).strip().lower()

                match decryption_choice:
                    case "1":
                        Functions.clear_screen()
                        KEYClass.get_key_action_choice(action="decrypt")
                    case "2":
                        Functions.clear_screen()
                        AESClass.get_aes_decryption_choice()
                    case "3":
                        Functions.clear_screen()
                        PGPClass.get_pgp_decryption_choice()
                    case "4":
                        Functions.clear_screen()
                        XORClass.get_xor_decryption_choice()
                    case "q":
                        Functions.exit_application()

            case "q":
                Functions.exit_application()

    # Register the SIGINT handler
    signal.signal(signal.SIGINT, handle_sigint)


if __name__ == "__main__":
    # App.main(App)
    # app = App()
    # app.main()

    App.main()
