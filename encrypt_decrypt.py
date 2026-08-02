# !/usr/bin/env python3
# DLU : 02-Aug-2026

import logging
from rich.prompt import Prompt
from rich.console import Console
import signal
import sys
from resources.logging_setup import setup_logging
from resources.functions import Functions
from resources._aes import AESClass
from resources._pgp import PGPClass
from resources._key import KEYClass
from resources._xor import XORClass
from resources.prompts import (
    show_main_app_menu,
    show_main_encryption_menu,
    show_main_decryption_menu
)

__author__ = "[@mikespon]"
__last_updated__ = "02-Aug-2026"


console = Console()


class App:

    def __init__(self):
        setup_logging()
        self.logger = logging.getLogger(__name__)

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


    def main(self) -> None:
        Functions.clear_screen()
        """Main function where the user can pick what option they want."""

        initial_choice = show_main_app_menu()

        self.logger.info(
            f"User selected {initial_choice}. Continuing..."
        )

        match initial_choice:
            case "1":
                Functions.clear_screen()
                encryption_choice = show_main_encryption_menu()

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
                decryption_choice = show_main_decryption_menu()

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


