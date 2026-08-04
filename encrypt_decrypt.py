# !/usr/bin/env python3
# DLU : 03-Aug-2026

import logging
from rich.console import Console
import signal
import sys
from resources.logging_setup import setup_logging
from resources.functions import Functions
from resources._aes import AES
from resources._pgp import PGP
from resources._key import KEY
from resources._xor import XOR
from resources.prompts import (
    show_main_app_menu,
    show_main_encryption_menu,
    show_main_decryption_menu
)

__author__ = "[@mikespon]"
__last_updated__ = "03-Aug-2026"


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
            f"{frame.f_code.co_filename}")
        console.print(
            "\n[bright_yellow][!] Operation cancelled by user. Exiting...")
        sys.exit(0)


    def main(self) -> None:
        Functions.clear_screen()
        """Main function where the user can pick what option they want."""

        initial_choice = show_main_app_menu()

        self.logger.info(
            f"User selected {initial_choice}. Continuing...")

        match initial_choice:

            case "1":  # MAIN ENCRYPTION MENU
                Functions.clear_screen()
                encryption_choice = show_main_encryption_menu()
                action = "encrypt"
                match encryption_choice:
                    case "1":
                        Functions.clear_screen()
                        KEY.get_key_action_choice(action=action)
                    case "2":
                        Functions.clear_screen()
                        AES.get_aes_action(action=action)
                    case "3":
                        Functions.clear_screen()
                        PGP.get_pgp_action(action=action)
                    case "4":
                        Functions.clear_screen()
                        XOR.get_xor_action(action=action)
                    case "q":
                        Functions.exit_application()

            case "2":  # MAIN DECRYPTION MENU
                Functions.clear_screen()
                decryption_choice = show_main_decryption_menu()
                action = "decrypt"
                match decryption_choice:
                    case "1":
                        Functions.clear_screen()
                        KEY.get_key_action_choice(action=action)
                    case "2":
                        Functions.clear_screen()
                        AES.get_aes_action(action=action)
                    case "3":
                        Functions.clear_screen()
                        PGP.get_pgp_action(action=action)
                    case "4":
                        Functions.clear_screen()
                        XOR.get_xor_action(action=action)
                    case "q":
                        Functions.exit_application()

            case "q":
                Functions.exit_application()

    # Register the SIGINT handler
    signal.signal(signal.SIGINT, handle_sigint)


if __name__ == "__main__":
    App.main()


