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
        # print(f"\nCleaning up {len(self.temp_files)} temporary files...")
        # for file in self.temp_files:
        #     file.unlink(missing_ok=True)
        # Optional: print a full stack traceback of where execution paused
        traceback.print_stack(frame)
        console.print(
            "\n[bright_yellow][!] Operation cancelled by user. Exiting..."
        )
        sys.exit(0)


    def return_to_main_menu(self) -> None:
        """Returns the user to the main application menu."""
        Functions.clear_screen()
        App.main(self)


    def main(self) -> None:
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
                    choices=["a", "b", "c", "d", "q"],
                    show_choices=False
                    ).strip().lower()

                match encryption_choice:
                    case "a":
                        Functions.clear_screen()
                        KEYClass.get_key_action_choice(self, action="encrypt")
                    case "b":
                        Functions.clear_screen()
                        AESClass.get_aes_encryption_choice(self)
                    case "c":
                        Functions.clear_screen()
                        PGPClass.get_pgp_encryption_choice(self)
                    case "d":
                        Functions.clear_screen()
                        XORClass.get_xor_encryption_choice(self)
                    case "q":
                        Functions.exit_application()

            case "2":
                Functions.clear_screen()
                decryption_choice = Prompt.ask(
                    TOP_LEVEL_DECRYPTION_MENU_PROMPT,
                    choices=["a", "b", "c", "d", "q"],
                    show_choices=False
                    ).strip().lower()

                match decryption_choice:
                    case "a":
                        Functions.clear_screen()
                        KEYClass.get_key_action_choice(self, action="decrypt")
                    case "b":
                        Functions.clear_screen()
                        AESClass.get_aes_decryption_choice(self)
                    case "c":
                        Functions.clear_screen()
                        PGPClass.get_pgp_decryption_choice(self)
                    case "d":
                        Functions.clear_screen()
                        XORClass.get_xor_decryption_choice(self)
                    case "q":
                        Functions.exit_application()

            case "q":
                Functions.exit_application()

    # Register the SIGINT handler
    signal.signal(signal.SIGINT, handle_sigint)


if __name__ == "__main__":
    App.main(App)
