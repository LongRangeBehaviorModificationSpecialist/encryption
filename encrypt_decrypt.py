# !/usr/bin/env python3
# DLU : 07-Aug-2026


from rich.console import Console
import signal
import sys
from resources.functions import Functions
from resources.vars import ICONS
from resources.prompts import show_main_menu

from resources._key import KEY
from resources._aes import AES
from resources._pgp import PGP
from resources._xor import XOR

__author__ = "[@mikespon]"
__last_updated__ = "07-Aug-2026"


console = Console()


class App:

    """Main application class."""

    def __init__(self):
        """Initialize the application and register signal handlers."""
        # Register SIGINT handler during initialization
        signal.signal(signal.SIGINT, self.handle_sigint)

        # Initialize subsystems
        self.key = KEY()
        self.aes = AES()
        self.pgp = PGP()
        self.xor = XOR()


    def handle_sigint(self, sig, frame) -> None:
        """Gracefully handles Ctrl+C signals across the entire application."""
        console.print(
            f"\n\n\n{ICONS['warning']}[red] Operation cancelled by "
            f"user. Exiting...\n"
        )
        sys.exit(0)


    def main(self) -> None:
        """Main function where the user can pick their option."""
        Functions.clear_screen()
        initial_choice = show_main_menu()
        Functions.clear_screen()

        match initial_choice:
            case "1":
                self.key.get_key_action()
            case "2":
                self.aes.get_aes_action()
            case "3":
                self.pgp.get_pgp_action()
            case "4":
                self.xor.get_xor_action()
            case "q":
                Functions.exit_application()
            case _:
                console.print(
                    f"{ICONS['warning']}[yellow] An invalid option "
                    "was entered"
                )


if __name__ == "__main__":
    app = App()
    app.main()


