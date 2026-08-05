# !/usr/bin/env python3
# DLU : 03-Aug-2026


from rich.console import Console
import signal
import sys
from resources.functions import Functions
from resources._aes import AES
from resources._pgp import PGP
from resources._key import KEY
from resources._xor import XOR
from resources.vars import STATUS_ICONS
from resources.prompts import show_main_menu

__author__ = "[@mikespon]"
__last_updated__ = "03-Aug-2026"


console = Console()


class App:


    def handle_sigint(sig, frame) -> None:
        """Gracefully handles Ctrl+C signals across the entire application."""
        console.print(
            f"\n\n{STATUS_ICONS['warning2']}[red] Interrupted at line "
            f"{frame.f_lineno} in {frame.f_code.co_filename}"
        )
        console.print(
            f"\n{STATUS_ICONS['warning2']}[red] Operation cancelled by "
            f"user. Exiting..."
        )
        sys.exit(0)


    def main(self) -> None:
        Functions.clear_screen()
        """Main function where the user can pick what option they want."""

        initial_choice = show_main_menu()
        Functions.clear_screen()
        match initial_choice:
            case "1":
                KEY.get_key_action()
            case "2":
                AES.get_aes_action()
            case "3":
                PGP.get_pgp_action()
            case "4":
                XOR.get_xor_action()
            case "q":
                console.print(
                    f"\n\n{STATUS_ICONS['arrow_right']}[green3] Exiting the "
                    "application...\n"
                    )
                sys.exit(0)

    # Register the SIGINT handler
    signal.signal(signal.SIGINT, handle_sigint)


if __name__ == "__main__":
    App().main()


