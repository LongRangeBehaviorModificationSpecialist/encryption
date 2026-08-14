# !/usr/bin/env python3

from functools import partial
import logging
from resources._key import KEY
from resources._aes import AES
from resources._pgp import PGP
from resources._xor import XOR
from utils import Utils
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.traceback import install
import signal
import sys
import traceback

from config.config import (
    GLOBAL_CONFIG,
    SubMenuItem,
)
from config.log_config import setup_logging, get_logger
from versions import (
    __version__,
    __author__,
    __last_updated__,
    get_version_string
)


console = Console()
install(show_locals=True, console=console)

# Set up logging FIRST (before anything else)
logger = setup_logging(log_dir="logs", log_level=logging.DEBUG)
logger = get_logger("main")


def get_exit_message(config) -> str:
    """Print exit confirmation message then exit app."""
    console.print(
        f"\n[green]Exiting the application...\n"
        f"[grey58]Done"
    )
    sys.exit(0)


class Main:
    """Main application class."""

    def __init__(self):
        """Initialize the application and register signal handlers."""
        # Register SIGINT handler during initialization
        signal.signal(signal.SIGINT, self.handle_sigint)
        # Use the pre-built config instance
        self.config = GLOBAL_CONFIG
        self._author = __author__
        self._version = __version__
        self._last_updated = __last_updated__
        self._version_banner = get_version_string(short=False)

        # Log initialization
        logger.info("Initializing application modules...")
        logger.info(f"Version: {self._version}")
        logger.info(f"Author: {self._author}")

        # Initialize subsystems
        self.key = KEY()
        self.aes = AES()
        self.pgp = PGP()
        self.xor = XOR()

        # Map handler names to actual method references
        self._modules = {
            "key": self.key,
            "aes": self.aes,
            "pgp": self.pgp,
            "xor": self.xor,
        }

        self._bind_handlers()
        logger.info("All modules initialized successfully")


    def handle_sigint(self, sig, frame) -> None:
        """Gracefully handles Ctrl+C signals across the entire application."""
        console.print(
            f"\n[cyan][{Utils.get_current_time()}][red] Operation "
            f"cancelled by user. Exiting...\n"
        )
        sys.exit(0)


    def _bind_handlers(self) -> None:
        """Bind partial functions for all submenu items."""
        # Iterate through each main category
        for category_key, category in self.config.main_categories.items():
            # Iterate through each submenu item in that category
            for sub_key, item in category.submenu_items.items():
                if item.handler_module and item.handler_method:
                    # Get the module instance
                    module = self._modules.get(item.handler_module)
                    if module:
                        handler = getattr(module, item.handler_method, None)
                        if handler and callable(handler):
                            try:
                                item.handler_callable = partial(
                                    handler,
                                    **item.handler_kwargs
                                )
                            except Exception as e:
                                console.print(
                                    f"{GLOBAL_CONFIG.yellow_line}"
                                    f"⚠ Failed to bind "
                                    f"[{category_key}][{sub_key}] -> {e}"
                                )
                        else:
                            console.print(
                                f"{GLOBAL_CONFIG.yellow_line}"
                                f"⚠ Warning: Method '{item.handler_method}' "
                                f"not found in {item.handler_module} for "
                                f"submenu [{category_key}][{sub_key}]"
                            )
                            console.print(
                                f"[cyan][{Utils.get_current_time()}][grey58] "
                                f"Available methods in {item.handler_module}: "
                                f"{[m for m in dir(module) if not m.startswith('_')]}"
                            )
                        # Debug info - list available methods
                        available = [
                            m for m in dir(module)
                            if callable(getattr(module, m))
                            and not m.startswith("_")
                        ]
                        console.print(
                            f"[cyan][{Utils.get_current_time()}][grey58] "
                            f"Available methods in {item.handler_module} -> "
                            f"{', '.join(available)}"
                        )
                        continue

                    # Verify it's actually callable
                    if not callable(handler):
                        console.print(
                            f"{GLOBAL_CONFIG.red_line}"
                            f"✗ Error: '{item.handler_method}' is not "
                            f"callable (it's a {type(handler).__name__}) "
                            f"for submenu {category_key}][{sub_key}]"
                        )
                        continue

                    try:
                        # Create the partial function with handler_kwargs
                        item.handler_callable = partial(
                            handler,
                            **item.handler_kwargs
                        )
                    except Exception as e:
                        console.print(
                            f"[cyan][{Utils.get_current_time()}][red] "
                            f"✗ Error binding handler for [{category_key}]"
                            f"[{sub_key}] -> {e}"
                        )
                        continue


    def _call_handler(self, menu_item: SubMenuItem) -> bool:
        """Execute the handler for a submenu item.

        Args:
            menu_item: The SubMenuItem to execute

        Returns:
            True if handler executed successfully, False otherwise
        """
        if menu_item.handler_module and menu_item.handler_method:
            module = self._modules.get(menu_item.handler_module)
            if module:
                handler = getattr(module, menu_item.handler_method, None)
                if handler and callable(handler):
                    try:
                        handler(**menu_item.handler_kwargs)
                        return True
                    except Exception as e:
                        console.print(
                            f"[cyan][{Utils.get_current_time()}][red] Error "
                            f"executing handler: {type(e).__name__} -> {e}"
                        )
                        import traceback
                        console.print(
                            f"[cyan][{Utils.get_current_time()}][grey58] "
                            "Traceback:"
                        )
                        console.print(traceback.format_exc())
                        return False
                else:
                    console.print(
                        f"[cyan][{Utils.get_current_time()}][red] Method "
                        f"'{menu_item.handler_method}' not found or not "
                        f"callable in {menu_item.handler_module}"
                    )
                    return False
            else:
                console.print(
                    f"[cyan][{Utils.get_current_time()}][red] Module "
                    f"'{menu_item.handler_module}' not found"
                )
                return False

        # No handler configured
        console.print(
            f"[cyan][{Utils.get_current_time()}][yellow] No handler "
            f"configured for this item"
        )
        return False


    def run_submenu_loop(self, category_key: str) -> None:
        """Run the submenu loop for a selected category.

        Args:
            category_key: Key from main_categories (e.g., "1", "2", "3", "4")
        """
        exit_program = False

        while not exit_program:
            category = self.config.main_categories.get(category_key)
            if not category:
                logger.error(
                    f"Invalid category requested: [ '{category_key}' ]"
                )
                console.print(
                    f"[cyan][{Utils.get_current_time()}][red] Invalid "
                    "category"
                )
                return

            logger.info(f"Entered submenu loop for category: {category_key}")

            # Clear the screen before showing submenu
            Utils.clear_screen()

            # Show the submenu
            self.display_sub_menu(category_key)

            try:
                selection = Prompt.ask(f"\n[yellow]ENTER CHOICE").strip()
                normalized = selection.lower()

                logger.debug(f"User selected: {normalized}")

                # Check for back command
                if normalized in ["r"]:
                    logger.debug("User returned to main menu")
                    # Return to main menu
                    return

                # Check for quit
                if normalized in ["q"]:
                    console.print(get_exit_message(self.config))
                    logger.info("User chose to exit from submenu")
                    exit_program = True
                    return

                # Validate submenu item exists
                if normalized not in category.submenu_items.keys():
                    console.print(
                        f"[cyan][{Utils.get_current_time()}][red] Invalid "
                        "choice. Try again or press \"R\" to go back."
                    )
                    continue

                # Execute the selected operation
                item = category.submenu_items[normalized]
                logger.info(
                    f"Executing operation: [{category_key}][{normalized}] -> "
                    f"{item.label}"
                )

                self._call_handler(item)

                # Ask if user wants to continue
                if not self._ask_continue():
                    exit_program = True
                    return

            except KeyboardInterrupt:
                console.print(
                    f"\n[cyan][{Utils.get_current_time()}][yellow] "
                    "Interrupted by user."
                )
                return
            except EOFError:
                return


    def _ask_continue(self) -> bool:
        """Ask user if they want to continue to main menu.

        Returns:
            True if user wants to continue, False to exit
        """
        try:

            response = Confirm.ask(
                f"\n[cyan][{Utils.get_current_time()}][grey66] Task complete! "
                "Return to previous menu?"
            )

            if not response:
                logger.info("The application was closed by the user")
                console.print(get_exit_message(self.config))
                return False

            logger.info("User returned to the previous menu")
            return True

        except (KeyboardInterrupt, EOFError) as e:
            logger.error(f"An error occured during this operation -> {e}")
            # Exit on interrupt during prompt
            return False


    def display_main_menu(self) -> None:
        """Render the main menu using configuration."""
        logger.info("Displaying main menu")

        menu_table = Table(
            box=None,
            show_header=False,
            header_style=self.config.header_style,
            show_lines=False,
            pad_edge=True,
            padding=(0, 5, 0, 1),
            caption_justify=self.config.credits_justify,
            caption_style="grey58",
            expand=False,
            safe_box=True,
        )

        menu_table.add_row(f"\n[yellow]What method do you want to use?\n")

        # Display main categories (1-4)
        for key in sorted(self.config.main_categories.keys()):
            category = self.config.main_categories[key]
            menu_table.add_row(
                f"[grey66][{key}] {category.label} [grey58]"
                f"[{category.description}]"
            )

        # Add quit option
        menu_table.add_row()  # Blank row
        menu_table.add_row(f"[yellow][Q] Quit Program")

        # Blank line at end
        menu_table.add_row()

        # To put the main menu table inside a Panel for better formatting
        menu_panel = Panel.fit(
            renderable=menu_table,
            title=(
                f"[blue][i]\n{self.config.app_name} (v.{self._version})"
            ),
            title_align="center",
            subtitle=(
                f"[grey66][dim][i]Written by: {self._author} | Last Updated: "
                f"{self._last_updated}"
            ),
            subtitle_align="center",
        )

        console.print(menu_panel)


    def display_sub_menu(self, category_key: str) -> None:
        """Render submenu for a specific encryption category.

        Args:
            category_key: Keys from main_categories
        """
        logger.info(f"User viewing submenu for category: {category_key}")
        category = self.config.main_categories.get(category_key)
        if not category:
            console.print(
                f"[cyan][{Utils.get_current_time()}][red] Invalid category "
                "selected"
            )
            return

        sub_menu_table = Table(
            box=None,
            show_header=False,
            header_style=self.config.header_style,
            show_lines=False,
            show_edge=False,
            pad_edge=True,
            padding=(0, 5, 0, 1),
            expand=False,
            safe_box=True,
        )

        sub_menu_table.add_row(f"\n[yellow]Options:\n")

        # Display sub-menu items
        for sub_key in sorted(category.submenu_items.keys()):
            item = category.submenu_items[sub_key]
            sub_menu_table.add_row(
                f"[grey66][{sub_key}] {item.label} [grey58][{item.description}]"
            )

        sub_menu_table.add_row()

        # Add back option
        sub_menu_table.add_row(f"[grey66][R] Return to the main menu")

        # Add exit option
        sub_menu_table.add_row(f"[grey66][Q] Quit the application")

        # Blank line at end
        sub_menu_table.add_row()

        # To put the main menu table inside a Panel for better formatting
        sub_menu_panel = Panel.fit(
            renderable=sub_menu_table,
            title=(
                f"[blue][i][{self.config.title_color}]\n{category.label}"
            ),
            title_align="center",
        )

        console.print(sub_menu_panel)


    def main(self) -> None:
        """Main application controller for the ENCRYPT/DECRYPT utility.

        Orchestrates input/output operations and manages converter
        subsystems. Provides menu-driven interface for various
        encoding/decoding operations.
        """
        exit_program = False

        while not exit_program:
            # Clear the screen before showing MAIN MENU
            Utils.clear_screen()

            # Show the main app menu
            self.display_main_menu()

            try:
                selection = Prompt.ask(f"\n[yellow]ENTER CHOICE").strip()

                normalized = selection.lower()

                # Check for quit
                if normalized in ["q"]:
                    console.print(get_exit_message(self.config))
                    exit_program = True
                    break

                # Validate main category
                if normalized not in self.config.main_categories.keys():
                    console.print(
                        f"[cyan][{Utils.get_current_time()}][yellow] Invalid "
                        f"choice. Please enter 1-4 or 'Q' to quit."
                    )
                    continue

                # Navigate to submenu
                self.run_submenu_loop(normalized)

                # After submenu returns, ask if want to continue in main menu
                if not self._ask_continue():
                    exit_program = True
                    break

            except KeyboardInterrupt:
                console.print(
                    f"\n\n[cyan][{Utils.get_current_time()}][yellow] Program "
                    "interrupted by user..."
                )
                logger.info("Program interrupted by user (KeyboardInterrupt)")
                console.print(get_exit_message(self.config))
                exit_program = True
                sys.exit(1)
            except EOFError:
                console.print(
                    f"\n[cyan][{Utils.get_current_time()}][red] EOF "
                    f"received. Exiting..."
                )
                logger.error("EOFError received. Program exited.")
                exit_program = True
                sys.exit(1)


if __name__ != "__main__":
    pass


if __name__ == "__main__":
    app = Main()
    try:
        app.main()
    except KeyboardInterrupt:
        console.print(
            f"\n[cyan][{Utils.get_current_time()}][yellow] Program "
            f"interrupted by user. Exiting..."
        )
        logger.info(
            "KeyboardInterrupt -- The program was interrupted by the user."
        )
        sys.exit(0)
    except Exception as e:
        logger.error(f"An unexpected error occured -> {e}")
        logger.error("Full traceback below:")
        # Include traceback
        logger.error(f"{traceback.format_exc}")

        console.print(
            f"[cyan][{Utils.get_current_time()}][red] Unexpected "
            f"error -> {e}"
        )
        console.print(
            f"[cyan][{Utils.get_current_time()}][yellow] Full traceback:"
        )
        # Shows exact line causing error
        console.print(traceback.format_exc())

        sys.exit(1)
