# !/usr/bin/env python3

# Python cryptography library documentation is available at:


from functools import partial
import logging
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.traceback import install
import signal
import sys
import traceback
from typing import Union

from config.config import (
    GLOBAL_CONFIG,
    SubMenuItem,
    SubMenuCategory,
)

#TODO - Import the encoding/decoding files and then add them to the
#TODO   __init__ method.


from config.log_config import setup_logging, get_logger
from resources._aes import AES
from resources._key import KEY
from resources._pgp import PGP
from resources._xor import XOR
from resources.detect import FileAnalyzer
from utils import Utils, UIHandlerProtocol, RichUIHandler, get_time
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



class Main:
    """Main application class."""

    def __init__(self,  ui: UIHandlerProtocol | None = None) -> None:
        """Initialize the application and register signal handlers."""
        # Register SIGINT handler during initialization
        signal.signal(signal.SIGINT, self.handle_sigint)
        self.ui = ui or RichUIHandler(get_time=get_time)
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
        self.detect = FileAnalyzer()

        # Map handler names to actual method references
        self._modules = {
            "key": self.key,
            "aes": self.aes,
            "pgp": self.pgp,
            "xor": self.xor,
            "detect": self.detect,
        }

        self._bind_handlers()
        logger.info("All modules initialized successfully")


    def handle_sigint(self, sig, frame) -> None:
        """Gracefully handles Ctrl+C signals across the entire application."""
        console.print("\n")
        self.ui.warning("Operation cancelled by user. Exiting...\n")
        sys.exit(0)


    def _bind_handlers(self) -> None:
        """Bind partial functions for all menu items across all tiers."""
        # Iterate through each main category
        for category_key, category in self.config.main_categories.items():

            # Iterate through each submenu item in that category
            for sub_key, sub_cat in category.submenu_categories.items():

                # ── Case 1: SubMenuCategory has a direct handler ──
                if sub_cat.handler_module and sub_cat.handler_method:
                    # Get the module instance
                    module = self._modules.get(sub_cat.handler_module)

                    if module:
                        handler = getattr(module, sub_cat.handler_method, None)

                        if handler and callable(handler):

                            try:
                                sub_cat.handler_callable = partial(
                                    handler,
                                    **sub_cat.handler_kwargs
                                )
                                logger.info(
                                f"Bound handler → "
                                f"[{category_key}][{sub_key}] "
                                f"{sub_cat.handler_module}."
                                f"{sub_cat.handler_method}"
                            )
                            except Exception as err:
                                self.ui.error(
                                    f"Failed to bind "
                                    f"[{category_key}][{sub_key}] → {err}"
                                )
                        else:
                            self.ui.warning(
                                f"Method '{sub_cat.handler_method}' "
                                f"not found in '{sub_cat.handler_module}"
                            )
                            available = [
                                m for m in dir(module)
                                if callable(getattr(module, m))
                                and not m.startswith("_")
                            ]
                            self.ui.info(
                                f"Available → {', '.join(available)}"
                            )
                    continue

                # ── Case 2: SubMenuCategory has submenu_items (third tier) ──
                for item_key, item in sub_cat.submenu_items.items():
                    if item.handler_module and item.handler_method:
                            module = self._modules.get(item.handler_module)
                            if module:
                                handler = getattr(
                                    module,
                                    item.handler_method,
                                    None,
                                )
                                if handler and callable(handler):
                                    try:
                                        item.handler_callable = partial(
                                            handler,
                                            **item.handler_kwargs
                                        )
                                        logger.info(
                                            f"Bound handler → "
                                            f"[{category_key}][{sub_key}]"
                                            f"[{item_key}] "
                                            f"{item.handler_module}."
                                            f"{item.handler_method}"
                                        )
                                    except Exception as err:
                                        self.ui.error(
                                            f"Failed to bind "
                                            f"[{category_key}][{sub_key}]"
                                            f"[{item_key}] → {err}"
                                        )
                                else:
                                    self.ui.warning(
                                        f"Method '{item.handler_method}' "
                                        f"not found in '{item.handler_module}'"
                                    )
                                    available = [
                                        m for m in dir(module)
                                        if callable(getattr(module, m))
                                        and not m.startswith("_")
                                    ]
                                    self.ui.info(
                                        f"Available → {', '.join(available)}"
                                    )


    def _call_handler(
            self,
            menu_item: Union[SubMenuItem, SubMenuCategory]
    ) -> bool:
        """Execute the handler for a menu item (leaf or mid-tier)

        Args:
            menu_item: Either a SubMenuItem or a SubMenuCategory with
                a direct handler attached.

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
                    except Exception as err:
                        self.ui.error(
                            f"Error executing handler: "
                            f"{type(err).__name__} → {err}"
                        )
                        import traceback
                        self.ui.info("Traceback:")
                        self.ui.warning(traceback.format_exc())
                        return False
                else:
                    self.ui.error(
                        f"Method '{menu_item.handler_method}' not found or "
                        f"not callable in {menu_item.handler_module}"
                    )
                    return False
            else:
                self.ui.error(
                    f"Module '{menu_item.handler_module}' not found"
                )
                return False

        # No handler configured
        self.ui.warning(
            f"No handler configured for this item → "
            f"{menu_item.handler_module} / {menu_item.handler_method}"
        )
        return False


    def run_submenu_loop(self, category_key: str) -> None:
        """Run the submenu loop for a selected top-level category.

        Handles both direct-handler SubMenuCategories (2-tier) and
        SubMenuCategories with nested SubMenuItems (3-tier).

        Args:
            category_key: Key from main_categories (e.g., "1", "2")
        """
        exit_program = False

        while not exit_program:
            category = self.config.main_categories.get(category_key)
            if not category:
                logger.error(
                    f"Invalid category requested: [ '{category_key}' ]"
                )
                self.ui.error("An invalid category was entered")
                return

            # Clear the screen before showing submenu
            Utils.clear_screen(self)

            # Show the middle-tier (level 1) sub-menu
            self.display_sub_menu(category_key)

            try:
                selection = self.ui.prompt(
                    "\n\nENTER CHOICE",
                    menu_prompt=True,
                ).strip()
                normalized = selection.lower()

                logger.debug(f"User selected → {normalized}")

                # Check for back command
                if normalized in ["r"]:
                    logger.debug("User returned to main menu")
                    # Return to main menu
                    return

                # Check for quit
                if normalized in ["q"]:
                    logger.info("User chose to exit from submenu")
                    exit_program = True
                    Utils.exit_application(self)
                    return

                # Look up the SubMenuCategory by key
                sub_cat = category.submenu_categories.get(normalized)
                if not sub_cat:
                    self.ui.error(
                        "Invalid choice. Try again or press \"R\" to go back."
                    )
                    continue

                # ── Branch A: Direct handler (encode/decode) ──
                if sub_cat.handler_module and sub_cat.handler_method:
                    logger.info(
                        f"Executing direct handler: "
                        f"[{category_key}][{normalized}] → {sub_cat.label}"
                    )
                    self._call_handler(sub_cat)

                    if not self._ask_continue():
                        exit_program = True
                        return
                    continue  # Back to the submenu loop

                # ── Branch B: Has submenu_items (encryption) ──
                if not sub_cat.submenu_items:
                    self.ui.warning(
                        "This category has no available actions."
                    )
                    continue

                # Enter the third-tier (sub-submenu) loop
                self.run_sub_submenu_loop(category_key, normalized)

                if not self._ask_continue():
                    exit_program = True
                    return


                # # Validate submenu item exists
                # if normalized not in category.submenu_items.keys():
                #     self.ui.error(
                #         "Invalid choice. Try again or press \"R\" to go back."
                #     )
                #     continue

                # # Execute the selected operation
                # item = category.submenu_items[normalized]
                # logger.info(
                #     f"Executing operation: [{category_key}][{normalized}] → "
                #     f"{item.label}"
                # )

                # self._call_handler(item)

                # # Ask if user wants to continue
                # if not self._ask_continue():
                #     exit_program = True
                #     return

            except KeyboardInterrupt:
                msg = "Application was interrupted by user (Ctrl+C)"
                self.ui.warning(msg)
                logger.warning(msg)
                return
            except EOFError:
                return


    def run_sub_submenu_loop(
            self,
            category_key: str,
            sub_cat_key: str
    ) -> None:
        """Run the third-tier (sub-submenu) loop for categories that
        have nested SubMenuItems (e.g., encryption methods).

        Args:
            category_key: Top-level menu key
            sub_cat_key: Middle-tier SubMenuCategory key
        """
        exit_loop = False

        while not exit_loop:
            category = self.config.main_categories.get(category_key)
            if not category:
                return

            sub_cat = category.submenu_categories.get(sub_cat_key)
            if not sub_cat:
                return

            Utils.clear_screen(self)

            # Display third-tier menu
            self.display_sub_sub_menu(category_key, sub_cat_key)

            try:
                selection = self.ui.prompt(
                    "\n\nENTER CHOICE",
                    menu_prompt=True,
                ).strip()
                normalized = selection.lower()

                if normalized in ["r"]:
                    logger.debug("User returned to submenu")
                    return

                if normalized in ["q"]:
                    logger.info("User chose to exit from sub-submenu")
                    Utils.exit_application(self)
                    return

                if normalized not in sub_cat.submenu_items.keys():
                    self.ui.error(
                        "Invalid choice. Try again or press \"R\" to go back."
                    )
                    continue

                item = sub_cat.submenu_items[normalized]
                logger.info(
                    f"Executing operation: "
                    f"[{category_key}][{sub_cat_key}][{normalized}] → "
                    f"{item.label}"
                )

                self._call_handler(item)

                if not self._ask_continue():
                    exit_loop = True
                    return

            except KeyboardInterrupt:
                msg = "Application was interrupted by user (Ctrl+C)"
                self.ui.warning(msg)
                logger.warning(msg)
                return
            except EOFError:
                return


    def _ask_continue(self) -> bool:
        """Ask user if they want to continue to main menu.

        Returns:
            True if user wants to continue, False to exit
        """
        try:

            response = self.ui.confirm(
                "Task complete! Return to previous menu?"
            )

            if not response:
                logger.info("The application was closed by the user")
                Utils.exit_application(self)
                return False

            logger.info("User returned to the previous menu")
            return True

        except (KeyboardInterrupt, EOFError) as e:
            logger.error(f"An error occured during this operation → {e}")
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
            caption_style="grey66",
            expand=False,
            safe_box=True,
        )

        menu_table.add_row(
            f"\n[light_goldenrod1]What method do you want to use?\n"
        )

        # Display main categories (1-4)
        for key in sorted(self.config.main_categories.keys()):
            category = self.config.main_categories[key]
            menu_table.add_row(
                f"[white][{key}] {category.label} [grey74]"
                f"[{category.description}]"
            )

        # Add quit option
        menu_table.add_row()  # Blank row
        menu_table.add_row("[Q] Quit the application")

        # Blank line at end
        menu_table.add_row()

        # To put the main menu table inside a Panel for better formatting
        menu_panel = Panel.fit(
            renderable=menu_table,
            title=(
                f"[bright_blue][i]\n{self.config.app_name} (v.{self._version})"
            ),
            title_align="center",
            subtitle=(
                f"[grey74][dim][i]Written by: {self._author} | Last Updated: "
                f"{self._last_updated}"
            ),
            subtitle_align="center",
        )

        console.print(menu_panel)


    def display_sub_menu(self, category_key: str) -> None:
        """Render the middle-tier submenu for a top-level category.

        Args:
            category_key: Key from main_categories
            """
        logger.info(f"User viewing submenu for category → {category_key}")
        category = self.config.main_categories.get(category_key)
        if not category:
            self.ui.warning("An invalid category was selected")
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

        sub_menu_table.add_row(f"\n[light_goldenrod1]Options:\n")

        # ── Changed: iterate submenu_categories, not submenu_items ──
        for sub_key in sorted(category.submenu_categories.keys()):
            sub_cat = category.submenu_categories[sub_key]
            sub_menu_table.add_row(
                f"[white][{sub_key}] {sub_cat.label} [grey74]"
                f"[{sub_cat.description}]"
            )

        sub_menu_table.add_row()

        # Add back option
        sub_menu_table.add_row(f"[R] Return to the main menu")

        # Add exit option
        sub_menu_table.add_row(f"[Q] Quit the application")

        # Blank line at end
        sub_menu_table.add_row()

        # To put the main menu table inside a Panel for better formatting
        sub_menu_panel = Panel.fit(
            renderable=sub_menu_table,
            title=(
                f"[bright_blue][i][{self.config.title_color}]\n{category.label}"
            ),
            title_align="center",
        )

        console.print(sub_menu_panel)


    def display_sub_sub_menu(self, category_key: str, sub_cat_key: str) -> None:
        """Render the third-tier (sub-submenu) for a specific SubMenuCategory.

        Args:
            category_key: Top-level menu key
            sub_cat_key: Middle-tier SubMenuCategory key
        """
        logger.info(
            f"User viewing sub-submenu for "
            f"[{category_key}][{sub_cat_key}]"
        )
        category = self.config.main_categories.get(category_key)
        if not category:
            return

        sub_cat = category.submenu_categories.get(sub_cat_key)
        if not sub_cat:
            return

        sub_sub_table = Table(
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

        sub_sub_table.add_row(f"\n[light_goldenrod1]Actions:\n")

        for item_key in sorted(sub_cat.submenu_items.keys()):
            item = sub_cat.submenu_items[item_key]
            sub_sub_table.add_row(
                f"[white][{item_key}] {item.label} [grey74]"
                f"[{item.description}]"
            )

        sub_sub_table.add_row()
        sub_sub_table.add_row("[R] Return to the previous menu")
        sub_sub_table.add_row("[Q] Quit the application")
        sub_sub_table.add_row()

        sub_sub_panel = Panel.fit(
            renderable=sub_sub_table,
            title=(
                f"[bright_blue][i][{self.config.title_color}]\n{sub_cat.label}"
            ),
            title_align="center",
        )

        console.print(sub_sub_panel)



    def main(self, ui: UIHandlerProtocol | None = None) -> None:
        """Main application controller for the ENCRYPT/DECRYPT utility.

        Orchestrates input/output operations and manages converter
        subsystems. Provides menu-driven interface for various
        encoding/decoding operations.
        """
        exit_program = False
        while not exit_program:
            # Clear the screen before showing MAIN MENU
            Utils.clear_screen(self)

            # Show the main app menu
            self.display_main_menu()

            try:
                selection = self.ui.prompt(
                    "\n\nENTER CHOICE",
                    menu_prompt=True,
                ).strip()

                normalized = selection.lower()

                # Check for quit
                if normalized in ["q"]:
                    exit_program = True
                    Utils.exit_application(self)
                    break

                # Validate main category
                if normalized not in self.config.main_categories.keys():
                    self.ui.warning(
                        "Invalid choice. Please enter 1-4 or 'Q' to quit."
                    )
                    continue

                # Navigate to submenu
                self.run_submenu_loop(normalized)

                # After submenu returns, ask if want to continue in main menu
                if not self._ask_continue():
                    exit_program = True
                    break

            except KeyboardInterrupt:
                self.ui.warning(
                    "Program interrupted by user (Ctrl+C)..."
                )
                logger.info("Program interrupted by user (KeyboardInterrupt)")
                exit_program = True
                Utils.exit_application(self)
                sys.exit(1)
            except EOFError:
                self.ui.error("EOFError received. Exiting...")
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
        app.ui.warning("Program interrupted by user. Exiting...")
        logger.info(
            "KeyboardInterrupt → The program was interrupted by the user."
        )
        sys.exit(0)
    except Exception as err:
        logger.error(f"An unexpected error occured → {err}")
        logger.error("Full traceback below:")
        # Include traceback
        logger.error(traceback.format_exc())

        app.ui.error(f"Unexpected error → {err}")
        app.ui.warning("Full traceback:")
        # Shows exact line causing error
        app.ui.info(traceback.format_exc())

        sys.exit(1)
