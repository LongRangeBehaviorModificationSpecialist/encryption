# !/usr/bin/env python3

from functools import partial
from resources._key import KEY
from resources._aes import AES
from resources._pgp import PGP
from resources._xor import XOR
from resources.utils import Utils
from resources.vars import ICONS
from rich import box
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from rich.traceback import install
import signal
import sys
import traceback

from ui.config import (
    AppConfig,
    MenuItem,
    get_menu_lines_for_category,
    get_exit_message,
)

from versions import (
    __version__,
    __author__,
    __last_updated__,
    get_version_string
)


c = Console()
install(show_locals=True, console=c)


class Main:

    """Main application class."""

    def __init__(self):
        """Initialize the application and register signal handlers."""
        # Register SIGINT handler during initialization
        signal.signal(signal.SIGINT, self.handle_sigint)

        self.config = AppConfig()
        self._author = __author__
        self._version = __version__
        self._last_updated = __last_updated__
        self._version_banner = get_version_string(short=False)

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


    def handle_sigint(self, sig, frame) -> None:
        """Gracefully handles Ctrl+C signals across the entire application."""
        c.print(
            f"\n\n\n{ICONS['warning']}[red] Operation cancelled by "
            f"user. Exiting...\n"
        )
        sys.exit(0)


    def _bind_handlers(self) -> None:
        """Bind partial functions with args/kwargs after modules are
        initialized.
        """
        for key, item in self.config.menu_items.items():
            if item.handler_module and item.handler_method:
                # Get the module instance
                module = self._modules.get(item.handler_module)
                if not module:
                    c.print(f"[yellow]⚠ Warning: Module '{item.handler_module}' not found for menu item '{key}'[/]")
                    continue

                # Get the method
                handler = getattr(module, item.handler_method, None)
                if not handler:
                    c.print(f"[yellow]⚠ Warning: Method '{item.handler_method}' not found in {item.handler_module}[/]")
                    c.print(f"[dim]Available methods in {item.handler_module}: {[m for m in dir(module) if not m.startswith('_')]}[/]")
                    continue

                # Verify it's actually callable
                if not callable(handler):
                    c.print(f"[red]✗ Error: '{item.handler_method}' is not callable (it's a {type(handler).__name__})[/]")
                    continue

                try:
                    # Create the partial function
                    item.handler_callable = partial(handler, **item.handler_kwargs)
                except Exception as e:
                    c.print(f"[red]✗ Error binding handler for menu item '{key}': {e}[/]")
                    continue


    def _call_handler(self, menu_item: MenuItem) -> bool:
        """Execute the handler with pre-bound arguments.

        Returns:
            True if successful, False otherwise
        """
        # Prefer partial callable
        if menu_item.handler_callable:
            try:
                menu_item.handler_callable()
                return True
            except Exception as e:
                c.print(f"[red]{type(e).__name__} -> {e}")
                import traceback
                c.print(traceback.format_exc())
                return False

        # Fall back to string resolution
        if not menu_item.handler_module or not menu_item.handler_method:
            c.print("[red]Invalid handler configuration")
            return False

        # Get module instance
        module = self._modules.get(menu_item.handler_module)
        if not module:
            c.print(
                f"[red]Module not found: {menu_item.handler_module}"
            )
            return False

        # Get method reference
        handler = getattr(module, menu_item.handler_method, None)
        if not handler:
            c.print(
                f"[red]Method not found: {menu_item.handler_method}"
            )
            return False

        # Call with args/kwargs
        try:
            handler(*menu_item.handler_args, **menu_item.handler_kwargs)
            return True
        except Exception as e:
            c.print(f"[red]{type(e).__name__} -> {e}")
            import traceback
            c.print(traceback.format_exc())
            return False


    def display_main_menu(self) -> None:
        """Render the main menu using configuration."""
        menu_table = Table(
            title=(
                f"[{self.config.title_color}]\n{self.config.app_name}, "
                f"v.{self._version}"
            ),
            box=box.HEAVY_HEAD,
            show_header=False,
            header_style=self.config.header_style,
            show_lines=False,
            pad_edge=True,
            padding=(0, 5, 0, 1),
            caption=(
                f"Written by: {self._author}  |  Last Updated: "
                f"{self._last_updated}"
            ),
            caption_justify=self.config.credits_justify,
            caption_style="grey58",
            expand=False,
        )

        menu_table.add_row(
            f"[{self.config.warning_color}]What method do you want to use?",
        )

        # Iterate through categories in defined order
        for category in self.config.category_order:
            for line in get_menu_lines_for_category(self.config, category):
                menu_table.add_row(line)

        # Blank line at end
        menu_table.add_row()

        c.print(menu_table)


    def handle_selection(self, selection: str) -> bool:
        """Process user's menu selection.

        Args:
            selection: The user's input

        Returns:
            True if program should continue, False if it should exit.
        """
        normalized = selection.lower().strip()

        # Check for special actions
        if normalized in self.config.special_actions:
            if self.config.special_actions[normalized] == "EXIT":
                c.print(get_exit_message(self.config))
                return False

        # Check for valid menu item
        if normalized not in [k.lower() for k in self.config.menu_items.keys()]:
            c.print(
                f"[{self.config.warning_color}][red1] Unknown choice -> "
                f"{selection}. Please enter a valid option or 'Q' to exit."
            )
            # Continue loop
            return True

        # Find the matching case-insensitive key
        actual_key = next(
            (k for k in self.config.menu_items.keys()
            if k.lower() == normalized),
            None
        )

        if actual_key:
            try:
                item = self.config.menu_items[actual_key]

                if item.handler_module and item.handler_method:
                    if self._call_handler(item):
                        # Handler succeeded - ask to continue
                        if not self._ask_continue():
                            c.print(get_exit_message(self.config))
                            return False
                    else:
                        # Handler failed - ask continue anyway
                        c.print(f"[yellow3]Handler returned an error")
                        if not self._ask_continue():
                            c.print(get_exit_message(self.config))
                            return False
                else:
                    # No handler configured
                    c.print(
                        f"[yellow3]No handler configured for "
                        f"{item.handler_module}.{item.handler_method}"
                    )
                    # Don't ask to continue - invalid menu item

            except ValueError as e:
                c.print(f"[red]Validation Error -> {e}")
                c.print(f"[dim]Input may contain invalid characters.")
                # Ask to continue after validation error
                if not self._ask_continue():
                    c.print(get_exit_message(self.config))
                    return False

            except Exception as e:
                # Show full traceback for debugging
                c.print(
                    f"[red]Unexpected Error -> {type(e).__name__}: {e}"
                )
                c.print(f"[yellow]Full traceback below:")
                import traceback
                c.print(traceback.format_exc())

                # Ask to continue after unexpected error
                if not self._ask_continue():
                    c.print(get_exit_message(self.config))
                    return False
        else:
            # actual_key was None - shouldn't happen but safety check
            c.print(
                f"[red1]Internal error -> Cound not find menu item"
            )
            return True  # Continue back to the main menu

        # Continue loop (success or handled error)
        return True


    def _ask_continue(self) -> bool:
        """Ask user if they want to continue to main menu.

        Returns:
            True if user wants to continue, False to exit
        """
        try:
            c.print("\n\n[dim]" + "-" * 45 + "[/dim]")
            response = Prompt.ask(
                f"[{self.config.success_color}]"
                f"{self.config.continue_prompt_text}",
                choices=self.config.continue_prompt_choices,
                default=self.config.continue_prompt_default
            ).lower().strip()

            if response in ["y", "yes", ""]:
                return True
            else:
                return False
        except (KeyboardInterrupt, EOFError):
            # Exit on interrupt during prompt
            return False


    def main(self) -> None:
        """Main application controller for the ENCRYPT/DECRYPT utility.

        Orchestrates input/output operations and manages converter subsystems.
        Provides menu-driven interface for various encoding/decoding operations.
        """
        while True:
            Utils.clear_screen()
            self.display_main_menu()

            try:
                selection = Prompt.ask(
                    f"\n[{self.config.warning_color}]ENTER CHOICE"
                )

                if not self.handle_selection(selection):
                    break

            except KeyboardInterrupt:
                c.print(
                    f"\n\n[{self.config.warning_color}]-> Program interrupted "
                    "by user..."
                )
                c.print(get_exit_message(self.config))
                sys.exit(0)
            except EOFError:
                c.print("\n[red1]EOF received. Exiting...")
                sys.exit(0)


if __name__ != "__main__":
    pass


if __name__ == "__main__":
    try:
        app = Main()
        app.main()
    except KeyboardInterrupt:
        c.print("\n[yellow3]-> Program interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        c.print(f"[red1]Unexpected error -> {e}")
        c.print(f"[yellow]Full traceback:[/yellow]")
        c.print(traceback.format_exc())  # Shows exact line causing error
        sys.exit(1)
