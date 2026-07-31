# !/usr/bin/env python3
# DLU : 27-Jul-2026


from rich.console import Console


# Make the console object
c = Console()


class Decryptor:


    def __init__(self, app_instance) -> None:
        """Store a reference to the main app loop controller."""
        self.app = app_instance


    # def return_to_main_menu(self) -> None:
    #     """Returns control cleanly back to the main menu processor."""
    #     self.app.main(self)