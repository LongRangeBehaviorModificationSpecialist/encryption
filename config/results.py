#!/usr/bin/env python3

from rich import box
from rich.console import Console
from rich.traceback import install
from rich.table import Table
from rich.text import Text

from config.display_helpers import escape_for_display


# Make the console object
console = Console()
install(show_locals=True)


class Results:


    @staticmethod
    def print_results_table(results_dict: dict) -> None:
        table = Table(
            box=box.ROUNDED,
            title="\nConversion Results",
            title_style="bold bright_blue",
            title_justify="center",
            show_lines=True,
            pad_edge=True,
            padding=(0, 5, 0, 1),
            border_style="dim",
            safe_box=True,
        )

        table.add_column(
            Text("Field", justify="left", style="bright_yellow"),
        )
        table.add_column(
            Text("Value", justify="left", style="bright_yellow"),
            ratio=2,
            no_wrap=False,
            overflow="fold",
        )

        table.add_row(
            f"[orange3]Input Type",
            f"[orange3]{results_dict['Input Type'].upper()}"
        )

        table.add_row(
            f"[bright_green]Input Value",
            f"[bright_green]{results_dict['Input Value']}"
        )

        table.add_row(
            f"[bright_green]Validation OK",
            f"[bright_green]{results_dict['Validation OK']}"
        )

        for key, value in results_dict.items():
            # Skip internal metadata fields
            if key in ["Input Type", "Input Value", "Validation OK"]:
                continue

            display_value = escape_for_display(str(value))
            table.add_row(key, display_value)

        console.print(table)
