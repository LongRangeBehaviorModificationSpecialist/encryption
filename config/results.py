#!/usr/bin/env python3

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.traceback import install
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from config.display_helpers import escape_for_display


# Make the console object
c = Console()
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

        c.print(table)

        # results_table = Table(
        #     box=box.HORIZONTALS,
        #     show_header=True,
        #     header_style="bold #2070b2",
        #     show_lines=True,
        # )

        # results_table.add_column(
        #     Text("Format", justify="left"),
        #         justify="left",
        #         no_wrap=False,
        # )

        # results_table.add_column(
        #     Text("Encoded String", justify="left"),
        #         justify="left",
        #         ratio=2,
        #         no_wrap=False,
        # )

        # results_table.add_row(
        #     f"[bold green3]Input Value",
        #     f"[bold green3]'{results_dict['user_input']}'"
        # )

        # new_dict = {
        #     key: value for key, value in results_dict.items()
        #     if key not in ["Input Type", "Input Value"]
        # }

        # for key, value in new_dict.items():
        #     results_table.add_row(
        #         f"[white]{key}",
        #         f"[khaki1]{value}",
        #         end_section=True,
        #     )

        # inner_panel = Panel(
        #     Align.center(Group(Align.left(results_table)), vertical="middle"),
        #     box=box.ROUNDED,
        #     expand=False,
        #     style="none",
        #     border_style="none",
        #     title=f"Input Data Type : {results_dict['type']}",
        #     safe_box=True,
        # )

        # c.print("\n")
        # c.print(inner_panel)
