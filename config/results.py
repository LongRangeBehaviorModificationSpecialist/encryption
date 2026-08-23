#!/usr/bin/env python3

from rich import box
from rich.console import Console
from rich.traceback import install
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from config.display_helpers import escape_for_display
from utils import UIHandlerProtocol, RichUIHandler, get_time


# Make the console object
console = Console()
install(show_locals=True)


class Results:
    """Custom results printer that handles multiple hash outputs."""

    def __init__(self, ui: UIHandlerProtocol | None = None) -> None:
        self.ui = ui or RichUIHandler(get_time=get_time)

    def _confirm_results(self, saved_path: str) -> None:
        pass

    @staticmethod
    def print_encode_decode_results_table(results_dict: dict) -> None:
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

    def print_hasher_results(self, results_dict: dict) -> None:
        """Print results in formatted table, handling multiple algorithms."""

        if results_dict.get("Validation OK") in ["False", "Partial"]:
            self.ui.error(f"Error: {results_dict.get('error')}")
            return

        input_type = results_dict.get("Input Type", "Unknown")

        if input_type == "Directory":
            Results._print_hash_directory_results(self, data=results_dict)
        else:
            Results._print_hash_simple_results(self, data=results_dict)

    def _print_hash_simple_results(self, data: dict):
        """Print string/file hash results (single or multiple algorithms)."""
        table = Table(
            title="\nHash Results",
            title_style="bold bright_blue",
            box=box.ROUNDED,
            border_style="dim",
            expand=True,
            show_lines=True,
            pad_edge=True,
            padding=(0, 5, 0, 1),
        )

        table.add_column(
            Text("Field", justify="left", style="bright_white"),
        )
        table.add_column(
            Text("Value", justify="left", style="bright_white"),
            ratio=2,
            no_wrap=False,
            overflow="fold",
        )

        # Metadata fields
        metadata = [
            "Input Type",
            "Input Value",
            "File Path",
            "File Size",
            "Directory Path",
            "Algorithms Used",
            "Algorithm",
        ]
        for key in metadata:
            if key in data:
                table.add_row(key, str(data[key]))

        # Hash fields (all keys ending in "Hash" or containing "Hash")
        for key, value in data.items():
            if "hash" in key.lower() and key not in metadata:
                label = key.replace(" Hash", "").title()
                table.add_row(label, f"[bright_blue]{value}[/bright_blue]")

        console.print(table)

    def _print_hash_directory_results(self, data: dict):
        """Print directory hash results with summary and per-file tables."""
        from rich.box import ROUNDED

        # Summary table
        summary = Table(
            title="\nDirectory Hash Summary",
            title_style="bold bright_white",
            box=box.ROUNDED,
            border_style="bright_blue",
            expand=True,
            padding=(0, 2),
            show_lines=False,
        )

        summary.add_column(
            Text(
                "Metric",
                style="bright_white",
                justify="left",
            ),
            style="bright_white",
            width=15,
        )
        summary.add_column(
            Text(
                "Value",
                style="bright_white",
                justify="left",
            ),
            style="green",
            width=40,
        )

        summary.add_row("Algorithm(s)", data.get("Algorithms Used", "N/A"))
        summary.add_row("Total Files", data.get("Total Files", "N/A"))
        summary.add_row("Successful", data.get("Successful", "N/A"))
        summary.add_row("Failed", data.get("Failed", "N/A"))
        summary.add_row("Total Size", data.get("Total Size", "N/A"))

        console.print(summary)

        # Per-file hash table
        files = data.get("Files", [])
        if files:
            # Determine which algorithms were used
            first_file = files[0]
            hash_keys = [k for k in first_file.get("Hashes", {}).keys()]

            file_table = Table(
                title="Per-File Hashes",
                title_style="bold bright_white",
                title_justify="center",
                box=box.ROUNDED,
                border_style="dim",
                expand=True,
                show_lines=True,
                pad_edge=True,
                padding=(0, 5, 0, 1),
            )

            file_table.add_column(
                Text(
                    "File",
                    justify="left",
                    style="bright_white",
                ),
                overflow="fold",
                style="bright_white",
                vertical="middle",
            ),
            file_table.add_column(
                Text(
                    "Size",
                    justify="left",
                    style="bright_white",
                ),
                justify="left",
                style="bright_white",
                vertical="middle",
            )
            for algo in hash_keys:
                display_name = f"{algo.upper()}"
                file_table.add_column(
                    Text(
                        display_name,
                        justify="left",
                        style="bright_white",
                    ),
                    justify="left",
                    overflow="fold",
                    style="bright_green",
                    vertical="middle",
                )

            for file_entry in files:
                row = [
                    file_entry.get("File", ""),
                    file_entry.get("Size", "N/A")
                ]
                hashes = file_entry.get("Hashes", {})
                for algo in hash_keys:
                    row.append(hashes.get(algo, "N/A"))
                file_table.add_row(*row)

            # console.print(Panel(file_table, border_style="blue"))
            console.print(file_table)
