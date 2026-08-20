#!/usr/bin/env python3

from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import install
from config.log_config import get_logger
from utils import Utils, UIHandlerProtocol, RichUIHandler, get_time


logger = get_logger("type_checker")
install()


class FileTypeValidator:
    """Validates file types by comparing magic bytes against extensions."""

    # Built-in file signatures (magic bytes)
    FILE_SIGNATURES: Dict[str, List[bytes]] = {
        '.jpg':      [b'\xFF\xD8\xFF'],
        '.jpeg':     [b'\xFF\xD8\xFF'],
        '.png':      [b'\x89PNG\r\n\x1a\n'],
        '.gif':      [b'GIF87a'],
        '.pdf':      [b'%PDF-'],
        '.zip':      [b'PK\x03\x04'],
        '.mp3':      [b'\xFF\xFB'],
        '.mp4':      [b'\x00\x00\x00\x1cftypmp4'],
        '.mov':      [b'\x00\x00\x00\x14moov'],
        '.avi':      [b'RIFF'],
        '.wav':      [b'RIFF'],
        '.exe':      [b'MZ'],
        '.elf':      [b'\x7fELF'],
        '.bmp':      [b'BM'],
        '.tiff':     [b'II\x2a\x00'],
        '.tif':      [b'II\x2a\x00'],
        '.rar':      [b'Rar!\x1a\x07\x00'],
        '.7z':       [b'7z\xbc\xaf\'\x1c'],
        '.gzip':     [b'\x1f\x8b'],
        '.tar.gz':   [b'\x1f\x8b'],
        '.docx':     [b'PK\x03\x04'],
        '.xlsx':     [b'PK\x03\x04'],
        '.pptx':     [b'PK\x03\x04'],
        '.html':     [b'<!DOCTYPE html'],
        '.htm':      [b'<!DOCTYPE html'],
        '.xml':      [b'<?xml'],
        '.json':     [b'{'],
    }

    def __init__(
            self,
            config_path: Optional[str] = None,
            max_workers: Optional[int] = None,
            ui: UIHandlerProtocol | None = None
    ):
        """
        Initialise the validator.

        Args:
            config_path: Path to a JSON config file with custom signatures.
                If the file doesn't exist yet, it is created with a template
                the user can edit.
            max_workers: Thread pool size for parallel scanning.
                Defaults to min(32, os.cpu_count() * 4).
        """
        self.ui = ui or RichUIHandler(get_time=get_time)
        self.max_workers = max_workers or min(32, (os.cpu_count() or 4) * 4)
        self.custom_signatures: Dict[str, List[bytes]] = {}
        self.config_path = config_path

        # Default to signature_config.json in the same directory as this module
        if not config_path:
            # Get the directory where the config file lives
            module_dir = os.path.dirname(os.path.abspath(__file__))
            self.ui.info(f"'module_dir' is {module_dir}")
            config_path = os.path.join(
                module_dir,
                "\\resources\\file_checker\\signature_config.json"
            )
            self.ui.success(f"'config_path' → {config_path}")
            self.load_config(config_path)

        if self.config_path:
            self.load_config(self.config_path)


    # --- Config file handling
    def load_config(self, config_path: Path | str) -> None:
        """
        Load custom file signatures from a JSON config file.

        The JSON structure is::

            {
                "signatures": {
                    ".ext1": "FF D8",
                    ".ext2": ["47 49 46 38 37 61", "47 49 46 38 39 61"],
                    ".ext3": "\\x50\\x4B\\x03\\x04"
                }
            }

        Each value can be either:
            - A single hex string
            - A list of hex strings (multiple valid magic byte sequences)

        Supported hex string formats:
            - "\\xFF\\xD8"   (Python-style escapes)
            - "FF D8"         (space-separated hex pairs)
            - "FFD8"          (contiguous hex pairs)

        If the file does not exist, a template is created.
        """
        if not os.path.exists(config_path):
            self._create_config_template(config_path)
            self.ui.info(f"Config template created at: {config_path}")
            self.ui.info(f"Edit it to add custom signatures, then re-run.")
            return

        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        sig_section = data.get("signatures", {})

        for ext, hex_value in sig_section.items():
            if ext.startswith("_"):
                continue

            # Normalize to a list of hex strings
            if isinstance(hex_value, str):
                hex_list = [hex_value]
            elif isinstance(hex_value, list):
                hex_list = hex_value
            else:
                self.ui.warning(
                    f"Warning: skipping '{ext}' → value must be a string or "
                    "list of strings"
                )
                continue

            # Parse each hex string into bytes
            parsed_bytes: List[bytes] = []
            for hs in hex_list:
                if not isinstance(hs, str):
                    self.ui.warning(
                        f"Warning: skipping non-string entry for "
                        f"'{ext}' → {hs!r}"
                    )
                    continue
                try:
                    parsed_bytes.append(self._parse_hex(hs))
                except ValueError as err:
                    self.ui.warning(
                        f"Warning: skipping invalid signature for "
                        f"'{ext}' → {err}"
                    )

            if parsed_bytes:
                self.custom_signatures[ext] = parsed_bytes

        # Merge: custom signatures override built-ins with the same extension
        self.FILE_SIGNATURES = {
            **self.FILE_SIGNATURES,
            **self.custom_signatures
        }

        count = sum(len(v) for v in self.custom_signatures.values())
        ext_count = len(self.custom_signatures)

        self.ui.info(
            f"Loaded {count} signature(s) across {ext_count} extension(s) "
            f"from the config file"
        )


    @staticmethod
    def _create_config_template(path: Path | str) -> None:
        """Write a commented JSON template with instructions."""
        template = {
            "_instructions": (
                "Add custom file signatures here. Each key is a file extension "
                "(including the dot) and the value is either a single hex "
                "string or a LIST of hex strings (for formats with multiple "
                "valid headers). Supported hex formats: 'FFD8', 'FF D8', "
                "'\\xff\\xd8'. Entries here override any built-in signatures "
                "with the same extension."
            ),
            "signatures": {
                ".example1": "FF D8 FF E0",
                ".example2": "\\x50\\x4B\\x03\\x04",
                ".custom_gif": [
                    "47 49 46 38 37 61",
                    "47 49 46 38 39 61"
                ],
                ".custom_tiff": [
                    "49 49 2A 00",
                    "4D 4D 2A 00"
                ]
            }
        }

        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(template, f, indent=4)


    @staticmethod
    def _parse_hex(hex_str: str) -> bytes:
        """
        Parse a hex string into raw bytes.

        Supports three input styles:
            - Python-style escapes:  "\\xff\\xd8"
            - Space-separated hex:   "FF D8"
            - Contiguous hex:        "FFD8"
        """
        hex_str = hex_str.strip()

        # Python-style escape sequences
        if "\\x" in hex_str:
            # eval is avoided; manually parse \xNN sequences
            result = bytearray()
            i = 0
            while i < len(hex_str):
                if hex_str[i] == '\\' and i + 3 < len(hex_str) and hex_str[i + 1] == "x":
                    byte_val = int(hex_str[i + 2:i + 4], 16)
                    result.append(byte_val)
                    i += 4
                elif hex_str[i] == '\\' and i + 3 < len(hex_str) and hex_str[i + 1] in ('n', 'r', 't'):
                    mapping = {'n': b'\n', 'r': b'\r', 't': b'\t'}
                    result.extend(mapping[hex_str[i + 1]])
                    i += 2
                else:
                    result.extend(hex_str[i].encode())
                    i += 1
            return bytes(result)

        # Space-separated or contiguous hex
        cleaned = hex_str.replace(' ', '').replace('\t', '')
        if len(cleaned) % 2 != 0:
            raise ValueError(f"Odd number of hex digits: '{hex_str}'")
        try:
            return bytes.fromhex(cleaned)
        except ValueError:
            raise ValueError(f"Invalid hex string: '{hex_str}'")


    # --- Signature checking
    def get_file_signature(
            self,
            filepath: Path | str,
            num_bytes: int = 8
    ) -> bytes:
        """Read the first N bytes of a file."""
        with open(filepath, 'rb') as f:
            return f.read(num_bytes)


    def get_extension(self, filepath: Path | str) -> str:
        """Get file extension including the dot, lowercase."""
        _, ext = os.path.splitext(filepath)
        return ext.lower()


    def find_matching_signature(self, header_bytes: bytes) -> List[str]:
        """
        Find which file signature(s) match the provided bytes.

        Each extension may have multiple valid magic byte sequences,
        so we check every entry in the list.
        """
        matches = []

        for ext, sig_list in self.FILE_SIGNATURES.items():
            if not sig_list:
                continue
            for sig in sig_list:
                if not sig:
                    continue
                if header_bytes.startswith(sig):
                    matches.append(ext)
                    break

        return matches


    def validate_file_type(
            self,
            filepath: Path | str,
            strict: bool = False
    ) -> Tuple[bool, str, str]:
        """Validate if file extension matches its actual type based on signature."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        claimed_ext = self.get_extension(filepath)

        try:
            header_bytes = self.get_file_signature(filepath)
        except IOError as e:
            raise IOError(f"Cannot read file: {filepath}, {str(e)}")

        if not header_bytes:
            return (False, "", claimed_ext)

        matching_sigs = self.find_matching_signature(header_bytes)

        if not matching_sigs:
            return (False, "unknown", claimed_ext)

        if claimed_ext in matching_sigs:
            return (True, matching_sigs[0], claimed_ext)

        if strict:
            return (False, matching_sigs[0], claimed_ext)
        else:
            compatible_groups = {
                ('.jpg', '.jpeg'),
                ('.docx', '.xlsx', '.pptx'),
                ('.tiff', '.tif'),
                ('.html', '.htm'),
            }
            for group in compatible_groups:
                if claimed_ext in group:
                    for sig_ext in matching_sigs:
                        if sig_ext in group:
                            return (True, matching_sigs[0], claimed_ext)
            return (False, matching_sigs[0], claimed_ext)


class FileCheckRunner:
    """Interactive runner with parallel scanning and config support."""

    def __init__(
            self,
            validator: Optional[FileTypeValidator] = None,
            ui: UIHandlerProtocol | None = None
    ) -> None:
        self.ui = ui or RichUIHandler(get_time=get_time)
        self.validator = validator or FileTypeValidator()

    # --- Interactive prompts
    @staticmethod
    def _prompt_yes_no(prompt: str, default: Optional[bool] = None) -> bool:
        hint = "[Y/n]" if default is True else "[y/N]" if default is False else "[y/n]"
        while True:
            raw = input(f"{prompt} {hint}: ").strip().lower()
            if not raw and default is not None:
                return default
            if raw in ("y", "yes"):
                return True
            if raw in ("n", "no"):
                return False
            print("Please enter 'y' or 'n'.")


    def scan_single_file(self, file_path: Path | str) -> dict:
        """Scan one file and return a result dictionary."""
        target_path = Path(file_path).resolve()

        result = {
            "path": target_path,
            "valid": False,
            "detected_ext": "",
            "claimed_ext": "",
            "error": None,
        }
        try:
            is_valid, detected_ext, claimed_ext = (
                self.validator.validate_file_type(
                    target_path,
                    strict=False,
                )
            )
            result["valid"] = is_valid
            result["detected_ext"] = detected_ext
            result["claimed_ext"] = claimed_ext
        except Exception as err:
            result["error"] = str(err)

        return result


    def scan_files_parallel(
            self,
            file_paths: List[Path | str],
            progress: bool = True,
    ) -> List[dict]:
        """
        Scan multiple files concurrently using a thread pool.

        Threads are chosen over processes because the workload is
        I/O-bound (reading a few header bytes per file), not CPU-bound.
        ThreadPoolExecutor avoids pickling overhead and IPC costs.

        Args:
            file_paths: List of file paths to scan.
            progress:  If True, print progress dots during scanning.

        Returns:
            List of result dicts in the same order as input paths.
        """
        results: List[Optional[dict]] = [None] * len(file_paths)

        with ThreadPoolExecutor(max_workers=self.validator.max_workers) as executor:
            # Submit all tasks, mapping future -> index for ordered results
            future_to_idx = {
                executor.submit(self.scan_single_file, fp): idx
                for idx, fp in enumerate(file_paths)
            }

            completed = 0
            total = len(file_paths)
            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                try:
                    results[idx] = future.result()
                except Exception as err:
                    results[idx] = {
                        "path": file_paths[idx],
                        "valid": False,
                        "detected_ext": "",
                        "claimed_ext": "",
                        "error": str(err),
                    }

                if progress:
                    completed += 1
                    # Progress bar
                    bar_width = 30
                    filled = (
                        int(bar_width * completed / total)
                        if total else bar_width
                    )
                    bar = '#' * filled + '-' * (bar_width - filled)
                    pct = (completed / total * 100) if total else 100
                    self.ui.info(
                        f"Scanning [{bar}] {completed}/{total} "
                        f"({pct:.0f}%)",
                        end='',
                        flush=True,
                    )

        if progress:
            print()  # newline after progress bar

        return [r for r in results if r is not None]


    def scan_directory(
            self,
            dir_path: Path | str,
            recursive: bool = False,
            progress: bool = True,
    ) -> List[dict]:
        """
        Collect all file paths in a directory and scan them in parallel.

        Collecting paths first (then batching the reads) is more efficient
        than spawning threads while still walking the tree, because
        os.walk itself is sequential and fast relative to file I/O.
        """
        file_paths: List[str] = []

        target_dir = Path(dir_path).resolve()

        if recursive:
            walker = os.walk(target_dir)
        else:
            try:
                entries = os.listdir(target_dir)
            except PermissionError as err:
                self.ui.error(f"Cannot access directory {target_dir} → {err}")
                return []
            walker = [(target_dir, [], entries)]

        for root, _dirs, files in walker:
            for file in files:
                file_path = os.path.join(root, file)
                if os.path.isfile(file_path):
                    file_paths.append(file_path)

        if not file_paths:
            self.ui.warning(f"No files found to scan in {target_dir}")
            return []

        self.ui.info(
            f"Found {len(file_paths)} file(s). Starting parallel scan..."
        )
        return self.scan_files_parallel(file_paths, progress=progress)


    def run_file_checker(self, type: str) -> List[dict]:
        """Main entry point: prompt user, scan, report."""
        # mode, path, recursive = self.prompt_user()

        if type == "file":
            target_file = Utils.get_file_path(self)
            results = [self.scan_single_file(file_path=target_file)]
        else:
            target_dir = Utils.get_directory_path(self)
            recursive = Utils.select_recursive_option(self)
            results = self.scan_directory(
                dir_path=target_dir,
                recursive=recursive,
            )

        self.print_report(results)
        return results


    # --- Reporting
    def print_report(self, results: List[dict]) -> None:
        """Print a readable summary of all checked files."""
        total = len(results)
        matched = sum(1 for r in results if r["valid"])
        mismatched = sum(
            1 for r in results if not r["valid"] and r["error"] is None
        )
        errors = sum(1 for r in results if r["error"] is not None)

        self.ui.success("RESULTS")

        for r in results:
            if r["error"]:
                status = f"ERROR   ({r['error']})"
            elif r["valid"]:
                status = "MATCH   ✓"
            else:
                status = (
                    f"MISMATCH  ✗  "
                    f"(detected: {r['detected_ext']}, "
                    f"extension: {r['claimed_ext'] or 'none'})"
                )

            rel_path = r["path"]
            print(f"  {status}")
            print(f"    {rel_path}")
            print()

        self.ui.info(f"Total files checked : [bright_blue]{total}")
        self.ui.info(f"Matches             : [bright_green]{matched}")
        self.ui.info(f"Mismatches          : [bright_yellow]{mismatched}")
        self.ui.info(f"Errors              : [bright_red]{errors}")
        if total > 0:
            pct = (matched / total) * 100
            self.ui.info(f"Match rate         : [bright_blue]{pct:.1f}%")

        export = self.ui.confirm("Do you want to export the results to a CSV?")

        if export:
            output_path = self.ui.prompt(
                "Enter the path where the CSV file will be saved"
            ).strip("\"'")
            csv_file = Path(output_path).resolve()
            if output_path:
                self.export_csv(results=results, output_path=csv_file)


    def export_csv(
            self,
            results: List[dict],
            output_path: Path | str
    ) -> None:
        """Export results to CSV for further analysis."""
        with open(output_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "filepath",
                "valid",
                "detected_ext",
                "claimed_ext",
                "error"
            ])
            for r in results:
                writer.writerow([
                    r["path"],
                    r["valid"],
                    r["detected_ext"],
                    r["claimed_ext"],
                    r["error"] or "",
                ])
        self.ui.success(f"Results exported to → {output_path}")


# --- Entry point
# if __name__ == "__main__":
#     config_path = os.path.join(
#         os.path.dirname(os.path.abspath(__file__)),
#         "signatures_config.json"
#     )

#     print("  Initialising validator...")
#     validator = FileTypeValidator(config_path=config_path)

#     runner = FileCheckRunner(validator=validator)

#     try:
#         results = runner.run_file_checker()

#         if len(results) > 1:
#             export = FileCheckRunner._prompt_yes_no(
#                 "\nExport results to CSV?", default=False
#             )
#             if export:
#                 out = input("Output file path: ").strip()
#                 if out:
#                     runner.export_csv(results, out)

#     except KeyboardInterrupt:
#         print("\n\nCancelled by user. Goodbye!")