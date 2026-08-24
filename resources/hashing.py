#!/usr/bin/env python3

import csv
from datetime import datetime
import hashlib
import json
from pathlib import Path
from typing import Dict, List, Any, Optional

from config.log_config import get_logger
from config.results import Results
from utils import Utils, UIHandlerProtocol, RichUIHandler, get_time


logger = get_logger("hasher")


class Hashing:
    """
    Standalone hashing class.

    Provides string, file, and directory hashing with multiple algorithms.
    Designed to work independently or integrate with framework via UI protocol.
    """

    ALGORITHM_CHOICES = {
        "1": "md5",
        "2": "sha1",
        "3": "sha256",
        "4": "sha512",
        "5": "blake2b"
    }
    ALGORITHM_NAMES = {
        "md5": "MD5",
        "sha1": "SHA1",
        "sha256": "SHA256",
        "sha512": "SHA512",
        "blake2b": "BLAKE2b"
    }

    SUPPORTED_ALGORITHMS = list(ALGORITHM_NAMES.keys())

    SUPPORTED_EXPORT_FORMATS = ["csv", "json", "txt"]

    def __init__(self, ui: UIHandlerProtocol | None = None) -> None:
        """
        Initialize Hashing engine.

        Args:
            ui: Optional UI handler implementing prompt/info/error/warning methods.
                Defaults to rich Console() if not provided.
        """
        self.ui = ui or RichUIHandler(get_time=get_time)
        self._chunk_size = 8192  # 8 KB chunks for large file streaming

    def prompt_algorithm_selection(self) -> List[str]:
        """
        Prompt user to select one or more hashing algorithms.

        Args:
            None

        Returns:
            List of selected algorithm names (e.g., ["md5", "sha256"]).
        """

        while True:
            selection = self.ui.prompt(
            "What algorithm do you want to use ([1] MD5, [2] SHA1, "
            "[3] SHA256, [4] SHA512, [5] All. Use '#, #, ...' to chose more "
            "than one)?",
        )

            if not selection:
                self.ui.warning("No selection made. Please enter a value.")
                continue

            algorithms = self._parse_algorithm_selection(selection)

            if algorithms:
                selected_names = [
                    self.ALGORITHM_NAMES[a].upper() for a in algorithms
                ]
                selections = ', '.join(selected_names)
                self.ui.info(f"Selected: {selections}")
                logger.info(
                    f"User chose the following hashing algorithm(s) → "
                    f"[ {selections} ]")
                return algorithms
            else:
                self.ui.error("Invalid selection. Please use numbers 1-5.")

    def _parse_algorithm_selection(
            self,
            selection: str
    ) -> Optional[List[str]]:
        """
        Parse comma-separated algorithm selection.

        Args:
            selection: User input like "1, 3, 4" or "5" for all.

        Returns:
            List of algorithm names or None if invalid.
        """
        if not selection:
            return None

        # Split by comma, strip whitespace, normalize
        choices = [s.strip().lower() for s in selection.split(",")]

        if "all" in choices or "5" in choices:
            return self.SUPPORTED_ALGORITHMS.copy()

        parsed_algorithms = []
        for choice in choices:
            if choice == "5":
                return self.SUPPORTED_ALGORITHMS.copy()
            elif choice in self.ALGORITHM_CHOICES:
                algo = self.ALGORITHM_CHOICES[choice]
                if algo not in parsed_algorithms:
                    parsed_algorithms.append(algo)
            else:
                # Invalid choice - return None to trigger retry
                return None

        return parsed_algorithms if parsed_algorithms else None

    def _get_hash_key(self, algorithm: str) -> str:
        """Generate result key for algorithm."""
        name = self.ALGORITHM_NAMES[algorithm]
        if len(self.ALGORITHM_NAMES) == 1:
            return "Hash"
        return f"{name} Hash"

    def _wrap_result(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Ensure result has required keys for framework compatibility."""
        if "Validation OK" not in data:
            data["Validation OK"] = "True"
        return data

    def compute_string_hash(
            self,
            text: str,
            algorithms: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Compute hash(es) of text string.

        Args:
            text: Input text to hash.
            algorithm: List of algorithms or None for all

        Returns:
            Dictionary with hash results for each algorithm.
        """

        algs = algorithms or self.SUPPORTED_ALGORITHMS
        results = self._wrap_result({
            "Input Type": "String",
            # "Input Value": self._truncate(text, 100),
            "Input Value": text,
            "Algorithms Used": ", ".join(self.ALGORITHM_NAMES[a].upper() for a in algs),
            "Validation OK": "True"
        })

        for algo in algs:
            hasher = hashlib.new(algo)
            hasher.update(text.encode("utf-8"))
            digest = hasher.hexdigest()
            key = self._get_hash_key(algo)
            results[key] = digest

        return results

    def compute_file_hash(
        self,
        file_path: str,
        algorithms: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Compute hash(s) of single file.

        Args:
            file_path: Path to file.
            algorithms: List of algorithms or None for all.

        Returns:
            Dictionary with hash results for each algorithm.
        """
        path = Path(file_path)

        if not path.exists():
            logger.warning(f"File not found → '{file_path}'")
            raise FileNotFoundError(f"File not found → {file_path}")
        if not path.is_file():
            logger.warning(f"'{file_path}' is not a file")
            raise ValueError(f"Not a file → {file_path}")

        algs = algorithms or self.SUPPORTED_ALGORITHMS
        file_size = path.stat().st_size
        logger.info(f"Size of '{path}' is → '{file_size:,} bytes'")

        hashes = {}
        try:
            with open(path, "rb") as f:
                # Create hasher for each algorithm upfront
                hashers = {algo: hashlib.new(algo) for algo in algs}

                # Read file ONCE, update all hashers simultaneously
                while chunk := f.read(self._chunk_size):
                    for hasher in hashers.values():
                        hasher.update(chunk)

                for algo in algs:
                    hashes[algo] = hashers[algo].hexdigest()
                    logger.info(
                        f"The '{algo.upper()}' hash of '{path}' is → "
                        f"'{hashers[algo].hexdigest()}'"
                    )
        except PermissionError:
            raise PermissionError(f"Permission denied: {file_path}")
        except IOError as err:
            raise IOError(f"Error reading file: {err}")

        results = self._wrap_result({
            "Input Type": "File",
            "File Path": str(path.absolute()),
            "File Size": f"{file_size:,} bytes",
            "Algorithms Used": ", ".join(self.ALGORITHM_NAMES[a].upper() for a in algs),
            "Validation OK": "True"
        })

        for algo in algs:
            key = self._get_hash_key(algo)
            results[key] = hashes[algo]

        return results

    def compute_directory_hash(
            self,
            dir_path: str,
            algorithms: Optional[List[str]] = None,
            recursive: bool = True,
            extensions_filter: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Compute hash(s) for all files in directory.

        Args:
            dir_path: Path to directory.
            algorithms: List of algorithms or None for all.
            recursive: Include subdirectories.
            extensions_filter: Filter by extensions.

        Returns:
            Dictionary with summary stats and per-file hashes.
        """
        path = Path(dir_path)

        if not path.exists():
            logger.warning(f"Directory not found → {dir_path}")
            raise FileNotFoundError(f"Directory not found → {dir_path}")
        if not path.is_dir():
            logger.warning(f"The input path is not a directory → {dir_path}")
            raise ValueError(f"Not a directory → {dir_path}")

        recursive = Utils.select_recursive_option(self)
        if recursive:
            logger.info("User selected recursive = 'True'")
        else:
            logger.info("User selected recursive = 'False'")

        algs = algorithms or self.SUPPORTED_ALGORITHMS
        pattern = "**/*" if recursive else "*"
        file_paths = [f for f in path.glob(pattern) if f.is_file()]

        if extensions_filter:
            file_paths = [
                f for f in file_paths if f.suffix in extensions_filter
            ]

        if not file_paths:
            return self._wrap_result({
                "Input Type": "Directory",
                "Directory Path": str(path.absolute()),
                "File Count": "0 files found",
                "Status": "No matching files",
                "Validation OK": "False",
                "error": "No files found matching criteria."
            })

        results_list = []
        total_files = successful = failed = total_size = 0

        for file_path in file_paths:
            try:
                hashes = self._compute_hashes_for_file(str(file_path), algs)
                file_size = file_path.stat().st_size
                results_list.append({
                    "File": str(file_path.relative_to(path)),
                    "Size": f"{file_size:,} bytes",
                    "Hashes": hashes,  # Dict of {algo: hash}
                    "Success": True
                })
                successful += 1
                total_files += 1
                total_size += file_size
            except (PermissionError, IOError, OSError) as err:
                results_list.append({
                    "File": str(file_path.relative_to(path)),
                    "Size": "N/A",
                    "Hashes": {algo: f"Error: {str(err)}" for algo in algs},
                    "Success": False
                })
                failed += 1
                total_files += 1

        output = {
            "Input Type": "Directory",
            "Directory Path": str(path.absolute()),
            "Algorithms Used": ", ".join(self.ALGORITHM_NAMES[a].upper() for a in algs),
            "Recursive": str(recursive),
            "Total Files": f"{total_files}",
            "Successful": f"{successful}",
            "Failed": f"{failed}",
            "Total Size": f"{total_size:,} bytes",
            "Files": results_list,
            "Validation OK": "True" if failed == 0 else "Partial"
        }

        if failed > 0:
            output["error"] = f"{failed} file(s) could not be hashed."

        # print(output)

        return self._wrap_result(output)

    def _compute_hashes_for_file(
            self,
            file_path: str,
            algorithms: List[str]
    ) -> Dict[str, str]:
        """Helper to hash file with multiple algorithms."""
        hashes = {}
        try:
            with open(file_path, "rb") as f:
                # Create hasher for each algorithm upfront
                hashers = {algo: hashlib.new(algo) for algo in algorithms}

                # Read once, update all hashers
                while chunk := f.read(self._chunk_size):
                    for hasher in hashers.values():
                        hasher.update(chunk)

                for algo in algorithms:
                    hashes[algo] = hashers[algo].hexdigest()
        except Exception:
            for algo in algorithms:
                hashes[algo] = "Error computing hash"

        return hashes

    def _normalize_algorithm(self, algorithm: str) -> str:
        """Normalize algorithm name and validate."""
        algo = algorithm.lower().strip()
        if algo not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(
                f"Unsupported algorithm '{algorithm}'. "
                f"Choose from: {', '.join(self.SUPPORTED_ALGORITHMS)}"
            )
        return algo

    def _truncate(self, text: str, max_length: int = 100) -> str:
        """Truncate long strings for display."""
        if len(text) > max_length:
            return text[:max_length] + "..."
        return text

    def _offer_export(self, results: Dict[str, Any]) -> None:
        """Ask user if they want to export directory results.

        Args:
            results: dictionary containing hashing results.

        Returns:
            None
        """
        if results.get("Validation OK") in ["False"]:
            return

        export_choice = self.ui.prompt(
            "Export results? (Options: [1] CSV, [2] JSON, [3] TXT "
            "(or press [ENTER] to skip)")

        if not export_choice:
            logger.info("User did not enter an option to export the results")
            return

        format_map = {"1": "csv", "2": "json", "3": "txt"}

        if export_choice not in format_map:
            self.ui.warning("Skipping export → an invalid option was entered")
            logger.info(
                f"Skipping data export. User entered an invalid export "
                f"option → '{export_choice}'"
            )
            return

        export_format = format_map[export_choice]
        logger.info(f"User chose to export the results as → '{export_format}'")

        # Ask for custom path or use default
        custom_dir = self.ui.prompt(
            f"Press [ENTER] to save next to the current directory or enter a "
            "custom file path"
        )
        custom_dir = Path(custom_dir.strip("\"'"))
        logger.info(f"'{custom_dir}' was selected as the export location")

        output_filename = self.ui.prompt(
            "Enter the name of the output file (w/o file extension)"
        )
        logger.info(
            f"User entered the export file name as → '{output_filename}'"
        )

        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        custom_path = (
            custom_dir / f"{timestamp}_{output_filename}.{export_format}"
        )
        logger.info(f"Full export file path → '{custom_path}'")

        try:
            saved_path = self.export_directory_results(
                results=results,
                export_path=custom_path if custom_path else None,
                export_format=export_format
            )
            self.ui.success(
                f"The results were exported to: [bright_blue]{saved_path}"
            )
            logger.info(f"The results were exported to: '{saved_path}'")
        except Exception as err:
            error_msg = f"❌ Export failed → {err}"
            self.ui.error(error_msg)
            logger.error(error_msg)

    def export_directory_results(
        self,
        results: Dict[str, Any],
        export_path: Optional[Path | str] = None,
        export_format: str = "csv",
    ) -> str:
        """
        Export directory hash results to a file.

        Args:
            results: Results dict from compute_directory_hash().
            export_path: Destination file path. If None, saves next to the
                directory.
            export_format: "csv", "json", or "txt".

        Returns:
            Path to the exported file.
        """
        export_format = export_format.lower().strip()

        if export_format not in self.SUPPORTED_EXPORT_FORMATS:
            raise ValueError(
                f"Unsupported format → '{export_format}'. "
                f"Choose from: {', '.join(self.SUPPORTED_EXPORT_FORMATS)}"
            )

        # If no path provided, generate one based on the directory and timestamp
        if not export_path:
            dir_path = results.get("Directory Path", "hash_results")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_name = f"hash_results_{timestamp}"
            export_path = (
                str(Path(dir_path).parent / f"{base_name}.{export_format}")
            )

        export_file = Path(export_path)
        export_file.parent.mkdir(parents=True, exist_ok=True)

        if export_format == "csv":
            self._export_csv(results=results, path=export_file)
        elif export_format == "json":
            self._export_json(results=results, path=export_file)
        elif export_format == "txt":
            self._export_txt(results=results, path=export_file)

        return str(export_file.absolute())

    def _export_csv(self, results: Dict[str, Any], path: Path) -> None:
        """Export file names and hash values to CSV format."""
        files = results.get("Files", [])

        if not files:
            self.ui.warning("No files to export")
            logger.warning("No files to export")
            return

        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)

            # Get algorithm keys from the first file that has hashes
            algo_columns = []
            for file_entry in files:
                hashes = file_entry.get("Hashes", {})
                if hashes:
                    algo_columns = list(hashes.keys())
                    break

            # Write header row (just File + algorithm names)
            header = ["File"] + algo_columns
            writer.writerow(header)

            # Write each file's data
            for file_entry in files:
                file_name = file_entry.get("File", "")
                hashes = file_entry.get("Hashes", {})

                row_data = [file_name]
                for algo in algo_columns:
                    row_data.append(hashes.get(algo, ""))

                writer.writerow(row_data)

    def _export_json(self, results: Dict[str, Any], path: Path) -> None:
        """Export to JSON format."""
        export_data = {
            "export_timestamp": datetime.now().isoformat(),
            "summary": {
                "directory_path": results.get("Directory Path", ""),
                "algorithms_used": results.get("Algorithms Used", ""),
                "total_files": results.get("Total Files", ""),
                "successful": results.get("Successful", ""),
                "failed": results.get("Failed", ""),
                "total_size": results.get("Total Size", ""),
                "validation_status": results.get("Validation OK", ""),
            },
            "files": [],
        }

        for file_entry in results.get("Files", []):
            export_data["files"].append(
                {
                    "file": file_entry.get("File", ""),
                    "size": file_entry.get("Size", ""),
                    "hashes": file_entry.get("Hashes", {}),
                    "success": file_entry.get("Success", False),
                }
            )

        with open(path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=4, ensure_ascii=False)

    def _export_txt(self, results: Dict[str, Any], path: Path) -> None:
        """Export to plain text format."""
        lines = []
        lines.append("=" * 72)
        lines.append("DIRECTORY HASH REPORT")
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 72)
        lines.append("")
        lines.append(f"Directory:    {results.get('Directory Path', '')}")
        lines.append(f"Algorithm(s): {results.get('Algorithms Used', '')}")
        lines.append(f"Total Files:  {results.get('Total Files', '')}")
        lines.append(f"Successful:   {results.get('Successful', '')}")
        lines.append(f"Failed:       {results.get('Failed', '')}")
        lines.append(f"Total Size:   {results.get('Total Size', '')}")
        lines.append("")

        files = results.get("Files", [])

        if files:
            for file_entry in files:
                file_name = file_entry.get("File", "")
                file_size = file_entry.get("Size", "")
                hashes = file_entry.get("Hashes", {})

                # File name and size on the same line
                lines.append(f"File Name : {file_name}")
                lines.append(f"    File Size : {file_size}")

                # Each hash algorithm indented underneath
                for algo, hash_val in hashes.items():
                    lines.append(f"    {algo.upper()} : {hash_val}")

                lines.append("")  # Blank line between files

        lines.append("=" * 72)

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def run_hash_with_ui_selection(self, input_type: str) -> Dict[str, Any]:
        """
        Interactive flow with algorithm selection and optional export.

        Args:
            input_type: "string", "file", or "directory".

        Returns:
            Results dictionary.
        """
        algorithms = self.prompt_algorithm_selection()

        if input_type == "string":
            user_input = self.ui.prompt("Enter text string to hash")
            logger.info(f"User entered string value → '{user_input}'")
            results = self.compute_string_hash(
                text=user_input,
                algorithms=algorithms,
            )
        elif input_type == "file":
            user_input = self.ui.prompt("Enter path of file to process")
            logger.info(f"User entered file path → '{user_input}'")
            file_path = user_input.strip("\"'")
            results = self.compute_file_hash(
                file_path=file_path,
                algorithms=algorithms,
            )
        elif input_type == "directory":
            user_input = self.ui.prompt("Enter directory path to process")
            logger.info(f"User entered directory path → '{user_input}'")
            dir_path = user_input.strip("\"'")
            results = self.compute_directory_hash(
                dir_path=dir_path,
                algorithms=algorithms,
            )

            # Offer export for directory results
            self._offer_export(results)

        else:
            results = self._wrap_result({
                "Input Type": "Unknown",
                "Validation OK": "False",
                "error": f"Unknown input type: {input_type}"
            })

        Results.print_hasher_results(self, results_dict=results)
