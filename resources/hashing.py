#!/usr/bin/env python3

import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional
from rich.console import Console

from config.results import Results
from utils import UIHandlerProtocol, RichUIHandler, get_time


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

        Returns:
            List of selected algorithm names (e.g., ["md5", "sha256"]).
        """
        # self.ui.info("[bold]Available Algorithms:[/bold]")
        # for num, algo in self.ALGORITHM_CHOICES.items():
        #     display_name = self.ALGORITHM_NAMES[algo]
        #     self.ui.info(f"  [{num}] {display_name}")
        # self.ui.info("  [5] All (run all available algorithms)")
        # self.ui.info("")

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
                self.ui.info(f"Selected: {', '.join(selected_names)}")
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
            raise FileNotFoundError(f"File not found: {file_path}")
        if not path.is_file():
            raise ValueError(f"Not a file: {file_path}")

        algs = algorithms or self.SUPPORTED_ALGORITHMS
        file_size = path.stat().st_size

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
            raise FileNotFoundError(f"Directory not found: {dir_path}")
        if not path.is_dir():
            raise ValueError(f"Not a directory: {dir_path}")

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


    def run_hash_with_ui_selection(self, input_type: str) -> Dict[str, Any]:
        """
        Interactive flow with algorithm selection prompt.

        Args:
            input_type: "string", "file", or "directory".

        Returns:
            Results dictionary.
        """
        algorithms = self.prompt_algorithm_selection()

        if input_type == "string":
            user_input = self.ui.prompt("Enter text to hash")
            results = self.compute_string_hash(
                text=user_input,
                algorithms=algorithms,
            )
        elif input_type == "file":
            user_input = self.ui.prompt("Enter path of file to hash")
            file_path = user_input.strip("\"'")
            results = self.compute_file_hash(
                file_path=file_path,
                algorithms=algorithms,
            )
        elif input_type == "directory":
            user_input = self.ui.prompt("Enter directory path to hash")
            dir_path = user_input.strip("\"'")
            results = self.compute_directory_hash(
                dir_path=dir_path,
                algorithms=algorithms,
            )
        else:
            results = self._wrap_result({
                "Input Type": "Unknown",
                "Validation OK": "False",
                "error": f"Unknown input type: {input_type}"
            })

        Results.print_hasher_results(self, results_dict=results)
