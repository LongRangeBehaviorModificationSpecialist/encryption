# !/usr/bin/env python3

import csv
from datetime import datetime
import magic
import math
from pathlib import Path
from rich.console import Console
from rich.table import Table
from shlex import split
from typing import Any, Dict, List, Tuple

# Imports from the main __init__.py file
from .. import install
from config.log_config import get_logger
from utils import Utils, UIHandlerProtocol, RichUIHandler, get_time


logger = get_logger("detect")
install()


class FileAnalyzer:

    # Refined entropy thresholds based on empirical analysis
    ENTROPY_THRESHOLDS = {
        "high_confidence": 7.95,      # Near-perfect randomness
        "medium_confidence": 7.80,    # Strong encryption signal
        "low_confidence": 7.60,       # Suspected encryption
    }

    # Known MIME types associated with standard encrypted payloads
    ENCRYPTION_MIME_TYPES = {
        "application/pgp-encrypted",
        "application/pgp-signature",
        "application/x-gpg",
        "application/x-openssl",
        "application/x-luks",
    }

    # Signatures for known encrypted formats
    ENCRYPTION_MAGIC_BYTES: Dict[str, bytes] = {
        "7-Zip Archive (Encrypted Header)": b"7z\xbc\xaf\x27\x1c",
        "BitLocker": b"mkfs.fuseblk",
        "GPG/PGP": b"\xc5",
        "GPG Encrypted Data": b"\x8c",
        "GPG Message": b"\x85",
        "LUKS": b"LUKS\xff\xfe",
        "LUKS Header": b"LUKS\xba\xbe",
        "OpenSSL Encrypted": b"Salted__",
        "SSL/TLS Record": b"\x16\x03",
        "Veracrypt": b"\x00\x00\x00\x00",
    }

    # Signatures for naturally high-entropy compressed or binary formats
    COMPRESSED_MAGIC_BYTES: Dict[str, bytes] = {
        "7z": b"\x37\x7a\xbc\xef",
        "bzip2": b"BXZ2",
        "GZIP Archive": b"\x1f\x8b",
        "JPEG Image": b"\xff\xd8\xff",
        "lzma": b"\x5d\x00\x00\x01\x00",
        "PDF Document": b"%PDF-",
        "PNG Image": b"\x89PNG\r\n\x1a\n",
        "rar": b"\x52\x61\x72\x21\x1a\x07",
        "RAR Archive": b"Rar!\x1a\x07",
        "xz": b"\xfd\x37\x7a\x58\x5a\x00",
        "XZ Compression": b"\xfd7zXZ\x00",
        "zip": b"\x50\x4b\x03\x04",
        "ZIP Archive": b"PK\x03\x04",
        "zstd": b"\x28\xb5\x2f\xfd",
    }

    def __init__(self, ui: UIHandlerProtocol | None = None) -> None:
        self.ui = ui or RichUIHandler(get_time=get_time)


    def _calculate_entropy(self, data: bytes) -> float:
        """Calculates Shannon entropy using vectorized NumPy operations."""
        if not data:
            return 0.0

        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        length = len(data)
        entropy = 0.0

        for count in byte_counts:
            if count > 0:
                probability = count / length
                entropy -= probability * math.log2(probability)

        return entropy


    def _chi_square_test(self, data: bytes) -> float:
        """
        Perform chi-square test for uniform distribution.
        Higher values indicate deviation from uniform distribution.
        Encrypted data should have LOW chi-square values (uniform).
        """
        if not data:
            return 0.0

        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        expected = len(data) / 256
        chi_square = sum(
            (observed - expected) ** 2 / expected for observed in byte_counts)

        # Normalize to 0-1 scale (approximate)
        max_chi = len(data) * 255 / 256  # Worst case
        normalized = min(chi_square / max_chi, 1.0)

        # Higher = more uniform = more likely encrypted
        return 1.0 - normalized


    def _run_length_check(self, data: bytes, max_run: int = 100) -> bool:
        """Check for suspiciously long runs of identical bytes.

        Returns:
            True or False
        """
        if len(data) < max_run:
            return True

        current_byte = data[0]
        run_length = 1

        # Only check first ~200 bytes
        for byte in data[1:max_run * 2]:
            if byte == current_byte:
                run_length += 1
                if run_length > max_run:
                    # Found suspicious run
                    return False
            else:
                current_byte = byte
                run_length = 1

        return True


    def _sample_regions(
            self,
            file_path: Path,
            sample_size: int = 65536,
            num_samples: int = 3
    ) -> List[Tuple[int, bytes]]:
        """Sample multiple regions of the file for analysis."""
        samples = []
        file_size = file_path.stat().st_size

        if file_size <= sample_size:
            with open(file_path, "rb") as f:
                return [(0, f.read())]

        regions = [
            0,                        # Beginning (headers)
            file_size // 4,           # Quarter point
            file_size // 2,           # Middle
            3 * file_size // 4,       # Three-quarter point
            file_size - sample_size,  # End
        ]

        # Select up to num_samples evenly spread
        selected_regions = regions[:num_samples + 1]

        with open(file_path, "rb") as f:
            for pos in selected_regions:
                f.seek(pos)
                samples.append((pos, f.read(sample_size)))

        return samples


    def _handle_inspect_file(self) -> None:
        raw_input = self.ui.prompt(
            "Enter the file path(s) of the file to be checked (separated by spaces)"
        )
        paths = [Path(p) for p in split(raw_input)]

        if not paths:
            self.ui.warning("No files provided")
            return
        logger.info(f"The file path(s) were entered as '{raw_input}'")

        self.scan_files(file_paths=paths)


    def inspect_file(
            self,
            file_path: Path,
            sample_size: int = 65536
    ) -> Dict[str, Any]:
        """Inspects a file to determine if it is encrypted based on headers,
        MIME types, and Shannon entropy.

        Param:
            file_path: Path to the target file.
            sample_size: Bytes to read for entropy analysis (default 64 KB).

        Returns:
            Dictionary containing file analysis results.
        """
        result = {
            "file_name": file_path.name,
            "file_size": 0,
            "is_encrypted": False,
            "confidence": "Low",
            "confidence_score": 0.0,
            "mime_type": None,
            "entropy": 0.0,
            "avg_entropy": 0.0,
            "entropy_variance": 0.0,
            "chi_square_uniformity": 0.0,
            "detected_format": None,
            "analysis_notes": [],
            "error": None,
        }

        try:
            if not file_path.is_file():
                result["error"] = "Not a regular file"
                return result

            result["file_size"] = file_path.stat().st_size

            if result["file_size"] == 0:
                result["error"] = "Empty file"
                return result

            # Read the file header
            with open(file_path, "rb") as f:
                header = f.read(16)

            samples = self._sample_regions(
                file_path,
                sample_size,
                num_samples=3,
            )

            if not samples:
                result["error"] = "Could not read file"
                return result

            # Calculate entropy for each region
            entropies = [self._calculate_entropy(data) for _, data in samples]
            result["avg_entropy"] = round(sum(entropies) / len(entropies), 4)
            result["entropy_variance"] = round(
                sum((e - result["avg_entropy"]) ** 2 for e in entropies) / len(entropies), 4
            )
            result["entropy"] = result["avg_entropy"]

            # Analyze first sample for MIME type
            first_sample = samples[0][1] if samples else b""
            mime_type = magic.from_buffer(first_sample, mime=True)
            description = magic.from_buffer(first_sample, mime=False)
            result["mime_type"] = mime_type

        # Check known encryption signatures
            for enc_name, magic_bytes in self.ENCRYPTION_MAGIC_BYTES.items():
                if header.startswith(magic_bytes):
                    result["is_encrypted"] = True
                    result["confidence"] = "High"
                    result["confidence_score"] = 0.95
                    result["detected_format"] = enc_name
                    result["analysis_notes"].append(
                            f"Encryption header detected: {enc_name}"
                        )
                    return result

            # Check known compression signatures (exclude from
            # encryption detection)
            for fmt_name, magic_bytes in self.COMPRESSED_MAGIC_BYTES.items():
                if header.startswith(magic_bytes):
                    result["is_encrypted"] = False
                    result["confidence"] = "High"
                    result["confidence_score"] = 0.95
                    result["detected_format"] = fmt_name
                    result["analysis_notes"].append(
                        f"Compression format detected: {fmt_name}"
                    )
                    return result

            # Skip high-entropy checks for known media files
            # (reduces false positives)
            media_prefixes = ("image/", "video/", "audio/", "application/pdf")
            if mime_type.startswith(media_prefixes):
                result["is_encrypted"] = False
                result["confidence"] = "High"
                result["confidence_score"] = 0.90
                result["detected_format"] = description
                return result

            # Chi-square uniformity test
            chi_uniformity = self._chi_square_test(first_sample)
            result["chi_square_uniformity"] = round(chi_uniformity, 4)

            # Run-length check
            has_suspicious_runs = not self._run_length_check(first_sample)

            # Build confidence score from multiple factors
            confidence_components = []

            # Factor 1: Average entropy (primary indicator)
            avg_ent = result["avg_entropy"]
            if avg_ent >= self.ENTROPY_THRESHOLDS["high_confidence"]:
                confidence_components.append(0.95)
                result["analysis_notes"].append(
                    f"Very high entropy: {avg_ent:.4f}"
                )
            elif avg_ent >= self.ENTROPY_THRESHOLDS["medium_confidence"]:
                confidence_components.append(0.80)
                result["analysis_notes"].append(
                    f"High entropy: {avg_ent:.4f}"
                )
            elif avg_ent >= self.ENTROPY_THRESHOLDS["low_confidence"]:
                confidence_components.append(0.50)
                result["analysis_notes"].append(
                    f"Elevated entropy: {avg_ent:.4f}"
                )
            else:
                confidence_components.append(0.10)

            # Factor 2: Entropy variance (should be consistent across file)
            if result["entropy_variance"] < 0.05:
                # Consistent = likely truly encrypted
                confidence_components.append(0.90)
                result["analysis_notes"].append(
                    "Low entropy variance across regions"
                )
            elif result["entropy_variance"] > 0.3:
                # High variance suggests mixed content
                confidence_components.append(0.30)
                result["analysis_notes"].append(
                    "High entropy variance - possible mixed content"
                )

            # Factor 3: Chi-square uniformity
            if chi_uniformity > 0.85:
                confidence_components.append(0.85)
                result["analysis_notes"].append(
                    "Byte distribution highly uniform"
                )
            elif chi_uniformity > 0.70:
                confidence_components.append(0.60)

            # Factor 4: No suspicious byte runs
            if not has_suspicious_runs:
                confidence_components.append(0.70)
                result["analysis_notes"].append(
                    "No suspicious run lengths detected"
                )
            else:
                confidence_components.append(0.40)
                result["analysis_notes"].append(
                    "Suspicious run lengths found - may be weak encryption "
                    "or compressed"
                )

            # Combined confidence score
            combined_score = (
                sum(confidence_components) /
                len(confidence_components)
            )
            result["confidence_score"] = round(combined_score, 2)

            # Final determination
            if combined_score >= 0.85:
                result["is_encrypted"] = True
                result["confidence"] = "High"
                result["detected_format"] = "Unknown High-Entropy Payload"
            elif combined_score >= 0.70:
                result["is_encrypted"] = True
                result["confidence"] = "Medium"
                result["detected_format"] = (
                    "Suspected Encrypted/Compressed Payload"
                )
            elif combined_score >= 0.50:
                result["is_encrypted"] = True
                result["confidence"] = "Low"
                result["detected_format"] = (
                    "Possibly Encrypted - Manual Review Recommended"
                )
            else:
                result["is_encrypted"] = False
                result["confidence"] = "Low"
                result["detected_format"] = "Likely Unencrypted"

        except PermissionError:
            result["error"] = "Permission denied"
        except (OSError, IOError) as err:
            result["error"] = str(err)

        return result


    def scan_files(self, file_paths: List[Path]) -> List[Dict[str, Any]]:
        """Scans one or more files and prints the results table."""
        results = []

        for path in file_paths:
            result = self.inspect_file(path)
            results.append(result)

        if results:
            self.print_results_table(results)

        return results


    def scan_directory(self) -> List[Dict[str, Any]]:
        """Scans all files within a directory and reports encryption
        statuses.
        """
        path_input = self.ui.prompt(
            "Enter the file path(s) of the file to be checked (separated "
            "by spaces)"
        ).strip("\"'")
        path = Path(path_input)
        logger.info(f"The target_dir was entered as '{path}'")

        if not path.exists():
            self.ui.error(f"The input path does not exist → '{path}'")
            return

        if path.is_file():
            files = [path]

        elif path.is_dir():
            recursive = Utils.select_recursive_option(self)
            logger.info(f"The recursive option was set to → '{recursive}'")

            if recursive:
                files = [f for f in path.rglob("*") if f.is_file()]
                self.ui.info(f"Found {len(files)} files (recursive scan)")
            else:
                files = [f for f in path.iterdir() if f.is_file()]
                self.ui.info(f"Found {len(files)} files (top-level only)")

            # Optionally filter by extension
            filter_ext = self.ui.prompt(
                "Filter by file extension? (press Enter to skip, or type "
                "extensions -- e.g. .bin .enc .dat)"
            )

            if filter_ext:
                ext_set = {ext.strip().lower() for ext in filter_ext.split()}
                files = [f for f in files if f.suffix.lower() in ext_set]
                self.ui.info(
                    f"Filtered to {len(files)} files matching extensions"
                )

        else:
            self.ui.error(f"Not a valid file or directory → {path}")
            return

        if not files:
            self.ui.warning("No files found to scan.")
            return

        self.scan_files(
            file_paths=files,
        )


    def print_results_table(self, results: List[Dict[str, Any]]) -> None:
        """Renders analysis results using Rich tables with enhanced
        encryption detection data.
        """
        table = Table(
            show_header=True,
            header_style="bold cyan",
            show_lines=True,
            row_styles=["dim", ""]
            )

        table.add_column("File", style="bold white")
        table.add_column("Size", justify="right", style="dim")
        table.add_column("Detected Format", style="bright_blue", max_width=30)
        table.add_column("Encryption")
        table.add_column("Confidence", justify="right")
        table.add_column("Entropy", justify="right")

        # First loop: build the table with all rows
        for result in results:
            if result.get("error"):
                table.add_row(
                    result["file_name"],
                    str(result.get("file_size", 0)),
                    "-",
                    "[bold red]Error[/bold red]",
                    "0%",
                    "-"
                )
                continue

            # Get file size
            file_size = result.get("file_size", 0)
            size_str = f"{file_size:,}B" if file_size < 1024 else f"{file_size/1024:.1f}KB" if file_size < 1048576 else f"{file_size/1048576:.1f}MB"

            # Get detected format
            detected_format = (
                result.get("detected_format")
                or result.get("mime_type")
                or "Unknown"
            )

            # is_encrypted is now boolean
            is_encrypted = result.get("is_encrypted", False)
            if is_encrypted:
                confidence = result.get("confidence", "Low")
                if confidence == "High":
                    status_style = f"[bold red]ENCRYPTED[/bold red]"
                elif confidence == "Medium":
                    status_style = f"[yellow]Suspected[/yellow]"
                else:  # Low
                    status_style = f"[dim yellow]Possible[/dim yellow]"
            else:
                status_style = "[green]Plaintext[/green]"

            # Combine confidence level and confidence score
            confidence_level = result.get("confidence", "Low")
            confidence_score = result.get("confidence_score", 0.0)
            confidence_str = f"{confidence_level} ({confidence_score:.0%})"

            # Add entropy info
            avg_entropy = (
                result.get("avg_entropy")
                or result.get("entropy", 0.0)
            )
            entropy_str = f"{avg_entropy:.2f}/8.0"

            table.add_row(
                result["file_name"],
                size_str,
                detected_format,
                status_style,
                confidence_str,
                entropy_str
            )

        # NOW print the completed table (OUTSIDE the first loop)
        console = Console()
        console.print(table)

        # Print additional analysis notes for encrypted files
        # (second separate loop)
        encrypted_results = [
            r for r in results
            if r.get("is_encrypted") and r.get("analysis_notes")
        ]
        if encrypted_results:
            console.print("\n[bold cyan]Detailed Analysis:")
            for result in encrypted_results:
                console.print(f"  [cyan]• {result['file_name']}")
                for note in result["analysis_notes"]:
                    console.print(f"    [dim]- {note}")

        # Print summary statistics (after both loops finish)
        total_files = len(results)
        encrypted_count = sum(1 for r in results if r.get("is_encrypted"))
        error_count = sum(1 for r in results if r.get("error"))

        console.print(f"\n[bold green]Summary:\n")
        console.print(f"  Total Files: {total_files}")
        console.print(f"  Encrypted/Detected: [red]{encrypted_count}")
        console.print(f"  Plaintext: [green]{total_files - encrypted_count - error_count}[/green]")
        console.print(f"  Errors: [yellow]{error_count}\n")

        if results:
            export = self.ui.confirm("Export results to CSV?")

            if export:
                custom_path = self.ui.prompt(
                    "Enter output path (press [Enter] for auto-generated "
                    "filename)"
                )

                if custom_path:
                    output_path = Path(custom_path).expanduser()
                else:
                    output_path = None

                try:
                    csv_path = self.export_results_csv(results, output_path)
                    self.ui.success(f"Results exported to → '{csv_path}'")
                except Exception as err:
                    self.ui.error(f"Failed to export CSV → {err}")


    def export_results_csv(
            self,
            results: List[Dict[str, Any]],
            output_path: Path = None
    ) -> Path:
        """Export analysis results to a CSV file.

        Args:
            results: List of result dictionaries from inspect_file.
            output_path: Custom output path. If None, generates a timestamped filename.

        Returns:
            Path to the exported CSV file.
        """
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = Path(f"encryption_scan_{timestamp}.csv")

        fieldnames = [
            "file_name",
            "file_size",
            "is_encrypted",
            "confidence",
            "confidence_score",
            "detected_format",
            "mime_type",
            "avg_entropy",
            "entropy_variance",
            "chi_square_uniformity",
            "analysis_notes",
            "error",
        ]

        with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(
                csvfile,
                fieldnames=fieldnames,
                extrasaction="ignore",
            )

            writer.writeheader()
            for result in results:
                # Convert analysis_notes list to a semicolon-separated string
                row = result.copy()
                if isinstance(row.get("analysis_notes"), list):
                    row["analysis_notes"] = "; ".join(row["analysis_notes"])
                # Convert boolean to Yes/No for readability
                row["is_encrypted"] = "Yes" if row.get("is_encrypted") else "No"
                writer.writerow(row)

        return output_path
