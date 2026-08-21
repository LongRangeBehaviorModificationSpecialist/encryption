#!/usr/bin/env python3

"""
timestamp_converter.py v3.0

Universal timestamp converter with endianness detection, bidirectional
conversion, relative time display, enhanced confidence scoring, ambiguity
reports, and timezone support.

Supported formats:
    - Unix epoch (seconds, milliseconds, microseconds, nanoseconds)
    - Windows FILETIME (100-ns intervals since 1601)
    - Chrome timestamp (same as Windows FILETIME)
    - Apple Cocoa / NSTimeInterval (seconds since 2001)
    - Apple HFS+ (seconds since 1904)
    - MS-DOS 32-bit packed timestamp
    - Microsoft .NET Ticks (100-ns intervals since year 1)
    - ISO 8601 datetime strings
    - Common date string formats
    - Hex values (auto-detects little-endian and big-endian)

Features:
    - Automatic endianness detection for hex input
    - Relative time display ("3 hours ago", "in 2 days")
    - Enhanced confidence scoring with recency bonus, range centerness, and
        structure checks
    - Ambiguity report showing all valid interpretations ranked by confidence
    - Timezone conversion for output display
    - Interactive CLI with encode, decode, batch, and test modes
"""

from datetime import datetime, timezone, timedelta
import re
from typing import Union, Optional, Tuple, List
from zoneinfo import ZoneInfo
TZ_AVAILABLE = True

from . import install
from config.log_config import get_logger
from utils import Utils, UIHandlerProtocol, RichUIHandler, get_time


logger = get_logger("time_converter")
install()


class DecodeResult:
    """Structured result from timestamp decoding."""

    def __init__(
            self,
            dt: datetime,
            fmt: str,
            confidence: float,
            endianness: Optional[str] = None,
            raw_value: Optional[int] = None,
            relative_time: Optional[str] = None,
            target_tz: Optional[str] = None,
            local_time: Optional[datetime] = None
    ) -> None:
        self.datetime = dt
        self.format = fmt
        self.confidence = confidence
        self.endianness = endianness
        self.raw_value = raw_value
        self.relative_time = relative_time
        self.target_tz = target_tz
        self.local_time = local_time


    def to_dict(self) -> dict:
        return {
            "datetime": self.datetime.isoformat(),
            "format": self.format,
            "confidence": round(self.confidence, 1),
            "endianness": self.endianness or "N/A",
            "raw_value": self.raw_value,
            "human_readable": self._format_human(self.datetime, "verbose"),
            "short_format": self._format_human(self.datetime, "short"),
            "iso_format": self.datetime.isoformat(),
            "relative_time": self.relative_time,
            "target_timezone": self.target_tz,
            "local_time": self.local_time.isoformat() if self.local_time else None,
            "local_human_readable": self._format_human(
                self.local_time,
                "verbose") if self.local_time else None,
        }


    @staticmethod
    def _format_human(dt: datetime, style: str = "iso") -> str:
        styles = {
            "iso": dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "verbose": dt.strftime("%A, %B %d, %Y at %I:%M:%S %p UTC"),
            "short": dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "compact": dt.strftime("%y-%m-%d %H:%M"),
            "full": dt.strftime("%A, %B %d, %Y %I:%M:%S %p (UTC)"),
        }
        return styles.get(style, styles["verbose"])


class AmbiguityReport:
    """Report when a timestamp could be interpreted in multiple ways."""

    def __init__(
            self,
            interpretations: List[dict],
            is_ambiguous: bool,
            recommendation: Optional[str] = None,
            notes: Optional[str] = None
    ) -> None:
        self.interpretations = interpretations
        self.is_ambiguous = is_ambiguous
        self.recommendation = recommendation
        self.notes = notes


    def to_dict(self) -> dict:
        return {
            "ambiguous": self.is_ambiguous,
            "interpretation_count": len(self.interpretations),
            "interpretations": self.interpretations,
            "recommendation": self.recommendation,
            "notes": self.notes,
        }


    def __str__(self) -> str:
        lines = []
        header = "AMBIGUOUS" if self.is_ambiguous else "UNAMBIGUOUS"
        lines.append(f"[{header}] {len(self.interpretations)} valid interpretation(s) found")
        if self.recommendation:
            lines.append(f"Recommendation: {self.recommendation}")
        if self.notes:
            lines.append(f"Notes: {self.notes}")
        lines.append("")
        for i, interp in enumerate(self.interpretations, 1):
            lines.append(f"  #{i} {interp['format']:<20} "
                        f"(endian: {interp.get('endianness', 'N/A'):<6}) "
                        f"→ {interp['datetime']} "
                        f"[confidence: {interp['confidence']:.1f}%]")
        return "\n".join(lines)


class TimestampConverter:
    """Universal timestamp converter supporting 10+ formats with endianness
    detection, relative time display, enhanced confidence scoring, ambiguity
    reports, and timezone support.
    """

    # Epochs
    UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
    WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
    APPLE_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)
    HFS_PLUS_EPOCH = datetime(1904, 1, 1, tzinfo=timezone.utc)
    NET_EPOCH = datetime(1, 1, 1, tzinfo=timezone.utc)
    DOS_EPOCH_YEAR = 1980

    # Conversion constants
    HUNDRED_NANOSECONDS_PER_SECOND = 10_000_000
    MICROSECONDS_PER_SECOND = 1_000_000
    MILLISECONDS_PER_SECOND = 1_000
    NANOSECONDS_PER_SECOND = 1_000_000_000
    TICKS_PER_SECOND = 10_000_000

    # Valid timestamp ranges (in each format's native unit)
    # 2000-2100
    VALID_UNIX_SECONDS_RANGE = (946684800, 4102444800)
    VALID_UNIX_MS_RANGE = (946684800000, 4102444800000)
    VALID_UNIX_US_RANGE = (946684800000000, 4102444800000000)
    # ~2000-2035 (100-ns)
    VALID_WINDOWS_RANGE = (125911584000000000, 137410560000000000)
    # same as Windows
    VALID_CHROME_RANGE = (125911584000000000, 137410560000000000)
    # 1990-2099 (seconds from 2001)
    VALID_APPLE_RANGE = (-315619200, 3108384000)
    # 2000-2099 (seconds from 1904)
    VALID_HFS_PLUS_RANGE = (3033427200, 6169084800)
    # 2000-2099
    VALID_TICKS_RANGE = (630822816000000000, 661489056000000000)


    def __init__(self, ui: UIHandlerProtocol | None = None) -> None:
        self.ui = ui or RichUIHandler(get_time=get_time)
        self.conversion_history = []
        self.last_endianness_used = None


    # --- PUBLIC API

    def _handle_time_decode_encode(self, method: str) -> None:
        if method == "decode":
            ts_input = Utils.get_time_converter_input(self, method="decode")
            if not ts_input:
                self.ui.warning("⚠️ No input provided.")

            target_tz = _prompt_timezone()

            try:
                result = self.decode(
                    timestamp=ts_input,
                    target_tz=target_tz
                )

                self.ui.success("DECODE SUCCESSFUL")
                self.ui.info(f"Format Detected    : {result['format']}")
                if result.get("endianness") and result["endianness"] != "N/A":
                    self.ui.info(
                        f"Endianness         : "
                        f"{result['endianness'].title()}"
                    )

                conf = result.get("confidence", 0)
                if conf >= 75:
                    conf_label = "🟢 High"
                elif conf >= 50:
                    conf_label = "🟡 Medium"
                else:
                    conf_label = "🔴 Low"
                self.ui.info(f"Confidence         : {conf:.1f}% ({conf_label})")
                self.ui.info(f"Datetime (UTC)     : {result['iso_format']}")
                self.ui.info(f"Human Readable     : {result['human_readable']}")
                self.ui.info(f"Relative Time      : {result['relative_time']}")

                if result.get("raw_value"):
                    self.ui.info(f"Raw Value Used     : {result['raw_value']}")

                if result.get("local_time"):
                    self.ui.info(
                        f"Local Time ({result['target_timezone']}) : "
                        f"{result['local_human_readable']}"
                    )

            except ValueError as err:
                print(f"\n❌ DECODE FAILED: {err}")

        else:
            dt_input = Utils.get_time_converter_input(self, method="encode")
            if not dt_input:
                print("⚠️ No input provided.")
                return

            self.ui.info(
                "Output formats\n"
                "[1] Unix, [2] Unix (ms), [3] Windows, [4] Apple, "
                "[5] Apple HFS+, [6] MSDOS, [7] Ticks, or [8] All"
            )

            fmt_choice = self.ui.prompt(
                "Select output format",
                choices=["1", "2", "3", "4", "5", "6", "7", "8"],
                show_choices=True,
                default="8"
            ).strip()
            fmt_map = {
                "1": "unix",
                "2": "unix_ms",
                "3": "windows",
                "4": "apple",
                "5": "hfs_plus",
                "6": "ms_dos",
                "7": "ticks",
                "8": "all",
            }
            target = fmt_map.get(fmt_choice, "all")
            try:
                results = self.encode(
                    datetime_str=dt_input,
                    target_format=target
                )

                self.ui.success("ENCODING RESULTS →")
                self.ui.info(
                    f"Original Datetime".ljust(25) + " →   [bright_blue]"
                    f"{results['human_readable']}"
                )
                self.ui.info(
                    f"ISO Format".ljust(25) + " →   [bright_blue]"
                    f"{results['input_datetime']}"
                )

                for key, value in sorted(results.items()):
                    if key not in ("human_readable", "input_datetime"):
                        if isinstance(value, int):
                            self.ui.info(
                                f"{key}".ljust(25) + " →   [bright_blue]"
                                f"{value}  [{(hex(value)).upper()}]"
                            )
                        else:
                            self.ui.info(
                                f"{key}".ljust(25) + " →   [bright_blue]"
                                f"{value}"
                            )

            except (ValueError, KeyError) as err:
                self.ui.error(f"\n❌ ENCODING FAILED → {err}")


    def decode(
            self,
            timestamp: str | int |float,
            target_tz: Optional[str] = None
    ) -> dict:
        """Decode any timestamp value to human-readable datetime.

        Args:
            timestamp: Input as string, integer, float, or hex string.
            target_tz: Optional timezone name (e.g. "America/New_York") for
                local time display. Requires Python 3.9+ or
                backports.zoneinfo.

        Returns:
            Dictionary with datetime, format, confidence, endianness,
            relative time, and optionally local timezone info.

        Raises:
            ValueError: If no format can parse the input.
        """
        normalized = self._normalize_input(timestamp)
        is_hex = self._is_hex_string(normalized)

        if is_hex:
            result = self._decode_hex_with_endianness(normalized)
            if result:
                dt = result["datetime"]
                fmt = result["format"]
                endian = result["endianness"]
                raw = result["raw_value"]
                confidence = result["confidence"]

                final_dt = self._apply_timezone(dt, target_tz)
                rel = self._relative_time(dt)

                self._record_conversion(f"{fmt}_{endian}", timestamp, dt)
                self.last_endianness_used = endian

                return DecodeResult(
                    dt=dt,
                    fmt=fmt,
                    confidence=confidence,
                    endianness=endian,
                    raw_value=raw,
                    relative_time=rel,
                    target_tz=target_tz,
                    local_time=final_dt if target_tz else None
                ).to_dict()

        # Non-hex path: try all detectors
        for name, detector in self._get_detectors():
            try:
                raw_value = detector(normalized)
                if raw_value is not None:
                    dt = self._convert_raw_to_datetime(raw_value, name)
                    confidence = self._enhanced_confidence(dt, raw_value, name)

                    final_dt = self._apply_timezone(dt, target_tz)
                    rel = self._relative_time(dt)

                    self._record_conversion(name, timestamp, dt)

                    return DecodeResult(
                        dt=dt,
                        fmt=name,
                        confidence=confidence,
                        endianness="N/A",
                        raw_value=raw_value,
                        relative_time=rel,
                        target_tz=target_tz,
                        local_time=final_dt if target_tz else None
                    ).to_dict()
            except Exception:
                continue

        raise ValueError(f"Unable to parse timestamp → {timestamp}")


    def encode(
            self,
            datetime_str: str,
            target_format: str = "all"
    ) -> dict:
        """Encode a datetime string into one or all supported timestamp
        formats.

        Args:
            datetime_str: Input like "2025-12-09 16:23:45.456"
            target_format: One of "unix", "unix_ms", "windows", "apple",
                "hfs_plus", "ms_dos", "ticks", "all"

        Returns:
            Dictionary mapping format names to encoded values (with hex).
        """
        dt = self._parse_input_datetime(datetime_str)
        results = {}

        formats_map = {
            "unix": "unix_seconds",
            "unix_ms": "unix_milliseconds",
            "windows": "windows_filetime",
            "apple": "apple_cocoa",
            "hfs": "hfs_plus",
            "dos": "ms_dos",
            "ticks": "microsoft_ticks",
        }

        if target_format == "all":
            targets = list(formats_map.keys())
        else:
            targets = [target_format]

        for tgt in targets:
            key = formats_map.get(tgt, tgt)
            if key == "unix_seconds":
                results["Unix (seconds)"] = (
                    int((dt - self.UNIX_EPOCH).total_seconds())
                )
            elif key == "unix_milliseconds":
                results["Unix (ms)"] = (
                    int((dt - self.UNIX_EPOCH).total_seconds() * 1000)
                )
            elif key == "windows_filetime":
                results["Windows Filetime"] = self._dt_to_windows_filetime(dt)
            elif key == "apple_cocoa":
                results["Apple Cocoa"] = (
                    int((dt - self.APPLE_EPOCH).total_seconds())
                )
            elif key == "hfs_plus":
                results["Apple HFS+"] = self._dt_to_hfs_plus(dt)
            elif key == "ms_dos":
                results["MSDOS"] = self._dt_to_ms_dos(dt)
            elif key == "microsoft_ticks":
                results["Microsoft Ticks"] = self._dt_to_microsoft_ticks(dt)

        # Add hex representations
        for k in list(results.keys()):
            if isinstance(results[k], int):
                results[f"{k} (hex)"] = "0x" + hex(results[k])[2:].upper()

        results["input_datetime"] = dt.isoformat()
        results["human_readable"] = DecodeResult._format_human(dt, "verbose")

        return results


    def get_ambiguity_report(
            self,
            timestamp: Union[str, int, float],
            target_tz: Optional[str] = None
    ) -> dict:
        """Analyze a timestamp for all possible valid interpretations.

        Returns an AmbiguityReport showing every format that could produce
        a valid datetime, ranked by confidence score.

        Args:
            timestamp: Input value to analyze.
            target_tz: Optional timezone for local time display.

        Returns:
            Dictionary with ambiguity analysis.
        """
        normalized = self._normalize_input(timestamp)
        is_hex = self._is_hex_string(normalized)
        interpretations = []

        # Collect all candidate values (accounting for endianness)
        candidates = []
        if is_hex:
            big_val, little_val = self._parse_hex_with_endianness(normalized)
            candidates.append(("big", big_val))
            candidates.append(("little", little_val))
        else:
            try:
                candidates.append(("N/A", int(float(normalized))))
            except ValueError:
                pass

        # Test every candidate against every format
        for endian, raw_val in candidates:
            for fmt_name, validator in self._get_validators():
                try:
                    is_valid, converted_val, reason = validator(raw_val)
                    if is_valid:
                        dt = self._convert_raw_to_datetime(
                            converted_val,
                            fmt_name
                        )
                        conf = self._enhanced_confidence(
                            dt,
                            converted_val,
                            fmt_name
                        )
                        local_dt = self._apply_timezone(dt, target_tz)

                        interpretations.append({
                            "format": fmt_name,
                            "endianness": endian,
                            "raw_value": raw_val,
                            "datetime": dt.isoformat(),
                            "human_readable": DecodeResult._format_human(
                                dt,
                                "verbose"
                            ),
                            "short_format": DecodeResult._format_human(
                                dt,
                                "short"
                            ),
                            "local_time": local_dt.isoformat() if target_tz and local_dt else None,
                            "local_human_readable": (
                                DecodeResult._format_human(local_dt, "verbose")
                                if target_tz and local_dt else None
                            ),
                            "confidence": round(conf, 1),
                            "reason": reason,
                        })
                except Exception:
                    continue

        # Sort by confidence descending
        interpretations.sort(key=lambda x: x["confidence"], reverse=True)

        is_ambiguous = len(interpretations) > 1
        recommendation = None
        notes = None

        if interpretations:
            best = interpretations[0]
            recommendation = (
                f"Most likely: {best['format']} ({best['endianness']} "
                f"endian) → {best['datetime']} [{best['confidence']:.1f}% "
                f"confidence]"
            )

            if is_ambiguous:
                second = interpretations[1]
                gap = best["confidence"] - second["confidence"]
                if gap < 10:
                    notes = (
                        f"Warning: Top two interpretations are within {gap:.1f}pp "
                        f"confidence. Manual verification recommended."
                    )
                elif gap < 25:
                    notes = (
                        f"Moderate confidence gap ({gap:.1f}pp). "
                        f"Primary interpretation likely correct but verify if critical."
                    )
                else:
                    notes = (
                        f"Clear winner with {gap:.1f}pp confidence gap. "
                        f"Primary interpretation is very likely correct."
                    )

        return AmbiguityReport(
            interpretations=interpretations,
            is_ambiguous=is_ambiguous,
            recommendation=recommendation,
            notes=notes
        ).to_dict()


    # --- RELATIVE TIME DISPLAY

    def _relative_time(self, dt: datetime) -> str:
        """Generate human-friendly relative time string.

        Examples: "3 minutes ago", "in 2 days", "just now", "5 years ago".
        """
        now = datetime.now(timezone.utc)
        delta = dt - now
        seconds = delta.total_seconds()

        past = seconds < 0
        abs_secs = abs(seconds)

        if abs_secs < 10:
            return "just now"
        elif abs_secs < 60:
            val = int(abs_secs)
            return f"{val} second{'s' if val != 1 else ''} {'ago' if past else 'from now'}"
        elif abs_secs < 3600:
            val = int(abs_secs / 60)
            return f"{val} minute{'s' if val != 1 else ''} {'ago' if past else 'from now'}"
        elif abs_secs < 86400:
            val = int(abs_secs / 3600)
            return f"{val} hour{'s' if val != 1 else ''} {'ago' if past else 'from now'}"
        elif abs_secs < 604800:
            val = int(abs_secs / 86400)
            return f"{val} day{'s' if val != 1 else ''} {'ago' if past else 'from now'}"
        elif abs_secs < 2629746:  # ~30.44 days (average month)
            val = int(abs_secs / 604800)
            return f"{val} week{'s' if val != 1 else ''} {'ago' if past else 'from now'}"
        elif abs_secs < 31556952:  # ~365.25 days
            val = int(abs_secs / 2629746)
            return f"{val} month{'s' if val != 1 else ''} {'ago' if past else 'from now'}"
        else:
            val = int(abs_secs / 31556952)
            return f"{val} year{'s' if val != 1 else ''} {'ago' if past else 'from now'}"


    # --- ENHANCED CONFIDENCE SCORING

    def _enhanced_confidence(
            self,
            dt: datetime,
            raw_value: float,
            format_name: str
    ) -> float:
        """Multi-factor confidence scoring algorithm.

        Factors:
            1. Recency bonus: timestamps closer to "now" score higher
                (most real-world timestamps are recent)
            2. Range centerness: values centered in the valid range score
                higher (avoids edge-case false positives)
            3. Structure validity: packed formats checked for valid component
                ranges
            4. Integer/roundness check: clean integers slightly more likely
                ntentional
            5. Penalty: dates before 1990 or after 2050 reduce confidence
            6. Bonus: dates within ±2 years of now get strong boost

        Returns:
            Float between 0 and 100.
        """
        confidence = 0.0
        now = datetime.now(timezone.utc)

        # --- Factor 1: Recency (up to 40 points) ---
        years_diff = abs((now - dt).total_seconds()) / 31556952

        if years_diff <= 0.5:
            confidence += 40  # Within 6 months
        elif years_diff <= 2:
            confidence += 35
        elif years_diff <= 5:
            confidence += 30
        elif years_diff <= 10:
            confidence += 22
        elif years_diff <= 20:
            confidence += 15
        elif years_diff <= 30:
            confidence += 8
        else:
            confidence += 2

        # --- Factor 2: Range centerness (up to 25 points) ---
        range_map = {
            "unix_seconds": self.VALID_UNIX_SECONDS_RANGE,
            "unix_milliseconds": self.VALID_UNIX_MS_RANGE,
            "unix_microseconds": self.VALID_UNIX_US_RANGE,
            "windows_filetime": self.VALID_WINDOWS_RANGE,
            "chrome": self.VALID_CHROME_RANGE,
            "apple_cocoa": self.VALID_APPLE_RANGE,
            "hfs_plus": self.VALID_HFS_PLUS_RANGE,
            "microsoft_ticks": self.VALID_TICKS_RANGE,
        }

        if format_name in range_map:
            min_v, max_v = range_map[format_name]
            range_size = max_v - min_v
            if range_size > 0:
                center = (min_v + max_v) / 2
                distance = abs(raw_value - center)
                ratio = distance / (range_size / 2)
                confidence += max(0, 25 * (1 - min(ratio, 1)))

        # --- Factor 3: Structure validity (up to 15 points) ---
        if 1 <= dt.month <= 12 and 1 <= dt.day <= 31:
            confidence += 10
            if 0 <= dt.hour <= 23 and 0 <= dt.minute <= 59:
                confidence += 5
        else:
            confidence -= 20

        # --- Factor 4: Integer/roundness (up to 5 points) ---
        if isinstance(raw_value, (int, float)):
            if raw_value == int(raw_value):
                confidence += 5
            elif raw_value == int(raw_value) * 1.0:
                confidence += 3

        # --- Factor 5: Outlier penalty ---
        if dt.year < 1990:
            confidence -= 15
        elif dt.year > 2050:
            confidence -= 15

        # --- Factor 6: Strong recency boost ---
        if years_diff <= 2:
            confidence += 15
        elif years_diff <= 5:
            confidence += 8

        return min(100.0, max(0.0, confidence))


    # --- TIMEZONE SUPPORT

    def _apply_timezone(
            self,
            dt: datetime,
            target_tz: Optional[str]
    ) -> Optional[datetime]:
        """Convert UTC datetime to target timezone.

        Returns:
            None if timezone is None or unavailable.
        """
        if not target_tz:
            return None

        if not TZ_AVAILABLE:
            return None

        try:
            tz = ZoneInfo(target_tz)
            return dt.astimezone(tz)
        except Exception:
            return None


    def list_common_timezones(self) -> list:
        """Return commonly used timezone names."""
        common = [
            "UTC",
            "America/New_York", "America/Chicago", "America/Denver",
            "America/Los_Angeles", "America/Sao_Paulo", "America/Toronto",
            "Europe/London", "Europe/Paris", "Europe/Berlin", "Europe/Madrid",
            "Europe/Moscow", "Africa/Cairo", "Africa/Johannesburg",
            "Asia/Dubai", "Asia/Kolkata", "Asia/Shanghai", "Asia/Tokyo",
            "Asia/Singapore", "Australia/Sydney", "Pacific/Auckland",
        ]
        if TZ_AVAILABLE:
            try:
                from zoneinfo import available_timezones
                all_tz = sorted(available_timezones())
                return all_tz if len(all_tz) > 50 else common
            except Exception:
                pass
        return common


    # --- HEX & ENDIANNESS HANDLING

    def _is_hex_string(self, value: str) -> bool:
        if not value:
            return False
        clean = value.lower().replace("_", "").replace("0x", "")
        return all(c in "0123456789abcdef" for c in clean) and len(clean) > 0


    def _parse_hex_with_endianness(self, value: str) -> Tuple[int, int]:
        """Return (big_endian_value, little_endian_value)."""
        clean = value.lower().replace("_", "").replace("0x", "")
        if len(clean) % 2 != 0:
            clean = "0" + clean

        big_endian_value = int(clean, 16)

        byte_array = bytearray.fromhex(clean)
        reversed_bytes = byte_array[::-1]
        little_endian_value = int.from_bytes(reversed_bytes, byteorder="little")

        return big_endian_value, little_endian_value


    def _decode_hex_with_endianness(self, hex_value: str) -> Optional[dict]:
        """Try hex value in both endianness, return best match."""
        big_val, little_val = self._parse_hex_with_endianness(hex_value)
        candidates = [("big", big_val), ("little", little_val)]
        results = []

        for endian, raw_val in candidates:
            for fmt_name, validator in self._get_validators():
                try:
                    is_valid, converted_val, reason = validator(raw_val)
                    if is_valid:
                        dt = self._convert_raw_to_datetime(
                            converted_val,
                            fmt_name
                        )
                        conf = self._enhanced_confidence(
                            dt,
                            converted_val,
                            fmt_name
                        )
                        results.append({
                            "endianness": endian,
                            "format": fmt_name,
                            "raw_value": raw_val,
                            "datetime": dt,
                            "confidence": conf,
                            "reason": reason,
                        })
                except Exception:
                    continue

        results.sort(key=lambda x: x["confidence"], reverse=True)

        if results:
            best = results[0]
            return best

        return None


    # --- VALIDATORS (return: is_valid, converted_value, reason)

    def _get_validators(self):
        return [
            ("unix_seconds", self._validate_unix_seconds),
            ("unix_milliseconds", self._validate_unix_ms),
            ("unix_microseconds", self._validate_unix_us),
            ("windows_filetime", self._validate_windows),
            ("chrome", self._validate_chrome),
            ("apple_cocoa", self._validate_apple),
            ("hfs_plus", self._validate_hfs_plus),
            ("ms_dos", self._validate_ms_dos),
            ("microsoft_ticks", self._validate_ticks),
        ]


    def _validate_unix_seconds(self, v: int) -> Tuple[bool, float, str]:
        lo, hi = self.VALID_UNIX_SECONDS_RANGE
        ok = lo <= v <= hi
        return ok, float(v), f"Range [{lo}, {hi}]" if ok else "Out of range"


    def _validate_unix_ms(self, v: int) -> Tuple[bool, float, str]:
        lo, hi = self.VALID_UNIX_MS_RANGE
        if lo <= v <= hi:
            return True, v / 1000, "Valid Unix milliseconds"
        lo2, hi2 = self.VALID_UNIX_US_RANGE
        if lo2 <= v <= hi2:
            return True, v / 1_000_000, "Valid Unix microseconds"
        return False, 0, "Not valid ms/us range"


    def _validate_unix_us(self, v: int) -> Tuple[bool, float, str]:
        lo, hi = self.VALID_UNIX_US_RANGE
        ok = lo <= v <= hi
        return ok, v / 1_000_000, f"Range [{lo}, {hi}]" if ok else "Out of range"


    def _validate_windows(self, v: int) -> Tuple[bool, float, str]:
        lo, hi = self.VALID_WINDOWS_RANGE
        ok = lo <= v <= hi
        seconds = v / self.HUNDRED_NANOSECONDS_PER_SECOND
        return ok, seconds, f"FILETIME → {seconds:.0f}s from 1601" if ok else "Out of range"


    def _validate_chrome(self, v: int) -> Tuple[bool, float, str]:
        return self._validate_windows(v)


    def _validate_apple(self, v: float) -> Tuple[bool, float, str]:
        lo, hi = self.VALID_APPLE_RANGE
        ok = lo <= v <= hi
        return ok, float(v), f"Range [{lo}, {hi}]" if ok else "Out of range"


    def _validate_hfs_plus(self, v: int) -> Tuple[bool, float, str]:
        lo, hi = self.VALID_HFS_PLUS_RANGE
        ok = lo <= v <= hi
        return ok, float(v), f"Range [{lo}, {hi}]" if ok else "Out of range"


    def _validate_ms_dos(self, v: int) -> Tuple[bool, dict, str]:
        if 0 < v <= 0xFFFFFFFF:
            try:
                date_part = (v >> 16) & 0xFFFF
                time_part = v & 0xFFFF
                year = ((date_part >> 9) & 0x7F) + 1980
                month = (date_part >> 5) & 0x0F
                day = date_part & 0x1F
                if 1980 <= year <= 2107 and 1 <= month <= 12 and 1 <= day <= 31:
                    return (
                        True,
                        {"date": date_part, "time": time_part},
                        f"DOS date {year}-{month:02d}-{day:02d}"
                    )
            except Exception:
                pass
        return False, {}, "Not valid DOS format"


    def _validate_ticks(self, v: int) -> Tuple[bool, float, str]:
        lo, hi = self.VALID_TICKS_RANGE
        ok = lo <= v <= hi
        seconds_from_year1 = v / self.TICKS_PER_SECOND
        return ok, seconds_from_year1, f"Ticks → {seconds_from_year1:.0f}s from year 1" if ok else "Out of range"


    # --- DETECTORS (for non-hex path; return raw_value or None)

    def _get_detectors(self):
        return [
            ("iso_format", self._detect_iso),
            ("date_string", self._detect_date_string),
            ("unix_seconds", self._detect_unix_seconds),
            ("unix_milliseconds", self._detect_unix_ms),
            ("windows_filetime", self._detect_windows),
            ("chrome", self._detect_chrome),
            ("apple_cocoa", self._detect_apple),
            ("hfs_plus", self._detect_hfs_plus),
            ("ms_dos", self._detect_ms_dos),
            ("microsoft_ticks", self._detect_ticks),
        ]


    def _detect_iso(self, value: str) -> Optional[datetime]:
        patterns = [r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", r"^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}"]
        for p in patterns:
            if re.match(p, value):
                try:
                    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
                    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
                except:
                    pass
        return None


    def _detect_date_string(self, value: str) -> Optional[datetime]:
        formats = [
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%d/%m/%Y %H:%M:%S",
            "%m/%d/%Y %H:%M:%S",
            "%Y%m%d%H%M%S",
            "%b %d %Y %H:%M:%S",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(value, fmt)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None


    def _detect_unix_seconds(self, value: str) -> Optional[float]:
        if self._is_hex_string(value):
            return None
        try:
            v = int(float(value))
            if self.VALID_UNIX_SECONDS_RANGE[0] <= v <= self.VALID_UNIX_SECONDS_RANGE[1]:
                return float(v)
        except:
            pass
        return None


    def _detect_unix_ms(self, value: str) -> Optional[float]:
        if self._is_hex_string(value):
            return None
        try:
            v = int(float(value))
            if self.VALID_UNIX_MS_RANGE[0] <= v <= self.VALID_UNIX_MS_RANGE[1]:
                return v / 1000
            if self.VALID_UNIX_US_RANGE[0] <= v <= self.VALID_UNIX_US_RANGE[1]:
                return v / 1_000_000
        except:
            pass
        return None


    def _detect_windows(self, value: str) -> Optional[float]:
        if self._is_hex_string(value):
            return None
        try:
            v = int(float(value))
            if self.VALID_WINDOWS_RANGE[0] <= v <= self.VALID_WINDOWS_RANGE[1]:
                return v / self.HUNDRED_NANOSECONDS_PER_SECOND
        except:
            pass
        return None


    def _detect_chrome(self, value: str) -> Optional[float]:
        return self._detect_windows(value)


    def _detect_apple(self, value: str) -> Optional[float]:
        if self._is_hex_string(value):
            return None
        try:
            v = float(value)
            if self.VALID_APPLE_RANGE[0] <= v <= self.VALID_APPLE_RANGE[1]:
                return v
        except:
            pass
        return None


    def _detect_hfs_plus(self, value: str) -> Optional[float]:
        if self._is_hex_string(value):
            return None
        try:
            v = int(float(value))
            if self.VALID_HFS_PLUS_RANGE[0] <= v <= self.VALID_HFS_PLUS_RANGE[1]:
                return float(v)
        except:
            pass
        return None


    def _detect_ms_dos(self, value: str) -> Optional[dict]:
        if self._is_hex_string(value):
            return None
        try:
            v = int(float(value))
            ok, dos_dict, _ = self._validate_ms_dos(v)
            if ok:
                return dos_dict
        except:
            pass
        return None


    def _detect_ticks(self, value: str) -> Optional[float]:
        if self._is_hex_string(value):
            return None
        try:
            v = int(float(value))
            if self.VALID_TICKS_RANGE[0] <= v <= self.VALID_TICKS_RANGE[1]:
                return v / self.TICKS_PER_SECOND
        except:
            pass
        return None


    # --- RAW VALUE → DATETIME CONVERSION

    def _convert_raw_to_datetime(
            self,
            raw_value,
            format_name: str
    ) -> datetime:
        if format_name in (
            "unix_seconds",
            "unix_milliseconds",
            "unix_microseconds"
        ):
            return datetime.fromtimestamp(raw_value, tz=timezone.utc)
        elif format_name == "apple_cocoa":
            return self.APPLE_EPOCH + timedelta(seconds=raw_value)
        elif format_name == "hfs_plus":
            return self.HFS_PLUS_EPOCH + timedelta(seconds=raw_value)
        elif format_name in ("windows_filetime", "chrome"):
            return self.WINDOWS_EPOCH + timedelta(seconds=raw_value)
        elif format_name == "microsoft_ticks":
            return self.NET_EPOCH + timedelta(microseconds=raw_value * 10)
        elif format_name == "ms_dos":
            if isinstance(raw_value, dict):
                dp = raw_value.get("date", 0)
                tp = raw_value.get("time", 0)
                year = ((dp >> 9) & 0x7F) + 1980
                month = (dp >> 5) & 0x0F
                day = dp & 0x1F
                hour = (tp >> 11) & 0x1F
                minute = (tp >> 5) & 0x3F
                second = (tp & 0x1F) * 2
                return datetime(
                    year,
                    month,
                    day,
                    hour,
                    minute,
                    second,
                    tzinfo=timezone.utc,
                )

        # Fallback: if it's already a datetime
        if isinstance(raw_value, datetime):
            return (
                raw_value.replace(tzinfo=timezone.utc)
                if raw_value.tzinfo is None
                else raw_value
            )

        return datetime.fromtimestamp(raw_value, tz=timezone.utc)


    # --- ENCODING HELPERS

    def _parse_input_datetime(self, datetime_str: str) -> datetime:
        formats = [
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d",
            "%d/%m/%Y %H:%M:%S",
            "%m/%d/%Y %H:%M:%S",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(datetime_str, fmt)
                return (
                    dt.replace(tzinfo=timezone.utc)
                    if dt.tzinfo is None
                    else dt
                )
            except ValueError:
                continue
        raise ValueError(f"Cannot parse datetime: {datetime_str}")


    def _dt_to_windows_filetime(self, dt: datetime) -> int:
        return (
            int(
                (dt - self.WINDOWS_EPOCH).total_seconds() *
                self.HUNDRED_NANOSECONDS_PER_SECOND
            )
        )


    def _dt_to_hfs_plus(self, dt: datetime) -> int:
        return int((dt - self.HFS_PLUS_EPOCH).total_seconds())


    def _dt_to_ms_dos(self, dt: datetime) -> int:
        if dt.year < 1980 or dt.year > 2107:
            raise ValueError(f"Year {dt.year} outside DOS range (1980-2107)")
        date_part = ((dt.year - 1980) << 9) | (dt.month << 5) | dt.day
        time_part = (dt.hour << 11) | (dt.minute << 5) | (dt.second // 2)
        return (date_part << 16) | time_part


    def _dt_to_microsoft_ticks(self, dt: datetime) -> int:
        return (
            int(
                (dt - self.NET_EPOCH).total_seconds() *
                self.TICKS_PER_SECOND
            )
        )


    # --- UTILITY METHODS

    def _normalize_input(self, timestamp: str | int | float) -> str:
        if isinstance(timestamp, (int, float)):
            return str(int(timestamp))
        elif isinstance(timestamp, str):
            return timestamp.strip()
        else:
            raise TypeError(f"Unsupported type: {type(timestamp)}")


    def _record_conversion(
            self,
            method: str,
            original: str | int | float,
            result: datetime
    ):
        self.conversion_history.append({
            "method": method,
            "original": str(original)[:50],
            "result": result.isoformat()
        })
        if len(self.conversion_history) > 100:
            self.conversion_history = self.conversion_history[-100:]


    def get_conversion_history(self) -> list:
        return self.conversion_history[-10:]


    def format_human_readable(self, dt: datetime, style: str = "iso") -> str:
        return DecodeResult._format_human(dt, style)


# --- INTERACTIVE CLI

def display_menu():
    print("\n" + "=" * 72)
    print("🕐  UNIVERSAL TIMESTAMP CONVERTER v3.0  🕐")
    print("   Decode · Encode · Ambiguity · Timezones · Relative Time   ")
    print("=" * 72)
    print("""
    [1] DECODE          - Convert timestamp → human-readable datetime
    [2] ENCODE          - Convert datetime string → timestamp format(s)
    [3] AMBIGUITY CHECK - Analyze all possible interpretations
    [4] BATCH PROCESS   - Convert multiple timestamps at once
    [5] FORMAT INFO     - Learn about supported timestamp formats
    [6] TEST SUITE      - Run built-in test cases
    [7] EXIT
    """)
    print("=" * 72)


def _prompt_timezone() -> Optional[str]:
    """Ask user if they want timezone conversion."""
    print(
        "\n🌍 Optional: Enter a timezone for local display (or press "
        "Enter to skip)"
    )
    print("Examples: America/New_York, Europe/London, Asia/Tokyo, UTC")
    tz_input = input("Timezone: ").strip()
    if not tz_input:
        return None
    return tz_input


def run_interactive_session():
    converter = TimestampConverter()

    while True:
        display_menu()

        try:
            choice = input("Enter your choice [1-7]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("Goodbye!")
            break

        if choice == "1":  # DECODE
            print("\n🔍 TIMESTAMP DECODER")
            print(
                "Enter a timestamp (integer, hex with 0x, or datetime "
                "string)"
            )
            print("Examples:")
            print("  1692384756              (Unix seconds)")
            print("  0x01D3F6C8C5A4B8000     (Hex Windows FILETIME)")
            print("  133365212760000000      (Windows FILETIME)")
            print("  2023-08-18 15:45:56.123 (Datetime string)\n")

            ts_input = input("Enter timestamp: ").strip()
            if not ts_input:
                print("⚠️ No input provided.")
                continue

            target_tz = _prompt_timezone()

            try:
                result = converter.decode(ts_input, target_tz=target_tz)

                print("✅ DECODE SUCCESSFUL")
                print(f"Format Detected    : {result['format']}")
                if result.get("endianness") and result["endianness"] != "N/A":
                    print(
                        f"Endianness         : "
                        f"{result['endianness'].title()}"
                    )

                conf = result.get("confidence", 0)
                if conf >= 75:
                    conf_label = "🟢 High"
                elif conf >= 50:
                    conf_label = "🟡 Medium"
                else:
                    conf_label = "🔴 Low"
                print(f"Confidence         : {conf:.1f}% ({conf_label})")

                print(f"Datetime (UTC)     : {result['iso_format']}")
                print(f"Human Readable     : {result['human_readable']}")
                print(f"Relative Time      : {result['relative_time']}")
                if result.get("raw_value"):
                    print(f"Raw Value Used     : {result['raw_value']}")

                if result.get("local_time"):
                    print(
                        f"Local Time ({result['target_timezone']})   : "
                        f"{result['local_human_readable']}"
                    )

            except ValueError as err:
                print(f"\n❌ DECODE FAILED: {err}")

        elif choice == "2":  # ENCODE
            print("\n🔧 TIMESTAMP ENCODER")
            print("Enter a datetime in format: YYYY-MM-DD HH:MM:SS[.fff]")
            print("Example: 2025-12-09 16:23:45.456\n")

            dt_input = input("Enter datetime: ").strip()
            if not dt_input:
                print("⚠️ No input provided.")
                continue

            print("\nOutput formats:")
            print("  [1] unix       [5] hfs_plus")
            print("  [2] unix_ms    [6] ms_dos")
            print("  [3] windows    [7] ticks")
            print("  [4] apple      [8] all")

            fmt_choice = input("\nSelect format [1-8]: ").strip()
            fmt_map = {
                "1": "unix",
                "2": "unix_ms",
                "3": "windows",
                "4": "apple",
                "5": "hfs_plus",
                "6": "ms_dos",
                "7": "ticks",
                "8": "all",
            }
            target = fmt_map.get(fmt_choice, "all")

            try:
                results = converter.encode(dt_input, target)

                print("✅ ENCODING RESULTS")
                print(f"Original Datetime : {results['human_readable']}")
                print(f"ISO Format        : {results['input_datetime']}\n")

                for key, value in sorted(results.items()):
                    if key not in ("human_readable", "input_datetime"):
                        if isinstance(value, int):
                            print(f"  {key:25s}: {value:>25,}  ({hex(value)})")
                        else:
                            print(f"  {key:25s}: {value}")

            except (ValueError, KeyError) as err:
                print(f"\n❌ ENCODING FAILED: {err}")

        elif choice == "3":  # AMBIGUITY CHECK
            print("\n🔬 AMBIGUITY ANALYZER")
            print(
                "Checks all possible format interpretations and ranks "
                "by confidence."
            )

            ts_input = input("Enter timestamp: ").strip()
            if not ts_input:
                print("⚠️ No input provided.")
                continue

            target_tz = _prompt_timezone()

            report = converter.get_ambiguity_report(
                ts_input,
                target_tz=target_tz
            )

            if report["ambiguous"]:
                print(
                    f"⚠️ AMBIGUOUS — {report['interpretation_count']} "
                    f"valid interpretation(s) found"
                )
            else:
                print(
                    f"✅ UNAMBIGUOUS — {report['interpretation_count']} "
                    "valid interpretation found"
                )

            if report.get("recommendation"):
                print(f"\n📌 {report['recommendation']}")

            if report.get("notes"):
                print(f"\n📝 {report['notes']}")

            print("\n" + "-" * 72)
            print(
                f"{'#':<4} {'FORMAT':<22} {'ENDIAN':<8} "
                f"{'CONFIDENCE':<12} {'DATETIME (UTC)':<28}"
            )

            for i, interp in enumerate(report["interpretations"], 1):
                endian = interp.get("endianness", "N/A")
                print(
                    f"{i:<4} {interp['format']:<22} {endian:<8} "
                    f"{interp['confidence']:>5.1f}%       "
                    f"{interp['short_format']}"
                )

                if interp.get("local_human_readable"):
                    print(
                        f"Local ({target_tz}) → "
                        f"{interp['local_human_readable']}"
                    )

        elif choice == "4":  # BATCH
            print("\n📦 BATCH PROCESSOR")
            print(
                "Enter timestamps, one per line. Press Enter twice when done."
            )

            batch = []
            while True:
                line = input("> ").strip()
                if not line and batch:
                    break
                if line:
                    batch.append(line)

            if not batch:
                print("⚠️ No inputs provided.")
                continue

            target_tz = _prompt_timezone()

            hdr = (
                f"{'INPUT':<30} {'FORMAT':<20} {'CONF':<8} "
                f"{'DATETIME (UTC)':<28}"
            )
            if target_tz:
                hdr += f" {'LOCAL TIME':<30}"
            print(hdr)

            for inp in batch:
                try:
                    result = converter.decode(inp, target_tz=target_tz)
                    row = (
                        f"{inp:<30} {result['format']:<20} "
                        f"{result['confidence']:>5.1f}%  "
                        f"{result['short_format']}"
                    )
                    if target_tz and result.get("local_human_readable"):
                        local_short = (
                            result.get("local_time", "")[:19]
                            if result.get("local_time")
                            else ""
                        )
                        row += f"  {local_short}"
                    print(row)
                except ValueError as err:
                    print(
                        f"{inp:<30} {'ERROR':<20} {'N/A':<8} {str(err)[:40]}"
                    )

        elif choice == "5":  # FORMAT INFO
            _display_format_info()
            input("\nPress Enter to continue...")

        elif choice == "6":  # TEST SUITE
            _run_test_suite(converter)

        elif choice == "7":  # EXIT
            print(
                "\n👋 Goodbye! Thanks for using the Universal Timestamp "
                "Converter!"
            )
            break

        else:
            print(f"\n⚠️ Invalid choice '{choice}'. Please enter 1-7.")


def _display_format_info():
    print("📋 SUPPORTED TIMESTAMP FORMATS")

    formats = {
        "UNIX Epoch (Seconds)": {
            "epoch": "January 1, 1970 00:00:00 UTC",
            "units": "Seconds",
            "typical_digits": "10 digits",
            "used_by": "Linux/Unix, JavaScript, most APIs",
        },
        "UNIX Milliseconds": {
            "epoch": "January 1, 1970 00:00:00 UTC",
            "units": "Milliseconds",
            "typical_digits": "13 digits",
            "used_by": "JavaScript Date, modern APIs",
        },
        "UNIX Microseconds": {
            "epoch": "January 1, 1970 00:00:00 UTC",
            "units": "Microseconds",
            "typical_digits": "16-17 digits",
            "used_by": "Python datetime, high-res timestamps",
        },
        "Windows FILETIME": {
            "epoch": "January 1, 1601 00:00:00 UTC",
            "units": "100-nanosecond intervals",
            "typical_digits": "16-18 digits",
            "used_by": "Windows NT, Registry, PE headers",
        },
        "Chrome Timestamp": {
            "epoch": "January 1, 1601 00:00:00 UTC",
            "units": "100-nanosecond intervals",
            "typical_digits": "16-18 digits",
            "used_by": "Google Chrome, Chromium browsers",
        },
        "Apple Cocoa (NSTimeInterval)": {
            "epoch": "January 1, 2001 00:00:00 UTC",
            "units": "Seconds (float)",
            "typical_digits": "~10 digits",
            "used_by": "macOS, iOS, Swift, Objective-C",
        },
        "Apple HFS+": {
            "epoch": "January 1, 1904 00:00:00 UTC",
            "units": "Seconds",
            "typical_digits": "10 digits",
            "used_by": "Classic Mac OS, HFS+ filesystem",
        },
        "MS-DOS 32-bit": {
            "epoch": "1980 (practical start)",
            "units": "Packed 16-bit date + 16-bit time",
            "typical_digits": "8-10 digits",
            "used_by": "FAT filesystem, ZIP file entries, PE headers",
        },
        "Microsoft .NET Ticks": {
            "epoch": "January 1, Year 1 00:00:00 UTC",
            "units": "100-nanosecond intervals",
            "typical_digits": "18 digits",
            "used_by": ".NET Framework, C#, DateTime.Ticks",
        },
        "Hex Values": {
            "handling": "Auto-detects little-endian and big-endian",
            "note": "Both byte orders tested; best match selected by confidence",
        },
    }

    for i, (name, info) in enumerate(formats.items(), 1):
        print(f"\n{i}. {name}")
        for k, v in info.items():
            print(f"   • {k}: {v}")

    print("💡 FEATURES:")
    print("• Relative time display ('3 hours ago', 'in 2 days')")
    print("• Enhanced confidence scoring (recency, centerness, structure)")
    print("• Ambiguity report with ranked interpretations")
    print(
        "• Timezone conversion (requires Python 3.9+ or backports.zoneinfo)"
    )


def _run_test_suite(converter: TimestampConverter):
    print("🧪 RUNNING TEST SUITE")

    test_cases = [
        ("Unix seconds", "1692384756"),
        ("Unix hex", "0x62E6C354"),
        ("Unix milliseconds", "1692384756000"),
        ("Windows FILETIME", "133365212760000000"),
        ("Windows FILETIME hex BE", "0x01D9A1B428E0E7E0"),
        ("Apple Cocoa", "684183756"),
        ("Apple HFS+", "3423085476"),
        ("Microsoft Ticks", "638294499560000000"),
        ("ISO 8601", "2023-08-18T15:45:56Z"),
        ("Datetime string", "2023-08-18 15:45:56.123"),
    ]

    passed = 0
    failed = 0

    for desc, ts in test_cases:
        try:
            result = converter.decode(ts)
            print(f"\n✓ {desc}:")
            print(f"Input:      {ts}")
            print(f"Format:     {result['format']}")
            print(f"Time:       {result['short_format']}")
            print(f"Relative:   {result['relative_time']}")
            print(f"Confidence: {result['confidence']:.1f}%")
            passed += 1
        except ValueError as err:
            print(f"\n✗ {desc}: FAILED - {err}")
            failed += 1

    print(f"RESULTS: {passed}/{len(test_cases)} tests passed")

    # Ambiguity test
    print("\n🔬 Testing ambiguity analysis on '133365212760000000'...")

    report = converter.get_ambiguity_report("133365212760000000")
    print(f"Ambiguous: {report['ambiguous']}")
    print(f"Interpretations found: {report['interpretation_count']}")

    if report.get("recommendation"):
        print(f"Recommendation: {report['recommendation']}")

    # Timezone test
    print("\n🌍 Testing timezone conversion...")
    result_tz = converter.decode("1692384756", target_tz="America/New_York")

    if result_tz.get("local_time"):
        print(f"UTC:  {result_tz['short_format']}")
        print(f"NYC:  {result_tz['local_human_readable']}")
    else:
        print(
            "Timezone support not available (need Python 3.9+ or "
            "backports.zoneinfo)"
        )


# --- CONVENIENCE FUNCTIONS

def quick_decode(
        timestamp: str | int | float,
        target_tz: Optional[str] = None
) -> str:
    converter = TimestampConverter()
    result = converter.decode(timestamp, target_tz=target_tz)
    parts = [result["iso_format"]]
    parts.append(f"({result['human_readable']})")
    parts.append(f"[{result['relative_time']}]")

    if result.get("local_human_readable"):
        parts.append(f"[Local: {result['local_human_readable']}]")

    return " ".join(parts)


def quick_encode(datetime_str: str, format_name: str = "unix") -> int:
    converter = TimestampConverter()
    results = converter.encode(datetime_str, format_name)
    key_map = {
        "unix": "unix_seconds",
        "unix_ms": "unix_milliseconds",
        "windows": "windows_filetime",
        "apple": "apple_cocoa",
        "hfs": "hfs_plus",
        "dos": "ms_dos",
        "ticks": "microsoft_ticks",
    }
    key = key_map.get(format_name, "unix_seconds")
    return results.get(key, results.get("unix_seconds", 0))


if __name__ == "__main__":
    print("\n✨ Welcome to the Universal Timestamp Converter v3.0 ✨")
    print("Now with relative time, enhanced confidence,")
    print("ambiguity reports, and timezone support!\n")
    run_interactive_session()
