#!/usr/bin/env python3

import base64
import codecs
import functools
from rich.console import Console
from rich.prompt import Prompt
from rich.traceback import install
import string
from typing import Dict, Tuple

from . import install
from config.results import Results
from utils import Utils, UIHandlerProtocol, RichUIHandler, get_time


c = Console()
install()


def handle_exceptions(func):
    """Defining the error handling decorator."""
    # Preserves the original function's name and docstring
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except AttributeError as e:
            return f"{e}"
        except TypeError as e:
            return (
                f"[Error Handled] {hex_str} caused a TypeError in "
                f"'{func.__name__}' -> {e}."
            )
        except ValueError as e:
            hex_str = args[0] if args else "Unknown Input"
            return (
                f"[Error Handled] {hex_str} caused a ValueError in "
                f"{func.__name__}' -> {e}."
            )
        except UnicodeDecodeError:
            return (
                f"Error: This hex sequence ({hex_str}) contains binary data "
                "that cannot be read as text."
            )
        except Exception as e:
            return f"[Error Handled] An unexpected error occurred -> {e}"
    return wrapper


class EncodeDecode:
    __slots__ = ["ui"]

    def __init__(self, ui: UIHandlerProtocol | None = None) -> None:
        self.ui = ui or RichUIHandler(get_time=get_time)


    def run_encode_decode(self, input_type: str) -> None:

        VALID_OPTIONS = {
            "ascii": Ascii.make_ascii_data_dict(input=input),
            "base64": Base64.make_data_dict(input=input),
            "binary": Binary.make_data_dict(input=input),
            "decimal_int": DecimalInteger.make_data_dict(input=input),
            "decimal_str": DecimalString.make_data_dict(input=input),
            "hexadecimal": Hexadecimal.make_data_dict(input=input),
            "morse_code": MorseCode.make_data_dict(input=input),
            "octal": Octal.make_data_dict(input=input),
            "rotate_string": RotateString.run_rotate_string()
        }

        try:
            if input_type not in VALID_OPTIONS.keys():
                self.ui.warning(
                    f"The input type value {input_type} is not supported"
                )
                return

            input = self.ui.prompt(
                f"Enter the data you want to convert"
            )
            # results = self.make_data_dict(input=input)
            results = VALID_OPTIONS[input_type]
            Results.print_results_table(results_dict=results)
        except ValueError as err:
            c.print(f"[bright_red]Validation Error → {err}")
            c.print(
                "[dim]Tip: Try simpler characters like letters and numbers."
                )



class Ascii(EncodeDecode):

    PRINTABLE_ASCII = set(string.printable)
    CONTROL_CHARS = set(chr(i) for i in range(32) if chr(i) not in '\t\n\r')
    WHITESPACE = set(string.whitespace)

    def validate_ascii_input(self, input: str) -> Tuple[bool, str]:
        """Comprehensive input validation."""
        if not input:
            return False, "Input cannot be empty"

        if not isinstance(input, str):
            return False, "Input must be a string"

        issues = []
        for pos, char in enumerate(input):
            code = ord(char)

            if code > 127:
                issues.append(f"Position {pos} → Non-ASCII '{char}' (U+{code:04X})")
            elif char in self.CONTROL_CHARS:
                issues.append(f"Position {pos} → Control character (ord={code})")

        if issues:
            return False, "; ".join(issues[:3]) + ("..." if len(issues) > 3 else "")

        return True, ""

    def sanitize_input(self, input: str, mode: str = "strict") -> str:
        """Sanitize input based on mode.

        Args:
            mode: "strict" (raise), "replace" (swap bad chars), "remove"
                (delete bad chars)
        """
        sanitized = []

        for char in input:
            code = ord(char)

            # Valid ASCII
            if code <= 127:
                # Printable or safe whitespace
                if code >= 32 or char in '\t\n\r':
                    sanitized.append(char)
                elif mode == "remove":
                    # Skip control chars
                    continue
                elif mode == "replace":
                    # Replace control chars
                    sanitized.append('?')
                # Strict mode
                else:
                    raise ValueError(
                        f"Control character at position → ord({code})"
                    )
            # Non-ASCII characters
            else:
                if mode == "remove":
                    continue
                elif mode == "replace":
                    sanitized.append('?')
                else:
                    raise ValueError(f"Non-ASCII character → '{char}'")
        return ''.join(sanitized)

    def ascii_to_base64(self, input: str) -> str:
        """Convert the ascii input string to base64 string."""
        is_valid, error_msg = self.validate_ascii_input(input)
        if not is_valid:
            raise ValueError(error_msg)
        return base64.b64encode(input.encode("ascii", errors="ignore")).decode()

    def ascii_to_base32(self, input: str) -> str:
        """Converts an ascii string to its base32 encoded representation."""
        is_valid, error_msg = self.validate_ascii_input(input)
        if not is_valid:
            raise ValueError(error_msg)
        return base64.b32encode(
            input.encode("ascii", errors="ignore")
        ).decode("ascii")

    def ascii_to_binary(self, input: str) -> str:
        """Convert the ascii input string to binary string."""
        is_valid, error_msg = self.validate_ascii_input(input)
        if not is_valid:
            raise ValueError(error_msg)
        return " ".join(bin(ord(c))[2:].zfill(8) for c in input)

    def ascii_to_decimal(self, input: str) -> str:
        """Convert the ascii input string to decimal string."""
        is_valid, error_msg = self.validate_ascii_input(input)
        if not is_valid:
            raise ValueError(error_msg)
        return " ".join(str(ord(i)) for i in input)

    def ascii_to_hexadecimal(self, input: str) -> str:
        """Convert the ascii input string to hexadecimal string."""
        is_valid, error_msg = self.validate_ascii_input(input)
        if not is_valid:
            raise ValueError(error_msg)
        return " ".join(f"{ord(c):02X}" for c in input)

    def ascii_to_rot13(self, input: str) -> str:
        """Convert the ascii input string to rot13 string."""
        is_valid, error_msg = self.validate_ascii_input(input)
        if not is_valid:
            raise ValueError(error_msg)
        return codecs.encode(input, "rot_13")

    def make_ascii_data_dict(self, input: str) -> Dict[str, str]:
        results = {}
        results["Input Type"] = "Ascii"
        results["Input Value"] = f"{input}"
        results["Validation OK"] = True
        try:
            results["Base64"] = f"{self.ascii_to_base64(input=input)}"
            results["Base32"] = f"{self.ascii_to_base32(input=input)}"
            results["Binary"] = f"{self.ascii_to_binary(input=input)}"
            results["Decimal"] = f"{self.ascii_to_decimal(input=input)}"
            results["Hexadecimal"] = f"{self.ascii_to_hexadecimal(input=input)}"
            results["Rot13"] = f"{self.ascii_to_rot13(input=input)}"
            results["Morse code"] = (
                f"{MorseCode.encode_morse_code(input=input)}"
            )
        except ValueError as e:
            results["Validation OK"] = False
            results["error"] = str(e)
        return results

    def run_ascii_convert(self):
        input = Prompt.ask(
            f"[white][-] Enter the data you want to convert"
        )
        try:
            results = self.make_data_dict(input=input)
            Results.print_results_table(results_dict=results)
        except ValueError as err:
            c.print(f"[bright_red]Validation Error → {err}")
            c.print(
                "[dim]Tip: Try simpler characters like letters and numbers."
                )


class Base64(EncodeDecode):

    def base64_to_ascii(self, input: str) -> str:
        """Convert base64 string to ascii string."""
        return base64.b64decode(input).decode()

    def base64_to_base32(self, input: str) -> str:
        """Convert a base64 string to a base32 string."""
        raw_bytes = base64.b64decode(input)
        return base64.b32encode(raw_bytes).decode("ascii")

    def base64_to_binary(self, input: str) -> str:
        """Convert base64 string to binary string."""
        return " ".join(
            format(ord(c), "b").zfill(8) for c in base64.b64decode(
                input).decode()
        )

    def base64_to_decimal(self, input: str) -> str:
        """Convert base64 string to decimal string."""
        d = [ord(c) for c in base64.b64decode(input).decode()]
        return " ".join(str(x) for x in d)

    def base64_to_hexadecimal(self, input: str) -> str:
        """Convert base64 string to hexadecimal string."""
        decoded_bytes = base64.b64decode(input)
        return " ".join(f"{n:02x}" for n in decoded_bytes).upper()

    def make_data_dict(self, input: str) -> None:
        results = {}
        results["Input Type"] = "Base64"
        results["Input Value"] = f"{input}"
        results["ascii"] = f"{self.base64_to_ascii(input=input)}"
        results["base32"] = f"{self.base64_to_base32(input=input)}"
        results["binary"] = f"{self.base64_to_binary(input=input)}"
        results["decimal"] = f"{self.base64_to_decimal(input=input)}"
        results["hexadecimal"] = f"{self.base64_to_hexadecimal(input=input)}"
        results["morse code"] = (
            f"{MorseCode.encode_morse_code(self, input=input)}"
        )
        return results

    def run_base64_convert(self):
        input = Prompt.ask(
            f"[white][-] Enter the data you want to convert"
        )
        try:
            results = self.make_data_dict(input=input)
            Results.print_results_table(results_dict=results)
        except ValueError as err:
            c.print(f"[bright_red]Validation Error → {err}")
            c.print("[dim]Tip: Try simpler characters like letters and numbers.")


class Binary(EncodeDecode):
    """Utility class for binary conversions."""

    def _validate(self, input: str) -> str:
        """Validates that the input is a non-empty binary string.

        Returns the cleaned string.
        """
        if not isinstance(input, str):
            raise TypeError("Input must be a string.")

        # Check for empty input value
        if not input:
            raise ValueError("Input can not be empty.")

        # Check to make sure the input consists of only 0 or 1
        if any (c not in "01" for c in input):
            raise ValueError("Binary input must be only 0 or 1.")

        clean_binary = input.replace(" ", "")

        if len(clean_binary) % 8 != 0:
            raise ValueError(
                f"Invalid binary length ({len(clean_binary)} bits). The "
                "total number of bits must be evenly divisible by 8."
            )
        return clean_binary

    def binary_to_ascii(self, input: str) -> str:
        """Converts binary string to ascii representation."""
        validated_input = self.validate(input=input)
        list = []
        for i in range(0, len(validated_input), 8):
            list.append(validated_input[i : i + 8])
        return "".join([chr(int(i, 2)) for i in list])

    def binary_to_base64(self, input: str) -> str:
        """Converts a binary string to base64 string."""
        binary_string = self._validate(input=input)

        # Pad binary string so length is multiple of 8
        padding_length = (8 - len(binary_string) % 8) % 8
        binary_string += "0" * padding_length

        # Convert binary string to bytes
        byte_array = bytearray()

        for i in range(0, len(binary_string), 8):
            byte = binary_string[i : i + 8]
            byte_array.append(int(byte, 2))

        # Encode to base64
        return base64.b64encode(byte_array).decode("utf-8")

    def binary_to_base32(self, input: str) -> str:
        """Converts a binary string to base32 string."""
        binary_string = self._validate(input=input)
        # Ensure the binary string is a multiple of 8 bits by padding
        # with leading zeros
        # remainder = len(binary_string) % 8

        # if remainder != 0:
        #     binary_string = (
        #         binary_string.zfill(len(binary_string) + (8 - remainder))
        #     )

        # byte_list = []
        # for i in range(0, len(binary_string), 8):
        #     byte_chunk = binary_string[i : i + 8]
        #     byte_list.append(int(byte_chunk, 2))

        # raw_bytes = bytes(byte_list)
        # return base64.b32encode(raw_bytes).decode("ascii")


        # Pad binary string so length is multiple of 8
        padding_length = (8 - len(binary_string) % 8) % 8
        binary_string += "0" * padding_length

        # Convert binary string to bytes
        byte_array = bytearray()

        for i in range(0, len(binary_string), 8):
            byte = binary_string[i : i + 8]
            byte_array.append(int(byte, 2))

        # Encode to Base32
        return base64.b32encode(byte_array).decode("ascii")

    def binary_to_decimal_int(self, input: str) -> int:
        """Converts a binary string to a decimal integer."""
        binary_string = self._validate(input=input)
        binary_string = binary_string.replace(" ", "")
        return f"{int(binary_string, 2):,}"

    def binary_to_decimal_char(self, input: str) -> str:
        """Converts each 8-bit byte chunk into its individual decimal
        value and returns them as a single space-seperated string.
        """
        binary_string = self._validate(input=input)
        clean_binary = binary_string.replace(" ", "")
        binary_bytes = [
            clean_binary[i : i + 8]
            for i in range(0, len(clean_binary), 8)
        ]
        return " ".join([str(int(b, 2)) for b in binary_bytes])

    def binary_to_hexadecimal(self, input: str) -> str:
        """Converts a binary string to a hexadecimal string."""
        binary_string = self._validate(input=input)
        decimal_value = int(binary_string, 2)
        hex_string = f"{decimal_value:X}"
        if len(hex_string) % 2 !=0:
            hex_string = "0" + hex_string
        return " ".join(
            hex_string[i : i + 2] for i in range(0, len(hex_string), 2)
        )

    def binary_to_octal(self, input: str) -> str:
        """Converts a binary string to a octal string."""
        binary_string = self._validate(input=input)
        return oct(int(binary_string, 2))[2:]

    def make_data_dict(self, input: str) -> dict:
        results = {}
        results["Input Type"] = "Binary"
        results["Input Value"] = f"{input}"
        results["ascii"] = f"{self.binary_to_ascii(input=input)}"
        results["base64"] = f"{self.binary_to_base64(input=input)}"
        results["base32"] = f"{self.binary_to_base32(input=input)}"
        results["decimal (int)"] = f"{self.binary_to_decimal_int(input=input)}"
        results["decimal (char)"] = (
            f"{self.binary_to_decimal_char(input=input)}"
        )
        results["hexadecimal"] = f"{self.binary_to_hexadecimal(input=input)}"
        results["octal"] = f"{self.binary_to_octal(input=input)}"
        return results

    def run_binary_convert(self):
        input = Prompt.ask(
            f"[white][-] Enter the data you want to convert"
        )
        try:
            results = self.make_data_dict(input=input)
            Results.print_results_table(self, results_dict=results)
        except ValueError as err:
            c.print(f"[bright_red]Validation Error → {err}")
            c.print(
                "[dim]Tip: Try simpler characters like letters and numbers."
            )


class DecimalInteger(EncodeDecode):

    def format_input(self, input: str):
        if "," in input:
            input = input.replace(",", "")
        return int(input)

    def decimal_to_binary(self, input: str) -> str:
        """Convert the decimal number to binary number."""
        return "{0:b}".format(input)

    def decimal_to_hexadecimal(self, input: str) -> str:
        """Convert the decimal number to hexadecimal number."""
        hex_str = hex(input)[2:]
        if len(hex_str) % 2 != 0:
            hex_str = "0" + hex_str
        pairs = [hex_str[i : i + 2] for i in range(0, len(hex_str), 2)]
        return "0x " + " ".join(pairs).upper()

    def decimal_to_octal(self, input: str) -> str:
        """Convert the decimal number to octal number."""
        return oct(input)

    def make_data_dict(self, input: str) -> None:
        results = {}
        results["Input Type"] = "Decimal (integer)"
        results["Input Value"] = f"{input}"
        results["binary"] = f"{self.decimal_to_binary(input=input)}"
        results["hexadecimal"] = f"{self.decimal_to_hexadecimal(input=input)}"
        results["octal"] = f"{self.decimal_to_octal(input=input)}"
        return results

    def run_decimal_int_convert(self) -> None:
        input = Prompt.ask(
            f"[white][-] Enter the data you want to convert"
        )
        try:
            results = self.make_data_dict(input=input)
            Results.print_results_table(self, results_dict=results)
        except ValueError as err:
            c.print(f"[bright_red]Validation Error → {err}")
            c.print(
                "[dim]Tip: Try simpler characters like letters and numbers."
            )


class DecimalString(EncodeDecode):

    def decimal_to_ascii(self, input: str) -> str:
        try:
            return "".join(chr(int(c)) for c in input.split())
        except ValueError:
            c.print(
                "[red1][!] Error -> Please ensure the input only contains "
                "numbers separated by spaces."
            )
        except OverflowError:
            c.print(
                "[red1][!] Error -> One of the numbers is too large to be a "
                "valid ascii character."
            )

    def decimal_to_base64(self, input: str) -> str:
        byte_data = bytes(int(c) for c in input.split())
        return base64.b64encode(byte_data).decode("utf-8")

    def make_data_dict(self, input: str) -> None:
        results = {}
        results["Input Type"] = "Decimal (String)"
        results["Input Value"] = f"{input}"
        results["ascii"] = f"{self.decimal_to_ascii(input=input)}"
        results["base64"] = f"{self.decimal_to_base64(input=input)}"
        return results

    def run_decimal_str_convert(self) -> None:
        input = Prompt.ask(
            f"[white][-] Enter the data you want to convert"
        )
        try:
            results = self.make_data_dict(input=input)
            Results.print_results_table(self, results_dict=results)
        except ValueError as err:
            c.print(f"[bright_red]Validation Error → {err}")
            c.print(
                "[dim]Tip: Try simpler characters like letters and numbers."
            )


class Hexadecimal(EncodeDecode):

    def clean_hex_input(self, input: str) -> str:
        hex_str = input.strip().lower()
        hex_str = hex_str.replace(" ", "")
        if hex_str.startswith("0x"):
            hex_str = hex_str[2:]
        return hex_str

    @handle_exceptions
    def hex_to_ascii(self, input: str) -> str:
        """Converts a hexadecimal string to its representation in ascii
        characters.
        """
        return bytes.fromhex(
            self.clean_hex_input(input)).decode("utf-8")

    @handle_exceptions
    def hex_to_base64(self, input: str) -> str:
        """Converts a hexadecimal string to its base64 representation."""
        hex_str = self.clean_hex_input(input)
        raw_bytes = bytes.fromhex(hex_str)
        return base64.b64encode(raw_bytes).decode("utf-8")

    @handle_exceptions
    def hex_to_binary(self, input: str) -> str:
        """Converts a hexadecimal string to its binary representation."""
        hex_str = self.clean_hex_input(self.input_string)
        return " ".join(f"{b:08b}" for b in bytes.fromhex(hex_str))

    @handle_exceptions
    def hex_to_decimal(self, input: str) -> str:
        """Converts a hex string to signed and unsigned representations.

        Args:
            hex_str (str): Hex string (e.g. 'FFFF', '0xFF').

        Returns:
            dict: Contains 'signed' and 'unsigned' representations.
        """
        hex_str = self.clean_hex_input(input)

        unsigned_value = int(hex_str, 16)
        bit_length = len(hex_str) * 4
        signed_value = unsigned_value

        if unsigned_value >= 2 ** (bit_length - 1):
            signed_value -= 2 ** bit_length

        decimal_results = {
            "Decimal (signed)": f"{signed_value:,}",
            "Decimal (unsigned)": f"{unsigned_value:,}"
        }

        return decimal_results

    @handle_exceptions
    def hex_to_morse_code(self, input: str) -> str:
        hex_str = self.clean_hex_input(input)
        return MorseCode.encode_morse_code(self, input=hex_str)

    @handle_exceptions
    def make_data_dict(self, input: str) -> dict:
        results = {}
        results["Input Type"] = "Hexadecimal"
        results["Input Value"] = f"{input}"
        results["ascii"] = f"{self.hex_to_ascii(input=input)}"
        results["base64"] = f"{self.hex_to_base64(input=input)}"
        results["binary"] = f"{self.hex_to_binary(input=input)}"

        for key, value in self.hex_to_decimal(input).items():
            results[f"{key}"] = f"{value}"

        return results

    @handle_exceptions
    def run_hex_convert(self) -> None:
        input = Prompt.ask(
            f"[white][-] Enter the data you want to convert"
        )
        try:
            results = self.make_data_dict(input=input)
            Results.print_results_table(self, results_dict=results)
        except ValueError as err:
            c.print(f"[bright_red]Validation Error → {err}")
            c.print(
                "[dim]Tip: Try simpler characters like letters and numbers."
            )


class MorseCode(EncodeDecode):
    """Python program to implement Morse Code Translator

        VARIABLE KEY
        "cipher"    → "stores the morse translated form of the english string"
        "decipher"   → "stores the english translated form of the morse string"
        "ciphertext" → "stores morse code of a single character"
        "i"          → "keeps count of the spaces between morse characters"
        "message"    → "stores the string to be encoded or decoded"
    """

    # Dictionary representing the morse code chart
    MORSE_CODE_DICT = {
        # Letters
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
        'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
        'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
        'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
        'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
        'Z': '--..',

        # Numbers
        '0': '-----', '1': '.----', '2': '..---', '3': '...--',
        '4': '....-', '5': '.....', '6': '-....', '7': '--...',
        '8': '---..', '9': '----.',

        # Punctuation - INCLUDING COMMA!
        ',': '--..--',
        '.': '.-.-.-',
        '?': '..--..',
        "'": '.----.',
        '!': '-.-.--',
        '/': '-..-.',
        '(': '-.--.',
        ')': '-.--.-',
        '&': '.-...',
        ':': '---...',
        ';': '-.-.-.',
        '=': '-...-',
        '+': '.-.-.',
        '-': '-....-',
        '_': '..--.-',
        '"': '.-..-.',
        '$': '...-..-',
        '@': '.--.-.',

        # Whitespace
        ' ': '/'
    }

    def is_valid_morse(self, input: str) -> str:
        """Validates that the input contains valid morse code characters."""
        if not input or input.isspace():
            return False
        allowed_characters = {".", "-", " "}
        if set(input).issubset(allowed_characters):
            return True
        else:
            return False

    def encode_morse_code(self, input: str) -> str:
        """Conversion from Morse Code value to ascii

        Args:
            str: ascii encoded string
                One (1) space indicates different character
                Two (2) spaces indicates different word

        Returns:
            str: Morse Code string to convert
        """
        cipher = ""
        input = input.upper()
        for letter in input:
            if letter != " ":
                # Looks up the dictionary and adds the corresponding morse code
                # along with a space to separate morse codes for different
                # characters
                cipher += f"{MorseCode.MORSE_CODE_DICT[letter] + ' '}"
            else:
                cipher += " "
        return cipher

    def decode_morse_code(self, input: str) -> str:
        """Conversion from Morse Code value to ascii.

        Args:
            str: Morse code string to convert

        Returns:
            str: ascii encoded string
        """
        # Extra space added at the end to access the last morse code
        if self.is_valid_morse(input=input):
            input += " "
            decipher = ""
            ciphertext = ""
            for entry in input:
                # Checks for space
                if (entry != " "):
                    # Counter to keep track of space
                    i = 0
                    # Storing morse code of a single character
                    ciphertext += entry
                # In case of space
                else:
                    # If i = 1 that indicates a new character
                    i += 1
                    # If i = 2 that indicates a new word
                    if i == 2 :
                        # Adding space to separate words
                        decipher += " "
                    else:
                        # Accessing the keys using their values
                        # (reverse of encryption)
                        decipher += list(
                            self.MORSE_CODE_DICT.keys())[list(
                                self.MORSE_CODE_DICT.values()
                                ).index(ciphertext)]
                        ciphertext = ""
            return decipher
        else:
            c.print(
                "[red1][!] The data containes not valid morse code "
                "characters. Check the data and try again."
            )

    def make_data_dict(self, input: str) -> dict:
        results = {}
        results["Input Type"] = "Morse Code"
        results["Input Value"] = f"{input}"
        results["Ascii"] = f"{self.decode_morse_code(input=input)}"
        return results

    def run_morse_code_convert(self):
        input = Prompt.ask(
            f"[white][-] Enter the data you want to convert"
        )
        try:
            results = self.make_data_dict(input=input)
            Results.print_results_table(self, results_dict=results)
        except ValueError as err:
            c.print(f"[bright_red]Validation Error → {err}")
            c.print(
                "[dim]Tip: Try simpler characters like letters and numbers."
            )


class Octal(EncodeDecode):

    def octal_to_binary(self, input: str) -> str:
        """Converts an octal string to binary.

        Args:
            input_string: A string of octal numbers.

        Returns:
            The binary equivalent of the octal numbers.
        """
        octal_list = input.split()
        binary_results = []
        for n in octal_list:
            # Convert octal string to decimal integer
            decimal_val = int(n, 8)
            # Convert decimal to binary
            # [2:] removes the '0b' prefix, zfill(8) ensures 8-bit padding
            binary_val = bin(decimal_val)[2:].zfill(8)
            binary_results.append(binary_val)
        return " ".join(binary_results)

    def octal_to_decimal(self, input: str) -> str:
        """Converts an octal string to a decimal integer.

        Args:
            input_string: A string of octal numbers.

        Returns:
            The decimal equivalent of the octal numbers.
        """
        decimal_vals = [int(num, 8) for num in input.split()]
        return " ".join(map(str, decimal_vals))

    def octal_to_hexadecimal(self, input: str) -> str:
        """Converts an octal string to hexadecimal.

        Args:
            input_string: A string of octal numbers.

        Returns:
            The hexadecimal representation of the octal numbers.
        """
        octal_list = input.split()
        hex_number = [hex(int(num, 8))[2:].upper() for num in octal_list]
        return " ".join(hex_number)

    def make_data_dict(self, input: str) -> dict:
        results = {}
        results["Input Type"] = "Octal"
        results["Input Value"] = f"{input}"
        results["binary"] = f"{self.octal_to_binary()}"
        results["decimal"] = f"{self.octal_to_decimal()}"
        results["hexadecimal"] = f"{self.octal_to_hexadecimal()}"
        return results

    def run_octal_convert(self) -> None:
        input = Prompt.ask(
            f"[white][-] Enter the data you want to convert"
        )
        try:
            results = self.make_data_dict(input=input)
            Results.print_results_table(self, results_dict=results)
        except ValueError as err:
            c.print(f"[bright_red]Validation Error → {err}")
            c.print(
                "[dim]Tip: Try simpler characters like letters and numbers."
            )


class RotateString(EncodeDecode):

    def get_input_value(self) -> None:
        input = Prompt.ask(
            f"[white][-] Enter the data you want to convert"
        )
        return input

    def get_cipher_shift_value(self) -> int:
        n: int = Prompt.ask(
            "[white][-] Enter a numeric value for the shift you "
            "want to use"
        )
        return n

    def run_rotate_string(self) -> str:
        input = self.get_input_value()
        n = self.get_cipher_shift_value()
        lc = string.ascii_lowercase
        uc = string.ascii_uppercase
        trans = str.maketrans(
            lc + uc, lc[n:] + lc[:n] + uc[n:] + uc[:n]
        )
        rotated_string = str.translate(input, trans)
        Results.print_rotation_results(self, results=rotated_string)
