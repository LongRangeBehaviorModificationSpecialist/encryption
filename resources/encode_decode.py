#!/usr/bin/env python3

import base64
import codecs
import functools
import string
from typing import Dict, Tuple

from . import install
from config.log_config import get_logger
from config.results import Results
from resources.decorators import handle_exceptions
from utils import UIHandlerProtocol, RichUIHandler, get_time


logger = get_logger("time_converter")
install()


class EncodeDecode:
    """Data encoder/decoder with configuration-driven conversion."""

    INPUT_FORMATS = {
        "ascii": {
            "Base64": "ascii_to_base64",
            "Base32": "ascii_to_base32",
            "Binary": "ascii_to_binary",
            "Decimal": "ascii_to_decimal",
            "Hexadecimal": "ascii_to_hexadecimal",
            "Rot13": "ascii_to_rot13",
            "Morse": "encode_morse_code",
        },
        "base64": {
            "Ascii": "base64_to_ascii",
            "Base32": "base64_to_base32",
            "Binary": "base64_to_binary",
            "Decimal": "base64_to_decimal",
            "Hexadecimal": "base64_to_hexadecimal",
            "Morse": "encode_morse_code",
        },
        "binary": {
            "Ascii": "binary_to_ascii",
            "Base64": "binary_to_base64",
            "Base32": "binary_to_base32",
            "Decimal_int": "binary_to_decimal_int",
            "Decimal_char": "binary_to_decimal_char",
            "Hexadecimal": "binary_to_hexadecimal",
            "Octal": "binary_to_octal",
        },
        "decimal_int": {
            "Binary": "decimal_int_to_binary",
            "Hexadecimal": "decimal_int_to_hexadecimal",
            "Octal": "decimal_int_to_octal",
        },
        "decimal_str": {
            "Ascii": "decimal_str_to_ascii",
            "Base64": "decimal_str_to_base64",
        },
        "hexadecimal": {
            "Ascii": "hex_to_ascii",
            "Base64": "hex_to_base64",
            "Binary": "hex_to_binary",
            "Decimal": "hex_to_decimal",
            "Decimal (bytes)": "hex_to_decimal_bytes",
        },
        "morse_code": {
            "Ascii": "decode_morse_code",
        },
        "octal": {
            "Binary": "octal_to_binary",
            "Decimal": "octal_to_decimal",
            "Hexadecimal": "octal_to_hexadecimal",
        },
        "rotate_string": {
            "Ascii": "run_rotate_string"
        }
    }

    LABELS = {
        "ascii": "Ascii",
        "base64": "Base64",
        "binary": "Binary",
        "decimal_int": "Decimal (integer)",
        "decimal_str": "Decimal (String)",
        "hexadecimal": "Hexadecimal",
        "morse_code": "Morse Code",
        "octal": "Octal",
        "rotate_string": "Rotated String",
    }


    def __init__(self, ui: UIHandlerProtocol | None = None) -> None:
        self.ui = ui or RichUIHandler(get_time=get_time)


    def _build_conversion_dict(
            self,
            input_type: str,
            user_input: str
    ) -> Dict[str, str]:
        """Build conversion results using configuration."""
        results = {}
        results["Input Type"] = self.LABELS[input_type]
        results["Input Value"] = user_input
        results["Validation OK"] = True

        # if input_type == "rotate_string":
        #     return self.run_rotate_string(input_value=user_input)

        # Get conversions for this input type
        conversions = self.INPUT_FORMATS.get(input_type, {})

        for output_key, method_name in conversions.items():
            try:
                method = getattr(self, method_name)
                value = method(user_input)

                # Special handling: hex_to_decimal returns dict with 2 keys
                if isinstance(value, dict):
                    for k, v in value.items():
                        results[k] = f"{v}"
                else:
                    results[output_key] = f"{value}"

                # results[output_key] = method(user_input)
            except (ValueError, AttributeError) as err:
                results["Validation OK"] = False
                results["error"] = str(err)
                break

        return results


    def run_encode_decode(self, input_type: str) -> None:

        VALID_OPTIONS = list(self.INPUT_FORMATS.keys())
        VALID_OPTIONS.append("rotate_string")

        logger.info("The 'run_encode_decode()' method was called")
        logger.info(f"The 'input_type' varaible was passed as '{input_type}'")

        try:
            if input_type not in VALID_OPTIONS:
                self.ui.warning(
                    f"The input type value {input_type} is not supported"
                )
                return

            user_input = self.ui.prompt(f"Enter the data you want to convert")

            logger.info(
                f"Calling '_build_conversion_dict()' with user_input type: "
                f"{type(user_input)}"
            )
            logger.info(f"user_input value: {repr(user_input)[:50]}")

            # Single generic builder instead of 9 methods
            results = self._build_conversion_dict(input_type, user_input)
            Results.print_encode_decode_results_table(results_dict=results)

        except ValueError as err:
            self.ui.error(f"Validation Error → {err}")
            self.ui.info(
                "[dim]Tip: Try simpler characters like letters and numbers."
            )


    PRINTABLE_ASCII = set(string.printable)
    CONTROL_CHARS = set(chr(i) for i in range(32) if chr(i) not in '\t\n\r')
    WHITESPACE = set(string.whitespace)


    def validate_ascii_input(self, input_value: str) -> Tuple[bool, str]:
        """Comprehensive input validation."""
        if not input_value:
            return False, "Input cannot be empty"

        if not isinstance(input_value, str):
            return False, "Input must be a string"

        issues = []
        for pos, char in enumerate(input_value):
            code = ord(char)

            if code > 127:
                issues.append(f"Position {pos} → Non-ASCII '{char}' (U+{code:04X})")
            elif char in self.CONTROL_CHARS:
                issues.append(f"Position {pos} → Control character (ord={code})")

        if issues:
            return False, "; ".join(issues[:3]) + ("..." if len(issues) > 3 else "")

        return True, ""


    def sanitize_input(self, input_value: str, mode: str = "strict") -> str:
        """Sanitize input based on mode.

        Args:
            mode: "strict" (raise), "replace" (swap bad chars), "remove"
                (delete bad chars)
        """
        sanitized = []

        for char in input_value:
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


    def ascii_to_base64(self, input_value: str) -> str:
        """Convert the ascii input string to base64 string."""
        is_valid, error_msg = self.validate_ascii_input(input_value)
        if not is_valid:
            raise ValueError(error_msg)
        return base64.b64encode(input_value.encode("ascii", errors="ignore")).decode()


    def ascii_to_base32(self, input_value: str) -> str:
        """Converts an ascii string to its base32 encoded representation."""
        is_valid, error_msg = self.validate_ascii_input(input_value)
        if not is_valid:
            raise ValueError(error_msg)
        return base64.b32encode(
            input_value.encode("ascii", errors="ignore")
        ).decode("ascii")


    def ascii_to_binary(self, input_value: str) -> str:
        """Convert the ascii input string to binary string."""
        is_valid, error_msg = self.validate_ascii_input(input_value)
        if not is_valid:
            raise ValueError(error_msg)
        return " ".join(bin(ord(c))[2:].zfill(8) for c in input_value)


    def ascii_to_decimal(self, input_value: str) -> str:
        """Convert the ascii input string to decimal string."""
        is_valid, error_msg = self.validate_ascii_input(input_value)
        if not is_valid:
            raise ValueError(error_msg)
        return " ".join(str(ord(i)) for i in input_value)


    def ascii_to_hexadecimal(self, input_value: str) -> str:
        """Convert the ascii input string to hexadecimal string."""
        is_valid, error_msg = self.validate_ascii_input(input_value)
        if not is_valid:
            raise ValueError(error_msg)
        return " ".join(f"{ord(c):02X}" for c in input_value)


    def ascii_to_rot13(self, input_value: str) -> str:
        """Convert the ascii input string to rot13 string."""
        is_valid, error_msg = self.validate_ascii_input(input_value)
        if not is_valid:
            raise ValueError(error_msg)
        return codecs.encode(input_value, "rot_13")


    def base64_to_ascii(self, input_value: str) -> str:
        """Convert base64 string to ascii string."""
        return base64.b64decode(input_value).decode()


    def base64_to_base32(self, input_value: str) -> str:
        """Convert a base64 string to a base32 string."""
        raw_bytes = base64.b64decode(input_value)
        return base64.b32encode(raw_bytes).decode("ascii")


    def base64_to_binary(self, input_value: str) -> str:
        """Convert base64 string to binary string."""
        return " ".join(
            format(ord(c), "b").zfill(8) for c in base64.b64decode(
                input_value).decode()
        )


    def base64_to_decimal(self, input_value: str) -> str:
        """Convert base64 string to decimal string."""
        d = [ord(c) for c in base64.b64decode(input_value).decode()]
        return " ".join(str(x) for x in d)


    def base64_to_hexadecimal(self, input_value: str) -> str:
        """Convert base64 string to hexadecimal string."""
        decoded_bytes = base64.b64decode(input_value)
        return " ".join(f"{n:02x}" for n in decoded_bytes).upper()


    def _validate_binary(self, input_value: str) -> str:
        """Validates that the input is a non-empty binary string.

        Automatically pads with leading zeros to make length divisible by 8.

        Returns the cleaned and padded binary string.
        """
        if not isinstance(input_value, str):
            raise TypeError("Input must be a string.")

        # Check for empty input value
        if not input_value:
            raise ValueError("Input can not be empty.")

        clean_binary = input_value.replace(" ", "")

        # Check to make sure the input consists of only 0 or 1
        if any (c not in "01" for c in clean_binary):
            raise ValueError("Binary input must be only 0 or 1.")

        if len(clean_binary) == 0:
            raise ValueError("Input cannot be empty after removing spaces.")

        if len(clean_binary) % 8 != 0:
            # The double '% 8' handles the case where 'len % 8 == 0'
            # then padding_needed = 0, not 8
            padding_needed = (8 - len(clean_binary) % 8) % 8
            clean_binary = (
                clean_binary.zfill(len(clean_binary) + padding_needed)
            )

        return clean_binary


    def binary_to_ascii(self, input_value: str) -> str:
        """Converts binary string to ascii representation."""
        validated_input = self._validate_binary(input_value=input_value)
        list = []
        for i in range(0, len(validated_input), 8):
            list.append(validated_input[i : i + 8])
        return "".join([chr(int(i, 2)) for i in list])


    def binary_to_base64(self, input_value: str) -> str:
        """Converts a binary string to base64 string."""
        binary_string = self._validate_binary(input_value=input_value)

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


    def binary_to_base32(self, input_value: str) -> str:
        """Converts a binary string to base32 string."""
        binary_string = self._validate_binary(input_value=input_value)
        padding_length = (8 - len(binary_string) % 8) % 8
        binary_string += "0" * padding_length

        # Convert binary string to bytes
        byte_array = bytearray()

        for i in range(0, len(binary_string), 8):
            byte = binary_string[i : i + 8]
            byte_array.append(int(byte, 2))

        # Encode to Base32
        return base64.b32encode(byte_array).decode("ascii")


    def binary_to_decimal_int(self, input_value: str) -> int:
        """Converts a binary string to a decimal integer."""
        binary_string = self._validate_binary(input_value=input_value)
        binary_string = binary_string.replace(" ", "")
        return f"{int(binary_string, 2):,}"


    def binary_to_decimal_char(self, input_value: str) -> str:
        """Converts each 8-bit byte chunk into its individual decimal
        value and returns them as a single space-seperated string.
        """
        binary_string = self._validate_binary(input_value=input_value)
        clean_binary = binary_string.replace(" ", "")
        binary_bytes = [
            clean_binary[i : i + 8]
            for i in range(0, len(clean_binary), 8)
        ]
        return " ".join([str(int(b, 2)) for b in binary_bytes])


    def binary_to_hexadecimal(self, input_value: str) -> str:
        """Converts a binary string to a hexadecimal string."""
        binary_string = self._validate_binary(input_value=input_value)
        decimal_value = int(binary_string, 2)
        hex_string = f"{decimal_value:X}"
        if len(hex_string) % 2 !=0:
            hex_string = "0" + hex_string
        return " ".join(
            hex_string[i : i + 2] for i in range(0, len(hex_string), 2)
        )


    def binary_to_octal(self, input_value: str) -> str:
        """Converts a binary string to a octal string."""
        binary_string = self._validate_binary(input_value=input_value)
        return oct(int(binary_string, 2))[2:]


    def format_dec_int_input(self, input_value: str) -> int:
        if "," in input_value:
            input_value = input_value.replace(",", "")
        return int(input_value)


    def decimal_int_to_binary(self, input_value: int) -> int:
        """Convert the decimal number to binary number."""
        input_value = self.format_dec_int_input(input_value=input_value)
        return "{0:b}".format(input_value)


    def decimal_int_to_hexadecimal(self, input_value: str) -> str:
        """Convert the decimal number to hexadecimal number."""
        input_value = self.format_dec_int_input(input_value=input_value)
        hex_str = hex(input_value)[2:]
        if len(hex_str) % 2 != 0:
            hex_str = "0" + hex_str
        pairs = [hex_str[i : i + 2] for i in range(0, len(hex_str), 2)]
        return "0x " + " ".join(pairs).upper()


    def decimal_int_to_octal(self, input_value: str) -> str:
        """Convert the decimal number to octal number."""
        input_value = self.format_dec_int_input(input_value=input_value)
        return oct(input_value)


    def decimal_str_to_ascii(self, input_value: str) -> str:
        try:
            return "".join(chr(int(c)) for c in input_value.split())
        except ValueError:
            self.ui.error(
                "Error → Please ensure the input only contains "
                "numbers separated by spaces."
            )
        except OverflowError:
            self.ui.error(
                "Error → One of the numbers is too large to be a "
                "valid ascii character."
            )


    def decimal_str_to_base64(self, input_value: str) -> str:
        byte_data = bytes(int(c) for c in input_value.split())
        return base64.b64encode(byte_data).decode("utf-8")


    def _clean_hex_input(self, input_value: str) -> str:
        hex_str = input_value.strip().lower().replace(" ", "")
        if hex_str.startswith("0x"):
            hex_str = hex_str[2:]
        return hex_str


    @handle_exceptions
    def hex_to_ascii(self, input_value: str) -> str:
        """Converts a hexadecimal string to its representation in ascii
        characters.
        """
        return bytes.fromhex(
            self._clean_hex_input(input_value)).decode("utf-8")


    @handle_exceptions
    def hex_to_base64(self, input_value: str) -> str:
        """Converts a hexadecimal string to its base64 representation."""
        hex_str = self._clean_hex_input(input_value)
        raw_bytes = bytes.fromhex(hex_str)
        return base64.b64encode(raw_bytes).decode("utf-8")


    @handle_exceptions
    def hex_to_binary(self, input_value: str) -> str:
        """Converts a hexadecimal string to its binary representation."""
        hex_str = self._clean_hex_input(input_value)
        return " ".join(f"{b:08b}" for b in bytes.fromhex(hex_str))


    @handle_exceptions
    def hex_to_decimal(self, input_value: str) -> str:
        """Converts a hex string to signed and unsigned representations.

        Args:
            hex_str (str): Hex string (e.g. 'FFFF', '0xFF').

        Returns:
            dict: Contains 'signed' and 'unsigned' representations.

        Raises:
            ValueError: If input is not valid hexadecimal.
        """
        hex_str = self._clean_hex_input(input_value)

        # Validate all characters are hex digits
        if any(c not in "0123456789abcdefABCDEF" for c in hex_str):
            raise ValueError(
                "Hexadecimal input must contain only 0-9 and A-F."
            )

        unsigned_value = int(hex_str, 16)
        bit_length = len(hex_str) * 4

        # Calculate signed value using two's complement
        # If highest bit is set, subtract 2^bit_length
        signed_value = unsigned_value

        if unsigned_value >= 2 ** (bit_length - 1):
            signed_value -= 2 ** bit_length

        return {
            "Decimal (signed)": f"{signed_value:,}",
            "Decimal (unsigned)": f"{unsigned_value:,}"
        }


    @handle_exceptions
    def hex_to_decimal_bytes(self, input_value: str) -> str:
        """Converts each hex byte to its decimal value.

        Args:
            input_value: Hex string (e.g., '4D 69 6B', '4D696B', '0x4D696B').

        Returns:
            Space-separated decimal values (e.g., '77 105 107').

        Raises:
            ValueError: If input is not valid hexadecimal or has odd length.
        """
        hex_str = self._clean_hex_input(input_value)

        if not hex_str:
            raise ValueError("Hex input cannot be empty.")

        if any(c not in "0123456789abcdefABCDEF" for c in hex_str):
            raise ValueError("Hexadecimal input must contain only 0-9 and A-F.")

        # Must be even length (each byte = 2 hex chars)
        if len(hex_str) % 2 != 0:
            raise ValueError(
                f"Hex string length ({len(hex_str)}) must be even. "
                "Each byte requires 2 hex characters."
            )

        # Split into pairs and convert each byte
        decimal_bytes = [str(int(hex_str[i:i+2], 16)) for i in range(0, len(hex_str), 2)]

        return " ".join(decimal_bytes)


    @handle_exceptions
    def hex_to_morse_code(self, input_value: str) -> str:
        hex_str = self._clean_hex_input(input_value)
        return self.encode_morse_code(input_value=hex_str)


    """Python program to implement Morse Code Translator

        VARIABLE KEY
        "cipher"     → "stores the morse translated form of the english string"
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


    def is_valid_morse(self, input_value: str) -> str:
        """Validates that the input contains valid morse code characters."""
        if not input_value or input_value.isspace():
            return False
        allowed_characters = {".", "-", " "}
        if set(input_value).issubset(allowed_characters):
            return True
        else:
            return False


    def encode_morse_code(self, input_value: str) -> str:
        """Conversion from Morse Code value to ascii

        Args:
            str: ascii encoded string
                One (1) space indicates different character
                Two (2) spaces indicates different word

        Returns:
            str: Morse Code string to convert
        """
        cipher = ""
        input_value = input_value.upper()
        for letter in input_value:
            if letter != " ":
                # Looks up the dictionary and adds the corresponding morse code
                # along with a space to separate morse codes for different
                # characters
                cipher += f"{self.MORSE_CODE_DICT[letter] + ' '}"
            else:
                cipher += " "
        return cipher


    def decode_morse_code(self, input_value: str) -> str:
        """Conversion from Morse Code value to ascii.

        Args:
            str: Morse code string to convert

        Returns:
            str: ascii encoded string
        """
        # Extra space added at the end to access the last morse code
        if self.is_valid_morse(input_value=input_value):
            input_value += " "
            decipher = ""
            ciphertext = ""
            for entry in input_value:
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
            self.ui.error(
                "The data containes not valid morse code characters."
                "Check the data and try again."
            )


    def octal_to_binary(self, input_value: str) -> str:
        """Converts an octal string to binary.

        Args:
            input_string: A string of octal numbers.

        Returns:
            The binary equivalent of the octal numbers.
        """
        octal_list = input_value.split()
        binary_results = []
        for n in octal_list:
            # Convert octal string to decimal integer
            decimal_val = int(n, 8)
            # Convert decimal to binary
            # [2:] removes the '0b' prefix, zfill(8) ensures 8-bit padding
            binary_val = bin(decimal_val)[2:].zfill(8)
            binary_results.append(binary_val)
        return " ".join(binary_results)


    def octal_to_decimal(self, input_value: str) -> str:
        """Converts an octal string to a decimal integer.

        Args:
            input_string: A string of octal numbers.

        Returns:
            The decimal equivalent of the octal numbers.
        """
        decimal_vals = [int(num, 8) for num in input_value.split()]
        return " ".join(map(str, decimal_vals))


    def octal_to_hexadecimal(self, input_value: str) -> str:
        """Converts an octal string to hexadecimal.

        Args:
            input_string: A string of octal numbers.

        Returns:
            The hexadecimal representation of the octal numbers.
        """
        octal_list = input_value.split()
        hex_number = [hex(int(num, 8))[2:].upper() for num in octal_list]
        return " ".join(hex_number)


    def get_cipher_shift_value(self) -> int:
        n: int = self.ui.prompt(
            "Enter a numeric value for the shift you want to use"
        )
        return int(n)


    def run_rotate_string(self, input_value: str) -> Dict[str, str]:
        results = {}
        results["Input Type"] = "Rotate String"
        results["Input Value"] = input_value
        results["Validation OK"] = True

        try:
            n: int = self.get_cipher_shift_value()
            lc = string.ascii_lowercase
            uc = string.ascii_uppercase
            trans = str.maketrans(
                lc + uc, lc[n:] + lc[:n] + uc[n:] + uc[:n]
            )
            rotated_string = str.translate(input_value, trans)
            # self.ui.info(
            #     f"String Rotation Results -> [bright_blue][b]{rotated_string}[/b]\n"
            # )
            return rotated_string
        except ValueError as err:
            results["Validation OK"] = False
            results["error"] = str(err)

        return results
