#!/usr/bin/env python3
"""External configuration for menu items and application settings."""

from dataclasses import dataclass, field
from enum import Enum
from rich.console import Console
from typing import Any, Callable, Dict, Optional, Union


console = Console()


class EncryptionMethod(Enum):
    """Top-level encryption method categories."""
    KEY_BASED = "1"
    AES_PASSWORD = "2"
    PGP = "3"
    XOR = "4"
    DETECT = "5"

class EncodeDecodeMethod(Enum):
    """Top-level encode/decode method categories"""
    FROM_ASCII = "1"
    FROM_BASE64 = "2"
    FROM_BINARY = "3"
    FROM_DECIMAL_INT = "4"
    FROM_DECIMAL_STR = "5"
    FROM_HEX = "6"
    FROM_OCT = "7"
    ROTATE_STR = "8"
    FROM_MORSE_CODE = "9"

class FileTypeCheckerMethod(Enum):
    CHECK_FILE = "1"
    CHECK_FOLDER = "2"

class TimeConvertMethod(Enum):
    TIME_DECODE = "1"
    TIME_ENCODE = "2"

class HashingMethod(Enum):
    HASH_STR = "1"
    HASH_FILE = "2"
    HASH_DIR = "3"


@dataclass
class SubMenuItem:
    """Represents a leaf-level menu action item configuration for
    level 2 menu items.
    """
    key: str
    label: str
    description: Optional[str] = None
    handler_module: str = None
    handler_method: str = None
    handler_kwargs: Dict[str, Any] = field(default_factory=dict)
    handler_callable: Optional[Callable] = None


@dataclass
class SubMenuCategory:
    """
    Middle tier menu entry.

    If `handler_module` and `handler_method` are set, this category
        acts as a leaf node and calls the handler directly.

    Otherwise, the user is presented with `submenu_items`.
    """
    key: str
    label: str
    description: str
    method_enum: Union[
        EncryptionMethod,
        EncodeDecodeMethod,
        FileTypeCheckerMethod,
        TimeConvertMethod,
    ]
    submenu_items: Dict[str, SubMenuItem] = field(default_factory=dict)
    # --- Optional direct-handler fields ---
    handler_module: Optional[str] = None
    handler_method: Optional[str] = None
    handler_kwargs: Dict[str, Any] = field(default_factory=dict)
    handler_callable: Optional[Callable] = None


@dataclass
class MainMenuCategory:
    """Represents a main menu category with its submenu."""
    key: str
    label: str
    description: str
    submenu_categories: Dict[str, SubMenuCategory] = field(default_factory=dict)


@dataclass
class AppConfig:
    """Central application configuration."""

    # Application metadata
    app_name: str = "VECTOR CLI APPLICATIONS"
    version_source: str = "versions"  # Module to load version from

    # Display settings
    console_width: int = 80
    show_credits: bool = True
    credits_justify: str = "left"

    # Colors (Rich color codes)
    header_style: str = "#2070b2"
    warning_color: str = "yellow3"
    success_color: str = "green3"

    show_separator_line: bool = False

    # Main menu categories
    main_categories: Dict[str, MainMenuCategory] = field(default_factory=dict)
    # Special actions (exit, help, etc.)
    special_actions: Dict[str, str] = field(default_factory=lambda: {
        "q": "EXIT", "r": "BACK"
    })
    back_prompt: str = "Back to main menu?"
    exit_message: str = "Exiting... Goodbye!"


# ========================
#
# MAIN MENU CONFIGURATION
#
# ========================

# Configure main categories first
MAIN_CATEGORIES_CONFIG = {
    # LEVEL 0 menu item - Encryption / Decryption Tools
    "1": MainMenuCategory(
        key="1",
        label="Encryption / Decryption Tools",
        description="All encryption and decryption methods",
        submenu_categories={
            # LEVEL 1 sub-menu (with child menu)
            EncryptionMethod.KEY_BASED.value: SubMenuCategory(
                key="1",
                label="Use a .key file",
                description="Encryption/decryption using generated key files",
                method_enum=EncryptionMethod.KEY_BASED,
                submenu_items={
                    # LEVEL 2 menu item
                    "1": SubMenuItem(
                        key="1",
                        label="Create a new .key file",
                        description="Create and save a new .key file",
                        handler_module="key",
                        handler_method="generate_and_save_key",
                    ),
                    # LEVEL 2 menu item
                    "2": SubMenuItem(
                        key="2",
                        label="ENCRYPT a single file using a .key",
                        description="",
                        handler_module="key",
                        handler_method="_handle_key_process_file",
                        handler_kwargs={"action": "encrypt"},
                    ),
                    # LEVEL 2 menu item
                    "3": SubMenuItem(
                        key="3",
                        label="DECRYPT a single file using a .key",
                        description="",
                        handler_module="key",
                        handler_method="_handle_key_process_file",
                        handler_kwargs={"action": "decrypt"},
                    ),
                    # LEVEL 2 menu item
                    "4": SubMenuItem(
                        key="4",
                        label="ENCRYPT all files in a folder using a .key",
                        description="",
                        handler_module="key",
                        handler_method="_handle_key_process_folder",
                        handler_kwargs={"action": "encrypt"},
                    ),
                    # LEVEL 2 menu item
                    "5": SubMenuItem(
                        key="5",
                        label="DECRYPT all files in a folder using a .key",
                        description="",
                        handler_module="key",
                        handler_method="_handle_key_process_folder",
                        handler_kwargs={"action": "decrypt"},
                    )
                }
            ),
            # LEVEL 1 sub-menu (with child menu)
            EncryptionMethod.AES_PASSWORD.value: SubMenuCategory(
                key="2",
                label="Use a password (AES-GCM)",
                description="Symmetric encryption using AES-256-GCM",
                method_enum=EncryptionMethod.AES_PASSWORD,
                submenu_items={
                    # LEVEL 2 menu item
                    "1": SubMenuItem(
                        key="1",
                        label="ENCRYPT a single file with password",
                        description="",
                        handler_module="aes",
                        handler_method="_handle_aes_process_file",
                        handler_kwargs={"action": "encrypt"},
                    ),
                    # LEVEL 2 menu item
                    "2": SubMenuItem(
                        key="2",
                        label="DECRYPT a single file with password",
                        description="",
                        handler_module="aes",
                        handler_method="_handle_aes_process_file",
                        handler_kwargs={"action": "decrypt"},
                    ),
                    # LEVEL 2 menu item
                    "3": SubMenuItem(
                        key="3",
                        label="ENCRYPT all files in folder with password",
                        description="",
                        handler_module="aes",
                        handler_method="_handle_aes_process_folder",
                        handler_kwargs={"action": "encrypt"},
                    ),
                    # LEVEL 2 menu item
                    "4": SubMenuItem(
                        key="4",
                        label="DECRYPT all files in folder with password",
                        description="",
                        handler_module="aes",
                        handler_method="_handle_aes_process_folder",
                        handler_kwargs={"action": "decrypt"},
                    ),
                }
            ),
            # LEVEL 1 sub-menu (with child menu)
            EncryptionMethod.PGP.value: SubMenuCategory(
                key="3",
                label="Use a PGP (password or PGP key)",
                description="Symmetric/Asymmetric encryption using PGP/GPG",
                method_enum=EncryptionMethod.PGP,
                submenu_items={
                    # LEVEL 2 menu item
                    "1": SubMenuItem(
                        key="1",
                        label="Create new PGP key pair",
                        description="",
                        handler_module="pgp",
                        handler_method="generate_pgp_key_pair",
                    ),
                    # LEVEL 2 menu item
                    "2": SubMenuItem(
                        key="2",
                        label="Import a PGP key",
                        description="",
                        handler_module="pgp",
                        handler_method="import_key",
                    ),
                    # LEVEL 2 menu item
                    "3": SubMenuItem(
                        key="3",
                        label="ENCRYPT a file using PGP",
                        description="",
                        handler_module="pgp",
                        handler_method="_handle_pgp_process_file",
                        handler_kwargs={"action": "encrypt"},
                    ),
                    # LEVEL 2 menu item
                    "4": SubMenuItem(
                        key="4",
                        label="DECRYPT a file using PGP",
                        description="",
                        handler_module="pgp",
                        handler_method="_handle_pgp_process_file",
                        handler_kwargs={"action": "decrypt"},
                    ),
                    # LEVEL 2 menu item
                    "5": SubMenuItem(
                        key="5",
                        label="ENCRYPT all files in folder using PGP",
                        description="",
                        handler_module="pgp",
                        handler_method="_handle_pgp_process_folder",
                        handler_kwargs={"action": "encrypt"},
                    ),
                    # LEVEL 2 menu item
                    "6": SubMenuItem(
                        key="6",
                        label="DECRYPT all files in folder using PGP",
                        description="",
                        handler_module="pgp",
                        handler_method="_handle_pgp_process_folder",
                        handler_kwargs={"action": "decrypt"},
                    ),
                    # LEVEL 2 menu item
                    "7": SubMenuItem(
                        key="7",
                        label="Sign a document with PGP",
                        description="",
                        handler_module="pgp",
                        handler_method="pgp_sign_file",
                    ),
                    # LEVEL 2 menu item
                    "8": SubMenuItem(
                        key="8",
                        label="Verify a PGP signature",
                        description="",
                        handler_module="pgp",
                        handler_method="pgp_verify_signature",
                    ),
                }
            ),
            # LEVEL 1 sub-menu (with child menu)
            EncryptionMethod.XOR.value: SubMenuCategory(
                key="4",
                label="Use XOR",
                description="Simple XOR encryption for text strings",
                method_enum=EncryptionMethod.XOR,
                submenu_items={
                    # LEVEL 2 menu item
                    "1": SubMenuItem(
                        key="1",
                        label="ENCRYPT message string with XOR",
                        description="",
                        handler_module="xor",
                        handler_method="_handle_xor_process_msg",
                        handler_kwargs={"action": "encrypt"},
                    ),
                    # LEVEL 2 menu item
                    "2": SubMenuItem(
                        key="2",
                        label="DECRYPT message string with XOR",
                        description="",
                        handler_module="xor",
                        handler_method="_handle_xor_process_msg",
                        handler_kwargs={"action": "decrypt"},
                    ),
                }
            ),
            # LEVEL 1 sub-menu (with child menu)
            EncryptionMethod.DETECT.value: SubMenuCategory(
                key="5",
                label="Detect possible encrypted files",
                description="Detect encrypted files",
                method_enum=EncryptionMethod.DETECT,
                submenu_items={
                    # LEVEL 2 menu item
                    "1": SubMenuItem(
                        key="1",
                        label="Examine single file",
                        description="Check entropy for a single file",
                        handler_module="DETECT",
                        handler_method="_handle_inspect_file"
                    ),
                    # LEVEL 2 menu item
                    "2": SubMenuItem(
                        key="2",
                        label="Examine directory for encrypted files",
                        description="Check entropy for all files in a folder",
                        handler_module="DETECT",
                        handler_method="scan_directory"
                    ),
                }
            ),
        }
    ),
    # LEVEL 0 menu item - Data Converter, Encoder, & Decoder
    "2": MainMenuCategory(
        key="2",
        label="Data Converter, Encoder, & Decoder",
        description="Convert files between various encoded formats",
        submenu_categories={
            # LEVEL 1 sub-menu (w/o child menu)
            EncodeDecodeMethod.FROM_ASCII.value: SubMenuCategory(
                key="1",
                label="From ASCII",
                description="Decode ASCII-encoded content",
                method_enum=EncodeDecodeMethod.FROM_ASCII,
                handler_module="encode_decode",
                handler_method="run_encode_decode",
                handler_kwargs={"input_type": "ascii"},
            ),
            # LEVEL 1 sub-menu (w/o child menu)
            EncodeDecodeMethod.FROM_BASE64.value: SubMenuCategory(
                key="2",
                label="From Base64",
                description="Convert Base64 encoded strings",
                method_enum=EncodeDecodeMethod.FROM_BASE64,
                handler_module="encode_decode",
                handler_method="run_encode_decode",
                handler_kwargs={"input_type": "base64"},
            ),
            # LEVEL 1 sub-menu (w/o child menu)
            EncodeDecodeMethod.FROM_BINARY.value: SubMenuCategory(
                key="3",
                label="From Binary",
                description="Convert Binary strings",
                method_enum=EncodeDecodeMethod.FROM_BINARY,
                handler_module="encode_decode",
                handler_method="run_encode_decode",
                handler_kwargs={"input_type": "binary"},
            ),
            # LEVEL 1 sub-menu (with child menu)
            EncodeDecodeMethod.FROM_DECIMAL_INT.value: SubMenuCategory(
                key="4",
                label="From Decimal Integer",
                description="Convert decimal integers",
                method_enum=EncodeDecodeMethod.FROM_DECIMAL_INT,
                handler_module="encode_decode",
                handler_method="run_encode_decode",
                handler_kwargs={"input_type": "decimal_int"},
            ),
            # LEVEL 1 sub-menu (with child menu)
            EncodeDecodeMethod.FROM_DECIMAL_STR.value: SubMenuCategory(
                key="5",
                label="From Decimal String",
                description="Convert decimal string",
                method_enum=EncodeDecodeMethod.FROM_DECIMAL_STR,
                handler_module="encode_decode",
                handler_method="run_encode_decode",
                handler_kwargs={"input_type": "decimal_str"},
            ),
            # LEVEL 1 sub-menu (with child menu)
            EncodeDecodeMethod.FROM_HEX.value: SubMenuCategory(
                key="6",
                label="From Hexadecimal",
                description="Convert hexadecimal values",
                method_enum=EncodeDecodeMethod.FROM_HEX,
                handler_module="encode_decode",
                handler_method="run_encode_decode",
                handler_kwargs={"input_type": "hexadecimal"},
            ),
            # LEVEL 1 sub-menu (with child menu)
            EncodeDecodeMethod.FROM_OCT.value: SubMenuCategory(
                key="7",
                label="From Octal",
                description="Convert octal value",
                method_enum=EncodeDecodeMethod.FROM_OCT,
                handler_module="encode_decode",
                handler_method="run_encode_decode",
                handler_kwargs={"input_type": "octal"},
            ),
            # LEVEL 1 sub-menu (with child menu)
            EncodeDecodeMethod.ROTATE_STR.value: SubMenuCategory(
                key="8",
                label="Rotate String",
                description="Rotate string value 'n' places",
                method_enum=EncodeDecodeMethod.ROTATE_STR,
                handler_module="encode_decode",
                handler_method="run_encode_decode",
                handler_kwargs={"input_type": "rotate_string"},
            ),
            # LEVEL 1 sub-menu (with child menu)
            EncodeDecodeMethod.FROM_MORSE_CODE.value: SubMenuCategory(
                key="9",
                label="From Morse Code",
                description="Convert Morse Code to string",
                method_enum=EncodeDecodeMethod.FROM_MORSE_CODE,
                handler_module="encode_decode",
                handler_method="run_encode_decode",
                handler_kwargs={"input_type": "morse_code"},
            ),
        }
    ),
    # LEVEL 0 menu item - File Type Checker
    "3": MainMenuCategory(
        key="3",
        label="File Type Checker",
        description="Validate file extension against file header",
        submenu_categories={
            # LEVEL 1 sub-menu (w/o child menu)
            FileTypeCheckerMethod.CHECK_FILE.value: SubMenuCategory(
                key="1",
                label="Check single file",
                description="Validate one file extension vs. it's header",
                method_enum=FileTypeCheckerMethod.CHECK_FILE,
                handler_module="file_checker",
                handler_method="run_file_checker",
                handler_kwargs={"type": "file"},
            ),
            # LEVEL 1 sub-menu (w/o child menu)
            FileTypeCheckerMethod.CHECK_FOLDER.value: SubMenuCategory(
                key="2",
                label="Check all files in directory",
                description="Validate all files in a directory",
                method_enum=FileTypeCheckerMethod.CHECK_FOLDER,
                handler_module="file_checker",
                handler_method="run_file_checker",
                handler_kwargs={"type": "folder"},
            ),
        }
    ),
    # LEVEL 0 menu item - Time Decoder / Encoder
    "4": MainMenuCategory(
        key="4",
        label="Time Decoder / Encoder",
        description="Encode or Decode timestamp values",
        submenu_categories={
            # LEVEL 1 sub-menu (w/o child menu)
            TimeConvertMethod.TIME_DECODE.value: SubMenuCategory(
                key="1",
                label="Decode a timestamp value",
                description="",
                method_enum=TimeConvertMethod.TIME_DECODE,
                handler_module="time_converter",
                handler_method="_handle_time_decode_encode",
                handler_kwargs={"method": "decode"},
            ),
            # LEVEL 1 sub-menu (w/o child menu)
            TimeConvertMethod.TIME_ENCODE.value: SubMenuCategory(
                key="1",
                label="Encode a string to a timestamp value",
                description="",
                method_enum=TimeConvertMethod.TIME_ENCODE,
                handler_module="time_converter",
                handler_method="_handle_time_decode_encode",
                handler_kwargs={"method": "encode"},
            )
        }
    ),
    # LEVEL 0 menu item - Hashing
    "5": MainMenuCategory(
        key="5",
        label="Hashing",
        description="Hash a string, file, or folder",
        submenu_categories={
            # LEVEL 1 sub-menu (w/o child menu)
            HashingMethod.HASH_STR.value: SubMenuCategory(
                key="1",
                label="Hash text string",
                description="Get the hash of a text string",
                method_enum=HashingMethod.HASH_STR,
                handler_module="hashing",
                handler_method="run_hash_with_ui_selection",
                handler_kwargs={"input_type": "string"},
            ),
            # LEVEL 1 sub-menu (w/o child menu)
            HashingMethod.HASH_FILE.value: SubMenuCategory(
                key="2",
                label="Hash a file",
                description="Get the hash of a single file",
                method_enum=HashingMethod.HASH_FILE,
                handler_module="hashing",
                handler_method="run_hash_with_ui_selection",
                handler_kwargs={"input_type": "file"},
            ),
            # LEVEL 1 sub-menu (w/o child menu)
            HashingMethod.HASH_DIR.value: SubMenuCategory(
                key="3",
                label="Hash files in a directory",
                description="Get the hashes of files in a directory",
                method_enum=HashingMethod.HASH_DIR,
                handler_module="hashing",
                handler_method="run_hash_with_ui_selection",
                handler_kwargs={"input_type": "directory"},
            ),
        },
    ),
}


# Build main categories dict after defining all configs
GLOBAL_CONFIG = AppConfig()
for key, category in MAIN_CATEGORIES_CONFIG.items():
    GLOBAL_CONFIG.main_categories[key] = category

# Also expose just the categories dict if needed elsewhere
MAIN_MENU_CATEGORIES = GLOBAL_CONFIG.main_categories


# For convenience in importing
__all__ = [
    "AppConfig",
    "MAIN_CATEGORIES_CONFIG",
    "GLOBAL_CONFIG",
    "MAIN_MENU_CATEGORIES"
]
