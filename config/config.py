# !/usr/bin/env python3
"""External configuration for menu items and application settings."""

from dataclasses import dataclass, field
from enum import Enum
from rich.console import Console
from typing import Any, Dict, Optional, Union


console = Console()


class EncryptionMethod(Enum):
    """Top-level encryption method categories."""
    KEY_BASED = "1"
    AES_PASSWORD = "2"
    PGP = "3"
    XOR = "4"
    detect = "5"


class EncodeDecodeMethod(Enum):
    """Top-level encode/decode method categories"""
    FROM_ASCII = "1"
    FROM_BASE64 = "2"
    FROM_BINARY = "3"
    FROM_DEC_INT = "4"
    FROM_DEC_STR = "5"
    FROM_HEX = "6"
    FROM_OCT = "7"
    ROT_STR = "8"
    FROM_MORSE_CODE = "9"


@dataclass
class SubMenuItem:
    """Represents a leaf-level menu action item configuration for
    level 2 menu items.
    ."""
    key: str
    label: str
    description: Optional[str] = None
    handler_module: str = None
    handler_method: str = None
    handler_kwargs: Dict[str, Any] = field(default_factory=dict)


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
    method_enum: Union[EncryptionMethod, EncodeDecodeMethod]
    submenu_items: Dict[str, SubMenuItem] = field(default_factory=dict)
    # --- Optional direct-handler fields ---
    handler_module: Optional[str] = None
    handler_method: Optional[str] = None
    handler_kwargs: Dict[str, Any] = field(default_factory=dict)


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
    app_name: str = "ENCRYPTION|DECRYPTION APPLICATION"
    version_source: str = "versions"  # Module to load version from

    # Display settings
    console_width: int = 80
    show_credits: bool = True
    credits_justify: str = "left"

    # Colors (Rich color codes)
    title_color: str = "blue"
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
    # LEVEL 0 - Encryption/Decryption Tools
    "1": MainMenuCategory(
        key="1",
        label="Encryption / Decryption Tools",
        description="All encryption and decryption methods",
        submenu_categories={
            EncryptionMethod.KEY_BASED.value: SubMenuCategory(
                key="1",
                label="Use a .key file",
                description="Encryption/decryption using generated key files",
                method_enum=EncryptionMethod.KEY_BASED,
                submenu_items={
                    "1": SubMenuItem(
                        key="1",
                        label="Create a new .key file",
                        description="Create and save a new .key file",
                        handler_module="key",
                        handler_method="generate_and_save_key",
                    ),
                    "2": SubMenuItem(
                        key="2",
                        label="ENCRYPT a single file using a .key",
                        description="",
                        handler_module="key",
                        handler_method="_handle_key_process_file",
                        handler_kwargs={"action": "encrypt"},
                    ),
                    "3  ": SubMenuItem(
                        key="3",
                        label="DECRYPT a single file using a .key",
                        description="",
                        handler_module="key",
                        handler_method="_handle_key_process_file",
                        handler_kwargs={"action": "decrypt"},
                    ),
                    "4": SubMenuItem(
                        key="4",
                        label="ENCRYPT all files in a folder using a .key",
                        description="",
                        handler_module="key",
                        handler_method="_handle_key_process_folder",
                        handler_kwargs={"action": "encrypt"},
                    ),
                    "5": SubMenuItem(
                        key="5",
                        label="DECRYPT all files in a folder using a .key",
                        description="",
                        handler_module="key",
                        handler_method="_handle_key_process_folder",
                        handler_kwargs={"action": "decrypt"},
                    )
                },
            ),
            EncryptionMethod.AES_PASSWORD.value: SubMenuCategory(
                key="2",
                label="Use a password (AES-GCM)",
                description="Symmetric encryption using AES-256-GCM",
                method_enum=EncryptionMethod.AES_PASSWORD,
                submenu_items={
                    "1": SubMenuItem(
                        key="1",
                        label="ENCRYPT a single file with password",
                        description="",
                        handler_module="aes",
                        handler_method="_handle_aes_process_file",
                        handler_kwargs={"action": "encrypt"},
                    ),
                    "2": SubMenuItem(
                        key="2",
                        label="DECRYPT a single file with password",
                        description="",
                        handler_module="aes",
                        handler_method="_handle_aes_process_file",
                        handler_kwargs={"action": "decrypt"},
                    ),
                    "3": SubMenuItem(
                        key="3",
                        label="ENCRYPT all files in folder with password",
                        description="",
                        handler_module="aes",
                        handler_method="_handle_aes_process_folder",
                        handler_kwargs={"action": "encrypt"},
                    ),
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
            EncryptionMethod.PGP.value: SubMenuCategory(
                key="3",
                label="Use a PGP (password or PGP key)",
                description="Symmetric/Asymmetric encryption using PGP/GPG",
                method_enum=EncryptionMethod.PGP,
                submenu_items={
                    "1": SubMenuItem(
                        key="1",
                        label="Create new PGP key pair",
                        description="",
                        handler_module="pgp",
                        handler_method="generate_pgp_key_pair",
                    ),
                    "2": SubMenuItem(
                        key="2",
                        label="Import a PGP key",
                        description="",
                        handler_module="pgp",
                        handler_method="import_key",
                    ),
                    "3": SubMenuItem(
                        key="3",
                        label="ENCRYPT a file using PGP",
                        description="",
                        handler_module="pgp",
                        handler_method="_handle_pgp_process_file",
                        handler_kwargs={"action": "encrypt"},
                    ),
                    "4": SubMenuItem(
                        key="4",
                        label="DECRYPT a file using PGP",
                        description="",
                        handler_module="pgp",
                        handler_method="_handle_pgp_process_file",
                        handler_kwargs={"action": "decrypt"},
                    ),
                    "5": SubMenuItem(
                        key="5",
                        label="ENCRYPT all files in folder using PGP",
                        description="",
                        handler_module="pgp",
                        handler_method="_handle_pgp_process_folder",
                        handler_kwargs={"action": "encrypt"},
                    ),
                    "6": SubMenuItem(
                        key="6",
                        label="DECRYPT all files in folder using PGP",
                        description="",
                        handler_module="pgp",
                        handler_method="_handle_pgp_process_folder",
                        handler_kwargs={"action": "decrypt"},
                    ),
                    "7": SubMenuItem(
                        key="7",
                        label="Sign a document with PGP",
                        description="",
                        handler_module="pgp",
                        handler_method="pgp_sign_file",
                    ),
                    "8": SubMenuItem(
                        key="8",
                        label="Verify a PGP signature",
                        description="",
                        handler_module="pgp",
                        handler_method="pgp_verify_signature",
                    ),
                }
            ),
            EncryptionMethod.XOR.value: SubMenuCategory(
                key="4",
                label="Use XOR",
                description="Simple XOR encryption for text strings",
                method_enum=EncryptionMethod.XOR,
                submenu_items={
                    "1": SubMenuItem(
                        key="1",
                        label="ENCRYPT message string with XOR",
                        description="",
                        handler_module="xor",
                        handler_method="_handle_xor_process_msg",
                        handler_kwargs={"action": "encrypt"},
                    ),
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
            EncryptionMethod.detect.value: SubMenuCategory(
                key="5",
                label="Detect possible encrypted files",
                description="Detect encrypted files",
                method_enum=EncryptionMethod.detect,
                submenu_items={
                    "1": SubMenuItem(
                        key="1",
                        label="Examine single file",
                        description="Check entropy for a single file",
                        handler_module="detect",
                        handler_method="_handle_inspect_file"
                    ),
                    "2": SubMenuItem(
                        key="2",
                        label="Examine directory for encrypted files",
                        description="Check entropy for all files in a folder",
                        handler_module="detect",
                        handler_method="scan_directory"
                    ),
                }
            ),
        },
    ),
    # LEVEL 0 - Encoding/Decoding Menu
    "2": MainMenuCategory(
        key="2",
        label="Data Converter, Encoder, & Decoder",
        description="Convert files between various encoded formats",
        submenu_categories={
            EncodeDecodeMethod.FROM_ASCII.value: SubMenuCategory(
                key="1",
                label="From ASCII",
                description="Decode ASCII-encoded content",
                method_enum=EncodeDecodeMethod.FROM_ASCII,
                handler_module="ascii",
                handler_method="run_ascii_converter",
                # handler_kwargs="",
            ),
            EncodeDecodeMethod.FROM_BASE64.value: SubMenuCategory(
                key="2",
                label="From Base64",
                description="Convert Base64 encoded strings",
                method_enum=EncodeDecodeMethod.FROM_BASE64,
                handler_module="base64",
                handler_method="run_base64_converter",
            ),
            EncodeDecodeMethod.FROM_BASE64.value: SubMenuCategory(
                key="3",
                label="From Binary",
                description="Convert Binary strings",
                method_enum=EncodeDecodeMethod.FROM_BINARY,
                handler_module="binary",
                handler_method="run_binary_converter",
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
