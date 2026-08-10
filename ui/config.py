# !/usr/bin/env python3
"""External configuration for menu items and application settings."""

from dataclasses import dataclass, field
from enum import Enum
from rich.console import Console
import sys
from typing import Dict, List, Any, Optional

c = Console()


class FileAction(Enum):
    """Enum for encryption/decryption actions."""
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"


class EncryptionMethod(Enum):
    """Top-level encryption method categories."""
    KEY_BASED = "1"
    AES_PASSWORD = "2"
    PGP = "3"
    XOR = "4"


@dataclass
class SubMenuItem:
    """Represents a submenu item configuration."""
    key: str
    label: str
    description: Optional[str] = None
    handler_module: str = None
    handler_method: str = None
    handler_kwargs: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MainMenuCategory:
    """Represents a main menu category with its submenu."""
    key: str
    label: str
    description: str
    method_enum: EncryptionMethod
    submenu_items: Dict[str, SubMenuItem] = field(default_factory=dict)


@dataclass
class AppConfig:
    """Central application configuration."""

    # Application metadata
    app_name: str = "ENCRYPTION/DECRYPTION APPLICATION"
    version_source: str = "versions"  # Module to load version from

    # Display settings
    console_width: int = 80
    show_credits: bool = True
    credits_justify: str = "left"

    # Colors (Rich color codes)
    title_color: str = "dodger_blue1"
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
    EncryptionMethod.KEY_BASED.value: MainMenuCategory(
        key="1",
        label="Use a .key file",
        description="Encryption/decryption using generated key files",
        method_enum=EncryptionMethod.KEY_BASED,
        submenu_items={
            "1": SubMenuItem(
                key="1",
                label="Create a new .key file",
                handler_module="key",
                handler_method="generate_and_save_key",
            ),
            "2": SubMenuItem(
                key="2",
                label="ENCRYPT a single file using a .key",
                handler_module="key",
                handler_method="_handle_key_process_file",
                handler_kwargs={"action": "encrypt"},
            ),
            "3": SubMenuItem(
                key="3",
                label="DECRYPT a single file using a .key",
                handler_module="key",
                handler_method="_handle_key_process_file",
                handler_kwargs={"action": "decrypt"},
            ),
            "4": SubMenuItem(
                key="4",
                label="ENCRYPT all files in a folder using a .key",
                handler_module="key",
                handler_method="_handle_key_process_folder",
                handler_kwargs={"action": "encrypt"},
            ),
            "5": SubMenuItem(
                key="5",
                label="DECRYPT all files in a folder using a .key",
                handler_module="key",
                handler_method="_handle_key_process_folder",
                handler_kwargs={"action": "decrypt"},
            ),
        }
    ),
    EncryptionMethod.AES_PASSWORD.value: MainMenuCategory(
        key="2",
        label="Use a password (AES-GCM)",
        description="Symmetric encryption using AES-256-GCM",
        method_enum=EncryptionMethod.AES_PASSWORD,
        submenu_items={
            "1": SubMenuItem(
                key="1",
                label="ENCRYPT a single file with password",
                handler_module="aes",
                handler_method="_handle_aes_process_file",
                handler_kwargs={"action": "encrypt"},
            ),
            "2": SubMenuItem(
                key="2",
                label="DECRYPT a single file with password",
                handler_module="aes",
                handler_method="_handle_aes_process_file",
                handler_kwargs={"action": "decrypt"},
            ),
            "3": SubMenuItem(
                key="3",
                label="ENCRYPT all files in folder with password",
                handler_module="aes",
                handler_method="_handle_aes_process_folder",
                handler_kwargs={"action": "encrypt"},
            ),
            "4": SubMenuItem(
                key="4",
                label="DECRYPT all files in folder with password",
                handler_module="aes",
                handler_method="_handle_aes_process_folder",
                handler_kwargs={"action": "decrypt"},
            ),
        }
    ),
    EncryptionMethod.PGP.value: MainMenuCategory(
        key="3",
        label="Use a PGP (password or PGP key)",
        description="Asymmetric encryption using PGP/GPG",
        method_enum=EncryptionMethod.PGP,
        submenu_items={
            "1": SubMenuItem(
                key="1",
                label="Create new PGP key pair",
                handler_module="pgp",
                handler_method="generate_pgp_key_pair",
            ),
            "2": SubMenuItem(
                key="2",
                label="Import a PGP key",
                handler_module="pgp",
                handler_method="import_key",
            ),
            "3": SubMenuItem(
                key="3",
                label="ENCRYPT a file using PGP",
                handler_module="pgp",
                handler_method="_handle_pgp_process_file",
                handler_kwargs={"action": "encrypt"},
            ),
            "4": SubMenuItem(
                key="4",
                label="DECRYPT a file using PGP",
                handler_module="pgp",
                handler_method="_handle_pgp_process_file",
                handler_kwargs={"action": "decrypt"},
            ),
            "5": SubMenuItem(
                key="5",
                label="ENCRYPT all files in folder using PGP",
                handler_module="pgp",
                handler_method="_handle_pgp_process_folder",
                handler_kwargs={"action": "encrypt"},
            ),
            "6": SubMenuItem(
                key="6",
                label="DECRYPT all files in folder using PGP",
                handler_module="pgp",
                handler_method="_handle_pgp_process_folder",
                handler_kwargs={"action": "decrypt"},
            ),
            "7": SubMenuItem(
                key="7",
                label="Sign a document with PGP",
                handler_module="pgp",
                handler_method="pgp_sign_file",
            ),
            "8": SubMenuItem(
                key="8",
                label="Verify a PGP signature",
                handler_module="pgp",
                handler_method="pgp_verify_signature",
            ),
        }
    ),
    EncryptionMethod.XOR.value: MainMenuCategory(
        key="4",
        label="Use XOR",
        description="Simple XOR encryption for text strings",
        method_enum=EncryptionMethod.XOR,
        submenu_items={
            "1": SubMenuItem(
                key="1",
                label="ENCRYPT message string with XOR",
                handler_module="xor",
                handler_method="_handle_xor_process_msg",
                handler_kwargs={"action": "encrypt"},
            ),
            "2": SubMenuItem(
                key="2",
                label="DECRYPT message string with XOR",
                handler_module="xor",
                handler_method="_handle_xor_process_msg",
                handler_kwargs={"action": "decrypt"},
            ),
        }
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


# def get_menu_lines_for_category(
#         config: AppConfig,
#         category: str,
# ) -> List[str]:
#     """Build menu lines for a specific category.

#     Args:
#         config: AppConfig instance
#         category: MenuCategory enum value

#     Returns:
#         List of formatted menu line strings
#     """
#     lines = []

#     # Get display label from config
#     section_label = config.menu_categories.get(category, category)
#     lines.append(f"[{config.warning_color}]{section_label}")

#     # Filter items by category
#     for key in sorted(config.main_menu_items.keys()):
#         item = config.main_menu_items[key]
#         if item.category == category:
#             lines.append(f"[white][{key}] {item.label}")

#     return lines
