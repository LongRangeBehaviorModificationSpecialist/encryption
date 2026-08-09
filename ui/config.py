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


class MenuCategory(Enum):
    """Enumeration of menu categories for organized display."""
    KEY_BASED = "key_based"
    PASSWORD_AES = "password_aes"
    PGP = "pgp"
    XOR = "xor"
    UTILITY = "utility"


@dataclass
class MenuItem:
    """Represents a single menu item configuration."""
    key: str
    label: str
    description: Optional[str] = None
    category: str = field(default_factory=lambda: "utility")
    handler_module: Optional[str] = None  # Module/Object name
    handler_method: Optional[str] = None  # Method name
    handler_args: tuple = field(default_factory=tuple)
    handler_kwargs: Dict[str, Any] = field(default_factory=dict)
    handler_callable: Any = None

    def __post_init__(self):
        # Validate key is string and non-empty
        if not isinstance(self.key, str) or not self.key.strip():
            raise ValueError("Menu item key must be a non-empty string")


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
    header_style: str = "bold #2070b2"
    exit_text_color: str = "#d700d7"
    warning_color: str = "yellow3"
    success_color: str = "green3"

    # Continuation prompt settings
    continue_prompt_text: str = "Would you like to return to the main menu?"
    continue_prompt_default: str = "y"
    continue_prompt_choices: List[str] = field(
        default_factory=lambda: ["y", "n", ""]
    )
    show_separator_line: bool = False

    # Category display configuration
    menu_categories: Dict[str, str] = field(default_factory=lambda: {
        "key_based": "\nUse a .key file",
        "password_aes": "\nUse a password (AES.GCM)",
        "pgp": "\nUse PGP (password or PGP key)",
        "xor": "\nUse XOR",
        "utility": "Utility Functions",
    })

    # Category display order (controls section ordering)
    category_order: List[MenuCategory] = field(default_factory=lambda: [
        "key_based",
        "password_aes",
        "pgp",
        "xor",
    ])


    # MAIN MENU configuration
    menu_items: Dict[str, MenuItem] = field(default_factory=lambda: {
        "1": MenuItem(
            key="1",
            label="Create a new .key file",
            description="Create new .key file to encrypt/decrypt file(s)",
            category="key_based",
            handler_module="key",
            handler_method="generate_and_save_key",
            handler_kwargs={},
        ),
        "2": MenuItem(
            key="2",
            label="ENCRYPT a single file using a .key",
            description="",
            category="key_based",
            handler_module="key",
            handler_method="_handle_key_process_file",
            handler_kwargs={"action": FileAction.ENCRYPT},
        ),
        "3": MenuItem(
            key="3",
            label="DECRYPT a single file using a .key",
            description="",
            category="key_based",
            handler_module="key",
            handler_method="_handle_key_process_file",
            handler_kwargs={"action": FileAction.DECRYPT},
        ),
        "4": MenuItem(
            key="4",
            label="ENCRYPT all files in a folder using a .key",
            description="",
            category="key_based",
            handler_module="key",
            handler_method="_handle_key_process_folder",
            handler_kwargs={"action": FileAction.ENCRYPT},
        ),
        "5": MenuItem(
            key="5",
            label="DECRYPT all files in a folder using a .key",
            description="",
            category="key_based",
            handler_module="key",
            handler_method="_handle_key_process_folder",
            handler_kwargs={"action": FileAction.DECRYPT}
        ),
        "6": MenuItem(
            key="6",
            label="ENCRYPT a single file using a password",
            description="",
            category="password_aes",
            handler_module="aes",
            handler_method="_handle_aes_process_file",
            handler_kwargs={"action": FileAction.ENCRYPT},
        ),
        "7": MenuItem(
            key="7",
            label="DECRYPT a single file using a password",
            description="",
            category="password_aes",
            handler_module="aes",
            handler_method="_handle_aes_process_file",
            handler_kwargs={"action": FileAction.DECRYPT},
        ),
        "8": MenuItem(
            key="8",
            label="ENCRYPT all files in a folder using a password",
            description="",
            category="password_aes",
            handler_module="aes",
            handler_method="_handle_aes_process_folder",
            handler_kwargs={"action": FileAction.ENCRYPT},
        ),
        "9": MenuItem(
            key="9",
            label="DECRYPT all files in a folder using a password",
            description="",
            category="password_aes",
            handler_module="aes",
            handler_method="_handle_aes_process_folder",
            handler_kwargs={"action": FileAction.DECRYPT},
        ),
        "10": MenuItem(
            key="10",
            label="Create new PGP key pair",
            description="",
            category="pgp",
            handler_module="pgp",
            handler_method="generate_pgp_key_pair",
            handler_kwargs={},
        ),
        "11": MenuItem(
            key="11",
            label="Import a PGP key",
            description="",
            category="pgp",
            handler_module="pgp",
            handler_method="import_key",
            handler_kwargs={},
        ),
        "12": MenuItem(
            key="12",
            label="ENCRYPT a file using PGP",
            description="",
            category="pgp",
            handler_module="pgp",
            handler_method="_handle_pgp_process_file",
            handler_kwargs={"action": FileAction.ENCRYPT},
        ),
        "13": MenuItem(
            key="13",
            label="DECRYPT a file using PGP",
            description="",
            category="pgp",
            handler_module="pgp",
            handler_method="_handle_pgp_process_file",
            handler_kwargs={"action": FileAction.DECRYPT},
        ),
        "14": MenuItem(
            key="14",
            label="ENCRYPT all files in a folder using PGP",
            description="",
            category="pgp",
            handler_module="pgp",
            handler_method="_handle_pgp_process_folder",
            handler_kwargs={"action": FileAction.ENCRYPT},
        ),
        "15": MenuItem(
            key="15",
            label="DECRYPT all files in a folder using PGP",
            description="",
            category="pgp",
            handler_module="pgp",
            handler_method="_handle_pgp_process_folder",
            handler_kwargs={"action": FileAction.DECRYPT},
        ),
        "16": MenuItem(
            key="16",
            label="Sign a document with PGP",
            description="",
            category="pgp",
            handler_module="pgp",
            handler_method="pgp_sign_file",
            handler_kwargs={},
        ),
        "17": MenuItem(
            key="17",
            label="Verify a PGP signature",
            description="",
            category="pgp",
            handler_module="pgp",
            handler_method="pgp_verify_signature",
            handler_kwargs={},
        ),
        "18": MenuItem(
            key="18",
            label="ENCRYPT message string with XOR",
            description="",
            category="xor",
            handler_module="xor",
            handler_method="_handle_xor_process_msg",
            handler_kwargs={"action": FileAction.ENCRYPT},
        ),
        "19": MenuItem(
            key="19",
            label="DECRYPT message string with XOR",
            description="",
            category="xor",
            handler_module="xor",
            handler_method="_handle_xor_process_msg",
            handler_kwargs={"action": FileAction.DECRYPT},
        ),
    })

    # Special actions (exit, help, etc.)
    special_actions: Dict[str, str] = field(default_factory=lambda: {
        "q": "EXIT",
        "Q": "EXIT",
        "?": "HELP",
        "h": "HELP",
        "H": "HELP"
    })


def get_menu_lines_for_category(
        config: AppConfig,
        category: str,
) -> List[str]:
    """Build menu lines for a specific category.

    Args:
        config: AppConfig instance
        category: MenuCategory enum value

    Returns:
        List of formatted menu line strings
    """
    lines = []

    # Get display label from config
    section_label = config.menu_categories.get(category, category)
    lines.append(f"[{config.warning_color}]{section_label}")

    # Filter items by category
    for key in sorted(config.menu_items.keys()):
        item = config.menu_items[key]
        if item.category == category:
            lines.append(f"[white][{key}] {item.label}")

    return lines


def get_exit_message(config: AppConfig) -> str:
    """Print exit confirmation message then exit app."""
    c.print(
        f"\n[bold {config.exit_text_color}]-> Exiting {config.app_name}... "
        "Goodbye!\n"
    )
    sys.exit(0)


#! ------------------------------------
#!  VERIFICATIONS CHECKS
#!
#!  Option "1"  -- tested 08-09 / working
#!  Option "2"  --
#!  Option "3"  --
#!  Option "4"  --
#!  Option "5"  --
#!  Option "6"  --
#!  Option "7"  --
#!  Option "8"  --
#!  Option "9"  --
#!  Option "10" --
#!  Option "11" --
#!  Option "12" --
#   TODO -- add passphrase verification for symmetric encryption option
#!  Option "13" --
#!  Option "14" --
#!  Option "15" --
#!  Option "16" --
#!  Option "17" --
#!  Option "18" --
#!  Option "19" --
#!  Option "q"  --
#!