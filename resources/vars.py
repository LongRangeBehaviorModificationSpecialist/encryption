#!/usr/bin/env python3

ENCRYPTED_EXT_LIST = {
    ".encrypted", ".enc", ".asc", ".pgp", ".gpg", ".key", "xor"
}

SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv"
}

ICONS = {
    "arrow_right": "➡️",
    "checkmark": "✓",  # {ICONS['checkmark']}
    "confirm": "🔁",
    "email": "📧",
    "encrypted": "🔐",
    "decrypted": "🔓",
    "failure": "❌",
    "file": "📄",
    "folder": "📁",
    "info": "ℹ️",
    "input": "📝",
    "key": "🗝️",
    "keyboard": "⌨️",
    "label": "🏷️",
    "processing": "⏳",
    "question": "❓",
    "shield": "🛡️",
    "success": "✅",
    "tray_in": "📥",
    "tray_out": "📤",
    "warning": "⚠️",
}
