ENCRYPTED_EXT_LIST = {
    ".encrypted", ".enc", ".asc", ".pgp", ".gpg", ".key", "xor"
}

SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv"
}

STATUS_ICONS = {
    "arrow_right": "➡️",  # {STATUS_ICONS['arrow_right']}
    "checkmark": "✓",  # {STATUS_ICONS['checkmark']}
    "confirm": "🔁",  # {STATUS_ICONS['confirm']}
    "email": "📧",  # {STATUS_ICONS['email']}
    "encrypted": "🔐",  # {STATUS_ICONS['encrypted']}
    "decrypted": "🔓",  # {STATUS_ICONS['decrypted']}
    "failure": "❌",  # {STATUS_ICONS['failure']}
    "file": "📄",  # {STATUS_ICONS['file']}
    "folder": "📁",  # {STATUS_ICONS['folder']}
    "info": "ℹ️",  # {STATUS_ICONS['info']}
    "input": "📝",  # {STATUS_ICONS['input']}
    "key": "🗝️",  # {STATUS_ICONS['key']}
    "keyboard": "⌨️",  # {STATUS_ICONS['keyboard']}
    "label": "🏷️",  # {STATUS_ICONS['label']}
    "processing": "⏳",  # {STATUS_ICONS['processing']}
    "question": "❓",  # {STATUS_ICONS['question']}
    "shield": "🛡️",  # {STATUS_ICONS['shield']}
    "success": "✅",  # {STATUS_ICONS['success']}
    "tray_in": "📥",  # {STATUS_ICONS['tray_in']}
    "tray_out": "📤",  # {STATUS_ICONS['tray_out']}
    "warning": "⚠️",  # {STATUS_ICONS['warning']}
}

"""
console.print(f"[green]{STATUS_ICONS['success']}[/] Processed: {filename}")
console.print(f"[red]{STATUS_ICONS['failure']}[/] Failed: {filename}")
console.print(f"[yellow]{STATUS_ICONS['warning']}[/] Skipping empty directory")

"""