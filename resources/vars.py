ENCRYPTED_EXT_LIST = {
    ".encrypted", ".enc", ".asc", ".pgp", ".gpg", ".key", "xor"
}

SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv"
}

STATUS_ICONS = {
    "arrow_right": "➡️",  # {STATUS_ICONS['arrow_right']}
    "encrypted": "🔐",  # {STATUS_ICONS['encrypted']}
    "decrypted": "🔓",  # {STATUS_ICONS['decrypted']}
    "failure": "✗",
    "failure2": "❌",  # {STATUS_ICONS['failure2']}
    "file": "📄",  # {STATUS_ICONS['file']}
    "folder": "📁",  # {STATUS_ICONS['folder']}
    "info": "ℹ️",  # {STATUS_ICONS['info']}
    "key": "🔑",  # {STATUS_ICONS['key']}
    "keyboard": "⌨️",  # {STATUS_ICONS['keyboard']}
    "processing": "⏳",  # {STATUS_ICONS['processing']}
    "question": "❓",  # {STATUS_ICONS['question']}
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