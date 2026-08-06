from pathlib import Path
import os
import sys

def get_gpg_default_storage() -> dict:
    """Return GPG storage paths for the current platform."""
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA", str(Path.home() / ".gnupg"))
        homedir = Path(appdata) / "gnupg"
    else:
        homedir = Path.home() / ".gnupg"

    return {
        "homedir": str(homedir.resolve()),
        "public_keys": str(homedir / "pubring.kbx"),
        "private_keys": str(homedir / "private-keys-v1.d"),
        "trust_db": str(homedir / "trustdb.gpg"),
        "gpg_agent": str(homedir / "S.gpg-agent"),
    }

# Usage
paths = get_gpg_default_storage()
print(f"Public keys: {paths['public_keys']}")
print(f"Private keys: {paths['private_keys']}")