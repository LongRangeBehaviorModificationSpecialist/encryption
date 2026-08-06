# !/usr/bin/env python3
# DLU : 06-Aug-2026


# Import the console object from the main __init__.py file
from . import console
from resources.vars import ENCRYPTED_EXT_LIST, STATUS_ICONS
from resources.functions import Functions
from resources.prompts import (
    show_main_menu,
    show_pgp_menu
)

from enum import StrEnum
import os
from pathlib import Path
import shutil
import sys
from typing import List
from rich.prompt import Prompt
from rich.traceback import install

HAS_PGP = False
try:
    from gnupg import GPG
    HAS_PGP = True
except ImportError:
    console.print(
        f"{STATUS_ICONS['warning']}[yellow3] Missing dependency: "
        "currently missing the 'python-gnupg' package.\n"
        "It can be installed using the 'pip install python-gnupg' command"
    )
    sys.exit(1)


install(show_locals=True)


class Action(StrEnum):
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"


class PGP:

    _PGP_ACTION_MAP = {
        "2": (Action.ENCRYPT, "single"),
        "3": (Action.DECRYPT, "single"),
        "4": (Action.ENCRYPT, "folder"),
        "5": (Action.DECRYPT, "folder")
    }


    def __init__(self, password: str | None = None):
        """Initialize with explicit homedir tracking."""
        # Get path of the gpg executable
        self.resolved_gpg = (
            shutil.which("gpg")
            or r"C:\Program Files\GnuPG\bin\gpg.exe"
        )
        if not self.resolved_gpg and not Path(self.resolved_gpg).exists():
            console.print(
                f"{STATUS_ICONS['warning']}[yellow3] GnuPG binary not found "
                f"at '{self.resolved_gpg}'. Please install GnuPG."
            )
            raise FileNotFoundError

        # Calculate homedir independently of GPG instance
        self.gpg_homedir = self._get_gpg_homedir()

        # Pass explicit homedir to GPG constructor
        self.gpg = GPG(
            gnupghome=str(self.gpg_homedir),
            gpgbinary=self.resolved_gpg,
        )

        # Optional: ensure directory exists
        self.gpg_homedir.mkdir(parents=True, exist_ok=True)

        # You now have reliable access without querying gpg.gnupghome
        console.print(
            f"{STATUS_ICONS['success']}[green3] GPG initialized "
            f"with: {self.gpg_homedir}"
        )

        # Public keyring
        self.pubring_path = self.gpg_homedir / "public-keys-v1.d"

        # Private keys directory
        self.private_keys_dir = self.gpg_homedir / "private-keys-v1.d"

        # Trust database
        self.trustdb_path = self.gpg_homedir / "trustdb.gpg"

        # GPG agent socket
        self.agent_socket = self.gpg_homedir / "S.gpg-agent"

        # Check if files exist
        if self.pubring_path.exists():
            console.print(
                f"[green]✓ Public keyring found: {self.pubring_path}"
            )
        else:
            console.print(
                f"[yellow]⚠ No public keyring at: {self.pubring_path}"
            )

        self.script_path = Path(__file__).parents[1].resolve()

        self.gpg.encoding = "utf-8"
        self._recipient_fp: str | None = None
        self._key_imported = False
        self._armored = False
        self._symmetric = False
        self._password = password

        if os.name == "posix":
            os.chmod(self.gnupg_home, 0o700)

        self.default_public_key_file = (
            self.script_path /
            f"{Functions.get_date_time(format='file')}_mas_public_key.asc"
        )
        self.default_private_key_file = (
            self.script_path /
            f"{Functions.get_date_time(format='file')}_mas_private_key.asc"
        )


    def _get_gpg_homedir(self) -> Path:
        """Determine GPG home directory from env var or system default."""
        env_home = os.environ.get("GNUPGHOME")
        if env_home:
            return Path(env_home).resolve()

        if os.name == "nt":  # Windows
            appdata = os.environ.get("APPDATA")
            if appdata:
                return Path(appdata) / "gnupg"
            else:
                return Path.home() / ".gnupg"
        else:  # Linux/macOS
            return Path.home() / ".gnupg"



    # @property
    # def gpg(self) -> GPG:
    #     if self._gpg is None:
    #         self._init_gpg()
    #     return self._gpg


    # def _init_gpg(self) -> None:
        # kwargs = {}
        # if self.gpg_home:
        #     kwargs["gnupghome"] = self.gpg_home
        # self._gpg = GPG(**kwargs)


    def print_status(self, action: str, status: GPG) -> None:
        """Prints GPG action execution status to terminal."""
        if status.ok == True:
            console.print(
                f"{STATUS_ICONS['success']}[green3] File {action}ion was "
                f"successful : {status.stderr}"
            )
        else:
            status_msg = getattr(
                status,
                "status",
                getattr(status, "stderr", "Unknown Error")
            )
            console.print(
                f"{STATUS_ICONS['failure']}[red] File encryption WAS NOT "
                f"successful : {status_msg}. Please try again."
            )


    def import_key(self, key_path: Path | str) -> bool:
        """Import a PGP public or private key from an external file.
        Returns True on success.
        """
        try:
            with open(key_path, "r", encoding="utf-8") as fh:
                key_data = fh.read()
        except OSError as e:
            console.print(
                f"{STATUS_ICONS['failure']}[red] Cannot read key file "
                f"\"{key_path}\" : {e}"
            )
            return False

        result = self.gpg.import_keys(key_data)

        if result.count == 0:
            console.print(
                f"{STATUS_ICONS['failure']}[red] No keys imported — the file "
                "may not contain a valid PGP key."
            )
            return False

        self._recipient_fp = result.fingerprints[0]
        self._key_imported = True
        console.print(
            f"{STATUS_ICONS['success']}[green3] Imported key fingerprint : "
            f"{self._recipient_fp}"
        )
        console.print(
            f"{STATUS_ICONS['file']}[cyan] Full import result : "
            f"{result.summary()}"
        )
        return True


    def is_symmetric(self) -> bool:
        """Check if the instance is configured for symmetric mode."""
        return self._symmetric


    def _get_passphrase(
            self,
            force_new: bool = False,
            purpose: str = "operation",
            confirm: bool = True,
    ) -> str | None:
        """Obtain passphrase via secure getpass prompt or reuse cached value.

        Args:
            force_new: If True, always prompt even if passphrase is cached.
            purpose: Description of what the passphrase is for (logging).
            confirm: If True, prompt twice to confirm the passphrase.
        """
        if self._password is not None and not force_new:
            console.print(
                f"{STATUS_ICONS['info']}[white] Using cached passphrase "
                f"for {purpose}"
            )
            return self._password

        attempts_left = 3
        while attempts_left > 0:
            if confirm:
                password1 = Prompt.ask(
                    f"{STATUS_ICONS['key']}[white] Enter passphrase for "
                    f"{purpose} ",
                    password=True
                )
                password2 = Prompt.ask(
                    f"{STATUS_ICONS['key']}[white] Confirm passphrase for "
                    f"{purpose} ",
                    password=True
                )

                if password1 != password2:
                    console.print(
                        f"{STATUS_ICONS['failure']}[red] Passphrases did "
                        "not match"
                    )
                    attempts_left -= 1
                    console.print(
                        f"{STATUS_ICONS['warning']}[yellow3] {attempts_left} "
                        "attempt(s) remaining"
                    )
                    continue
            else:
                password1 = Prompt.ask(
                    f"{STATUS_ICONS['key']}[white] Enter passphrase for "
                    f"{purpose} ",
                    password=True
                )
                if len(password1) < 1:
                    console.print(
                        f"{STATUS_ICONS['warning']}[yellow3] An empty "
                        "passphrase not allowed."
                    )
                    attempts_left -= 1
                    continue

            console.print(
                f"{STATUS_ICONS['success']}[white] Passphrase accepted for "
                f"{purpose}"
            )
            self._password = password1
            return password1

        console.print(
            f"{STATUS_ICONS['failure']}[red] Too many failed passphrase "
            f"attempts for {purpose}"
        )
        return None


    def clear_passphrase(self) -> None:
        """Clear any cached passphrase from memory (after sensitive ops)."""
        self._password = None
        console.print(
            f"{STATUS_ICONS['info']}[white] Cleared cached passphrase "
            "from memory"
        )


    def pgp_export_public_key(
            self,
            keyid: str,
            output_path: Path | str | None = None,
    ) -> str:
        """Exports an armored public key by Key ID to the designated file path.

        Args:
            keyid: ID or fingerprint of the PGP key to export.

        Returns:
            str: The exported ASCII-armored public key block.
        """
        output_file = (
            Path(output_path).resolve()
            if output_path
            else self.default_public_key_file
        )

        public_key_data = self.gpg.export_keys(
            keyids=[keyid],  # Must be a list, not bare string
            armor=True,
        )

        if not public_key_data:
            console.print(
                f"{STATUS_ICONS['failure']}[red] Failed to export public key "
                f"for Key ID : {keyid}"
            )
            raise
        # RuntimeError(f"{STATUS_ICONS['failure']}[red] Failed to export public key ID: {keyid}")

        try:
            with open(output_file, "w", newline="\n", encoding="utf-8") as f:
                f.write(public_key_data)
        except Exception as e:
            console.print(
                f"{STATUS_ICONS['failure']}[red] Failed to write key to "
                f"{output_file}: {e}"
            )
            raise

        console.print(
            f"{STATUS_ICONS['success']}[white] [bold]Public[/bold] key exported "
            f"successfully to -> {output_file}"
        )

        return public_key_data


    def pgp_export_private_key(
            self,
            keyid: str,
            passphrase: str,
            output_path: Path | str | None = None
    ) -> str:
        """Exports an armored private key by Key ID and passphrase to the
        designated file path.

        Args:
            keyid: ID or fingerprint of the PGP key to export.
            password: Passphrase protecting the private key.
            output_path: Destination file for exported key. If None,
                uses default.

        Returns:
            str: The exported ASCII-armored private key block.
        """
        output_file = (
            Path(output_path).resolve()
            if output_path
            else self.default_private_key_file
        )

        private_key_data = self.gpg.export_keys(
            keyids=[keyid],
            secret=True,
            armor=True,
            passphrase=passphrase,
            )

        if not private_key_data:
            console.print(
                f"{STATUS_ICONS['failure']}[red] Failed to export private key "
                f"for Key ID : {keyid}. Check the keyid/passphrase."
            )
            raise
        # RuntimeError(f"Failed to export private key ID {keyid}. ")

        try:
            with open(output_file, "w", newline="\n", encoding="utf-8") as f:
                f.write(private_key_data)
            if os.name != "nt":
                os.chmod(str(output_file), 0o600)  # Owner read/write only
        except Exception as e:
            console.print(
                f"{STATUS_ICONS['failure']}[red] Failed to write key to "
                f"{output_file}: {e}"
            )
            raise

        console.print(
            f"{STATUS_ICONS['success']}[white] [bold]Private[/bold] key "
            f"exported successfully to -> {output_file}"
        )

        return private_key_data


    def generate_pgp_key_pair(self, key_length: int = 4096) -> str:
        """Generates a new RSA PGP key pair and exports public/private keys.

        Must use 'self.gpg_homedir' (not gpg.gnupghome) within the code.

        Args:
            key_length: Bit length of the RSA key (default: 4096).
            expire_days: Key expiration in days. If None, key never expires.

        Returns:
            str: Fingerprint of the newly created key pair.
        """
        full_name = Functions.get_pgp_full_name()
        email_address = Functions.get_pgp_email_address()
        password = Functions.get_confirmed_password()

        # Optional: Add a comment field
        comment = Prompt.ask(
            f"{STATUS_ICONS['file']}[white] Enter a comment (optional, "
            "e.g., 'Work Key')",
            default=""
        ).strip()

        key_params = {
            "name_real": full_name,
            "name_email": email_address,
            "passphrase": password,
            "key_type": "RSA",
            "key_length": key_length,
        }

        if comment:
            key_params["name_comment"] = comment

        expire_value  = Functions.get_pgp_key_expire_date()

        # In generate_pgp_key_pair()
        if expire_value:
            # Check if it's already GNU format (ends with letter)
            if isinstance(expire_value, str) and expire_value[-1].isalpha():
                # GNU format: "365d", "1y", "6m" - works perfectly!
                key_params["Expire-Date"] = expire_value
                console.print(
                    f"[cyan]Key expires: {expire_value}"
                )
            else:
                if isinstance(expire_value, str):
                    try:
                        key_params["Expire-Date"] = expire_value
                        console.print(
                            f"[cyan]Key expires: {expire_value}"
                        )
                    except ValueError:
                        console.print(
                            f"{STATUS_ICONS['warning']}[yellow] Invalid date "
                            "format."
                        )
                        del key_params["Expire-Date"]

                key_params["Expire-Date"] = expire_value
                console.print(f"[cyan]Key expires: {expire_value[:10]}")

        input_data = self.gpg.gen_key_input(**key_params)

        key = self.gpg.gen_key(input_data)

        if not key.fingerprint:
            console.print(
                f"{STATUS_ICONS['failure']}[red] PGP key generation failed : "
                f"{key.stderr}"
            )
            raise RuntimeError("PGP key generation failed.")

        keyid = str(key.fingerprint)

        # Display key summary information
        console.print(
            f"{STATUS_ICONS['success']}[white] Generated PGP key pair "
            "successfully"
        )

        console.print(
            f"\n"
            f"[cyan]  Name         :  {full_name}"
            f"[cyan]  Comment      :  {comment}"
            f"[cyan]  Email        :  {email_address}"
            f"[cyan]  Fingerprint  :  {keyid}")

        if expire_value is None:
            # No expiration set
            console.print(
            f"[cyan]  Expires      :  Never")
        elif isinstance(expire_value, int):
            console.print(
            f"[cyan]  Expires      :  {expire_value} (in {expire_value} days)"
            )
        elif isinstance(expire_value, str):
            # Date-based expiry (absolute)
            console.print(
            f"[cyan]  Expires      :  {expire_value}")

        console.print(
            f"{STATUS_ICONS['success']}[white] Generated Key Fingerprint : "
            f"{keyid}"
        )

        export_keys = Prompt.ask(
            f"{STATUS_ICONS['question']}[white] Do you want to export the "
            "newly created PGP keys? ",
            choices=["y","n"],
            show_choices=True
        )

        if export_keys:
            # Export keys upon successful generation
            self.pgp_export_public_key(keyid=keyid)
            self.pgp_export_private_key(
                keyid=keyid,
                passphrase=password,
            )
            return keyid
        else:
            return keyid


    def _handle_pgp_process_file(self, action: Action) -> None:
        """Collect user inputs and call pgp_process_file."""
        # Email address (required for public-key encryption)
        email_input = Prompt.ask(
            f"{STATUS_ICONS['keyboard']}[white] Enter recipient email "
            "address(es) "
        ).strip()

        if not email_input:
            console.print(
                f"{STATUS_ICONS['warning']}[yellow3] No email address provided."
            )
            return

        email_address = [addr.strip() for addr in email_input.split(",")]

        # Password -> required for symmetric encryption or decryption
        if action == Action.ENCRYPT:
            confirm = Prompt.ask(
                f"{STATUS_ICONS['question']}[white] Use symmetric (password "
                f"only) encryption? ",
                choices=["y", "n"],
                show_choices=True
            )
            if confirm:
                password = Functions.get_password()
                if not password:
                    console.print(
                        f"{STATUS_ICONS['warning']}[yellow3] Password required "
                        "for symmetric encryption."
                    )
                    return

                symmetric = True
                armored = Prompt.ask(
                    f"{STATUS_ICONS['question']}[white] Use ASCII-armored "
                    "output (.asc)? ",
                    choices=["y", "n"],
                    show_choices=True
                )
            else:
                # Will prompt GPG for private key passphrase
                password = None
                symmetric = False
                armored = Prompt.ask(
                    f"{STATUS_ICONS['question']}[white] Use ASCII-armored "
                    "output (.asc)? ",
                    choices=["y", "n"],
                    show_choices=True
                )
        else:  # Decrypt
            confirm = Prompt.ask(
                f"{STATUS_ICONS['question']}[white] Do you want to provide a "
                "passphrase now? (leave blank for GPG prompt) ",
                choices=["y", "n", ""],
                show_choices=True
            )
            if confirm:
                password = Prompt.ask(
                    f"{STATUS_ICONS['key']}[white] Enter passphrase for "
                    "decryption ",
                    password=True
                )
            else:
                password = None
            symmetric = None  # Auto-detect from file

        # Output path (optional)
        output_path_input = Prompt.ask(
            f"{STATUS_ICONS['keyboard']}[white] Enter output path (leave "
            "blank for default) ",
        ).strip("\"'")
        output_path = (
            Path(output_path_input).resolve()
            if output_path_input else None
        )

        # Get target file
        target_file = Functions.get_file_path()
        if not target_file:
            return

        # Process the file
        try:
            result = self.pgp_process_file(
                target_file=target_file,
                action=action.value,
                email_address=email_address,
                output_path=output_path,
                armored=armored,
                symmetric=symmetric,
                password=password,
                always_trust=True,
            )
            console.print(
                f"{STATUS_ICONS['success']}[green3] Successfully processed : "
                f"{result}"
            )
        except Exception as e:
            console.print(
                f"{STATUS_ICONS['failure']}[red] Operation failed : {e}"
            )


    def _handle_pgp_process_folder(self, action: Action) -> None:
        """Collect user inputs and call pgp_process_folder."""
        # Target directory
        target_dir = Functions.get_directory_path()
        if not target_dir:
            return

        # Recursive option
        recursive = Functions.select_recursive_option()

        # Email address (required for public-key encryption)
        email_input = Prompt.ask(
            f"{STATUS_ICONS['keyboard']}[white] Enter recipient email "
            "address(es) (comma-separated) "
        ).strip()

        if not email_input and action == Action.ENCRYPT:
            console.print(
                f"{STATUS_ICONS['warning']}[yellow3] No email provided."
            )
            confirm = Prompt.ask(
                f"{STATUS_ICONS['question']}[white] Proceed with symmetric "
                "encryption instead? ",
                choices=["y", "n"],
                show_choices=True
            )
            if confirm:
                email_input = None
                symmetric = True
            else:
                return
        else:
            symmetric = None

        email_address = None
        if email_input:
            email_address = [addr.strip() for addr in email_input.split(",")]

        # Password (required for symmetric encryption)
        if symmetric:
            password =Prompt.ask(
                f"{STATUS_ICONS['keyboard']}[white] Enter passphrase for "
                "encryption "
            )
            if not password:
                console.print(
                    f"{STATUS_ICONS['warning']}[yellow3] Passphrase required "
                    "for symmetric encryption."
                )
                return
        elif action == Action.DECRYPT:
            confirm = Prompt.ask(
                f"{STATUS_ICONS['question']}[white] Do you want to provide a "
                "passphrase now? (leave blank for GPG prompt) ",
                choices=["y", "n"],
                show_choices=True
            )
            if confirm:
                password = Prompt.ask(
                    f"{STATUS_ICONS['keyboard']}[white] Enter passphrase for "
                    "processing ",
                    password=True
                )
            else:
                password = None
        else:
            password = None

        # Armored option
        armored = Prompt.ask(
            f"{STATUS_ICONS['question']}[white] Use ASCII-armored output "
            "(.asc)? ",
            choices=["y", "n"],
            show_choices=True
        )

        # Process the directory
        try:
            results = self.pgp_process_folder(
                target_dir=target_dir,
                action=action.value,
                email_address=email_address,
                password=password,
                recursive=recursive,
                armored=armored,
                symmetric=symmetric,
                always_trust=True,
            )

            console.print(
                f"{STATUS_ICONS['success']}[green3] Completed processing "
                f"{len(results)} files."
            )
        except Exception as e:
            console.print(
                f"{STATUS_ICONS['failure']}[red] Operation failed : {e}")


    def pgp_process_file(
            self,
            target_file: Path | str,
            action: str,
            email_address: str | List[str],
            output_path: Path | str | None = None,
            armored: bool | None = None,
            symmetric: bool | None = None,
            password: str | None = None,
            always_trust: bool = True,
    ) -> Path:
        """Encrypts a single file using PGP/GPG and handles GPG engine
        failures safely.

        Args:
            target_file: Path to the plaintext source.
            action: Operational mode, either 'encrypt' or 'decrypt'.
            email_address: Recipient email or key ID(s). Required for public-key
                encryption. Ignored for symmetric encryption.
            output_path: Where to write the ciphertext. If None, derived from
                input
            armored: True → ASCII-armored (.asc); False → binary (.gpg).
                If None, uses the instance default.
            symmetric: True → password-only encryption; False → public-key
                encryption. If None, uses the instance default
                (self.default_symmetric).
            password: Password for symmetric encryption or private key. If
                None, will be prompted interactively.
            always_trust: Trust all public keys without verification.

        Returns:
            Path: Path to the resulting encrypted or decrypted file.

        Raises:
            FileNotFoundError: If target file or key file does not exist.
            ValueError: If a valid key ID is not provided
        """
        target_file = Path(target_file).resolve()

        if not target_file.is_file():
            console.print(
                f"{STATUS_ICONS['failure']}[red] {target_file.name} does not "
                "exist or is a directory."
            )
            raise FileNotFoundError(f"Invalid target file : {target_file}")

        action = action.lower().strip()

        # Resolve instance defaults for symmetric and armored
        use_symmetric = symmetric if symmetric is not None else getattr(
            self, "_symmetric", False)
        use_armored = armored if armored is not None else getattr(
            self, "_armored", False)

        # Normalize recipients input to a list
        if email_address and isinstance(email_address, str):
            email_address = [email_address]

        # Validate: public-key encryption requires recipients
        if action == "encrypt" and not use_symmetric:
            if not email_address:
                console.print(
                    f"{STATUS_ICONS['warning']}[yellow3] At least one recipient "
                    "email or key ID must be provided for public-key "
                    "encryption. Use symmetric=True for password-only "
                    "encryption."
                )
                raise ValueError

        # Validate: symmetric encryption requires a password
        if action == "encrypt" and use_symmetric and not password:
            console.print(
                f"{STATUS_ICONS['warning']}[yellow3]A password is required for "
                "symmetric encryption."
            )
            raise ValueError

        try:
            console.print(
                f"{STATUS_ICONS['file']}[white] Reading file : "
                f"{target_file.name}..."
            )

            if action == "encrypt":
                # Determine output extension based on armored mode
                ext = ".asc" if use_armored else ".pgp"
                output_file = (
                    Path(output_path).resolve()
                    if output_path
                    else target_file.with_name(f"{target_file.name}.{ext}")
                )

                with open(target_file, "rb") as f:
                    console.print(
                        f"{STATUS_ICONS['info']}[white] {action.capitalize()}ing "
                        "file data..."
                    )
                    if use_symmetric:
                        # Symmetric: password-only, no recipients needed
                        status = self.gpg.encrypt_file(
                            f,
                            symmetric=True,
                            passphrase=password,
                            armor=use_armored,
                            output=str(output_file),
                        )
                    else:
                        # Public key -> use recipient keys
                        status = self.gpg.encrypt_file(
                            f,
                            recipients=email_address,
                            always_trust=always_trust,
                            armor=use_armored,
                            output=str(output_file),
                        )
            else:
                if target_file.suffix in {".pgp", ".asc", ".gpg"}:
                    output_file = (
                        Path(output_path).resolve()
                        if output_path
                        else target_file.with_suffix("")
                    )
                else:
                    output_file = (
                        Path(output_path).resolve()
                        if output_path
                        else target_file.with_name(
                            f"{target_file.name}.decrypted")
                    )

                with open(target_file, "rb") as f:
                    status = self.gpg.decrypt_file(
                        f,
                        passphrase=password,
                        output=str(output_file),
                    )

        except Exception as e:
            console.print(
                f"{STATUS_ICONS['failure']}[red] Failed to execute GPG "
                f"{action}ion: {e}"
            )
            raise RuntimeError

        if not status.ok:
            # Clean up partial/empty output file if created
            if output_file.exists():
                output_file.unlink(missing_ok=True)

            error_msg = getattr(
                status, "status", getattr(status, "status", "Unknown GPG error")
            )
            console.print(
                f"{STATUS_ICONS['failure']}[red] PGP {action.title()}ion "
                f"failed for '{target_file.name}'. GPG status: {error_msg}"
            )
            raise RuntimeError

        if hasattr(self, "print_status"):
            self.print_status(status)

        console.print(
            f"{STATUS_ICONS['success']}[green3] PGP file {action}ed "
            f"successfully : {output_file.name}"
        )

        return output_file


    def pgp_process_folder(
            self,
            target_dir: Path | str,
            action: str,
            email_address: str | list[str] | None = None,
            password: str | None = None,
            recursive: bool = False,
            armored: bool | None = None,
            symmetric: bool | None = None,
            always_trust: bool = True,
    ) -> List[Path]:
        """Encrypts or decrypts all discovered assets within a target
        directory.

        Args:
            target_dir: Path to the directory containing files.
            action: Either 'encrypt' or 'decrypt'.
            email_address: Recipient email or key ID(s). Required for public-key
                encryption. Ignored for symmetric encryption.
            password: Passphrase for symmetric encryption or private key
                decryption. If None, will be prompted interactively.
            recursive: Traverse the target_dir and process files in sub-folders.
            armored: True → ASCII-armored (.asc); False → binary (.pgp/.gpg).
                If None, uses the instance default.
            symmetric: True → password-only encryption; False → public-key
                encryption. If None, uses the instance default.
            always_trust: Trust all public keys without verification.

        Returns:
            List[Path]: List of successfully processed file paths.
        """
        action = action.lower().strip()
        target_dir = Path(target_dir).resolve()

        if not Functions.verify_is_directory(target_dir=target_dir):
            return []

        # Resolve instance defaults
        use_symmetric = symmetric if symmetric is not None else getattr(
            self, "_symmetric", False)
        use_armored = armored if armored is not None else getattr(
            self, "_armored", False)

        # Normalize recipients
        if email_address and isinstance(email_address, str):
            email_address = [email_address]

        # Validate: public-key encryption requires recipients
        if action == "encrypt" and not use_symmetric and not email_address:
            console.print(
                f"{STATUS_ICONS['failure']}[red] At least one recipient email "
                "or key ID must be provided for public-key encryption. Use "
                "symmetric=True for password-only encryption."
            )
            raise ValueError

        # Determine expected encrypted extensions based on armored mode
        encrypted_exts = (
            {".asc", ".pgp", ".gpg"}
            if use_armored else {".pgp", ".gpg"}
        )

        try:
            # Dynamically filter files based on the requested action
            files_iterator = (
                target_dir.rglob("*")
                if recursive else target_dir.iterdir()
            )

            if action == "decrypt":
                all_files = [
                    f for f in files_iterator
                    if f.is_file() and f.suffix in encrypted_exts
                ]
            else:
                # Encrypt files EXCEPT those ending with certain extensions
                all_files = [
                    f for f in files_iterator
                    if f.is_file()
                    and f.suffix.lower() not in ENCRYPTED_EXT_LIST
                ]

        except Exception as e:
            console.print(
                f"{STATUS_ICONS['failure']}[red] Failed to retrieve files "
                f"from {target_dir} : {e}"
            )
            return []

        if not all_files:
            console.print(
                f"{STATUS_ICONS['warning']}[yellow3] No valid files to "
                f"{action} in {target_dir}"
            )
            return []

        successful_files: List[Path] = []
        failed_files: List[Path] = []

        for file_path in all_files:
            try:
                processed_path = self.pgp_process_file(
                    target_file=file_path,
                    action=action,
                    email_address=email_address,
                    armored=use_armored,
                    symmetric=use_symmetric,
                    password=password,
                    always_trust=always_trust,
                )
                successful_files.append(processed_path)
            except Exception as e:
                console.print(
                    f"{STATUS_ICONS['failure']}[red] Error during {action}ing "
                    f"{file_path.name} : {e}"
                )
                failed_files.append(file_path)

        # Summary reporting
        if successful_files:
            console.print(
                f"{STATUS_ICONS['success']}[green3] Action Completed\n"
                f"Successfully {action}ed {len(successful_files)} files in "
                f"{target_dir} :"
            )
            for processed_file in successful_files:
                console.print(f"[green3]  {processed_file.name}")

        if failed_files:
            console.print(
                f"{STATUS_ICONS['failure']}[red] Warning\n"
                f"Failed to {action} {len(failed_files)} files :"
            )
            for failed_file in failed_files:
                console.print(f"[red]  {failed_file.name}")

        return successful_files


    def pgp_sign_file (
            self,
            target_file: Path | str,
            signer_email: str,
            password: str,
            detached: bool = True,
            clearsign: bool = False,
            armored: bool | None = None,
    ) -> Path:
        """Signs a file using PGP/GPG, producing either a detached signature
        or a clearsigned document.

        Args:
            # target_file: Path to the file to be signed.
            signer_email: Email address or key ID of the signer's private key.
            password: Passphrase for the signer's private key.
            output_path: Where to write the signature or signed file. If None,
                derived from the input file path.
            detached: If True, produce a detached signature (.sig). If False,
                produce an inline/compressed signed file.
            clearsign: If True, produce a cleartext-signed document (.asc) that
                remains readable while carrying an embedded signature. Overrides
                `detached` when True.
            armored: True → ASCII-armored output; False → binary. If None, uses
                the instance default.
        Returns:
            Path: Path to the resulting signature or signed file.

        Raises:
            FileNotFoundError: If target file does not exist.
            ValueError: If signer_email is empty or invalid.
            RuntimeError: If the GPG signing operation fails.
        """
        target_file = Prompt.ask(
            f"{STATUS_ICONS['keyboard']}[white] Enter the path of the file to "
            "be signed "
        )
        target_file = Path(target_file).resolve()

        if not target_file.is_file():
            Functions.print_not_file_error(target_file=target_file)
            raise FileNotFoundError(f"Invalid target file : {target_file}")

        signer_email = Prompt.ask(
            f"{STATUS_ICONS['keyboard']}[white] Enter the email address or "
            "key ID of the signer's private key "
        )
        if not signer_email:
            console.print(
                f"{STATUS_ICONS['warning']}[yellow3] The signer's email or "
                "key ID must be provided"
            )
            raise ValueError

        password = Prompt.ask(
            f"{STATUS_ICONS['key']}[white] Enter the passphrase for the "
            "signer's private key ",
            password=True
        )

        use_armored = armored if armored is not None else getattr(
            self, "_armored", False)

        sig_type = Prompt.ask(
            f"{STATUS_ICONS['question']}[white] What type of signature do "
            "you want to use to sign this file? (1 = clearsign, 2 = detached, "
            "3 = other) ",
            choices=["1", "2", "3"],
            show_choices=True
        )

        match sig_type:
            case "1":
                clearsign, detached = True, False
            case "2":
                clearsign, detached = False, True
            case "3":
                clearsign, detached = False, False
            case _:
                console.print(
                    f"{STATUS_ICONS['warning']}[yellow3] Invalid choice, "
                    "defaulting to inline signature"
                )
                clearsign, detached = False, False
        # Determine output path and extension
        if clearsign:
            output_file = target_file.with_suffix(".asc")
        elif detached:
            output_file = target_file.with_suffix(
                target_file.suffix + ".sig")
        else:
            output_file = target_file.with_suffix(".gpg")

        # Calling the signing method
        try:
            console.print(
                f"{STATUS_ICONS['info']}[white] Signing file : "
                f"{target_file.name}..."
            )
            console.print(
                f"{STATUS_ICONS['info']}[cyan] Signature will be written "
                f"to : {output_file.name}"
            )

            with open(target_file, "rb") as f:
                status = self.gpg.sign_file(
                    f,
                    keyid=signer_email,
                    passphrase=password,
                    detached=detached,
                    clearsign=clearsign,
                    armor=use_armored,
                    output=str(output_file),
            )
            console.print(
                f"{STATUS_ICONS['success']}[green3] Signature created : "
                f"{output_file.name}"
            )
        except Exception as e:
            console.print(
                f"{STATUS_ICONS['failure']}[red] File signing failed : {e}"
            )
            raise RuntimeError(f"Failed to execute GPG signing: {e}") from e

        if not status:
            if output_file.exists():
                output_file.unlink(missing_ok=True)

            error_msg = getattr(status, "stderr", "Unknown GPG error")
            raise RuntimeError(
                f"{STATUS_ICONS['failure']}[red] PGP signing failed for : "
                f"{target_file.name}. GPG status: {error_msg}"
            )

        if hasattr(self, "print_status"):
            self.print_status(status)

        return output_file


    def pgp_verify_signature(
        self,
        signature_file: Path | str,
        original_file: Path | str | None = None,
        signer_email: str | None = None,
    ) -> bool:
        """Verifies a PGP signature on a document or file.

        For detached signatures, both the signature file and the original
        file must be provided. For cleartext or inline signatures, only the
        signed file itself is needed.

        Args:
            signature_file: Path to the signature file (.sig, .asc, or signed
                file for inline/clearsign verification).
            original_file: Path to the original unsigned file. Required for
                detached signatures. Ignored for inline/cleartext signatures.
            signer_email: Expected signer email or key ID. If provided, the
                method will check that the signature was produced by this key.
                If None, any valid signature is accepted.

        Returns:
            bool: True if the signature is valid, False otherwise.

        Raises:
            FileNotFoundError: If the signature file or original file does
                not exist.
        """
        signature_file = Path(signature_file).resolve()

        if not signature_file.is_file():
            console.print(
                f"{STATUS_ICONS['failure']}[red] Signature file not found : "
                f"{signature_file}"
            )
            raise FileNotFoundError(
                f"Invalid signature file : {signature_file}"
            )

        # Determine if this is a detached or inline/cleartext signature
        is_detached = original_file is not None

        if is_detached:
            original_file = Path(original_file).resolve()

            if not original_file.is_file():
                console.print(
                    f"{STATUS_ICONS['failure']}[red] Original file not "
                    f"found : {original_file}"
                )
                raise FileNotFoundError(
                    f"Invalid original file : {original_file}"
                )

        try:
            console.print(
                f"{STATUS_ICONS['info']}white] Verifying signature : "
                f"{signature_file.name}..."
            )

            if is_detached:
                # Detached signature verification
                with open(signature_file, "rb") as sig_f, \
                    open(original_file, "rb") as orig_f:
                    verified = self.gpg.verify_file(sig_f, file_data=orig_f)
            else:
                # Inline or cleartext signature verification
                with open(signature_file, "rb") as sig_f:
                    verified = self.gpg.verify_file(sig_f)

        except Exception as e:
            console.print(
                f"{STATUS_ICONS['failure']}[red] Verification error for "
                f"{signature_file.name} : {e}"
            )
            return False

        # Check basic validity
        if not verified:
            console.print(
                f"{STATUS_ICONS['failure']}[red] Signature verification "
                f"FAILED for {signature_file.name}."
            )
            if hasattr(verified, "stderr") and verified.stderr:
                console.print(f"[red]  {verified.stderr.strip()}")
            return False

        # If a specific signer was expected, verify the key matches
        if signer_email:
            actual_key_id = getattr(verified, "key_id", "").upper()
            actual_fingerprint = getattr(verified, "fingerprint", "").upper()
            expected = signer_email.upper()

            # Match against key ID, fingerprint, or email in the UID
            key_matches = (
                expected in actual_key_id
                or expected in actual_fingerprint
            )

            # Also check username field which may contain the email
            username = getattr(verified, "username", "") or ""
            if not key_matches and expected in username.upper():
                key_matches = True

            if not key_matches:
                console.print(
                    f"{STATUS_ICONS['failure']}[red] Signature is valid "
                    f"but was NOT produced by expected signer : "
                    f"{signer_email}.\n"
                    f"  -> Actual signer key_id      : {actual_key_id}\n"
                    f"  -> Actual signer fingerprint : {actual_fingerprint}"
                )
                return False

        # Success
        signer_name = getattr(verified, "username", "Unknown")
        signer_key = getattr(verified, "key_id", "Unknown")
        sign_date = getattr(verified, "timestamp", "Unknown")

        console.print(
            f"{STATUS_ICONS['success']}[green3] Signature verification "
            f"PASSED with {signature_file.name}"
        )
        console.print(
            f"[green3]  Signer  : {signer_name}\n"
            f"[green3]  Key ID  : {signer_key}\n"
            f"[green3]  Signed  : {sign_date}\n"
        )

        if hasattr(self, "print_status"):
            self.print_status(verified)

        return True


    def get_pgp_action(self) -> None:
        """Gets input from the user on what action to start next."""
        pgp_choice = show_pgp_menu()

        match pgp_choice:
            case "a":
                self._debug_gpg_setup()
            case "1":
                self.generate_pgp_key_pair()
            case "2" | "3" | "4" | "5":
                action, scope = self._PGP_ACTION_MAP[pgp_choice]
                if scope == "single":
                    self._handle_pgp_process_file(action=action)
                else:
                    self._handle_pgp_process_folder(action=action)
            case "6":
                self.pgp_sign_file()
            case "7":
                self.pgp_verify_signature()
            case "r":
                Functions.clear_screen()
                show_main_menu()
            case "q":
                Functions.exit_application()
            case _:
                console.print(
                    f"{STATUS_ICONS['warning']}[yellow] An invalid option was "
                    "entered"
                )


    def _debug_gpg_setup(self) -> None:
        """Print diagnostic info about GPG configuration."""
        console.print("\n[bold cyan]GPG Configuration:[/]")
        console.print(f"[cyan]HomDir (tracked):[/] {self.gpg_homedir}")
        console.print(f"[cyan]HomDir (GPG obj):[/] {self.gpg.gnupghome or 'None (known python-gnupg issue)'}")
        console.print(f"[cyan]HomDir exists:[/] {'Yes' if self.gpg_homedir.exists() else 'No'}")
        console.print(f"[cyan]HomDir writable:[/] {'Yes' if os.access(self.gpg_homedir, os.W_OK) else 'No'}")

        # List available keys
        keys = self.gpg.list_keys()
        console.print(f"[cyan]Keys found:[/] {len(keys)}")
        for key in keys[:5]:  # Show first 5
            console.print(f"  - {key['uids'][0]} ({key['fingerprint'][:16]}...)")


#! ------------------------------------
#!  VERIFICATIONS CHECKS
#!
#!  Option "1" -- verified 08-06-26
#!  Option "2" --
#!  Option "3" --
#!  Option "4" --
#!  Option "5" --
#!  Option "6" --
#!  Option "7" --
#!  Option "r" --
#!  Option "q" --
#!





"""

#!
#! Usage examples for signing a file:
#!

# Detached signature (creates .sig file alongside original)
sig_path = pgp.pgp_sign_file(
    target_file="/path/to/document.pdf",
    signer_email="alice@example.com",
    password="my_private_key_passphrase",
    detached=True,
)

# Cleartext signature (embeds signature in readable .asc file)
asc_path = pgp.pgp_sign_file(
    target_file="/path/to/message.txt",
    signer_email="alice@example.com",
    password="my_private_key_passphrase",
    clearsign=True,
)

# Inline signature (compressed + signed .gpg file)
signed_path = pgp.pgp_sign_file(
    target_file="/path/to/data.bin",
    signer_email="alice@example.com",
    password="my_private_key_passphrase",
    detached=False,
)


#!
#! Usage examples for verifying a signature:
#!

# Verify detached signature — requires original file
is_valid = pgp.pgp_verify_signature(
    signature_file="/path/to/document.pdf.sig",
    original_file="/path/to/document.pdf",
    signer_email="alice@example.com",  # Optional: enforce expected signer
)

# Verify cleartext/inline signature — original file not needed
is_valid = pgp.pgp_verify_signature(
    signature_file="/path/to/message.asc",
)

# Verify without enforcing a specific signer (accept any valid signature)
is_valid = pgp.pgp_verify_signature(
    signature_file="/path/to/document.pdf.sig",
    original_file="/path/to/document.pdf",
)

"""

"""
        # Conditionally add expiry based on return type
        if expire_value:
            if isinstance(expire_value, str):
                # Already GNU format like "365d" OR ISO date like "2030-12-31"
                # Check if it's GNU format (ends with letter)
                if expire_value[-1].isalpha():
                    # GNU format: "365d", "1y", "6m" - use directly
                    key_params["Expire-Date"] = expire_value  # Capitalized!
                else:
                    # ISO date: add time component if needed
                    if "T" not in expire_value:
                        expire_value += "T00:00:00"
                    key_params["expire_date"] = expire_value
                    console.print(f"[cyan]Key expires: {expire_value[:10]}")

            elif isinstance(expire_value, int):
                # Days-based expiry (relative)
                from datetime import datetime, timedelta
                expiry_date = datetime.now() + timedelta(days=expire_value)
                expire_value = expiry_date.strftime("%Y-%m-%d %H:%M:%S")
                key_params["Expire-Date"] = expire_value  # Capitalized!
            # elif isinstance(expire_value, str):
            #     # Date-based expiry (absolute)
            #     expire_str = expire_value + "T00:00:00"  # Add time component


        if expire_str:
            key_params["expire_date"] = expire_str
"""