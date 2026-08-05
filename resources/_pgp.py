# !/usr/bin/env python3
# DLU : 04-Aug-2026


from enum import StrEnum
import getpass
import os
from pathlib import Path
import shutil
import sys
from typing import List, Optional
from rich.prompt import Prompt

HAS_PGP = False
try:
    import gnupg
    HAS_PGP = True
except ImportError:
    print(
        "Missing dependency: python-gnupg\n"
        "Install with: \"pip install python-gnupg\""
    )
    sys.exit(1)

# Import the console object from the main __init__.py file
from . import console
from resources.vars import ENCRYPTED_EXT_LIST
from resources.functions import Functions
from resources.prompts import (
    show_main_menu,
    show_pgp_menu
)


class Action(StrEnum):
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"


class PGP:

    _ACTION_MAP = {
        "2": (Action.ENCRYPT, "single"),
        "3": (Action.DECRYPT, "single"),
        "4": (Action.ENCRYPT, "folder"),
        "5": (Action.DECRYPT, "folder")
    }


    def __init__(self, password: str | None = None):
        self.script_path = Path(__file__).parent.resolve()
        self.gpg_home = self.script_path / ".gnupg"
        self._recipient_fp: str | None = None
        self._key_imported = False
        self._armored = False
        self._symmetric = False
        self._password = password

        if not self.gpg_home.exists():
            self.gpg_home.mkdir(parents=True, exist_ok=True)

        if os.name == "posix":
            os.chmod(self.gnupg_home_dir, 0o700)

        self.resolved_gpg = (
            shutil.which("gpg")
            or r"C:\Program Files\GnuPG\bin\gpg.exe")

        if not self.resolved_gpg and not Path(self.resolved_gpg).exists():
            raise FileNotFoundError(
                f"GnuPG binary not found at '{self.resolved_gpg}'. Please "
                "install GnuPG."
            )

        self.gpg = gnupg.GPG(
            gnupghome=str(self.gpg_home),
            gpgbinary=self.resolved_gpg,
        )
        self.gpg.encoding = "utf-8"

        self.private_key_file = self.script_path / "mas_private_key.asc"
        self.public_key_file = self.script_path / "mas_public_key.asc"


    @property
    def gpg(self) -> gnupg.GPG:
        if self._gpg is None:
            self._init_gpg()
        return self._gpg


    def _init_gpg(self) -> None:
        kwargs = {}
        if self.gpg_home:
            kwargs["gnupghome"] = self.gpg_home
        self._gpg = gnupg.GPG(**kwargs)


    def print_status(self, action: str, status: gnupg.GPG) -> None:
        """Prints GPG action execution status to terminal."""
        if status.ok == True:
            console.print(
                f"[green][-] File {action}ion was successful : "
                f"{status.stderr}"
            )
        else:
            status_msg = getattr(
                status,
                "status",
                getattr(status, "stderr", "Unknown Error")
            )
            console.print(
                f"[red1][!] File encryption WAS NOT successful : "
                f"{status_msg}. Please try again."
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
                f"[red1][!] Cannot read key file \"{key_path}\" : {e}"
            )
            return False

        result = self.gpg.import_keys(key_data)

        if result.count == 0:
            console.print(
                "[red1][!] No keys imported — the file may not contain a "
                "valid PGP key."
            )
            return False

        self._recipient_fp = result.fingerprints[0]
        self._key_imported = True
        console.print(
            f"[green][-] Imported key fingerprint : {self._recipient_fp}"
        )
        console.print(
            f"[cyan][-] Full import result : {result.summary()}"
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
    ) -> Optional[str]:
        """Obtain passphrase via secure getpass prompt or reuse cached value.

        Args:
            force_new: If True, always prompt even if passphrase is cached.
            purpose: Description of what the passphrase is for (logging).
            confirm: If True, prompt twice to confirm the passphrase.
        """
        if self._password is not None and not force_new:
            console.print(
                f"[bright_white][-] Using cached passphrase for {purpose}"
            )
            return self._password

        attempts_left = 3
        while attempts_left > 0:
            if confirm:
                password1 = getpass.getpass(
                    f"Enter passphrase for {purpose} : "
                )
                password2 = getpass.getpass(
                    f"Confirm passphrase for {purpose} : "
                )

                if password1 != password2:
                    console.print(
                        "[yellow][!] Passphrases did not match."
                    )
                    attempts_left -= 1
                    console.print(
                        f"[yellow][!] {attempts_left} attempt(s) remaining.\n"
                    )
                    continue
            else:
                password1 = getpass.getpass(
                    f"[bright_white][-] Enter passphrase for {purpose} : "
                )
                if len(password1) < 1:
                    console.print(
                        "[yellow][!] Empty passphrase not allowed."
                    )
                    attempts_left -= 1
                    continue

            console.print(
                f"[bright_white][-] Passphrase accepted for {purpose}"
            )
            self._password = password1
            return password1

        console.print(
            f"[red1][!] Too many failed passphrase attempts for {purpose}"
        )
        return None


    def clear_passphrase(self) -> None:
        """Clear any cached passphrase from memory (use after sensitive ops)."""
        self._password = None
        console.print(
            "[bright_white][-] Cleared cached passphrase from memory"
        )


    def pgp_export_public_key(self, keyid: str) -> str:
        """Exports an armored public key by Key ID to the designated file path.

        Args:
            keyid: ID or fingerprint of the PGP key to export.

        Returns:
            str: The exported ASCII-armored public key block.
        """
        public_key_data = self.gpg.export_keys(
            keyids=keyid,
            output=str(self.public_key_file)
        )

        if not public_key_data or not self.public_key_file.exists():
            console.print(
                f"[red1][!] Failed to export public key for Key ID : {keyid}"
            )
            raise RuntimeError(
                f"Failed to export public key for Key ID : {keyid}")

        console.print(
            f"[bright_white][-] Public key exported successfully to "
            f"{self.public_key_file.name}"
        )

        return str(public_key_data)


    def pgp_export_private_key(self, keyid: str, password: str) -> str:
        """Exports an armored private key by Key ID and passphrase to the
        designated file path.

        Args:
            keyid: ID or fingerprint of the PGP key to export.
            password: Passphrase protecting the private key.

        Returns:
            str: The exported ASCII-armored secret key block.
        """
        private_key_data = self.gpg.export_keys(
            keyids=keyid,
            secret=True,
            passphrase=password,
            output=str(self.private_key_file),
            )

        if not private_key_data or not self.private_key_file.exists():
            console.print(
                f"[red1][!] Failed to export private key for Key ID : {keyid}. "
                "Check the keyid/passphrase."
            )
            raise RuntimeError(
                f"Failed to export private key for Key ID : {keyid}. "
                "Check the keyid/passphrase."
            )

        console.print(
            f"[bright_white][-] Private key exported successfully to "
            f"{self.private_key_file.name}"
        )

        return str(private_key_data)


    def generate_pgp_key_pair(self, key_length: int = 4096) -> str:
        """Generates a new RSA PGP key pair and exports public/private keys.

        Args:
            key_length: Bit length of the RSA key (default: 4096).

        Returns:
            str: Fingerprint of the newly created key pair.
        """
        password = Prompt.ask(
            "[bright_white][-] Enter passphrase for the private key ",
            password=True
        )

        email_address = Prompt.ask(
            "[bright_white][-] Enter email address of the PGP key owner "
            ).strip().lower()

        if not email_address or "@" not in email_address:
            console.print(
                "[yellow][!] Invalid or missing email address provided : "
                f"{email_address}"
            )
            raise ValueError(
                f"Invalid or missing email address provided : {email_address}"
            )

        input_data = self.gpg.gen_key_input(
            name_email=email_address,
            passphrase=password,
            key_type="RSA",
            key_length=key_length,
        )

        key = self.gpg.gen_key(input_data)

        if not key.fingerprint:
            raise RuntimeError(
                f"PGP key generation failed. Engine error output : "
                f"{key.stderr}"
            )

        keyid = str(key.fingerprint)
        console.print(
            f"[bright_white][-] Generated Key Fingerprint : {keyid}"
        )

        # Export keys upon successful generation
        self.pgp_export_public_key(keyid=keyid)
        self.pgp_export_private_key(
            keyid=keyid,
            password=password,
        )

        return keyid


    def _handle_pgp_process_file(self, action: Action) -> None:
        """Collect user inputs and call pgp_process_file."""
        # Email address (required for public-key encryption)
        email_input = Prompt.ask(
            "[bright_white][-] Enter recipient email address(es): "
        ).strip()

        if not email_input:
            console.print("[yellow][!] No email address provided.")
            return

        email_address = [addr.strip() for addr in email_input.split(",")]

        # Password -> required for symmetric encryption or decryption
        if action == Action.ENCRYPT:
            confirm = Prompt.ask(
                "[bright_white][?] Use symmetric (password only) encryption? ",
                choices=["y", "n"],
                show_choices=True
            )
            if confirm:
                password = Functions.get_password()
                if not password:
                    console.print(
                        "[yellow][!] Password required for symmetric "
                        "encryption."
                    )
                    return

                symmetric = True
                armored = Prompt.ask(
                    "[bright_white][?] Use ASCII-armored output (.asc)? ",
                    choices=["y", "n"],
                    show_choices=True
                )
            else:
                # Will prompt GPG for private key passphrase
                password = None
                symmetric = False
                armored = Prompt.ask(
                    "[bright_white][?] Use ASCII-armored output (.asc)? ",
                    choices=["y", "n"],
                    show_choices=True
                )
        else:  # Decrypt
            confirm = Prompt.ask(
                "[bright_white][-] Provide a passphrase now? (leave blank "
                "for GPG prompt) ",
                choices=["y", "n", ""],
                show_choices=True
            )
            if confirm:
                password = Prompt.ask(
                    "[bright_white][-] Enter passphrase for decryption ",
                    password=True
                )
            else:
                password = None
            symmetric = None  # Auto-detect from file

        # Output path (optional)
        output_path_input = Prompt.ask(
            "[bright_white][-] Enter output path (leave blank for default) ",
        ).strip()
        output_path = (
            Path(output_path_input).resolve()
            if output_path_input else None
        )

        # Get target file
        target_file = Functions.get_file_path(action=action.value)
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
            console.print(f"[green][*] Successfully processed : {result}")
        except Exception as e:
            console.print(f"[red1][!] Operation failed : {e}")


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
                f"[red1][!] {target_file.name} does not exist or "
                "is a directory."
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
                raise ValueError(
                "At least one recipient email or key ID must be provided "
                "for public-key encryption. Use symmetric=True for "
                "password-only encryption."
            )

        # Validate: symmetric encryption requires a password
        if action == "encrypt" and use_symmetric and not password:
            raise ValueError(
                "A password is required for symmetric encryption."
            )

        try:
            console.print(
                f"[bright_white][-] Reading file : {target_file.name}...")

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
                        f"[bright_white][-] {action.capitalize()}ing file "
                        "data..."
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
            raise RuntimeError(f"Failed to execute GPG {action}ion: {e}") from e

        if not status.ok:
            # Clean up partial/empty output file if created
            if output_file.exists():
                output_file.unlink(missing_ok=True)

            error_msg = getattr(
                status, "status", getattr(status, "status", "Unknown GPG error")
            )
            raise RuntimeError(
                f"PGP {action.title()}ion failed for '{target_file.name}'. "
                f"GPG status: {error_msg}"
            )

        if hasattr(self, "print_status"):
            self.print_status(status)

        console.print(
            f"[green][*] PGP file {action}ed successfully : {output_file.name}"
        )

        return output_file


    def _handle_pgp_process_folder(self, action: Action) -> None:
        """Collect user inputs and call pgp_process_folder."""
        # Target directory
        target_dir = Functions.get_directory_path(action=action.value)
        if not target_dir:
            return

        # Recursive option
        recursive = Functions.select_recursive_option()

        # Email address (required for public-key encryption)
        email_input = Prompt.ask(
            "[bright_white][-] Enter recipient email address(es) "
            "(comma-separated) "
        ).strip()

        if not email_input and action == Action.ENCRYPT:
            console.print("[yellow][!] No email provided.")
            confirm = Prompt.ask(
                "[bright_white][?] Proceed with symmetric encryption "
                "instead? ",
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
                "[bright_white][-] Enter passphrase for encryption "
            )
            if not password:
                console.print(
                    "[yellow][!] Password required for symmetric "
                    "encryption.")
                return
        elif action == Action.DECRYPT:
            confirm = Prompt.ask(
                "[bright_white][?] Provide a passphrase now? (leave blank "
                "for GPG prompt) ",
                choices=["y", "n"],
                show_choices=True
            )
            if confirm:
                password = Prompt.ask(
                    "[bright_whtite][-] Enter passphrase for decryption ",
                    password=True
                )
            else:
                password = None
        else:
            password = None

        # Armored option
        armored = Prompt.ask(
            "[bright_white][?] Use ASCII-armored output (.asc)? ",
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
                f"[green][*] Completed processing {len(results)} files."
            )
        except Exception as e:
            console.print(f"[red1][!] Operation failed : {e}")


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
            raise ValueError(
                "At least one recipient email or key ID must be provided "
                "for public-key encryption. Use symmetric=True for "
                "password-only encryption."
            )

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
                "[red1][!] Failed to retrieve files from "
                f"{target_dir} : {e}"
            )
            return []

        if not all_files:
            console.print(
                f"[yellow][!] No valid files to {action} in {target_dir}"
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
                    f"[red1][!] Error during {action}ing "
                    f"{file_path.name} : {e}"
                )
                failed_files.append(file_path)

        # Summary reporting
        if successful_files:
            console.print(
                f"[green][*] Action Completed\nSuccessfully {action}ed "
                f"{len(successful_files)} files in {target_dir} :"
            )
            for processed_file in successful_files:
                console.print(f"[green]  {processed_file.name}")

        if failed_files:
            console.print(
                f"[red1][!] ** Warning **\nFailed to {action} "
                f"{len(failed_files)} files :"
            )
            for failed_file in failed_files:
                console.print(f"[red1]  {failed_file.name}")

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
            "[bright_white][-] Enter the path of the file to be signed "
        )
        target_file = Path(target_file).resolve()

        if not target_file.is_file():
            console.print(
                f"[red1][!] {target_file.name} does not exist or is "
                "a directory."
            )
            raise FileNotFoundError(f"Invalid target file : {target_file}")

        signer_email = Prompt.ask(
            "[bright_white][-] Enter the email address or key ID of the signer's "
            "private key "
        )
        if not signer_email:
            raise ValueError("Signer email or key ID must be provided.")

        password = Prompt.ask(
            "[bright_white][-] Enter the passphrase for the signer's "
            "private key ",
            password=True
        )

        use_armored = armored if armored is not None else getattr(
            self, "_armored", False)

        sig_type = Prompt.ask(
            "[bright_white][?] What type of signature do you want to use "
            "to sign this file? (1 = clearsign, 2 = detached, 3 = other) ",
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
                    "[yellow][!] Invalid choice, defaulting to inline "
                    "signature"
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
                f"[bright_white][-] Signing file : {target_file.name}..."
            )
            console.print(
                f"[cyan][-] Signature will be written to : {output_file.name}"
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
            console.print(f"[green][*] Signature created : {output_file.name}")
        except Exception as e:
            console.print(f"[red1][!] File signing failed : {e}")
            raise RuntimeError(f"Failed to execute GPG signing: {e}") from e

        if not status:
            if output_file.exists():
                output_file.unlink(missing_ok=True)

            error_msg = getattr(status, "stderr", "Unknown GPG error")
            raise RuntimeError(
                f"PGP signing failed for : {target_file.name}. "
                f"GPG status: {error_msg}"
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
                f"[red1][!] Signature file not found : {signature_file}"
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
                    f"[red1][!] Original file not found : {original_file}"
                )
                raise FileNotFoundError(
                    f"Invalid original file : {original_file}"
                )

        try:
            console.print(
                "[bright_white][-] Verifying signature : "
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
                "[red1][!] Verification error for "
                f"{signature_file.name} : {e}"
            )
            return False

        # Check basic validity
        if not verified:
            console.print(
                f"[red1][!] Signature verification FAILED for "
                f"{signature_file.name}."
            )
            if hasattr(verified, "stderr") and verified.stderr:
                console.print(f"[red1]  {verified.stderr.strip()}")
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
                    f"[red1][!] Signature is valid but was NOT produced "
                    f"by expected signer : {signer_email}.\n"
                    f"  -> Actual signer key_id      : {actual_key_id}\n"
                    f"  -> Actual signer fingerprint : {actual_fingerprint}"
                )
                return False

        # Success
        signer_name = getattr(verified, "username", "Unknown")
        signer_key = getattr(verified, "key_id", "Unknown")
        sign_date = getattr(verified, "timestamp", "Unknown")

        console.print(
            f"[green][-] Signature verification PASSED for "
            f"{signature_file.name}"
        )
        console.print(
            f"[green]  Signer  : {signer_name}\n"
            f"[green]  Key ID  : {signer_key}\n"
            f"[green]  Signed  : {sign_date}\n"
        )

        if hasattr(self, "print_status"):
            self.print_status(verified)

        return True


    def get_pgp_action(self, action: str) -> None:
        """Gets input from the user on what action to start next."""
        pgp_choice = show_pgp_menu()

        # GPG home
        gpg_home = Prompt.ask(
            "[bright_white][-] Enter GPG home directory "
            "(blank for default ~/.gnupg) "
        )
        self.gpg_home = gpg_home.strip() or None
        self._init_gpg()

        match pgp_choice:
            case "1":
                self.generate_pgp_key_pair()
            case "2" | "3" | "4" | "5":
                action, scope = self._ACTION_MAP[pgp_choice]
                if scope == "single":
                    self._handle_pgp_process_file(action)
                else:
                    self._handle_pgp_process_folder(action)
            case "6":
                self.pgp_sign_file()
            case "7":
                self.pgp_verify_signature()
            case "r":
                show_main_menu()
            case "q":
                Functions.exit_application()

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
