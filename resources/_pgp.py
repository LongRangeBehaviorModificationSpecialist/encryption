# !/usr/bin/env python3
# DLU : 27-Jul-2026


import gnupg
import logging
import os
from pathlib import Path
import shutil
from typing import List, Optional, Union

from rich.console import Console
from rich.prompt import Prompt

from resources.functions import Functions


c = Console()


logger = logging.getLogger(__name__)


class PGPClass:


    def __init__(
        self,
        app_instance,
        gnupg_home: Optional[Union[str, Path]] = None,
        gpg_binary: Optional[str] = None
    ) -> None:
        """Store a reference to the main app loop controller."""
        self.app = app_instance

        self.script_path = Path(__file__).parent.resolve()

        if gnupg_home:
            self.gnupg_home_dir = Path(gnupg_home)
        else:
            self.gnupg_home_dir = self.script_path / ".gnupg"

        if not self.gnupg_home_dir.exists():
            self.gnupg_home_dir.mkdir(parents=True, exist_ok=True)

        if os.name == "posix":
            os.chmod(self.gnupg_home_dir, 0o700)

        resolved_gpg = (
            gpg_binary
            or shutil.which("gpg")
            or r"C:\Program Files\GnuPG\bin\gpg.exe"
        )
        if not shutil.which(resolved_gpg) and not Path(resolved_gpg).exists():
            raise FileNotFoundError(
                f"GnuPG binary not found at '{resolved_gpg}'. Please install \
        GnuPG."
            )

        self.gpg = gnupg.GPG(
            gnupghone=str(self.gnupg_home_dir), gpgbinary=resolved_gpg
        )
        self.gpg.encoding = "utf-8"

        self.private_key_file = self.script_path / "mas_private_key.asc"
        self.public_key_file = self.script_path / "mas_public_key.asc"


    def ask_pgp_key_choice(self) -> str:
        Functions.clear_screen()
        return (
            Prompt.ask("""[dodger_blue1]
---------------------------------------
ENCRYPT FILE(S) USING PGP KEY
---------------------------------------\n
[khaki3]Choose an option ->[bright_white]\n
[1] Generate new PGP key pair
[2] Encrypt files using PGP encryption
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """,
                choices=["1", "2", "r", "q"],
                show_choices=False,
            )
            .strip()
            .lower()
        )


    def generate_pgp_key(
        self, password: str, email_address: str, key_length: int = 2048
    ) -> str:
        """Generates a new RSA PGP key pair and exports public/private keys.

        Args:
            password: Passphrase to encrypt the generated private key.
            email_address: Associated identity email address.
            key_length: Bit length of the RSA key (default: 2048).

        Returns:
            str: Fingerprint of the newly created key pair.
        """
        if not email_address or "@" not in email_address:
            raise ValueError(
                f"Invalid or missing email address provided : '{email_address}'"
            )

        password = Functions.get_password()

        input_data = self.gpg.gen_key_input(
            name_email=email_address,
            passphrase=password,
            key_type="RSA",
            key_length=key_length
        )

        key = self.gpg.gen_key(input_data)

        if not key.fingerprint:
            raise RuntimeError(
                f"PGP key generation failed. Engine error output: {key.stderr}."
            )

        fingerprint = str(key.fingerprint)
        c.print(f"""[bright_white]
[-] Generated Key Fingerprint: {fingerprint}."""
        )

        # Export keys upon successful generation
        self.pgp_export_public_key(keyid=fingerprint)
        self.pgp_export_private_key(keyid=fingerprint, password=password)

        return fingerprint


    def get_existing_key_file_path(self) -> Path:
        """Prompts for a key file path and loop-validates its existence."""
        while True:
            key_file = (
                Prompt.ask("""[bright_white]
[-] Enter the path to the .key file to use to encrypt the file """
                )
            )
            path = Path(key_file)
            if path.is_file():
                return path


    def pgp_encrypt_file(
        self,
        target_file_path: Union[Path, str],
        recipients: Union[str, List[str]],
        always_trust: bool = True
    ) -> None:
        """Encrypts a single file using PGP/GPG and handles GPG engine
        failures safely.
        """

        # Normalize recipients input to a list
        if isinstance(recipients, str):
            recipients = [recipients]

        if not recipients:
            raise ValueError(
                "At least one recipient email or key ID must be provided."
            )

        encrypted_file_path = target_file_path.with_name(
            f"{target_file_path.name}.pgp"
        )

        try:
            with open(target_file_path, "rb") as f:
                status = self.gpg.encrypt_file(
                    f,
                    recipients=[recipients],
                    always_trust=always_trust,
                    output=str(encrypted_file_path)
                )
        except Exception as e:
            logger.error(
                f"GPG process invocation failed for {target_file_path}: {e}",
                exc_info=True,
            )
            raise RuntimeError(
                f"Failed to execute GPG encryption: {e}"
            ) from e
        
        if not status.ok:
            # Clean up partial/empty output file if created
            if encrypted_file_path.exists():
                encrypted_file_path.unlink(missing_ok=True)

            error_msg = getattr(
                status, "status", getattr(status, "stderr", "Unknown GPG error")
            )
            logger.error(
                f"PGP encryption failed for {target_file_path.name} : {error_msg}"
            )
            raise RuntimeError(
                f"PGP Encryption failed for '{target_file_path.name}'. \
GPG status: {error_msg}"
            )

        if hasattr(self, "print_status"):
            self.print_status(status)

        c.print(f"""[green3]
[-] PGP file encrypted successfully : {encrypted_file_path.name}"""
                )

        return encrypted_file_path