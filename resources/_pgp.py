# !/usr/bin/env python3
# DLU : 29-Jul-2026


import gnupg
import os
from pathlib import Path
import shutil
from typing import List, Optional, Union

from rich.prompt import Prompt

# Import the console object from the main __init__.py file
from . import console
from resources.functions import Functions
from resources.prompts import PGP_ENCRYPTION_PROMPT


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


    def return_to_main_menu(self) -> None:
        """Returns control cleanly back to the main menu processor."""
        self.app.main(self)


    def get_pgp_key_choice(self) -> str:
        Functions.clear_screen()
        return (
            Prompt.ask(
                PGP_ENCRYPTION_PROMPT,
                choices=["1", "2", "r", "q"],
                show_choices=False,
            )
            .strip()
            .lower()
        )


    def pgp_export_public_key(self, keyid: str) -> str:
        """Exports an armored public key by Key ID to the designated file path.

        Args:
            keyid: ID or fingerprint of the PGP key to export.

        Returns:
            str: The exported ASCII-armored public key block.
        """
        public_key_data = self.gpg.export_keys(
            keyids=keyid, output=str(self.public_key_file)
        )

        if not public_key_data or not self.public_key_file.exists():
            raise RuntimeError(
                f"Failed to export public key for Key ID '{keyid}'"
            )

        console.print(f"""[bright_white]
[-] Public key exported successfully to {self.public_key_file.name}""")

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
            output=str(self.private_key_file)
        )

        if not private_key_data or not self.private_key_file.exists():
            raise RuntimeError(
                f"Failed to export private key for Key ID : {keyid}. \
Check keyid/passphrase.")

        console.print(f"""[bright_white]
[-] Private key exported successfully to {self.private_key_file.name}""")

        return str(private_key_data)


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
                f"Invalid or missing email address provided : {email_address}"
            )

        input_data = self.gpg.gen_key_input(
            name_email=email_address,
            passphrase=password,
            key_type="RSA",
            key_length=key_length
        )

        key = self.gpg.gen_key(input_data)

        if not key.fingerprint:
            raise RuntimeError(
                f"PGP key generation failed. Engine error output : {key.stderr}"
            )

        fingerprint = str(key.fingerprint)
        console.print(f"""[bright_white]
[-] Generated Key Fingerprint : {fingerprint}""")

        # Export keys upon successful generation
        PGPClass.pgp_export_public_key(self, keyid=fingerprint)
        PGPClass.pgp_export_private_key(self, keyid=fingerprint, password=password)

        return fingerprint


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
                "At least one recipient email or key ID must be provided.")

        encrypted_file_path = target_file_path.with_name(
            f"{target_file_path.name}.pgp")

        try:
            with open(target_file_path, "rb") as f:
                status = self.gpg.encrypt_file(
                    f,
                    recipients=[recipients],
                    always_trust=always_trust,
                    output=str(encrypted_file_path)
                )
        except Exception as e:
            raise RuntimeError(
                f"Failed to execute GPG encryption: {e}") from e

        if not status.ok:
            # Clean up partial/empty output file if created
            if encrypted_file_path.exists():
                encrypted_file_path.unlink(missing_ok=True)

            error_msg = getattr(
                status, "status", getattr(
                    status,
                    "stderr",
                    "Unknown GPG error"
                )
            )
            raise RuntimeError(
                f"PGP Encryption failed for '{target_file_path.name}'. \
GPG status : {error_msg}")

        if hasattr(self, "print_status"):
            self.print_status(status)

        console.print(f"""[green3]
[-] PGP file encrypted successfully : {encrypted_file_path.name}""")

        return encrypted_file_path


    def pgp_encryption_workflow(self) -> None:
        pgp_key_choice = PGPClass.get_pgp_key_choice(self)

        if pgp_key_choice == "r":
            self.return_to_main_menu()
            return

        if pgp_key_choice == "q":
            Functions.exit_application()
            return

        if pgp_key_choice == "1":
            # Get password and an email address in order to generate
            # a new pgp key pair
            password = Functions.get_password()
            email_address = Functions.get_email_address()

            if not password.strip() or not email_address.strip():
                console.print("""[yellow]
[!] Key generation cancelled : Missing password or email.""")
                Prompt.ask("""[bright_white]
Press Enter to return to menu...""")
                return

            PGPClass.generate_pgp_key(
                self,
                password=password,
                email_address=email_address
            )

        #TODO -- Add option to return to menu to use the new keys to encrypt a file

        elif pgp_key_choice == "2":
            raw_path = Functions.get_file_path(text="ENCRYPTED")
            # User cancelled input
            if not raw_path or not raw_path.strip():
                return

            recipient = Prompt.ask("""[bright_white]
[-] Enter recipient email or Key ID """).strip()
            if not recipient:
                console.print("""[yellow]
[!] Encryption cancelled : No recipient specified""")
                Prompt.ask("""[bright_white]
Press Enter to continue...""")
                return

            PGPClass.pgp_encrypt_file(
                self,
                target_file_path=Path(raw_path),
                recipients=[recipient]
            )
