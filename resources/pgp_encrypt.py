# !/usr/bin/env python3
# DLU : 27-Jul-2026

import logging
from rich.console import Console
from rich.prompt import Prompt
import gnupg
from pathlib import Path
from typing import List, Optional, Union
import os
import shutil

from resources.functions import Functions


# Make the console object
c = Console()


class PGPEncrypt:

    def __init__(
        self,
        app_instance,
        gnupg_home: Optional[Union[str, Path]] = None,
        gpg_binary: Optional[str] = None
    ):
        """Initializes GnuPG environment safely within the instance
        constructor.
        """

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


    def print_status(self, status: gnupg.GPG) -> None:
        """Prints GPG action execution status to terminal."""
        if getattr(status, "ok", False):
            c.print(f"""[green]
[-] GPG operation successful.\n{status.stderr}"""
            )
        else:
            status_msg = getattr(
                status,
                "status",
                getattr(status, "stderr", "Unknown Error"),
            )
            c.print(f"""[bright_red]
[-] GPG operation WAS NOT successful : {status_msg}"""
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

        c.print(f"""[bright_white]
[-] Public key exported successfully to {self.public_key_file.name}"""
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
            output=str(self.private_key_file)
        )

        if not private_key_data or not self.private_key_file.exists():
            raise RuntimeError(
                f"Failed to export private key for Key ID '{keyid}'. \
Check keyid/passphrase."
            )
        c.print(f"""[bright_white]
[-] Private key exported successfully to {self.private_key_file.name}"""
        )

        return str(private_key_data)


    def generate_pgp_key_pair(
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


    def pgp_encrypt_file(
        self,
        target_file: Path | str,
        recipients: Union[str, List[str]],
        always_trust: bool = True
    ) -> None:
        """Encrypts a single file using PGP/GPG and handles GPG engine
        failures safely.
        """

        logger = logging.getLogger(__name__)

        target_file = Path(target_file)

        # Path existence and file type checks
        if not target_file.exists():
            raise FileNotFoundError(
                f"Target file not found : {target_file}"
            )
        if not target_file.is_file():
            raise IsADirectoryError(
                f"Provided path is a directory, not a file : {target_file}"
            )

        # Normalize recipients input to a list
        if isinstance(recipients, str):
            recipients = [recipients]

        if not recipients:
            raise ValueError(
                "At least one recipient email or key ID must be provided."
            )

        c.print(f"[bright_white][-] Encrypting data..."
        )
        encrypted_file_path = target_file.with_name(
            f"{target_file.name}.pgp"
        )

        try:
            with open(target_file, "rb") as f:
                status = self.gpg.encrypt_file(
                    f,
                    recipients=[recipients],
                    always_trust=always_trust,
                    output=str(encrypted_file_path)
                )
        except Exception as e:
            logger.error(
                f"GPG process invocation failed for {target_file}: {e}",
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
                f"PGP encryption failed for {target_file.name} : {error_msg}"
            )
            raise RuntimeError(
                f"PGP Encryption failed for '{target_file.name}'. \
GPG status: {error_msg}"
            )

        if hasattr(self, "print_status"):
            self.print_status(status)

        c.print(f"""[green]
[-] PGP file encrypted successfully : {encrypted_file_path.name}"""
        )

        return encrypted_file_path


    def pgp_encrypt_directory(
        self,
        target_directory_path: Union[str, Path],
        recipients: Union[str, List[str]],
        always_trust: bool = True
    ) -> List[Path]:
        """Encrypts all non-PGP files in a directory using PGP/GPG."""

        # Set up logging for non-UI diagnostics
        logger = logging.getLogger(__name__)

        target_dir = Path(target_directory_path)

        if not target_dir.exists():
            raise FileNotFoundError(
                f"Target directory does not exist : {target_dir}"
            )
        if not target_dir.is_dir():
            raise NotADirectoryError(
                f"The provided path is not a directory : {target_dir}"
            )

        try:
            files = [f for f in target_dir.rglob("*") if f.is_file()]

        except Exception as e:
            c.print(f"""[bright_red]
[!] Failed to retrieve files from {target_dir}: {e}."""
            )
            return []

        pgp_extensions = {".gpg", ".pgp", ".asc"}
        files_to_encrypt = [
            Path(f) for f in files
            if not Path(f).suffix.lower() not in pgp_extensions
        ]

        if not files_to_encrypt:
            c.print(f"""[yellow]
[!] No valid files to encrypt in {target_dir}"""
            )
            return []

        successful_encryptions: List[Path] = []
        failed_encryptions: List[Path] = []

        for file_path in files_to_encrypt:
            try:
                encrypted_path = self.pgp_encrypt_file(
                    target_file=file_path,
                    recipients=recipients,
                    always_trust=always_trust
                )
                successful_encryptions.append(encrypted_path)
            except Exception as e:
                logger.error(
                    f"Failed to PGP-encrypt file: {file_path}",
                    exc_info=True
                )
                c.print(f"""[bright_red]
[!] Error encrypting {file_path.name}: {e}"""
                )
                failed_encryptions.append(file_path)

        if successful_encryptions:
            c.print(f"""[green]
** Action Completed **
Successfully PGP-encrypted {len(successful_encryptions)} files in \
{target_dir} :"""
            )
            for encrypted_file in successful_encryptions:
                c.print(f"""[green]
    {encrypted_file.name}"""
                )

        if failed_encryptions:
            c.print(f"""[bright_red]
** Warning **
Failed to encrypt {len(failed_encryptions)} files in {target_dir} :"""
            )
            for failed_file in failed_encryptions:
                c.print(f"""[bright_red]
    {failed_file.name}"""
                )

        return successful_encryptions


    def get_target_choice(self):
        """Main routing controller for encryption jobs."""
        while True:
            try:
                # Functions.clear_screen()
                target_option = (
                    Prompt.ask("""[dodger_blue1]
---------------------------------------
ENCRYPT FILE(S) USING PGP KEY
---------------------------------------\n
[khaki3]Choose an option ->[bright_white]\n
[1] Generate new PGP key pair
[2] Encrypt files using PGP encryption
[3] Encrypt all files in a directory using PGP keys\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """,
                        choices=["1", "2", "3", "r", "q"],
                        show_choices=False,
                    )
                    .strip()
                    .lower()
                )

                # Global exits
                if target_option == "r":
                    # self.return_to_main_menu()
                    # return
                    pass
                if target_option == "q":
                    Functions.exit_application()
                    return

                # Option 1: Generate new key pair
                if target_option == "1":
                    password = Functions.get_password()
                    email_address = Functions.get_email_address()

                    if not password.strip() or not email_address.strip():
                        c.print("""[yellow]
[!] Key generation cancelled : Missing password or email."""
                        )
                        Prompt.ask("""[bright_white]
Press Enter to return to menu..."""
                        )
                        continue

                    self.generate_pgp_key_pair(
                        password=password, email_address=email_address
                    )

                # Option 2: Encrypt single file
                elif target_option == "2":
                    raw_path = Functions.get_file_path(text="encrypted")
                    # User cancelled input
                    if not raw_path or not raw_path.strip():
                        continue

                    recipient = Prompt.ask("""[bright_white]
[-] Enter recipient email or Key ID : """
                    ).strip()
                    if not recipient:
                        c.print("""[yellow]
[!] Encryption cancelled : No recipient specified."""
                        )
                        Prompt.ask("""[bright_white]
Press Enter to continue..."""
                        )
                        continue

                    self.pgp_encrypt_file(
                        target_file=Path(raw_path),
                        recipients=[recipient]
                    )

                # Option 3: Encrypt directory
                elif target_option == "3":
                    raw_dir = Functions.get_directory_path(text="encrypted")
                    if not raw_dir or not raw_dir.strip():
                        continue

                    recipient = Prompt.ask("""[bright_white]
[-] Enter recipient email or Key ID """
                    ).strip()
                    if not recipient:
                        c.print("""[yellow]
[!] Encryption cancelled : No recipient specified."""
                        )
                        Prompt.ask("""[bright_white]
Press Enter to continue..."""
                        )
                        continue

                    self.pgp_encrypt_directory(
                        target_directory_path=Path(raw_dir),
                        recipients=[recipient]
                    )

                # Pause after task completion so user can read output before
                # screen clears
                Prompt.ask("""[bright_white]
Press Enter to return to the menu..."""
                )

            except KeyboardInterrupt:
                c.print("""[yellow]
[!] Operation cancelled by user."""
                )
                break
            except Exception as e:
                c.print(f"""[bright_red]
[!] An error occured during processing: {e}."""
                )
                Prompt.ask("""[bright_white]
Press Enter to continue..."""
                )
