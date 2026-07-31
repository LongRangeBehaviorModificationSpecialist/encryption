# !/usr/bin/env python3
# DLU : 31-Jul-2026


import gnupg
import os
from pathlib import Path
import shutil
from typing import List, Optional

from rich.prompt import Prompt

# Import the console object from the main __init__.py file
from . import console
from resources.functions import Functions
from resources.prompts import PGP_ENCRYPTION_PROMPT


class PGPClass:

    script_path = Path(__file__).parent.resolve()

    gnupg_home_dir = script_path / ".gnupg"

    if not gnupg_home_dir.exists():
        gnupg_home_dir.mkdir(parents=True, exist_ok=True)

    if os.name == "posix":
        os.chmod(gnupg_home_dir, 0o700)

    resolved_gpg = (
        shutil.which("gpg")
        or r"C:\Program Files\GnuPG\bin\gpg.exe"
        )
    if not shutil.which(resolved_gpg) and not Path(resolved_gpg).exists():
        raise FileNotFoundError(
            f"GnuPG binary not found at '{resolved_gpg}'. Please install "
            "GnuPG."
            )

    gpg = gnupg.GPG(
        gnupghome=str(gnupg_home_dir), gpgbinary=resolved_gpg
        )
    gpg.encoding = "utf-8"

    private_key_file = script_path / "mas_private_key.asc"
    public_key_file = script_path / "mas_public_key.asc"


    @classmethod
    def pgp_export_public_key(cls, keyid: str) -> str:
        """Exports an armored public key by Key ID to the designated file path.

        Args:
            keyid: ID or fingerprint of the PGP key to export.

        Returns:
            str: The exported ASCII-armored public key block.
        """
        public_key_data = cls.gpg.export_keys(
            keyids=keyid,
            output=str(cls.public_key_file)
            )
        if not public_key_data or not cls.public_key_file.exists():
            raise RuntimeError(
                f"Failed to export public key for Key ID '{keyid}'"
                )
        console.print(
            f"[bright_white][-] Public key exported successfully to "
            f"{cls.public_key_file.name}"
            )
        return str(public_key_data)


    @classmethod
    def pgp_export_private_key(cls, keyid: str, password: str) -> str:
        """Exports an armored private key by Key ID and passphrase to the
        designated file path.

        Args:
            keyid: ID or fingerprint of the PGP key to export.
            password: Passphrase protecting the private key.

        Returns:
            str: The exported ASCII-armored secret key block.
        """
        private_key_data = cls.gpg.export_keys(
            keyids=keyid,
            secret=True,
            passphrase=password,
            output=str(cls.private_key_file)
            )
        if not private_key_data or not cls.private_key_file.exists():
            raise RuntimeError(
                f"Failed to export private key for Key ID : {keyid}. "
                "Check the keyid/passphrase."
                )
        console.print(
            f"[bright_white][-] Private key exported successfully to "
            f"{cls.private_key_file.name}"
            )
        return str(private_key_data)


    @classmethod
    def generate_pgp_key_pair(
            cls,
            password: str,
            email_address: str,
            key_length: int = 2048
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

        input_data = cls.gpg.gen_key_input(
            name_email=email_address,
            passphrase=password,
            key_type="RSA",
            key_length=key_length
            )

        key = cls.gpg.gen_key(input_data)

        if not key.fingerprint:
            raise RuntimeError(
                f"PGP key generation failed. Engine error output : "
                f"{key.stderr}"
                )

        fingerprint = str(key.fingerprint)
        console.print(
            f"[bright_white][-] Generated Key Fingerprint : {fingerprint}"
            )

        # Export keys upon successful generation
        cls.pgp_export_public_key(keyid=fingerprint)
        cls.pgp_export_private_key(
            keyid=fingerprint,
            password=password
            )

        return fingerprint


    @classmethod
    def pgp_encrypt_file(
            cls,
            target_file_path: Path | str,
            recipients: str|List[str],
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
            f"{target_file_path.name}.pgp")

        try:
            with open(target_file_path, "rb") as f:
                status = cls.gpg.encrypt_file(
                    f,
                    recipients=[recipients],
                    always_trust=always_trust,
                    output=str(encrypted_file_path)
                    )
        except Exception as e:
            raise RuntimeError(
                f"Failed to execute GPG encryption: {e}"
                ) from e

        if not status.ok:
            # Clean up partial/empty output file if created
            if encrypted_file_path.exists():
                encrypted_file_path.unlink(missing_ok=True)

            error_msg = getattr(
                status,
                "status",
                getattr(status, "stderr", "Unknown GPG error")
                )
            raise RuntimeError(
                f"PGP Encryption failed for '{target_file_path.name}'. GPG "
                f"status : {error_msg}"
                )

        if hasattr(cls, "print_status"):
            cls.print_status(status)

        console.print(
            f"\n[green][-] PGP file encrypted successfully : "
            f"{encrypted_file_path.name}"
            )

        return encrypted_file_path


    @classmethod
    def pgp_encrypt_files_in_folder(
            cls,
            target_dir_path: Path | str,
            recipients: str|List[str],
            recursive: bool = True,
            always_trust: bool = True
    ) -> List[Path]:
        """Encrypts all files in a directory using PGP/GPG.

        Args:
            dir_path: Target directory containing files to encrypt.
            recipients: Recipient email(s) or key ID(s).
            recursive: If True, search subdirectories recursively.
            always_trust: Passed to single-file encryption method.

        Returns:
            List[Path]: Paths of successfully encrypted `.pgp` files.
        """
        target_dir_path = Path(target_dir_path)
        if not target_dir_path.is_dir():
            console.print(
                f"[bright_red][!] {target_dir_path} does not exist or is "
                "not a valid directory."
                )
            return []

        if isinstance(recipients, str):
            recipients = [
                r.strip() for r in recipients.split(",") if r.strip()
                ]

        if not recipients:
            raise ValueError(
                "At least one recipient email or key ID must be provided."
                )

        # Collect files to encrypt
        if recursive:
            files_to_process = [
                p for p in target_dir_path.rglob("*")
                if p.is_file()
                ]
        else:
            files_to_process = [
                p for p in target_dir_path.iterdir()
                if p.is_file()
                ]

        if not files_to_process:
            console.print(
                f"[yellow][!] No valid files to encrypt in {target_dir_path}"
                )
            return []

        successful_encryptions: List[Path] = []
        failed_encryptions: List[Path] = []

        for file_path in files_to_process:
            # Skip files already encrypted to prevent double encryption
            if file_path.suffix.lower() in [".pgp", ".gpg"]:
                continue

            try:
                encrypted_path = cls.pgp_encrypt_file(
                    target_file_path=file_path,
                    recipients=recipients,
                    always_trust=always_trust
                    )
                successful_encryptions.append(encrypted_path)
            except Exception as e:
                # Continue encrypting remaining files even if one fails
                console.print(
                    f"[bright_red][!] Skipping {file_path.name} due to "
                    f"error : {e}"
                    )
                failed_encryptions.append(file_path)

        if successful_encryptions:
            console.print(
                f"[green][!] ** Action Completed **\nSuccessfully encrypted "
                f"{len(successful_encryptions)} files in \{target_dir_path} :"
                )
            for encrypted_file in successful_encryptions:
                console.print(
                    f"[green]\t{encrypted_file.name}"
                    )

        if failed_encryptions:
            console.print(
                f"\n[bright_red][!] ** Warning **\nFailed to encrypt "
                f"{len(failed_encryptions)} files :"
                )
            for failed_file in failed_encryptions:
                console.print(
                    f"[bright_red]\t{failed_file.name}"
                    )

        return successful_encryptions


    @staticmethod
    def get_pgp_encryption_choice() -> None:
        pgp_encryption_choice = Prompt.ask(
            PGP_ENCRYPTION_PROMPT,
            choices=["1", "2", "3", "r", "q"],
            show_choices=False
            ).strip().lower()

        match pgp_encryption_choice:
            case "1":
                password = Functions.get_password()
                email_address = Functions.get_email_address()
                if not password.strip() or not email_address.strip():
                    console.print(
                        "\n[yellow][!] Key generation cancelled : Missing "
                        "password or email."
                        )
                    Prompt.ask(
                        "[bright_white] [-] Press Enter to return to menu..."
                        )
                    return
                PGPClass.generate_pgp_key_pair(
                    password=password,
                    email=email_address
                    )
            case "2":
                target_file_path = Functions.get_file_path(text="encrypted")
                # User cancelled input
                if not target_file_path or not target_file_path.strip():
                    return
                recipient = Prompt.ask(
                    "\n[bright_white][-] Enter recipient email or Key ID "
                    ).strip()
                if not recipient:
                    console.print(
                        "\n[yellow][!] Encryption cancelled : No recipient "
                        "specified"
                        )
                    Prompt.ask(
                        "[bright_white][-] Press Enter to continue..."
                        )
                    return
                PGPClass.pgp_encrypt_file(
                    target_file_path=target_file_path,
                    recipients=recipient
                    )
            case "3":
                target_dir_path = Functions.get_folder_path(text="encrypted")
                recipient = Prompt.ask(
                    "\n[bright_white][-] Enter recipient email or Key ID "
                    ).strip()
                if not recipient:
                    console.print(
                        "\n[yellow][!] Encryption cancelled : No recipient "
                        "specified"
                        )
                    Prompt.ask(
                        "[bright_white][-] Press Enter to continue..."
                        )
                    return
                recursive = Functions.select_recursive_option()
                PGPClass.pgp_encrypt_files_in_folder(
                    target_dir_path=target_dir_path,
                    recipients=recipient,
                    recursive=recursive
                    )
            case "r":
                # self.return_to_main_menu()
                pass
            case "q":
                Functions.exit_application()



    @staticmethod
    def get_pgp_decryption_choice() -> None:
        pass