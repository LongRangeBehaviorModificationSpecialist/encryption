# !/usr/bin/env python3
# DLU : 03-Aug-2026


from datetime import datetime
import getpass
import logging
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
from resources.functions import Functions
from resources.prompts import (
    show_main_app_menu,
    show_pgp_encryption_menu,
    show_pgp_decryption_menu,
    show_pgp_encryption_type_menu,
    show_pgp_decryption_type_menu,
    show_pgp_armor_choice
)


class PGP:

    def __init__(self, password: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        self.EXCLUDE_EXT_LIST = {".encrypted", ".enc", ".pgp", "gpg", ".key"}
        self.ENCRYPTED_SUFFIXES = (".gpg", ".asc")
        self.BINARY_SUFFIX = ".gpg"
        self.ARMORED_SUFFIX = ".asc"
        self.SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv"}
        self.script_path = Path(__file__).parent.resolve()
        self.gpg_home = self.script_path / ".gnupg"
        self._recipient_fp: Optional[str] = None
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
                "install GnuPG.")

        self.gpg = gnupg.GPG(
            gnupghome=str(self.gpg_home), gpgbinary=self.resolved_gpg)
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


    def import_key(self, key_path: Path | str) -> bool:
        """Import a PGP public or private key from an external file.
        Returns True on success.
        """
        try:
            with open(key_path, "r", encoding="utf-8") as fh:
                key_data = fh.read()
        except OSError as e:
            self.logger.error(
                f"Cannot read key file \"{key_path}\" : {e}")
            return False

        result = self.gpg.import_keys(key_data)

        if result.count == 0:
            self.logger.error(
                "No keys imported — the file may not contain a valid PGP key.")
            return False

        self._recipient_fp = result.fingerprints[0]
        self._key_imported = True
        self.logger.info(
            f"Imported key fingerprint : {self._recipient_fp}")
        self.logger.debug(
            f"Full import result : {result.summary()}")
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
            force_new : If True, always prompt even if passphrase is cached.

            purpose : Description of what the passphrase is for (logging).

            confirm : If True, prompt twice to confirm the passphrase.
        """
        if self._password is not None and not force_new:
            self.logger.debug(
                f"Using cached passphrase for {purpose}")
            return self._password

        attempts_left = 3
        while attempts_left > 0:
            if confirm:
                password1 = getpass.getpass(
                    f"Enter passphrase for {purpose} : ")
                password2 = getpass.getpass(
                    f"Confirm passphrase for {purpose} : ")

                if password1 != password2:
                    self.logger.warning(
                        "Passphrases did not match.")
                    attempts_left -= 1
                    console.print(
                        f"\n[-] {attempts_left} attempt(s) remaining.\n")
                    continue
            else:
                password1 = getpass.getpass(
                    f"Enter passphrase for {purpose} : ")
                if len(password1) < 1:
                    self.logger.warning(
                        "Empty passphrase not allowed.")
                    attempts_left -= 1
                    continue

            self.logger.info(
                f"Passphrase accepted for {purpose}")
            self._password = password1
            return password1

        self.logger.error(
            f"Too many failed passphrase attempts for {purpose}")
        return None


    def clear_passphrase(self) -> None:
        """Clear any cached passphrase from memory (use after sensitive ops)."""
        self._password = None
        self.logger.info(
            "Cleared cached passphrase from memory")


    def pgp_export_public_key(self, keyid: str) -> str:
        """Exports an armored public key by Key ID to the designated file path.

        Args:
            keyid: ID or fingerprint of the PGP key to export.

        Returns:
            str: The exported ASCII-armored public key block.
        """
        public_key_data = self.gpg.export_keys(
            keyids=keyid,
            output=str(self.public_key_file))
        if not public_key_data or not self.public_key_file.exists():
            raise RuntimeError(
                f"Failed to export public key for Key ID '{keyid}'")
        console.print(
            f"[bright_white][-] Public key exported successfully to "
            f"{self.public_key_file.name}")
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
            output=str(self.private_key_file))
        if not private_key_data or not self.private_key_file.exists():
            raise RuntimeError(
                f"Failed to export private key for Key ID : {keyid}. "
                "Check the keyid/passphrase.")
        console.print(
            f"[bright_white][-] Private key exported successfully to "
            f"{self.private_key_file.name}")
        return str(private_key_data)


    def generate_pgp_key_pair(
            self,
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
                f"Invalid or missing email address provided : {email_address}")

        input_data = self.gpg.gen_key_input(
            name_email=email_address,
            passphrase=password,
            key_type="RSA",
            key_length=key_length)

        key = self.gpg.gen_key(input_data)

        if not key.fingerprint:
            raise RuntimeError(
                f"PGP key generation failed. Engine error output : "
                f"{key.stderr}")

        fingerprint = str(key.fingerprint)
        console.print(
            f"[bright_white][-] Generated Key Fingerprint : {fingerprint}")

        # Export keys upon successful generation
        self.pgp_export_public_key(keyid=fingerprint)
        self.pgp_export_private_key(
            keyid=fingerprint,
            password=password)

        return fingerprint


    def pgp_encrypt_single_file(
            self,
            target_file: Path | str,
            recipients: str | List[str],
            output_path: Optional[Path | str] = None,
            armored: Optional[bool] = None,
            symmetric: Optional[bool] = None,
            password: Optional[str] = None,
            always_trust: bool = True
    ) -> bool:
        """Encrypts a single file using PGP/GPG and handles GPG engine
        failures safely.

        Args:
            target_file : Path to the plaintext source.

            output_path : Where to write the ciphertext. If None, derived from
            input.

            armored : True → ASCII-armored (.asc); False → binary (.gpg). If
            None, uses the instance default.

            symmetric : True → password-only encryption; False → public-key
            encryption. If None, uses the instance setting.

            passphrase : Passphrase for symmetric encryption or private key.
            If None, will be prompted interactively.
        """
        # Resolve instance settings
        use_armor = self._armored if armored is None else armored
        use_symmetric = self._symmetric if symmetric is None else symmetric
        suffix = self.ARMORED_SUFFIX if use_armor else self.BINARY_SUFFIX
        target_file = Path(target_file).resolve()

        if not target_file.is_file():
            self.logger.error(
                f"\"{target_file}\" is not a regular file.")
            return

        # Prepare output path
        base_name = str(target_file)
        for sfx in self.ENCRYPTED_SUFFIXES:
            if base_name.endswith(sfx):
                base_name = base_name[: -len(sfx)]
                break

        if output_path is None:
            output_path = base_name + suffix
        else:
            output_path = str(Path(output_path).resolve())

        # Handle passphrase
        effective_password = password or self._password

        if use_symmetric:
            # Symmetric mode requires a passphrase
            if effective_password is None:
                effective_password = self._get_passphrase(
                    purpose="symmetric encryption",
                    confirm=True)
            if effective_password is None:
                self.logger.error(
                    "Symmetric encryption aborted -> no passphrase provided.")
                return False
        else:
            # Asymmetric mode requires a key
            if not self._key_imported:
                self.logger.error(
                    "Asymmetric encryption requires an imported public key.")
                return False

        try:
            with open(target_file, "rb") as fh:
                if use_symmetric:
                    result = self.gpg.encrypt_file(
                        fh,
                        output=output_path,
                        symmetric=True,
                        password=effective_password,
                        armor=use_armor,
                        always_trust=True)
                else:
                    result = self.gpg.encrypt_file(
                        fh,
                        recipients=[self._recipient_fp],
                        output=output_path,
                        always_trust=True,
                        armor=use_armor)
        except OSError as e:
            self.logger.error(
                f"Cannot read \"{target_file}\" : {e}")
            return False

        if result.ok:
            mode_str = "SYMMETRIC" if use_symmetric else "ASYMMETRIC"
            arm_str = "ARMORED" if use_armor else "BINARY"
            self.logger.info(
                f"Encrypted [{mode_str} + {arm_str}] "
                f"{target_file.name} → {Path(output_path).name}")
            self.logger.debug(
                f"Result status : {result.status}")
            return True
        else:
            self.logger.error(
                f"Failed to encrypt \"{target_file.name}\" : {result.status}")
            if output_path.exists():
                output_path.unlink(missing_ok=True)
            return False


    def pgp_encrypt_files_in_directory(
            self,
            dir_path: Path | str,
            recursive: bool = False,
            armored: Optional[bool] = None,
            symmetric: Optional[bool] = None,
    ) -> int:
        """
        Encrypt every regular file inside *dir_path*.
        Returns count of files successfully encrypted.
        """
        dir_path = Path(dir_path).resolve()
        encrypted, skipped, failed = 0, 0, 0

        self.logger.info(
            f"Starting {"SYMMETRIC" if symmetric else "ASYMMETRIC"} "
            f"encryption of directory \"{dir_path}\""
            )

        iterator = dir_path.rglob("*") if recursive else dir_path.glob("*")

        for entry in iterator:
            if entry.is_dir():
                continue
            if not entry.is_file():
                continue
            if entry.name.startswith("."):
                continue
            if entry.suffix in self.ENCRYPTED_SUFFIXES:
                skipped += 1
                continue

            if self.encrypt_file(
                str(entry),
                armored=armored,
                symmetric=symmetric):
                encrypted += 1
            else:
                failed += 1

        self.logger.info(
            f"Directory \"{dir_path}\" — "
            f"encrypted: {encrypted}, skipped: {skipped}, failed: {failed}")
        return encrypted


    def pgp_decrypt_single_file(
            self,
            file_path: Path | str,
            output_path: Optional[str] = None,
            password: Optional[str] = None,
    ) -> bool:
        """Decrypt a single PGP-encrypted file.

        Args:
            file_path : Path to the encrypted (.gpg / .asc) file.

            output_path : Where to write the decrypted plaintext. If None, the
            cipher suffix is stripped from the input name.

            passphrase : Passphrase for symmetric decryption or private key. If
            None, will be prompted interactively.
        """
        file_path = Path(file_path).resolve()

        if not file_path.is_file():
            self.logger.error(
                f"\"{file_path}\" is not a regular file.")
            return False

        # Derive output path by stripping known cipher suffixes
        base_name = str(file_path)
        for sfx in self.ENCRYPTED_SUFFIXES:
            if base_name.endswith(sfx):
                base_name = base_name[: -len(sfx)]
                break

        if output_path is None:
            output_path = base_name
        else:
            output_path = str(Path(output_path).resolve())

        # Avoid overwriting an existing plaintext file silently
        if Path(output_path).exists():
            overwrite = self._confirm(
                f"Output \"{Path(output_path).name}\" already exists. "
                "Overwrite?")
            if not overwrite:
                self.logger.warning(
                    f"Skipped \"{file_path.name}\" — output exists and was "
                    "not overwritten.")
                return False

        # Determine if this is likely symmetric (no private key in keyring)
        use_symmetric = self._symmetric or not self._key_imported

        # Handle passphrase
        effective_password = password or self._password

        if use_symmetric:
            if effective_password is None:
                effective_password = self._get_passphrase(
                    purpose="symmetric decryption",
                    confirm=False)
            if effective_password is None:
                self.logger.error(
                    "Symmetric decryption aborted : no passphrase provided.")
                return False
        else:
            # Asymmetric mode - passphrase needed if private key is protected
            # We still allow None since GPG may use agent or unencrypted key
            if effective_password is not None:
                self.logger.info(
                    "Private key passphrase supplied for asymmetric decryption")

        try:
            with open(file_path, "rb") as fh:
                if use_symmetric:
                    result = self.gpg.pgp_decrypt_single_file(
                        fh,
                        output=output_path,
                        passphrase=effective_password,
                        always_trust=True,)
                else:
                    result = self.gpg.pgp_decrypt_single_file(
                        fh,
                        output=output_path,
                        passphrase=effective_password,
                        always_trust=True,)
        except OSError as e:
            self.logger.error(
                f"Cannot read \"{file_path}\" : {e}")
            return False

        if result.ok:
            mode_str = "SYMMETRIC" if use_symmetric else "ASYMMETRIC"
            self.logger.info(
                f"Decrypted [{mode_str}] {file_path.name} -> "
                f"{Path(output_path).name}")
            self.logger.debug(
                f"Result status : {result.status}")
            return True
        else:
            self.logger.error(
                f"Failed to decrypt -> {file_path.name} : {result.status}")
            self.logger.debug(
                f"stderr : {result.stderr}")

            # Provide context for common failure modes
            if "bad passphrase" in (result.stderr or "").lower():
                self.logger.warning(
                    "Possible wrong passphrase or expired key")
            elif "no secret key" in (result.stderr or "").lower():
                self.logger.warning(
                    "Private key not found in keyring")
            return False


    def pgp_decrypt_files_in_directory(
                self,
                dir_path: Path | str,
                recursive: bool = False,
        ) -> int:
            """Decrypt every PGP-encrypted file inside *dir_path*.
            Returns count of files successfully decrypted.
            """
            dir_path = Path(dir_path).resolve()
            decrypted, skipped, failed = 0, 0, 0

            self.logger.info(
                f"Starting decryption of directory -> {dir_path}"
                )

            iterator = dir_path.rglob("*") if recursive else dir_path.glob("*")

            for entry in iterator:
                if entry.is_dir():
                    continue
                if not entry.is_file():
                    continue

                if entry.suffix not in (self.BINARY_SUFFIX, self.ARMORED_SUFFIX):
                    skipped += 1
                    continue

                if self.pgp_decrypt_single_file(str(entry)):
                    decrypted += 1
                else:
                    failed += 1

            self.logger.info(
                f"Directory \"{dir_path}\" — "
                f"decrypted : {decrypted}, skipped : {skipped}, failed : "
                f"{failed}")

            return decrypted


    def get_pgp_action_choice(self, action: str) -> None:
        """Gets input from the user on what action to start next."""
        action = action.lower().strip()

        # GPG home
        gpg_home = Prompt.ask(
            "Enter GPG home directory (blank for default ~/.gnupg) : ")
        self.gpg_home = gpg_home.strip() or None
        self._init_gpg()



        if action == "encrypt":
            pgp_encryption_choice = show_pgp_encryption_menu()
            match pgp_encryption_choice:
                case "1":  # Generate new PGP key pair
                    password = Functions.get_password()
                    email_address = Functions.get_email_address()
                    if not password.strip() or not email_address.strip():
                        console.print(
                            "\n[yellow][!] Key generation cancelled : Missing "
                            "password or email.")
                        Prompt.ask(
                            "[bright_white][-] Press Enter to return to menu...")
                        return
                    PGP.generate_pgp_key_pair(
                        password=password,
                        email=email_address)
                case "2":  # Encrypt a file with PGP
                    # Ask user to select type of PGP encryption:
                    # "1" = Asymmetric
                    # "2" = Symmetric
                    pgp_encryption_type_choice = show_pgp_encryption_type_menu()
                    match pgp_encryption_type_choice:
                        case "1":  # Asymmetric
                            self._symmetric = False
                            self._armored = False
                            pgp_encryption_armor_choice = show_pgp_armor_choice()
                            match pgp_encryption_armor_choice:
                                case "1":  # User chooses .pgp file output
                                    self._armored = False
                                case "2":  # User chooses .asc file output
                                    self._armored = True
                        case "2":  # Symmetric
                            self._symmetric = True
                            self._armored = False
                        case "r":
                            Functions.clear_screen()
                            show_main_app_menu()
                        case "q":
                            Functions.exit_application()
                    # Key import (only for asymmetric)
                    if not self._symmetric:
                        key_label = "private"
                        key_path = Prompt.ask(
                            "[bright_white][-] enter the path to the "
                            f"recipient's {key_label} PGP key file ")
                        if not self.import_key(key_path):
                            self.logger.error(
                                "Key import failed. Cannot continue")
                            return

                case "3":
                    target_dir = Functions.get_directory_path(text="encrypted")

                    recursive = Functions.select_recursive_option(
                        action="encrypt")
                    PGP.pgp_encrypt_single_files_in_folder(
                        target_dir=target_dir,
                        recursive=recursive)
                case "r":
                    Functions.clear_screen()
                    show_main_app_menu()
                case "q":
                    Functions.exit_application()





        elif action == "decrypt":
            pgp_decryption_choice = show_pgp_decryption_menu()
            match pgp_decryption_choice:
                case "1":  # Decrypt a single file with PGP
                    # For decrypt, auto-detect based on available keys
                    has_keys = len(
                        self.gpg.list_keys(secret=True)
                        ) > 0
                    if has_keys:
                        # Ask user to select type of PGP encryption:
                        # "1" = Asymmetric
                        # "2" = Symmetric
                        pgp_decryption_type_choice = (
                            show_pgp_decryption_type_menu())
                        match pgp_decryption_type_choice:
                            case "1":
                                # Set self._symmetric value to True
                                self._symmetric = (
                                    pgp_decryption_type_choice == "2")
                            case "2":
                                pass
                    else:
                        self.logger.info(
                            "No private keys found. Switching to symmetric mode."
                        )
                        self._symmetric = True
                    # Key import (only for asymmetric)
                    if not self._symmetric:
                        key_label = "private"
                        key_path = self._prompt(
                            f"Enter the path to the recipient's {key_label} PGP key file : ",
                            validator=self._validate_existing_file,
                            )
                        if not self.import_key(key_path):
                            self.logger.error(
                                "Key import failed. Cannot continue."
                                )
                            return
                case "2":
                    target_path = Functions.get_directory_path(text="decrypt")
                    recursive = Functions.select_recursive_option()
                case "r":
                    Functions.clear_screen()
                    show_main_app_menu()
                case "q":
                    Functions.exit_application()
