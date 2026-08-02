"""
PGP File Encryption / Decryption Utility
========================================

Requires:
    pip install python-gnupg
    GnuPG installed on the system (gpg command available)

Usage:
    python pgp_encryptor.py
"""

import os
import sys
import getpass
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Tuple

try:
    import gnupg
except ImportError:
    print(
        "Missing dependency: python-gnupg\n"
        "Install with: \"pip install python-gnupg\""
        )
    sys.exit(1)

class PGPCrypto:
    """
    Encrypts or decrypts files using PGP/GPG via python-gnupg.

    Supports:
        • Asymmetric encryption (public/private key pairs)
        • Symmetric encryption (password-only, no keys required)
        • ASCII-armoured output (.asc) or binary output (.gpg)
        • Recursive directory traversal
        • Logging to both console and a log file
        • Secure passphrase prompting via getpass
    """

    ENCRYPTED_SUFFIXES = (".gpg", ".asc")
    BINARY_SUFFIX = ".gpg"
    ARMORED_SUFFIX = ".asc"
    SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv"}


    # ==========================
    #
    #  Construction & GPG setup
    #
    # ==========================

    def __init__(
            self,
            gpg_home: Optional[str] = None,
            log_file: Optional[str] = None,
            passphrase: Optional[str] = None,
    ):
        """
        Args:
            gpg_home : Path to the GPG keyring directory. None → default (~/.gnupg).
            log_file : Path to a log file.
            None → auto-generated in cwd.
            passphrase : Passphrase for private key decryption or symmetric ops.
            If None, will be prompted interactively when needed.
        """
        self.gpg_home = gpg_home
        self._gpg: Optional[gnupg.GPG] = None
        self._recipient_fp: Optional[str] = None
        self._key_imported = False
        self._armored = False
        self._symmetric = False
        self._passphrase = passphrase
        self.logger = self._setup_logger(log_file)

    def _setup_logger(
            self,
            log_file: Optional[str]
    ) -> logging.Logger:
        """Create a logger that writes to both console and a log file."""
        if log_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_file = f"pgp_crypto_{timestamp}.log"

        logger = logging.getLogger("pgp_crypto")
        logger.setLevel(logging.DEBUG)
        logger.handlers.clear()

        fmt = logging.Formatter(
            fmt="%(asctime)s  %(levelname)-7s  %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            )

        # File handler (DEBUG level - captures everything)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

        # Console handler (INFO level - user-facing)
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.INFO)
        ch.setFormatter(fmt)
        logger.addHandler(ch)

        logger.info(f"Log file : {log_file}")
        return logger

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


    # ------------------------------------————
    #
    #  Key management (asymmetric mode only)
    #
    # ----------------------------------------

    def import_key(self, key_path: str) -> bool:
        """Import a PGP public or private key from an external file.
        Returns True on success.
        """
        try:
            with open(key_path, "r", encoding="utf-8") as fh:
                key_data = fh.read()
        except OSError as e:
            self.logger.error(
                f"Cannot read key file \"{key_path}\" : {e}"
                )
            return False

        result = self.gpg.import_keys(key_data)

        if result.count == 0:
            self.logger.error(
                "No keys imported — the file may not contain a valid PGP key."
                )
            return False

        self._recipient_fp = result.fingerprints[0]
        self._key_imported = True
        self.logger.info(
            f"Imported key fingerprint : {self._recipient_fp}"
            )
        self.logger.debug(
            f"Full import result : {result.summary()}"
            )
        return True

    def is_symmetric(self) -> bool:
        """Check if the instance is configured for symmetric mode."""
        return self._symmetric


    # ---------------------
    #
    #  Passphrase handling
    #
    # ---------------------

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
        if self._passphrase is not None and not force_new:
            self.logger.debug(
                f"Using cached passphrase for {purpose}"
                )
            return self._passphrase

        attempts_left = 3
        while attempts_left > 0:
            if confirm:
                pass1 = getpass.getpass(
                    f"Enter passphrase for {purpose} : "
                    )
                pass2 = getpass.getpass(
                    f"Confirm passphrase for {purpose} : "
                    )

                if pass1 != pass2:
                    self.logger.warning(
                        "Passphrases did not match."
                        )
                    attempts_left -= 1
                    print(
                        f"\n[-] {attempts_left} attempt(s) remaining.\n"
                        )
                    continue
            else:
                pass1 = getpass.getpass(
                    f"Enter passphrase for {purpose} : "
                    )
                if len(pass1) < 1:
                    self.logger.warning(
                        "Empty passphrase not allowed."
										)
                    attempts_left -= 1
                    continue

            self.logger.info(
						f"Passphrase accepted for {purpose}"
						)
            self._passphrase = pass1
            return pass1

        self.logger.error(
            f"Too many failed passphrase attempts for {purpose}"
            )
        return None

    def clear_passphrase(self) -> None:
        """Clear any cached passphrase from memory (use after sensitive ops)."""
        self._passphrase = None
        self.logger.info(
            "Cleared cached passphrase from memory"
            )


    # ------------------
    #
    #  Encryption
    #
    # ------------------

    def encrypt_file(
            self,
            file_path: Path | str,
            output_path: Optional[str] = None,
            armored: Optional[bool] = None,
            symmetric: Optional[bool] = None,
            passphrase: Optional[str] = None,
    ) -> bool:
        """
        Encrypt a single file.

        Args:
            file_path : Path to the plaintext source.
            output_path : Where to write the ciphertext.
            If None, derived from input.
            armored : True → ASCII-armored (.asc); False → binary (.gpg).
            If None, uses the instance default.
            symmetric : True → password-only encryption; False → public-key encryption.
            If None, uses the instance setting.
            passphrase : Passphrase for symmetric encryption or private key.
            If None, will be prompted interactively.
        """
        # Resolve instance settings
        use_armor = self._armored if armored is None else armored
        use_symmetric = self._symmetric if symmetric is None else symmetric
        suffix = self.ARMORED_SUFFIX if use_armor else self.BINARY_SUFFIX
        file_path = Path(file_path).resolve()

        if not file_path.is_file():
            self.logger.error(
                f"\"{file_path}\" is not a regular file."
                )
            return False

        # Prepare output path
        base_name = str(file_path)
        for sfx in self.ENCRYPTED_SUFFIXES:
            if base_name.endswith(sfx):
                base_name = base_name[: -len(sfx)]
                break

        if output_path is None:
            output_path = base_name + suffix
        else:
            output_path = str(Path(output_path).resolve())

        # Handle passphrase
        effective_passphrase = passphrase or self._passphrase

        if use_symmetric:
            # Symmetric mode requires a passphrase
            if effective_passphrase is None:
                effective_passphrase = self._get_passphrase(
                    purpose="symmetric encryption",
                    confirm=True
                    )
            if effective_passphrase is None:
                self.logger.error(
                    "Symmetric encryption aborted : no passphrase provided."
                    )
                return False
        else:
            # Asymmetric mode requires a key
            if not self._key_imported:
                self.logger.error(
                    "Asymmetric encryption requires an imported public key."
                    )
                return False

        try:
            with open(file_path, "rb") as fh:
                if use_symmetric:
                    result = self.gpg.encrypt_file(
                        fh,
                        output=output_path,
                        symmetric=True,
                        passphrase=effective_passphrase,
                        armor=use_armor,
                        always_trust=True,
                        )
                else:
                    result = self.gpg.encrypt_file(
                        fh,
                        recipients=[self._recipient_fp],
                        output=output_path,
                        always_trust=True,
                        armor=use_armor,
                        )
        except OSError as e:
            self.logger.error(
                f"Cannot read \"{file_path}\" : {e}"
                )
            return False

        if result.ok:
            mode_str = "SYMMETRIC" if use_symmetric else "ASYMMETRIC"
            arm_str = "ARMORED" if use_armor else "BINARY"
            self.logger.info(
                f"Encrypted [{mode_str} + {arm_str}] "
                f"{file_path.name} → {Path(output_path).name}"
                )
            self.logger.debug(
                f"Result status : {result.status}"
                )
            return True
        else:
            self.logger.error(
                f"Failed to encrypt \"{file_path.name}\" : {result.status}"
                )
            return False

    def encrypt_directory(
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
            f"encrypted: {encrypted}, skipped: {skipped}, failed: {failed}"
            )
        return encrypted


    # -------------------
    #
    #  Decryption
    #
    # -------------------

    def decrypt_file(
            self,
            file_path: Path | str,
            output_path: Optional[str] = None,
            passphrase: Optional[str] = None,
    ) -> bool:
        """Decrypt a single PGP-encrypted file.

        Args:
            file_path : Path to the encrypted (.gpg / .asc) file.
            output_path : Where to write the decrypted plaintext.
            If None, the cipher suffix is stripped from the input name.
            passphrase : Passphrase for symmetric decryption or private key.
            If None, will be prompted interactively.
        """
        file_path = Path(file_path).resolve()

        if not file_path.is_file():
            self.logger.error(
                f"\"{file_path}\" is not a regular file."
                )
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
                f"Output \"{Path(output_path).name}\" already exists. Overwrite?"
                )
            if not overwrite:
                self.logger.warning(
                    f"Skipped \"{file_path.name}\" — output exists and was not overwritten."
                    )
                return False

        # Determine if this is likely symmetric (no private key in keyring)
        use_symmetric = self._symmetric or not self._key_imported

        # Handle passphrase
        effective_passphrase = passphrase or self._passphrase

        if use_symmetric:
            if effective_passphrase is None:
                effective_passphrase = self._get_passphrase(
                    purpose="symmetric decryption",
                    confirm=False
                    )
            if effective_passphrase is None:
                self.logger.error(
                    "Symmetric decryption aborted : no passphrase provided."
                    )
                return False
        else:
            # Asymmetric mode - passphrase needed if private key is protected
            # We still allow None since GPG may use agent or unencrypted key
            if effective_passphrase is not None:
                self.logger.info(
                    "Private key passphrase supplied for asymmetric decryption"
                    )

        try:
            with open(file_path, "rb") as fh:
                if use_symmetric:
                    result = self.gpg.decrypt_file(
                        fh,
                        output=output_path,
                        passphrase=effective_passphrase,
                        always_trust=True,
                        )
                else:
                    result = self.gpg.decrypt_file(
                        fh,
                        output=output_path,
                        passphrase=effective_passphrase,
                        always_trust=True,
                        )
        except OSError as e:
            self.logger.error(
                f"Cannot read \"{file_path}\" : {e}"
                )
            return False

        if result.ok:
            mode_str = "SYMMETRIC" if use_symmetric else "ASYMMETRIC"
            self.logger.info(
                f"Decrypted [{mode_str}] {file_path.name} -> "
                f"{Path(output_path).name}"
                )
            self.logger.debug(
                f"Result status : {result.status}"
                )
            return True
        else:
            self.logger.error(
                f"Failed to decrypt -> {file_path.name} : {result.status}"
                )
            self.logger.debug(
                f"stderr : {result.stderr}"
                )

            # Provide context for common failure modes
            if "bad passphrase" in (result.stderr or "").lower():
                self.logger.warning(
                    "Possible wrong passphrase or expired key"
                    )
            elif "no secret key" in (result.stderr or "").lower():
                self.logger.warning(
                    "Private key not found in keyring"
                    )
            return False

    def decrypt_directory(
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

            if self.decrypt_file(str(entry)):
                decrypted += 1
            else:
                failed += 1

        self.logger.info(
            f"Directory \"{dir_path}\" — "
            f"decrypted : {decrypted}, skipped : {skipped}, failed : {failed}"
            )
        return decrypted


    # ----------------------
    #
    #  Interactive session
    #
    # ----------------------

    def run_interactive(self) -> None:
        """Drive the full interactive encryption or decryption session."""
        self._print_banner()

        # GPG home
        gpg_home = self._prompt(
            "Enter GPG home directory (blank for default ~/.gnupg) : ",
            default="",
            )
        self.gpg_home = gpg_home.strip() or None
        self._init_gpg()

        # Operation mode
        operation = self._prompt(
            "\nChoose operation :\n"
            "  1) Encrypt\n"
            "  2) Decrypt\n"
            "Selection [1/2] : ",
            validator=lambda v: v.strip() in ("1", "2"),
            error_msg="Please enter \"1\" or \"2\".",
            ).strip()

        # Encryption/Decryption mode selection
        # Encrypt
        if operation == "1":
            enc_mode = self._prompt(
                "\nEncryption type :\n"
                "  1) Asymmetric (using public key)\n"
                "  2) Symmetric (password-only, no key needed)\n"
                "Selection [1/2] : ",
                validator=lambda v: v.strip() in ("1", "2"),
                error_msg="Please enter \"1\" or \"2\".",
                ).strip()

            self._symmetric = (enc_mode == "2")
            # Reset default
            self._armored = False

        # For decrypt, auto-detect based on available keys
        # Decrypt
        if operation == "2":
            has_keys = len(
                self.gpg.list_keys(secret=True)
                ) > 0
            if has_keys:
                dec_mode = self._prompt(
                    "\nDecryption type :\n"
                    "  1) Asymmetric (using private key)\n"
                    "  2) Symmetric (password-only)\n"
                    "Selection [1/2] : ",
                    validator=lambda v: v.strip() in ("1", "2"),
                    error_msg="Please enter \"1\" or \"2\".",
                    ).strip()
                self._symmetric = (dec_mode == "2")
            else:
                self.logger.info(
                    "No private keys found. Switching to symmetric mode."
                    )
                self._symmetric = True

        # Key import (only for asymmetric)
        if not self._symmetric:
            key_label = "public" if operation == "1" else "private"
            key_path = self._prompt(
                f"Enter the path to the recipient's {key_label} PGP key file : ",
                validator=self._validate_existing_file,
                )
            if not self.import_key(key_path):
                self.logger.error(
                    "Key import failed. Cannot continue."
                    )
                return

        # Target scope
        scope = self._prompt(
            "\nTarget :\n"
            "  1) Single file\n"
            "  2) All files in a directory\n"
            "Selection [1/2] : ",
            validator=lambda v: v.strip() in ("1", "2"),
            error_msg="Please enter \"1\" or \"2\".",
            ).strip()

        recursive = False
        target_path = ""
        if scope == "2":
            target_path = self._prompt(
                "Enter the directory path : ",
                validator=self._validate_existing_dir,
                )
            recursive = self._prompt(
                "Recursively traverse subdirectories? [y/n]: ",
                validator=lambda v: v.strip().lower() in ("y", "n", ""),
                error_msg="Please enter \"y\" or \"n\".",
                ).strip().lower() == "y"
        else:
            target_path = self._prompt(
                "Enter the file path : ",
                validator=self._validate_existing_file,
                )

        # Armor option (encrypt only, asymmetric only typically)
        if operation == "1" and not self._symmetric:
            armor_choice = self._prompt(
                "\nOutput format :\n"
                "  1) Binary (.gpg)\n"
                "  2) ASCII-armored (.asc)\n"
                "Selection [1/2] : ",
                validator=lambda v: v.strip() in ("1", "2"),
                error_msg="Please enter \"1\" or \"2\".",
                ).strip()
            self._armored = (armor_choice == "2")
        elif operation == "1" and self._symmetric:
            self._armored = self._prompt(
                "\nASCII-armored output (.asc)? [y/n] : ",
                validator=lambda v: v.strip().lower() in ("y", "n", ""),
                error_msg="Please enter \"y\" or \"n\".",
                ).strip().lower() == "y"

        # Execute
        self.logger.info("=" * 50)
        op_type = "SYMMETRIC" if self._symmetric else "ASYMMETRIC"
        self.logger.info(
            f"Operation: {"ENCRYPT" if operation == "1" else "DECRYPT"}  |  "
            f"Mode: {op_type}  |  "
            f"Scope: {"DIRECTORY" if scope == "2" else "FILE"}  |  "
            f"Recursive: {recursive}  |  "
            f"Armored: {self._armored}"
            )
        self.logger.info("=" * 50)

        # Encrypt
        if operation == "1":
            if scope == "1":
                self.encrypt_file(target_path)
            else:
                count = self.encrypt_directory(
                    target_path,
                    recursive=recursive,
                    symmetric=True if self._symmetric else False
                    )
                self.logger.info(
                    f"Total files encrypted : {count}"
                    )
        else:
        # Decrypt
            if scope == "1":
                self.decrypt_file(target_path)
            else:
                count = self.decrypt_directory(
                    target_path,
                    recursive=recursive
                    )
                self.logger.info(
                    f"Total files decrypted : {count}"
                    )

        # Security cleanup for symmetric mode
        if self._symmetric:
            self._prompt(
                "\nPress Enter to clear cached passphrase from memory...",
                default="",
                )
            self.clear_passphrase()
            self.logger.info(
                "Session complete. Passphrase cleared from memory."
                )


    # -------------------
    #
    #  Prompt helpers
    #
    # -------------------

    @staticmethod
    def _prompt(
            message: str,
            validator = None,
            error_msg: str = "Invalid input, please try again.",
            default: Optional[str] = None,
    ) -> str:
        while True:
            user_input = input(message).strip()
            if not user_input and default is not None:
                return default
            if validator is None or validator(user_input):
                return user_input
            print(f"  ✖ {error_msg}")

    @staticmethod
    def _confirm(message: str) -> bool:
        resp = input(
            f"{message} [y/n] : "
            ).strip().lower()
        return resp == "y"

    @staticmethod
    def _validate_existing_file(path: str) -> bool:
        return Path(path).is_file()

    @staticmethod
    def _validate_existing_dir(path: str) -> bool:
        return Path(path).is_dir()

    @staticmethod
    def _print_banner() -> None:
        width = 60
        print("=" * width)
        print(
            "PGP File Encryption / Decryption Utility".center(width)
            )
        print("=" * width)


# ===================
#
#  Entry point
#
# ===================

def main() -> None:
    crypto = PGPCrypto()
    try:
        crypto.run_interactive()
    except KeyboardInterrupt:
        print(
            "\n\nOperation cancelled by user.\n"
            )
        sys.exit(130)

if __name__ == "__main__":
    main()
