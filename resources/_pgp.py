# !/usr/bin/env python3

import inspect
import os
from pathlib import Path
from rich.prompt import Prompt, Confirm
import shutil
import subprocess
import sys
from typing import List

# Imports from the main __init__.py file
from . import console, install
from config.log_config import get_logger
from resources.vars import ENCRYPTED_EXT_LIST
from utils import Utils, UIHandlerProtocol, RichUIHandler

HAS_PGP = False
try:
    from gnupg import GPG
    HAS_PGP = True
except ImportError:
    console.print(
        f"[cyan][{Utils.get_time()}][yellow] Missing "
        "dependency: currently missing the 'python-gnupg' package.\n"
        "It can be installed using the 'pip install python-gnupg' command"
    )
    sys.exit(1)


logger = get_logger("pgp")
install()


class PGP:

    def __init__(self,
        password: str | None = None,
        ui: UIHandlerProtocol | None = None
    ) -> None:
        """Initialize with explicit homedir tracking."""
        self.ui = ui or RichUIHandler(get_time=Utils.get_time)
        # Get path of the gpg executable
        try:
            subprocess.run(["gpgconf", "--kill", "gpg-agent"], check=False)
            logger.info("Killed existing GPG agent")
        except Exception as err:
            logger.warning(f"Could not kill GPG agent: {err}")

        self.resolved_gpg = (
            shutil.which("gpg")
            or r"C:\Program Files\GnuPG\bin\gpg.exe"
        )
        if not self.resolved_gpg and not Path(self.resolved_gpg).exists():
            gnupg_not_found_msg = (
                f"GnuPG binary not found at '{self.resolved_gpg}'. Please "
                "install GnuPG before continuing."
            )
            self.ui.warning(f"{gnupg_not_found_msg}")
            raise FileNotFoundError(f"{gnupg_not_found_msg}")

        # Calculate homedir independently of GPG instance
        self.gpg_homedir = self._get_gpg_homedir()
        os.environ['GNUPGHOME'] = str(self.gpg_homedir)

        # Pass explicit homedir to GPG constructor
        self.gpg = GPG(
            gnupghome=str(self.gpg_homedir),
            gpgbinary=self.resolved_gpg,
            options=[
                "--batch",  # Non-interactive mode
                "--yes",  # Auto-confirm prompts
                "--trust-model", "always",  # Skip key verification
                "--pinentry-mode", "loopback",
                # "--no-use-agent"  # Tells GPG to ignore the agent
            ]
        )

        # Optional: ensure directory exists
        self.gpg_homedir.mkdir(parents=True, exist_ok=True)

        # Now have reliable access without querying gpg.gnupghome
        self.ui.success(f"GPG initialized with: {self.gpg_homedir}")

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
            self.ui.success(f"✓ Public keyring found: {self.pubring_path}")
        else:
            self.ui.warning(f"No public keyring at: {self.pubring_path}")

        if not self.verify_gpg_setup():
            self.ui.error(
                "GPG setup verification failed. Some operations may fail."
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
            f"{Utils.get_date_time(format='file')}_mas_public_key.asc"
        )
        self.default_private_key_file = (
            self.script_path /
            f"{Utils.get_date_time(format='file')}_mas_private_key.asc"
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


    @property
    def class_name(self) -> str:
        """Cached class name (calculated once)."""
        return self.__class__.__name__

    @property
    def current_method(self) -> str:
        """Current method name including class."""
        frame = inspect.currentframe()
        try:
            return f"{self.class_name}.{frame.f_code.co_name}"
        finally:
            del frame


    def print_status(self, status: GPG, current_method: str) -> None:
        """Prints GPG action execution status to terminal."""
        # stderr should be empty/None on success
        if status.ok == True:
            self.ui.success(f"{current_method}() was run successfully")
        else:
            # Show the error message
            status_msg = getattr(
                status,
                "status",
                getattr(status, "stderr", "Unknown Error")
            )
            self.ui.error(
                f"{current_method}() WAS NOT executed → {status_msg}."
                f"Please try again."
            )


    def import_key(self) -> None:
        """Imports a PGP public or private key from an external file.

        Args:
            key_path: Path to the key file. If None, prompts user.
            silent: Suppress console output (useful for batch operations).

        Returns:
            tuple[bool, str]: (success, fingerprint) where fingerprint is
                None on failure
        """
        try:
            key_file = Prompt.ask(
                f"[cyan][{Utils.get_time()}][grey74] Enter the "
                f"file path to the PGP key you want to import"
            ).strip("\"'")

            if not key_file:
                self.ui.warning("No file path provided")
                return

            key_file = Path(key_file).resolve()

            if not key_file.exists():
                self.ui.warning(f"File not found → {key_file}")
                return

            logger.info(f"Importing PGP key from: {key_file}")

            # Read key content
            with open(key_file, "r", encoding="utf-8") as f:
                key_data =f.read()

            # Import the key
            result = self.gpg.import_keys(key_data)

            logger.info(f"Import result type: {type(result)}")
            logger.info(
                f"Import result dir: {[attr for attr in dir(result) if not attr.startswith('_')]}"
            )

            # FIXED: Safely access all optional attributes
            imported = getattr(result, 'imported', 0)
            considered = getattr(result, 'considered', None)
            missing = getattr(result, 'missing', None)
            failed = getattr(result, 'failed', None)
            count = getattr(result, 'count', None)


            if result.fingerprints:
                # Get primary fingerprint (first one)
                # Handles both string and dict formats
                fp = result.fingerprints[0]
                if isinstance(fp, dict):
                    fingerprint = fp.get("fingerprint") or fp
                else:
                    fingerprint = fp  # Already a string

                self.ui.success("✓ Key imported successfully!")
                self.ui.success(f"Fingerprint: {fingerprint}")
                self.ui.success(f"Keys imported: {imported}")
                if considered:
                    self.ui.success(f"Keys considered: {considered}")
                if missing:
                    self.ui.warning(f"Keys missing: {missing}")
                if failed:
                    self.ui.error(f"Keys failed: {failed}")
                if count:
                    self.ui.info(f"Total keys processed: {count}")

                    logger.info(
                        f"Successfully imported PGP key: {fingerprint}"
                    )
            else:
                self.ui.warning("Warning: No fingerprints returned from import")
                self.ui.info(f"Imported count: {imported}")
                self.ui.warning(f"Failed count: {failed or 0}")

        except Exception as err:
            logger.exception(f"Failed to import PGP key → {err}")
            self.ui.error(f"Error importing key → {err}")
            raise RuntimeError(f"Failed to import PGP key → {err}") from err


    def pgp_export_public_key(
            self,
            keyid: str,
            output_path: Path | str | None = None,
    ) -> str:
        """Exports an armored public key by Key ID to the designated
        file path.

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
            self.ui.error(f"Failed to export public key for Key ID → {keyid}")
            raise

        try:
            with open(output_file, "w", newline="\n", encoding="utf-8") as f:
                f.write(public_key_data)
        except Exception as err:
            self.ui.error(f"Failed to write key to {output_file} → {err}")
            raise RuntimeError(
                f"Failed to write key to {output_file} → {err}"
            ) from err

        self.ui.info(f"[bold]Public[/bold] key exported to → {output_file}")

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
            self.ui.error(
                f"Failed to export private key for Key ID → {keyid}. "
                "Check the keyid/passphrase."
            )
            raise RuntimeError(
                f"Failed to export private key ID → {keyid}."
            )

        try:
            with open(output_file, "w", newline="\n", encoding="utf-8") as f:
                f.write(private_key_data)
            if os.name != "nt":
                os.chmod(str(output_file), 0o600)  # Owner read/write only
        except Exception as err:
            self.ui.error(f"Failed to write key to {output_file} → {err}")
            raise RuntimeError(
                f"Failed to write key to {output_file} → {err}"
            ) from err

        self.ui.info(
            f"[b]Private[/b] key exported successfully to → "
            f"[blue]{output_file}"
        )

        return private_key_data


    def generate_pgp_key_pair(self, key_length: int = 4096) -> str:
        """Generates a new RSA PGP key pair and prompts the user to
        export the public and/or private keys.

        Must use 'self.gpg_homedir' (not gpg.gnupghome) within the code.

        Args:
            key_length: Bit length of the RSA key (default: 4096).
            expire_days: Key expiration in days. If None, key never expires.

        Returns:
            str: Fingerprint of the newly created key pair.
        """
        full_name = Utils.get_pgp_full_name()
        email_address = Utils.get_pgp_email_address()
        password = Utils.get_confirmed_password()

        # Optional: Add a comment field
        comment = Prompt.ask(
            f"[cyan][{Utils.get_time()}][grey74] Enter a comment "
            f"(optional, e.g., 'Work Key')",
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

        expire_value  = Utils.get_pgp_key_expire_date()

        # In generate_pgp_key_pair()
        if expire_value:
            # Check if it's already GNU format (ends with letter)
            if isinstance(expire_value, str) and expire_value[-1].isalpha():
                # GNU format: "365d", "1y", "6m" - works perfectly!
                key_params["Expire-Date"] = expire_value
            else:
                if isinstance(expire_value, str):
                    try:
                        key_params["Expire-Date"] = expire_value
                    except ValueError:
                        self.ui.warning("Invalid date format.")
                        del key_params["Expire-Date"]

                key_params["Expire-Date"] = expire_value

        input_data = self.gpg.gen_key_input(**key_params)

        key = self.gpg.gen_key(input_data)

        if not key.fingerprint:
            self.ui.error(f"PGP key generation failed → {key.stderr}")
            raise RuntimeError(f"PGP key generation failed → {key.stderr}")

        keyid = str(key.fingerprint)

        # Display key summary information
        self.ui.success("PGP key pair created successfully!")

        if expire_value is None:
            # No expiration set
            expire_dt_str = "Never"
        elif isinstance(expire_value, int):
            expire_dt_str = f"{expire_value} (in {expire_value} days)"
        elif isinstance(expire_value, str):
            # Date-based expiry (absolute)
            expire_date_str = (
                f"{expire_value[:4]}-{expire_value[4:6]}-{expire_value[6:8]}"
            )
            expire_time_str = (
                f"{expire_value[9:11]}:{expire_value[11:13]}:\
                {expire_value[13:15]}"
            )
            expire_dt_str = f"{expire_date_str} at {expire_time_str}"

        console.print(
            f"\n"
            f"[cyan]  Name         :  {full_name}\n"
            f"[cyan]  Comment      :  {comment}\n"
            f"[cyan]  Email        :  {email_address}\n"
            f"[cyan]  Fingerprint  :  {keyid}\n"
            f"[cyan]  Key Expires  :  {expire_dt_str}"
        )

        export_pub_key = Confirm.ask(
            f"[cyan][{Utils.get_time()}][grey74] Do you want to "
            "export the newly created PGP PUBLIC key?",
        )
        if export_pub_key:
            # Export public key
            self.pgp_export_public_key(keyid=keyid)

        export_private_key = Confirm.ask(
            f"[cyan][{Utils.get_time()}][grey74] Do you want to "
            "export the newly created PGP PRIVATE key?",
        )
        if export_private_key:
            # Export private key
            self.pgp_export_private_key(
                keyid=keyid,
                passphrase=password,
            )

        return keyid


    def _handle_pgp_process_file(self, action: str) -> None:
        """Collect user inputs and call pgp_process_file method."""
        ask_use_symmetric = Prompt.ask(
            f"[cyan][{Utils.get_time()}][grey74] How do you want to "
            f"{action} the file (1=password, 2=PGP key)",
            choices=["1", "2"],
            show_choices=True,
        ).strip().lower()
        symmetric = (ask_use_symmetric == "1")

        password = None
        recipients = None

        if action == "encrypt":
            if symmetric:
                password = self.ui.prompt(
                    "Enter a password to encrypt the file(s)",
                    password=True
                )
                if not password:
                    self.ui.warning(
                        "A password is required for symmetric encryption"
                    )
                    return
            else:
                # Asymmetric encryption - recipients required
                email_input = self.ui.prompt(
                    "Enter the email address of the owner of the public key "
                    f"that will be used for {action}ion of the file"
                ).strip()

                if not email_input:
                    self.ui.warning("No email address provided.")
                    return

                recipients = [addr.strip() for addr in email_input.split(",")]

        else:
            # DECRYPTION - password only needed for symmetric-encrypted files
            enter_password = self.ui.confirm(
                "Enter decryption password now? (leave blank for GPG prompt)"
            )

            if enter_password:
                password = self.ui.prompt(
                    "Enter the password to decrypt the file(s)",
                    password=True
                )

        try:
            self.pgp_process_file(
                action=action,
                symmetric=symmetric,
                password=password,
                recipients=recipients,
            )
        except Exception as err:
            self.ui.error(f"Operation failed → {err}")
            raise RuntimeError(f"Operation failed → {err}") from err


    def _handle_pgp_process_folder(self, action: str) -> None:
        """Collect user inputs and call pgp_process_folder."""
        # Target directory
        target_dir = Utils.get_directory_path()
        if not target_dir.is_dir():
            raise NotADirectoryError(f"The provided path is not a directory")

        # Recursive option
        recursive = Utils.select_recursive_option()

        # Email address (required for public-key encryption)
        email_input = self.ui.prompt(
            "Enter recipient email address(es) (comma-separated)"
        ).strip()

        if not email_input and action == "encrypt":
            self.ui.warning("No email provided")
            proceed = self.ui.confirm(
                "Proceed with symmetric encryption instead?"
            )
            if proceed:
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
            password = self.ui.prompt("Enter passphrase for encryption",
                password=True
            )
            if not password:
                self.ui.warning(
                    "A passphrase is required for symmetric encryption"
                )
                return

        elif action == "decrypt":
            enter_password = self.ui.confirm(
                "Do you want to provide a passphrase now? (leave blank for "
                "GPG prompt)",
            )
            if enter_password:
                password = self.ui.prompt("Enter passphrase for processing",
                    password=True
                )
            else:
                password = None
        else:
            password = None

        # Armored option
        armored = self.ui.confirm("Use ASCII-armored output (.asc)?")

        # Process the directory
        try:
            results = self.pgp_process_folder(
                target_dir=target_dir,
                action=action,
                email_address=email_address,
                password=password,
                recursive=recursive,
                armored=armored,
                symmetric=symmetric,
                always_trust=True,
            )

            self.ui.success(f"Completed processing {len(results)} files.")

        except Exception as err:
            self.ui.error(f"Operation failed → {err}")
            raise RuntimeError(f"Operation failed → {err}") from err


    def pgp_process_file(
            self,
            action: str,
            recipients: list[str],
            target_file: Path | str | None = None,
            symmetric: bool | None = None,
            password: str | None = None,
            always_trust: bool = True,
    ) -> Path:
        """Encrypts a single file using PGP/GPG and handles GPG engine
        failures safely.

        Args:
            action: Operational mode, either 'encrypt' or 'decrypt'.
            recipients: Recipient email or key ID(s). Required for public-key
                encryption. Ignored for symmetric encryption. Optional
                otherwise.
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
        # Resolve instance defaults for symmetric
        use_symmetric = symmetric if symmetric is not None else getattr(
            self, "_symmetric", False)
        use_armored = getattr(self, "default_armored", False)

        action = action.lower().strip()

        # Get target file
        if target_file is None:
            # target_file = Utils.get_file_path()
            target_file = r"C:\Users\mikes\Desktop\test\OSHA.docx"
        target_file = Path(target_file).resolve()

        if not target_file.is_file():
            self.ui.error(
                f"{target_file.name} does not exist or is a directory."
            )
            raise FileNotFoundError(f"Invalid target file → {target_file}")

        # Output path (optional)
        output_path_input = self.ui.prompt(
            "Enter output path (leave blank for default)"
        ).strip("\"'")
        output_path = (
            Path(output_path_input).resolve()
            if output_path_input else None
        )

        # Collect encryption parameters based on action
        if action == "encrypt":
            # Symmetric vs asymmetric decision
            if use_symmetric:
            # Password → required for symmetric encryption or decryption
                armored_response = self.ui.confirm(
                    f"Use ASCII-armored output (.asc)?"
                )
                use_armored = armored_response == True
                armored_prompt_used = True

                # Validate: symmetric encryption requires a password
                if not password:
                    self.ui.warning(
                        "A password is required for symmetric encryption"
                    )
                    raise ValueError(
                        "A password is required for symmetric encryption"
                    )

        # Determine output path and extension
        if action == "encrypt":
            ext = ".asc" if use_armored else ".pgp"
            output_file = (
                Path(output_path).resolve() if output_path
                else target_file.with_name(f"{target_file.name}{ext}")
            )
        else:
            if target_file.suffix in {".pgp", ".asc", ".gpg"}:
                output_file = (
                    Path(output_path).resolve() if output_path
                    else target_file.with_suffix("")
                )
            else:
                output_file = (
                    Path(output_path).resolve() if output_path
                    else target_file.with_name(
                        f"{target_file.name}.decrypted")
                )

        # DEBUG: Log password status BEFORE encryption
        logger.debug(
            f"PASSED PASSWORD: {'***HIDDEN***' if password else 'NONE'}"
        )
        logger.debug(f"SYM MODE: {use_symmetric}")
        logger.debug(f"TARGET FILE: {target_file}")
        logger.debug(f"OUTPUT FILE: {output_file}")

        try:
            self.ui.info(f"Reading file → {target_file.name}...")

            with open(target_file, "rb") as f:
                if action == "encrypt":
                    self.ui.info(f"{action.capitalize()}ing file data...")
                    if use_symmetric:
                        logger.info(
                            f"Starting SYMMETRIC encrypt for → "
                            f"{target_file.name}"
                        )

                        # VERIFY PASSWORD EXISTS
                        if not password:
                            logger.error(
                                "PASSWORD IS NONE FOR SYMMETRIC ENCRYPTION!"
                            )
                            raise ValueError(
                                "Password required for symmetric encryption"
                            )

                        # Symmetric encryption - NO recipients
                        status = self.gpg.encrypt_file(
                            f,
                            recipients=[],
                            symmetric=True,
                            # python-gnupg will send this via stdin
                            passphrase=password,
                            armor=use_armored,
                            output=str(output_file),
                        )

                        logger.debug(
                            f"Encryption status.ok → {status.ok}"
                        )
                        logger.debug(
                            f"Encryption status.status → "
                            f"{getattr(status, 'status', 'NO STATUS ATTR')}"
                        )

                        if status.stderr:
                            logger.error(f"GPG STDERR: {status.stderr}")

                    else:
                        # Asymmetric encryption - REQUIRES recipients
                        if not recipients:
                            raise ValueError(
                                "At least one recipient is required for "
                                "public-key encryption."
                            )
                        status = self.gpg.encrypt_file(
                            f,
                            recipients=recipients,
                            always_trust=always_trust,
                            armor=use_armored,
                            output=str(output_file),
                        )
                else:
                    # Decryption
                    status = self.gpg.decrypt_file(
                        f,
                        # Pass for private key decryption
                        passphrase=password,
                        output=str(output_file),
                    )
        except Exception as err:
            # Try to extract GPG-specific error message
            if hasattr(err, "stderr"):
                logger.error(f"GPG stderr → {err.stderr}")
            elif hasattr(err, "status"):
                logger.error(f"GPG status → {err.status}")
            self.ui.error(f"Failed to execute GPG {action}ion → {err}")
            # Try to show helpful troubleshooting info
            if "broken pipe" in str(err).lower():
                self.ui.warning(
                    "Troubleshooting: Check if pinentry is installed. "
                    "On Linux → 'sudo apt install pinentry-gnome3'"
                )
                self.ui.warning(
                    "Also verify GPG agent is running → 'gpg-connect-agent "
                    "reloadagent /bye'"
                )
            raise RuntimeError(f"GPG operation failed → {err}") from err

        # Validate GPG status
        if not status.ok:
            # Clean up partial/empty output file if created
            if output_file.exists():
                output_file.unlink(missing_ok=True)

            error_msg = getattr(
                status, "status", getattr(
                    status, "status", "Unknown GPG error"
                )
            )
            self.ui.error(
                f"PGP {action.title()}ion failed for {target_file.name}. GPG "
                f"status → {error_msg}"
            )
            raise RuntimeError(f"PGP {action.title()}ion failed → {error_msg}")

        # Log status
        if hasattr(self, "print_status"):
            self.print_status(
                status=status,
                current_method=self.current_method
            )

        self.ui.success(
            f"File {action}ed successfully. {target_file.name}  →  "
            f"{output_file.name}"
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
            email_address: Recipient email or key ID(s). Required for
                public-key encryption. Ignored for symmetric encryption.
            password: Passphrase for symmetric encryption or private key
                decryption. If None, will be prompted interactively.
            recursive: Traverse the target_dir and process files in
                sub-folders.
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

        if not Utils.verify_is_directory(target_dir=target_dir):
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
            self.ui.warning(
                "At least one recipient email or key ID must be provided for "
                "public-key encryption. Use 'symmetric=True' for password-only "
                "encryption."
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

        except Exception as err:
            self.ui.error(
                f"Failed to retrieve files from {target_dir} → {err}"
            )
            return []

        if not all_files:
            self.ui.warning(
                f"No valid files to {action} in {target_dir}"
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
                self.ui.error(
                    f"Error during {action}ing {file_path.name} → {e}"
                )
                failed_files.append(file_path)

        # Summary reporting
        if successful_files:
            self.ui.success(
                f"Action Completed. "
                f"Successfully {action}ed {len(successful_files)} files in "
                f"{target_dir}:"
            )
            for processed_file in successful_files:
                console.print(f"[green]    {processed_file.name}")

        if failed_files:
            self.ui.error(
                f"Warning. Failed to {action} {len(failed_files)} files:"
            )
            for failed_file in failed_files:
                console.print(f"[red]    {failed_file.name}")

        return successful_files


    def pgp_sign_file (
            self,
            detached: bool = True,
            clearsign: bool = False,
            armored: bool | None = None,
    ) -> Path:
        """Signs a file using PGP/GPG, producing either a detached signature
        or a clearsigned document.

        Args:
            detached: If True, produce a detached signature (.sig). If False,
                produce an inline/compressed signed file.
            clearsign: If True, produce a cleartext-signed document (.asc)
                that remains readable while carrying an embedded signature.
                Overrides `detached` when True.
            armored: True → ASCII-armored output; False → binary. If None,
                uses the instance default.
        Returns:
            Path: Path to the resulting signature or signed file.

        Raises:
            FileNotFoundError: If target file does not exist.
            ValueError: If signer_email is empty or invalid.
            RuntimeError: If the GPG signing operation fails.
        """
        target_file = self.ui.prompt("Enter the path of the file to be signed")
        target_file = Path(target_file).resolve()

        if not target_file.is_file():
            Utils.print_not_file_error(target_file=target_file)
            raise FileNotFoundError(f"Invalid target file → {target_file}")

        signer_email = self.ui.prompt(
            "Enter the email address or key ID of the signer's private key"
        )
        if not signer_email:
            self.ui.warning(
                "The signer's email or key ID must be provided"
            )
            raise ValueError

        password = self.ui.prompt(
            "Enter the passphrase for the signer's private key",
            password=True
        )

        use_armored = armored if armored is not None else getattr(
            self, "_armored", False)

        sig_type = self.ui.prompt(
            "What type of signature do you want to use to sign this file? "
            "(1=clearsign, 2=detached, 3=other)",
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
                    f"[cyan][{Utils.get_time()}][yellow] "
                    "Invalid choice, defaulting to inline signature"
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
            self.ui.info(f"Signing file → {target_file.name}...")
            self.ui.info(f"Signature will be written to → {output_file.name}")

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
            self.ui.success(f"Signature created → {output_file.name}")
        except Exception as err:
            self.ui.error(f"File signing failed → {err}")
            raise RuntimeError(
                f"Failed to execute GPG signing → {err}"
            ) from err

        if not status:
            if output_file.exists():
                output_file.unlink(missing_ok=True)

            error_msg = getattr(status, "stderr", "Unknown GPG error")
            raise RuntimeError(
                f"PGP signing failed for → {target_file.name}. GPG status → "
                f"{error_msg}"
            )

        if hasattr(self, "print_status"):
            self.print_status(status=status, method=self.current_method)

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
            self.ui.error(f"Signature file not found → {signature_file}")
            raise FileNotFoundError(
                f"Invalid signature file → {signature_file}"
            )

        # Determine if this is a detached or inline/cleartext signature
        is_detached = original_file is not None

        if is_detached:
            original_file = Path(original_file).resolve()

            if not original_file.is_file():
                self.ui.error(f"The original file not found → {original_file}")
                raise FileNotFoundError(
                    f"Invalid original file → {original_file}"
                )

        try:
            self.ui.info(f"Verifying signature → {signature_file.name}...")

            if is_detached:
                # Detached signature verification
                with open(signature_file, "rb") as sig_f, \
                    open(original_file, "rb") as orig_f:
                    verified = self.gpg.verify_file(sig_f, file_data=orig_f)
            else:
                # Inline or cleartext signature verification
                with open(signature_file, "rb") as sig_f:
                    verified = self.gpg.verify_file(sig_f)

        except Exception as err:
            self.ui.error(
                f"Verification error for {signature_file.name} → {err}"
            )
            return False

        # Check basic validity
        if not verified:
            self.ui.error(
                f"Signature verification FAILED for {signature_file.name}."
            )
            if hasattr(verified, "stderr") and verified.stderr:
                self.ui.error(f"{verified.stderr.strip()}")
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
                    f"[cyan][{Utils.get_time()}][red] "
                    f"Signature is valid but was NOT produced by expected "
                    f"signer : {signer_email}.\n"
                    f"  → Actual signer key_id      : {actual_key_id}\n"
                    f"  → Actual signer fingerprint : {actual_fingerprint}"
                )
                return False

        # Success
        signer_name = getattr(verified, "username", "Unknown")
        signer_key = getattr(verified, "key_id", "Unknown")
        sign_date = getattr(verified, "timestamp", "Unknown")

        self.ui.success(
            f"Signature verification PASSED with {signature_file.name}"
        )
        self.ui.success(
            f"  Signer  : {signer_name}\n"
            f"  Key ID  : {signer_key}\n"
            f"  Signed  : {sign_date}\n"
        )

        if hasattr(self, "print_status"):
            self.print_status(status=verified, method=self.current_method)

        return True


    def _debug_gpg_setup(self) -> None:
        """Print diagnostic info about GPG configuration."""
        console.print("\n[bold cyan]GPG Configuration:[/]")
        console.print(f"[cyan]HomDir (tracked):[/] {self.gpg_homedir}")
        console.print(f"[cyan]HomDir (GPG obj):[/] {self.gpg.gnupghome or 'None (known python-gnupg issue)'}")
        console.print(f"[cyan]HomDir exists:[/] {'Yes' if self.gpg_homedir.exists() else 'No'}")
        console.print(f"[cyan]HomDir writable:[/] {'Yes' if os.access(self.gpg_homedir, os.W_OK) else 'No'}")

        # List available keys
        keys = self.gpg.list_keys()
        console.print(
            f"[cyan][{Utils.get_time()}][grey74] Keys found: "
            f"{len(keys)}"
        )
        for key in keys[:5]:  # Show first 5
            console.print(
                f"[cyan][{Utils.get_time()}][grey74]  - "
                f"{key['uids'][0]} ({key['fingerprint'][:16]}...)"
            )


    def verify_gpg_setup(self) -> bool:
        """Verify GPG installation and configuration."""
        logger = get_logger("pgp")

        # Use standard library to check for gpg binary
        gpg_path = shutil.which("gpg")

        if not gpg_path:
            console.print(
                f"[cyan][{Utils.get_time()}][red] GPG binary not "
                "found in PATH. Install Gpg4win (Windows) or gpg (Linux/Mac)"
            )
            return False

        logger.debug(f"GPG binary found at: {gpg_path}")

        # Test keyring access
        try:
            keys = self.gpg.list_keys()
            logger.debug(f"Found {len(keys)} public keys")

            secret_keys = self.gpg.list_keys(secret=True)
            logger.debug(f"Found {len(secret_keys)} secret keys")

            if not secret_keys and not getattr(self, "default_symmetric", False):
                console.print(
                    f"[cyan][{Utils.get_time()}][yellow] Warning: No "
                    "secret keys found. Symmetric encryption recommended."
                )
        except Exception as e:
            console.print(
                f"[cyan][{Utils.get_time()}][red] Error accessing "
                f"GPG keyring → {e}"
            )
            return False

        return True





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