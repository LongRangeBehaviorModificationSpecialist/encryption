# !/usr/bin/env python3

from rich.console import Console
from rich.prompt import Prompt
import gnupg
from pathlib import Path
import os
import sys

from resources.functions import Functions


# Make the console object
c = Console()


class PGP:

    script_path = Path(__file__).parent
    gnupg_home_dir = script_path / ".gnupg"

    if not gnupg_home_dir.exists():
        gnupg_home_dir.mkdir(parents=True, exist_ok=True)
    #     os.chmod(gnupg_home_dir, 0o700)
    # else:
    #     os.chmod(gnupg_home_dir, 0o700)

    gpg = gnupg.GPG(
        gnupghome=str(gnupg_home_dir),
        gpgbinary=r"C:\Program Files\GnuPG\bin\gpg.exe"
    )
    private_key_file = script_path / "mas_private_key.asc"
    public_key_file = script_path / "mas_public_key.asc"


    def print_status(self, status):
        if status.ok == True:
            c.print(f"""[yellow3]
[-] File encryption successful.
    {status.stderr}""")
        else:
            c.print(f"""[red]
[-] File encryption WAS NOT successful: {status.status}. Please try again.""")


    def pgp_export_public_key(self, keyid: str) -> None:
        """
        Decrypts a file using a provided .key file.

        Args:
            keyid -> str: id of pgp key to export

        Returns:
            file: public PGP key
        """
        public_key = self.gpg.export_keys(
            keyids=keyid,
            output=str(self.public_key_file)
        )
        c.print(f"""[white]
[-] Public key exported successfully""")
        return public_key


    def pgp_export_private_key(self, keyid: str, password: str) -> None:
        """
        Decrypts a file using a provided .key file.

        Args:
            keyid -> str: id of pgp key to export
            password -> str: password to use to decrypt file(s)

        Returns:
            file: private PGP key
        """
        private_key = self.gpg.export_keys(
            keyids=keyid,
            secret=True,
            passphrase=password,
            output=str(self.private_key_file)
        )
        c.print(f"""[white]
[-] Private key exported successfully""")
        return private_key


    def generate_pgp_key_pair(self, password: str, email_address: str) -> None:
        """
        Generates new pair of PGP keys.

        Args:
            password -> str: password to use to generate the pgp keys

        Returns:
                file: new pgp key pair
        """
        self.gpg.encoding = "utf-8"

        input_data = self.gpg.gen_key_input(
            name_email=email_address,
            passphrase=password,
            key_type="RSA",
            key_length=2048
        )
        key = self.gpg.gen_key(input_data)
        keyid = str(key)

        c.print(f"""[white]
[-] Generated Key ID: {keyid}""")

        self.pgp_export_public_key(keyid=keyid)
        self.pgp_export_private_key(keyid=keyid, password=password)


    def pgp_encrypt_file(self, file_path: Path) -> None:
        file_path = Path(file_path)
        encrypted_file = Functions.get_encrypted_file_name(self,
            file_path=file_path)

        with open(file_path, "rb") as f:
            status = self.gpg.encrypt_file(
                f,
                recipients=["test_email@gmail.com"],
                always_trust=True,
                output=str(encrypted_file)
            )

        # Print status message to the terminal
        self.print_status(status)


    def pgp_decrypt_file(self, file_path: Path, password: str) -> None:
        file = Path(file_path)

        if file.suffix == ".encrypted":
            decrypted_file = file.with_suffix("")
        else:
            decrypted_file = file.with_name(f"{file.name}.decrypted")

        with open(file, "rb") as f:
            status = self.gpg.decrypt_file(
                f,
                passphrase=password,
                output=str(decrypted_file)
            )

        # Print status message to the terminal
        self.print_status(status)


    def pgp_encrypt_folder(self, folder_path: Path) -> None:
        folder = Path(folder_path)
        delete_originals = Prompt.ask(f"""[yellow3]
[-] Do you want to delete the original files after encryption (y/n)? """).strip().lower()

        if delete_originals not in ["y", "n"]:
            c.print("""[yellow3]\n[!] Seriously, you did not enter a valid \
option. Exiting...""")
            sys.exit(0)

        if delete_originals == "y":
            choice = Prompt.ask(f"""[yellow3]
[-] All of the original files in this directory will be [orange_red1]\
PERMANENTLY DELETED! [yellow3]Are you sure you wish to continue (y/n)? """).strip().lower()

            if choice != "y":
                c.print("[yellow3]Exiting program. Please wait...")
                sys.exit(0)

        status = None
        for file_name in os.listdir(folder):
            current_file = folder / file_name

            if current_file.is_dir() or current_file.suffix == ".encrypted":
                continue

            with open(current_file, "rb") as efile:
                status = PGP.gpg.encrypt_file(
                    efile,
                    recipients=["TEST.EMAIL@gmail.com"],
                    always_trust=True,
                    output=str(current_file.with_name(f"{file_name}.encrypted"))
                )

            if delete_originals == "y" and status.ok:
                os.remove(current_file)

        if status:
            # Print status message to the terminal
            self.print_status(status)
