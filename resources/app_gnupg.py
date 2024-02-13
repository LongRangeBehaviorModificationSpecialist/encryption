# !/usr/bin/env python3

from rich.console import Console
import gnupg
from pathlib import Path
import os
import sys

from resources.functions import Functions

# Make the console object
console = Console()


class PGPClass:

    script_path = Path(__file__).parent
    gnupg_home_dir = os.path.join(Path(__file__).parent, '.gnupg')
    if not os.path.exists(gnupg_home_dir):
        os.mkdir(gnupg_home_dir)
    gpg = gnupg.GPG(gnupghome=gnupg_home_dir)
    private_key_file = f'{script_path}\\mas_private_key.asc'
    public_key_file = f'{script_path}\\mas_public_key.asc'


    def print_status(self, status):
        if status.ok == True:
            console.print(f"""[khaki3]
[-] File encryption successful.
    {status.stderr}""")
        else:
            console.print("""[red1]
[-] File encryption WAS NOT successful. Please try again.""")


    def pgp_export_public_key(self, keyid: str) -> None:
        """Decrypts a file using a provided .key file

            Args:
                keyid -> str: id of pgp key to export

            Returns:
                file: public PGP key
        """
        public_key = PGPClass.gpg.export_keys(keyids=keyid,
                                              output=PGPClass.public_key_file)

        console.print(f"""[bright_white]
[{Functions.get_date_time(self)}] Public key exported successfully""")
        return public_key


    def pgp_export_private_key(self,
                               keyid: str,
                               password: str) -> None:
        """Decrypts a file using a provided .key file

            Args:
                keyid -> str: id of pgp key to export
                password -> str: password to use to decrypt file(s)

            Returns:
                file: private PGP key
        """
        private_key = PGPClass.gpg.export_keys(keyids=keyid,
                                               secret=True,
                                               passphrase=password,
                                               output=PGPClass.private_key_file)

        console.print(f"""[bright_white]
[{Functions.get_date_time(self)}] Private key exported successfully""")
        return private_key


    def generate_pgp_key(self,
                         password: str,
                         email_address: str) -> None:
        """Generates new pair of PGP keys

            Args:
                password -> str: password to use to generate the pgp keys

            Returns:
                file: new pgp key pair
        """
        PGPClass.gpg.encoding = 'utf-8'

        input_data = PGPClass.gpg.gen_key_input(name_email=email_address,
                                                passphrase=password,
                                                key_type='RSA',
                                                key_length=1024)

        global keyid
        keyid = PGPClass.gpg.gen_key(input_data)

        console.print(f"""[bright_white]
[{Functions.get_date_time(self)}] Generated Key ID: {keyid}""")

        PGPClass.pgp_export_public_key(self,
                                       keyid=str(keyid))

        PGPClass.pgp_export_private_key(self,
                                        keyid=str(keyid),
                                        password=password)


    def pgp_encrypt_file(self,
                         file_path: Path) -> None:

        encrypted_file = Functions.get_encrypted_file_name(self,
                                                           file_path=file_path)

        with open(file_path, 'rb') as f:
            status = PGPClass.gpg.encrypt_file(
                f,
                recipients=['mikespon@gmail.com'],
                output=encrypted_file)

        # Print status message to the terminal
        PGPClass.print_status(self, status)


    def pgp_decrypt_file(self,
                         file_path: Path,
                         password: str) -> None:

        file = file_path
        if file.endswith('.encrypted'):
            decrypted_file = file[:-10]
        else:
            decrypted_file = f'{file}.decrypted'

        with open(file, 'rb') as f:
            status = PGPClass.gpg.decrypt_file(
                f,
                passphrase=password,
                output=decrypted_file)
        # Print status message to the terminal
        PGPClass.print_status(self, status)


    def pgp_encrypt_folder(self,
                           folder_path: Path) -> None:

        delete_originals = console.input("""[khaki3]
[-] Do you want to delete the original files after encryption (y/n)? >>> """)

        delete_originals = delete_originals.strip().lower()

        if delete_originals == 'y':
            choice = console.input("""[khaki3]
[-] All of the original files in this directory will be [orange_red1]\
PERMANENTLY DELETED! [khaki3]Are you sure you wish to continue (y/n)? >>> """)

            choice = choice.strip().lower()

            if choice == 'y':
                for file in os.listdir(folder_path):
                    with open(f'{folder_path}\\{file}', 'rb') as efile:
                        status = PGPClass.gpg.encrypt_file(
                            efile,
                            recipients=['mikespon@gmail.com'],
                            output=f'{folder_path}\\{file}.encrypted')
                os.remove(f'{folder_path}\\{file}')

            # EXIT THE PROGRAM
            elif choice == 'n':
                console.print("""[khaki3]
Exiting program. Please wait...""")
                sys.exit(0)

            # NO VALID CHOICE WAS ENTERED
            else:
                console.print("""[khaki3]
Seriously, you did not enter a valid option. Exiting...""")
            sys.exit(0)

        # IF THE USER CHOOSES NOT TO DELETE ORIGINAL FILES
        elif delete_originals == 'n':
            with open(f'{folder_path}\\{file}', 'rb') as efile:
                status = PGPClass.gpg.encrypt_file(
                    efile,
                    recipients=['mikespon@gmail.com'],
                    output=f'{folder_path}\\{file}.encrypted')

        # NO VALID CHOICE WAS ENTERED
        else:
            console.print("""[khaki3]
Seriously, you did not enter a valid option. Exiting...""")
            sys.exit(0)

        # PRINT STATUS MESSAGE TO THE TERMINAL
        PGPClass.print_status(self, status)
