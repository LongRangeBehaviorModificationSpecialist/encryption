VERSION = "0.3.17076096"

INITIAL_MENU_PROMPT = f"""[dodger_blue1]
----------------------------------------
ENCRYPT/DECRYPT APPLICATION MENU
v.{VERSION}
----------------------------------------\n
[khaki3]What do you want to do? (select one) :[bright_white]\n
[1] Run ENCRYPTION
[2] Run DECRYPTION\n
[Q] Quit the Application[khaki3]\n\n
ENTER CHOICE """


TOP_LEVEL_ENCRYPTION_MENU_PROMPT = f"""[dodger_blue1]
----------------------------------------
ENCRYPTION MENU
v.{VERSION}
----------------------------------------\n
[khaki3]Select the ENCRYPTION method you want to use :[bright_white]\n
[A] Use a .key file
[B] Use a password
[C] Use PGP keys
[D] Use XOR\n
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """


KEY_ENCRYPTION_PROMPT = """[dodger_blue1]
----------------------------------------
ENCRYPT FILE(S) WITH A .KEY FILE
----------------------------------------\n
[khaki3]Options :[bright_white]\n
[1] Create a [bold]new[/bold] .key file
[2] Encrypt a single file using a .key
[3] Erypt all files in a folder using a .key\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """


AES_ENCRYPTION_PROMPT = """[dodger_blue1]
----------------------------------------------------
USE PASSWORD TO ENCRYPT FILE(S) [AES-CBC / AES-GCM]
----------------------------------------------------\n
[khaki3]Options :[bright_white]\n
[AES.CBC mode]\n
[1] Encrypt a single file
[2] Encrypt all files in a folder\n
[AES.GCM mode]\n
[3] Encrypt a single file
[4] Encrypt all files in a folder\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """


PGP_ENCRYPTION_PROMPT = """[dodger_blue1]
---------------------------------------
ENCRYPT FILE(S) USING PGP KEY
---------------------------------------\n
[khaki3]Options :[bright_white]\n
[1] Create new PGP key pair
[2] Encrypt a file using PGP
[3] Encrypt all files in a folder using PGP\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """


XOR_ENCRYPTION_PROMPT = """[dodger_blue1]
--------------------------------------------
ENCRYPT MESSAGE OR FILE(S) USING AN XOR KEY
--------------------------------------------\n
[khaki3]Options :[bright_white]\n
[1] Encrypt a single message string
[2] Encrypt a file
[3] Encrypt all files in a folder\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """


DECRYPTION_MENU_PROMPT = f"""[dodger_blue1]
----------------------------------------
DECRYPTION MENU
v.{VERSION}
----------------------------------------\n
[khaki3]Select the ENCRYPTION method you want to use :[bright_white]\n
[F] Decrypt file/files using a .key file
[G] Decrypt file/files using a password
[H] Decrypt file/files using a PGP key file
[I] Decrypt message/file using XOR\n
[Q] Quit the Application\n\n
[khaki3]ENTER CHOICE """


def format_key_file_log(key_path, hash_value, timestamp) -> str:
    return (
        "------------------------------------------\n"
        f"[{timestamp}]\n"
        f"Key file name : {key_path.name}\n"
        f"Key file hash value (SHA-256) : {hash_value}\n"
        "------------------------------------------")


def format_key_file_verification(
    key_file_dir, full_key_path, key_file_hash_file, key_file_hash_value
) -> str:
    return (f"""[bright_white]
------------------------------------------\n
[green3][-] Key file created\n[bright_white]
[-] Key file saved in : [khaki3]{key_file_dir}[bright_white]
[-] Key file name : [khaki3]{full_key_path.name}\n
[green3][-] Key file hashed\n[bright_white]
[-] Key file hash verification saved in : [khaki3]\
{key_file_hash_file.parent}[bright_white]
[-] Key file hash file name : [khaki3]\
{key_file_hash_file.name}[bright_white]
[-] Key file hash value (SHA256) : [khaki3]{key_file_hash_value}
------------------------------------------""")
