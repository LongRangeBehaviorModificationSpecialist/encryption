VERSION = "0.3.17076096"

INITIAL_MENU_PROMPT = f"""[dodger_blue1]
--------------------------------------------
ENCRYPT/DECRYPT APPLICATION MENU
v.{VERSION}
--------------------------------------------\n
[khaki3]What do you want to do? (select one) :[bright_white]\n
[1] Run ENCRYPTION
[2] Run DECRYPTION\n
[Q] Quit the Application\n\n
[khaki3]ENTER CHOICE """


TOP_LEVEL_ENCRYPTION_MENU_PROMPT = f"""[dodger_blue1]
--------------------------------------------
ENCRYPTION MENU
v.{VERSION}
--------------------------------------------\n
[khaki3]Select the ENCRYPTION method you want to use :[bright_white]\n
[A] Use a .key file
[B] Use a password
[C] Use PGP keys
[D] Use XOR\n
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """


KEY_ENCRYPTION_PROMPT = """[dodger_blue1]
--------------------------------------------
ENCRYPT FILE(S) WITH A .KEY FILE
--------------------------------------------\n
[khaki3]Options :[bright_white]\n
[1] Create a [bold]new[/bold] .key file
[2] Encrypt a single file using a .key
[3] Erypt all files in a folder using a .key\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """


AES_ENCRYPTION_PROMPT = """[dodger_blue1]
--------------------------------------------
ENCRYPT FILE(S) WITH PASSWORD [AES-GCM mode]
--------------------------------------------\n
[khaki3]Options :[bright_white]\n
[1] Encrypt a single file
[2] Encrypt all files in a folder\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """


PGP_ENCRYPTION_PROMPT = """[dodger_blue1]
--------------------------------------------
ENCRYPT FILE(S) USING PGP KEY
--------------------------------------------\n
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


TOP_LEVEL_DECRYPTION_MENU_PROMPT = f"""[dodger_blue1]
--------------------------------------------
DECRYPTION MENU
v.{VERSION}
--------------------------------------------\n
[khaki3]Select the DECRYPTION method you want to use :[bright_white]\n
[A] Decrypt file(s) using a .key file
[B] Decrypt file(s) using a password
[C] Decrypt file(s) using a PGP key
[D] Decrypt message/file(s) using XOR\n
[Q] Quit the Application\n\n
[khaki3]ENTER CHOICE """


KEY_DECRYPTION_PROMPT = """[dodger_blue1]
--------------------------------------------
DECRYPT FILE(S) WITH PROVIDED .KEY
--------------------------------------------\n
[khaki3]Options :[bright_white]\n
[1] Decrypt a file using a .key
[2] Decrypt files in a folder using a .key\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """


AES_DECRYPTION_PROMPT = """[dodger_blue1]
--------------------------------------------
DECRYPT FILE(S) WITH PASSWORD [AES-GCM mode]
--------------------------------------------\n
[khaki3]Options :[bright_white]\n
[1] Decrypt a single file using a password
[2] Decrypt all files in a directory using a password\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """


PGP_DECRYPTION_PROMPT = """[dodger_blue1]
--------------------------------------------
DECRYPT FILE(S) USING PGP KEY
--------------------------------------------\n
[khaki3]Options :[bright_white]\n
[1] Decrypt a file using PGP key
[2] Decrypt all files in a folder using PGP key\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """


XOR_DECRYPTION_PROMPT = """[dodger_blue1]
--------------------------------------------
ENCRYPT MESSAGE OR FILE(S) USING AN XOR KEY
--------------------------------------------\n
[khaki3]Options :[bright_white]\n
[1] Decrypt a single message
[2] Decrypt a file\n
[R] Return to the main menu
[Q] Quit the application\n\n
[khaki3]ENTER CHOICE """