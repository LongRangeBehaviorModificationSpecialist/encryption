# !/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path

drive = Path(__file__).drive
# drive = Path(f'{drive}\\Users\\mikes\\Desktop\\')

# General all-purpose password
password = 'mysecretpassword34'

# TO TEST ENCRYPTION/DECRYPTION WITH A .KEY FILE
key_file = Path(f'{drive}\\encryption\\aaa\\2024-01-24_105425_key.key')
file_for_key_test = Path(f'{drive}\\encryption\\aaa\\File_2_Folder_2_for_KEY.txt')
file_for_new_key_test = Path(f'{drive}\\encryption\\aaa\\File_for_NEW_KEY_TEST.JPG')
folder_path_for_key_test = Path(f'{drive}\\encryption\\aaa\\txtfiles_KEY')
file_to_decrypt_with_key = Path(f'{drive}\\encryption\\aaa\\File_2_Folder_2_for_KEY.txt.encrypted')


file_path = Path(f'{drive}\\encryption\\aaa\\Falcon_OneDrive_Backup.py')
py_file_to_encrypt = Path(f'{drive}\\encryption\\aaa\\Falcon_OneDrive_Backup.py')
aes_file_to_encrypt = Path(f'{drive}\\encryption\\aaa\\File_2_Folder_2_for_AES.txt')
aes_file_to_decrypt = Path(f'{drive}\\encryption\\aaa\\File_2_Folder_2_for_AES.txt.encrypted')
aes_folder = Path(f'{drive}\\encryption\\aaa\\txtfiles_AES')


gcm_file_to_encrypt = f'{drive}\\encryption\\aaa\\compare_dirs_GCM.py'
gcm_file_to_decrypt = Path(f'{drive}\\encryption\\aaa\\compare_dirs_GCM.py.encrypted')
gcm_folder_path = Path(f'{drive}\\encryption\\aaa\\txtfiles_GCM')


file_to_decrypt = Path(f'{drive}\\encryption\\aaa\\File_2_Folder_2.txt.encrypted')

pgp_folder_path = Path(f'{drive}\\encryption\\aaa\\txtfiles_pgp')
pgp_file_to_encrypt = Path(f'{drive}\\encryption\\aaa\\Falcon_OneDrive_Backup_for_PGP.py')
pgp_file_to_decrypt = Path(f'{drive}\\encryption\\aaa\\Falcon_OneDrive_Backup_for_PGP.py.encrypted')


xor_msg = 'This is a super secret message. The launch code is: 456F8A1C453EF92BEFAA23.'
# 655A5A4715584113551542474351471141565747544613595042415253501F12675C50115E52415B525A13575A5557135D460B12070103770A72057605070071730800717173707301071B

# b'eZZG\x15XA\x13U\x15BGCQG\x11AVWGTF\x13YPBARSP\x1f\x12g\\P\x11^RA[RZ\x13WZUW\x13]F\x0b\x12\x07\x01\x03w\nr\x05v\x05\x07\x00qs\x08\x00qqsps\x01\x07\x1b'

"""
eZZGXAUBGCQGAVWGTFYPBARSPg\P^RA[RZWZUW]F
w
rvqqqsps
"""

xor_key = '1748556941AA47Zfrtty'
xor_msg_file = f'{drive}\\encryption\\aaa\\xor_crypt.txt'
xor_enc_msg_file = f'{drive}\\encryption\\aaa\\xor_enc_msg.txt.encrypted'
xor_file = f'{drive}\encryption\\aaa\\test_for_XOR.py'
# xor_enc_file = f'{drive}:\\encryption\\aaa\\test_for_XOR.encrypted'
# xor_dec_file = f'{drive}:\\encryption\\aaa\\test_for_XOR.decrypted'