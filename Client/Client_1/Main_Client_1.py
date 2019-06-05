import Objects_Client
import asyncio
from time import sleep

# Create Conn Objects
Server1_conn = Objects_Client.Client('127.0.0.1', 6800)
Server2_conn = Objects_Client.Client('127.0.0.1', 6801)

# Create DH_algo Objects
DH_Algorithm_Server1 = Objects_Client.DH_algorithm()
DH_Algorithm_Server2 = Objects_Client.DH_algorithm()
DH_Algorithm_Client = Objects_Client.DH_algorithm()

# Create Key Objects
KeyFile_Server1 = Objects_Client.Key()
KeyFile_Server2 = Objects_Client.Key()
KeyFile_Client = Objects_Client.Key()
KeyFile_Mine = Objects_Client.Key()

# Create File and AES objects
AES_Encryption = Objects_Client.AES_Algorithm()
File_Manipulation = Objects_Client.File()

# Create some variable
global danger
global key_initialised

danger = False
my_turn = True
s1_connected = False
s2_connected = False
dh_s1_status = False
dh_s2_status = False
dh_c_status = False
key_s1_status = False
key_s2_status = False
key_c_send_status = False
key_c_recv_status = False



sleep(3)  # We wait 3 sec before doing something, to maintain relative sync


print("-------- CONN PHASE : START --------")
print("----- CONN S1 : START -----")
while not s1_connected:
    s1_connected = Server1_conn.client_activation()
print("Connected to Server 1 !")
print("----- CONN S1 : END -----")

print("----- CONN S2 : START -----")
while not s2_connected:
    s2_connected = Server2_conn.client_activation()
print("Connected to Server 2 !")
print("----- CONN S2 : END -----")
print("-------- CONN PHASE : END --------")



print("-------- DH INIT : START --------")
print("----- DH INIT S1 : START -----")
while not dh_s1_status:
    DH_Algorithm_Server1.public_key_generator()
    Server1_conn.sending(DH_Algorithm_Server1.public_key, 0)
    print("C1 key : ", DH_Algorithm_Server1.public_key)
    friendkey = Server1_conn.receiving(0)
    print("S1 key : ", friendkey)
    DH_Algorithm_Server1.private_key_generator(friendkey)
    print("common key : ", DH_Algorithm_Server1.private_key)
    dh_s1_status = True
print("----- DH INIT S1 : END -----")

print("----- DH INIT S2 : START -----")
while not dh_s2_status:
    DH_Algorithm_Server2.public_key_generator()
    Server2_conn.sending(DH_Algorithm_Server2.public_key, 0)
    print("C1 key : ", DH_Algorithm_Server2.public_key)
    friendkey = Server2_conn.receiving(0)
    print("S2 key : ", friendkey)
    DH_Algorithm_Server2.private_key_generator(friendkey)
    print("common key : ", DH_Algorithm_Server2.private_key)
    dh_s2_status = True
print("----- DH INIT S2 : END -----")

print("----- DH INIT C2 : START -----")
while not dh_c_status:
    DH_Algorithm_Client.public_key_generator()
    print("pubkey : ", DH_Algorithm_Client.public_key)
    pub_key_part1 = str(DH_Algorithm_Client.public_key)[:(int(len(str(DH_Algorithm_Client.public_key))/2))]
    print("part 1 : ", pub_key_part1)
    pub_key_part2 = str(DH_Algorithm_Client.public_key)[(int(len(str(DH_Algorithm_Client.public_key))/2)):]
    print("part 2 : ", pub_key_part2)
    Server1_conn.sending(pub_key_part1, 0)
    Server2_conn.sending(pub_key_part2, 0)
    pub_keyC2_part1 = Server1_conn.receiving(0)
    print("keyrecv part 1 : ", pub_keyC2_part1)
    pub_keyC2_part2 = Server2_conn.receiving(0)
    print("keyrecv part 2 : ", pub_keyC2_part2)
    DH_Algorithm_Client.private_key_generator((pub_keyC2_part1 + pub_keyC2_part2))
    print("Private key :", DH_Algorithm_Client.private_key)
    dh_c_status = True
print("----- DH INIT C2 : END -----")
print("-------- DH INIT : END --------")



print("-------- KEY INIT : START --------")
print("----- KEY INIT S1 : START -----")
while not key_s1_status:
    KeyFile_Server1.big_key_nonce_generator()
    KeyFile_Server1.key_choice()
    bigkeynonce = KeyFile_Server1.big_key_nonce_format(0)
    print("start of bigkeynonce : ", bigkeynonce[:15])
    bigkeynonce_sum = File_Manipulation.SHA512_checksum_creation(bigkeynonce)
    print("bigkeynonce sum : ", bigkeynonce_sum)
    bigkeynonce_and_sum = KeyFile_Server1.big_key_nonce_format(1, bigkeynonce_sum, bigkeynonce)
    cryptedbigkeynonce, tag, nonce = DH_Algorithm_Server1.encrypt(bigkeynonce_and_sum)
    print("cbkn : ", cryptedbigkeynonce[:15])
    print("ckn_tag : ", tag)
    print("ckn_nonce : ", nonce)
    f_cryptedbigkeynonce = KeyFile_Server1.big_key_nonce_format(2, tag, nonce, cryptedbigkeynonce)
    print("f_cryptedbigkeynonce : ", f_cryptedbigkeynonce[:15])
    Server1_conn.sending(f_cryptedbigkeynonce, 1)
    key_s1_status = True
print("----- KEY INIT S1 : END -----")

print("----- KEY INIT S2 : START -----")
while not key_s2_status:
    KeyFile_Server2.big_key_nonce_generator()
    KeyFile_Server2.key_choice()
    bigkeynonce = KeyFile_Server2.big_key_nonce_format(0)
    print("start of bigkeynonce : ", bigkeynonce[:15])
    bigkeynonce_sum = File_Manipulation.SHA512_checksum_creation(bigkeynonce)
    print("bigkeynonce sum : ", bigkeynonce_sum)
    bigkeynonce_and_sum = KeyFile_Server2.big_key_nonce_format(1, bigkeynonce_sum, bigkeynonce)
    cryptedbigkeynonce, tag, nonce = DH_Algorithm_Server2.encrypt(bigkeynonce_and_sum)
    print("cbkn : ", cryptedbigkeynonce[:15])
    print("ckn_tag : ", tag)
    print("ckn_nonce : ", nonce)
    f_cryptedbigkeynonce = KeyFile_Server2.big_key_nonce_format(2, tag, nonce, cryptedbigkeynonce)
    print("f_cryptedbigkeynonce : ", f_cryptedbigkeynonce[:15])
    Server2_conn.sending(f_cryptedbigkeynonce, 1)
    key_s2_status = True
print("----- KEY INIT S2 : END -----")

print("----- KEY INIT C2 SEND : START -----")
while not key_c_send_status:
    KeyFile_Mine.big_key_nonce_generator()
    KeyFile_Mine.key_choice()
    print("Start of BKey : ", KeyFile_Mine.big_key_original[:15])
    print("Start of BNonce : ", KeyFile_Mine.big_nonce_original[:15])
    bigkey_sum = File_Manipulation.SHA512_checksum_creation(KeyFile_Mine.big_key_original)
    print("bigkey_sum : ", bigkey_sum)
    bignonce_sum = File_Manipulation.SHA512_checksum_creation(KeyFile_Mine.big_nonce_original)
    print("bignonce_sum : ", bignonce_sum)
    bigkey_and_sum = KeyFile_Mine.big_key_nonce_format(1, bigkey_sum, KeyFile_Mine.big_key_original)
    bignonce_and_sum = KeyFile_Mine.big_key_nonce_format(1, bignonce_sum, KeyFile_Mine.big_nonce_original)
    crypted_bigkey, bktag, bknonce = DH_Algorithm_Client.encrypt(bigkey_and_sum)
    print("c_bigkey : ", crypted_bigkey[:15])
    print("c_bigkey_tag : ", bktag)
    print("c_bigkey_nonce : ", bknonce)
    crypted_bignonce, bntag, bnnonce = DH_Algorithm_Client.encrypt(bignonce_and_sum)
    print("c_bignonce : ", crypted_bigkey[:15])
    print("c_bignonce_tag : ", bntag)
    print("c_bignonce_nonce : ", bnnonce)
    f_crypted_bigkey = KeyFile_Mine.big_key_nonce_format(2, bktag, bknonce, crypted_bigkey)
    print("f_crypted_bigkey :", f_crypted_bigkey[:15])
    f_crypted_bignonce = KeyFile_Mine.big_key_nonce_format(2, bntag, bnnonce, crypted_bignonce)
    print("f_crypted_bignonce : ", f_crypted_bignonce[:15])
    Server1_conn.sending(f_crypted_bigkey, 1)
    Server2_conn.sending(f_crypted_bignonce, 1)
    key_c_send_status = True
print("----- KEY INIT C2 SEND : END -----")

print("----- KEY INIT C2 RECV : START -----")
while not key_c_recv_status:
    f_crypted_bigkey = Server1_conn.receiving(1)
    print("f_crypted_bigkey :", f_crypted_bigkey[:15])
    f_crypted_bignonce = Server2_conn.receiving(1)
    print("f_crypted_bignonce : ", f_crypted_bignonce[:15])
    crypted_bigkey, bktag, bknonce = KeyFile_Client.get_big_key_nonce(0, f_crypted_bigkey)
    print("c_bigkey : ", crypted_bigkey[:15])
    print("c_bigkey_tag : ", bktag)
    print("c_bigkey_nonce : ", bknonce)
    crypted_bignonce, bntag, bnnonce = KeyFile_Client.get_big_key_nonce(0, f_crypted_bignonce)
    print("c_bignonce : ", crypted_bigkey[:15])
    print("c_bignonce_tag : ", bntag)
    print("c_bignonce_nonce : ", bnnonce)
    bigkey_and_sum = DH_Algorithm_Client.decrypt(crypted_bigkey, bktag, bknonce)
    bignonce_and_sum = DH_Algorithm_Client.decrypt(crypted_bignonce, bntag, bnnonce)
    bigkey_sum, bigkey = KeyFile_Client.get_big_key_nonce(1, bigkey_and_sum)
    print("bigkey_sum : ", bigkey_sum)
    print("bigkey : ", bigkey[:15])
    bignonce_sum, bignonce = KeyFile_Client.get_big_key_nonce(1, bignonce_and_sum)
    print("bignonce_sum : ", bignonce_sum)
    print("bignonce : ", bignonce[:15])
    if File_Manipulation.file_integrity_check(bigkey, bigkey_sum) == False or File_Manipulation.file_integrity_check(bignonce, bignonce_sum) == False:
        key_c_recv_status = True
    else:
        KeyFile_Client.get_big_key_nonce(2, bigkey, bignonce)
        KeyFile_Client.key_choice()
        key_c_recv_status = True
print("----- KEY INIT C2 RECV : END -----")
print("-------- KEY INIT : END --------")

print("-------- SENDING/RECEIVING FILE : START --------")
print("----- C1 SENDING FILE : START -----")
while my_turn:
    KeyFile_Mine.key_nonce_reload()
    KeyFile_Server1.key_nonce_reload()
    KeyFile_Server2.key_nonce_reload()
    File_Manipulation.reset_init()
    File_Manipulation.ask_file()
    print("uncrypted_full_file : ", File_Manipulation.uncrypted_full_file[:15])
    # format sum + file
    file_format = File_Manipulation.format_file("file_format")
    AES_Encryption.update_data(file_format, KeyFile_Mine.key, KeyFile_Mine.nonce, "")
    File_Manipulation.crypted_full_file, File_Manipulation.tag_first_encryption1 = AES_Encryption.encrypt()
    File_Manipulation.split_file(0)
    # parts format
    File_Manipulation.format_file("part_format")
    File_Manipulation.file_part1_sum = File_Manipulation.SHA512_checksum_creation(File_Manipulation.full_format_file_part1)
    File_Manipulation.file_part2_sum = File_Manipulation.SHA512_checksum_creation(File_Manipulation.full_format_file_part2)
    print("full format file part 1 : ", File_Manipulation.full_format_file_part1[:15])
    print("full format file part 2 : ", File_Manipulation.full_format_file_part2[:15])
    File_Manipulation.format_file("last_format")
    # parts encryption
    AES_Encryption.update_data(File_Manipulation.full_format_file_part1, KeyFile_Server1.key, KeyFile_Server1.nonce, "")
    File_Manipulation.full_format_file_part1, File_Manipulation.tag_second_encryption1 = AES_Encryption.encrypt()
    AES_Encryption.update_data(File_Manipulation.full_format_file_part2, KeyFile_Server2.key, KeyFile_Server2.nonce, "")
    File_Manipulation.full_format_file_part2, File_Manipulation.tag_second_encryption2 = AES_Encryption.encrypt()
    Server1_conn.sending(File_Manipulation.format_file("format_bef_send1"), 1)
    Server2_conn.sending(File_Manipulation.format_file("format_bef_send2"), 1)
    my_turn = False
print("----- C1 SENDING FILE : END -----")

print("----- RECEIVING FILE : START -----")
while not my_turn:
    KeyFile_Client.key_nonce_reload()
    KeyFile_Server1.key_nonce_reload()
    KeyFile_Server2.key_nonce_reload()
    File_Manipulation.reset_init()
    File_Manipulation.crypted_file_part1 = Server1_conn.receiving(1)
    File_Manipulation.crypted_file_part2 = Server2_conn.receiving(1)
    File_Manipulation.tag_second_encryption1, File_Manipulation.crypted_file_part1 = File_Manipulation.crypted_file_part1.split(File_Manipulation.delimiter3.encode())
    File_Manipulation.tag_second_encryption2, File_Manipulation.crypted_file_part2 = File_Manipulation.crypted_file_part2.split(File_Manipulation.delimiter3.encode())
    AES_Encryption.update_data(File_Manipulation.crypted_file_part1, KeyFile_Server1.key, KeyFile_Server1.nonce, File_Manipulation.tag_second_encryption1)
    File_Manipulation.full_format_file_part1 = AES_Encryption.decrypt()
    AES_Encryption.update_data(File_Manipulation.crypted_file_part2, KeyFile_Server2.key, KeyFile_Server2.nonce, File_Manipulation.tag_second_encryption2)
    File_Manipulation.full_format_file_part2 = AES_Encryption.decrypt()
    File_Manipulation.get_file_informations(1, File_Manipulation.full_format_file_part1, File_Manipulation.full_format_file_part2)
    if not File_Manipulation.file_integrity_check(File_Manipulation.full_format_file_part1, File_Manipulation.file_part1_sum) or not File_Manipulation.file_integrity_check(File_Manipulation.full_format_file_part2, File_Manipulation.file_part2_sum):
        danger = True
        print("DANGER OVER HERE")
    else:
        File_Manipulation.get_big_key_nonce(0, File_Manipulation.format_file_part1, File_Manipulation.format_file_part2)
        File_Manipulation.reassemble_file(0)
        AES_Encryption.update_data(File_Manipulation.crypted_full_file, KeyFile_Client.key, KeyFile_Client.nonce, File_Manipulation.tag_first_encryption1)
        File_Manipulation.uncrypted_full_file = AES_Encryption.decrypt()
        if not File_Manipulation.file_integrity_check(File_Manipulation.uncrypted_full_file, File_Manipulation.file_sum):
            danger = True
            print("DANGER OVER HERE")
        else:
            File_Manipulation.reassemble_file(1)
print("----- RECEIVING FILE : END -----")
print("-------- SENDING/RECEIVING FILE : END --------")