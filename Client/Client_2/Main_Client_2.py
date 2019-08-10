import Objects_Client
from time import sleep

# Create Conn Objects
Server1_conn = Objects_Client.Client('127.0.0.1', 6802)
Server2_conn = Objects_Client.Client('127.0.0.1', 6803)

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
my_turn = False
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
print("----- CONN S2 : START -----")
while not s2_connected:
    s2_connected = Server2_conn.client_activation()
print("state of s2_connected : ", s2_connected)
print("----- CONN S2 : END -----")

print("")

print("----- CONN S1 : START -----")
while not s1_connected:
    s1_connected = Server1_conn.client_activation()
print("state of s1_connected : ", s1_connected)
print("----- CONN S1 : END -----")
print("-------- CONN PHASE : END --------")

print("")
print("")

print("-------- DH INIT : START --------")
print("----- DH INIT S2 : START -----")
while not dh_s2_status:
    DH_Algorithm_Server2.public_key_generator()
    Server2_conn.sending(DH_Algorithm_Server2.public_key, 0)
    print("C1 to S2 key : ", str(DH_Algorithm_Server2.public_key)[:15])
    print("C1 to S2 key length :", len(str(DH_Algorithm_Server2.public_key)))
    friendkey = Server2_conn.receiving(0)
    print("S2 to C1 key : ", friendkey[:15])
    print("S2 to C1 key length : ", len(friendkey))
    DH_Algorithm_Server2.private_key_generator(friendkey)
    print("common key : ", DH_Algorithm_Server2.private_key[:15])
    print("common key length : ", len(DH_Algorithm_Server2.private_key))
    dh_s2_status = True
    print("state of DH_s2_status : ", dh_s2_status)
print("----- DH INIT S2 : END -----")

print("")

print("----- DH INIT S1 : START -----")
while not dh_s1_status:
    DH_Algorithm_Server1.public_key_generator()
    Server1_conn.sending(DH_Algorithm_Server1.public_key, 0)
    print("C1  to S1 key : ", str(DH_Algorithm_Server1.public_key)[:15])
    print("C1 to S1 key length :", len(str(DH_Algorithm_Server1.public_key)))
    friendkey = Server1_conn.receiving(0)
    print("S1 to C1 key : ", friendkey[:15])
    print("S1 to C1 key length :", len(friendkey))
    DH_Algorithm_Server1.private_key_generator(friendkey)
    print("common key : ", DH_Algorithm_Server1.private_key[:15])
    print("common key length : ", len(DH_Algorithm_Server1.private_key))
    dh_s1_status = True
    print("state of DH_s1_status : ", dh_s1_status)
print("----- DH INIT S1 : END -----")

print("")

print("----- DH INIT C1 : START -----")
while not dh_c_status:
    pub_keyC1_part1 = Server1_conn.receiving(0)
    print("keyrecv part 1 : ", pub_keyC1_part1[:15])
    print("keyrecv part 1  len : ", len(pub_keyC1_part1))
    pub_keyC1_part2 = Server2_conn.receiving(0)
    print("keyrecv part 2 : ", pub_keyC1_part2[:15])
    print("keyrecv part 2 len : ", len(pub_keyC1_part2))
    DH_Algorithm_Client.public_key_generator()
    print("pubkey : ", str(DH_Algorithm_Client.public_key)[:15])
    print("pubkey len : ", len(str(DH_Algorithm_Client.public_key)))
    pub_key_part1 = str(DH_Algorithm_Client.public_key)[:(int(len(str(DH_Algorithm_Client.public_key))/2))]
    print("part 1 : ", pub_key_part1[:15])
    print("part 1 len : ", len(pub_key_part1))
    pub_key_part2 = str(DH_Algorithm_Client.public_key)[(int(len(str(DH_Algorithm_Client.public_key))/2)):]
    print("part 2 : ", pub_key_part2[:15])
    print("part 2 len : ", len(pub_key_part2))
    Server1_conn.sending(pub_key_part1, 0)
    Server2_conn.sending(pub_key_part2, 0)
    DH_Algorithm_Client.private_key_generator((pub_keyC1_part1 + pub_keyC1_part2))
    print("Private key :", DH_Algorithm_Client.private_key)
    print("Private key len :", len(DH_Algorithm_Client.private_key))
    dh_c_status = True
    print("state of DH_c_status : ", dh_c_status)
print("----- DH INIT C1 : END -----")
print("-------- DH INIT : END --------")

print("")
print("")

print("-------- KEY INIT : START --------")
print("----- KEY INIT S2 : START -----")
while not key_s2_status:
    KeyFile_Server2.big_key_nonce_generator()
    KeyFile_Server2.key_choice()
    bigkeynonce = KeyFile_Server2.big_key_nonce_format(0)
    print("start of bigkeynonce : ", bigkeynonce[:15])
    print("start of bigkeynonce len : ", len(bigkeynonce))
    bigkeynonce_sum = File_Manipulation.SHA512_checksum_creation(bigkeynonce)
    print("bigkeynonce sum : ", bigkeynonce_sum)
    bigkeynonce_and_sum = KeyFile_Server2.big_key_nonce_format(1, bigkeynonce_sum, bigkeynonce)
    cryptedbigkeynonce, tag, nonce = DH_Algorithm_Server2.encrypt(bigkeynonce_and_sum)
    print("cbkn : ", cryptedbigkeynonce[:15])
    print("cbkn len : ", len(cryptedbigkeynonce))
    print("ckn_tag : ", tag)
    print("ckn_nonce : ", nonce)
    f_cryptedbigkeynonce = KeyFile_Server2.big_key_nonce_format(2, tag, nonce, cryptedbigkeynonce)
    print("f_cryptedbigkeynonce : ", f_cryptedbigkeynonce[:15])
    print("f_cryptedbigkeynonce len : ", len(f_cryptedbigkeynonce))
    Server2_conn.sending(f_cryptedbigkeynonce, 1)
    key_s2_status = True
    print("state of key_s2_status : ", key_s2_status)
print("----- KEY INIT S2 : END -----")

print("")

print("----- KEY INIT S1 : START -----")
while not key_s1_status:
    KeyFile_Server1.big_key_nonce_generator()
    KeyFile_Server1.key_choice()
    bigkeynonce = KeyFile_Server1.big_key_nonce_format(0)
    print("start of bigkeynonce : ", bigkeynonce[:15])
    print("start of bigkeynonce length : ", len(bigkeynonce))
    bigkeynonce_sum = File_Manipulation.SHA512_checksum_creation(bigkeynonce)
    print("bigkeynonce sum : ", bigkeynonce_sum)
    bigkeynonce_and_sum = KeyFile_Server1.big_key_nonce_format(1, bigkeynonce_sum, bigkeynonce)
    print("bigkeynonce_and_sum : ", bigkeynonce_and_sum[:15])
    print("bigkeynonce_and_sum : ", len(bigkeynonce_and_sum))
    cryptedbigkeynonce, tag, nonce = DH_Algorithm_Server1.encrypt(bigkeynonce_and_sum)
    print("cbkn : ", cryptedbigkeynonce[:15])
    print("cbkn len : ", len(cryptedbigkeynonce))
    print("ckn_tag : ", tag)
    print("ckn_nonce : ", nonce)
    f_cryptedbigkeynonce = KeyFile_Server1.big_key_nonce_format(2, tag, nonce, cryptedbigkeynonce)
    print("f_cryptedbigkeynonce : ", f_cryptedbigkeynonce[:15])
    print("f_cryptedbigkeynonce len : ", len(f_cryptedbigkeynonce))
    Server1_conn.sending(f_cryptedbigkeynonce, 1)
    key_s1_status = True
    print("state of key_s1_status : ", key_s1_status)
print("----- KEY INIT S1 : END -----")

print("")

print("----- KEY INIT C1 RECV : START -----")
while not key_c_recv_status:
    f_crypted_bigkey = Server1_conn.receiving(1)
    print("f_crypted_bigkey :", f_crypted_bigkey[:15])
    print("f_crypted_bigkey :", f_crypted_bigkey[:15])
    f_crypted_bignonce = Server2_conn.receiving(1)
    print("f_crypted_bignonce : ", f_crypted_bignonce[:15])
    print("f_crypted_bignonce len : ", len(f_crypted_bignonce))
    crypted_bigkey, bktag, bknonce = KeyFile_Client.get_big_key_nonce(0, f_crypted_bigkey)
    print("c_bigkey : ", crypted_bigkey[:15])
    print("c_bigkey len : ", len(crypted_bigkey))
    print("c_bigkey_tag : ", bktag)
    print("c_bigkey_nonce : ", bknonce)
    crypted_bignonce, bntag, bnnonce = KeyFile_Client.get_big_key_nonce(0, f_crypted_bignonce)
    print("c_bignonce : ", crypted_bigkey[:15])
    print("c_bignonce len : ", len(crypted_bigkey))
    print("c_bignonce_tag : ", bntag)
    print("c_bignonce_nonce : ", bnnonce)
    bigkey_and_sum = DH_Algorithm_Client.decrypt(crypted_bigkey, bktag, bknonce)
    bignonce_and_sum = DH_Algorithm_Client.decrypt(crypted_bignonce, bntag, bnnonce)
    bigkey_sum, bigkey = KeyFile_Client.get_big_key_nonce(1, bigkey_and_sum)
    print("bigkey_sum : ", bigkey_sum)
    print("bigkey : ", bigkey[:15])
    print("bigkey len : ", len(bigkey))
    bignonce_sum, bignonce = KeyFile_Client.get_big_key_nonce(1, bignonce_and_sum)
    print("bignonce_sum : ", bignonce_sum)
    print("bignonce : ", bignonce[:15])
    print("bignonce len : ", len(bignonce))
    if File_Manipulation.file_integrity_check(bigkey, bigkey_sum.decode()) == False or File_Manipulation.file_integrity_check(bignonce, bignonce_sum.decode()) == False:
        key_c_recv_status = True
        print("integrity file check key init C1 failed")
    else:
        KeyFile_Client.get_big_key_nonce(2, bigkey, bignonce)
        KeyFile_Client.key_choice()
        key_c_recv_status = True
        print("key_c_recv_status : ", key_c_recv_status)
print("----- KEY INIT C1 RECV : END -----")

print("")

print("----- KEY INIT C1 SEND : START -----")
while not key_c_send_status:
    KeyFile_Mine.big_key_nonce_generator()
    KeyFile_Mine.key_choice()
    print("Start of BKey : ", KeyFile_Mine.big_key_original[:15])
    print("Start of BKey len : ", len(KeyFile_Mine.big_key_original))
    print("Start of BNonce : ", KeyFile_Mine.big_nonce_original[:15])
    print("Start of BNonce len : ", len(KeyFile_Mine.big_nonce_original))
    bigkey_sum = File_Manipulation.SHA512_checksum_creation(KeyFile_Mine.big_key_original)
    print("bigkey_sum : ", bigkey_sum)
    bignonce_sum = File_Manipulation.SHA512_checksum_creation(KeyFile_Mine.big_nonce_original)
    print("bignonce_sum : ", bignonce_sum)
    bigkey_and_sum = KeyFile_Mine.big_key_nonce_format(1, bigkey_sum, KeyFile_Mine.big_key_original)
    print("bigkey_and_sum : ", bigkey_and_sum[:15])
    print("bigkey_and_sum len : ", len(bigkey_and_sum))
    bignonce_and_sum = KeyFile_Mine.big_key_nonce_format(1, bignonce_sum, KeyFile_Mine.big_nonce_original)
    print("bignonce_and_sum : ", bignonce_and_sum[:15])
    print("bignonce_and_sum len : ", len(bignonce_and_sum))
    crypted_bigkey, bktag, bknonce = DH_Algorithm_Client.encrypt(bigkey_and_sum)
    print("c_bigkey : ", crypted_bigkey[:15])
    print("c_bigkey len : ", len(crypted_bigkey))
    print("c_bigkey_tag : ", bktag)
    print("c_bigkey_nonce : ", bknonce)
    crypted_bignonce, bntag, bnnonce = DH_Algorithm_Client.encrypt(bignonce_and_sum)
    print("c_bignonce : ", crypted_bigkey[:15])
    print("c_bignonce len : ", len(crypted_bigkey))
    print("c_bignonce_tag : ", bntag)
    print("c_bignonce_nonce : ", bnnonce)
    f_crypted_bigkey = KeyFile_Mine.big_key_nonce_format(2, bktag, bknonce, crypted_bigkey)
    print("f_crypted_bigkey :", f_crypted_bigkey[:15])
    print("f_crypted_bigkey len :", len(f_crypted_bigkey))
    f_crypted_bignonce = KeyFile_Mine.big_key_nonce_format(2, bntag, bnnonce, crypted_bignonce)
    print("f_crypted_bignonce : ", f_crypted_bignonce[:15])
    print("f_crypted_bignonce len : ", len(f_crypted_bignonce))
    Server1_conn.sending(f_crypted_bigkey, 1)
    Server2_conn.sending(f_crypted_bignonce, 1)
    key_c_send_status = True
    print("state of key_c_send_status : ", key_c_send_status)
print("----- KEY INIT C1 SEND : END -----")
print("-------- KEY INIT : END --------")

print("")
print("")

print("-------- SENDING/RECEIVING FILE : START --------")
print("----- RECEIVING FILE : START -----")
while not my_turn:
    while not my_turn:
        # Change key/nonce and reset File_Manipulation's variables
        KeyFile_Client.key_nonce_reload()
        KeyFile_Server1.key_nonce_reload()
        KeyFile_Server2.key_nonce_reload()
        File_Manipulation.reset_init()
        # Receiving
        File_Manipulation.crypted_file_part1 = Server1_conn.receiving(1)
        File_Manipulation.crypted_file_part2 = Server2_conn.receiving(1)
        print("received fc_part 1 : ", File_Manipulation.crypted_file_part1[:15])
        print("received fc_part 1 len : ", len(File_Manipulation.crypted_file_part1))
        print("received fc_part 2 : ", File_Manipulation.crypted_file_part2[:15])
        print("received fc_part 2 len : ", len(File_Manipulation.crypted_file_part2))
        # Get encryption tag of files
        File_Manipulation.tag_second_encryption1, File_Manipulation.crypted_file_part1 = File_Manipulation.crypted_file_part1.split(
            File_Manipulation.delimiter3.encode())
        File_Manipulation.tag_second_encryption2, File_Manipulation.crypted_file_part2 = File_Manipulation.crypted_file_part2.split(
            File_Manipulation.delimiter3.encode())
        print("tag 1 : ", File_Manipulation.tag_second_encryption1)
        print("tag 2 : ", File_Manipulation.tag_second_encryption2)
        print("c_part 1 : ", File_Manipulation.crypted_file_part1[:15])
        print("c_part 1 len : ", len(File_Manipulation.crypted_file_part1))
        print("c_part 2 : ", File_Manipulation.crypted_file_part2[:15])
        print("c_part 2 len : ", len(File_Manipulation.crypted_file_part2))
        # decrypt files
        AES_Encryption.update_data(File_Manipulation.crypted_file_part1, KeyFile_Server1.key, KeyFile_Server1.nonce,
                                   File_Manipulation.tag_second_encryption1)
        File_Manipulation.full_format_file_part1 = AES_Encryption.decrypt()
        print("File_Manipulation.full_format_file_part1 : ", File_Manipulation.full_format_file_part1[:15])
        print("File_Manipulation.full_format_file_part1 len : ", len(File_Manipulation.full_format_file_part1))
        AES_Encryption.update_data(File_Manipulation.crypted_file_part2, KeyFile_Server2.key, KeyFile_Server2.nonce,
                                   File_Manipulation.tag_second_encryption2)
        File_Manipulation.full_format_file_part2 = AES_Encryption.decrypt()
        print("File_Manipulation.full_format_file_part2 : ", File_Manipulation.full_format_file_part2[:15])
        print("File_Manipulation.full_format_file_part2 len : ", len(File_Manipulation.full_format_file_part2))
        # Get files sum and check integrity
        File_Manipulation.get_file_information(1, File_Manipulation.full_format_file_part1,
                                               File_Manipulation.full_format_file_part2)
        print("File 1 sum : ", File_Manipulation.file_part1_sum)
        print("File 2 sum : ", File_Manipulation.file_part2_sum)
        print("uncrypted_f_file 1 : ", File_Manipulation.full_format_file_part1[:15])
        print("uncrypted_f_file 1 len : ", len(File_Manipulation.full_format_file_part1))
        print("uncrypted_f_file 2 : ", File_Manipulation.full_format_file_part2[:15])
        print("uncrypted_f_file 2 len : ", len(File_Manipulation.full_format_file_part2))
        if not File_Manipulation.file_integrity_check(File_Manipulation.full_format_file_part1,
                                                      File_Manipulation.file_part1_sum.decode()) or not File_Manipulation.file_integrity_check(
                File_Manipulation.full_format_file_part2, File_Manipulation.file_part2_sum.decode()):
            danger = True
            print("DANGER OVER HERE1")
        else:
            File_Manipulation.get_file_information(0, File_Manipulation.full_format_file_part1,
                                                   File_Manipulation.full_format_file_part2)
            File_Manipulation.reassemble_file(0)
            AES_Encryption.update_data(File_Manipulation.crypted_full_file, KeyFile_Client.key, KeyFile_Client.nonce,
                                       File_Manipulation.tag_first_encryption1)
            print("nonce : ", KeyFile_Client.nonce)
            print("nonce length : ", len(KeyFile_Client.nonce))
            File_Manipulation.get_file_information(2, AES_Encryption.decrypt())
            print("type of file sum : ", File_Manipulation.file_sum)
            if not File_Manipulation.file_integrity_check(File_Manipulation.uncrypted_full_file,
                                                          File_Manipulation.file_sum.decode()):
                danger = True
                print("DANGER OVER HERE2")
            else:
                File_Manipulation.reassemble_file(1)
                print("DONE !")
                my_turn = True
print("----- RECEIVING FILE : END -----")

print("")

print("----- C2 SENDING FILE : START -----")
while my_turn:
    KeyFile_Mine.key_nonce_reload()
    KeyFile_Server1.key_nonce_reload()
    KeyFile_Server2.key_nonce_reload()
    File_Manipulation.reset_init()
    File_Manipulation.ask_file()
    print("uncrypted_full_file : ", File_Manipulation.uncrypted_full_file[:15])
    print("uncrypted_full_file len : ", len(File_Manipulation.uncrypted_full_file))
    # format sum + file
    file_format = File_Manipulation.format_file("file_format")
    print("file_format : ", file_format[:15])
    print("file_format len : ", len(file_format))
    AES_Encryption.update_data(file_format, KeyFile_Mine.key, KeyFile_Mine.nonce, "")
    File_Manipulation.crypted_full_file, File_Manipulation.tag_first_encryption1 = AES_Encryption.encrypt()
    print("File_Manipulation.crypted_full_file : ", File_Manipulation.crypted_full_file[:15])
    print("File_Manipulation.crypted_full_file len : ", len(File_Manipulation.crypted_full_file))
    File_Manipulation.split_file(0)
    # parts format
    File_Manipulation.format_file("part_format")
    File_Manipulation.file_part1_sum = File_Manipulation.SHA512_checksum_creation(File_Manipulation.full_format_file_part1)
    print("file_part1_sum : ", File_Manipulation.file_part1_sum)
    File_Manipulation.file_part2_sum = File_Manipulation.SHA512_checksum_creation(File_Manipulation.full_format_file_part2)
    print("file part2 sum : ", File_Manipulation.file_part2_sum)
    File_Manipulation.format_file("last_format")
    # parts encryption
    AES_Encryption.update_data(File_Manipulation.full_format_file_part1, KeyFile_Server1.key, KeyFile_Server1.nonce, "")
    File_Manipulation.full_format_file_part1, File_Manipulation.tag_second_encryption1 = AES_Encryption.encrypt()
    print("full format file part1 :", File_Manipulation.full_format_file_part1[:15])
    print("full format file part1 len :", len(File_Manipulation.full_format_file_part1))
    AES_Encryption.update_data(File_Manipulation.full_format_file_part2, KeyFile_Server2.key, KeyFile_Server2.nonce, "")
    File_Manipulation.full_format_file_part2, File_Manipulation.tag_second_encryption2 = AES_Encryption.encrypt()
    print("full format file part2 :", File_Manipulation.full_format_file_part2[:15])
    print("full format file part2 len :", len(File_Manipulation.full_format_file_part2))
    part1_last_format = File_Manipulation.format_file("format_bef_send1")
    print("part1_last_format : ", part1_last_format[:15])
    print("part1_last_format len : ", len(part1_last_format))
    part2_last_format = File_Manipulation.format_file("format_bef_send2")
    print("part2_last_format : ", part2_last_format[:15])
    print("part2_last_format len : ", len(part2_last_format))
    Server1_conn.sending(part1_last_format, 1)
    Server2_conn.sending(part2_last_format, 1)
    my_turn = False
print("----- C2 SENDING FILE : END -----")
print("-------- SENDING/RECEIVING FILE : END --------")