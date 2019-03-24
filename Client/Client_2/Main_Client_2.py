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
global sockets

sockets = []
danger = False
my_turn = False
s1_connected = False
s2_connected = False
dh_initialised = False
key_initialised = False

# Create function to clear the code
def conn_s(server):
    if server == 1:
        return Server1_conn.client_activation()
    elif server == 2:
        return Server2_conn.client_activation()

def dh_init():
    print(" ")
    print("------------ DH INIT : END ---------------")
    dh_pubkey = []
    dh_pbkey_s1 = DH_Algorithm_Server1.public_key_generator()
    dh_pbkey_s2 = DH_Algorithm_Server2.public_key_generator()
    dh_pbkey_c = DH_Algorithm_Client.public_key_generator()
    while True:
        if len(dh_pubkey) == 0:
            Server2_conn.sending(dh_pbkey_s2, 0)
            dh_pubkey.append(Server2_conn.receiving(0))
            print("DH key (S2) : ", dh_pubkey[0])
        elif len(dh_pubkey) == 1:
            Server1_conn.sending(dh_pbkey_s1, 0)
            dh_pubkey.append(Server1_conn.receiving(0))
            print("DH key (S1) : ", dh_pubkey[1])
        elif len(dh_pubkey) == 2:
            part1, part2 = File_Manipulation.split_file(dh_pbkey_c)
            print("DH key part1 : ", part1)
            print("DH key part2 : ", part2)
            Server1_conn.sending(part1, 0)
            Server2_conn.sending(part2, 0)
            dh_pubkey.append((Server1_conn.receiving(0) + Server2_conn.receiving(0)))
        elif len(dh_pubkey) == 3:
            print("-----GEN PRIVATE KEY : START-----")
            DH_Algorithm_Server2.private_key_generator(dh_pubkey[0])
            print("Private key S2 : ", DH_Algorithm_Server2.private_key)
            DH_Algorithm_Server1.private_key_generator(dh_pubkey[1])
            print("Private key S1 : ", DH_Algorithm_Server1.private_key)
            DH_Algorithm_Client.private_key_generator(dh_pubkey[2])
            print("Private key C : ", DH_Algorithm_Client.private_key)
            print("-----GEN PRIVATE KEY : END-----")
            dh_pubkey.clear()
            print("------------ DH INIT : END ---------------")
            print(" ")
            return True, False

def key_init():
    print(" ")
    print("-------KEY INIT : START----------")
    big_key_nonce = []
    while True:
        if len(big_key_nonce) == 0:
            print(" ")
            print("-----BIG_KEY_NONCE S2 : START-----")
            KeyFile_Server2.big_key_nonce_generator()
            KeyFile_Server2.key_choice()
            big_key_nonce.append(KeyFile_Server2.big_key_nonce_format(0))
            encrypted_key, tag, nonce = DH_Algorithm_Server2.encrypt((KeyFile_Server2.big_key_nonce_format(1, File_Manipulation.SHA512_checksum_creation(big_key_nonce[0]), big_key_nonce[0])))
            print("ENCRYPTED KEY : ", encrypted_key)
            print(type(encrypted_key))
            print("TAG : ", tag)
            print(type(tag))
            print("NONCE : ", nonce)
            print(type(nonce))
            Server2_conn.sending(KeyFile_Server2.big_key_nonce_format(2, tag, nonce, encrypted_key), 1)
            print("-----BIG_KEY_NONCE S2 : END-----")
            print("  ")
        elif len(big_key_nonce) == 1:
            print(" ")
            print("-----BIG_KEY_NONCE S1 : START-----")
            KeyFile_Server1.big_key_nonce_generator()
            KeyFile_Server1.key_choice()
            big_key_nonce.append(KeyFile_Server1.big_key_nonce_format(0))
            encrypted_key, tag, nonce = DH_Algorithm_Server1.encrypt((KeyFile_Server1.big_key_nonce_format(1, File_Manipulation.SHA512_checksum_creation(big_key_nonce[1]), big_key_nonce[1])))
            print("ENCRYPTED KEY : ", encrypted_key)
            print(type(encrypted_key))
            print("TAG : ", tag)
            print(type(tag))
            print("NONCE : ", nonce)
            print(type(nonce))
            Server1_conn.sending(KeyFile_Server1.big_key_nonce_format(2, tag, nonce, encrypted_key), 1)
            print("-----BIG_KEY_NONCE S1 : START-----")
            print("  ")
        elif len(big_key_nonce) == 2:
            print(" ")
            print("-----BIG_KEY_NONCE C1 : START-----")
            bigpart1, tag1, nonce1 = KeyFile_Client.get_big_key_nonce(0, Server1_conn.receiving(1))
            print("BIGPART 1 KEY : ", bigpart1)
            print("TAG 1 : ", tag1)
            print("NONCE 1 : ", nonce1)
            bigpart2, tag2, nonce2 = KeyFile_Client.get_big_key_nonce(0, Server2_conn.receiving(1))
            print("BIGPART 2 KEY : ", bigpart2)
            print("TAG 2 : ", tag2)
            print("NONCE 2 : ", nonce2)
            bigpart1 = DH_Algorithm_Client.decrypt(bigpart1, tag1, nonce1)
            bigpart2 = DH_Algorithm_Client.decrypt(bigpart2, tag2, nonce2)
            bigpart1_sum, bigpart1 = KeyFile_Client.get_big_key_nonce(1, bigpart1)
            print("BIGPART SUM 1 : ", bigpart1_sum)
            bigpart2_sum, bigpart2 = KeyFile_Client.get_big_key_nonce(1, bigpart2)
            print("BIGPART SUM 2 : ", bigpart2_sum)
            if not File_Manipulation.file_integrity_check(bigpart1, bigpart1_sum) or not File_Manipulation.file_integrity_check(bigpart2, bigpart2_sum):
                integrity_failed_closing_protocol("Integrity fail.")
            else:
                if data_check(bigpart1[1]) == "ok" and data_check(bigpart2[1]) == "ok":
                    bigfile = (bigpart1 + bigpart2)
                    KeyFile_Client.get_big_key_nonce(2, bigfile)
                    print("KEY : ", KeyFile_Client.big_key_original)
                    print("Nonce : ", KeyFile_Client.big_nonce_original)
                    big_key_nonce.append(bigfile)
            print("-----BIG_KEY_NONCE C1 : END-----")
            print(" ")
        elif len(big_key_nonce) == 3:
            print(" ")
            print("-----BIG_KEY_NONCE C2 : START-----")
            KeyFile_Mine.big_key_nonce_generator()
            KeyFile_Mine.key_choice()
            big_key_nonce.append(KeyFile_Mine.big_key_nonce_format(0))
            part1, part2 = File_Manipulation.split_file(big_key_nonce[2])
            encrypted_key, tag, nonce = DH_Algorithm_Client.encrypt((KeyFile_Server1.big_key_nonce_format(1, File_Manipulation.SHA512_checksum_creation(part1), part1)))
            Server1_conn.sending(KeyFile_Client.big_key_nonce_format(2, tag, nonce, encrypted_key), 1)
            print("ENCRYPTED KEY : ", encrypted_key)
            print("TAG : ", tag)
            print("NONCE : ", nonce)
            encrypted_key, tag, nonce = DH_Algorithm_Client.encrypt((KeyFile_Server2.big_key_nonce_format(1, File_Manipulation.SHA512_checksum_creation(part2), part2)))
            Server2_conn.sending(KeyFile_Client.big_key_nonce_format(2, tag, nonce, encrypted_key), 1)
            print("ENCRYPTED KEY : ", encrypted_key)
            print("TAG : ", tag)
            print("NONCE : ", nonce)
            print("-----BIG_KEY_NONCE C2 : END-----")
            print(" ")
        elif len(big_key_nonce) == 4:
            big_key_nonce.clear()
            return True

def sending_file():
    keyfile_reload(0)
    File_Manipulation.reset_init()
    # Full file manipulation
    File_Manipulation.ask_file()
    AES_Encryption.update_data((File_Manipulation.file_sum + File_Manipulation.delimiter1 + File_Manipulation.uncrypted_full_file), KeyFile_Mine.key, KeyFile_Mine.nonce)
    File_Manipulation.Crypted_full_file = AES_Encryption.encrypt()
    # Part manipulation
    File_Manipulation.split_file(0)
    File_Manipulation.format_file(0)
    File_Manipulation.file_part1_sum = File_Manipulation.SHA512_checksum_creation(File_Manipulation.full_format_file_part1)
    File_Manipulation.file_part2_sum = File_Manipulation.SHA512_checksum_creation(File_Manipulation.full_format_file_part2)
    File_Manipulation.format_file(1)
    AES_Encryption.update_data(File_Manipulation.full_format_file_part1, KeyFile_Server1.key, KeyFile_Server1.nonce)
    Server1_conn.sending(AES_Encryption.encrypt())
    AES_Encryption.update_data(File_Manipulation.full_format_file_part2, KeyFile_Server2.key, KeyFile_Server2.nonce)
    Server2_conn.sending(AES_Encryption.encrypt())
    return False

def receiving_file():
    keyfile_reload(0)
    File_Manipulation.reset_init()
    # Part manipulation
    File_Manipulation.crypted_file_part1 = Server1_conn.receiving()
    File_Manipulation.crypted_file_part2 = Server2_conn.receiving()
    AES_Encryption.update_data(File_Manipulation.crypted_file_part1, KeyFile_Server1.key, KeyFile_Server1.nonce)
    File_Manipulation.full_format_file_part1 = AES_Encryption.decrypt()
    AES_Encryption.update_data(File_Manipulation.crypted_file_part2, KeyFile_Server2.key, KeyFile_Server2.nonce)
    File_Manipulation.full_format_file_part2 = AES_Encryption.decrypt()
    part1_sum, part1 = File_Manipulation.get_file_information(1, File_Manipulation.full_format_file_part1)
    part2_sum, part2 = File_Manipulation.get_file_information(1, File_Manipulation.full_format_file_part2)
    if not File_Manipulation.file_integrity_check(part1, part1_sum) or not File_Manipulation.file_integrity_check(part2, part2_sum):
        integrity_failed_closing_protocol("Integrity fail.")
    else:
        if data_check(part1) == "ok" and data_check(part2) == "ok":
            File_Manipulation.get_file_information(0, part1, part2)
            AES_Encryption.update_data(File_Manipulation.unrecrypted_file_part1, KeyFile_Client.key, KeyFile_Client.nonce)
            File_Manipulation.unrecrypted_file_part1 = AES_Encryption.decrypt()
            AES_Encryption.update_data(File_Manipulation.unrecrypted_file_part2, KeyFile_Client.key, KeyFile_Client.nonce)
            File_Manipulation.unrecrypted_file_part2 = AES_Encryption.decrypt()
            File_Manipulation.reassemble_file()
            if not File_Manipulation.file_integrity_check(File_Manipulation.uncrypted_full_file, File_Manipulation.file_sum):
                integrity_failed_closing_protocol("Integrity fail.")
            else:
                return True
                # open file

def data_check(data):
    if data == "ping":
        ping_or_pong("pong")
    elif data == "Integrity fail.":
        total_disconnection()
    else:
        return "ok"

def ping_or_pong(ping_pong):
    keyfile_reload(1)
    formatted_ping = File_Manipulation.SHA512_checksum_creation(ping_pong) + File_Manipulation.delimiter2 + ping_pong
    AES_Encryption.update_data(formatted_ping, KeyFile_Server1.key, KeyFile_Server1.nonce)
    Server1_conn.sending(AES_Encryption.encrypt())
    AES_Encryption.update_data(formatted_ping, KeyFile_Server2.key, KeyFile_Server2.nonce)
    Server2_conn.sending(AES_Encryption.encrypt())
    if ping_pong == "ping":
        ping_check()

def ping_check():
    keyfile_reload(1)
    received_data1 = Server1_conn.receiving()
    received_data2 = Server2_conn.receiving()
    AES_Encryption.update_data(received_data1, KeyFile_Server1.key, KeyFile_Server1.nonce)
    decrypted_data1 = AES_Encryption.decrypt().split(File_Manipulation.delimiter2)
    AES_Encryption.update_data(received_data2, KeyFile_Server2.key, KeyFile_Server2.nonce)
    decrypted_data2 = AES_Encryption.decrypt().split(File_Manipulation.delimiter2)
    if not File_Manipulation.file_integrity_check(decrypted_data1[1], decrypted_data1[0]) or not File_Manipulation.file_integrity_check(decrypted_data2[1], decrypted_data2[0]):
        integrity_failed_closing_protocol("Integrity fail.")
    else:
        if decrypted_data1[1] == "Integrity fail." or decrypted_data2[1] == "Integrity fail.":
            total_disconnection()
        elif decrypted_data1[1] != "pong" or decrypted_data2[1] != "pong":
            integrity_failed_closing_protocol("Ping check failed.")

def keyfile_reload(mode):
    global key_initialised
    if mode == 0:
        # Reset File_manipulation init
        File_Manipulation.reset_init()
        # Verify length of nonce and key and take one nonce for each objects
        if not KeyFile_Mine.key_nonce_length_check() or not KeyFile_Client.key_nonce_length_check() or not KeyFile_Server1.key_nonce_length_check() or not KeyFile_Server2.key_nonce_length_check():
            key_initialised = False
        KeyFile_Mine.nonce_choice()
        KeyFile_Client.nonce_choice()
        KeyFile_Server1.nonce_choice()
        KeyFile_Server2.nonce_choice()
    elif mode == 1:
        if not KeyFile_Server1.key_nonce_length_check() or not KeyFile_Server2.key_nonce_length_check():
            KeyFile_Server1.nonce_choice()
            KeyFile_Server2.nonce_choice()

def integrity_failed_closing_protocol(error):
    keyfile_reload(1)
    AES_Encryption.update_data((File_Manipulation.SHA512_checksum_creation(error) + File_Manipulation.delimiter2 + error), KeyFile_Server1.key, KeyFile_Server1.nonce)
    Server1_conn.sending(AES_Encryption.encrypt())
    AES_Encryption.update_data((File_Manipulation.SHA512_checksum_creation(error) + File_Manipulation.delimiter2 + error), KeyFile_Server2.key, KeyFile_Server2.nonce)
    Server2_conn.sending(AES_Encryption.encrypt())
    total_disconnection()
    print("contacting an administrator..")

def total_disconnection():
    global danger
    Server1_conn.disconnecting()
    Server2_conn.disconnecting()
    danger = True


sleep(4)
i = 0
while not s2_connected:
    print("trying to connect to S2 : ")
    i += 1
    s2_connected = conn_s(2)
    print("s2 state : ", s2_connected)
while not s1_connected:
    print("trying to connect to S1 : ")
    s1_connected = conn_s(1)
    print("s1 state : ", s1_connected)
while not dh_initialised:
    dh_initialised, key_initialised = dh_init()
while not key_initialised:
    key_initialised = key_init()

print("3 premieres etapes OK !")



'''
while not danger:
    if s2_connected:
        if s1_connected:
            if dh_initialised:
                if key_initialised:
                    if my_turn:
                        my_turn = sending_file()
                    else:
                        my_turn = receiving_file()
                else:
                    key_initialised = key_init()
            else:
                dh_initialised, key_initialised = dh_init()
        else:
            s1_connected = conn_s(1)
            print(s1_connected)
    else:
        s2_connected = conn_s(2)
        print(s2_connected)
'''







'''
while not danger:
    if not s2_connected:
        s2_connected = conn_s(2)
        print(s2_connected)
    elif not s1_connected:
        s1_connected = conn_s(1)
        print(s1_connected)
    else:
        if not dh_initialised:  # Initialise DH_algo key creation / send
            dh_initialised, key_initialised = dh_init()
        elif not key_initialised:  # Initialise Key creation / send
            key_initialised = key_init()
        else:
            if my_turn:
                my_turn = sending_file()
            else:
                my_turn = receiving_file()
'''