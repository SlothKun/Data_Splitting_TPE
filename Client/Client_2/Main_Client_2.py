import Objects_Client

# Create Conn Objects
Server1_conn = Objects_Client.Client('127.0.0.1', 6801)
Server2_conn = Objects_Client.Client('127.0.0.1', 6799)

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
dh_initialised = False
key_initialised = False
dh_pubkey = []
big_key_nonce = []

# Create function to clear the code
def conn_s(server):
    if server == 1:
        Server1_conn.client_activation()
        return True
    elif server == 2:
        Server2_conn.client_activation()
        return True

def dh_init():
    dh_pbkey_s1 = DH_Algorithm_Server1.public_key_generator()
    dh_pbkey_s2 = DH_Algorithm_Server2.public_key_generator()
    dh_pbkey_c = DH_Algorithm_Client.public_key_generator()
    if len(dh_pubkey) == 0:
        Server1_conn.sending(dh_pbkey_s1)
        dh_pubkey.append(Server1_conn.receiving())
    elif len(dh_pubkey) == 1:
        Server2_conn.sending(dh_pbkey_s2)
        dh_pubkey.append(Server2_conn.receiving())
    elif len(dh_pubkey) == 2:
        part1, part2 = File_Manipulation.split_file(dh_pbkey_c)
        Server1_conn.sending(part1)
        Server2_conn.sending(part2)
        dh_pubkey.append((Server1_conn.receiving() + Server2_conn.receiving()))
    elif len(dh_pubkey) == 3:
        DH_Algorithm_Server1.private_key_generator(dh_pubkey[0])
        DH_Algorithm_Server2.private_key_generator(dh_pubkey[1])
        DH_Algorithm_Client.private_key_generator(dh_pubkey[2])
        dh_pubkey.clear()
        return False, True

def key_init():
    if len(big_key_nonce) == 0:
        KeyFile_Server1.big_key_nonce_generator()
        KeyFile_Server1.key_choice()
        big_key_nonce.append(KeyFile_Server1.big_key_nonce_format(0))
        Server1_conn.sending(DH_Algorithm_Server1.encrypt(KeyFile_Server1.big_key_nonce_format(1, File_Manipulation.SHA512_checksum_creation(big_key_nonce[0]), big_key_nonce[0])))
    elif len(big_key_nonce) == 1:
        KeyFile_Server2.big_key_nonce_generator()
        KeyFile_Server2.key_choice()
        big_key_nonce.append(KeyFile_Server2.big_key_nonce_format(0))
        Server2_conn.sending(DH_Algorithm_Server2.encrypt(KeyFile_Server2.big_key_nonce_format(1, File_Manipulation.SHA512_checksum_creation(big_key_nonce[1]), big_key_nonce[1])))
    elif len(big_key_nonce) == 2:
        bigpart1 = DH_Algorithm_Client.decrypt(Server1_conn.receiving())
        bigpart2 = DH_Algorithm_Client.decrypt(Server2_conn.receiving())
        bigpart1_sum, bigpart1 = KeyFile_Client.get_big_key_nonce(0, bigpart1)
        bigpart2_sum, bigpart2 = KeyFile_Client.get_big_key_nonce(0, bigpart2)
        if not File_Manipulation.file_integrity_check(bigpart1, bigpart1_sum) or not File_Manipulation.file_integrity_check(bigpart2, bigpart2_sum):
            integrity_failed_closing_protocol("Integrity fail.")
        else:
            if data_check(bigpart1[1]) == "ok" and data_check(bigpart2[1]) == "ok":
                bigfile = (bigpart1 + bigpart2)
                KeyFile_Client.get_big_key_nonce(1, bigfile)
                big_key_nonce.append(bigfile)
    elif len(big_key_nonce) == 3:
        KeyFile_Mine.big_key_nonce_generator()
        KeyFile_Mine.key_choice()
        big_key_nonce.append(KeyFile_Mine.big_key_nonce_format(1))
        part1, part2 = File_Manipulation.split_file(big_key_nonce[3])
        Server1_conn.sending(DH_Algorithm_Client.encrypt(KeyFile_Mine.big_key_nonce_format(1, File_Manipulation.SHA512_checksum_creation(part1), part1)))
        Server2_conn.sending(DH_Algorithm_Client.encrypt(KeyFile_Mine.big_key_nonce_format(1, File_Manipulation.SHA512_checksum_creation(part2), part2)))
    elif len(big_key_nonce) == 4:
        big_key_nonce.clear()
        return False

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

while not danger:
    if not s1_connected:
        s1_connected = conn_s(1)
        print(s1_connected)
    elif not s2_connected and s1_connected == True:
        s2_connected = conn_s(2)
        print(s2_connected)
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