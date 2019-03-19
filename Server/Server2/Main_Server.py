import Objects_Server

# Create Conn Objects
Client1_conn = Objects_Server.Server("127.0.0.1", 6802)
Client2_conn = Objects_Server.Server("127.0.0.1", 6803)

# Create DH_algo Objects
DH_Algorithm_Client1 = Objects_Server.DH_algorithm()
DH_Algorithm_Client2 = Objects_Server.DH_algorithm()

# Create Key Objects
KeyFile_Client1 = Objects_Server.Key()
KeyFile_Client2 = Objects_Server.Key()

# Create File and AES objects
AES_Encryption = Objects_Server.AES_Algorithm()
File_Manipulation = Objects_Server.File()

# Create some variable
global danger
global key_initialised
danger = False
receiving_sending_mode = 0
c1_connected = False
c2_connected = False
dh_initialised = False
key_initialised = False

# Create function to clear the code
def conn_s(client):
    if client == 1:
        Client1_conn.server_activation()
        print("Client 1 connected")
        return True
    elif client == 2:
        Client2_conn.server_activation()
        print("Client 2 connected")
        return True

def dh_init():
    dh_pubkey = []
    dh_pbkey_c1 = DH_Algorithm_Client1.public_key_generator()
    dh_pbkey_c2 = DH_Algorithm_Client2.public_key_generator()
    while True:
        if len(dh_pubkey) == 0:
            dh_pubkey.append(Client1_conn.receiving())
            Client1_conn.sending(dh_pbkey_c1)
        elif len(dh_pubkey) == 1:
            dh_pubkey.append(Client2_conn.receiving())
            Client2_conn.sending(dh_pbkey_c2)
        elif len(dh_pubkey) == 2:
            dh_part_key_C1 = Client1_conn.receiving()
            dh_part_key_C2 = Client2_conn.receiving()
            Client1_conn.sending(dh_part_key_C2)
            Client2_conn.sending(dh_part_key_C1)
            dh_pubkey.append((dh_part_key_C1 + dh_part_key_C2))
        elif len(dh_pubkey) == 3:
            DH_Algorithm_Client1.private_key_generator(dh_pubkey[0])
            DH_Algorithm_Client2.private_key_generator(dh_pubkey[1])
            return True, False


def key_init():
    big_key_nonce = []
    if len(big_key_nonce) == 0:
        big_key_nonce.append(DH_Algorithm_Client1.decrypt(Client1_conn.receiving()))
        key_nonce_sum, key_nonce = KeyFile_Client1.get_big_key_nonce(0, big_key_nonce[0])
        if not File_Manipulation.file_integrity_check(key_nonce, key_nonce_sum):
            integrity_failed_closing_protocol("Integrity fail.")
        else:
            if data_check(key_nonce) == "ok":
                KeyFile_Client1.get_big_key_nonce(1, key_nonce)
    elif len(big_key_nonce) == 1:
        big_key_nonce.append(DH_Algorithm_Client2.decrypt(Client2_conn.receiving()))
        key_nonce_sum, key_nonce = KeyFile_Client2.get_big_key_nonce(0, big_key_nonce[0])
        if not File_Manipulation.file_integrity_check(key_nonce, key_nonce_sum):
            integrity_failed_closing_protocol("Integrity fail.")
        else:
            if data_check(key_nonce) == "ok":
                KeyFile_Client2.get_big_key_nonce(1, key_nonce)
    elif len(big_key_nonce) == 2:
        bkey_nonceC1 = DH_Algorithm_Client1.decrypt(Client1_conn.receiving())
        bkey_nonceC2 = DH_Algorithm_Client2.decrypt(Client2_conn.receiving())
        key_nonce_sumC1, key_nonceC1 = KeyFile_Client2.get_big_key_nonce(0, bkey_nonceC1)
        key_nonce_sumC2, key_nonceC2 = KeyFile_Client2.get_big_key_nonce(0, bkey_nonceC2)
        if not File_Manipulation.file_integrity_check(key_nonceC1, key_nonce_sumC1) or not File_Manipulation.file_integrity_check(key_nonceC2, key_nonce_sumC2):
            integrity_failed_closing_protocol("Integrity fail.")
        else:
            if data_check(key_nonceC1) == "ok" or data_check(key_nonceC2) == "ok":
                big_key_nonce.append((bkey_nonceC1 + bkey_nonceC2))
                Client1_conn.sending(bkey_nonceC2)
                Client2_conn.sending(bkey_nonceC1)
                return False

def receiving_sending_file(mode):
    keyfile_reload()
    if mode == 0:
        crypted_file = Client1_conn.receiving()
        AES_Encryption.update_data(crypted_file, KeyFile_Client1.key, KeyFile_Client1.nonce)
        file_sum, uncrypted_file = File_Manipulation.get_file_information(AES_Encryption.decrypt())
        if not File_Manipulation.file_integrity_check(uncrypted_file, file_sum):
            integrity_failed_closing_protocol("Integrity fail.")
        else:
            if data_check(uncrypted_file) == "ok":
                AES_Encryption.update_data(File_Manipulation.format_file(uncrypted_file, file_sum), KeyFile_Client2.key, KeyFile_Client2.nonce)
                Client2_conn.sending(AES_Encryption.encrypt())
    elif mode == 1:
        crypted_file = Client2_conn.receiving()
        AES_Encryption.update_data(crypted_file, KeyFile_Client2.key, KeyFile_Client2.nonce)
        file_sum, uncrypted_file = File_Manipulation.get_file_information(AES_Encryption.decrypt())
        if not File_Manipulation.file_integrity_check(uncrypted_file, file_sum):
            integrity_failed_closing_protocol("Integrity fail.")
        else:
            if data_check(uncrypted_file) == "ok":
                AES_Encryption.update_data(File_Manipulation.format_file(uncrypted_file, file_sum), KeyFile_Client1.key, KeyFile_Client1.nonce)
                Client1_conn.sending(AES_Encryption.encrypt())
def data_check(data):
    if data == "ping":
        ping_or_pong("pong")
    elif data == "Integrity fail.":
        total_disconnection()
    else:
        return "ok"

def ping_or_pong(ping_pong):
    keyfile_reload()
    formatted_ping = File_Manipulation.SHA512_checksum_creation(ping_pong) + File_Manipulation.delimiter2 + ping_pong
    AES_Encryption.update_data(formatted_ping, KeyFile_Client1.key, KeyFile_Client1.nonce)
    Client1_conn.sending(AES_Encryption.encrypt())
    AES_Encryption.update_data(formatted_ping, KeyFile_Client2.key, KeyFile_Client2.nonce)
    Client2_conn.sending(AES_Encryption.encrypt())
    if ping_pong == "ping":
        ping_check()

def ping_check():
    keyfile_reload()
    received_data1 = Client1_conn.receiving()
    received_data2 = Client2_conn.receiving()
    AES_Encryption.update_data(received_data1, KeyFile_Client1.key, KeyFile_Client1.nonce)
    decrypted_data1 = AES_Encryption.decrypt().split(File_Manipulation.delimiter2)
    AES_Encryption.update_data(received_data2, KeyFile_Client2.key, KeyFile_Client2.nonce)
    decrypted_data2 = AES_Encryption.decrypt().split(File_Manipulation.delimiter2)
    if not File_Manipulation.file_integrity_check(decrypted_data1[1], decrypted_data1[0]) or not File_Manipulation.file_integrity_check(decrypted_data2[1], decrypted_data2[0]):
        integrity_failed_closing_protocol("Integrity fail.")
    else:
        if decrypted_data1[1] == "Integrity fail." or decrypted_data2[1] == "Integrity fail.":
            total_disconnection()
        elif decrypted_data1[1] != "pong" or decrypted_data2[1] != "pong":
            integrity_failed_closing_protocol("Ping check failed.")

def keyfile_reload():
    global key_initialised
    # Reset File_manipulation init
    File_Manipulation.reset_init()
    # Verify length of nonce and key and take one nonce for each objects
    if not KeyFile_Client1.key_nonce_length_check() or not KeyFile_Client2.key_nonce_length_check():
        key_initialised = False
    KeyFile_Client1.nonce_choice()
    KeyFile_Client2.nonce_choice()

def integrity_failed_closing_protocol(error):
    keyfile_reload(1)
    AES_Encryption.update_data((File_Manipulation.SHA512_checksum_creation(error) + File_Manipulation.delimiter + error), KeyFile_Client1.key, KeyFile_Client1.nonce)
    Client1_conn.sending(AES_Encryption.encrypt())
    AES_Encryption.update_data((File_Manipulation.SHA512_checksum_creation(error) + File_Manipulation.delimiter + error), KeyFile_Client2.key, KeyFile_Client2.nonce)
    Client2_conn.sending(AES_Encryption.encrypt())
    total_disconnection()
    print("contacting an administrator..")

def total_disconnection():
    global danger
    Client1_conn.disconnecting()
    Client2_conn.disconnecting()
    danger = True

while not danger:
    if not c1_connected:
        c1_connected = conn_s(1)
    elif not c2_connected:
        c2_connected = conn_s(2)
    else:
        if not dh_initialised:  # Initialise DH_algo key creation / send
            dh_initialised, key_initialised = dh_init()
        elif not key_initialised:  # Initialise Key creation / send
            key_initialised = key_init()
        else:
            if receiving_sending_mode == 0:
                receiving_sending_file(receiving_sending_mode)
                receiving_sending_mode = 1
            elif receiving_sending_mode == 1:
                receiving_sending_file(receiving_sending_mode)
                receiving_sending_mode = 0
