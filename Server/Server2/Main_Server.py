import Objects_Server
from time import sleep

# Create Conn Objects
Client1_conn = Objects_Server.Server("127.0.0.1", 6801)
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
dh_c1_status = False
dh_c2_status = False
dh_c_status = False
key_c1_status = False
key_c2_status = False
key_c1_sender_status = False
key_c2_sender_status = False
c1_complete = False
c2_complete = True

sleep(3)  # We wait 3 sec before doing something, to maintain relative sync

print("-------- CONN PHASE : START --------")
print("----- CONN C2 : START -----")
while not c2_connected:
    c2_connected = Client2_conn.server_activation()
print("state of c2_connected : ", c2_connected)
print("Connected to Client 2 !")
print("----- CONN C2 : END -----")

print("")

print("----- CONN C1 : START -----")
while not c1_connected:
    c1_connected = Client1_conn.server_activation()
print("state of c1_connected : ", c1_connected)
print("Connected to Client 1 !")
print("----- CONN C1 : END -----")
print("-------- CONN PHASE : END --------")

print("")
print("")

print("-------- DH INIT : START --------")
print("----- DH INIT C2 : START -----")
while not dh_c2_status:
    DH_Algorithm_Client2.public_key_generator()
    print("S2 to C2 key : ", str(DH_Algorithm_Client2.public_key)[:15])
    print("S2 to C2 key len : ", len(str(DH_Algorithm_Client2.public_key)))
    friendkey = Client2_conn.receiving(0)
    print("C2 to S2 key : ", friendkey[:15])
    print("C2 to S2 key len : ", len(friendkey))
    Client2_conn.sending(DH_Algorithm_Client2.public_key, 0)
    DH_Algorithm_Client2.private_key_generator(friendkey)
    print("common key : ", DH_Algorithm_Client2.private_key[:15])
    print("common key len : ", len(DH_Algorithm_Client2.private_key))
    dh_c2_status = True
    print("dh_c2_status : ", dh_c2_status)
print("----- DH INIT C2 : END -----")

print("")

print("----- DH INIT C1 : START -----")
while not dh_c1_status:
    DH_Algorithm_Client1.public_key_generator()
    print("S2 key : ", str(DH_Algorithm_Client1.public_key)[:15])
    print("S2 key : ", len(str(DH_Algorithm_Client1.public_key)))
    friendkey = Client1_conn.receiving(0)
    print("C1 key : ", friendkey[:15])
    print("C1 key len : ", len(friendkey))
    Client1_conn.sending(DH_Algorithm_Client1.public_key, 0)
    DH_Algorithm_Client1.private_key_generator(friendkey)
    print("common key : ", DH_Algorithm_Client1.private_key[:15])
    print("common key len : ", len(DH_Algorithm_Client1.private_key))
    dh_c1_status = True
    print("dh_c1_status : ", dh_c1_status)
print("----- DH INIT C1 : END -----")

print("")

print("----- DH INIT C : START -----")
while not dh_c_status:
    friendkey = Client1_conn.receiving(0)
    print("C1 part key : ", friendkey[:15])
    print("C1 part key len : ", len(friendkey))
    Client2_conn.sending(friendkey, 0)
    friendkey = Client2_conn.receiving(0)
    print("C2 part key : ", friendkey[:15])
    print("C2 part key len : ", len(friendkey))
    Client1_conn.sending(friendkey, 0)
    dh_c_status = True
    print("dh_c_status : ", dh_c_status)
print("----- DH INIT C : END -----")
print("-------- DH INIT : END --------")

print("")
print("")

print("-------- KEY INIT : START --------")
print("----- KEY INIT C2 : START -----")
while not key_c2_status:
    f_cryptedbigkeynonce = Client2_conn.receiving(1)
    print("f_cryptedbigkeynonce : ", f_cryptedbigkeynonce[:15])
    print("f_cryptedbigkeynonce len: ", len(f_cryptedbigkeynonce))
    cryptedbigkeynonce, tag, nonce = KeyFile_Client2.get_big_key_nonce(0, f_cryptedbigkeynonce)
    print("cbkn : ", cryptedbigkeynonce[:15])
    print("cbkn len : ", len(cryptedbigkeynonce))
    print("ckn_tag : ", tag)
    print("ckn_nonce : ", nonce)
    bigkeynonce_and_sum = DH_Algorithm_Client2.decrypt(cryptedbigkeynonce, tag, nonce)
    print("bigkeynonce_and_sum : ", bigkeynonce_and_sum[:15])
    print("bigkeynonce_and_sum : ", len(bigkeynonce_and_sum))
    bigkeynonce_sum, bigkeynonce = KeyFile_Client2.get_big_key_nonce(1, bigkeynonce_and_sum)
    print("bigkeynonce sum : ", bigkeynonce_sum)
    print("start of bigkeynonce : ", bigkeynonce[:15])
    print("start of bigkeynonce len : ", len(bigkeynonce))
    if File_Manipulation.file_integrity_check(bigkeynonce, bigkeynonce_sum) == False:
        key_c2_status = True
    else:
        KeyFile_Client2.get_big_key_nonce(2, bigkeynonce)
        KeyFile_Client2.key_choice()
        key_c2_status = True
        print("key_c2_status : ", key_c2_status)
print("----- KEY INIT C2 : END -----")

print("")

print("----- KEY INIT C1 : START -----")
while not key_c1_status:
    f_cryptedbigkeynonce = Client1_conn.receiving(1)
    print("f_cryptedbigkeynonce : ", f_cryptedbigkeynonce[:15])
    print("f_cryptedbigkeynonce len: ", len(f_cryptedbigkeynonce))
    cryptedbigkeynonce, tag, nonce = KeyFile_Client1.get_big_key_nonce(0, f_cryptedbigkeynonce)
    print("cbkn : ", cryptedbigkeynonce[:15])
    print("cbkn len : ", len(cryptedbigkeynonce))
    print("ckn_tag : ", tag)
    print("ckn_nonce : ", nonce)
    bigkeynonce_and_sum = DH_Algorithm_Client1.decrypt(cryptedbigkeynonce, tag, nonce)
    print("bigkeynonce_and_sum : ", bigkeynonce_and_sum[:15])
    print("bigkeynonce_and_sum : ", len(bigkeynonce_and_sum))
    bigkeynonce_sum, bigkeynonce = KeyFile_Client1.get_big_key_nonce(1, bigkeynonce_and_sum)
    print("bigkeynonce sum : ", bigkeynonce_sum)
    print("start of bigkeynonce : ", bigkeynonce[:15])
    print("start of bigkeynonce len : ", len(bigkeynonce))
    if File_Manipulation.file_integrity_check(bigkeynonce, bigkeynonce_sum) == False:
        key_c1_status = True
    else:
        KeyFile_Client1.get_big_key_nonce(2, bigkeynonce)
        KeyFile_Client1.key_choice()
        key_c1_status = True
        print("key_c1_status : ", key_c1_status)
print("----- KEY INIT C1 : END -----")

print("")

print("----- KEY INIT C1 SENDER : START -----")
while not key_c1_sender_status:
    print("receiving..")
    f_cryptedbigkeynonce = Client1_conn.receiving(1)
    print("f_cryptedbigkeynonce : ", f_cryptedbigkeynonce[:15])
    print("f_cryptedbigkeynonce len : ", len(f_cryptedbigkeynonce))
    print("received ! send..")
    Client2_conn.sending(f_cryptedbigkeynonce, 1)
    print("sent !")
    key_c1_sender_status = True
    print("key_c1_sender_status : ", key_c1_sender_status)
print("----- KEY INIT C1 SENDER : END -----")

print("")

print("----- KEY INIT C2 SENDER : START -----")
while not key_c2_sender_status:
    print("receiving..")
    f_cryptedbigkeynonce = Client2_conn.receiving(1)
    print("f_cryptedbigkeynonce : ", f_cryptedbigkeynonce[:15])
    print("f_cryptedbigkeynonce len : ", len(f_cryptedbigkeynonce))
    print("received ! send..")
    Client1_conn.sending(f_cryptedbigkeynonce, 1)
    print("sent !")
    key_c2_sender_status = True
    print("key_c2_sender_status : ", key_c2_sender_status)
print("----- KEY INIT C2 SENDER : END -----")
print("-------- KEY INIT : END --------")

print("")
print("")

print("-------- SENDING/RECEIVING FILE : START --------")
print("----- C1 SENDING FILE : START -----")
while not c1_complete:
    KeyFile_Client1.key_nonce_reload()
    KeyFile_Client2.key_nonce_reload()
    f_cryptedfile = Client1_conn.receiving(1)
    print("f_cryptedfile : ", f_cryptedfile[:15])
    print("f_cryptedfile len : ", len(f_cryptedfile))
    tag, cryptedfile = File_Manipulation.get_file_information(1, f_cryptedfile)
    print("cryptedfile : ", cryptedfile[:15])
    print("cryptedfile len : ", len(cryptedfile))
    print("tag : ", tag)
    AES_Encryption.update_data(cryptedfile, KeyFile_Client1.key, KeyFile_Client1.nonce, tag)
    full_file = AES_Encryption.decrypt()
    print("full file : ", full_file[:15])
    print("full file len : ", len(full_file))
    file_sum, file = File_Manipulation.get_file_information(0, full_file)
    print("file : ", file[:15])
    print("file len : ", len(file))
    print("file sum : ", file_sum)
    if not File_Manipulation.file_integrity_check(file, file_sum):
        danger = True
        print("DANGER OVER HERE")
    else:
        AES_Encryption.update_data(full_file, KeyFile_Client2.key, KeyFile_Client2.nonce, "")
        cryptedfile, tag = AES_Encryption.encrypt()
        print("cryptedfile : ", cryptedfile[:15])
        print("cryptedfile len : ", len(cryptedfile))
        print("tag : ", tag)
        f_cryptedfile = File_Manipulation.format_file(cryptedfile, tag)
        print("f_cryptedfile : ", f_cryptedfile[:15])
        print("f_cryptedfile len : ", len(f_cryptedfile))
        Client2_conn.sending(f_cryptedfile, 1)
        c1_complete = True
        c2_complete = False
        print("C1_complete : ", c1_complete)
        print("C2_complete : ", c2_complete)
print("----- C1 SENDING FILE : END -----")

print("")

print("----- C2 SENDING FILE : START -----")
while not c2_complete:
    KeyFile_Client1.key_nonce_reload()
    KeyFile_Client2.key_nonce_reload()
    f_cryptedfile = Client2_conn.receiving(1)
    print("f_cryptedfile : ", f_cryptedfile[:15])
    print("f_cryptedfile len : ", len(f_cryptedfile))
    tag, cryptedfile = File_Manipulation.get_file_information(1, f_cryptedfile)
    print("cryptedfile : ", cryptedfile[:15])
    print("cryptedfile len : ", len(cryptedfile))
    print("tag : ", tag)
    AES_Encryption.update_data(cryptedfile, KeyFile_Client2.key, KeyFile_Client2.nonce, tag)
    full_file = AES_Encryption.decrypt()
    print("full file : ", full_file[:15])
    print("full file len : ", len(full_file))
    file_sum, file = File_Manipulation.get_file_information(0, full_file)
    print("file : ", file[:15])
    print("file len : ", len(file))
    print("file sum : ", file_sum)
    if not File_Manipulation.file_integrity_check(file, file_sum):
        danger = True
        print("DANGER OVER HERE")
    else:
        AES_Encryption.update_data(full_file, KeyFile_Client1.key, KeyFile_Client1.nonce, "")
        cryptedfile, tag = AES_Encryption.encrypt()
        print("cryptedfile : ", cryptedfile[:15])
        print("cryptedfile len : ", len(cryptedfile))
        print("tag : ", tag)
        f_cryptedfile = File_Manipulation.format_file(cryptedfile, tag)
        print("f_cryptedfile : ", f_cryptedfile[:15])
        print("f_cryptedfile len : ", len(f_cryptedfile))
        Client1_conn.sending(f_cryptedfile, 1)
        c1_complete = False
        c2_complete = True
        print("C1_complete : ", c1_complete)
        print("C2_complete : ", c2_complete)
print("----- C2 SENDING FILE : END -----")
print("-------- SENDING/RECEIVING FILE : END --------")