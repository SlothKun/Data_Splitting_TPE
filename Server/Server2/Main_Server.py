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

sleep(3)  # We wait 3 sec before doing something, to maintain relative sync

print("-------- CONN PHASE : START --------")
print("----- CONN C2 : START -----")
while not c2_connected:
    c2_connected = Client2_conn.server_activation()
print("Connected to Client 2 !")
print("----- CONN C2 : END -----")

print("----- CONN C1 : START -----")
while not c1_connected:
    c1_connected = Client1_conn.server_activation()
print("Connected to Client 1 !")
print("----- CONN C1 : END -----")
print("-------- CONN PHASE : END --------")



print("-------- DH INIT : START --------")
print("----- DH INIT C2 : START -----")
while not dh_c2_status:
    DH_Algorithm_Client2.public_key_generator()
    print("S2 key : ", DH_Algorithm_Client2.public_key)
    friendkey = Client2_conn.receiving(0)
    print("C2 key : ", friendkey)
    Client2_conn.sending(DH_Algorithm_Client2.public_key, 0)
    DH_Algorithm_Client2.private_key_generator(friendkey)
    print("common key : ", DH_Algorithm_Client2.private_key)
    dh_c2_status = True
print("----- DH INIT C2 : END -----")

print("----- DH INIT C1 : START -----")
while not dh_c1_status:
    DH_Algorithm_Client1.public_key_generator()
    print("S2 key : ", DH_Algorithm_Client1.public_key)
    friendkey = Client1_conn.receiving(0)
    print("C1 key : ", friendkey)
    Client1_conn.sending(DH_Algorithm_Client1.public_key, 0)
    DH_Algorithm_Client1.private_key_generator(friendkey)
    print("common key : ", DH_Algorithm_Client1.private_key)
    dh_c1_status = True
print("----- DH INIT C1 : END -----")

print("----- DH INIT C : START -----")
while not dh_c_status:
    friendkey = Client1_conn.receiving(0)
    print("C1 part key : ", friendkey)
    Client2_conn.sending(friendkey, 0)
    friendkey = Client2_conn.receiving(0)
    print("C2 part key : ", friendkey)
    Client1_conn.sending(friendkey, 0)
    dh_c_status = True
print("----- DH INIT C : END -----")
print("-------- DH INIT : END --------")



print("-------- KEY INIT : START --------")
print("----- KEY INIT C2 : START -----")
while not key_c2_status:
    f_cryptedbigkeynonce = Client2_conn.receiving(1)
    print("f_cryptedbigkeynonce : ", f_cryptedbigkeynonce[:15])
    cryptedbigkeynonce, tag, nonce = KeyFile_Client2.get_big_key_nonce(0, f_cryptedbigkeynonce)
    bigkeynonce_and_sum = DH_Algorithm_Client2.decrypt(cryptedbigkeynonce, tag, nonce)
    bigkeynonce_sum, bigkeynonce = KeyFile_Client2.get_big_key_nonce(1, bigkeynonce_and_sum)
    print("bigkeynonce sum : ", bigkeynonce_sum)
    print("start of bigkeynonce : ", bigkeynonce[:15])
    if File_Manipulation.file_integrity_check(bigkeynonce, bigkeynonce_sum) == False:
        key_c2_status = True
    else:
        KeyFile_Client2.get_big_key_nonce(2, bigkeynonce)
        KeyFile_Client2.key_choice()
        key_c2_status = True
print("----- KEY INIT C2 : END -----")

print("----- KEY INIT C1 : START -----")
while not key_c1_status:
    f_cryptedbigkeynonce = Client1_conn.receiving(1)
    print("f_cryptedbigkeynonce : ", f_cryptedbigkeynonce[:15])
    cryptedbigkeynonce, tag, nonce = KeyFile_Client1.get_big_key_nonce(0, f_cryptedbigkeynonce)
    bigkeynonce_and_sum = DH_Algorithm_Client1.decrypt(cryptedbigkeynonce, tag, nonce)
    bigkeynonce_sum, bigkeynonce = KeyFile_Client1.get_big_key_nonce(1, bigkeynonce_and_sum)
    print("bigkeynonce sum : ", bigkeynonce_sum)
    print("start of bigkeynonce : ", bigkeynonce[:15])
    if File_Manipulation.file_integrity_check(bigkeynonce, bigkeynonce_sum) == False:
        key_c1_status = True
    else:
        KeyFile_Client1.get_big_key_nonce(2, bigkeynonce)
        KeyFile_Client1.key_choice()
        key_c1_status = True
print("----- KEY INIT C1 : END -----")

print("----- KEY INIT C1 SENDER : START -----")
while not key_c1_sender_status:
    print("receiving..")
    f_cryptedbigkeynonce = Client1_conn.receiving(1)
    print("received ! send..")
    Client2_conn.sending(f_cryptedbigkeynonce, 1)
    print("sent !")
    key_c1_sender_status = True
print("----- KEY INIT C1 SENDER : END -----")

print("----- KEY INIT C2 SENDER : START -----")
while not key_c2_sender_status:
    print("receiving..")
    f_cryptedbigkeynonce = Client2_conn.receiving(1)
    print("received ! send..")
    Client1_conn.sending(f_cryptedbigkeynonce, 1)
    print("sent !")
    key_c2_sender_status = True
print("----- KEY INIT C2 SENDER : END -----")
print("-------- KEY INIT : END --------")

