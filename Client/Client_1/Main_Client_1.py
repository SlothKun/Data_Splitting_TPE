import Objects_Client

# Create Conn Objects
Server1_conn = Objects_Client.Client('127.0.0.1', 80)
Server2_conn = Objects_Client.Client('127.0.0.1', 6799)

# Create DH_algo Objects
DH_Algorithm_Server1 = Objects_Client.DH_algorithm()
DH_Algorithm_Server2 = Objects_Client.DH_algorithm()
DH_Algorithm_Client = Objects_Client.DH_algorithm()

# Create Key Objects
KeyFile_Server1 = Objects_Client.Key()
KeyFile_Server2 = Objects_Client.Key()
KeyFile_Client = Objects_Client.Key()

# Create File and AES objects
AES_Encrypt = Objects_Client.AES_Algorithm()
File_Manipulation = Objects_Client.File()

# Create some variable
my_turn = False
S1_connected = True
S2_connected = True
DH_initialised = False
Key_initialised = False
DH_PubKey = []
Big_key_nonce = []

# Create function to clear the code
def Conn_S(server):
    if server == 1:
        Server1_conn.client_activation()
        print("Server 1 connected")
    elif server == 2:
        Server2_conn.client_activation()
        print("Server 2 connected")

def DH_init():
    DH_PbKey_S1 = DH_Algorithm_Server1.public_key_generator()
    DH_PbKey_S2 = DH_Algorithm_Server2.public_key_generator()
    DH_PbKey_C = DH_Algorithm_Client.public_key_generator()
    if len(DH_PubKey) == 0:
        Server1_conn.sending(DH_PbKey_S1)
        DH_PubKey.append(Server1_conn.receiving())
    elif len(DH_PubKey) == 1:
        Server2_conn.sending(DH_PbKey_S2)
        DH_PubKey.append(Server2_conn.receiving())
    elif len(DH_PubKey) == 2:
        part1, part2 = File_Manipulation.split_file(DH_PbKey_C)
        Server1_conn.sending(part1)
        Server2_conn.sending(part2)
        DH_PubKey.append((Server1_conn.receiving() + Server2_conn.receiving()))
    elif len(DH_PubKey) == 3:
        DH_Algorithm_Server1.private_key_generator(DH_PubKey[0])
        DH_Algorithm_Server2.private_key_generator(DH_PubKey[1])
        DH_Algorithm_Client.private_key_generator(DH_PubKey[2])
        DH_PubKey.clear()
        DH_initialised = False
        Key_initialised = True

def Key_init():
    if len(Big_key_nonce) == 0:
        KeyFile_Server1.big_key_nonce_generator()
        KeyFile_Server1.key_choice()
        Big_key_nonce.append(KeyFile_Server1.big_key_nonce_format())
        format_sum = File_Manipulation.SHA512_checksum_creation(Big_key_nonce[0])
        Server1_conn.sending(DH_Algorithm_Server1.encrypt((format_sum + Big_key_nonce[0])))
    elif len(Big_key_nonce) == 1:
        KeyFile_Server2.big_key_nonce_generator()
        KeyFile_Server2.key_choice()
        Big_key_nonce.append(KeyFile_Server2.big_key_nonce_format())
        format_sum = File_Manipulation.SHA512_checksum_creation(Big_key_nonce[1])
        Server2_conn.sending(DH_Algorithm_Server2.encrypt((format_sum + Big_key_nonce[1])))
    elif len(Big_key_nonce) == 2:
        KeyFile_Client.big_key_nonce_generator()
        KeyFile_Client.key_choice()
        Big_key_nonce.append(KeyFile_Client.big_key_nonce_format())
        full_file = File_Manipulation.SHA512_checksum_creation(Big_key_nonce[2]) + Big_key_nonce[2]
        part1, part2 = File_Manipulation.split_file(full_file)
        part1_sum = File_Manipulation.SHA512_checksum_creation(part1)
        part2_sum = File_Manipulation.SHA512_checksum_creation(part2)
        Server1_conn.sending(DH_Algorithm_Client.encrypt((part1_sum + "([-_])" + part1)))
        Server2_conn.sending(DH_Algorithm_Client.encrypt((part2_sum + "([-_])" + part2)))
    elif len(Big_key_nonce) == 3:
        Big_key_nonce.clear()
        Key_initialised = False

def Sending_file():

def Receiving_file():
i=0
while True:
    if not S1_connected:
        Conn_S(1)
    elif not S2_connected:
        Conn_S(2)
    else:
        if DH_initialised == True:  # Initialise DH_algo key creation / send
            DH_init()
        elif Key_initialised == True:  # Initialise Key creation / send
            Key_init()
        else:
            if my_turn:
                Sending_file()
            else:
                Receiving_file()
