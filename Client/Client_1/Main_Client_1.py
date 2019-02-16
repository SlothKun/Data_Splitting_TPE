import Objects_Client
import pprint


#while True:

def dump(obj):
  for attr in dir(obj):
    print("obj.%s = %r" % (attr, getattr(obj, attr)))

meh = Objects_Client.DH_algorithm()
print(meh.public_key_generator())



'''
    Change Client object : 1 object per conn, it'll help in many many things
    need to adapt Client function too and __init__
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
don't forget to send tag when send data

serverobj = Client()
file = File()

file.ask_file()
file.split_file()
file.reassemble_file()
file.SHA512_checksum_creation()
file1, file2 = file.format_file()
print(file1)
print(file2)

file.get_file_information(file1, file2)
print("-------")
print(file.file_sum)
file.file_integrity_check(file.uncrypted_full_file, file.file_sum)

pif = crypto.encrypt()
print("èèèèèèèèèèèèèèèèèèèèèèèèèèèèèèèèèèèèèè")
print(pif)

while False:
    serverobj.client_activation(serverobj.serverhost1, serverobj.port_listening)
    serverobj.connected = False
    serverobj.client_activation(serverobj.serverhost2, serverobj.port_listening2)
    serverobj.sending()
    serverobj.receiving()
    
    '''