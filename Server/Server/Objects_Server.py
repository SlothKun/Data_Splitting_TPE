import socket
import select
import string
import random
import re
import pathlib
import os
import hashlib
import tkinter
import tkinter.filedialog
import rstr
import pyDH
from Crypto.Cipher import AES
from Crypto import Random



class Server:
    def __init__(self):
        self.host = '127.0.0.1'
        self.port_listening = 6800
        self.whitelisted_client = ["127.0.0.1"]
        self.socket = ""
        self.message_content = b""
        self.init = False

    def server_activation(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port_listening))
        s.listen(2)
        self.etablishing_conn(s)

    def etablishing_conn(self, sock):
        clientconnect, clientinfo = sock.accept()
        self.socket = sock
        ip, port = clientconnect.getpeername()
        if ip in self.whitelisted_client:  # Whitelist application
            self.connected_client.append(clientconnect)
            print(ip, " is connected on port ", port)
        else:
            print("This client isn't whitelisted")
            print("Closing connection..")
            sock.close()

    def receiving(self):
        try:
            client_to_read, wlist, xlist = select.select(self.connected_client, [], [], 0.05)
        except select.error:  # avoid error if there's no one to read
            pass
        else:
            message_content = self.socket.recv(16777216)
            self.answer()

    def answer(self):
        if self.message_content.decode() == "ping":
            self.socket.sendall(b"pong")
        elif self.message_content.decode() == "received":
            pass
        elif self.message_content.decode() == "init":
            self.socket.sendall(b"received")
            self.init = True
        elif self.message_content.decode() == "tini":
            self.socket.sendall(b"received")
            self.init = False
        else:
            self.socket.sendall(b"received")
            return self.message_content.decode()

    def sending(self, *datas):
        file = ""
        for data in datas:
            file += str(data)
        self.socket.sendall(file.encode())

    def ping(self):  # send ping to verify if server is ok
        self.socket.sendall(b"ping")
        self.ping_check()

    def ping_check(self):  # verify if server answer to the ping, if not, he closes conn
        msg_received = self.socket.recv(2048)
        if msg_received.decode() != "pong":
            print("The client ", self.socket, " didn't answer to the ping correctly. disconnection to the client..")
            self.socket.sendall(b"Wrong!")
            self.socket.close()

class File:
    def __init__(self):
        self.received_data = ""
        self.file_sum = ""
        self.delimiter = b"#&_#"

    def get_file_information(self, file):
        self.received_data = file.decode()
        self.file_sum = file.split(self.delimiter)[1]

    def file_integrity_check(self):  # Simply compare the actual file sum with given sum
        if hashlib.sha512(self.received_data).hexdigest() == self.file_sum:
            print("integrity check")
        else:
            print("INTEGRITY FAILED ! ABORT ! ABORT !")


class DH_algorithm:
    def __init__(self):
        self.engine = ""
        self.public_key = ""
        self.private_key = ""

    def public_key_generator(self):
        self.engine = pyDH.DiffieHellman()
        self.public_key = self.engine.gen_public_key()
        return self.public_key

    def private_key_generator(self, friendkey):
        self.private_key = self.engine.gen_shared_key(int(friendkey))

    def encrypt(self, key_to_encrypt):
        cipher = AES.new(self.private_key.encode(), AES.MODE_OCB)
        crypted_key, tag = cipher.encrypt_and_digest(key_to_encrypt)
        return crypted_key, tag

    def decrypt(self, crypted_key, tag):
        cipher = AES.new(self.private_key.encode(), AES.MODE_OCB)
        uncrypted_key = cipher.decrypt_and_verify(crypted_key, tag)
        return uncrypted_key


class Key:
    def __init__(self):
        self.big_key_original = ""
        self.big_nonce_original = ""
        self.big_key_modified = ""
        self.big_nonce_modified = ""
        self.key = ""
        self.nonce = ""
        self.n_choice = 0
        self.k_choice = 0
        self.delimiter = b"([-_])"

    def big_key_nonce_generator(self):  # Create a big key and a big nonce
        self.big_key_original = rstr.rstr('azertyuiopmlkjhgfdsqwxcvbnAZERTYUIOPMLKJHGFDSQWXCVBN0123456789', 64000)
        self.big_key_modified = self.big_key_original
        self.big_nonce_original = rstr.rstr('azertyuiopmlkjhgfdsqwxcvbnAZERTYUIOPMLKJHGFDSQWXCVBN0123456789', 64000)
        self.big_nonce_modified = self.big_nonce_original
        return self.big_key_original, self.big_nonce_original

    def key_nonce_length_check(self):
        if len(self.big_nonce_modified) <= 128:
            self.key_choice()
            self.big_nonce_modified = self.big_nonce_original
        elif len(self.big_key_modified) <= 64:
            self.big_key_nonce_generator()
            print("NEED RENVOI KEY")

    def nonce_choice(self):
        if self.n_choice == 0:
            self.n_choice = 1
            self.nonce = self.big_nonce_modified[-128:-64]
        elif self.n_choice == 1:
            self.n_choice = 2
            self.nonce = self.big_nonce_modified[:-64]
        elif self.n_choice == 2:
            self.n_choice = 0
            self.nonce = self.big_nonce_modified[64:]

    def key_choice(self):
        if self.k_choice == 0:
            self.k_choice = 1
            self.key = self.big_key_modified[-32:]
        elif self.k_choice == 1:
            self.k_choice = 2
            self.key = self.big_key_modified[:32]
        elif self.k_choice == 2:
            self.k_choice = 0
            self.key = self.big_key_modified[-64:-32]

    def big_key_nonce_format(self):
        formatted = self.big_key_original + self.delimiter + self.big_nonce_original
        return formatted

    def get_big_key_nonce(self, data):
        self.big_key_original = data.split(self.delimiter)[0]
        self.big_nonce_original = data.split(self.delimiter)[1]
        if data.split(self.delimiter)[2] != None:
            return data


class AES_Algorithm:
    def __init__(self):
        self.data = ""
        self.key = ""
        self.nonce = ""
        self.tag = ""

    def update_data(self, data, key, nonce, tag):
        self.data = data
        self.key = key
        self.nonce = nonce
        self.tag = tag

    def encrypt(self):
        cipher = AES.new(self.key.encode(), AES.MODE_OCB, nonce=self.nonce)
        crypted_data, tag = cipher.encrypt_and_digest(self.data)
        return crypted_data, tag

    def decrypt(self):
        cipher = AES.new(self.key.encode(), AES.MODE_OCB, nonce=self.nonce)
        uncrypted_data = cipher.decrypt_and_verify(self.crypted_full_file, self.tag)
        return uncrypted_data
