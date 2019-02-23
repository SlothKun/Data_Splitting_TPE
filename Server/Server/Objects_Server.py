import socket
import select
import string
import random
import re
import os
import pathlib
import hashlib
import rstr
import tkinter
import tkinter.filedialog
import pyDH
from Crypto.Cipher import AES
from Crypto import Random

class Server:
    def __init__(self):
        self.host = '127.0.0.1'
        self.port_listening = 6801
        self.whitelisted_client = ["172.16.1.42", "127.0.0.1", "192.168.0.33", "192.168.0.34", "172.16.1.19"]
        self.socket = ""
        self.message_content = b""

    def server_activation(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port_listening))
        s.listen()
        self.establishing_conn(s)

    def establishing_conn(self, sock):
        try:
            clientconnect, clientinfo = sock.accept()
            self.socket = sock
            ip, port = clientconnect.getpeername()
            if ip in self.whitelisted_client:  # Whitelist application
                print(ip, " is connected on port : ", port)
            else:
                print("This client isn't whitelisted")
                print("Closing connection..")
                sock.close()
                self.server_activation()
        except (ConnectionRefusedError, OSError):
            self.server_activation()

    def disconnecting(self):
        self.socket.close()

    def receiving(self):
        try:
            client_to_read, wlist, xlist = select.select([self.socket], [], [], 0.05)
        except select.error:  # avoid error if there's no one to read
            pass
        else:
            self.message_content = b""
            self.message_content = self.socket.recv(16777216)
            if self.message_content.decode() == "":
                self.receiving()
            else:
                return self.message_content.decode()

    def sending(self, data):
        self.socket.sendall(str(data).encode())


class File:
    def __init__(self):
        self.delimiter = "#&_#"

    def get_file_information(self, file):
        cuted_file = file.split(self.delimiter)
        return cuted_file[0], cuted_file[1]

    def format_file(self, data, sum):
        return sum + self.delimiter + data

    def SHA512_checksum_creation(self, file):
        return hashlib.sha512(file).hexdigest()

    def file_integrity_check(self, data, sum):
        if hashlib.sha512(data).hexdigest() == sum:
            return True
        else:
            return False


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

    def encrypt(self, data):
        cipher = AES.new(self.private_key.encode(), AES.MODE_OCB)
        crypted_key, tag = cipher.encrypt_and_digest(data)
        return crypted_key

    def decrypt(self, data):
        cipher = AES.new(self.private_key.encode(), AES.MODE_OCB)
        uncrypted_key = cipher.decrypt(data)
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
        self.delimiter1 = "([-_])"
        self.delimiter2 = ")-_-_("

    def key_nonce_length_check(self):
        if len(self.big_key_modified) == 32:
            return False
        elif len(self.big_nonce_modified) <= 512:
            self.key_choice()
            self.big_nonce_modified = self.big_nonce_original

     # /!\ MODIFIER LE NONCE ET LE KEY CHOICE /!\
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
    # /!\ MODIFIER LE NONCE ET LE KEY CHOICE /!\

    def get_big_key_nonce(self, mode, data):
        if mode == 0:
            splitted_data = data.split(self.delimiter2)
            checksum = splitted_data[0]
            key_nonce = splitted_data[1]
            return checksum, key_nonce
        elif mode == 1:
            data_splitted = data.split(self.delimiter1)
            self.big_key_original = data_splitted[0]
            self.big_key_modified = self.big_key_original
            self.big_nonce_original = data_splitted[1]
            self.big_nonce_modified = self.big_nonce_original


class AES_Algorithm:
    def __init__(self):
        self.data = ""
        self.key = ""
        self.nonce = ""

    def update_data(self, data, key, nonce):
        self.data = data
        self.key = key
        self.nonce = nonce

    def encrypt(self):
        cipher = AES.new(self.key.encode(), AES.MODE_OCB, nonce=self.nonce)
        crypted_data, tag = cipher.encrypt_and_digest(self.data)
        return crypted_data

    def decrypt(self):
        cipher = AES.new(self.key.encode(), AES.MODE_OCB, nonce=self.nonce)
        uncrypted_data = cipher.decrypt(self.data)
        return uncrypted_data
