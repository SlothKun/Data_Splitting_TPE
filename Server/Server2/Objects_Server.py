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
import asyncio

class Server:
    def __init__(self, host, port_listening):
        self.host = host
        self.port_listening = port_listening
        self.whitelisted_client = ["172.16.1.42", "127.0.0.1", "192.168.0.33", "192.168.0.34", "172.16.1.19"]
        self.socket = ""
        self.message_content = b""

    def server_activation(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port_listening))
        s.listen()
        return self.establishing_conn(s)

    def establishing_conn(self, sock):
        try:
            print("in function")
            clientconnect, clientinfo = sock.accept()
            self.socket = clientconnect
            ip, port = clientconnect.getpeername()
            if ip in self.whitelisted_client:  # Whitelist application
                self.socket.send(b"ok")
                print(ip, " is connected on port : ", port)
                return True
            else:
                print("This client isn't whitelisted")
                print("Closing connection..")
                sock.close()
                self.server_activation()
        except (ConnectionRefusedError, OSError):
            self.server_activation()

    def disconnecting(self):
        self.socket.close()

    def receiving(self, mode):
        while True:
            try:
                try:
                    client_to_read, wlist, xlist = select.select([self.socket], [], [], 0.05)
                    for client in client_to_read:
                        self.message_content = b""
                        self.message_content = client.recv(16777216)
                        if self.message_content:
                            if mode == 0:
                                return self.message_content.decode()
                            elif mode == 1:
                                return self.message_content
                            elif mode == 2:
                                if self.message_content == b'ok':
                                    return True
                                else:
                                    pass
                except (ConnectionAbortedError, ConnectionResetError):
                    self.client_activation()
            except select.error:  # avoid error if there's no one to read
                pass

    def sending(self, data, mode):
        if mode == 0:
            self.socket.sendall(str(data).encode())
        elif mode == 1:
            self.socket.sendall(data)


class File:
    def __init__(self):
        self.delimiter = "#&_#"
        self.delimiter2 = "-)_)-_"

    def get_file_information(self, format, file):
        if format == 0:
            cuted_file = file.split(self.delimiter.encode())
            return cuted_file[0], cuted_file[1]
        if format == 1:
            cuted_file = file.split(self.delimiter2.encode())
            return cuted_file[0], cuted_file[1]

    def format_file(self, data, tag):
        return (tag + self.delimiter2.encode() + data)

    def SHA512_checksum_creation(self, file):
        print("file checksum crea : ", file[:15])
        try:
            return hashlib.sha512(file.encode()).hexdigest()
        except AttributeError:
            return hashlib.sha512(file).hexdigest()

    def file_integrity_check(self, data, sum):
        if hashlib.sha512(data).hexdigest() == sum.decode():
            print("TRUE")
            return True
        else:
            print("FALSE")
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
        self.private_key = self.private_key[int(len(str(self.private_key)) / 2):].encode()

    def encrypt(self, data):
        nonce = os.urandom(15)
        #nonce = ''.join(rstr.rstr("abcdefghijklmABCDEFGHIJKLM01234nopqrstuvwxyzNOPQRSTUVWXYZ56789", 15))
        cipher = AES.new(self.private_key, AES.MODE_OCB, nonce=nonce.encode())
        crypted_key, tag = cipher.encrypt_and_digest(data.encode())
        return crypted_key, tag, nonce.encode()

    def decrypt(self, data, tag, nonce):
        print("key : ", self.private_key)
        cipher = AES.new(self.private_key, AES.MODE_OCB, nonce=nonce)
        uncrypted_key = cipher.decrypt_and_verify(data, tag)
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
        self.delimiter3 = "-)_)-_"

    def key_nonce_reload(self):
        if len(self.big_key_modified) <= 32:
            return False
        elif len(self.big_nonce_modified) <= 512:
            self.key_choice()
            self.big_nonce_modified = self.big_nonce_original
        else:
            self.nonce_choice()
    def nonce_choice(self):
        if self.n_choice == 0:
            self.n_choice = 1
            self.nonce = self.big_nonce_modified[-30:-15]
        elif self.n_choice == 1:
            self.n_choice = 2
            self.nonce = self.big_nonce_modified[-15:]
        elif self.n_choice == 2:
            self.n_choice = 0
            self.nonce = self.big_nonce_modified[:15]
        print("the chosen nonce is : ", self.nonce)

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
        print("the chosen key is : ", self.key)

    def get_big_key_nonce(self, mode, data):
        if mode == 0:
            datas = data.split(self.delimiter3.encode())
            tag = datas[0]
            print("Tag : ", tag)
            nonce = datas[2]
            print("Nonce : ", nonce)
            cryptedbigkeynonce = datas[1]
            print("cbkn : ", cryptedbigkeynonce[:15])
            return cryptedbigkeynonce, tag, nonce
        elif mode == 1:
            splitted_data = data.split(self.delimiter2.encode())
            checksum = splitted_data[0]
            key_nonce = splitted_data[1]
            return checksum, key_nonce
        elif mode == 2:
            data_splitted = data.decode().split(self.delimiter1)
            self.big_key_original = data_splitted[0]
            self.big_key_modified = self.big_key_original
            self.big_nonce_original = data_splitted[1]
            self.big_nonce_modified = self.big_nonce_original


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
        try:
            cipher = AES.new(self.key.encode(), AES.MODE_OCB, nonce=self.nonce.encode())
            crypted_data, self.tag = cipher.encrypt_and_digest(self.data)
            return crypted_data, self.tag
        except AttributeError:
            try:
                cipher = AES.new(self.key, AES.MODE_OCB, nonce=self.nonce.encode())
                crypted_data, self.tag = cipher.encrypt_and_digest(self.data)
                return crypted_data, self.tag
            except AttributeError:
                cipher = AES.new(self.key, AES.MODE_OCB, nonce=self.nonce)
                crypted_data, self.tag = cipher.encrypt_and_digest(self.data)
                return crypted_data, self.tag

    def decrypt(self):
        try:
            cipher = AES.new(self.key.encode(), AES.MODE_OCB, nonce=self.nonce.encode())
            uncrypted_data = cipher.decrypt_and_verify(self.data, self.tag)
            return uncrypted_data
        except AttributeError:
            try:
                cipher = AES.new(self.key.encode(), AES.MODE_OCB, nonce=self.nonce)
                uncrypted_data = cipher.decrypt_and_verify(self.data, self.tag)
                return uncrypted_data
            except AttributeError:
                try:
                    cipher = AES.new(self.key, AES.MODE_OCB, nonce=self.nonce.encode())
                    uncrypted_data = cipher.decrypt_and_verify(self.data, self.tag)
                    return uncrypted_data
                except AttributeError:
                    cipher = AES.new(self.key, AES.MODE_OCB, nonce=self.nonce)
                    uncrypted_data = cipher.decrypt_and_verify(self.data, self.tag)
                    return uncrypted_data