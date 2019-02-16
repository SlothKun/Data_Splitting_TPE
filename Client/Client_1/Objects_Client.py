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


class Client:
    def __init__(self, serverhost, port):
        self.serverhost = str(serverhost)
        self.port_listening = port
        self.socket = ""
        self.message_content = b""
        self.init = False

    def client_activation(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.etablishing_conn(s)

    def etablishing_conn(self, sock):
        try:
            sock.connect((self.serverhost, self.port_listening))
            self.socket = sock
            print("connected")
        except (ConnectionRefusedError, OSError):
                self.etablishing_conn(sock)

    def receiving(self):
        try:
            client_to_read, wlist, xlist = select.select([self.socket], [], [], 0.05)
        except select.error:  # avoid error if there's no one to read
            pass
        else:
            self.message_content = self.socket.recv(16777216)
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
        self.uncrypted_full_file = ""
        self.file_name = ""
        self.file_extension = ""
        self.file_sum = ""
        self.length_byte_file = 0
        self.crypted_full_file = ""
        self.delimiter1 = b"$\-$"
        self.delimiter2 = b"#&_#"

        self.unrecrypted_file_part1 = ""
        self.file_part1_sum = ""
        self.crypted_file_part1 = ""
        self.full_format_file_part1 = ""

        self.unrecrypted_file_part2 = ""
        self.file_part2_sum = ""
        self.crypted_file_part2 = ""
        self.full_format_file_part2 = ""

    def ask_file(self):
        root = tkinter.Tk()
        root.withdraw()
        get_file = tkinter.filedialog.askopenfilename()
        with open(get_file, 'rb') as file_opened:
            self.uncrypted_full_file = file_opened.read()
            full_file_name = ",".join(file_opened.name.rsplit("/", 1)[1:])
            self.file_name = ",".join(full_file_name.rsplit(".", 1)[:1])
            self.file_extension = ",".join(full_file_name.rsplit(".", 1)[1:])
            self.length_byte_file = len(self.uncrypted_full_file)
            file_opened.close()

    def get_file_information(self, *file):
            extension_from_part = []
            name_from_part = []
            file_sum_from_part = []
            for data in file:
                splitted_informations = data.replace(self.delimiter2, self.delimiter1).split(self.delimiter1)
                if re.findall("[a-m]*[0-4]*", splitted_informations[0].decode()) != None:  # Decode first part and get info
                    self.file_part1_sum = splitted_informations[1].decode()
                    extension_from_part.append(splitted_informations[2].decode())
                    file_sum_from_part.append(splitted_informations[3].decode())
                    name_from_part.append(splitted_informations[4].decode())
                    self.unrecrypted_file_part1 = splitted_informations[5]
                elif re.findall("[n-z]*[5-9]*", splitted_informations[0].decode()) != None:  # It decode the second part of file and get sum, file, filename..
                    self.file_part1_sum = splitted_informations[1].decode()
                    self.file_part2_sum = splitted_informations[1].decode()
                    extension_from_part.append(splitted_informations[2].decode())
                    file_sum_from_part.append(splitted_informations[3].decode())
                    name_from_part.append(splitted_informations[4].decode())
                    self.unrecrypted_file_part2 = splitted_informations[5]

            part_1_list = [extension_from_part[0], name_from_part[0], file_sum_from_part[0]]  # List of information to compare
            part_2_list = [extension_from_part[1], name_from_part[1], file_sum_from_part[1]]
            i = 0
            for parameter_part1, parameter_part2 in zip(part_1_list, part_2_list):  # Compare each information in list, if match, put it in variable associated, if not, print it
                if parameter_part1 == parameter_part2:
                    if i == 0:
                        self.file_extension = parameter_part1
                    elif i == 1:
                        self.file_name = parameter_part1
                    elif i == 2:
                        self.file_sum = parameter_part1
                else:
                    if i == 0:
                        print("both extension doesn't match")
                    elif i == 1:
                        print("both name doesn't match")
                    elif i == 2:
                        print("both sum doesn't match")
                i += 1

    def split_file(self):  # Take 1 file and split into 2 files
        self.unrecrypted_file_part1 = self.uncrypted_full_file[:int(self.length_byte_file/2)]
        self.unrecrypted_file_part2 = self.uncrypted_full_file[int(self.length_byte_file/2):]

    def reassemble_file(self):  # Take 2 given file and add them together
        f = open(self.file_name + "." + self.file_extension, "wb")
        self.uncrypted_full_file = self.unrecrypted_file_part1 + self.unrecrypted_file_part2
        f.write(str(self.uncrypted_full_file))
        f.close()

    def SHA512_checksum_creation(self):  # Can be modify to create sum of 3 files in 1 call
        self.file_sum = hashlib.sha512(self.uncrypted_full_file).hexdigest()
        self.file_part1_sum = hashlib.sha512(self.unrecrypted_file_part1).hexdigest()
        self.file_part2_sum = hashlib.sha512(self.unrecrypted_file_part2).hexdigest()

    def format_file(self):  # Arrange the each file in order to know what information is what
        self.full_format_file_part1 = self.part_format_generator(random.randint(5, 10), 1) + self.delimiter2 + str(self.file_part1_sum) + self.delimiter2 + self.file_extension + self.delimiter1 + str(self.file_sum) + self.delimiter1 + self.file_name + self.delimiter1 + self.unrecrypted_file_part1
        self.full_format_file_part2 = self.part_format_generator(random.randint(5, 10), 2) + self.delimiter2 + str(self.file_part2_sum) + self.delimiter2 + self.file_extension + self.delimiter1 + str(self.file_sum) + self.delimiter1 + self.file_name + self.delimiter1 + self.unrecrypted_file_part2
        return self.full_format_file_part1.encode(), self.full_format_file_part2.encode()

    def part_format_generator(self, size, part_number):  # It create random string that'll to know what is each part
        if part_number == 1:
            return ''.join(rstr.rstr("abcdefghijklmABCDEFGHIJKLM01234", size))
        elif part_number == 2:
            return ''.join(rstr.rstr("nopqrstuvwxyzNOPQRSTUVWXYZ56789", size))

    def file_integrity_check(self, file, sum):  # Simply compare the actual file sum with given sum
        if hashlib.sha512(file).hexdigest() == sum:
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

