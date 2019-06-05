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
from tkinter.filedialog import *
import pyDH
import self as self
from Crypto.Cipher import AES
from Crypto import Random
import base64
from time import sleep
import os

class Client:
    def __init__(self, serverhost, port):
        self.serverhost = str(serverhost)
        self.port_listening = port
        self.socket = ""
        self.message_content = b""

    def client_activation(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return self.establishing_conn(s)

    def establishing_conn(self, sock):
        try:
            print("---- ESTA CONN START ------")
            sock.connect((self.serverhost, self.port_listening))
            self.socket = sock
            if self.socket.recv(4096) == b'ok':
                print("---- ESTA CONN SUCCESS ------")
                return True
            else:
                pass
        except (ConnectionRefusedError, OSError):
            sleep(2)
            print("error")
            pass

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
                except (ConnectionAbortedError, ConnectionResetError):
                    self.client_activation()
            except select.error:  # avoid error if there's no one to read
                pass

    def sending(self, data, mode):
        if mode == 0:
            self.socket.sendall(str(data).encode())
        elif mode == 1:
            self.socket.sendall(data)


class File:  # modify
    def __init__(self):
        self.uncrypted_full_file = ""
        self.file_name = ""
        self.file_extension = ""
        self.file_sum = ""
        self.crypted_full_file = ""
        self.delimiter1 = "$\-$"
        self.delimiter2 = "#&_#"
        self.delimiter3 = "-)_)-_"

        self.unrecrypted_file_part1 = ""
        self.file_part1_sum = ""
        self.crypted_file_part1 = ""
        self.full_format_file_part1 = ""

        self.unrecrypted_file_part2 = ""
        self.file_part2_sum = ""
        self.crypted_file_part2 = ""
        self.full_format_file_part2 = ""

        self.tag_first_encryption1 = ""
        self.tag_first_encryption2 = ""
        self.tag_second_encryption1 = ""
        self.tag_second_encryption2 = ""

    def reset_init(self):
        self.uncrypted_full_file = ""
        self.file_name = ""
        self.file_extension = ""
        self.file_sum = ""
        self.crypted_full_file = ""

        self.unrecrypted_file_part1 = ""
        self.file_part1_sum = ""
        self.full_format_file_part1 = ""
        self.crypted_file_part1 = ""

        self.unrecrypted_file_part2 = ""
        self.file_part2_sum = ""
        self.full_format_file_part2 = ""
        self.crypted_file_part2 = ""
        self.tag_first_encryption1 = ""
        self.tag_first_encryption2 = ""
        self.tag_second_encryption1 = ""
        self.tag_second_encryption2 = ""

    def ask_file(self):
        with open(askopenfilename(), 'rb') as file_opened:
            self.uncrypted_full_file = file_opened.read()
            print("file binary :", self.uncrypted_full_file)
            full_file_name = ",".join(file_opened.name.rsplit("/", 1)[1:])
            print("full file name : ", full_file_name)
            self.file_name = ",".join(full_file_name.rsplit(".", 1)[:1])
            print("file name : ", self.file_name)
            self.file_extension = ",".join(full_file_name.rsplit(".", 1)[1:])
            print("file extension : ", self.file_extension)
            self.file_sum = self.SHA512_checksum_creation(self.uncrypted_full_file)
            print("file sum : ", self.file_sum)
            file_opened.close()

    def get_file_information(self, mode, *file):
            if mode == 0:
                extension_from_part = []
                name_from_part = []
                file_sum_from_part = []
                for data in file:
                    splitted_informations = data.split(self.delimiter1.encode())
                    if re.findall("[a-m]*[A-M]*[0-4]*", splitted_informations[0].decode()) != False:
                        extension_from_part.append(splitted_informations[1].decode())
                        name_from_part.append(splitted_informations[2].decode())
                        self.tag_first_encryption1 = splitted_informations[3]
                        self.unrecrypted_file_part1 = splitted_informations[4]
                    elif re.findall("[h-n]*[H-N]*[5-9]*", splitted_informations[0].decode()) != False:
                        extension_from_part.append(splitted_informations[1].decode())
                        name_from_part.append(splitted_informations[2].decode())
                        self.tag_first_encryption2 = splitted_informations[3]
                        self.unrecrypted_file_part2 = splitted_informations[4]

                part_1_list = [extension_from_part[0], name_from_part[0]]
                part_2_list = [extension_from_part[1], name_from_part[1]]
                i = 0
                for parameter_part1, parameter_part2 in zip(part_1_list, part_2_list):
                    if parameter_part1 == parameter_part2:
                        if i == 0:
                            self.file_extension = parameter_part1
                        elif i == 1:
                            self.file_name = parameter_part1
                        else:
                            i += 1
                    else:
                        if i == 0:
                            return False
                        elif i == 1:
                            return False
            elif mode == 1:
                i = 0
                for x in file:
                    if i == 0:
                        splitted_file = x.split(self.delimiter2.encode())
                        self.file_part1_sum = splitted_file[0]
                        self.full_format_file_part1 = splitted_file[1]
                        i += 1
                    if i == 1:
                        splitted_file = x.split(self.delimiter2.encode())
                        self.file_part2_sum = splitted_file[0]
                        self.full_format_file_part2 = splitted_file[1]
            elif mode == 2:
                splitted_file = file.split(self.delimiter1.encode())
                self.file_sum = splitted_file[0]
                self.uncrypted_full_file = splitted_file[1]

    def split_file(self, data):
        if data == 0:
            self.unrecrypted_file_part1 = self.crypted_full_file[:int(len(self.crypted_full_file)/2)]
            self.unrecrypted_file_part2 = self.crypted_full_file[int(len(self.crypted_full_file)/2):]
        else:
            print("data : ", data)
            splitted_data1 = str(data)[:int(len(str(data)) /2)]
            print("sp data 1 : ", splitted_data1)
            splitted_data2 = str(data)[int(len(str(data)) /2):]
            print("sp data 2 : ", splitted_data2)
            return splitted_data1, splitted_data2

    def reassemble_file(self, mode):
        if mode == 0:
            self.crypted_full_file = self.unrecrypted_file_part1 + self.unrecrypted_file_part2
        elif mode == 1:
            f = open(self.file_name + "." + self.file_extension, "wb")
            f.write(self.uncrypted_full_file.encode())
            f.close()

    def SHA512_checksum_creation(self, file):
        print("file checksum crea : ", file[:15])
        try:
            return hashlib.sha512(file.encode()).hexdigest()
        except AttributeError:
            return hashlib.sha512(file).hexdigest()

    def format_file(self, which_format):
        if which_format == "part_format":
            self.full_format_file_part1 = self.part_format_generator(random.randint(5, 10), 1).encode() + self.delimiter1.encode() + self.file_extension.encode() + self.delimiter1.encode() + self.file_name.encode() + self.delimiter1.encode() + self.tag_first_encryption1 + self.delimiter1.encode() + self.unrecrypted_file_part1
            self.full_format_file_part2 = self.part_format_generator(random.randint(5, 10), 2).encode() + self.delimiter1.encode() + self.file_extension.encode() + self.delimiter1.encode() + self.file_name.encode() + self.delimiter1.encode() + self.tag_first_encryption1 + self.delimiter1.encode() + self.unrecrypted_file_part2
        elif which_format == "last_format":
            self.full_format_file_part1 = self.file_part1_sum.encode() + self.delimiter2.encode() + self.full_format_file_part1
            self.full_format_file_part2 = self.file_part2_sum.encode() + self.delimiter2.encode() + self.full_format_file_part2
        elif which_format == "file_format":
            return (self.file_sum.encode() + self.delimiter1.encode() + self.uncrypted_full_file)
        elif which_format == "format_bef_send1":
            return (self.tag_second_encryption1 + self.delimiter3.encode() + self.full_format_file_part1)
        elif which_format == "format_bef_send2":
            return (self.tag_second_encryption2 + self.delimiter3.encode() + self.full_format_file_part2)

    def part_format_generator(self, size, part_number):
        if part_number == 1:
            return ''.join(rstr.rstr("abcdefghijklmABCDEFGHIJKLM01234", size))
        elif part_number == 2:
            return ''.join(rstr.rstr("nopqrstuvwxyzNOPQRSTUVWXYZ56789", size))

    def file_integrity_check(self, file, sum):
        if hashlib.sha512(file).hexdigest() == sum:
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
        self.private_key = self.private_key[int(len(str(self.private_key)) / 2):].encode()

    def encrypt(self, data):
        nonce = os.urandom(15)
        print("NONCE : ", nonce)
        print("LEN NONCE : ", len(nonce))
        sleep(1)
        cipher = AES.new(self.private_key, AES.MODE_OCB, nonce=nonce)
        crypted_key, tag = cipher.encrypt_and_digest(data.encode())
        return crypted_key, tag, nonce

    def decrypt(self, data, tag, nonce):
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

    def big_key_nonce_generator(self):
        self.big_key_original = rstr.rstr('azertyuiopmlkjhgfdsqwxcvbnAZERTYUIOPMLKJHGFDSQWXCVBN0123456789', 16000)
        self.big_key_modified = self.big_key_original
        self.big_nonce_original = rstr.rstr('azertyuiopmlkjhgfdsqwxcvbnAZERTYUIOPMLKJHGFDSQWXCVBN0123456789', 16000)
        self.big_nonce_modified = self.big_nonce_original
        return self.big_key_original, self.big_nonce_original

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

    def get_big_key_nonce(self, mode, *data):
        if mode == 0:
            datas = data[0].split(self.delimiter3.encode())
            tag = datas[0]
            print("Tag : ", tag)
            nonce = datas[2]
            print("Nonce : ", nonce)
            cryptedbigkeynonce = datas[1]
            print("cbkn : ", cryptedbigkeynonce)
            return cryptedbigkeynonce, tag, nonce
        elif mode == 1:
            splitted_data = data[0].split(self.delimiter2.encode())
            checksum = splitted_data[0]
            key_nonce = splitted_data[1]
            return checksum, key_nonce
        elif mode == 2:
            self.big_key_original = data[0]
            self.big_key_modified = self.big_key_original
            self.big_nonce_original = data[1]
            self.big_nonce_modified = self.big_nonce_original

    def big_key_nonce_format(self, mode, *datas):
        if mode == 0:
            formatted = self.big_key_original + self.delimiter1 + self.big_nonce_original
        elif mode == 1:
            formatted = datas[0] + self.delimiter2 + datas[1]
        elif mode == 2:
            formatted = datas[0] + self.delimiter3.encode() + datas[2] + self.delimiter3.encode() + datas[1]
        return formatted


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
            cipher = AES.new(self.key.encode(), AES.MODE_OCB, nonce=self.nonce)
            uncrypted_data = cipher.decrypt_and_verify(self.data, self.tag)
            return uncrypted_data
        except (TypeError, AttributeError) as error:
            try:
                cipher = AES.new(self.key, AES.MODE_OCB, nonce=self.nonce.encode())
                uncrypted_data = cipher.decrypt_and_verify(self.data, self.tag)
                return uncrypted_data
            except (TypeError, AttributeError) as error:
                try:
                    cipher = AES.new(self.key, AES.MODE_OCB, nonce=self.nonce)
                    uncrypted_data = cipher.decrypt_and_verify(self.data, self.tag)
                    return uncrypted_data
                except (TypeError, AttributeError) as error:
                    cipher = AES.new(self.key.encode(), AES.MODE_OCB, nonce=self.nonce.encode())
                    uncrypted_data = cipher.decrypt_and_verify(self.data, self.tag)
                    return uncrypted_data