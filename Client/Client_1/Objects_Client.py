import socket
import select
import random
import hashlib
import rstr
from tkinter.filedialog import *
import pyDH
from Crypto.Cipher import AES
from time import sleep
import os

class Client:
    def __init__(self, serverhost, port):
        self.serverhost = str(serverhost)
        self.port_listening = port
        self.socket = ""
        self.message_content = b""
        self.buffsize = 4096

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
                print("---- ESTA CONN END ------")
                return True
            else:
                pass
        except (ConnectionRefusedError, OSError):
            sleep(2)
            print("error")
            pass

    def disconnecting(self):
        print("---- DISCONNECTING FUNCTION START ------")
        self.socket.close()
        print("---- DISCONNECTING FUNCTION END ------")

    def receiving(self, mode):
        print("---- RECEIVING FUNCTION START ------")
        while True:
            try:
                try:
                    client_to_read, wlist, xlist = select.select([self.socket], [], [], 0.05)
                    for client in client_to_read:
                        self.message_content = b""
                        while True:
                            part = client.recv(self.buffsize)
                            self.message_content += part
                            if len(part) < self.buffsize:
                                break
                        if self.message_content:
                            print("received message :", self.message_content[:15])
                            print("received message len :", len(self.message_content))
                            if mode == 0:
                                print("decode mode")
                                print("---- RECEIVING FUNCTION END ------")
                                return self.message_content.decode()
                            elif mode == 1:
                                print("no decode mode")
                                print("---- RECEIVING FUNCTION END ------")
                                return self.message_content
                except (ConnectionAbortedError, ConnectionResetError):
                    self.client_activation()
            except select.error:  # avoid error if there's no one to read
                pass

    def sending(self, data, mode):
        print("---- RECEIVING FUNCTION START ------")
        if mode == 0:
            print("encode data mode")
            self.socket.sendall(str(data).encode())
        elif mode == 1:
            print("no encode data mode")
            self.socket.sendall(data)
        print("---- SENDING FUNCTION END ------")


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
        print("---- RESET INIT FUNCTION START ------")
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
        print("---- RESET INIT FUNCTION END ------")

    def ask_file(self):
        print("---- ASK FILE FUNCTION START ------")
        with open(askopenfilename(), 'rb') as file_opened:
            self.uncrypted_full_file = file_opened.read()
            print("file binary :", self.uncrypted_full_file[:15])
            print("file binary len :", len(self.uncrypted_full_file))
            full_file_name = ",".join(file_opened.name.rsplit("/", 1)[1:])
            print("full file name : ", full_file_name)
            self.file_name = ",".join(full_file_name.rsplit(".", 1)[:1])
            print("file name : ", self.file_name)
            self.file_extension = ",".join(full_file_name.rsplit(".", 1)[1:])
            print("file extension : ", self.file_extension)
            self.file_sum = self.SHA512_checksum_creation(self.uncrypted_full_file)
            print("file sum : ", self.file_sum)
            file_opened.close()
        print("---- ASK FILE FUNCTION END ------")

    def get_file_information(self, mode, *file):
            print("---- GET FILE INFO FUNCTION START ------")
            if mode == 0:
                print("mode 0 : all info from file")
                extension_from_part = []
                name_from_part = []
                file_sum_from_part = []
                for data in file:
                    print("data : ", data[:15])
                    print("data len : ", len(data))
                    splitted_informations = data.split(self.delimiter1.encode())
                    print("splitted info len : ", splitted_informations)
                    print("splitted info 0 : ", splitted_informations[0].decode())
                    if bool(re.findall("^[a-m A-M 0-4]*$", splitted_informations[0].decode())) == True:
                        print('FOUND 1')
                        extension_from_part.append(splitted_informations[1].decode())
                        name_from_part.append(splitted_informations[2].decode())
                        self.tag_first_encryption1 = splitted_informations[3]
                        print("tag first encryption part1 : ", self.tag_first_encryption1)
                        self.unrecrypted_file_part1 = splitted_informations[4]
                        print("unrecrypted_file_part1 : ", self.unrecrypted_file_part1[:15])
                        print("unrecrypted_file_part1 len : ", len(self.unrecrypted_file_part1))
                    elif bool(re.findall("^[h-z H-Z 5-9]*$", splitted_informations[0].decode())) == True:
                        print('FOUND 2')
                        extension_from_part.append(splitted_informations[1].decode())
                        name_from_part.append(splitted_informations[2].decode())
                        self.tag_first_encryption2 = splitted_informations[3]
                        print("tag first encryption part2 : ", self.tag_first_encryption2)
                        self.unrecrypted_file_part2 = splitted_informations[4]
                        print("unrecrypted_file_part2 : ", self.unrecrypted_file_part2[:15])
                        print("unrecrypted_file_part2 len : ", len(self.unrecrypted_file_part2))
                part_1_list = [extension_from_part[0], name_from_part[0]]
                part_2_list = [extension_from_part[1], name_from_part[1]]
                i = 0
                for parameter_part1, parameter_part2 in zip(part_1_list, part_2_list):
                    if parameter_part1 == parameter_part2:
                        if i == 0:
                            self.file_extension = parameter_part1
                            print("file extension : ", self.file_extension)
                        elif i == 1:
                            self.file_name = parameter_part1
                            print("file name ", self.file_name)
                        i += 1
                    else:
                        if i == 0:
                            print("---- GET FILE INFO FUNCTION END ------")
                            return False
                        elif i == 1:
                            print("---- GET FILE INFO FUNCTION END ------")
                            return False
            elif mode == 1:
                print("mode1 : get sum and full_format_part1 & 2")
                i = 0
                for x in file:
                    if i == 0:
                        splitted_file = x.split(self.delimiter2.encode())
                        print("splitted file len : ", len(splitted_file))
                        self.file_part1_sum = splitted_file[0]
                        print("file part 1 sum : ", self.file_part1_sum)
                        self.full_format_file_part1 = splitted_file[1]
                        print("full format file part1 : ", self.full_format_file_part1[:15])
                        print("full format file part1 len : ", len(self.full_format_file_part1))
                        i += 1
                    if i == 1:
                        splitted_file = x.split(self.delimiter2.encode())
                        print("splitted file len : ", len(splitted_file))
                        self.file_part2_sum = splitted_file[0]
                        print("file part 2 sum : ", self.file_part2_sum)
                        self.full_format_file_part2 = splitted_file[1]
                        print("full format file part2 : ", self.full_format_file_part2[:15])
                        print("full format file part2 len : ", len(self.full_format_file_part2))
            elif mode == 2:
                print("mode1 : get sum and uncrypted full file")
                splitted_file = file[0].split(self.delimiter1.encode())
                print("splitted file len : ", len(splitted_file))
                self.file_sum = splitted_file[0]
                print("file sum : ", self.file_sum)
                self.uncrypted_full_file = splitted_file[1]
                print("uncrypted full file : ", self.uncrypted_full_file[:15])
                print("uncrypted full file len : ", len(self.uncrypted_full_file))
            print("---- GET FILE INFO FUNCTION END ------")

    def split_file(self, data):
        print("---- SPLIT FILE INFO FUNCTION START ------")
        if data == 0:
            print("split the crypted data mode")
            self.unrecrypted_file_part1 = self.crypted_full_file[:int(len(self.crypted_full_file)/2)]
            print("unrecrypted_file_part1 : ", self.unrecrypted_file_part1[:15])
            print("unrecrypted_file_part1 len : ", len(self.unrecrypted_file_part1))
            self.unrecrypted_file_part2 = self.crypted_full_file[int(len(self.crypted_full_file)/2):]
            print("unrecrypted_file_part2 : ", self.unrecrypted_file_part2[:15])
            print("unrecrypted_file_part2 len : ", len(self.unrecrypted_file_part2))
            print("---- SPLIT FILE INFO FUNCTION END ------")
        else:
            print("split the given data mode")
            print("data : ", data[:15])
            print("data len : ", len(data))
            splitted_data1 = str(data)[:int(len(str(data)) /2)]
            print("splitted data 1 : ", splitted_data1[:15])
            print("splitted data 1 : ", len(splitted_data1))
            splitted_data2 = str(data)[int(len(str(data)) /2):]
            print("splitted data 2 : ", splitted_data2[:15])
            print("splitted data 2 : ", len(splitted_data2))
            print("---- SPLIT FILE INFO FUNCTION END ------")
            return splitted_data1, splitted_data2

    def reassemble_file(self, mode):
        print("---- REASSEMBLE FILE INFO FUNCTION START ------")
        if mode == 0:
            print("reassemble part together mode")
            print("part1 :", self.unrecrypted_file_part1[:15])
            print("part1 len :", len(self.unrecrypted_file_part1))
            print("part2 :", self.unrecrypted_file_part2[:15])
            print("part2 len :", len(self.unrecrypted_file_part2))
            self.crypted_full_file = self.unrecrypted_file_part1 + self.unrecrypted_file_part2
            print("crypted full file : ", self.crypted_full_file[:15])
            print("crypted full file len : ", len(self.crypted_full_file))
        elif mode == 1:
            print("create the file mode")
            f = open(self.file_name + "." + self.file_extension, "wb")
            f.write(self.uncrypted_full_file)
            f.close()
        print("---- REASSEMBLE FILE INFO FUNCTION END ------")

    def SHA512_checksum_creation(self, file):
        print("---- SHA512_checksum_creation INFO FUNCTION START ------")
        print("file checksum crea : ", file[:15])
        print("file checksum crea len : ", len(file))
        try:
            print("---- SHA512_checksum_creation INFO FUNCTION END ------")
            return hashlib.sha512(file.encode()).hexdigest()
        except AttributeError:
            print("got attribute error")
            print("---- SHA512_checksum_creation INFO FUNCTION END ------")
            return hashlib.sha512(file).hexdigest()

    def format_file(self, which_format):
        print("---- FORMAT FILE FUNCTION START ------")
        if which_format == "part_format":
            print("part format mode")
            self.full_format_file_part1 = self.part_format_generator(random.randint(5, 10), 1).encode() + self.delimiter1.encode() + self.file_extension.encode() + self.delimiter1.encode() + self.file_name.encode() + self.delimiter1.encode() + self.tag_first_encryption1 + self.delimiter1.encode() + self.unrecrypted_file_part1
            print("full format file part1 : ", self.full_format_file_part1[:15])
            print("full format file part1 len : ", len(self.full_format_file_part1))
            self.full_format_file_part2 = self.part_format_generator(random.randint(5, 10), 2).encode() + self.delimiter1.encode() + self.file_extension.encode() + self.delimiter1.encode() + self.file_name.encode() + self.delimiter1.encode() + self.tag_first_encryption1 + self.delimiter1.encode() + self.unrecrypted_file_part2
            print("full format file part2 : ", self.full_format_file_part2[:15])
            print("full format file part2 len : ", len(self.full_format_file_part2))
        elif which_format == "last_format":
            print("last format part mode")
            self.full_format_file_part1 = self.file_part1_sum.encode() + self.delimiter2.encode() + self.full_format_file_part1
            print("full format file part1 : ", self.full_format_file_part1[:15])
            print("full format file part1 len : ", len(self.full_format_file_part1))
            self.full_format_file_part2 = self.file_part2_sum.encode() + self.delimiter2.encode() + self.full_format_file_part2
            print("full format file part2 : ", self.full_format_file_part2[:15])
            print("full format file part2 len : ", len(self.full_format_file_part2))
        elif which_format == "file_format":
            print("file format mode")
            file_format = (self.file_sum.encode() + self.delimiter1.encode() + self.uncrypted_full_file)
            print("file format : ", file_format[:15])
            print("file format len : ", len(file_format))
            print("---- FORMAT FILE FUNCTION END ------")
            return file_format
        elif which_format == "format_bef_send1":
            print("format before send part1")
            part1_format = (self.tag_second_encryption1 + self.delimiter3.encode() + self.full_format_file_part1)
            print("part1_format : ", part1_format[:15])
            print("part1_format len : ", len(part1_format))
            print("---- FORMAT FILE FUNCTION END ------")
            return part1_format
        elif which_format == "format_bef_send2":
            print("format before send part2")
            part2_format = (self.tag_second_encryption2 + self.delimiter3.encode() + self.full_format_file_part2)
            print("part2_format : ", part2_format[:15])
            print("part2_format len : ", len(part2_format))
            print("---- FORMAT FILE FUNCTION END ------")
            return part2_format
        print("---- FORMAT FILE FUNCTION END ------")

    def part_format_generator(self, size, part_number):
        print("---- PART NUMBER GEN FUNCTION START ------")
        if part_number == 1:
            print("for part 1 mode")
            part_number_generated = ''.join(rstr.rstr("abcdefghijklmABCDEFGHIJKLM01234", size))
            print("part number generated 1", part_number_generated)
            print("---- PART NUMBER GEN FUNCTION END ------")
            return part_number_generated
        elif part_number == 2:
            print("for part 2 mode")
            part_number_generated = ''.join(rstr.rstr("nopqrstuvwxyzNOPQRSTUVWXYZ56789", size))
            print("part number generated 2", part_number_generated)
            print("---- PART NUMBER GEN FUNCTION END ------")
            return part_number_generated

    def file_integrity_check(self, file, sum):
        print("---- FILE INTEGRITY CHECK FUNCTION START ------")
        if hashlib.sha512(file).hexdigest() == sum:
            print("test passed")
            print("---- FILE INTEGRITY CHECK FUNCTION END ------")
            return True
        else:
            print("---- FILE INTEGRITY CHECK FUNCTION END ------")
            return False

class DH_algorithm:
    def __init__(self):
        self.engine = ""
        self.public_key = ""
        self.private_key = ""

    def public_key_generator(self):
        print("---- PUB KEY GEN FUNCTION START ------")
        self.engine = pyDH.DiffieHellman()
        self.public_key = self.engine.gen_public_key()
        print("---- PUB KEY GEN FUNCTION END ------")
        return self.public_key

    def private_key_generator(self, friendkey):
        print("---- PRIV KEY GEN FUNCTION START ------")
        self.private_key = self.engine.gen_shared_key(int(friendkey))
        self.private_key = self.private_key[int(len(str(self.private_key)) / 2):].encode()
        print("private key : ", self.private_key[:15])
        print("private key len : ", len(self.private_key))
        print("---- PRIV KEY GEN FUNCTION START ------")

    def encrypt(self, data):
        print("---- ENCRYPT FUNCTION START ------")
        nonce = os.urandom(15)
        print("NONCE : ", nonce)
        print("LEN NONCE : ", len(nonce))
        sleep(1)
        cipher = AES.new(self.private_key, AES.MODE_OCB, nonce=nonce)
        crypted_key, tag = cipher.encrypt_and_digest(data.encode())
        print("crypted_key : ", crypted_key[:15])
        print("crypted_key len : ", len(crypted_key))
        print("tag : ", tag)
        print("---- ENCRYPT FUNCTION END ------")
        return crypted_key, tag, nonce

    def decrypt(self, data, tag, nonce):
        print("---- DECRYPT FUNCTION START ------")
        cipher = AES.new(self.private_key, AES.MODE_OCB, nonce=nonce)
        uncrypted_key = cipher.decrypt_and_verify(data, tag)
        print("uncrypted key : ", uncrypted_key[:15])
        print("uncrypted key len : ", len(uncrypted_key))
        print("---- DECRYPT FUNCTION END ------")
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
        print("---- BIG KEY NONCE GEN FUNCTION START ------")
        self.big_key_original = rstr.rstr('azertyuiopmlkjhgfdsqwxcvbnAZERTYUIOPMLKJHGFDSQWXCVBN0123456789', 16000)
        self.big_key_modified = self.big_key_original
        print("big key original : ", self.big_key_original[:15])
        print("big key original len : ", len(self.big_key_original))
        print("big key modified len : ", len(self.big_key_modified))
        self.big_nonce_original = rstr.rstr('azertyuiopmlkjhgfdsqwxcvbnAZERTYUIOPMLKJHGFDSQWXCVBN0123456789', 16000)
        self.big_nonce_modified = self.big_nonce_original
        print("big nonce original : ", self.big_nonce_original[:15])
        print("big nonce original len : ", len(self.big_nonce_original))
        print("big nonce modified len : ", len(self.big_nonce_modified))
        print("---- BIG KEY NONCE GEN FUNCTION END ------")
        return self.big_key_original, self.big_nonce_original

    def key_nonce_reload(self):
        print("---- KEY NONCE RELOAD FUNCTION START ------")
        if len(self.big_key_modified) <= 32:
            print("not enough key ")
            print("---- KEY NONCE RELOAD FUNCTION END ------")
            return False
        elif len(self.big_nonce_modified) <= 512:
            print("changing key")
            self.key_choice()
            self.big_nonce_modified = self.big_nonce_original
            print("big nonce modified len : ", len(self.big_nonce_modified))
        else:
            print("changing nonce")
            self.nonce_choice()
        print("---- KEY NONCE RELOAD FUNCTION END ------")

    def nonce_choice(self):
        print("---- NONCE CHOICE FUNCTION START ------")
        if self.n_choice == 0:
            print("nonce_choice number : ", self.n_choice)
            self.n_choice = 1
            self.nonce = self.big_nonce_modified[-30:-15]
        elif self.n_choice == 1:
            print("nonce_choice number : ", self.n_choice)
            self.n_choice = 2
            self.nonce = self.big_nonce_modified[-15:]
        elif self.n_choice == 2:
            print("nonce_choice number : ", self.n_choice)
            self.n_choice = 0
            self.nonce = self.big_nonce_modified[:15]
        print("the chosen nonce is : ", self.nonce)
        print("---- NONCE CHOICE FUNCTION END ------")

    def key_choice(self):
        print("---- KEY CHOICE FUNCTION START ------")
        if self.k_choice == 0:
            print("key choice number : ", self.k_choice)
            self.k_choice = 1
            self.key = self.big_key_modified[-32:]
        elif self.k_choice == 1:
            print("key choice number : ", self.k_choice)
            self.k_choice = 2
            self.key = self.big_key_modified[:32]
        elif self.k_choice == 2:
            print("key choice number : ", self.k_choice)
            self.k_choice = 0
            self.key = self.big_key_modified[-64:-32]
        print("the chosen key is : ", self.key)
        print("---- KEY CHOICE FUNCTION END ------")

    def get_big_key_nonce(self, mode, *data):
        print("---- GET BIG KEY NONCE FUNCTION START ------")
        if mode == 0:
            print("get tag, nonce and cbkn mode")
            datas = data[0].split(self.delimiter3.encode())
            tag = datas[0]
            print("Tag : ", tag)
            nonce = datas[2]
            print("Nonce : ", nonce)
            cryptedbigkeynonce = datas[1]
            print("cbkn : ", cryptedbigkeynonce[:15])
            print("cbkn len : ", len(cryptedbigkeynonce))
            print("---- GET BIG KEY NONCE FUNCTION END ------")
            return cryptedbigkeynonce, tag, nonce
        elif mode == 1:
            print("get checksum and keynonce mode")
            splitted_data = data[0].split(self.delimiter2.encode())
            checksum = splitted_data[0]
            print("checksum : ", checksum)
            key_nonce = splitted_data[1]
            print("key_nonce : ", key_nonce[:15])
            print("key_nonce len : ", len(key_nonce))
            print("---- GET BIG KEY NONCE FUNCTION END ------")
            return checksum, key_nonce
        elif mode == 2:
            print("get big key and big nonce mode")
            self.big_key_original = data[0]
            self.big_key_modified = self.big_key_original
            print("big key original : ", self.big_key_original[:15])
            print("big key original len : ", len(self.big_key_original))
            print("big key modified len : ", len(self.big_key_modified))
            self.big_nonce_original = data[1]
            self.big_nonce_modified = self.big_nonce_original
            print("big nonce original : ", self.big_nonce_original[:15])
            print("big nonce original len : ", len(self.big_nonce_original))
            print("big nonce modified len : ", len(self.big_nonce_modified))
        print("---- GET BIG KEY NONCE FUNCTION END ------")

    def big_key_nonce_format(self, mode, *datas):
        print("---- BIG KEY NONCE FORMAT FUNCTION START ------")
        if mode == 0:
            print("bigkey ", self.delimiter1, " bignonce format mode")
            formatted = self.big_key_original + self.delimiter1 + self.big_nonce_original
        elif mode == 1:
            print("data ", self.delimiter2, " other date format mode")
            formatted = datas[0] + self.delimiter2 + datas[1]
        elif mode == 2:
            print("data ", self.delimiter3, " other data ", self.delimiter3, " other other data format mode")
            formatted = datas[0] + self.delimiter3.encode() + datas[2] + self.delimiter3.encode() + datas[1]
        print("formatted data : ", formatted[:15])
        print("formatted data len : ", len(formatted))
        print("---- BIG KEY NONCE FORMAT FUNCTION END ------")
        return formatted


class AES_Algorithm:
    def __init__(self):
        self.data = ""
        self.key = ""
        self.nonce = ""
        self.tag = ""

    def update_data(self, data, key, nonce, tag):
        print("---- UPDATE DATA FUNCTION START ------")
        self.data = data
        print("data : ", data[:15])
        print("data len : ", len(data))
        self.key = key
        print("key : ", key)
        self.nonce = nonce
        print("nonce : ", nonce)
        self.tag = tag
        print("tag : ", tag)
        print("---- UPDATE DATA FUNCTION END ------")

    def encrypt(self):
        print("---- ENCRYPT FUNCTION START ------")
        try:
            cipher = AES.new(self.key.encode(), AES.MODE_OCB, nonce=self.nonce.encode())
            crypted_data, self.tag = cipher.encrypt_and_digest(self.data)
            print("crypted data : ", crypted_data[:15])
            print("crypted data len : ", len(crypted_data))
            print("tag : ", self.tag)
            print("---- ENCRYPT FUNCTION END ------")
            return crypted_data, self.tag
        except AttributeError:
            try:
                cipher = AES.new(self.key, AES.MODE_OCB, nonce=self.nonce.encode())
                crypted_data, self.tag = cipher.encrypt_and_digest(self.data)
                print("crypted data : ", crypted_data[:15])
                print("crypted data len : ", len(crypted_data))
                print("tag : ", self.tag)
                print("---- ENCRYPT FUNCTION END ------")
                return crypted_data, self.tag
            except AttributeError:
                cipher = AES.new(self.key, AES.MODE_OCB, nonce=self.nonce)
                crypted_data, self.tag = cipher.encrypt_and_digest(self.data)
                print("crypted data : ", crypted_data[:15])
                print("crypted data len : ", len(crypted_data))
                print("tag : ", self.tag)
                print("---- ENCRYPT FUNCTION END ------")
                return crypted_data, self.tag

    def decrypt(self):
        print("---- DECRYPT FUNCTION START ------")
        try:
            cipher = AES.new(self.key.encode(), AES.MODE_OCB, nonce=self.nonce)
            uncrypted_data = cipher.decrypt_and_verify(self.data, self.tag)
            print("tag : ", self.tag)
            print("nonce : ", self.nonce)
            print("uncrypted data : ", uncrypted_data[:15])
            print("uncrypted data len : ", len(uncrypted_data))
            print("---- DECRYPT FUNCTION END ------")
            return uncrypted_data
        except (TypeError, AttributeError) as error:
            try:
                cipher = AES.new(self.key, AES.MODE_OCB, nonce=self.nonce.encode())
                uncrypted_data = cipher.decrypt_and_verify(self.data, self.tag)
                print("tag : ", self.tag)
                print("nonce : ", self.nonce)
                print("uncrypted data : ", uncrypted_data[:15])
                print("uncrypted data len : ", len(uncrypted_data))
                print("---- DECRYPT FUNCTION END ------")
                return uncrypted_data
            except (TypeError, AttributeError) as error:
                try:
                    cipher = AES.new(self.key, AES.MODE_OCB, nonce=self.nonce)
                    uncrypted_data = cipher.decrypt_and_verify(self.data, self.tag)
                    print("tag : ", self.tag)
                    print("nonce : ", self.nonce)
                    print("uncrypted data : ", uncrypted_data[:15])
                    print("uncrypted data len : ", len(uncrypted_data))
                    print("---- DECRYPT FUNCTION END ------")
                    return uncrypted_data
                except (TypeError, AttributeError) as error:
                    cipher = AES.new(self.key.encode(), AES.MODE_OCB, nonce=self.nonce.encode())
                    uncrypted_data = cipher.decrypt_and_verify(self.data, self.tag)
                    print("tag : ", self.tag)
                    print("nonce : ", self.nonce)
                    print("uncrypted data : ", uncrypted_data[:15])
                    print("uncrypted data len : ", len(uncrypted_data))
                    print("---- DECRYPT FUNCTION END ------")
                    return uncrypted_data