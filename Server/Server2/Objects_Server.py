import socket
import select
import os
import hashlib
import pyDH
from Crypto.Cipher import AES

class Server:
    def __init__(self, host, port_listening):
        self.host = host
        self.port_listening = port_listening
        self.whitelisted_client = ["172.16.1.42", "127.0.0.1", "192.168.0.33", "192.168.0.34", "172.16.1.19"]
        self.socket = ""
        self.message_content = b""
        self.buffsize = 4096

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


class File:
    def __init__(self):
        self.delimiter = "#&_#"
        self.delimiter2 = "-)_)-_"

    def get_file_information(self, format, file):
        print("---- GET FILE INFO FUNCTION START ------")
        if format == 0:
            cuted_file = file.split(self.delimiter.encode())
            print("cuted file length : ", len(cuted_file))
            print("cutedfile[0] : ", cuted_file[0][:15])
            print("cutedfile[1] : ", cuted_file[1][:15])
            print("---- GET FILE INFO FUNCTION END ------")
            return cuted_file[0], cuted_file[1]
        if format == 1:
            cuted_file = file.split(self.delimiter2.encode())
            print("cuted file length : ", len(cuted_file))
            print("cutedfile[0] : ", cuted_file[0][:15])
            print("cutedfile[1] : ", cuted_file[1][:15])
            print("---- GET FILE INFO FUNCTION END ------")
            return cuted_file[0], cuted_file[1]

    def format_file(self, data, tag):
        formatted = (tag + self.delimiter2.encode() + data)
        print("formatted : ", formatted[:15])
        print("formatted len : ", len(formatted))
        return formatted

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

    def file_integrity_check(self, data, sum):
        print("---- FILE INTEGRITY CHECK FUNCTION START ------")
        if hashlib.sha512(data).hexdigest() == sum.decode():
            print("TRUE")
            print("---- FILE INTEGRITY CHECK FUNCTION END ------")
            return True
        else:
            print("FALSE")
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

    def get_big_key_nonce(self, mode, data):
        print("---- GET BIG KEY NONCE FUNCTION START ------")
        if mode == 0:
            print("get tag, nonce and cbkn mode")
            datas = data.split(self.delimiter3.encode())
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
            splitted_data = data.split(self.delimiter2.encode())
            checksum = splitted_data[0]
            print("checksum : ", checksum)
            key_nonce = splitted_data[1]
            print("key_nonce : ", key_nonce[:15])
            print("key_nonce len : ", len(key_nonce))
            print("---- GET BIG KEY NONCE FUNCTION END ------")
            return checksum, key_nonce
        elif mode == 2:
            data_splitted = data.decode().split(self.delimiter1)
            self.big_key_original = data_splitted[0]
            self.big_key_modified = self.big_key_original
            print("big key original : ", self.big_key_original[:15])
            print("big key original len : ", len(self.big_key_original))
            print("big key modified len : ", len(self.big_key_modified))
            self.big_nonce_original = data_splitted[1]
            self.big_nonce_modified = self.big_nonce_original
            print("big nonce original : ", self.big_nonce_original[:15])
            print("big nonce original len : ", len(self.big_nonce_original))
            print("big nonce modified len : ", len(self.big_nonce_modified))
        print("---- GET BIG KEY NONCE FUNCTION END ------")

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