import socket
import select

class Server:
    def __init__(self):
        self.host = '127.0.0.1'
        self.port_listening = 6801
        self.port_listening2 = 6802
        self.nickname = "Server1"
        self.whitelisted_client = ["172.16.1.42", "127.0.0.1", "192.168.0.33", "192.168.0.34", "172.16.1.19"]
        self.connected_client = []
        self.who_sent = ""
        self.who_to_send = ""
        self.message_content = b""

    def server_activation(self, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, port))
        s.listen(2)
        self.etablishing_conn(s)

    def etablishing_conn(self, sock):
        client_ask_conn, wlist, xlist = select.select([sock], [], [], 0.05)
        for client in client_ask_conn:
            clientconnect, clientinfo = sock.accept()
            ip, port = clientconnect.getpeername()
            print(port)
            if ip in self.whitelisted_client:  # Whitelist application
                self.connected_client.append(clientconnect)
                print(ip, " is connected on port ", port)
            else:
                print("This client isn't whitelisted")
                print("Closing connection..")
                client.close()

    def receiving(self):
        try:
            client_to_read, wlist, xlist = select.select(self.connected_client, [], [], 0.05)
        except select.error:  # avoid error if there's no one to read
            pass
        else:
            for client in client_to_read:
                ip, port = client.getpeername()
                self.who_sent = client
                self.connected_client.remove(client)
                self.connected_client.insert(0, client)
                # need to handle out of range
                self.message_content = client.recv(2048)
                print(ip, " >> ", self.message_content)
                self.answer(client)
                return True

    def answer(self, client):
        if self.message_content.decode() == "ping":
            client.send(b"pong")
        else:
            client.send(b"received")

    def sending(self):
        for client in self.connected_client:
            if self.who_sent == client:
                self.who_to_send = self.connected_client[1] # need to handle list out of range
                self.who_to_send.send(b"Ok")
                break

    def ping(self):
        for client in self.connected_client:
            client.send(b"ping")
            self.answer(client)

    def ping_check(self, client):
        msg_received = client.recv(2048)
        if msg_received.decode() != "pong":
            print("The client ", client, " didn't answer to the ping correctly. disconnection to the client..")
            client.send(b"Wrong!")
            client.close()

#class File:
#   def __init__(self):

#   def file_integrity_check(self):

#    def crypt(self):

#    def decrypt(self):




serverobj = Server()

while True:
    serverobj.server_activation(serverobj.port_listening)
    serverobj.server_activation(serverobj.port_listening2)
    receive = serverobj.receiving()
    if receive:
       serverobj.sending()