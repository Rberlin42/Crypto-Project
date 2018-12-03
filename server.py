import pickle
import socket
import sys
import time
import random
import json
import gzip

from util import encode_dict, decode_dict, compute_HMAC
from alg_handler import AlgHandler

class Server:
    def __init__(self):
        self.srv_address = ('localhost', 42010)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(self.srv_address)
        self.sock.listen(1)
        print("SSL Server started at", self.srv_address)
        # self.kdc_address_1 = ('localhost', 42011)
        # self.kdc_address_2 = ('localhost', 42009)
        # self.alice_address = ('localhost', 42010)
        # self.bob_address = ('localhost', 42012)

    def accept_cli(self):
        """
        Accepts new incoming client connection
        """
        while True:
            # Blocking call for a connection
            conn, client_address = self.sock.accept()
            try:
                print('Incoming client:', client_address)
                print('Connection:', conn)

                # Exchange Hello
                self.recv_hello(conn)
                self.send_hello(conn)

                # Exchange CipherSuite
                self.recv_suite(conn)
                self.send_suite(conn)

                # Exchange public keys
                self.recv_key_exc(conn)
                self.send_key_exc(conn)

                # Recv sym key and send ACK
                self.recv_sym_key(conn)
                self.send_ACK(conn)

                msg = ""
                while msg != "quit":
                    self.recv_msg(conn)
                    msg = input("Enter msg to send: ")
                    if msg == "quit":
                        break
                    self.send_msg(conn, msg)

                # packet = decode_dict(packet)
                # self.decode_packet(packet, connection)
                #
                # # Check if DH done, move on to NS part
                # alice_done = 'secret_s' in self.dh_dict['alice']
                # bob_done = 'secret_s' in self.dh_dict['bob']
                # if alice_done and bob_done:
                #     # Tell alice to begin NS with bob
                #     self.sock.close()
                #     self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                #     self.sock.bind(self.kdc_address_2)
                #     time.sleep(5)
                #     self.sock.connect(self.alice_address)
                #     self.handle_NS()
                #     break
            finally:
                print("Closing connection...")
                conn.close()

    def send_hello(self, conn):
        """
        Send response hello packet to client
        """
        packet = {'type': 'hello'}
        packet = encode_dict(packet)
        conn.sendall(packet)

    def recv_hello(self, conn):
        """
        Receive initial hello packet; if reply packet was not hello, then abort
        TODO: replace with abort protocol
        """
        packet = conn.recv(20000)
        packet = decode_dict(packet)
        if packet['type'] != "hello":
            print("No hello recv'd!")
            sys.exit()

    def send_suite(self, conn):
        """
        Send selected cipher suite to client
        """
        packet = {'type': 'suite'}
        packet['sym_key'] = self.alg_handler.sym_key_alg
        packet['key_exc'] = self.alg_handler.key_exc_alg
        packet['hash'] = self.alg_handler.hash_alg
        packet = encode_dict(packet)
        conn.sendall(packet)

    def recv_suite(self, conn):
        """
        Recv cipher suite from client
        """
        packet = conn.recv(20000)
        packet = decode_dict(packet)
        sk = packet['sym_key'][0]
        ke = packet['key_exc'][0]
        h = packet['hash'][0]
        self.alg_handler = AlgHandler(sk, ke, h)

    def send_key_exc(self, conn):
        """
        Generate public keys and send to client
        """
        self.alg_handler.gen_asym_keys()
        packet = {'type': 'key_exc'}
        (n, e) = self.alg_handler.get_my_pub_key()
        packet['public_key_1'] = n
        packet['public_key_2'] = e
        packet = encode_dict(packet)
        conn.sendall(packet)

    def recv_key_exc(self, conn):
        """
        Recv public key from client
        """
        packet = conn.recv(20000)
        packet = decode_dict(packet)
        n = packet['public_key_1']
        e = packet['public_key_2']
        self.alg_handler.set_their_pub_key((n,e))

    def send_ACK(self, conn):
        packet = {'type': 'ACK'}
        packet = encode_dict(packet)
        packet = conn.sendall(packet)
        print("Handshake complete")

    def decrypt_sym_key(self, e_sym_key):
        """
        TODO: use RSA.decrypt(e_sym_key) here...
        """
        return self.alg_handler.asym_decrypt(e_sym_key)

    def recv_sym_key(self, conn):
        """
        Recv symmetric key from client
        """
        packet = conn.recv(20000)
        packet = decode_dict(packet)
        e_sym_key = packet['key']
        self.sym_key = self.decrypt_sym_key(e_sym_key)

    def verify_MAC(self, HMAC, compressed):
        local_HMAC = compute_HMAC(self.sym_key, compressed, self.alg_handler)
        return HMAC == local_HMAC

    def send_msg(self, conn, msg):
        """
        Compress, hash, and encrypt msg. Then, send to client.
        """
        msg_bytes = msg.encode()
        compressed = gzip.compress(msg_bytes)

        HMAC = compute_HMAC(self.sym_key, compressed, self.alg_handler)
        compressed_num = int.from_bytes(compressed, byteorder='big')
        encrypted = self.alg_handler.sym_encrypt(self.sym_key, compressed_num)

        packet = {'type': msg}
        packet['msg'] = encrypted
        packet['num_bytes'] = len(compressed)
        packet['MAC'] = HMAC

        packet = encode_dict(packet)
        conn.sendall(packet)

    def recv_msg(self, conn):
        """
        Recv msg from client
        """
        packet = conn.recv(20000)
        # Client terminated connection
        if packet.decode('ascii') == "":
            sys.exit()
        packet = decode_dict(packet)

        encrypted = packet['msg']
        num_bytes = packet['num_bytes']
        HMAC = packet['MAC']

        decrypted = self.alg_handler.sym_decrypt(self.sym_key, encrypted)
        compressed = decrypted.to_bytes(num_bytes, byteorder='big')
        msg_bytes = gzip.decompress(compressed)
        msg = msg_bytes.decode('ascii')

        verified = self.verify_MAC(HMAC, compressed)
        print("MAC verified:", verified)
        if verified == False:
            sys.exit()

        print("Received msg from client:", msg)

if __name__ == "__main__":
    server = Server()
    server.accept_cli()
