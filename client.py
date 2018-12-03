import socket
import sys
import time
import random
import json
import gzip
import pickle

from util import encode_dict, decode_dict, gen_sym_key, compute_HMAC
from alg_handler import AlgHandler

class Client:
    def __init__(self):
        self.srv_address = ('localhost', 42010)

    def connect_to_server(self):
        self.srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv_sock.connect(self.srv_address)

    def send_hello(self):
        """
        Send initial hello packet to server
        """
        packet = {'type': 'hello'}
        packet = encode_dict(packet)
        self.srv_sock.sendall(packet)

    def recv_hello(self):
        """
        Receive hello packet; if reply packet was not hello, then abort
        TODO: replace with abort protocol
        """
        packet = self.srv_sock.recv(20000)
        packet = decode_dict(packet)
        if packet['type'] != "hello":
            print("No hello recv'd!")
            sys.exit()

    def send_suite(self):
        """
        Send cipher suite to server
        """
        packet = {'type': 'suite'}
        packet['sym_key'] = ['des']
        packet['key_exc'] = ['rsa']
        packet['hash'] = ['sha1']
        packet = encode_dict(packet)
        self.srv_sock.sendall(packet)

    def recv_suite(self):
        """
        Recv selected cipher suite from server
        """
        packet = self.srv_sock.recv(20000)
        packet = decode_dict(packet)
        sk = packet['sym_key']
        ke = packet['key_exc']
        h = packet['hash']
        self.alg_handler = AlgHandler(sk, ke, h)

    def send_key_exc(self):
        """
        Generate public keys and send to server
        """
        self.alg_handler.gen_asym_keys()
        packet = {'type': 'key_exc'}
        (n, e) = self.alg_handler.get_my_pub_key()
        packet['public_key_1'] = n
        packet['public_key_2'] = e
        packet = encode_dict(packet)
        self.srv_sock.sendall(packet)

    def recv_key_exc(self):
        """
        Recv public key from server
        """
        packet = self.srv_sock.recv(20000)
        packet = decode_dict(packet)
        n = packet['public_key_1']
        e = packet['public_key_2']
        self.alg_handler.set_their_pub_key((n,e))

    def encrypt_sym_key(self, sym_key):
        return self.alg_handler.asym_encrypt(sym_key)

    def send_sym_key(self):
        """
        Generate symmetric key for session and send to server
        """
        self.sym_key = gen_sym_key(168)
        e_sym_key = self.encrypt_sym_key(self.sym_key)
        packet = {'type': 'sym_key'}
        packet['key'] = e_sym_key
        packet = encode_dict(packet)
        self.srv_sock.sendall(packet)

    def recv_ack(self):
        """
        Recv ACK from server
        """
        packet = self.srv_sock.recv(20000)
        packet = decode_dict(packet)
        print("Handshake complete")

    def convert_to_int(self, text):
        return "".join(str(ord(char)) for char in text)

    def send_msg(self, msg):
        """
        Compress, hash, and encrypt msg. Then, send to server.
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
        self.srv_sock.sendall(packet)

    def verify_MAC(self, HMAC, compressed):
        local_HMAC = compute_HMAC(self.sym_key, compressed, self.alg_handler)
        return HMAC == local_HMAC

    def recv_msg(self):
        """
        Recv msg from server
        """
        packet = self.srv_sock.recv(20000)
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

        print("Received msg from server:", msg)

    def end_conn(self):
        self.srv_sock.close()

if __name__ == "__main__":
    client = Client()
    client.connect_to_server()

    """
    Handshake
    """
    # Exchange Hello
    client.send_hello()
    client.recv_hello()

    # Exchange CipherSuite
    client.send_suite()
    client.recv_suite()

    # Exchange public keys
    client.send_key_exc()
    client.recv_key_exc()

    # Give symmetric key and recv ACK
    client.send_sym_key()
    client.recv_ack()

    """
    Message Passing
    """
    msg = ""
    while msg != "quit":
        msg = input("Enter msg to send: ")
        if msg == "quit":
            client.end_conn()
            break
        client.send_msg(msg)
        client.recv_msg()
