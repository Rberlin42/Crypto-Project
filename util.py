import random
import json
import string
import secrets

def encode_dict(packet):
    """
    For use with sending a packet over the wire.
    """
    packet = json.dumps(packet)
    packet = packet.encode('ascii')
    return packet

def decode_dict(packet):
    """
    For use with recv'ing a packet over the wire.
    """
    packet = packet.decode('ascii')
    packet = json.loads(packet)
    return packet

def gen_sym_key(len):
    # Generate len bits for key
    key = secrets.randbits(len)
    return key

def compute_HMAC(sym_key, compressed, alg_handler):
    """
    Compute the hashed MAC value
    """
    # print(self.sym_key)
    # half_1 = self.convert_to_int(self.sym_key)
    half_1 = str(sym_key)

    compressed_num = int.from_bytes(compressed, byteorder='big')
    half_2 = half_1 + str(len(compressed)) + str(compressed_num)

    combined = int(half_1 + half_2)
    HMAC = alg_handler.hash(combined)
    return HMAC

    # for i in range(6):
    #     password += secrets.choice(stringSource)
    # char_list = list(password)
    # secrets.SystemRandom().shuffle(char_list)
    # password = ''.join(char_list)
    # print ("Secure Password is ", password)

# def parse_secret_key(key_num, key_letter):
#     key_num_domain = [0, 1, 2, 3]
#
#     if int(key_num) not in key_num_domain:
#         print("key_num should be 0, 1, 2, or 3")
#         sys.exit()
#
#     if len(key_letter) != 1:
#         print("key_letter should only be one character")
#         sys.exit()
#
#     key = (int(key_num) << 8) | ord(key_letter)
#
#     return key
