import sha1
import des
import rsa

class AlgHandler:
    """
    Handles the various cryptographic algorithms based on cipher suite.
    Cipher suite is provided to constructor
    """
    def __init__(self, sym_key, key_exc, hash):
        self.sym_key_alg = sym_key
        self.key_exc_alg = key_exc
        self.hash_alg = hash

    def gen_asym_keys(self):
        if self.key_exc_alg == "rsa":
            self.my_kr = rsa.generate(2048)

    def get_my_pub_key(self):
        if self.key_exc_alg == "rsa":
            n = self.my_kr.public().n
            e = self.my_kr.public().e
            return (n, e)

    def set_their_pub_key(self, public):
        if self.key_exc_alg == "rsa":
            (n, e) = public
            self.their_ku = rsa.RSAKeys(n=n, e=e, hash_func=None)

    def hash(self, value):
        ret_val = 0
        if self.hash_alg == "sha1":
            ret_val = sha1.hash(value)
        return ret_val

    def sym_encrypt(self, key, msg):
        cipher = 0
        if self.sym_key_alg == "des":
            cipher = des.encrypt(key, msg)
        return cipher

    def sym_decrypt(self, key, encrypted):
        plain = 0
        if self.sym_key_alg == "des":
            plain = des.decrypt(key, encrypted)
        return plain

    def asym_encrypt(self, msg):
        cipher = 0
        if self.key_exc_alg == "rsa":
            cipher = self.their_ku.encrypt(msg)
        return cipher

    def asym_decrypt(self, msg):
        plain = 0
        if self.key_exc_alg == "rsa":
            plain = self.my_kr.decrypt(msg)
        return plain
