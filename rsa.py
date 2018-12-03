from utils import *
# going to need a sha1 import

def create_RSA_prime(lo, hi):
    mid = (lo + hi) // 2
    a = secrets.randbits(mid.bit_length()//2)
    a = 2*(a//2) + 1
    while not MR_primality(a, 50):
        a += 2
    k = secrets.randbelow(hi//a - lo//a) + lo//a
    k = 2*(k//2)
    while not MR_primality(k*a + 1, 50):
        k += 2
    return k*a + 1

def create_RSA_primes(N):
    while True:
        p = create_RSA_prime( 1 << (N//2 - 1), 1 << (N//2) )
        q = create_RSA_prime( (1 << (N - 1))//p, (1 << N)//p )
        if abs(p-q) > 2*int_sqrt(int_sqrt(p*q)):
            break
    return p, q

# generates the RSA keys for a bitlength of N and an optional hash function to make it semantically secure
def generate(N, hash_func=None):
    p, q = create_RSA_primes(N)
    n = p*q
    phi = (p - 1)*(q - 1)
    while True:
        e = secrets.randbelow(phi - 5) + 5
        gcd, x, y = gcd_bez(e, phi)
        if gcd == 1:
            d = x % phi
            if d > int_sqrt(int_sqrt(n))//3:
                break
    return RSAKeys(p=p, q=q, n=n, e=e, d=d, hash_func=hash_func)


class RSAKeys:
    def __init__(self, **kwargs):
        # set all the kwargs to attributes
        for attr in kwargs:
            setattr(self, attr, kwargs[attr])
    
    def public(self):
        return RSAKeys(n=self.n, e=self.e, hash_func=self.hash_func)
    
    def encrypt(self, plaintext):
        if self.hash_func is not None:
            #r = random.randint(2, self.n - 2)
            r = secrets.randbelow(self.n - 3) + 2
            return (pow(r, self.e, self.n), self.hash_func(r, self.n.bit_length()) ^ plaintext)
        else:
            return pow(plaintext, self.e, self.n)
    
    def decrypt(self, ciphertext):
        if not hasattr(self, 'd'):
            raise AttributeError("No private key to decrypt with.")
        if self.hash_func is not None:
            return self.hash_func(pow(ciphertext[0], self.d, self.n), self.n.bit_length()) ^ ciphertext[1]
        else:
            return pow(ciphertext, self.d, self.n)


def sha1_mult(m, bits):
    num_chunks = bits // 160 + (1 if bits % 160 != 0 else 0)
    mask = (1 << 160) - 1
    r = 0
    for i in range(num_chunks):
        t = sha1(m & mask)
        r |= t << (160*i)
        m >>= 160
    return r




'''
to generate a 2048 bit key
>>> kr = generate(2048)

to extract the public component to send
>>> ku = kr.public()

takes a plaintext integer M and encrypts as
>>> C = ku.encrypt(M)

which can be decrypted as
>>> P = kr.decrypt(C)

'''


if __name__ == '__main__':
    kr = generate(2048, sha1_mult)
    pass