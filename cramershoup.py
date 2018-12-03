from utils import *



def generate(hash_func, N=2048):
    if N == 2048:
        p = SP2048
    elif N == 1536:
        p = SP1536
    elif N == 1024:
        p = SP1024
    else:
        raise ValueError("Number of bits must be 1024, 1536, or 2048, not {}".format(str(N)))
    q = p // 2
    
    while True:
        g1 = pow(secrets.randbelow(p - 3) + 2, p//q, p)
        if g1 != 1: break
    
    while True:
        g2 = pow(secrets.randbelow(p - 3) + 2, p//q, p)
        if g2 != 1 and g2 != g1: break
    
    x1 = secrets.randbelow(q - 2) + 2
    x2 = secrets.randbelow(q - 2) + 2
    y1 = secrets.randbelow(q - 2) + 2
    y2 = secrets.randbelow(q - 2) + 2
    z  = secrets.randbelow(q - 2) + 2
    
    c = pow(g1, x1, p) * pow(g2, x2, p) % p
    d = pow(g1, y1, p) * pow(g2, y2, p) % p
    h = pow(g1, z, p)
    return CramerShoupKeys(p=p, q=q, g1=g1, g2=g2, x1=x1, x2=x2, y1=y1, y2=y2, z=z, c=c, d=d, h=h, hash_func=hash_func)



class CramerShoupKeys:
    def __init__(self, **kwargs):
        # set all the kwargs to attributes
        for attr in kwargs:
            setattr(self, attr, kwargs[attr])
    
    def public(self):
        return CramerShoupKeys(p=p, q=q, g1=g1, g2=g2, c=c, d=d, h=h)
    
    def encrypt(self, plaintext):
        k = random.randint(0, self.q-1)
        u1 = pow(self.g1, k, self.p)
        u2 = pow(self.g2, k, self.p)
        e = pow(self.h, k, self.p) * plaintext % self.p
        
        alpha = self.hash_func(u1 ^ u2 ^ e)
        v = pow(self.c, k, self.p)*pow(self.d, k*alpha, self.p)%self.p
        return u1, u2, e, v
    
    def decrypt(self, ciphertext):
        if not hasattr(self, 'x1'):
            raise AttributeError("No private key to decrypt with.")
        u1, u2, e, v = ciphertext
        alpha = self.hash_func(u1 ^ u2 ^ e)
        
        t = pow(u1, self.y1, self.p)*pow(u2, self.y2, self.p)
        t = pow(t, alpha, self.p)
        v2 = pow(u1, self.x1, self.p)*pow(u2, self.x2, self.p)*t%self.p
        if v != v2:
            raise ValueError('Verification failed.')
        
        w = pow(u1, self.z, self.p)
        w_inv = gcd_bez(w, self.p)[1]
        
        return e*w_inv%self.p


if __name__ == '__main__':
    pass
    