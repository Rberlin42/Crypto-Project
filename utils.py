import secrets

def stoo(s):
    """
    stoo = string to ordinal
    converts a string to a number by using the ord() of each character and creating a number from these 8 bit chunks
    inverse of otos
    """
    o = 0
    for i in range(len(s)):
        o |= ord(s[-i-1]) << (i << 3)
    return o

def otos(o, just=None):
    """
    otos = ordinals to string
    converts a number to a string by taking the chr() of each 8 bit chunk
    inverse of stoo
    """
    s = ""
    for i in range(((o.bit_length() - 1) >> 3), -1, -1):
        s += chr((o >> (i << 3)) & 255)
    if just is None:
        return s
    else:
        # option to rjust with 0s to fit a certain byte size
        return s.rjust(just, '\x00')


# Extended Euclidean Algorithm
# m returned is the gcd of the inputs
# x and y terms returned satisfy Bezout's Identity for input m and n (gcd = m*x + n*y)
def gcd_bez(m, n):
    xp, yp = 1, 0
    xc, yc = 0, 1
    while n != 0:
        q, r = divmod(m, n)
        m, n = n, r
        xc, xp = xp - q * xc, xc
        yc, yp = yp - q * yc, yc
    return m, xp, yp

# finds the smallest integer x such that x*x <= n
def int_sqrt(n):
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x


# Miller Rabin primality test with t trials
def MR_primality(n, t):
    if n == 2: return True
    if n % 2 == 0: return False
    k, q = 0, n - 1
    while q & 1 == 0:
        k += 1
        q >>= 1
    for _ in range(t):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, q, n)
        if x == 1 or x == n - 1: continue
        c = False
        for __ in range(k-1):
            x = x * x % n
            if x == n - 1:
                c = True
                break
        if c is True: continue
        return False
    return True

SP1024 = 4769007554006087612783897446215655802380900103982125397609897182072339371415796076879645321640323027911552828720030598492470451640287467698122663638209673066282564948516623920770991570554930096634614611667755427079073059395675817474201509877293697114420249983621890718391291153573883768719

SP1536 = 1986702703336512168974095902608939706708610170125446566276791191028392919262689892163116951551501644525541833425963647884492932731895049578604995902490639831350489038979307041736917350978334543038791565243759379758233150240631768125878167283347243964373887070795008286523027417331996035012486729481999220351500239399470794736803736284731195374070872304241822205235441488062487290791318228783370466500906247363251278998643106771258873772216890032058701533681820523

SP2048 = 20746519106868717022983401189792162608920308969743612231406732764023724791575619681663466471455556700747267828384897087423952030622248946610341198578882283952574519323170177410038116340217274867320059463214232920523774190906203727987539250421969117323992082748514543589945560805424769038759949981276449498133721622778524056464637358057307326855459994593208694119916958474501223450575004871582491185623644377064894932892710085337013632812211050452397585227546038343585075998247973824982450045258626561471104727065822499516021962887308532609360098863385156806140425632615197139453675589873415663803666566386690596359539










