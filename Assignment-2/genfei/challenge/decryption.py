from struct import pack, unpack


def F(w):
    return ((w * 31337) ^ (w * 1337 >> 16)) % 2 ** 32


def decrypt(block):
    a, b, c, d = unpack("<4I", block)
    for rno in range(32):
        # Decrypting the following ecryption equation
        ##a, b, c, d = c ^ F(d | F(b ^ F(a)) ^ F(d | b) ^ a), b ^ F(d ^ F(a) ^ (d | a)), a ^ F(d | F(d) ^ d), d ^ 1337
        tmp = a
        d = d ^ 1337
        a = c ^ F(d | F(d) ^ d)
        b = b ^ F(d ^ F(a) ^ (d | a))
        c = tmp ^ F(d | F(b ^ F(a)) ^ F(d | b) ^ a)
        # Decrypting the following ecryption equation
        # a, b, c, d = b ^ F(a | F(c ^ F(d)) ^ F(a | c) ^ d), c ^ F(a ^ F(d) ^ (a | d)), d ^ F(a | F(a) ^ a), a ^ 31337
        tmp = a
        a = d ^ 31337
        d = c ^ F(a | F(a) ^ a)
        c = b ^ F(a ^ F(d) ^ (a | d))
        b = tmp ^ F(a | F(c ^ F(d)) ^ F(a | c) ^ d)
    return pack("<4I", a, b, c, d)


ct = open("flag.enc", "rb").read()
pt = b"".join(decrypt(ct[i:i + 16]) for i in range(0, len(ct), 16))
open("decryptedFlag.txt", "wb").write(pt)
