# 独立实现（按 FIPS-197 文字规范）用于交叉验证 C++ 的 AES-256
def xt(a):
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff


def mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = xt(a)
        b >>= 1
    return r


def rot(b, n):
    return ((b << n) | (b >> (8 - n))) & 0xff


sbox = [0] * 256
sbox[0] = 0x63
for i in range(1, 256):
    e = 1
    for x in range(1, 256):
        if mul(x, i) == 1:
            e = x
            break
    sbox[i] = (e ^ rot(e, 1) ^ rot(e, 2) ^ rot(e, 3) ^ rot(e, 4) ^ 0x63) & 0xff

Nk, Nr = 8, 14
key = bytes(range(32))
w = [list(key[4 * i:4 * i + 4]) for i in range(Nk)]
rcon = 1
for i in range(Nk, 4 * (Nr + 1)):
    t = list(w[i - 1])
    if i % Nk == 0:
        t = t[1:] + t[:1]
        t = [sbox[b] for b in t]
        t[0] ^= rcon
        rcon = xt(rcon)
    elif i % Nk == 4:
        t = [sbox[b] for b in t]
    w.append([w[i - Nk][j] ^ t[j] for j in range(4)])


def enc(block):
    # s[r][c]
    s = [[block[c * 4 + r] for c in range(4)] for r in range(4)]

    def addrk(rnd):
        for c in range(4):
            for r in range(4):
                s[r][c] ^= w[rnd * 4 + c][r]

    addrk(0)
    for rnd in range(1, Nr):
        for r in range(4):
            s[r] = [sbox[x] for x in s[r]]
        for r in range(1, 4):
            s[r] = s[r][r:] + s[r][:r]
        for c in range(4):
            a = [s[r][c] for r in range(4)]
            s[0][c] = mul(a[0], 2) ^ mul(a[1], 3) ^ a[2] ^ a[3]
            s[1][c] = a[0] ^ mul(a[1], 2) ^ mul(a[2], 3) ^ a[3]
            s[2][c] = a[0] ^ a[1] ^ mul(a[2], 2) ^ mul(a[3], 3)
            s[3][c] = mul(a[0], 3) ^ a[1] ^ a[2] ^ mul(a[3], 2)
        addrk(rnd)
    for r in range(4):
        s[r] = [sbox[x] for x in s[r]]
    for r in range(1, 4):
        s[r] = s[r][r:] + s[r][:r]
    addrk(Nr)
    out = bytearray()
    for c in range(4):
        for r in range(4):
            out.append(s[r][c])
    return bytes(out)


pt = bytes.fromhex('00112233445566778899aabbccddeeff')
print('AES-256 ECB ct =', enc(pt).hex())
print('FIPS-197 C.3   = 8ea2b7ca516745bfeea449fc1b16249d')
print('sbox[0x00]=%02x sbox[0x01]=%02x sbox[0x53]=%02x sbox[0xff]=%02x' %
      (sbox[0], sbox[1], sbox[0x53], sbox[0xff]))
