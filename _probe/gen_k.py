def icbrt(n):
    lo, hi = 0, 1
    while hi ** 3 <= n:
        hi *= 2
    while lo + 1 < hi:
        m = (lo + hi) // 2
        if m ** 3 <= n:
            lo = m
        else:
            hi = m
    return lo


def primes(c):
    r = []
    v = 2
    while len(r) < c:
        if all(v % p for p in r if p * p <= v):
            r.append(v)
        v += 1
    return r


P = primes(64)
K = [icbrt(p << 96) - icbrt(p) * (1 << 32) for p in P]
lines = []
for i in range(0, 64, 8):
    lines.append('    ' + ' '.join('0x%08xu,' % k for k in K[i:i + 8]))
lines[-1] = lines[-1].rstrip(',')
body = chr(10).join(lines)
open('ktable.txt', 'w').write(body)
print(body)
print('K[0]=0x%08x K[8]=0x%08x K[63]=0x%08x' % (K[0], K[8], K[63]))
