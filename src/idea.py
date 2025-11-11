MOD_ADD = 1 << 16          # 65536
MOD_MUL = (1 << 16) + 1    # 65537

def _add(a, b):
    return (a + b) & 0xFFFF

def _mul(a, b):
    if a == 0:
        a = MOD_MUL - 1
    if b == 0:
        b = MOD_MUL - 1
    r = (a * b) % MOD_MUL
    return 0 if r == MOD_MUL - 1 else r

def _rol(v, n, bits):
    n %= bits
    mask = (1 << bits) - 1
    return ((v << n) & mask) | ((v & mask) >> (bits - n))

def _to_words(block8):
    return [(block8[0] << 8) | block8[1],
            (block8[2] << 8) | block8[3],
            (block8[4] << 8) | block8[5],
            (block8[6] << 8) | block8[7]]

def _from_words(w):
    return bytes([(w[0] >> 8) & 0xFF, w[0] & 0xFF,
                  (w[1] >> 8) & 0xFF, w[1] & 0xFF,
                  (w[2] >> 8) & 0xFF, w[2] & 0xFF,
                  (w[3] >> 8) & 0xFF, w[3] & 0xFF])

def _key_schedule(key16):
    if len(key16) != 16:
        raise ValueError("Key must be 16 bytes (128 bits).")
    K = int.from_bytes(key16, "big")
    sub = []
    while len(sub) < 52:
        for off in range(0, 128, 16):
            if len(sub) >= 52:
                break
            val = (K >> (128 - 16 - off)) & 0xFFFF
            sub.append(val)
        K = _rol(K, 25, 128)
    return sub

def _inv(x):
    if x == 0:
        return 0
    t, newt = 0, 1
    r, newr = MOD_MUL, x
    while newr != 0:
        q = r // newr
        t, newt = newt, t - q * newt
        r, newr = newr, r - q * newr
    if r > 1:
        return 0
    if t < 0:
        t += MOD_MUL
    return t if t != MOD_MUL - 1 else 0

def _dec_subkeys(enc):
    d = [0] * 52
    p = 48
    d[48] = _inv(enc[0])
    d[49] = (-enc[1]) & 0xFFFF
    d[50] = (-enc[2]) & 0xFFFF
    d[51] = _inv(enc[3])
    for r in range(7, -1, -1):
        e0, e1, e2, e3, e4, e5 = enc[r*6:(r+1)*6]
        d[p-6] = _inv(e0)
        d[p-5] = (-e2) & 0xFFFF
        d[p-4] = (-e1) & 0xFFFF
        d[p-3] = _inv(e3)
        if r != 0:
            d[p-2] = e4
            d[p-1] = e5
        p -= 6
    return d

def encrypt_block(block8, sub):
    if len(block8) != 8:
        raise ValueError("Block must be 8 bytes (64 bits).")
    X1, X2, X3, X4 = _to_words(block8)
    for r in range(8):
        k0, k1, k2, k3, k4, k5 = sub[r*6:(r+1)*6]
        X1 = _mul(X1, k0)
        X2 = _add(X2, k1)
        X3 = _add(X3, k2)
        X4 = _mul(X4, k3)
        t0 = _mul(k4, X1 ^ X3)
        t1 = _mul(k5, _add(X2 ^ X4, t0))
        t2 = _add(t0, t1)
        X1 ^= t1
        X4 ^= t2
        X2, X3 = (X3 ^ t1), (X2 ^ t2)
    k0, k1, k2, k3 = sub[48:52]
    Y1 = _mul(X1, k0)
    Y2 = _add(X3, k1)
    Y3 = _add(X2, k2)
    Y4 = _mul(X4, k3)
    return _from_words((Y1, Y2, Y3, Y4))

def decrypt_block(block8, sub):
    dsk = _dec_subkeys(sub)
    return encrypt_block(block8, dsk)

def expand_key(key16):
    return _key_schedule(key16)


if __name__ == "__main__":
    # Inserir manualmente a chave e o texto
    chave_hex = input("Digite a chave (16 bytes em HEX, ex: 00112233445566778899AABBCCDDEEFF): ").strip()
    texto_hex = input("Digite o texto (8 bytes em HEX, ex: 0123456789ABCDEF): ").strip()

    key = bytes.fromhex(chave_hex)
    plaintext = bytes.fromhex(texto_hex)

    sub = expand_key(key)
    cifrado = encrypt_block(plaintext, sub)
    decifrado = decrypt_block(cifrado, sub)

    print("\nTexto Original :", plaintext.hex().upper())
    print("Texto Cifrado  :", cifrado.hex().upper())
    print("Texto Decifrado:", decifrado.hex().upper())
