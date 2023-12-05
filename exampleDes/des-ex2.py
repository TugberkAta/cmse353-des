KEY = "F7AC7D10C9F8145F"
M = "TestStringPlease@DontIgnore!"

# Permuted Choice 1
PC1 = (57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4)

# Permuted Choice 2
PC2 = (14, 17, 11, 24, 1, 5,
       3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32)

# Initial Permutation
IP = (58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7)

# Expansion
E = (32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1)

# Substitution Boxes
SBOX = {
    0: (14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13),
    
    1: (15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9),

    2: (10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12),

    3: (7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14),

    4: (2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3),

    5: (12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13),

    6: (4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12),

    7: (13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11)
    }

# Permutation
P = (16, 7, 20, 21,
     29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2, 8, 24, 14,
     32, 27, 3, 9,
     19, 13, 30, 6,
     22, 11, 4, 25)

# Final Permutation
IP_FINAL = (40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25)

def binary(i, length):
    # Convert an int to binary while keeping leading zeroes
    return bin(i)[2:].zfill(length)

def hex2int(h):
    return int(h, 16)

def int2hex(i):
    return hex(i)[2:]

def str2int(s):
    s = s.encode()
    return int(s.hex(), 16)

def hex2str(h):
    return bytearray.fromhex(h).decode()

def lst2int(lst):
    # Binary list to int
    return int(''.join(lst), 2)

def split(block, length):
    h1 = block >> length
    h2 = block & (2**length-1)
    return h1, h2
    
def permute(block, length, table):
    result = []
    binary_block = binary(block, length)
    for i in range(len(table)):
        result.append(binary_block[table[i] - 1])
    return lst2int(result)

def rol(block, bits, length):
    # Circular shift left with support for arbitrary lengths
    return (block << bits % length) & (2**length-1) | \
           (block & (2**length-1)) >> (length - (bits%length))

def calc_sub_keys(c0, d0):
    keys = []
    left_shifts = (1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1)

    keys.append((c0, d0))

    for i in range(16):
        bits = left_shifts[i]  
        c = rol(keys[i][0], bits, 28)
        d = rol(keys[i][1], bits, 28)
        keys.append((c, d))

    del keys[0]

    for i, (c, d) in enumerate(keys):
        cd = (c << 28) + d
        keys[i] = permute(cd, 56, PC2)
        
    return keys

def split_r(r):
    # 0b111111 = 63
    # Loop range ends at -1 because of r >> 0
    return [(r >> x) & 63 for x in range(42, -1, -6)]

def apply_sub_keys(l, r, subkeys, decrypt):
    for i in range(16):     
        if decrypt: i = 15-i

        r_last = r
        r = permute(r, 32, E)
        r ^= subkeys[i]
        
        blocks = split_r(r)
        
        for j, block in enumerate(blocks):
            # Row - Combine 1st and 6th bit of block
            row = (1 & block) + ((32 & block) >> 4)
            # Col - 2nd through 5th bits of block, so 30 (0b11110)
            col = (30 & block) >> 1
            # Tuples are one-dimensional therefore row = 16*row
            blocks[j] = SBOX[j][16*row+col]

        # Concentrate blocks
        r = 0
        j = 28
        for block in blocks:
            r += (block << j)
            j -= 4

        r = permute(r, 32, P)
        r ^= l
        l = r_last
        
    cipher_block = (r << 32) + l
    cipher_block = permute(cipher_block, 64, IP_FINAL)
    return cipher_block

def encrypt(m, key):
    key = hex2int(key)
    blocks = des(m, key)

    c = []
    for block in blocks:
        c.append(int2hex(block))
    return ''.join(c)
        

def decrypt(c, key):
    key = hex2int(key)
    blocks = des(c, key, True)

    m = []
    for block in blocks:
        m.append(hex2str(int2hex(block)))
    return ''.join(m)

def des(m, key, decrypt=False):
    key = permute(key, 64, PC1)
    c0, d0 = split(key, 28)

    sub_keys = calc_sub_keys(c0, d0)

    cipher_blocks = []

    # Split the message in:
    # 8 character blocks when encrypting.
    # 16 character blocks (hex) when decrypting.
    n = 8 if not decrypt else 16
    blocks = [m[i:i+n] for i in range(0, len(m), n)]
        
    for block in blocks:
        if decrypt:
            block = hex2int(block)
        else:
            block = str2int(block)
        
        block = permute(block, 64, IP)
        l, r = split(block, 32)
        cipher_block = apply_sub_keys(l, r, sub_keys, decrypt)
        
        cipher_blocks.append(cipher_block)      
    return cipher_blocks

if __name__ == "__main__":
    print("Message: " + M)
    
    c = encrypt(M, KEY)
    print("Ciphertext (hex): " + c)
    
    m = decrypt(c, KEY)
    print("Plaintext: " + m)