from tables import *

def to_blocks(message):
    if len(message) < 16:
        message.extend([ 0 ] * (16 - len(message))) # black magic
        return [ message ]
    else:
        return [ message[:16] ] + to_blocks(message[16:]) if len(message) > 16 else [ message[:16 ] ]

def transform(b): # even more black magic
    b[0], b[4], b[8], b[12], \
    b[1], b[5], b[9], b[13], \
    b[2], b[6], b[10], b[14], \
    b[3], b[7], b[11], b[15] = b

# takes a key(list) and expands it from 16 bytes to 176 bytes
def expand_key(key):
    Nk = 4
    key_size = Nk * 4
    new_key_size = 176       # new_key_size = sizeof(dword)*Nb*(Nr+1) = 4*4*11
    key.extend([0] * (new_key_size - key_size))

    for current_size in xrange(key_size,new_key_size, 4):
        temp = key[current_size-4:current_size]
        if (current_size/4) % Nk == 0:
            temp = sub_bytes(rot_word(temp))
            temp[0] = temp[0] ^ rcon[(current_size/4)/Nk]
        for i in xrange(4):
            key[current_size+i] = key[current_size-(key_size)+i] ^ temp[i]

    return to_blocks(key)

def sub_bytes(block):
    for i in xrange(len(block)):
        block[i] = sbox[block[i]]
    return block

def rot_word(block):
    return block[1:] + block[:1]

def add_round_key(block, round_key):
    key = list(round_key)
    transform(key)
    for i in xrange(len(block)):
        block[i] = (block[i] & 0xFF) ^ (key[i] & 0xFF)

def mix_columns(b):
    cpy = list(b)
    for i in xrange(4):
        cpy[i + 0]  = (mul(b[i + 0], 2) & 0xFF) ^ (mul(b[i + 4], 3) & 0xFF) ^ (mul(b[i + 8], 1) & 0xFF) ^ (mul(b[i + 12], 1) & 0xFF)
        cpy[i + 4]  = (mul(b[i + 0], 1) & 0xFF) ^ (mul(b[i + 4], 2) & 0xFF) ^ (mul(b[i + 8], 3) & 0xFF) ^ (mul(b[i + 12], 1) & 0xFF)
        cpy[i + 8]  = (mul(b[i + 0], 1) & 0xFF) ^ (mul(b[i + 4], 1) & 0xFF) ^ (mul(b[i + 8], 2) & 0xFF) ^ (mul(b[i + 12], 3) & 0xFF)
        cpy[i + 12] = (mul(b[i + 0], 3) & 0xFF) ^ (mul(b[i + 4], 1) & 0xFF) ^ (mul(b[i + 8], 1) & 0xFF) ^ (mul(b[i + 12], 2) & 0xFF)

    for i in xrange(len(cpy)):
        b[i] = cpy[i]

def shift_rows(b):
    b[0],  b[1],  b[2],  b[3]  = b[0],  b[1],  b[2],  b[3]
    b[4],  b[5],  b[6],  b[7]  = b[5],  b[6],  b[7],  b[4]
    b[8],  b[9],  b[10], b[11] = b[10], b[11], b[8],  b[9]
    b[12], b[13], b[14], b[15] = b[15], b[12], b[13], b[14]

def encrypt_block(block, key):
    round_keys = expand_key(map(ord, key))

    # Initial Round
    add_round_key(block, round_keys[0])

    # Rounds
    for i in xrange(1, 10):
        sub_bytes(block)
        shift_rows(block)
        mix_columns(block)
        add_round_key(block, round_keys[i])

    # Final Round
    sub_bytes(block)
    shift_rows(block)
    add_round_key(block, round_keys[10])

# Decryption methods start here (move to new module?)

def decrypt_block(block, key):
    round_keys = expand_key(map(ord, key))

    # Initial Round
    add_round_key(block, round_keys[10])

    # Rounds
    for i in xrange(9, 0, -1):
        inv_shift_rows(block)
        inv_sub_bytes(block) # inv_sub_bytes(block)
        add_round_key(block, round_keys[i])
        inv_mix_columns(block)

    # Final Round
    inv_shift_rows(block)
    inv_sub_bytes(block)
    add_round_key(block, round_keys[0])

# shift now 1, 2 or 3 to right
def inv_shift_rows(b):
    #b[0],  b[1],  b[2],  b[3]  = b[0],  b[1],  b[2],  b[3]
    b[4],  b[5],  b[6],  b[7]  = b[7],  b[4],  b[5],  b[6]
    b[8],  b[9],  b[10], b[11] = b[10], b[11], b[8],  b[9]
    b[12], b[13], b[14], b[15] = b[13], b[14], b[15], b[12]

def inv_mix_columns(b):
    cpy = list(b)
    for i in xrange(4): # for each column
        # checken, wieso mul
        cpy[i + 0]  = (mul(b[i + 0], 0xE) & 0xFF) ^ (mul(b[i + 4], 0xB) & 0xFF) ^ (mul(b[i + 8], 0xD) & 0xFF) ^ (mul(b[i + 12], 0x9) & 0xFF)
        cpy[i + 4]  = (mul(b[i + 0], 0x9) & 0xFF) ^ (mul(b[i + 4], 0xE) & 0xFF) ^ (mul(b[i + 8], 0xB) & 0xFF) ^ (mul(b[i + 12], 0xD) & 0xFF)
        cpy[i + 8]  = (mul(b[i + 0], 0xD) & 0xFF) ^ (mul(b[i + 4], 0x9) & 0xFF) ^ (mul(b[i + 8], 0xE) & 0xFF) ^ (mul(b[i + 12], 0xB) & 0xFF)
        cpy[i + 12] = (mul(b[i + 0], 0xB) & 0xFF) ^ (mul(b[i + 4], 0xD) & 0xFF) ^ (mul(b[i + 8], 0x9) & 0xFF) ^ (mul(b[i + 12], 0xE) & 0xFF)

    for i in xrange(len(cpy)):
        b[i] = cpy[i]

def inv_sub_bytes(b):
    for i in xrange(len(b)):
        b[i] = inv_sbox[b[i]]

def mul(a, b):
    return exp_table[(log_table[a] + log_table[b]) % 255] if a and b else 0
