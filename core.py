from tables import *
from math import ceil

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
    xorBlocks(block, key)

def xorBlocks(block, key):
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
    round_keys = expand_key(hex_to_list(key))

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
    #round_keys = expand_key(map(ord, key))
    round_keys = expand_key(hex_to_list(key))

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

def hex_to_unicode(hexmessage):
    return ''.join(map(unichr, [ int(hexmessage[i], 16) * 16 + int(hexmessage[i + 1], 16) for i in xrange(0, len(hexmessage), 2) ]))

def hex_to_list(key):
    return [ int(key[i], 16) * 16 + int(key[i+1], 16) for i in xrange(0, len(key), 2) ]

def list_to_hex(list):
    return ''.join([ (hex(item)[2:] if len(hex(item)[2:]) > 1 else '0' + hex(item)[2:]) for item in list ])
#
# CMAC-PART
#
# Just another fancy hashtag
# TODO: Overhaul the aes_cmac code for simplification

# Implementation according to http://tools.ietf.org/html/rfc4493#section-1
# and in obedience of http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf
def generate_subkeys(key):
    block = [0x00]*16
    transform(block)
    encrypt_block(block, key)
    transform(block)

    key1 = create_subkey(list(block), (block[0]&0x80)!=0)
    key2 = create_subkey(list(key1),  (key1[0] &0x80)!=0)
    return (key1,key2)

def create_subkey(key, msb_of_key_is_set):
    shift_array(key,1)
    if msb_of_key_is_set:
        key[-1] ^= 0x87 # Rb_const
    return key

def shift_array(block, shift_num):
    last_msb = 0x00
    for i in reversed(range(len(block))):
        new_msb = block[i] & 0x80
        block[i] = (block[i] << shift_num) & 0xFF if last_msb == 0 else ((block[i] << shift_num) | 0x01) & 0xFF
        last_msb = new_msb

# Output is message authentification code
def aes_cmac(key, message):
    const_bsize = 16
    k1, k2 = generate_subkeys(key)

    blocks = to_blocks(map(ord, message))
    if (len(message) % const_bsize != 0):
        blocks[-1][(len(message) % const_bsize)] |= 0x80
    elif len(message) == 0:
        blocks[0][0] |= 0x80

    leng = len(message)
    chosen_key = k1 if len(message) != 0 and len(message) % const_bsize == 0 else k2
    for i in range(16):
        blocks[-1][i] ^= chosen_key[i]

    y = [0x00]*16
    for i in range(len(blocks)):
        if i != 0:
            for j in range(16):
                blocks[i][j] = blocks[i-1][j] ^ blocks[i][j]
        transform(blocks[i])
        encrypt_block(blocks[i],key)
        transform(blocks[i])

    return blocks[-1]

def cmac_verify(key,message,cmac):
    return aes_cmac(key,message) == cmac