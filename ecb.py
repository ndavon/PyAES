import core
import base64
import itertools
import struct
import sys

testMessage = "Hallo"
testKey = "0123456789abcdef"

def encrypt(message, key, b64=False):
    # convert message to 128-bit blocks
    blocks = core.message_to_blocks(map(ord, message))

    # transform each block and apply transformation from array to matrix
    for block in blocks:
        core.transform(block)
        core.encrypt_block(block, key)
        core.transform(block)

    # flatten out blocks
    flat = list(itertools.chain.from_iterable(blocks))
    print "Encrypted message:"
    print flat
    print_chars(flat)
    return flat

def encrypt_file(file, key, b64=False):
    with open(file, 'r') as fr:
        message = encrypt(fr.read(), key, b64) # TODO: write
        with open('encrypted', 'w') as fw:
            fw.write(message)

def decrypt(message, key, b64=False):
    blocks = core.message_to_blocks(message)
    for block in blocks:
        core.transform(block)
        core.decrypt_block(block, key)
        core.transform(block)

    flat = list(itertools.chain.from_iterable(blocks))
    print "Decrypted message:"
    print flat
    print_chars(flat)
    return flat

def print_chars(list):
    for i in range(0,len(list)):
        sys.stdout.write(unichr(list[i])),
    print ""

def decrypt_file(file, key, b64=False):
    with open(file, 'r') as fr:
        message = decrypt(fr.read(), key, b64) # TODO: write
        with open('encrypted', 'w') as fw:
            fw.write(message)
