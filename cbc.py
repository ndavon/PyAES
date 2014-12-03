import core
import itertools
import copy

def decrypt(message, key, iv):
    blocks = core.to_blocks(map(ord, message))
    next_cbc_block = map(ord, iv)
    core.transform(next_cbc_block)
    for block in blocks:
        core.transform(block)
        current_cbc_vector = next_cbc_block
        next_cbc_block = copy.deepcopy(block)
        core.decrypt_block(block, key)
        core.xorBlocks(block, current_cbc_vector)
        core.transform(block)

    flat = list(itertools.chain.from_iterable(blocks))
    result = ''.join(map(unichr, flat))
    return result

def decrypt_file(file, key, iv):
    with open(file, 'r') as f:
        decrypt(f.read(), key, iv)

def encrypt(message, key, iv):
    # convert message to 128-bit blocks
    blocks = core.to_blocks(map(ord, message))
    current_cbc_block = map(ord, iv)
    core.transform(current_cbc_block)
    # transform each block and apply transformation from array to matrix
    for block in blocks:
        core.transform(block)
        core.xorBlocks(block, current_cbc_block) # block = block ^ current_cbc_block
        core.encrypt_block(block, key)
        current_cbc_block = copy.deepcopy(block)
        core.transform(block)

    # flatten out blocks
    flat = list(itertools.chain.from_iterable(blocks))
    print "Flat: "
    print flat
    result = ''.join(map(unichr, flat))
    return result

def encrypt_file(file, key, iv):
    pass

print 'CBC Test'

testKey = "0123456789abcdef";
testIv = "fedcba9876543210";
testMessage = "Hallo";

encrypted = encrypt(testMessage, testKey, testIv)
decrypted = decrypt(encrypted, testKey, testIv)

print 'Message: ', testMessage
print 'Encrypted: ', encrypted
print 'Decrypted: ', decrypted