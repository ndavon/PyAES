import core
import itertools
import copy

def decrypt(message, key, iv):
    blocks = core.to_blocks(map(ord, message))
    next_cbc_block = core.hexToList(iv) #map(ord, iv)
    core.transform(next_cbc_block)
    for block in blocks:
        core.transform(block)
        current_cbc_vector = next_cbc_block
        next_cbc_block = list(block)
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
    current_cbc_block = core.hexToList(iv) #map(ord, iv)
    core.transform(current_cbc_block)
    # transform each block and apply transformation from array to matrix
    for block in blocks:
        core.transform(block)
        core.xorBlocks(block, current_cbc_block) # block = block ^ current_cbc_block
        core.encrypt_block(block, key)
        current_cbc_block = copy.deepcopy(block)
        core.transform(block)
        print "cypher for this block: "+core.listToHex(block)

    # flatten out blocks
    flat = list(itertools.chain.from_iterable(blocks))
    print "Flat: "
    print flat
    result = ''.join(map(unichr, flat))
    return result

def encrypt_file(file, key, iv):
    pass

if __name__ == "__main__":
    # er nutzte die Tests aus http://www.inconteam.com/software-development/41-encryption/55-aes-test-vectors#aes-ecb-128
    # und er sah, dass es gut war

    print 'CBC Test'
    testMessage = core.hex_to_unicode("6bc1bee22e409f96e93d7e117393172a")
    testKey = "2b7e151628aed2a6abf7158809cf4f3c";
    testIv = "000102030405060708090A0B0C0D0E0F";

    encrypted = encrypt(testMessage, testKey, testIv)
    decrypted = decrypt(encrypted, testKey, testIv)
    print 'Expected cypher 7649abac8119b246cee98e9b12e9197d'
    print 'Message: ', testMessage
    print 'Encrypted: ', encrypted
    print 'Decrypted: ', decrypted