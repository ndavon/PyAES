from CodeWarrior.CodeWarrior_suite import message_document
import core
import itertools



def encrypt(message, key, b64=False):
    # convert message to 128-bit blocks
    blocks = core.to_blocks(map(ord, message))

    # transform each block and apply transformation from array to matrix
    for block in blocks:
        core.transform(block)
        core.encrypt_block(block, key)
        core.transform(block)
        print 'Cypher for this block: ', core.listToHex(block)

    # flatten out blocks
    flat = list(itertools.chain.from_iterable(blocks))
    result = ''.join(map(unichr, flat))
    return result

def encrypt_file(file, key, b64=False):
    with open(file, 'r') as fr:
        message = encrypt(fr.read(), key, b64) # TODO: write
        with open('encrypted', 'w') as fw:
            fw.write(message.encode('utf-8'))

def decrypt(message, key, b64=False):
    blocks = core.to_blocks(map(ord, message))
    for block in blocks:
        core.transform(block)
        core.decrypt_block(block, key)
        core.transform(block)

    flat = list(itertools.chain.from_iterable(blocks))
    result = ''.join(map(unichr, flat))
    return result

def decrypt_file(file, key, b64=False):
    with open(file, 'r') as fr:
        message = decrypt(fr.read().decode('utf-8'), key, b64) # TODO: write
        with open('decrypted', 'w') as fw:
            fw.write(message.encode('utf-8'))

if __name__ == "__main__":
    # er nutzte die Tests aus http://www.inconteam.com/software-development/41-encryption/55-aes-test-vectors#aes-ecb-128
    # und er sah, dass es gut war
    message = core.hex_to_unicode("6bc1bee22e409f96e93d7e117393172a")
    key = "2b7e151628aed2a6abf7158809cf4f3c"
    encrypted = encrypt(message, key)
    decrypted = decrypt(encrypted, key)
    print "Expected Cypher 3ad77bb40d7a3660a89ecaf32466ef97"
    print 'Message: ', message
    print 'Encrypted: ', encrypted
    print 'Decrypted: ', decrypted

    #encrypt_file('testfile', key)
    #decrypt_file('encrypted', key)