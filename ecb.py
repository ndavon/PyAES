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
    message = "Hallo"
    key = "0123456789abcdef"

    encrypted = encrypt(message, key)
    decrypted = decrypt(encrypted, key)

    print 'Message: ', message
    print 'Encrypted: ', encrypted
    print 'Decrypted: ', decrypted

    encrypt_file('testfile', key)
    decrypt_file('encrypted', key)