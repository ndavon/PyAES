import core
import base64

def encrypt(message, key, b64=False):
    # convert message to 128-bit blocks
    blocks = core.to_blocks(map(ord, message))
    # transform each block and apply transformation from array to matrix
    for block in blocks:
        core.transform(block)
        core.encrypt_block(block, key)
        core.transform(block)

    # flatten out blocks and join to string
    result = ''.join([ chr(c) for c in list(*blocks) ])
    return result if not b64 else base64.b64encode(result)

def encrypt_file(file, key, b64=False):
    with open(file, 'r') as fr:
        message = encrypt(fr.read(), key, b64) # TODO: write
        with open('encrypted', 'w') as fw:
            fw.write(message)

def decrypt(message, key, b64=False):
    blocks = core.to_blocks(map(ord, message))
    for block in blocks:
        core.transform(block)
        core.decrypt_block(block, key)
        core.transform(block)

    result = ''.join([ chr(c) for c in list(*blocks) ])
    return result if not b64 else base64.b64decode(result)

def decrypt_file(file, key, b64=False):
    with open(file, 'r') as fr:
        message = decrypt(fr.read(), key, b64) # TODO: write
        with open('encrypted', 'w') as fw:
            fw.write(message)