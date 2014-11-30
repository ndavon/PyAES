import core

def encrypt(message, key):
    # convert message to 128-bit blocks
    blocks = core.message_to_blocks([ ord(c) for c in message ])
    # transform each block and apply transformation from array to matrix
    for block in blocks:
        core.transform(block)
        core.encrypt_block(block, key)

    # flatten out blocks and join to string
    return ''.join([ chr(c) for c in list(*blocks) ])

def encrypt_file(self, file, key):
    with open(file, 'r') as f:
        message = self.encrypt(f.read(), key) # TODO: write

def decrypt(self, message, key):
    blocks = core.message_to_blocks([ ord(c) for c in message ])
    for block in blocks:
        core.decrypt_block(block, key)

    return ''.join([ chr(c) for c in list(*blocks) ])

def decrypt_file(self, file, key):
    with open(file, 'r') as f:
        message = self.decrypt(f.read(), key) # TODO: write