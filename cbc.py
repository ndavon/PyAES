import core
import itertools
import copy

def decrypt_cmac(message, key, iv, cmac):
    decrypted_message = core.hex_to_unicode(decrypt(message, key, iv))
    new_cmac = core.aes_cmac(key, decrypted_message)
    if new_cmac != cmac:
        raise Exception('No valid cmac')
    return decrypted_message

def decrypt(message, key, iv):
    blocks = core.to_blocks(core.hex_to_list(message))
    next_cbc_block = core.hex_to_list(iv) #map(ord, iv)
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
    return core.list_to_hex(flat)

def decrypt_file_cmac(file, key, iv, cmac_file):
    with open(file, 'r') as fr:
        with open(cmac_file, 'r') as handle_cmac:
            message = decrypt_cmac(fr.read(), key, iv, core.hex_to_list(handle_cmac.read()))
    with open('decrypted', 'w') as fw:
        print 'decrypted message: ', message
        fw.write(message)

def decrypt_file(file, key, iv):
    with open(file, 'r') as fr:
        message = decrypt(fr.read(), key, iv)
        with open('decrypted', 'w') as fw:
            fw.write(message)

def encrypt_cmac(message, key, iv):
    return (encrypt(message, key, iv), core.aes_cmac(key, message))

def encrypt(message, key, iv):
    # convert message to 128-bit blocks
    blocks = core.to_blocks(map(ord, message))
    current_cbc_block = core.hex_to_list(iv) #map(ord, iv)
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
    # print 'Flat: '
    # print flat
    # result = ''.join(map(unichr, flat))
    return core.list_to_hex(flat)

def encrypt_file_cmac(file, key, iv):
    with open(file, 'r') as fr:
        message, cmac = encrypt_cmac(unicode(fr.read()), key, iv)
        with open('encrypted', 'w') as fw:
            fw.write(message)
        with open('encrypted.sig', 'w') as sigFile:
            sigFile.write(core.list_to_hex(cmac))

def encrypt_file(file, key, iv):
    with open(file, 'r') as fr:
        message = encrypt(unicode(fr.read()), key, iv)
        with open('encrypted', 'w') as fw:
            fw.write(message)

def mac_test(key, message, expected):
    print '\nMac of String(%i bytes) should be: %s' % (len(message), expected)
    mac = core.aes_cmac(key, message)
    print 'MAC: {' + core.list_to_hex(mac) +'}'

if __name__ == '__main__':
    # er nutzte die Tests aus http://www.inconteam.com/software-development/41-encryption/55-aes-test-vectors#aes-ecb-128
    # und er sah, dass es gut war

    print 'CBC Test'
    testMessage = core.hex_to_unicode('6bc1bee22e409f96e93d7e117393172a')
    testKey = '2b7e151628aed2a6abf7158809cf4f3c'
    testIv = '000102030405060708090A0B0C0D0E0F'

    encrypted = encrypt(testMessage, testKey, testIv)
    decrypted = decrypt(encrypted, testKey, testIv)
    print 'Expected cipher 7649abac8119b246cee98e9b12e9197d'
    print 'Message: ', testMessage
    print 'Encrypted: ', encrypted
    print 'Decrypted: ', decrypted


    encrypted, cmac = encrypt_cmac(testMessage, testKey, testIv)
    decrypted = decrypt_cmac(encrypted, testKey, testIv, cmac)

    print '\nCMAC-Validation Encryption:'
    print 'Message: ', testMessage
    print 'Encrypted: ', encrypted
    print 'CMAC: ' , core.list_to_hex(cmac)
    print 'Decrypted: ', decrypted


    print '\nSubkey-Test (Validation data is taken from http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf\n'

    print 'Subkey1 should be: fbeed618357133667c85e08f7236a8de'
    print 'Subkey2 should be: f7ddac306ae266ccf90bc11ee46d513b'
    subkey1, subkey2 = core.generate_subkeys('2b7e151628aed2a6abf7158809cf4f3c')
    print 'Key1: {' + core.list_to_hex(subkey1) +'}'
    print 'Key2: {' + core.list_to_hex(subkey2) +'}'

    mac_test('2b7e151628aed2a6abf7158809cf4f3c', '', 'bb1d6929e95937287fa37d129b756746')
    mac_test('2b7e151628aed2a6abf7158809cf4f3c', core.hex_to_unicode('6bc1bee22e409f96e93d7e117393172a'), '070a16b46b4d4144f79bdd9dd04a287c')
    mac_test('2b7e151628aed2a6abf7158809cf4f3c', core.hex_to_unicode('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411'), 'dfa66747de9ae63030ca32611497c827')

    # encrypt_file_cmac
    mac_test('2b7e151628aed2a6abf7158809cf4f3c', '725c7b6f97f5cd86ed3df662db9ff4ab', 'c9ec2d1aab0537eb7e0c4b47b656c5fc')

    encrypt_file_cmac('message.txt','2b7e151628aed2a6abf7158809cf4f3c', '2b7e151628aed2a6abf7158809cf4f3c')
    decrypt_file_cmac('encrypted','2b7e151628aed2a6abf7158809cf4f3c', '2b7e151628aed2a6abf7158809cf4f3c', 'encrypted.sig')


