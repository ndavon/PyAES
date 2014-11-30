
def decrypt(message, key, iv):
    pass

def decrypt_file(file, key, iv):
    with open(file, 'r') as f:
        decrypt(f.read(), key, iv)

def encrypt(message, key, iv):
    pass

def encrypt_file(file, key, iv):
    with open(file, 'w') as f:
        encrypt(f.read(), key, iv)