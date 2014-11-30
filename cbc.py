
class CBC:
    def decrypt(self, message, key, iv):
        pass

    def decrypt_file(self, file, key, iv):
        with open(file, 'r') as f:
            self.decrypt(f.read(), key, iv)

    def encrypt(self, message, key, iv):
        pass

    def encrypt_file(self, file, key, iv):
        with open(file, 'w') as f:
            self.encrypt(f.read(), key, iv)