from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import os

class AESCipher:
    def __init__(self, key):
        self.key = key
        self.pad = lambda x: pad(x, AES.block_size,style='pkcs7')
        self.unpad = lambda x: unpad(x, AES.block_size, style='pkcs7')
        self.bs = AES.block_size
    def encrypt(self, data):
        iv = os.urandom(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ciphertext_hex = iv + cipher.encrypt(self.pad(data.encode()))
        return ciphertext_hex.hex()

    def decrypt(self, data):
        raw = bytes.fromhex(data)
        iv = raw[:self.bs]
        ct = raw[self.bs:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        plaintext = self.unpad(cipher.decrypt(ct)).decode()
        return plaintext
    
    
def gen_cookie(cipher, username):
    cookie_data = f"username={username}&admin=0"
    encrypted_cookie = cipher.encrypt(cookie_data)
    return encrypted_cookie.decode()    


