from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
from base64 import b64encode, b64decode
import os

class SessionHandler:
    def __init__(self):
        self.sessions = {}

    def create_session(self, data: str) -> str:
        session_id = hashlib.md5(data.encode()).hexdigest()
        self.sessions[session_id] = data
        return session_id

    def get_session(self, session_id: str) -> str:
        return self.sessions.get(session_id, "")

    def encrypt(self, session_id: str, data: str) -> str:
        key = hashlib.md5(session_id.encode()).digest()
        cipher = AES.new(key, AES.MODE_CBC, iv=b'\x00'*16)
        return b64encode(cipher.encrypt(pad(data.encode(), 16))).decode()

    def decrypt(self, session_id: str, data: str) -> str:
        key = hashlib.md5(session_id.encode()).digest()
        cipher = AES.new(key, AES.MODE_CBC, iv=b'\x00'*16)
        return unpad(cipher.decrypt(b64decode(data)), 16).decode()






