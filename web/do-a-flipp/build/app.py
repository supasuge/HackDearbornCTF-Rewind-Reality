import random
import socketserver
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Server configuration
host, port = '0.0.0.0', 8000

# Greeting banner
greeting = """hi"""

# Secret key and initialization vector for AES
key = get_random_bytes(16)
iv = get_random_bytes(16)
flag = open('flag.txt', 'r').read().strip()

def encrypt_data(data):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    enc = cipher.encrypt(pad(data.encode(), 16, style='pkcs7'))
    return enc.hex()

def decrypt_data(encrypted_params):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_params = cipher.decrypt(bytes.fromhex(encrypted_params))
    return unpad(padded_params, 16, style='pkcs7').decode()


class DoAFlip:

    def handle(self):
        try:
            print(f"{greeting}")
            # Step 1: Send the encrypted token representing 'access=guest' to the user
            auth_token = "admin=0"
            print("Welcome to the the flipped API system.")
            print("We put the 'secure' in 'security'!")
            print("Your current access level is: guest")
           
            encrypted_token = iv.hex() + encrypt_data(auth_token)
            print(f"Here's your authentication token: {encrypted_token}\n")
            while True:
            # Step 2: Receive the modified encrypted token from the user
                encrypted_input = input("Provide the modified encrypted token to elevate your access level: \n")
        
            # Step 3: Attempt to decrypt the modified token
                final_dec_msg = decrypt_data(encrypted_input)

            # Step 4: Check if the user has successfully changed 'access=guest' to 'access=authorized'
                if "admin=1" in final_dec_msg:
                    print("Access level elevated! You are now authorized!")
                    print(f"Flag: {flag}")
                    break
                else:
                    print("Access level not elevated. You are still a guest.")
                    continue
            
        except Exception as e:
            print("error occurred: " + str(e))

def main():
    DoAFlip().handle()


if __name__ == '__main__':
    main()
