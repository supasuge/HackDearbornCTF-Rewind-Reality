from pwn import *

# Connect to the server
conn = remote('localhost', 8000)

# Receive the initial message
print(conn.recvuntil(b'Encrypted Token: ').decode())

# Receive the encrypted token
encrypted_token = conn.recvline().strip().decode()
print(f"Received encrypted token: {encrypted_token}")

# Modify the encrypted token
iv = encrypted_token[:32]
ciphertext = encrypted_token[32:]

# Convert hex to bytes
iv_bytes = bytes.fromhex(iv)

# Flip the 7th byte (index 6) of the IV
modified_iv = iv_bytes[:6] + bytes([iv_bytes[6] ^ 1]) + iv_bytes[7:]

# Convert back to hex
modified_encrypted_token = modified_iv.hex() + ciphertext

print(f"Modified encrypted token: {modified_encrypted_token}")

# Send the modified encrypted token
conn.sendlineafter(b'Provide the modified encrypted token to elevate your access level: \n', modified_encrypted_token.encode())

# Receive and print the response
response = conn.recvline()
print(response)

conn.close()