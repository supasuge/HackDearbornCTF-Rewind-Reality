from pwn import *

# Set up the connection
host, port = 'l72.17.0.2', 1337
conn = remote(host, port)

def inv_mod(a, m):
    # ... (keep this function as is)

def extract_flag(H, S):
    # ... (keep this function as is)

def main():
    # Receive the hashed value to match
    conn.recvuntil(b"Hashed value to match: ")
    hashed_value = conn.recvline().strip().decode()
    log.info(f"Hashed value to match: {hashed_value}")

    # Send a message to get H and S
    conn.sendlineafter(b"Enter your message to test: ", b"test")

    # Receive H
    conn.recvuntil(b"H = ")
    H_str = conn.recvline().strip().decode()
    H = eval(H_str)  # Convert string representation to list

    # Receive S
    conn.recvuntil(b"S = ")
    S_str = conn.recvline().strip().decode()
    S = eval(S_str)  # Convert string representation to list

    # Extract the flag (random string)
    extracted_string = extract_flag(H, S)
    log.info(f"Extracted string: {extracted_string}")

    # Send the extracted string to get the flag
    conn.sendlineafter(b"Enter the secret string to verify: ", extracted_string.encode())

    # Receive the flag
    response = conn.recvline().strip().decode()
    if response.startswith("Flag:"):
        flag = response.split("Flag: ")[1]
        log.success(f"Flag: {flag}")
    else:
        log.failure("Failed to get the flag")

    conn.close()

if __name__ == "__main__":
    main()