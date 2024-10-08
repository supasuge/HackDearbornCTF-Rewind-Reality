from pwn import *

def inv_mod(a, m):
    # Computes modular inverse using extended Euclidean Algorithm
    t, new_t = 0, 1
    r, new_r = m, a
    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r
    if r > 1:
        raise ValueError(f"{a} has no inverse modulo {m}")
    if t < 0:
        t += m
    return t

def extract_random_string(H, S):
    # Function to extract the random string embedded in Q
    N = 137
    inv_6 = pow(6, -1, N)  # Modular inverse of 6 mod N
    Q = [(s - 5 * h - 14) * inv_6 % N for s, h in zip(S, H)]
    random_string = ''.join(chr(q) if 32 <= q <= 126 else '?' for q in Q[:30])
    return random_string.rstrip('?')

def main():
    # Connecting to the challenge
    h, p = 'localhost', 1337  # Replace with actual host and port
    c = remote(h, p)

    # Step 1: Receive the hash string from the server
    c.recvuntil(b'Hashed value to match: ')
    hashed_value = c.recvline().strip().decode()
    print(f"Hashed value to match: {hashed_value}")

    # Step 2: Interact and send the input message
    c.recvuntil(b"Enter your message to test: ")
    msg = "A"  # We are sending a simple message 'A' as the input
    c.sendline(msg.encode())

    # Step 3: Receive H and S from the server
    c.recvuntil(b"H = ")
    H_str = c.recvline().strip().decode()
    H = list(map(int, H_str.strip('[]').split(',')))  # Convert H to a list of integers

    c.recvuntil(b"S = ")
    S_str = c.recvline().strip().decode()
    S = list(map(int, S_str.strip('[]').split(',')))  # Convert S to a list of integers

    print(f"H: {H}")
    print(f"S: {S}")

    # Step 4: Extract the random string using the extracted H and S values
    random_string = extract_random_string(H, S)
    print(f"Extracted random string: {random_string}")

    # Step 5: Send the extracted random string back to the server
    c.recvuntil(b"Enter the secret string to verify: ")
    c.sendline(random_string.encode())

    # Step 6: Receive and print the response (the flag)
    response = c.recvline().strip().decode()
    print(response)

    # Step 7: Close the connection
    c.close()

if __name__ == "__main__":
    main()
