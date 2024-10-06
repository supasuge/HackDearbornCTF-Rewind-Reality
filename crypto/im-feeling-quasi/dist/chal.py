# chal.py

import hashlib
import random

# Define the modulus
N = 137

def e(x):
    """
    Mixing function e(x) = (5 * x + 7) mod 137
    """
    return (5 * x + 7) % N

def get_hash(message):
    """
    Computes the SHA-256 hash of the message and maps it to a list H of length N.
    Each element H[i] is derived from the hash bytes modulo N.
    """
    hash_bytes = hashlib.sha256(message.encode()).digest()
    H = [hash_bytes[i % len(hash_bytes)] % N for i in range(N)]
    return H

def generate_Q(flag, flag_start=0):
    """
    Generates the Q vector of length N.
    Embeds the flag into Q starting at the specified index.
    The rest of Q is filled with random integers modulo N.
    """
    Q = [random.randint(0, N-1) for _ in range(N)]
    # Embed the flag in Q starting at flag_start
    for i, c in enumerate(flag):
        if flag_start + i < N:
            Q[flag_start + i] = ord(c)
        else:
            raise ValueError("Flag is too long to embed in Q at the specified start index.")
    return Q

def compute_S(H, Q):
    """
    Computes the signature S based on H and Q.
    S[i] = (e(H[i]) + e(Q[i]) + Q[i]) mod N for each element.
    """
    S = [(e(H[i]) + e(Q[i]) + Q[i]) % N for i in range(N)]
    return S

def main():
    message = 'magic_sign'
    flag = 'hctf3{[REDACTED]}'
    H = get_hash(message)
    Q = generate_Q(flag, flag_start=0)
    S = compute_S(H, Q)
    print(f"H = {H}\n")
    print(f"S = {S}")

if __name__ == "__main__":
    print("Attemptting to retrieve flag from Q...")
    main()
