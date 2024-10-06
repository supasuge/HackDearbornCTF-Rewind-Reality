# solve.py
from pwn import *

def inv_mod(a, m):
    # compute's modular inverse using extended euclidean algorithm
    # Extended Euclidean Algorithm
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

def extract_flag(H, S):
    # Second function
    N = 137
    inv_6 = pow(6, -1, N)  # Modular inverse using pow
    Q = [(s - 5 * h - 14) * inv_6 % N for s, h in zip(S, H)]
    flag = ''.join(chr(q) if 32 <= q <= 126 else '?' for q in Q[:30])
    return flag.rstrip('?')

def main():
    h, p = 'localhost', 1337
    c = remote(h, p)
    h1 = c.recvline().strip().decode().split(': ')[1]
    print(f"hash: {h}")
    h2 = c.recvuntil(b"Enter your message to test: ")
    msg = b"A"
    c.sendline(msg)
    H = c.recvline().strip().decode()
    S = c.recvline().strip().decode()
    
    print(f"\n\n\n{H}\ttype: {type(H)}\n\n\n{S}\ttype: {type(S)}")
    print(f"\n\n\n{S}")

if __name__ == "__main__":
    main()