import hashlib
import random
import string
import secrets
import re
import os



def is_hex(s: str) -> bool:
    return bool(re.fullmatch(r'[0-9a-fA-F]+', s))

N: int = 137

def flag() -> str:
    pth = os.path.abspath("flag.txt")
    try:
        f: str = open("flag.txt", "r").read().rstrip()
        if not f:
            raise Exception("Flag file is empty -_-")
        return f
    except Exception as e:
        raise Exception(f"Error reading flag: {e}")

def e(x: int) -> int:
    return (5 * x + 7) % N

def get_hash(message):
    hash_obj = hashlib.sha3_256(message.encode())
    return [hash_obj.digest()[i % 32] % N for i in range(N)]

def generate_Q(random_str, flag_start=0):
    Q = [random.randint(0, N-1) for _ in range(N)]
    for i, c in enumerate(random_str):
        if flag_start + i < N:
            Q[flag_start + i] = ord(c)
        else:
            raise ValueError("String too long to embed in Q at the specified start index.")
    return Q

def compute_S(H, Q):
    S = [(e(H[i]) + e(Q[i]) + Q[i]) % N for i in range(N)]
    return S

def getRndStr(n: int = None) -> str:
    if n is None:
        n = 30
    elif not isinstance(n, int):
        raise ValueError("n must be an integer value.")
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(n))

def main():
    try:
        # Generate a random string as the "flag"
        w_w = flag()
        random_string = getRndStr(30)
        
        # Hash the string with SHA3-256
        hashed_string = hashlib.sha3_256(random_string.encode()).hexdigest()
        
        print(f"Hashed value to match: {hashed_string}")

        # Generate H from a dynamic message
        message = input("Enter your message to test: ")
        H = get_hash(message)

        # Generate Q with the random string embedded
        Q = generate_Q(random_string, flag_start=0)

        # Compute signature S
        S = compute_S(H, Q)
        
        # Send H and S to the user
        print("H =", H)
        print("S =", S)

        # Verifying if user can recreate the hashed random string
        user_input = input("Enter the secret string to verify: ")
        
        if hashlib.sha3_256(user_input.encode()).hexdigest() == hashlib.sha3_256(random_string.encode()).hexdigest():
            print(f"Flag: {w_w}")
        else:
            print("Incorrect string.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
