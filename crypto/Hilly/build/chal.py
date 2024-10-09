#!/usr/bin/env python3
import numpy as np
import secrets
import math
import gmpy2

def generate_secret_key(matrix_size=8, alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789_{}"):
    """
    Generates a cryptographically secure, invertible key matrix for the Hill Cipher using printable ASCII characters.
    
    Args:
        matrix_size (int): The size of the square matrix (default is 8 for an 8x8 matrix).
        alphabet (str): A string of allowed printable ASCII characters. Default is "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789_{}".
    
    Returns:
        list of lists: The generated invertible key matrix with integer entries.
    """
    alphabet_size = len(alphabet)
    
    def is_invertible(matrix, modulus):
        """Check if the matrix is invertible modulo the given modulus."""
        det = int(round(np.linalg.det(matrix))) % modulus
        if gmpy2.gcd(det, modulus) != 1:
            return False
        try:
            # Attempt to compute the inverse determinant
            gmpy2.invert(det, modulus)
        except ZeroDivisionError:
            return False
        return True
    
    while True:
        # Generate a random matrix with entries as indices of the alphabet using cryptographically secure randomness
        matrix = np.array([
            [secrets.randbelow(alphabet_size) for _ in range(matrix_size)]
            for _ in range(matrix_size)
        ])
        
        if is_invertible(matrix, alphabet_size):
            # Convert the matrix to a list of lists for easy readability and usage
            key_matrix = matrix.tolist()
            return key_matrix
        # If not invertible, repeat the process

def stov(s, alphabet):
    """Convert string to list of indices based on the alphabet."""
    return [alphabet.index(c) for c in s]

def vtos(x, alphabet):
    """Convert list of indices to string based on the alphabet."""
    return ''.join([alphabet[i] for i in x])

def chunk(s, n):
    """Split the string into chunks of size n."""
    return [s[i:i+n] for i in range(0, len(s), n)]

def modinv(matrix, m):
    """Compute the inverse of a matrix modulo m."""
    det = int(round(np.linalg.det(matrix))) % m
    det_inv = int(gmpy2.invert(det, m))
    adjugate = np.round(det * np.linalg.inv(matrix)).astype(int)
    inv_matrix = (det_inv * adjugate) % m
    return inv_matrix

def encrypt(plaintext, alphabet, key_matrix):
    """Encrypt plaintext using the Hill Cipher."""
    m = len(alphabet)  # modulo
    n = len(key_matrix)
    ciphertext = ''
    
    plaintext = plaintext.strip()
    
    # Ensure the plaintext length is a multiple of n
    if len(plaintext) % n != 0:
        padding = n - (len(plaintext) % n)
        plaintext += 'x' * padding  # Padding with 'x' or any character in the alphabet
    
    for block in chunk(plaintext, n):
        x = np.array(stov(block, alphabet))
        y = np.dot(key_matrix, x) % m
        ciphertext += vtos(y.tolist(), alphabet)
    
    return ciphertext

def main():
    FLAG = open("flag.txt", "r").read().strip()
    OUT = ""
    MxM = 8  # 8x8 
    SECRET_KEY = generate_secret_key(MxM)
    ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789_{}"
    OUT+="SECRET_KEY = [\n"
    for row in SECRET_KEY:
        OUT += f"    {row},\n"
    OUT+="]"
    ct = encrypt(FLAG, ALPHABET, SECRET_KEY)
    with open("output.txt", "w") as f:
        f.write(OUT)
        f.write("\n\n")
        f.write(f"Ciphertext = {ct}")

if __name__ == "__main__":
    main()
