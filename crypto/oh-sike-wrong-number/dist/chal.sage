import random
from sage.all import *

# SIDH parameters (simplified for demonstration)
p = 2^32 * 3^20 - 1  # A small prime for quick computation
eA, eB = 32, 20

import random
from sage.all import *

# SIDH parameters (simplified for demonstration)
p = 2^32 * 3^20 - 1  # A small prime for quick computation
eA, eB = 32, 20

def keygen():
    # Generate base curve
    Fp2 = GF(p^2, 'i', modulus=x^2+1)
    E0 = EllipticCurve(Fp2, [0,6,0,1,0])  # y^2 = x^3 + 6x^2 + x
    
    # Generate torsion bases
    xP2, xQ2 = E0.division_points(2^eA, 2)
    xP3, xQ3 = E0.division_points(3^eB, 2)
    
    # Bob's secret and public key
    secret_key = random.randint(0, 3^eB - 1)
    phi = E0.isogeny((xP3 + secret_key * xQ3), 3^eB)
    EB = phi.codomain()
    xPB = phi(xP2)
    xQB = phi(xQ2)
    
    return E0, xP2, xQ2, xP3, xQ3, EB, xPB, xQB, secret_key

def encrypt_flag(flag, shared_secret):
    key = int(shared_secret.xy()[0])
    return bytes([c ^ ((key >> (8*i)) & 0xFF) for i, c in enumerate(flag)])

# Generate keys
E0, xP2, xQ2, xP3, xQ3, EB, xPB, xQB, secret_key = keygen()

# Encrypt flag
flag = b'hctf3{exexwxe}'
shared_secret = E0.isogeny((xP2 + secret_key * xQ2), 2^eA).codomain().j_invariant()
encrypted_flag = encrypt_flag(flag, shared_secret)

print(f"p = {p}")
print(f"E0: {E0}")
print(f"xP2 = {xP2}")
print(f"xQ2 = {xQ2}")
print(f"xP3 = {xP3}")
print(f"xQ3 = {xQ3}")
print(f"EB: {EB}")
print(f"xPB = {xPB}")
print(f"xQB = {xQB}")
print(f"Encrypted flag: {encrypted_flag.hex()}")