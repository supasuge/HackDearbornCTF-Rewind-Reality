from sympy import Matrix


def decrypt(matrix, words):
    alph = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789_{}"
    char_to_index = {c: i for i, c in enumerate(alph)}
    inverse_matrix = Matrix(matrix).inv_mod(64)
    # this one liner took much longer than I would like to admit to write and get right. Bathe in its glory, for it is beautiful and could be considered a war crime in some countries.
    plaintext = ''.join( 
        alph[int(x) % 64]     # I have way too much time on my hands sometimes
        for block_start in range(0, len(words), 8)
        for x in (inverse_matrix * Matrix([char_to_index.get(c, 0) for c in words[block_start:block_start + 8]])).tolist()
        for x in x  
    )
    return plaintext



if __name__ == '__main__':
    SECRET_KEY = [
        [45, 61, 52, 34, 29, 53, 37, 49],
        [1, 10, 17, 39, 9, 21, 51, 13],
        [25, 24, 47, 39, 60, 30, 35, 2],
        [47, 9, 53, 60, 40, 36, 0, 63],
        [3, 29, 39, 16, 26, 24, 49, 31],
        [39, 61, 57, 31, 9, 0, 10, 17],
        [17, 26, 38, 44, 7, 4, 62, 62],
        [41, 47, 36, 59, 3, 59, 8, 48],
]

    Ciphertext = "7bnp_CY_yWxlhfBlyVmj9UvdtVWmHKJo"
    pt = decrypt(SECRET_KEY, Ciphertext).rstrip('x')
    print(pt)