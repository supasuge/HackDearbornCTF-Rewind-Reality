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
        [8, 49, 49, 24, 48, 29, 59, 0],
        [22, 31, 57, 60, 39, 16, 36, 34],
        [8, 53, 42, 34, 29, 31, 31, 60],
        [43, 14, 41, 1, 13, 50, 48, 43],
        [41, 30, 63, 41, 25, 17, 60, 56],
        [41, 6, 33, 39, 36, 61, 37, 20],
        [50, 57, 1, 61, 52, 14, 2, 6],
        [0, 41, 14, 41, 15, 60, 13, 43],
    ]

    Ciphertext = "vcmHgTdnzICmqfS61g11WkdgtaO__Vur"
    pt = decrypt(SECRET_KEY, Ciphertext).rstrip('x')
    print(pt)