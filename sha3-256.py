import numpy as np

def pad(data, block_size):
    P = data + b'\x01'  # Добавляет первый бит «1»
    L = len(P) % block_size
    if L > 0:
        P += b'\x00' * (block_size - L - 1)  # Добавляет биты «0»
    P += b'\x80'  # Добавляет последний бит «1»
    return P

def keccak_f(state):
    for round in range(24):
        theta(state)
        rho(state)
        pi(state)
        chi(state)
        iota(state, round)
    return state

def theta(state):
    C = np.zeros((5, 64), dtype=bool)
    for x in range(5):
        C[x] = state[x, 0] ^ state[x, 1] ^ state[x, 2] ^ state[x, 3] ^ state[x, 4]
    D = np.zeros((5, 64), dtype=bool)
    for x in range(5):
        D[x] = C[(x - 1) % 5] ^ np.roll(C[(x + 1) % 5], -1)
    for x in range(5):
        for y in range(5):
            state[x, y] ^= D[x]
    return state

def rho(state):
    rotations = [
        [0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14]
    ]
    for x in range(5):
        for y in range(5):
            state[x, y] = np.roll(state[x, y], rotations[x][y])
    return state

def pi(state):
    new_state = np.zeros((5, 5, 64), dtype=bool)
    for x in range(5):
        for y in range(5):
            new_state[y, (2 * x + 3 * y) % 5] = state[x, y]
    state[:, :, :] = new_state
    return state

def chi(state):
    new_state = np.zeros((5, 5, 64), dtype=bool)
    for x in range(5):
        for y in range(5):
            new_state[x, y] = state[x, y] ^ ((~state[(x + 1) % 5, y]) & state[(x + 2) % 5, y])
    state[:, :, :] = new_state
    return state

def iota(state, round):
    RC = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
        0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    ]
    rc = np.array(list(bin(RC[round])[2:].rjust(64, '0')), dtype=bool)
    state[0, 0] ^= rc
    return state

def sha3_256_file(input_file, output_file):
    state = np.zeros((5, 5, 64), dtype=bool)
    rate = 1088
    output_length = 256
    block_size = rate // 8

    with open(input_file, 'rb') as file:
        buffer = file.read()

    buffer = pad(buffer, block_size)

    while len(buffer) >= block_size:
        block = buffer[:block_size]
        buffer = buffer[block_size:]
        absorb_block(state, block, block_size)
    
    hash_value = squeeze(state, output_length)
    print('Хэш файла:', hash_value.hex())

    with open(output_file, 'w') as file:
        file.write(hash_value.hex())

def absorb_block(state, block, block_size):
    block_bits = np.unpackbits(np.frombuffer(block, dtype=np.uint8))
    block_bits = block_bits.reshape((-1, 64)).astype(bool)
    for i in range(block_bits.shape[0]):
        state[i // 5, i % 5] ^= block_bits[i]
    keccak_f(state)
    return state

def squeeze(state, output_length):
    Z = bytearray()
    rate = 1088
    while len(Z) < output_length // 8:
        squeezed_bits = np.packbits(state.reshape(-1)[:rate])
        squeezed_bytes = squeezed_bits.tobytes()
        Z += squeezed_bytes[:(output_length // 8) - len(Z)]
        keccak_f(state)
    return Z

input_file = "file.txt"
output_file = "output_hash.txt"

sha3_256_file(input_file, output_file)
print("Хэш сохранен в", output_file)