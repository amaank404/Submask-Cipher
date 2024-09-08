"""
Licensed under MIT License, please check the LICENSE file provided
alongside this piece of software.

Uses xorshiftstar[1] rng, xorshiftstar code taken from [2].
Uses SHA512, sha512 taken from python's standard library hashlib module

[1]: https://en.wikipedia.org/wiki/Xorshift
[2]: https://rosettacode.org/wiki/Pseudo-random_numbers/Xorshift_star#Python
"""

import hashlib
import random

MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1


# Modifed from [2] https://rosettacode.org/wiki/Pseudo-random_numbers/Xorshift_star#Python
class RNG():
    const = 0x2545F4914F6CDD1D
    def __init__(self) -> None:
        self.state = 0

    def set_seed(self, seed: int):
        """
        set the seed for this RNG object!
        """
        self.state = seed & MASK64

    def get_rand(self):
        """
        get a random number from 0 to 255
        """
        x = self.state
        x = (x ^ (x << 12)) & MASK64
        x = (x ^ (x >> 25)) & MASK64
        x = (x ^ (x << 27)) & MASK64
        self.state = x
        answer = (((x * self.const) & MASK64) >> 32) & 0xff
        return answer
    
    def get_key(self):
        """
        Generate a random substitution key
        """
        init_key = [i for i in range(256)]
        new_key = []
        for x in range(256):
            new_key.append(init_key.pop(self.get_rand() % (256-x)))
        return new_key
    
def gen_nonce() -> bytes:
    """
    return a 128 byte long nonce!

    replace this function to ur heart's content!
    """
    return random.randbytes(128)

def decode_password(password: bytes) -> tuple[int, bytes]:
    """
    {4-byte unsigned int}{n-byte pattern}
    decode the given password into the following format given above.

    The hashed password is truncated to a rng provided length//2
    """
    password = hashlib.sha512(password).digest()
    seed = int.from_bytes(password[:4], "big", signed=False)
    rng = RNG()
    rng.set_seed(seed)

    # Truncate the password, truncate length = 128 + rand // 2
    truncate_length = (1 << 8) + rng.get_rand() >> 1
    pattern = password[4:truncate_length]
    return (rng, pattern)

def gen_substitution_key_grid(rng: RNG):
    """
    Generate a substitution key grid
    each substitution key is 255 bytes long
    and 255 substitution keys are there in the grid

    the key generation happens by taking an initial
    sequence from 0 <= x <= 255. The initial
    sequence is shuffled by popping and appending
    the i = rng_int() % current_length_initial_sequence
    """
    keys_grid = []
    for _ in range(256):
        current_key = rng.get_key()
        current_key = bytes(current_key)
        keys_grid.append(current_key)

    return keys_grid, rng

def _encrypt1(data: bytes, password: bytes) -> bytes:
    """
    Generate the substitution key grid based on the given password
    and replace

    it also uses the same rng that was used to generate subkey grid
    without reseeding to make changes to pattern.
    a[i] = sub_table[
        (pattern[i % len(pattern)] + rng.get_rand()) % 256
    ][a[i]]
    """
    rng, pattern = decode_password(password)
    sub_table, rng = gen_substitution_key_grid(rng)
    
    encrypted_data = []
    for i, x in enumerate(data):
        random_number_i = rng.get_rand()
        key = sub_table[(pattern[i % len(pattern)] + random_number_i)%256]  # This is our key for the current byte
        encrypted_data.append(key[x])  # Get the corresponding value for the given data byte

    return bytes(encrypted_data)

def _decrypt1(data: bytes, password: bytes) -> bytes:
    """
    Reverse the encryption by first generating the substitution
    grid!
    """
    rng, pattern = decode_password(password)
    sub_table, rng = gen_substitution_key_grid(rng)

    decrypted_data = []
    for i, x in enumerate(data):
        random_number_i = rng.get_rand()
        key = sub_table[(pattern[i % len(pattern)] + random_number_i)%256]  # This is our key for the current byte
        decrypted_data.append(key.find(x))  # Get the corresponding value for the given data byte in reverse

    return bytes(decrypted_data)

def encrypt(data: bytes, password: bytes, nonce = None) -> bytes:
    """
    encrypt the given data using a given password
    """
    if nonce is None:
        nonce = gen_nonce()
    assert len(nonce) == 128, "Nonces have to be 128 bytes long"
    return _encrypt1(nonce, password) + _encrypt1(data, password+nonce)


def decrypt(data: bytes, password: bytes) -> bytes:
    """
    decrypt the given ciphertext with a given password
    """
    nonce = _decrypt1(data[:128], password)
    return _decrypt1(data[128:], password+nonce)
