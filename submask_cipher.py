"""
Licensed under MIT License, please check the LICENSE file provided
alongside this piece of software.

Uses xorshiftstar[1] rng, xorshiftstar code taken from [2].
Uses SHA512, sha512 taken from python's standard library hashlib module

[1]: https://en.wikipedia.org/wiki/Xorshift
[2]: https://rosettacode.org/wiki/Pseudo-random_numbers/Xorshift_star#Python
"""

import hashlib

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

def decode_password(password: bytes) -> tuple[int, bytes]:
    """
    {4-byte unsigned int}{n-byte pattern}
    decode the given password into the following format given above
    """
    password = hashlib.sha512(password).digest()[:len(password)]
    seed = int.from_bytes(password[:4], "big", signed=False)
    pattern = password[4:]
    return (seed, pattern)

def gen_substitution_key_grid(seed: int):
    """
    Generate a substitution key grid
    each substitution key is 255 bytes long
    and 255 substitution keys are there in the grid

    the key generation happens by taking an initial
    sequence from 0 <= x <= 255. The initial
    sequence is shuffled by popping and appending
    the i = rng_int() % current_length_initial_sequence
    """
    rng = RNG()
    rng.set_seed(seed)
    rng.get_rand()

    keys_grid = []
    for _ in range(256):
        current_key = rng.get_key()
        current_key = bytes(current_key)
        keys_grid.append(current_key)

    return keys_grid, rng

def encrypt(data: bytes, password: bytes) -> bytes:
    """
    Generate the substitution key grid based on the given password
    and replace

    it also uses the same rng that was used to generate subkey grid
    without reseeding to make changes to pattern.
    a[i] = sub_table[
        (pattern[i % len(pattern)] + rng.get_rand()) % 256
    ][a[i]]
    """
    seed, pattern = decode_password(password)
    sub_table, rng = gen_substitution_key_grid(seed)
    
    encrypted_data = []
    for i, x in enumerate(data):
        random_number_i = rng.get_rand()
        key = sub_table[(pattern[i % len(pattern)] + random_number_i)%256]  # This is our key for the current byte
        encrypted_data.append(key[x])  # Get the corresponding value for the given data byte

    return bytes(encrypted_data)

def decrypt(data: bytes, password: bytes) -> bytes:
    """
    Reverse the encryption by first generating the substitution
    grid!
    """
    seed, pattern = decode_password(password)
    sub_table, rng = gen_substitution_key_grid(seed)

    decrypted_data = []
    for i, x in enumerate(data):
        random_number_i = rng.get_rand()
        key = sub_table[(pattern[i % len(pattern)] + random_number_i)%256]  # This is our key for the current byte
        decrypted_data.append(key.find(x))  # Get the corresponding value for the given data byte in reverse

    return bytes(decrypted_data)


# Have fun with this lil section
if __name__ == "__main__":
    print(data := encrypt(b"This is some textThis is some textThis is some text", b"totally a secure password lol"))
    print(decrypt(data, b"totally a secure password lol"))