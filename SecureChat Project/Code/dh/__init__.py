from Crypto.Hash import SHA256
from Crypto.Random import random

from lib.helpers import read_hex

# 1536 bit safe prime for Diffie-Hellman key exchange
# obtained from RFC 3526

raw_prime = """FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF"""
# Convert from the value supplied in the RFC to an integer
prime = read_hex(raw_prime)
alpha = 87


def create_dh_key():
    # Creates a Diffie-Hellman key
    # Returns (public, private)

    # 1. Create a private key randomly
    private_key = random.randint(0, prime - 1)

    # 2. Create the public key using Diffie-Hellman
    public_key = pow(alpha, private_key, prime)

    #print("My private key: ", private_key)
    #print("My public key: ", public_key)
    #print("My alpha: ", alpha)

    return public_key, private_key


def calculate_dh_secret(their_public, my_private):
    # Calculate the shared secret
    # shared_secret = their_public * my_private

    shared_secret = pow(their_public, my_private, prime)

    # Hash the value so that:
    # (a) There's no bias in the bits of the output
    #     (there may be bias if the shared secret is used raw)
    # (b) We can convert to raw bytes easily
    # (c) We could add additional information if we wanted
    # Feel free to change SHA256 to a different value if more appropriate
    shared_hash = SHA256.new(bytes(str(shared_secret), "ascii")).hexdigest()

    #print("My shared hash: ", shared_hash)
    return shared_hash

