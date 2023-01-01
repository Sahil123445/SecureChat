import os
from lib.xor import XOR

import hmac
import hashlib

def decrypt_content(f):
    password = "hardcoded_password"
    cipher = XOR.new(password[:4].encode("utf-8"))
    
    decrypted_f = cipher.decrypt(f)

    signature = decrypted_f[:64]
    contents = decrypted_f[64:]

    return contents


def decrypt(fn):
    f = open(fn, "rb").read()
    contents = decrypt_content(f)
    return contents
