import os
from lib.xor import XOR

import hmac
import hashlib

def sign_file(f):
    password = "hardcoded_password"
    hash_f = hmac.new(key=password.encode(), msg=f.encode(), digestmod=hashlib.sha256)
    f_digest = hash_f.hexdigest()
    cipher = XOR.new(password[:4].encode("utf-8"))
    signed_f = f_digest + f
    encrypted_f = cipher.encrypt(signed_f.encode())
    return encrypted_f


def save_signed_file(fn):
    f = open(fn).read()
    signed_f = sign_file(f)
    signed_fn = fn + ".signed"
    out = open(signed_fn, "wb")
    out.write(signed_f)
    out.close()
    #print("Signed file written to", signed_fn)
