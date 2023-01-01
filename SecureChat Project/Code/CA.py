'''
    *  Full Name:
    *  Course:EECS 3482 A
    *  Description: Certification Authority 
    *
'''

from dh import create_dh_key, calculate_dh_secret

from Crypto.Hash import SHA256
from lib.xor import XOR
from sign import save_signed_file
from decrypt import decrypt

import os
import hmac
import hashlib



class Certificate_Authority:
    def __init__(self):
        
        self.ca_pub_key, self.ca_pri_key = self.generateCAkeys()
        self.ca_signed_certificate = None

    #Generate a public/private key pair for the certificate authority. The public key of the CA is self-signed.
    def generateCAkeys(self):
        
        f = None
        pub_key = None
        pri_key = None

        if os.path.isdir("../CA_certificates") == False:
            os.mkdir("../CA_certificates")
        
        try:
            f = open("../CA_certificates/ca_keys", "r")
        except:
            key1, key2 = create_dh_key()
            pub_key_str = str(key1)[:128]
            pri_key_str = str(key2)[:128]
            f = open("../CA_certificates/ca_keys", "w")
            f.write(pub_key_str)
            f.write(pri_key_str)
            f.close()
            pub_key = int(pub_key_str)
            pri_key = int(pri_key_str)
            f = None

        if f is not None:
            pub_key = int(f.read(128))
            pri_key = int(f.read(128))
        
        return pub_key, pri_key 

    def generateCertificate(self, user_id, user_pub_key):

        f = None

        if os.path.isdir("../keystore") == False:
            os.mkdir("../keystore")

        client_fname = "../keystore/" + user_id

        not_found = False
 
        try:

            f = open(client_fname + ".signed", "r")
        
        except:

            not_found = True
        
        if not_found:
        
            tmp_string = str(user_pub_key) + user_id
            
            unsigned_certificate = str(tmp_string).encode();

            hash_unsigned_certificate = SHA256.new(unsigned_certificate).hexdigest()
        
            encrypted_hash = hmac.new(key=str(self.ca_pri_key).encode(), msg=str(hash_unsigned_certificate).encode(), digestmod=hashlib.sha256)
        
            self.ca_signed_certificate = encrypted_hash.hexdigest() + hash_unsigned_certificate
            
            f = open(client_fname, "w")
       
            f.write(self.ca_signed_certificate)
            
            f.close()
            
            f = None

            save_signed_file(client_fname)
        
        if f is not None:
            
            f.close()
            
            client_fname = client_fname + ".signed"

            self.ca_signed_certificate = decrypt(client_fname)
            
        return self.ca_signed_certificate

     