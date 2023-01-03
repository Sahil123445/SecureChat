import struct

from dh import create_dh_key, calculate_dh_secret
from .xor import XOR

from enum import Enum

import hmac
import hashlib

# part 2 - start
 
from CA import Certificate_Authority

# part 2 - end

# Add messages
class Message(bytes, Enum):
    LIST = bytes("LIST", "ascii")
    AUTH = bytes("AUTH", "ascii")
    ECHO = bytes("ECHO", "ascii")
    ERROR = bytes("ERROR", "ascii")
    CHAT = bytes("CHAT", "ascii")
    ACK = bytes("OK", "ascii")
    CHAT_SESSION = bytes("PORT", "ascii")
    FILE = bytes("FILE", "ascii")
    FILE_TRANSFER = bytes("TRANSFER", "ascii")


class StealthConn(object):
    def __init__(self, conn,
                 client=False,
                 server=False,
                 user=None,
                 verbose=False):
        self._secret = None
        self.conn = conn
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.user = user		
        
        # part 2 - start

        self.state = 0
        self.localID = None
        self.remoteID = "server"
        self.pub_key = None
        self.remote_pub_key = None
        self.certificate_authority = None
        self.certificate = None
        
        # part 2 - end
        self.cipher, self._secret = self.generate_secret()

    def generate_secret(self):
        # Perform the initial connection handshake for agreeing on a shared secret

        # This can be broken into code run just on the server or just on the clientasdsad
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            shared_hash = calculate_dh_secret(their_public_key,
                                              my_private_key)

            # part 2 - start

            self.pub_key = my_public_key
            self.remote_pub_key = their_public_key

            # part 2 - end
            

            self._secret = shared_hash
            # if self.verbose:
            #print("Shared hash: {}".format(shared_hash.encode("utf-8").hex()))

            # Default XOR algorithm can only take a key of length 32
            self.cipher = XOR.new(shared_hash[:4].encode("utf-8"))
            return self.cipher, self._secret

    def send(self, data_to_send):
        hmac_key = "Sahil's Secret Key"
        hmac_object = hmac.new(key=hmac_key.encode(), msg=data_to_send, digestmod=hashlib.sha256)
        message_digest = hmac_object.digest()
        data = bytes(message_digest) + bytes(data_to_send)
        #print("Going to send original Message: ", data_to_send)
        #print("with appended HMAC: ", message_digest)
        #print("Full Message: ", data)



        if self.cipher:
            encrypted_data = self.cipher.encrypt(data)
            if self.verbose:
                # print("Original data: {}".format(data))
                # print("HMAC data: {}".format(message_digest))
                # print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data

        if self.verbose:
            print("Send state is ", self.state)

        # part 2 - start
        if self.state == 1 and self.localID is not None:
            self.certificate_authority = Certificate_Authority()
            self.certificate = self.certificate_authority.generateCertificate(self.localID, self.pub_key)
            self.state = 2
        
        if self.state == 2:
            encrypted_data = self.certificate + encrypted_data
        # part 2 - end
        
        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)

        # for testing
        # print("Sending to ", self.conn)
        return struct.pack('H', len(encrypted_data)), encrypted_data

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]

        encrypted_data = self.conn.recv(pkt_len)
        
        if self.verbose:
            print("Receive state is ", self.state)
        
        # part 2 - start
        if self.state == 1 and self.localID is not None:
            self.certificate_authority = Certificate_Authority()
            self.certificate = self.certificate_authority.generateCertificate(self.localID, self.pub_key)
            self.state = 2

        if self.state != 0 and pkt_len > 128:
            signature = encrypted_data[:128]
            msg = encrypted_data[128:]
            pkt_len = pkt_len - 128
            if self.state == 2:
                # verify signature
                user_certificate = self.certificate_authority.generateCertificate(self.remoteID, self.remote_pub_key)
                if user_certificate == signature:
                    print("User Signature Verified")

        else:
            msg = encrypted_data

        # part 2 - end

        if self.cipher:
            data = self.cipher.decrypt(msg)
            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                #print("Encrypted data: {}".format(repr(encrypted_data)))
                #print("Original data: {}".format(data))
        else:
            data = msg

        my_hmac_key = "Sahil's Secret Key"
        hmac_key = bytes(data[:32])
        hmac_msg = data[32:]
        hmac_object = hmac.new(key=my_hmac_key.encode(), msg=hmac_msg, digestmod=hashlib.sha256)
        message_digest = hmac_object.digest()

        if self.verbose:
            #print("Message Received:  ", data)
            #print("Locally calculated HMAC: ", message_digest)
            print("Actual Message Received: ", hmac_msg)

        return hmac_msg

    def close(self):
        self.conn.close()
