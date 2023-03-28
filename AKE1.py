#import pygost
import uuid
from Crypto.Random import random, get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from pygost.gost3410 import CURVES, prv_unmarshal, public_key, sign, verify, pub_marshal
from pygost import gost34112012512
from os import urandom

KEY_SIZE = 16
PUBLIC_PATH = "receiver.pem"
PRIVATE_PATH = "private.pem"
curve = CURVES["id-tc26-gost-3410-12-512-paramSetA"]

def asym_encr(public_key_path, plain_text):
    public_key = RSA.importKey(open(public_key_path).read())
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(plain_text)

def asym_decr(private_key_path, cipher_text):
    private_key = RSA.importKey(open(private_key_path).read())
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(cipher_text)

'''class GOST_sign:
    curve = CURVES["id-tc26-gost-3410-12-512-paramSetA"]

    def __init__(self):'''



def get_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    file_out = open(PRIVATE_PATH, "wb")
    file_out.write(private_key)
    file_out.close()
    public_key = key.publickey().export_key()
    file_out = open(PUBLIC_PATH, "wb")
    file_out.write(public_key)
    file_out.close()

def get_public_key():
    prv_raw = urandom(64)
    prv = prv_unmarshal(prv_raw)
    pub = public_key(curve, prv)
    return pub, prv


def get_dgst(data_for_signing):
   return gost34112012512.new(data_for_signing).digest()[::-1]


def sign_data(data_for_signing: bytes, prv):
    dgst = gost34112012512.new(data_for_signing).digest()[::-1]
    signature = sign(curve, prv, dgst)
    return signature


def verify_signature(pub, signature, dgst) -> bool:
    return verify(curve, pub, dgst, signature)



class AKE_CA():
    def __init__(self):
        self._id = uuid.uuid4()
        self._k = get_random_bytes(KEY_SIZE)
        self._cert = None
        self._public_key = None
        self._msg = None

    def get_msg(self, other_user):
        self._msg = other_user.send_msg()

    def set_cert(self, public_key):
        self._public_key = public_key
        self._cert = [self._id.bytes, self._public_key]

    def send_msg(self):
        c = asym_encr(self._msg[1][1], self._k + self._id.bytes)
        public_key, prv = get_public_key()
        self.set_cert(public_key)
        sign = sign_data(self._msg[0] + c + self._msg[1][0], prv)
        msg = [c, sign, self._cert]
        return msg

class AKE_client():
    def __init__(self):
        self._id = uuid.uuid4()
        self._public = PUBLIC_PATH
        self._private = PRIVATE_PATH
        self._cert = list()
        self._nonce = None

    def set_cert(self):
        self._cert = [self._id.bytes, self._public]


    def send_msg(self):
        self._nonce = get_random_bytes(KEY_SIZE) # ~r
        self.set_cert()
        msg = [self._nonce, self._cert]
        return msg

    def get_msg(self, other_user):
        msg = other_user.send_msg()
        c = msg[0]
        sign = msg[1]
        cert = msg[2]
        hsh = get_dgst(self._nonce + c + self._id.bytes)
        if verify_signature(cert[1], sign, hsh):
            print('true sign')
        else:
            print('false sign')
            exit(0)

        session_key = asym_decr(self._private, c)
        print('session_key: ', session_key.hex())


if __name__ == "__main__":
    get_keys()
    CA = AKE_CA()
    client = AKE_client()
    CA.get_msg(client)
    client.get_msg(CA)



