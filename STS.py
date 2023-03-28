import uuid

from DH import get_params, get_key
from Crypto.Random import random
from random import randint
import gmpy2
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from pygost.gost3410 import CURVES, prv_unmarshal, public_key, sign, verify, pub_marshal
from pygost import gost34112012512
from os import urandom
from pygost.gost3412 import GOST3412Kuznechik


KEY_SIZE = 16
BLOCK = 16
PUBLIC_PATH = "receiver.pem"
PRIVATE_PATH = "private.pem"
curve = CURVES["id-tc26-gost-3410-12-512-paramSetA"]

def create_pad(pad_len):
    return (BLOCK - pad_len).to_bytes(1, byteorder='big') * (BLOCK - pad_len)

def kuzn_encr(key, plain):
    plain_pad = plain + create_pad(len(plain) % BLOCK)
    cipher = GOST3412Kuznechik(key)
    cipher_text = b''
    for i in range(0, len(plain_pad), 16):
        cipher_text += cipher.encrypt(plain_pad[i:i+16])

    return cipher_text

def del_pad(data):
    pad = data[len(data) - 1]
    plain = data[:len(data) - pad]
    return plain

def kuzn_decr(key, cipher_text):
    cipher = GOST3412Kuznechik(key)
    plain_pad = b''
    for i in range(0, len(cipher_text), 16):
        plain_pad += cipher.decrypt(cipher_text[i:i+16])
    return del_pad(plain_pad)

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






class STS_serv:
    def __init__(self, prime, gen):
        self._id = uuid.uuid4()
        self._prime = prime
        self._gen = gen
        self._public_key = None
        self._sign_public_key = None
        self._power = None
        self._partner_public = None
        self._session_key = None
        self._cert = list()

    def set_power(self):
        self._power = randint(1, self._prime - 2)

    def set_public_key(self):
        self.set_power()
        self._public_key = gmpy2.to_binary(gmpy2.powmod(self._gen, self._power, self._prime))

    def set_cert(self):
        self._cert = [self._id.bytes, self._sign_public_key]

    def fst_step(self, partner):
        self.set_public_key()
        self._partner_public = partner.fst_step()
        self._sign_public_key, prv = get_public_key()
        self.set_cert()
        data = self._public_key + self._partner_public
        sign = sign_data(data, prv)
        self._session_key = get_key((gmpy2.powmod(gmpy2.from_binary(self._partner_public), self._power, self._prime)))
        encr = kuzn_encr(self._session_key, sign)
        return [self._public_key, encr, self._cert]

    def thrd_step(self, partner):
        msg = partner.scnd_step(self)
        decr = kuzn_decr(self._session_key, msg[0])
        hsh = get_dgst(self._partner_public + self._public_key)
        if verify_signature(msg[1][1], decr, hsh):
            print('sign true2')
        else:
            print('sign false2')





class STS_usr:
    def __init__(self, prime, gen):
        self._id = uuid.uuid4()
        self._prime = prime
        self._gen = gen
        self._public_key = None
        self._sign_public_key = None
        self._power = None
        self._partner_public = None
        self._session_key = None


    def set_power(self):
        self._power = randint(1, self._prime - 2)

    def set_public_key(self):
        self.set_power()
        self._public_key = gmpy2.to_binary(gmpy2.powmod(self._gen, self._power, self._prime))

    def set_cert(self):
        self._cert = [self._id.bytes, self._sign_public_key]

    def fst_step(self):
        self.set_public_key()
        return self._public_key

    def scnd_step(self, partner):
        msg = partner.fst_step(self)
        self._partner_public = msg[0]
        session_key = get_key((gmpy2.powmod(gmpy2.from_binary(self._partner_public), self._power, self._prime)))
        decr = kuzn_decr(session_key, msg[1])
        hsh = get_dgst(self._partner_public + self._public_key)
        if verify_signature(msg[2][1], decr, hsh):
            print('sign true')
            self._session_key = session_key
        else:
            print('sign false')

        self._sign_public_key, prv = get_public_key()
        self.set_cert()
        sign = sign_data(self._public_key + self._partner_public, prv)
        encr = kuzn_encr(self._session_key, sign)
        return [encr, self._cert]


if __name__ == "__main__":
    prime, gen = get_params()
    srv = STS_serv(prime, gen)
    usr = STS_usr(prime, gen)
    srv.thrd_step(usr)