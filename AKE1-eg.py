from DH import get_params, get_key
import uuid
from Crypto.Random import random, get_random_bytes
import gmpy2
from random import randint
from pygost.gost3410 import CURVES, prv_unmarshal, public_key, sign, verify
from pygost import gost34112012512
from os import urandom

curve = CURVES["id-tc26-gost-3410-12-512-paramSetA"]
KEY_SIZE = 16

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

class AKE1eg_CA:
    def __init__(self, prime, gen):
        self._id = uuid.uuid4()
        self._prime = prime
        self._gen = gen
        self._msg = None
        self._public = None
        self._cert = list()
        self._beta = None
        self._key = None


    def get_msg(self, client):
        self._msg = client.send_msg()

    def set_cert(self):
        self._beta = randint(1, self._prime - 2)
        self._public = gmpy2.to_binary(gmpy2.powmod(self._gen, self._beta, self._prime))
        self._cert = [self._id.bytes, self._public]

    def send_msg(self):
        public_key, prv = get_public_key()
        self.set_cert()
        sign = sign_data(self._msg[0] + self._public + self._msg[1][0], prv)
        self._cert = [self._id.bytes, public_key]
        data = self._msg[1][1] + self._public + gmpy2.to_binary(gmpy2.powmod(gmpy2.from_binary(self._msg[1][1]),
                                                                self._beta, self._prime)) + self._id.bytes
        key = get_key(gmpy2.from_binary(data))
        print(f'data: {self._msg[1][1].hex()} : {self._public.hex()} : {self._id.bytes}')
        print('srv_key: ', key.hex())
        return [self._public, sign, self._cert]

class AKE1eg_user:
    def __init__(self, prime, gen):
        self._id = uuid.uuid4()
        self._nonce = None
        self._cert = list()
        self._prime = prime
        self._gen = gen
        self._public = None
        self._alpha = None
        self._key = None


    def set_cert(self):
        self._alpha = randint(1, self._prime - 2)
        self._public = gmpy2.to_binary(gmpy2.powmod(self._gen, self._alpha, self._prime))
        self._cert = [self._id.bytes, self._public]

    def send_msg(self):
        self._nonce = get_random_bytes(KEY_SIZE)
        self.set_cert()
        msg = [self._nonce, self._cert]
        return msg

    def get_msg(self, srv):
        msg = srv.send_msg()
        srv_public = msg[0]
        sign = msg[1]
        srv_cert = msg[2]
        hsh = get_dgst(self._nonce + srv_public + self._id.bytes)
        if verify_signature(srv_cert[1], sign, hsh):
            print('true sign')
        else:
            print('false sign')

        data = self._public + srv_public + gmpy2.to_binary(gmpy2.powmod(gmpy2.from_binary(srv_public),
                                                                        self._alpha, self._prime)) + srv_cert[0]

        print(f'data: {self._public.hex()} : {srv_public.hex()} : {srv_cert[0]}')
        key = get_key(gmpy2.from_binary(data))
        print('usr_key: ', key.hex())



if __name__ == "__main__":
    prime, gen = get_params()
    srv = AKE1eg_CA(prime, gen)
    client = AKE1eg_user(prime, gen)
    srv.get_msg(client)
    client.get_msg(srv)
