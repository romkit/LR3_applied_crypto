from DH import get_params, get_key
import uuid
from Crypto.Random import random, get_random_bytes
import gmpy2
from random import randint
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from pygost.gost3410 import CURVES, prv_unmarshal, public_key, sign, verify
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


class AKE2eg_srv:
    def __init__(self, prime, gen):
        self._id = uuid.uuid4()
        self._gen = gen
        self._prime = prime
        self._k = get_random_bytes(KEY_SIZE)
        self._cert = None
        self._public = None
        self._msg = None
        self._session_key = None
        self._sign_public = None

    def set_param(self):
        self._beta = randint(1, self._prime - 2)
        self._public = gmpy2.to_binary(gmpy2.powmod(self._gen, self._beta, self._prime))
        # self._cert = [self._id.bytes, self._public]

    def get_msg(self, client):
        self.set_param()
        self._msg = client.send_msg()

    def send_msg(self):
        client_public = self._msg[0]
        client_sign = self._msg[1]
        client_cert = self._msg[2]
        hsh = get_dgst(client_public)
        if verify_signature(client_cert[1], client_sign, hsh):
            print('true sign')
            self._usr_pub = client_public
            self._client_cert = client_cert
        else:
            print('false sign')
            exit(0)
        data = self._msg[0] + self._public + gmpy2.to_binary(gmpy2.powmod(gmpy2.from_binary(self._msg[0]),
                                                                          self._beta, self._prime)) + self._id.bytes
        self._session_key = get_key(gmpy2.from_binary(data))
        print('srv_key: ', self._session_key.hex())

        self._sign_public, prv = get_public_key()
        self._cert = [self._id.bytes, self._sign_public]
        #print(f'srv data: srv pub: {self._public.hex()}, usr pub: {client_public.hex()}, srv id: {self._id.bytes}')
        sign = sign_data(client_public + self._public + self._id.bytes, prv)
        msg = [self._public, sign, self._cert]
        return msg


class AKE2eg_client:
    def __init__(self, prime, gen):
        self._id = uuid.uuid4()
        self._nonce = None
        self._cert = list()
        self._prime = prime
        self._gen = gen
        self._public = None
        self._private = None
        self._alpha = None
        self._sign_public = None
        self._session_key = None

    def set_param(self):
        self._alpha = randint(1, self._prime - 2)
        self._public = gmpy2.to_binary(gmpy2.powmod(self._gen, self._alpha, self._prime))
        # self._cert = [self._id.bytes, self._public]

    def send_msg(self):
        self.set_param()
        self._sign_public, prv = get_public_key()
        sign = sign_data(self._public, prv)
        self._cert = [self._id.bytes, self._sign_public]
        msg = [self._public, sign, self._cert]
        return msg

    def get_msg(self, srv):
        msg = srv.send_msg()
        srv_public = msg[0]
        srv_sign = msg[1]
        srv_cert = msg[2]
        hsh = get_dgst(self._public + srv_public + srv_cert[0])
        if verify_signature(srv_cert[1], srv_sign, hsh):
            print('srv_true_sign')
        else:
            print('srv_false_sign')
            exit(0)

        #print(f'usr data: srv pub: {srv_public.hex()}, usr pub: {self._public.hex()}, srv id: {srv_cert[0]}')
        data = self._public + srv_public + gmpy2.to_binary(gmpy2.powmod(gmpy2.from_binary(srv_public),
                                                                        self._alpha, self._prime)) + srv_cert[0]
        self._session_key = get_key(gmpy2.from_binary(data))
        print('usr_key: ', self._session_key.hex())


if __name__ == "__main__":
    prime, gen = get_params()
    srv = AKE2eg_srv(prime, gen)
    client = AKE2eg_client(prime, gen)
    srv.get_msg(client)
    client.get_msg(srv)
