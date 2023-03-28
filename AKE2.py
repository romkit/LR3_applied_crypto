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


class AKE2_CA:
    def __init__(self):
        self._id = uuid.uuid4()
        self._usr_rsa_pub = None
        self._k = get_random_bytes(KEY_SIZE)
        self._public = None
        self._client_cert = None
        self._cert = list()

    def get_msg(self, client):
        msg = client.send_msg()
        client_rsa_public = msg[0].encode()
        client_sign = msg[1]
        client_cert = msg[2]
        hsh = get_dgst(client_rsa_public)
        if verify_signature(client_cert[1], client_sign, hsh):
            print('true sign')
            self._usr_rsa_pub = client_rsa_public
            self._client_cert = client_cert
        else:
            print('false sign')
            exit(0)

    def send_msg(self):
        c = asym_encr(self._usr_rsa_pub, self._k + self._id.bytes)
        self._public, prv = get_public_key()
        sign = sign_data(self._usr_rsa_pub + c + self._client_cert[0], prv)
        self._cert = [self._id.bytes, self._public]
        msg = [c, sign, self._cert]

        return msg



class AKE2_user:
    def __init__(self):
        self._id = uuid.uuid4()
        self._rsa_public = PUBLIC_PATH
        self._rsa_private = PRIVATE_PATH
        self._sign_public = None
        self._cert = list()


    def send_msg(self):
        self._sign_public, prv = get_public_key()
        sign = sign_data(self._rsa_public.encode(), prv)
        self._cert = [self._id.bytes, self._sign_public]
        msg = [self._rsa_public, sign, self._cert]
        return msg

    def get_msg(self, srv):
        msg = srv.send_msg()
        c = msg[0]
        sign = msg[1]
        cert = msg[2]
        hsh = get_dgst(self._rsa_public.encode() + c + self._id.bytes)
        if verify_signature(cert[1], sign, hsh):
            print('true sign2')
        else:
            print('false sign2')

        c_plain = asym_decr(self._rsa_private, c)
        session_key = c_plain[:-16]
        print('session_key: ', session_key.hex())


if __name__ == "__main__":
    get_keys()
    srv = AKE2_CA()
    client = AKE2_user()
    srv.get_msg(client)
    client.get_msg(srv)
