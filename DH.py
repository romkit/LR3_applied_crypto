# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
from Crypto.Util.number import getStrongPrime
from Crypto.Random import random, get_random_bytes
import uuid
import gmpy2
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.number import long_to_bytes, getStrongPrime
from Crypto.Hash import SHA512

def randint(x, y):
    a = int(x)
    b = int(y)

    return gmpy2.mpz(random.randint(a, b))

def get_params(length = 512):
    prime = gmpy2.mpz(getStrongPrime(length))
    gen = randint(2, prime - 2)
    return prime, gen

def get_key(pre_key):
    key = HKDF(DiffieHellman.HKDF_master_secret,
               DiffieHellman.KEY_LENGTH,
               long_to_bytes(int(pre_key)),
               SHA512,
               1)
    return key

class DiffieHellman:
    HKDF_master_secret = get_random_bytes(16)
    KEY_LENGTH = 32


    def __init__(self, prime, gen):
        self.p = prime
        self.a = gen
        self.pre_key = None
        self.id = uuid.uuid4()
        self.pre_param = None

    def gen_pre_param(self):
        self.pre_param = randint(1, int(self.p) - 2)

    def fst_gen_step(self):
        param = gmpy2.powmod(self.a, self.pre_param, self.p)

        return param

    def scnd_gen_step(self, other_client):
        other_client_param = other_client.fst_gen_step()
        self.pre_key = gmpy2.powmod(other_client_param, self.pre_param, self.p)
        key = get_key(self.pre_key)
        return key

if __name__ == '__main__':
    prime, gen = get_params()

    fst = DiffieHellman(prime,gen)
    scnd = DiffieHellman(prime, gen)
    fst.gen_pre_param()
    scnd.gen_pre_param()
    key1 = fst.scnd_gen_step(scnd)
    key2 = scnd.scnd_gen_step(fst)
    print(f'1st key: {key1.hex()}')
    print(f'2nd key: {key2.hex()}')

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
