from Crypto import Random
from Crypto.PublicKey import RSA

public_key: bytes
private_key: bytes

def generate_keys():
    generatedkey = RSA.generate(1024, Random.new().read)
    global private_key
    private_key = generatedkey.exportKey()
    global public_key
    public_key = generatedkey.publickey().exportKey()

generate_keys()
print(public_key)
print(private_key)