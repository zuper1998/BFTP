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
open("public.pem","w").write(public_key.decode('utf-8'))
open("private.pem","w").write(private_key.decode('utf-8'))