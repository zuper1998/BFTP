from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import SHA3_256, SHA256
from Crypto.Hash import HMAC
import time


# DSR C-> S  TS | CMD_NUM | USER_NAME | CMD | DATA* | MAC

class Client():
    client_master_key: bytes = bytes(0)
    client_generated_keys = []
    username = ""
    CMD_NUM = 0

    def __init__(self, username):
        self.client_master_key = bytes.fromhex("746869732069732064656661756c7420")  # Default key, it wont work with it
        if len(username)>80:
            raise ValueError(f"Username is too long, it should be 10 characters long but it is {len(username)}")
        self.username = username

    def generateKeysFromMaster(self):
        salt = SHA256.new(bytes(self.username, 'utf-8')).hexdigest()
        self.client_generated_keys = scrypt(self.client_master_key, salt, int(128 / 8), 2 ** 14, 8, 1, 4000)

    def generatePacket(self, cmd: int, Data):
        TS = int(time.time())

        CMD_NUM = self.CMD_NUM
        username = self.username
        nonce = TS.to_bytes(4,'big')[2:] + CMD_NUM.to_bytes(2,'big')
        cipher = AES.new(self.client_generated_keys[CMD_NUM], AES.MODE_CTR, nonce=nonce)
        cmd_and_data = cmd.to_bytes(1,'big') + bytes(Data,'utf-8')
        enc_cmd_and_data = cipher.encrypt(cmd_and_data)
        uname_bytes = bytes(username,'utf-8') + bytes(10-len(bytes(username,'utf-8')))
        message = TS.to_bytes(4,'big') + CMD_NUM.to_bytes(1,'big') + uname_bytes + enc_cmd_and_data
        h = HMAC.new(self.client_generated_keys[CMD_NUM],digestmod=SHA256)
        MAC = h.update(message).hexdigest()
        print(self.client_generated_keys[CMD_NUM])
        message+= bytes.fromhex(MAC)
        self.CMD_NUM = self.CMD_NUM + 1
        print(message)
        return message


def byte_xor(ba1, ba2):
    """ XOR two byte strings """
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])