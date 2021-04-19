from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import SHA3_256, SHA256
from Crypto.Hash import HMAC
from Crypto.Util.Padding import pad, unpad
import os
import time


# DSR C-> S  TS | CMD_NUM | USER_NAME | CMD | DATA* | MAC

class Client():
    client_master_key: bytes = bytes(0)
    client_generated_keys = []
    username = ""
    CMD_NUM = 0

    def __init__(self, username):
        self.client_master_key = bytes.fromhex("746869732069732064656661756c7420")  # Default key, it wont work with it
        if len(username) > 9:
            raise ValueError(f"Username is too long, it should be 9 characters long maximum, but it is {len(username)}")
        self.username = username

    def generateKeysFromMaster(self):
        salt = SHA256.new(bytes(self.username, 'utf-8')).hexdigest()
        self.client_generated_keys = scrypt(self.client_master_key, salt, int(128 / 8), 2 ** 14, 8, 1, 4000)

    def generatePacket(self, cmd: int, Data:bytes):
        TS = int(time.time())

        CMD_NUM = self.CMD_NUM
        username = self.username
        nonce = TS.to_bytes(4, 'big')[2:] + CMD_NUM.to_bytes(2, 'big')
        cipher = AES.new(self.client_generated_keys[CMD_NUM], AES.MODE_CTR, nonce=nonce)
        cmd_and_data = cmd.to_bytes(1, 'big') + Data
        enc_cmd_and_data = cipher.encrypt(cmd_and_data)
        uname_bytes = pad(bytes(username, 'utf-8'), 10)
        message = TS.to_bytes(4, 'big') + CMD_NUM.to_bytes(1, 'big') + uname_bytes + enc_cmd_and_data
        h = HMAC.new(self.client_generated_keys[CMD_NUM], digestmod=SHA256)
        MAC = h.update(message).hexdigest()
        message += bytes.fromhex(MAC)
        self.CMD_NUM = self.CMD_NUM + 1
        # print(message)
        return message

    def utilGetCurDir(self):
        BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return BASE_DIR

    def upload(self, file: str):
        path_f = os.path.join(self.utilGetCurDir(), file)
        file_content = "AAAAAAAAA"
        file_name = "Bababoe.txt"
        return bytes(file_name,'utf-8') + bytes([0, 0, 0, 8]) + bytes(file_content,'utf-8')
