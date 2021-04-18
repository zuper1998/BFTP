from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import SHA3_256, SHA256
from Crypto.Hash import HMAC
import time


class User:
    server_master_key = bytes.fromhex("746869732069732064656661756c7420")  # Default key, it wont work with it
    server_key_list = []
    current_dir = "/"
    CMD_CNT = 0
    RESP_CNT = 0
    username = ""
    password = ""

    def __init__(self, username):
        self.username = username
        self.generateKeysFromMaster()

    def generateKeysFromMaster(self):
        salt = SHA256.new(bytes(self.username, 'utf-8')).hexdigest()
        self.server_key_list = scrypt(self.server_master_key, salt, int(128 / 8), 2 ** 14, 8, 1, 4000)

    def getKeyRec(self):
        key = self.server_key_list[self.CMD_CNT]
        self.CMD_CNT += 1
        return key

    def getKeyResp(self):
        key = self.server_key_list[self.RESP_CNT]
        self.RESP_CNT += 1
        return key


class Server:
    users = []

    def addUser(self, Uname, Server_Master):  # TODO set username master pwd
        self.users.append(User(Uname))

    def waitForMSG(self):
        return 0

    def decodeMSG(self, MSG: bytes, username):
        MAC_GOT = MSG[len(MSG) - 32:]
        REST_OF_MSG = MSG[:len(MSG) - 32]
        user = None
        for i in self.users:
            if i.username == username:
                user = i
        key = user.getKeyRec()
        h = HMAC.new(key, digestmod=SHA256)

        MAC = bytes.fromhex(h.update(REST_OF_MSG).hexdigest())
        print(len(MAC))
        print(len(MAC_GOT))

        if (MAC_GOT != MAC):
            raise ValueError("Mac values are not the same aborting...")
        TS: bytes = REST_OF_MSG[:4]
        CMD_NUM: bytes = REST_OF_MSG[4:5]
        USERNAME: bytes = REST_OF_MSG[5:15]
        ENC_MSG: bytes = REST_OF_MSG[15:]

        print(int.from_bytes(TS, 'big'))
        print(int.from_bytes(CMD_NUM, 'big'))
        print(USERNAME.decode('utf-8'))
        enc_text = ENC_MSG
        nonce = nonce = TS[2:] + CMD_NUM
        cipher = AES.new(key,AES.MODE_CTR,nonce=nonce)
        text : bytes = cipher.decrypt(enc_text)
        print(text)
        CMD = text[0]
        DATA = text[1:].decode('utf8')
        print(CMD)
        print(DATA)
