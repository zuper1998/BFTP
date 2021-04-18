from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import SHA3_256, SHA256
from Crypto.Hash import HMAC
import time
from enum import Enum

MAX_TIME_WINDOW = 30 # Max 3 seconds from send


class Commands(Enum):
    MKD = 0
    RMD = 1
    GWD = 2
    CWD = 3
    LST = 4
    UPL = 5
    DNL = 6
    RMF = 7


class Message:
    TS: int
    CMD_NUM: int
    USER_NAME: str
    CMD: int
    DATA: bytes
    MAC: bytes

    def __init__(self, TS, CMD_NUM, USER_NAME, CMD, DATA, MAC):
        self.TS = TS
        self.CMD_NUM = CMD_NUM
        self.USER_NAME = USER_NAME
        self.CMD = CMD
        self.DATA = DATA
        self.MAC = MAC


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

        TS: int = int.from_bytes(TS, 'big')
        CMD_NUM: int = int.from_bytes(CMD_NUM, 'big')
        USERNAME: str = USERNAME.decode('utf-8')
        enc_text = ENC_MSG
        nonce = nonce = TS[2:] + CMD_NUM
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        text: bytes = cipher.decrypt(enc_text)
        CMD = text[0]
        DATA = text[1:].decode('utf8')
        print(CMD)
        print(DATA)
        return Message(TS, CMD_NUM, USERNAME, CMD, DATA, MAC)

    def createDir(self):
        return
    def removeDir(self):
        return
    def getCurDir(self):
        return
    def setCurDir(self):
        return
    def getContents(self):
        return
    def upload(self):
        return
    def download(self):
        return
    def removeFileFromDir(self):
        return

    def doCommand(self,msg: Message):
        if int(time.time()) - msg.TS > 30:
            raise ValueError("Message is to old")

        switch = {
            Commands.MKD : self.createDir(),
            Commands.RMD : self.removeDir(),
            Commands.GWD : self.getCurDir(),
            Commands.CWD : self.setCurDir(),
            Commands.LST : self.getContents(),
            Commands.UPL : self.upload(),
            Commands.DNL : self.download(),
            Commands.RMF : self.removeFileFromDir()
        }


