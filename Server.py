from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import SHA3_256, SHA256
from Crypto.Hash import HMAC
import time
from enum import Enum
import os

from Crypto.Util.Padding import unpad
from pathvalidate import sanitize_filepath, sanitize_filename

MAX_TIME_WINDOW = 30  # Max 3 seconds from send


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

        enc_text = ENC_MSG
        nonce = nonce = TS[2:] + CMD_NUM
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        text: bytes = cipher.decrypt(enc_text)
        CMD = text[0]
        DATA = text[1:]
        TS: int = int.from_bytes(TS, 'big')
        CMD_NUM: int = int.from_bytes(CMD_NUM, 'big')
        USERNAME: str = unpad(USERNAME, 10).decode('utf-8')
        print(CMD)
        print(DATA)
        return Message(TS, CMD_NUM, USERNAME, CMD, DATA, MAC)

    def createDir(self, FolderName: str, user: User):
        folder_DIR = os.path.join(self.utilGetCurDir(user))
        os.mkdir(folder_DIR)
        return "Folder Created"

    def removeDir(self, FolderName: str, user: User):
        folder_DIR = os.path.join(self.utilGetCurDir(user))
        os.rmdir(folder_DIR)
        return "Done removing"

    def getCurDir(self, user: User):
        return self.utilGetCurDir(user)

    def setCurDir(self, path: str, user: User):
        if os.path.exists(os.path.join(self.utilGetCurDir(user), path)):
            user.current_dir = path
        else:
            return "No such path"

    def getContents(self, path: str, user: User):
        if os.path.exists(os.path.join(self.utilGetCurDir(user), path)):
            return os.listdir(os.path.join(self.utilGetCurDir(user), path))
        else:
            raise ValueError("No such path")

    # TODO FAST! upload datamethod
    def upload(self, Data: bytes, user: User):

        return "Upload completed"

    def download(self, file: str, user: User):
        path_to_file = os.path.join(self.utilGetCurDir(user), file)
        return open(path_to_file).read()

    def removeFileFromDir(self, path_and_file: str, user: User):
        path_to_file = os.path.join(self.utilGetCurDir(user), path_and_file)
        os.remove(path_to_file)
        return f"{path_to_file} successfully deleted"

    def doCommand(self, msg: Message):
        if int(time.time()) - msg.TS > 30:
            raise ValueError("Message is to old")
        user = None
        for u in self.users:
            print(u.username)
            print(msg.USER_NAME)
            if u.username == msg.USER_NAME:
                user = u
        out = None
        cmd = Commands(msg.CMD_NUM)
        if cmd == Commands.MKD:
            out = self.createDir(sanitize_filepath(msg.DATA.decode('utf-8')), user)
        if cmd == Commands.RMD:
            out = self.removeDir(sanitize_filepath(msg.DATA.decode('utf-8')), user)
        if cmd == Commands.GWD:
            out = self.getCurDir(user)
        if cmd == Commands.CWD:
            out = self.setCurDir(sanitize_filepath(msg.DATA.decode('utf-8')), user)
        if cmd == Commands.LST:
            out = self.getContents(sanitize_filepath(msg.DATA.decode('utf-8')), user)
        if cmd == Commands.UPL:
            out = self.upload(msg.DATA, user)
        if cmd == Commands.DNL:
            out = self.download(sanitize_filepath(msg.DATA.decode('utf-8')), user)
        if cmd == Commands.RMF:
            out = self.removeFileFromDir(sanitize_filepath(msg.DATA.decode('utf-8')), user)

        print(out)


    def utilGetCurDir(self, user: User):
        BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        user_DIR = os.path.join(BASE_DIR, user.username)
        cur_dir = os.path.join(user_DIR, user.current_dir)
        return cur_dir
