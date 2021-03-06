import pickle

from Crypto.Hash import SHA256
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import SHA3_256, SHA256
from Crypto.Hash import HMAC
import time
from enum import Enum
import os
import pickle as Pickle
from Crypto.PublicKey import RSA

from netsim.netinterface import network_interface

from Crypto.Util.Padding import unpad, pad
from pathvalidate import sanitize_filepath, sanitize_filename, sanitize_file_path

from Common import MsgType, Message, Commands, RegMessage

MAX_TIME_WINDOW = 30  # Max 3 seconds from send


class User:  # TODO: persistent storage
    server_master_key = bytes(0)  # Default key, it wont work with it
    server_key_list = []
    current_dir = ""
    CMD_CNT = 0
    RESP_CNT = 0
    username = ""
    password = ""

    def __init__(self, username, ServerMasterKey, PWD):
        self.server_master_key = ServerMasterKey
        self.username = username
        self.password = PWD
        self.generateKeysFromMaster()

    def generateKeysFromMaster(self):
        salt = SHA256.new(bytes(self.username, 'utf-8')).hexdigest()
        self.server_key_list = scrypt(self.server_master_key, salt, int(128 / 8), 2 ** 14, 8, 1, 4000)

    def getKeyRec(self, cnt: int):
        key = self.server_key_list[cnt]
        self.CMD_CNT = cnt
        return key

    def getKeyResp(self):
        key = self.server_key_list[self.RESP_CNT]
        self.RESP_CNT += 1
        return key

    def SaveToFile(self):
        saveLoc = os.path.join(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'Users'),
                               self.username)
        open(f"{saveLoc}", "wb").write(pickle.dumps(self, protocol=pickle.HIGHEST_PROTOCOL))


class Server:
    users = []  # TODO: Persistence
    private_key: bytes  # How to store it safely?

    # Loads users from storage.
    def loadUsers(self):
        userLoc = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Users")
        for file in os.scandir(userLoc):
            if file.is_file():
                file1 = open(file.path,'rb')
                self.loadUser(file1)
                file1.close()
        return

    # Saves users to storage.
    def saveUsers(self):
        for u in self.users:
            u.SaveToFile()

    def loadUser(self, file1):
        self.users.append(pickle.load(file1))

    def addUser(self, Uname, Server_Master, PWD_HASH):
        BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        user_DIR = os.path.join(BASE_DIR, Uname)
        newUser = User(Uname, Server_Master, PWD_HASH)
        self.users.append(newUser)
        newUser.SaveToFile()

        if os.path.exists(user_DIR):
            pass
        else:
            os.mkdir(user_DIR)

    def decodeMSG(self, MSG: bytes):
        MAC_GOT = MSG[len(MSG) - 32:]
        REST_OF_MSG = MSG[:len(MSG) - 32]
        user = None
        CMD_NUM: bytes = REST_OF_MSG[5:6]
        USERNAME: bytes = REST_OF_MSG[6:16]
        for i in self.users:
            if i.username == unpad(USERNAME, 10).decode('utf-8'):
                user = i
        key = user.getKeyRec(int.from_bytes(CMD_NUM, 'big'))
        h = HMAC.new(key, digestmod=SHA256)
        MAC = bytes.fromhex(h.update(REST_OF_MSG).hexdigest())

        if MAC_GOT != MAC:
            raise ValueError("Mac values are not the same aborting...")
        MSG_TYPE: bytes = REST_OF_MSG[0:1]
        TS: bytes = REST_OF_MSG[1:5]
        CMD_NUM: bytes = REST_OF_MSG[5:6]
        USERNAME: bytes = REST_OF_MSG[6:16]
        ENC_MSG: bytes = REST_OF_MSG[16:]

        enc_text = ENC_MSG
        nonce = TS[2:] + int.from_bytes(CMD_NUM, 'big').to_bytes(2, 'big')  # TODO: fix CMD_NUM being max 1 bytes
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        text: bytes = cipher.decrypt(enc_text)
        CMD = text[0]
        DATA = text[1:]
        TS: int = int.from_bytes(TS, 'big')
        CMD_NUM: int = int.from_bytes(CMD_NUM, 'big')

        USERNAME: str = unpad(USERNAME, 10).decode('utf-8')
        return Message(TS, CMD_NUM, USERNAME, CMD, DATA, MAC)

    def createDir(self, FolderName: str, user: User):
        folder_DIR = os.path.join(self.utilGetCurDir(user), FolderName)
        if self.isInUserDir(user, folder_DIR):
            os.mkdir(folder_DIR)
            return "Folder Created"
        else:
            return "Not in your own subdomain"

    def removeDir(self, FolderName: str, user: User):
        folder_DIR = os.path.join(self.utilGetCurDir(user), FolderName)
        if os.path.exists(folder_DIR):
            try:
                os.rmdir(folder_DIR)
                return "Done removing"
            except:
                return "Directory not empty"
        else:
            return f"There is no folder named {FolderName}"

    def getCurDir(self, user: User):
        return self.utilGetCurDir(user)

    def setCurDir(self, path: str, user: User):
        if os.path.exists(os.path.join(self.utilGetCurDir(user), path)):
            if self.isInUserDir(user, path):
                user.current_dir = os.path.normpath(os.path.join(user.current_dir, path))

                return f"new path set: {os.path.join(self.utilGetCurDir(user))}"
            else:
                return "Not own dir"
        else:
            return "No such path"

    def getContents(self, path: str, user: User):
        if os.path.exists(os.path.join(self.utilGetCurDir(user), path)):
            if self.isInUserDir(user, path):
                return os.listdir(os.path.join(self.utilGetCurDir(user), path))
            else:
                return "Not your own filesystem -.-"
        else:
            return f"{path} does not exits"

    # First 10 bytes filename, then the data to put there
    def upload(self, Data: bytes, user: User):
        # Somehow get the filename and the data to put
        index = Data.index(bytes([0, 0, 0, 8]))
        filename: str = (Data[:index].decode('utf-8'))
        data = (Data[index + 4:])
        path = self.utilGetCurDir(user)
        file_path = os.path.join(path, filename)
        f = open(file_path, "wb")
        f.write(data)

        return "Upload completed"

    def download(self, file: str, user: User):
        path_to_file = os.path.join(self.utilGetCurDir(user), file)
        if os.path.exists(path_to_file):
            if self.isInUserDir(user, file):
                file_content: bytes = open(path_to_file, "br").read()
                file_name = os.path.basename(path_to_file)
                return bytes(file_name, 'utf-8') + bytes([0, 0, 0, 8]) + file_content
            else:
                return "File not in your folder"
        return "File does not exists"

    def removeFileFromDir(self, path_and_file: str, user: User):
        path_to_file = os.path.join(self.utilGetCurDir(user), path_and_file)
        if os.path.exists(path_to_file):
            if self.isInUserDir(user, path_to_file):
                os.remove(path_to_file)
                return f"{path_to_file} successfully deleted"
            else:
                return "File not in your folder"
        return "File does not exists"

    def doCommand(self, msg: Message):
        if int(time.time()) - msg.TS > 30:
            raise ValueError("Message is to old")
        user = None
        for u in self.users:
            if u.username == msg.USER_NAME:
                user = u
        out = None
        cmd = Commands(msg.CMD)

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
            out = self.download(sanitize_filename(msg.DATA.decode('utf-8')), user)
        if cmd == Commands.RMF:
            out = self.removeFileFromDir(sanitize_filepath(msg.DATA.decode('utf-8')), user)

        return out

    def isInUserDir(self, user: User, path: str):
        BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        user_DIR = os.path.join(BASE_DIR, user.username)
        return dir_in_directory(os.path.join(self.utilGetCurDir(user), path), user_DIR)

    def utilGetCurDir(self, user: User):
        BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        user_DIR = os.path.join(BASE_DIR, user.username)
        cur_dir = os.path.join(user_DIR, user.current_dir)
        cur_dir = os.path.realpath(cur_dir)
        return cur_dir

    def genReply(self, reply_data: bytes, uname: str, cmd: int):
        msg_type: int = 2

        TS = int(time.time())
        user: User = None
        for u in self.users:
            if u.username == uname:
                user = u
        if user is None:
            raise ValueError(f"No user named {uname}")
        CMD_NUM = int(user.CMD_CNT)
        username = "SERVER"
        key = user.getKeyRec(CMD_NUM)
        nonce = TS.to_bytes(4, 'big')[2:] + CMD_NUM.to_bytes(2, 'big')
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        cmd_and_data = cmd.to_bytes(1, 'big') + reply_data
        enc_cmd_and_data = cipher.encrypt(cmd_and_data)
        uname_bytes = pad(bytes(username, 'utf-8'), 10)
        message = msg_type.to_bytes(1, 'big') + TS.to_bytes(4, 'big') + CMD_NUM.to_bytes(1,
                                                                                         'big') + uname_bytes + enc_cmd_and_data
        h = HMAC.new(key, digestmod=SHA256)
        MAC = h.update(message).hexdigest()
        message += bytes.fromhex(MAC)
        return message

    def decodePrivKeyMSG(self, MSG: bytes):
        MAC_GOT = MSG[len(MSG) - 32:]
        REST_OF_MSG = MSG[:len(MSG) - 32]
        # FIrst we need to get the key used in the mac so we can do the mac :D
        ENC_DATA = REST_OF_MSG[1:]
        PrivKey = RSA.import_key(open("private.pem").read())
        cipher_rsa = PKCS1_OAEP.new(PrivKey)
        DATA = cipher_rsa.decrypt(ENC_DATA)
        USERNAME: str = unpad(DATA[:10], 10).decode('utf-8')
        PWD: bytes = unpad(DATA[10:26], 16)
        PRIV_KEY: bytes = DATA[26:42]
        MSG_TYPE = int.from_bytes(REST_OF_MSG[:1], 'big')
        h = HMAC.new(PRIV_KEY, digestmod=SHA256)
        MAC = bytes.fromhex(h.update(REST_OF_MSG).hexdigest())

        if MAC_GOT != MAC:
            raise ValueError("Mac values are not the same aborting...")

        return RegMessage(MSG_TYPE, USERNAME, PWD, PRIV_KEY)

    # Registers User. Returns str message about the success of the registration.
    def registerUser(self, regMSG: RegMessage):
        if regMSG.USERNAME in self.users:
            return bytes([0])  # "Registration failed."
        if len(regMSG.PWD) == 0:
            return bytes([0])
        self.addUser(regMSG.USERNAME, regMSG.PRIV_KEY, PWD_HASH=SHA3_256.new().update(regMSG.PWD).hexdigest())
        # add key
        return bytes([1])

    # User login. Returns str message about the success of login.
    def loginUser(self, regMSG: RegMessage):
        for user in self.users:
            if user.username == regMSG.USERNAME:
                if user.password == SHA3_256.new().update(regMSG.PWD).hexdigest():
                    user.server_master_key = regMSG.PRIV_KEY
                    user.generateKeysFromMaster()
                    return bytes([1])

        return bytes([0])
        # return "Login failed: wrong password or username does not exist."


def file_in_directory(file, directory):  # Stolen from https://stackoverflow.com/questions/3812849/how-to-check-whether
    # -a-directory-is-a-sub-directory-of-another-directory make both absolute
    directory = os.path.join(os.path.realpath(directory), '')
    file = os.path.realpath(file)

    # return true, if the common prefix of both is equal to directory
    # e.g. /a/b/c/d.rst and directory is /a/b, the common prefix is /a/b
    return os.path.commonprefix([file, directory]) == directory


def dir_in_directory(directory1, directory2):  # Main dir first sub dir second
    # make both absolute
    directory1 = os.path.join(os.path.realpath(directory1), '')
    directory2 = os.path.join(os.path.realpath(directory2), '')

    # return true, if the common prefix of both is equal to directory
    # e.g. /a/b/c/d.rst and directory is /a/b, the common prefix is /a/b
    return os.path.commonprefix([directory2, directory1]) == directory2


if __name__ == "__main__":
    s = Server()
    s.loadUsers()
    netif = network_interface(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "\\DSR\\", "S")
    #print(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    while True:
        status, msg = netif.receive_msg(blocking=True)
        msg_type = int.from_bytes(msg[0:1], 'big')
        if msg_type == MsgType.Login:
            reply_data: bytes = s.loginUser(s.decodePrivKeyMSG(msg))
            # also handles private key, so reply can be encoded. Only saves it, if successful.
            netif.send_msg("C", reply_data)
        elif msg_type == MsgType.Register:
            reply_data: bytes = s.registerUser(s.decodePrivKeyMSG(msg))

            # also handles private key, so reply can be encoded. Only saves it, if successful.
            netif.send_msg("C", reply_data)
        elif msg_type == MsgType.GenReply:
            MSG = s.decodeMSG(msg)
            reply_data = s.doCommand(MSG)
            if MSG.CMD == Commands.DNL.value:
                reply = s.genReply(reply_data, MSG.USER_NAME, Commands.RPLY_UPL.value)
                netif.send_msg("C", reply)
            else:
                reply = s.genReply(bytes(str(reply_data), 'utf-8'), MSG.USER_NAME, Commands.RPLY.value)
                netif.send_msg("C", reply)
