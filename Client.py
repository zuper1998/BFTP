from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import SHA3_256, SHA256
from Crypto.Hash import HMAC
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import os
import time
from enum import Enum
import pyfiglet

from Common import MsgType, Message, Commands
from netsim.netinterface import network_interface


# DSR C-> S  MSG_TYPE | TS | CMD_NUM | USER_NAME | CMD | DATA* | MAC


class Client():
    server_public_key: bytes
    client_master_key: bytes = bytes(0)
    client_generated_keys = []
    username = ""
    CMD_NUM = 0

    def __init__(self, username):
        self.client_master_key = bytes(0)  # Default key, it wont work with it
        if len(username) > 9:
            raise ValueError(f"Username is too long, it should be 9 characters long maximum, but it is {len(username)}")
        self.username = username

    def generateKeysFromMaster(self):
        salt = SHA256.new(bytes(self.username, 'utf-8')).hexdigest()
        self.client_generated_keys = scrypt(self.client_master_key, salt, int(128 / 8), 2 ** 14, 8, 1, 4000)

    def generatePacket(self, cmd: int, Data: bytes):
        msg_type: int = 2
        TS = int(time.time())

        CMD_NUM = self.getCMDNUMInc()
        username = self.username
        nonce = TS.to_bytes(4, 'big')[2:] + CMD_NUM.to_bytes(2, 'big')
        cipher = AES.new(self.client_generated_keys[CMD_NUM], AES.MODE_CTR, nonce=nonce)
        cmd_and_data = cmd.to_bytes(1, 'big') + Data
        enc_cmd_and_data = cipher.encrypt(cmd_and_data)
        uname_bytes = pad(bytes(username, 'utf-8'), 10)
        message = msg_type.to_bytes(1, 'big') + TS.to_bytes(4, 'big') + CMD_NUM.to_bytes(1,
                                                                                         'big') + uname_bytes + enc_cmd_and_data
        h = HMAC.new(self.client_generated_keys[CMD_NUM], digestmod=SHA256)
        MAC = h.update(message).hexdigest()
        message += bytes.fromhex(MAC)
        return message

    def utilGetCurDir(self):
        BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return BASE_DIR

    def upload(self, file: str):
        path_f = os.path.join(self.utilGetCurDir(), file)
        if os.path.exists(path_f):
            file_content: bytes = open(path_f, "br").read()
            file_name = os.path.basename(path_f)
            return bytes(file_name, 'utf-8') + bytes([0, 0, 0, 8]) + file_content

    def getCommand(self, command: str):  # get the text user types in, should be smth like LST folderName
        comd_arr = command.split(" ")
        folder_file_name: str = ""
        if len(comd_arr) > 0:
            try:
                cmd = Commands[comd_arr[0].upper()]
            except:
                print("Command not found")
                return
        if len(comd_arr) > 1:
            folder_file_name: str = comd_arr[1]

        if cmd == Commands.UPL:
            return self.generatePacket(cmd.value, self.upload(folder_file_name))
        else:
            return self.generatePacket(cmd.value, bytes(folder_file_name, 'utf-8'))

    def decodeMsg(self, MSG: bytes):
        MAC_GOT = MSG[len(MSG) - 32:]
        REST_OF_MSG = MSG[:len(MSG) - 32]
        CMD_NUM: bytes = REST_OF_MSG[5:6]
        key = self.client_generated_keys[int.from_bytes(CMD_NUM, 'big')]
        self.CMD_NUM = int.from_bytes(CMD_NUM, 'big')
        h = HMAC.new(key, digestmod=SHA256)
        MAC = bytes.fromhex(h.update(REST_OF_MSG).hexdigest())
        if MAC_GOT != MAC:
            raise ValueError("Mac values are not the same aborting...")
        TS: bytes = REST_OF_MSG[1:5]
        CMD_NUM: bytes = REST_OF_MSG[5:6]
        USERNAME: bytes = REST_OF_MSG[6:16]
        ENC_MSG: bytes = REST_OF_MSG[16:]

        nonce = TS[2:] + int.from_bytes(CMD_NUM, 'big').to_bytes(2, 'big')
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        text: bytes = cipher.decrypt(ENC_MSG)
        CMD = text[0]
        DATA = text[1:]
        TS: int = int.from_bytes(TS, 'big')
        CMD_NUM: int = int.from_bytes(CMD_NUM, 'big')
        USERNAME: str = unpad(USERNAME, 10).decode('utf-8')
        return Message(TS, CMD_NUM, USERNAME, CMD, DATA, MAC)

    def processMessage(self, MSG_R: Message):

        if MSG_R.CMD == Commands.RPLY.value:
            print(MSG_R.DATA.decode('utf-8'))
        if MSG_R.CMD == Commands.RPLY_UPL.value:
            Data = MSG_R.DATA
            index = Data.index(bytes([0, 0, 0, 8]))
            filename: str = (Data[:index].decode('utf-8'))
            data = (Data[index + 4:])
            saveFile(filename, data)
            print(f"{filename} downloaded")

    def genPrivateKey(self):
        self.client_master_key = get_random_bytes(16)
        return self.client_master_key

    # Generates registration message
    # MSG_TYPE|USERNAME|PASSWORD|PRIV_KEY|MAC
    # TODO: Remove make it more compatct ( delete the other gen msg)
    def genRegisterMsg(self, user_name: str, password: str):
        msg_type: int = MsgType.Register
        PRIV_KEY: bytes = self.genPrivateKey()
        publicKey = RSA.import_key(open("public.pem").read())
        encrpyted_MSG = pad(bytes(user_name, 'utf-8'), 10) + pad(bytes(password, 'utf8'), 16) + PRIV_KEY
        cipher_rsa = PKCS1_OAEP.new(publicKey)
        encrpyted_MSG = cipher_rsa.encrypt(encrpyted_MSG)
        MSG: bytes = msg_type.to_bytes(1, 'big') + encrpyted_MSG
        h = HMAC.new(self.client_generated_keys[self.getCMDNUMInc()], digestmod=SHA256)
        MAC = h.update(MSG).hexdigest()
        MSG += bytes.fromhex(MAC)
        return MSG

    # Generates login message
    # MSG_TYPE|USERNAME|PASSWORD|PRIV_KEY|MAC
    # PWD MAX LEN = 16!!
    def genSetupCommunicationMsg(self, user_name: str, password: str, msg_type: int):
        PRIV_KEY: bytes = self.genPrivateKey()
        publicKey = RSA.import_key(open("public.pem").read())
        encrpyted_MSG = pad(bytes(user_name, 'utf-8'), 10) + pad(bytes(password, 'utf8'), 16) + PRIV_KEY
        cipher_rsa = PKCS1_OAEP.new(publicKey)
        encrpyted_MSG = cipher_rsa.encrypt(encrpyted_MSG)
        MSG: bytes = msg_type.to_bytes(1, 'big') + encrpyted_MSG
        h = HMAC.new(PRIV_KEY, digestmod=SHA256)
        MAC = h.update(MSG).hexdigest()
        MSG += bytes.fromhex(MAC)
        return MSG

    def getCMDNUMInc(self):
        out = self.CMD_NUM
        self.CMD_NUM = self.CMD_NUM + 1
        return out


def saveFile(name: str, Data: bytes):
    open(f"{os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), name)}", "wb").write(Data)


if __name__ == "__main__":

    print(pyfiglet.figlet_format("Bundas Kenyer Protocol"))

    c = Client(input(f"give username:"))
    netif = network_interface(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "\\DSR\\", "C")
    while True:
        choice = input("Login/Register? (L/R): ")
        msg_type = MsgType.Login
        if str.upper(choice) == "L" or choice == "Login":
            msg_type = MsgType.Login
        elif str.upper(choice) == "R" or choice == "Register":
            msg_type = MsgType.Register
        user_name = c.username
        password = input("Password: ")
        message = c.genSetupCommunicationMsg(user_name, password, msg_type)  # contains private key also
        netif.send_msg("S", message)
        msg_type, resp = netif.receive_msg(blocking=True)
        if resp == bytes([1]):
            print(f"Successfull Login/Registration")
            break
        else:
            print("Error, try again")
    #  Authenticated user
    c.generateKeysFromMaster()
    while True:
        msg = c.getCommand(input(f"{os.path.dirname(os.path.dirname(os.path.abspath(__file__)))} $"))
        if msg:
            netif.send_msg("S", msg)
            stat, msg_r = netif.receive_msg(blocking=True)
            msg_type = int.from_bytes(msg_r[0:1], 'big')
            if msg_type == 2:  # DSR TYPE message
                MSG_R = c.decodeMsg(msg_r)
                c.processMessage(MSG_R)
