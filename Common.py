from enum import Enum, IntEnum

class MsgType(IntEnum):
    Register = 0
    Login = 1
    GenReply = 2

class Commands(Enum):
    MKD = 0
    RMD = 1
    GWD = 2
    CWD = 3
    LST = 4
    UPL = 5
    DNL = 6
    RMF = 7
    RPLY = 8
    RPLY_UPL = 9

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