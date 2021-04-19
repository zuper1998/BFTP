# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import Lib.netsim
import Client as C
import Server as S
from Server import Commands

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    c = C.Client("AAAAAAAAA")
    s = S.Server()
    s.addUser(c.username, c.client_master_key)
    c.generateKeysFromMaster()
    while(True):
        s.doCommand(s.decodeMSG(c.getCommand(input())))
# See PyCharm help at https://www.jetbrains.com/help/pycharm/
