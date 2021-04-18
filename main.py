# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import Lib.netsim
import Client as C
import Server as S


def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press Ctrl+F8 to toggle the breakpoint.


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    c = C.Client("AAAAAA")
    c.generateKeysFromMaster()
    MSG = c.generatePacket(4, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    s = S.Server()
    s.addUser(c.username, c.client_master_key)
    message = s.decodeMSG(MSG, c.username)
    s.doCommand(message)

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
