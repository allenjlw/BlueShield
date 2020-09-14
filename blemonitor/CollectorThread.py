#!/usr/bin/python
import threading
import time
from Advpkt import *


class CollectorThread(threading.Thread):
    """
    This class is used for collecting data from collectors in
    seprate processes in monitoring phase.
    """
    def __init__(self, sock, queueDict, colNumb, maclist):
        threading.Thread.__init__(self)
        self.sock = sock
        self.dict = queueDict
        self.maclist = maclist
        self.exit = False
        self.collector = colNumb

    def getPacket(self):
        pkt = getPkt(self.sock, maclist=self.maclist)
        print(pkt.adv_type)
        return pkt

    def run(self):
        print('Collector ' + str(self.collector) + ' started.')
        while not self.exit:
            pkt = self.getPacket()
            if pkt is not None:
                self.dict[pkt.addr][self.collector].put(pkt)

        print('Ctrl C pressed. Exiting...')

