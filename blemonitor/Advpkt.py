#!/usr/bin/python
import os.path as ospath

class AdvPkt:
    """Class representation of advertising packets"""
    def __init__(self):
        self.adv_type = ''
        self.addr = ''
        self.addr_type = ''
        self.data = ''
        self.channel = 0
        self.time = 0
        self.rssi = 0
        self.cfo = 0

    def setTime(self, time):
        self.time = int(time)

    def setAddr(self, addr):
        self.addr = addr

    def setRssi(self, rssi):
        self.rssi = int(rssi)

    def setAdvType(self, adv_type):
        self.adv_type = adv_type

    def setChannel(self, channel):
        self.channel = int(channel)

    def setData(self, data):
        self.data = data

    def setAddrType(self, addr_type):
        self.addr_type = addr_type

    def setCfo(self, cfo):
        self.cfo = cfo


def getPkts(infile, pktnum=30, maclist=None):
    pkts = []
    for i in range(pktnum):
        pkts.append(getPkt(infile, maclist=maclist))
    pkts.sort(key=lambda x:x.time)
    return pkts


def getPkt(infile, timeout=10, maclist=None):
    p = None

    while infile.can_recv(timeout):
        x = infile.readline()
        if x.startswith("Type:"):
            p = AdvPkt()
            if x.split()[1] == 'CONNECT_REQ':
                p.setAdvType('CONN')
                p.init = infile.readline().strip().split()[1]
                p.addr = infile.readline().strip().split()[1]
                x = infile.readline()
                p.setTime(x.split()[0].split('=')[1])
                p.setRssi(x.split()[3].split('=')[1][:-1])
                x = infile.readline()
            else:
                # Advertising packet
                p.setAdvType(x.strip().split()[1])
                x = infile.readline()
                while not x.strip() == '':
                    if x.startswith('AdvA:'):
                        p.setAddr(x.split()[1])
                        p.setAddrType(x.strip().split()[2][1:-1])
                    elif x.startswith('AdvData:'):
                        p.setData(x.split(':')[1].strip())
                    elif x.startswith('Channel'):
                        p.setChannel(x.split()[-1])
                    elif x.startswith('systime'):
                        p.setTime(x.split()[0].split('=')[1])
                        p.setRssi(x.split()[3].split('=')[1][:-1])
                        p.setCfo(x.split()[5].split('=')[1])
                    x = infile.readline()
            if maclist is None or p.addr in maclist:
                break
    return p

