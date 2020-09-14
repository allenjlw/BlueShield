#!/usr/bin/python
import pickle
from pwn import *
from Advpkt import *
from Device import *


sock = None
p = None
uberpath = '/usr/local/bin/ubertooth-btle'

def getUbertooth(channel, mac=None, timeout=None):
    global p
    if timeout is None:
        if mac is None:
            p = process(uberpath + ' -n -A ' + channel, shell=True)
        else:
            p = process(uberpath + ' -n -A ' + channel + ' -t' + mac, shell=True)
    else:
        p = process('timeout ' + timeout + ' ' + uberpath + ' -n -A ' + channel, shell=True)
    return p


def collect(channel, time):
    global sock, p
    # clear target
    process(uberpath + ' -t none', shell=True)
    p = getUbertooth(channel, timeout=time)
    while True:
        try:
            data = p.recv()
            sock.send(data)
        except EOFError:
            break

def getInterval(mac, channel):
    global p
    p = getUbertooth(channel, mac)
    p.recvline()
    pkts = getPkts(p)
    p.kill()
    return getIntervalFromPkts(pkts)


def getRssiFromPkts(data):
    rssi_map = {}
    for d in data:
        if d.rssi in rssi_map.keys():
            rssi_map[d.rssi] += 1
        else:
            rssi_map[d.rssi] = 1
    mode = data[0].rssi
    times = 1
    for k in rssi_map.keys():
        if rssi_map[k] > times:
            times = rssi_map[k]
            mode = k
    return mode


def getIntervalFromPkts(data):
    pre = data[0].time
    # 5000ms
    interval = 5000
    for i in range(1, len(data)):
        post = data[i].time
        if (post - pre)/1000 < interval:
            interval = (post - pre)/1000
        pre = post
    return interval


def startServer():
    sock = server(5555, callback=cmdloop)
    sock.wait()


def cmdloop(insock):
    global sock, p
    sock = insock
    print('Center connected.\n')
    while True:
        try:
            line = sock.recvline()
            if 'cmd' in line:
            # handle command from center
                cmd = line.strip().split()[1]
                if cmd == 'advdata':
                    print('CMD: advdata')
                    mac = sock.recvline(keepends=False)
                    sendPkt(getAdvertisingData(mac))
                elif cmd == 'advdatatimeout':
                    print('CMD: advdatatimeout')
                    timeout = int(line.strip().split()[2])
                    mac = sock.recvline(keepends=False)
                    sendPkt(getAdvertisingData(mac, timeout))
                elif cmd == 'intervalandrssi':
                    print('CMD: intervalandrssi')
                    channel = line.strip().split()[2]
                    mac = sock.recvline(keepends=False)
                    interval = getInterval(mac, channel)
                    sendData(str(interval))
                elif cmd == 'collect':
                    print('CMD: collect')
                    channel = line.strip().split()[2]
                    time = line.strip().split()[3]
                    collect(channel, time)
        except EOFError:
            print('Center disconnected.')
            sock.close()
            p.kill()
            break


def getAdvertisingData(mac, timeout=10):
    global p
    p = getUbertooth('37', mac)
    p.readline()
    pkt = getPkt(p, timeout)
    while pkt is not None and not pkt.adv_type == 'ADV_IND':
        pkt = getPkt(p)
    p.kill()
    return pkt


def sendPkts(pkt_list):
    global sock
    sock.sendline(str(len(pkt_list)))
    for pkt in pkt_list:
        sendPkt(pkt)


def sendPkt(pkt):
    global sock
    pickle.dump(pkt, sock)


def sendData(data_list):
    global sock
    sock.sendline(str(len(data_list)))
    for data in data_list:
        sock.sendline(data)


def main():
    startServer()


if __name__ == "__main__":
    main()
