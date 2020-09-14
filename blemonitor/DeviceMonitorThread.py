#!/usr/bin/python
import threading
import numpy as np
import pickle
import os.path as ospath
# from trainning import trainPhase
from helper_functions import isAligned

def add_mac_to_db(mac):
    mac_db_path = '../spoof_mac'
    fmacdb = open(mac_db_path, 'a+')
    fmacdb.write(mac + '\n')
    fmacdb.close()

def gaussian(x, mu, sig):
    return np.exp(-np.power(x - mu, 2.) / (2 * np.power(sig, 2.)))

class DeviceMonitorThread(threading.Thread):
    """
    This class is used for monitoring one device in a seprate thread.
    """

    def __init__(self):
        threading.Thread.__init__(self)
        self.dev = None
        self.c1queue = None
        self.c2queue = None
        self.c3queue = None

        self.c1ml37channel = []
        self.c1ml38channel = []
        self.c1ml39channel = []
        self.c2ml37channel = []
        self.c2ml38channel = []
        self.c2ml39channel = []
        self.c3ml37channel = []
        self.c3ml38channel = []
        self.c3ml39channel = []

        self.exit = False
        self.maxmiss = 5
        self.model = dict()
        self.timestamps = dict()
        self.window_size = 100
        self.lookbackwindowsize = 3
        self.rssithreshold = 4
        self.cfothreshold = 3
        self.location_check_flag = False

    def setQueue(self, queueDict):
        self.c1queue = queueDict[1]
        self.c2queue = queueDict[2]
        self.c3queue = queueDict[3]

    def setDevice(self, dev):
        self.dev = dev
        self.timeout = float(self.dev.advInterval) / 1000 * self.maxmiss

    def alignPackets(self):
        # If timestamp difference is bigger than an interval
        # ignore the older packet.
        # Therefore, the three packets from three channels are aligned.
        # This is for real time purpose.
        pkt1 = self.checkInterval(1)
        pkt2 = self.checkInterval(2)
        pkt3 = self.checkInterval(3)
        while not self.exit:
            result = isAligned(pkt1, pkt2, pkt3, int(self.dev.advInterval) - 10)
            if len(result) == 0:
                if pkt1.channel == 37:
                    if len(self.c1ml37channel) == self.window_size:
                        self.c1ml37channel.pop(0)
                    self.c1ml37channel.append(pkt1)
                elif pkt1.channel == 38:
                    if len(self.c1ml38channel) == self.window_size:
                        self.c1ml38channel.pop(0)
                    self.c1ml38channel.append(pkt1)
                elif pkt1.channel == 39:
                    if len(self.c1ml39channel) == self.window_size:
                        self.c1ml39channel.pop(0)
                    self.c1ml39channel.append(pkt1)

                if pkt2.channel == 37:
                    if len(self.c2ml37channel) == self.window_size:
                        self.c2ml37channel.pop(0)
                    self.c2ml37channel.append(pkt2)
                elif pkt2.channel == 38:
                    if len(self.c2ml38channel) == self.window_size:
                        self.c2ml38channel.pop(0)
                    self.c2ml38channel.append(pkt2)
                elif pkt2.channel == 39:
                    if len(self.c2ml39channel) == self.window_size:
                        self.c2ml39channel.pop(0)
                    self.c2ml39channel.append(pkt2)

                if pkt3.channel == 37:
                    if len(self.c3ml37channel) == self.window_size:
                        self.c3ml37channel.pop(0)
                    self.c3ml37channel.append(pkt3)
                elif pkt3.channel == 38:
                    if len(self.c3ml38channel) == self.window_size:
                        self.c3ml38channel.pop(0)
                    self.c3ml38channel.append(pkt3)
                elif pkt3.channel == 39:
                    if len(self.c3ml39channel) == self.window_size:
                        self.c3ml39channel.pop(0)
                    self.c3ml39channel.append(pkt3)
                break
            else:
                if 1 in result:
                    pkt1 = self.checkInterval(1)
                if 2 in result:
                    pkt2 = self.checkInterval(2)
                if 3 in result:
                    pkt3 = self.checkInterval(3)

    def checkInterval(self, collector):
        while not self.exit:
            pkt = self.checkStatusAndGetDataByCollector(collector)
            if not pkt is None:
                break
        prev_stamp = self.timestamps.get(collector)
        if prev_stamp is None:
            self.timestamps[collector] = pkt.time
        else:
            # if the interval is less than *interval* - 10 raise warning
            if (pkt.time - prev_stamp)/1000 < int(self.dev.advInterval) - 10:
                add_mac_to_db(self.dev.mac)
                print('Suspicious advertiser of MAC: ' + self.dev.mac + ' at channel ' + str(pkt.channel))
            self.timestamps[collector] = pkt.time
        return pkt

    def checkStatusAndGetDataByCollector(self, collector):
        channel_map = {1: self.c1queue, 2: self.c2queue, 3: self.c3queue}
        item = None
        if self.dev.connectedData is None:
            item = channel_map[collector].get(True)

        elif self.dev.connectedData == 'ADV_SCAN_IND' or self.dev.connectedData == 'ADV_NONCONN_IND':
            item = channel_map[collector].get()
            if item.adv_type == self.dev.connectedData:
                print('Device ' + self.dev.mac + ' connected!')

        if item.adv_type == 'CONN' and not self.location_check_flag:
            print('check rssicfo')
            self.rssiCfoCheck()
        return item

    def rssiCfoCheck(self):
        # match rssi before and after connection
        # set location check flag, so that rssiCheck() will not be called when collecting later part data
        self.location_check_flag = True
        c1pkt37 = self.c1ml37channel
        c1pkt38 = self.c1ml38channel
        c1pkt39 = self.c1ml39channel
        c2pkt37 = self.c2ml37channel
        c2pkt38 = self.c2ml38channel
        c2pkt39 = self.c2ml39channel
        c3pkt37 = self.c3ml37channel
        c3pkt38 = self.c3ml38channel
        c3pkt39 = self.c3ml39channel
        self.c1ml37channel = []
        self.c1ml38channel = []
        self.c1ml39channel = []
        self.c2ml37channel = []
        self.c2ml38channel = []
        self.c2ml39channel = []
        self.c3ml37channel = []
        self.c3ml38channel = []
        self.c3ml39channel = []
        while True:
            self.alignPackets()
            if len(self.c1ml37channel) >= self.lookbackwindowsize and len(self.c1ml38channel) >= self.lookbackwindowsize and len(self.c1ml39channel) >= self.lookbackwindowsize and len(self.c2ml37channel) >= self.lookbackwindowsize and len(self.c2ml38channel) >= self.lookbackwindowsize and len(self.c2ml39channel) >= self.lookbackwindowsize and len(self.c3ml37channel) >= self.lookbackwindowsize and len(self.c3ml38channel) >= self.lookbackwindowsize and len(self.c3ml39channel) >= self.lookbackwindowsize:
                break
        self.location_check_flag = False
        self.datacmp([c1pkt37, c1pkt38, c1pkt39], [self.c1ml37channel, self.c1ml38channel, self.c1ml39channel])
        self.datacmp([c2pkt37, c2pkt38, c2pkt39], [self.c2ml37channel, self.c2ml38channel, self.c2ml39channel])
        self.datacmp([c3pkt37, c3pkt38, c3pkt39], [self.c3ml37channel, self.c3ml38channel, self.c3ml39channel])


    def datacmp(self, befor_con, after_con):
        rssilist37 = []
        rssilist38 = []
        rssilist39 = []
        cfolist37 = []
        cfolist38 = []
        cfolist39 = []
        for i in range(len(befor_con)):
            rssilist37.append(befor_con[0][i].rssi)
            rssilist38.append(befor_con[1][i].rssi)
            rssilist39.append(befor_con[2][i].rssi)
            cfolist37.append(befor_con[0][i].cfo)
            cfolist38.append(befor_con[1][i].cfo)
            cfolist39.append(befor_con[2][i].cfo)
        rssimean37 = np.mean(rssilist37)
        rssimean38 = np.mean(rssilist38)
        rssimean39 = np.mean(rssilist39)
        rssistd37 = np.std(rssilist37)
        rssistd38 = np.std(rssilist38)
        rssistd39 = np.std(rssilist39)

        cfomean37 = np.mean(cfolist37)
        cfomean38 = np.mean(cfolist38)
        cfomean39 = np.mean(cfolist39)
        cfostd37 = np.std(cfolist37)
        cfostd38 = np.std(cfolist38)
        cfostd39 = np.std(cfolist39)

        # rssi check
        loglikely = []
        for i in after_con[0]:
            loglikely.append(-np.log(gaussian(i.rssi, rssimean37, rssistd37)))
        if np.mean(loglikely) > self.rssithreshold:
            self.warning()
        loglikely = []
        for i in after_con[1]:
            loglikely.append(-np.log(gaussian(i.rssi, rssimean38, rssistd38)))
        if np.mean(loglikely) > self.rssithreshold:
            self.warning()
        loglikely = []
        for i in after_con[2]:
            loglikely.append(-np.log(gaussian(i.rssi, rssimean39, rssistd39)))
        if np.mean(loglikely) > self.rssithreshold:
            self.warning()

        # cfo check
        loglikely = []
        for i in after_con[0]:
            loglikely.append(-np.log(gaussian(i.cfo, cfomean37, cfostd37)))
        if np.mean(loglikely) > self.rssithreshold:
            self.warning()
        loglikely = []
        for i in after_con[1]:
            loglikely.append(-np.log(gaussian(i.cfo, cfomean38, cfostd38)))
        if np.mean(loglikely) > self.rssithreshold:
            self.warning()
        loglikely = []
        for i in after_con[2]:
            loglikely.append(-np.log(gaussian(i.rssi, cfomean39, cfostd39)))
        if np.mean(loglikely) > self.rssithreshold:
            self.warning()

    def warning(self):
        print("Warning: spoofer detected of MAC address: " + self.dev.mac)


    def run(self):
        print('Device monitor thread ' + self.dev.mac + ' started.')

        print('Device model loaded.')
        while not self.exit:
            self.alignPackets()

        print('Ctrl C pressed, exiting...')
