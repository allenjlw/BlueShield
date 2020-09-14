#!/usr/bin/python

class Device():
    def __init__(self):
        self.mac = '11:22:33:44:55:66'
        self.advInterval = 0
        self.advData = ''
        self.connectedData = ''
        self.addrType = ''
        self.rssi1 = 0
        self.rssi2 = 0
        self.rssi3 = 0
        self.timeout = 0
        self.param = None

    def setMac(self, mac):
        self.mac = mac

    def setAdvInterval(self, interval):
        self.advInterval = int(interval)

    def setAdvData(self, adv_data):
        self.advData = adv_data

    def setConnedData(self, conned_data):
        self.connectedData = conned_data

    def setAddressType(self, addr_type):
        self.addrType = addr_type

    def setTimeout(self, timeout):
        self.timeout = int(timeout)

