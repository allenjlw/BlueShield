# BlueShield

BlueShield is a monitoring system that can detect spoofed BLE advertising messages based on the physical features of the advertising and the cyber features of the BLE devices.
Detailed information about BlueShield can be found in our [paper](https://friends.cs.purdue.edu/pubs/RAID20-BlueShield.pdf).

## Dependency

- Monitor (laptop or desktop)

    Python 2.7.18rc1

    Numpy 1.16.6

    pwntools 4.0.1

- Collector (Raspberry Pi with Ubertooth One)

    Python 2.7.13

    pwntools 4.0.1


## Deployment

BlueShield needs three Collectors and one Monitor within a local network so that the Collector can send the captured data to the Monitor.
The Collector consists of a Raspberry Pi and a Ubertooth One.

The Ubertooth One uses the customized firmware, host library, and tools.

Please use the ubertooth code within this repo and follow [this tutorial](https://github.com/greatscottgadgets/ubertooth/wiki/Building-from-git) to build the binary and [flash the firmware](https://github.com/greatscottgadgets/ubertooth/wiki/Firmware) to Ubertooth.

- blemonitor/config

    This file contains the IP addresses of the Collector so that the Monitor can read this file and connect to the three collectors.

- blemonitor/maclist

    This file contains the MAC addresses of the BLE devices being monitored.

- blemonitor/profiles/

    This directory contains the profile for each BLE device generated during the profile phase.
    The Monitor loads these profiles when executed.

- blemonitor/collector.py

    The script runs on the collector (Raspberry Pi with Ubertooth One).
    It receives and executes commands from the Monitor.

- blemonitor/monitor.py

    The script runs on the Monitor (laptop or desktop).
    It controls the three Collectors (either profiling a BLE device or monitoring all devices).

    Usage:
    
    Run the script on the Collector first.
    
    ```
    python2 collector.py
    ```

    Profile a device with MAC address 00:11:22:33:44:55.

    ```
    python2 monitor.py profile 00:11:22:33:44:55
    ```

    Monitor all devices in the maclist file.

    ```
    python2 monitor.py
    ```
