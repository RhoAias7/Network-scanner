#!/usr/bin/env python
import argparse

import scapy.all as scapy


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", dest="ip", help="New ip range")
    options = parser.parse_args()
    if not options.ip:
        parser.error("[-] Please specify an ip range, use --help for more info")
    return options


options = get_args()


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for response in answered_list:
        client_dictionary = {"ip": response[1].psrc, "mac": response[1].hwsrc}
        clients_list.append(client_dictionary)
    return clients_list


def print_result(result_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])


print_result(scan(options.ip))
