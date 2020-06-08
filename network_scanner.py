#!/usr/bin/env python

import scapy.all as scapy
import optparse

def get_args():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target_ip", help="Target IP / IP Range")
    options, arguments = parser.parse_args()
    return options



def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')

    arp_request_packet = broadcast/arp_request

    answered_list = scapy.srp(arp_request_packet, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client_dictionary = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dictionary)

    return clients_list




def print_result(results_list):
    print("IP\t\t\tMAC Address\n----------------------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

options = get_args()

scan_result = scan(options.target_ip)

print_result(scan_result)
