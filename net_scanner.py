#!usr/bin/env python

import scapy.all as scapy
import optparse


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--ip", dest="ip", help="IP address range to scan")

    (options, arguments) = parser.parse_args()

    if not options.ip:
        parser.error("Please specifiy the IP address range to scan")

    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast,
                              timeout=1, verbose=False)[0]

    clients_list = []

    for e in answered_list:
        clients_list.append({"ip": e[1].psrc, "mac": e[1].hwsrc})

    return clients_list


def print_results(results_list):
    if len(results_list) > 0:
        print("IP\t\tMAC")
        print("------------------------------------")

        for client in results_list:
            print(client["ip"] + "\t" + client["mac"])
    else:
        print("Something went wrong. Please make sure to specify a valid IP address range")


options = get_arguments()

scan_results = scan(options.ip)

print_results(scan_results)
