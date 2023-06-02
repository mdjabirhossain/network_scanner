import scapy.all as scapy
import argparse


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP range to scan")
    values = parser.parse_args()
    if not values.target:
        parser.error("[-] Please enter a target, use --help for more info.")
    return values.target


def scan(ip):
    #scapy.arping(ip)
    arp_request = scapy.ARP(pdst=ip)                                        # instance of an arp request packet
    #print(scapy.ls(scapy.ARP()))
    #arp_request.show()
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")                        # instance of an ethernet packet
    #broadcast.show()
    arp_request_broadcast = broadcast/arp_request                           # combines the two packets
    #arp_request_broadcast.show()

    # searches the MAC address of each device within the network
    # and looks for the one that has the ip of the arp_request packet,
    # we configured to search every MAC address by setting up the Ether dst to ff:ff:ff:ff:ff:ff
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list

def print_result(answered_list):
    print("IP" + "\t\t\t" + "MAC Address" + "\n-----------------------------------------")
    for answer in answered_list:
        # ip address of the client that responded to the arp request
        # mac address of the client with that ip that responded to the arp request
        print(answer[1].psrc + "\t\t" + answer[1].hwsrc)

def main():
    target = get_args()
    answered_list = scan(target)
    print_result(answered_list)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()
