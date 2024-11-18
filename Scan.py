from scapy.all import *
from prettytable import PrettyTable


def get_mac(ipv4):
    packet = Ether()/ARP(pdst=ipv4)
    while True:
        ans, _ = srp(packet, iface=conf.iface, timeout=5, verbose=False)
        if ans:
            return ans[0][1][Ether].src

def get_gateway_inf():
    gateway_ip = conf.route.route("0.0.0.0")
    return gateway_ip   #[iface, ip_src_addr, gateway_ip]

def get_addr_inf(target_ip):
    return (get_mac(target_ip),target_ip)

def scan_host():
    ip_list = []
    request_broadcast = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=get_gateway_inf()[2] + "/24")
    ans = srp(request_broadcast, timeout=1)[0] 
    table = PrettyTable()
    table.field_names = ["No", "IP Address", "MAC Address"]

    for index, i in enumerate(ans, start= 0):
        table.add_row([index, i[1].psrc, i[1].hwsrc])
        ip_list.append(i[1].psrc)
    print(table)
    return ip_list
