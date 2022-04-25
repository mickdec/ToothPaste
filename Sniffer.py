from scapy.all import *

class toothPaste:
    def __init__(self, iface, proxy_ip, proxy_port, client_ip, target_ip, target_port):
        self.proxy_ip = proxy_ip
        self.proxy_port = proxy_port
        self.client_ip = client_ip
        self.target_ip = target_ip
        self.target_port = target_port
        self.iface = iface
    

def handle_fn(tooth):
    def handle(packet):
        ip = packet.getlayer(IP)
        tcp = packet.getlayer(TCP)
        tcp_response = \
            IP(src=ip.dst, dst=ip.src) / \
            TCP(
                sport=tcp.dport,
                dport=tcp.sport
            )
        print("PACKET==================")
        print(packet.show())
        print("TCPRESP=================")
        print(tcp_response.show())
        exit()
        # send(tcp_response)
    return handle


#Penser à démarrer pcap service
tooth = toothPaste("Wi-Fi", "127.0.0.1", "8081", "192.168.8.131", "51.210.109.138", "9010")
#  + " && dst " + target_ip
#  && src " + proxy_ip
seek = f"tcp port {tooth.target_port}"
pkts = sniff(count=25,filter=seek,prn=handle_fn(tooth))
