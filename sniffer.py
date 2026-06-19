from scapy.all import *

def packet_callback(packet):

    if packet.haslayer(IP):

        src = packet[IP].src
        dst = packet[IP].dst


        proto_num = packet[IP].proto

        protocols = {
            1:  "ICMP",
            6: "TCP",
            17: "UDP"
        }

        proto = protocols.get(proto_num,"Other")

        print("\n==========================================")
        print("Source: ",src)
        print("Destination: ",dst)
        print("Protocol: ",proto)

        if packet.haslayer(Raw):
            print("Payload: ")
            print(packet[Raw].load[:100])
sniff(prn = packet_callback)            