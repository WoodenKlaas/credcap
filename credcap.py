from scapy.all import *
from sys import argv
import re

def errorPcap():
    print('Error reading pcap, try converting with:\ntshark -r old.pcapng -w new.pcap -F libpcap')
    exit()
def readPacket(packet_file):
    user_re = r'(username(=|\: )|uname(=|\: )|user(=|\: )|usr(=|\: )|USER )(\w*)' # re.findall(user_re, packet.load)[0][4]
    pass_re = r'(password(=|\: )|passwd(=|\: )|pass(=|\: )|PASS )(\w*)' #re.findall(pass_re, packet.load)[0][3]
    try:
        packets = rdpcap(packet_file)
    except scapy.error.Scapy_Exception:
        errorPcap()
    all_packets = []
    packet_data = {}

    for packet in packets:
        if 'Raw' in packet:
            if 'Please login with USER and PASS.' in packet.load:
                continue
            user = re.findall(user_re, packet.load)
            passwd = re.findall(pass_re, packet.load)
            if user != [] and 'username' not in packet_data:
                username = user[0][5]
                packet_data['username'] = username
                packet_data['src_ip'] = packet['IP'].src
                packet_data['dst_ip'] = packet['IP'].dst
                print('Found username: {}'.format(username))
            if passwd != [] and 'password' not in packet_data:
                password = passwd[0][4]
                packet_data['password'] = password
                packet_data['src_ip'] = packet['IP'].src
                packet_data['dst_ip'] = packet['IP'].dst
                print('Found password: {}'.format(password))
            if ' at ' in packet.load:
                domain = re.findall(r'((\w|\.)+.com)', packet.load)[0][0]
                packet_data['domain'] = domain
                packet_data['src_ip'] = packet['IP'].src
                packet_data['dst_ip'] = packet['IP'].dst
        elif len(packet_data) >= 4:
            all_packets.append(packet_data)
            packet_data = {}
    return all_packets


def print_help():
    print('Usage: {} <pcap file>'.format(argv[0]))

def main():
    if len(argv) < 2:
        print_help()
        exit()
    data = readPacket(argv[1])
    print data

if __name__ == '__main__':
    main()
