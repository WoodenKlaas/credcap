from scapy.all import rdpcap
import sys
import re


def errorPcap():
    print('Error reading pcap, try converting with:\ntshark -r {} -w new.pcap -F libpcap'.format(sys.argv[1]))
    exit()

def readPacket(packet_file):
    user_re = r'(?i)(?:username|uname|user|usr)[=:\s]{1,2}(\w{2,200})' # re.findall(user_re, packet.load)[0][4]
    pass_re = r'(?i)(?:password|passwd|pass)[=:\s]{1,2}(\w{2,200})' #re.findall(pass_re, packet.load)[0][3]

    try:
        streams = rdpcap(packet_file).sessions()

    except scapy.error.Scapy_Exception:
        errorPcap()

    all_packets = []
    packet_data = {}
    for stream in streams:
        for packet in streams[stream]:
            if 'Raw' in packet:
                domain_re = re.findall(r'((?!:\/\/)(\w+\.)*\w+\.\w{2,11})', packet.load)
                user = re.findall(user_re, packet.load)
                passwd = re.findall(pass_re, packet.load)
                if user != [] and 'username' not in packet_data:
                    username = user[0]
                    packet_data['username'] = username
                    packet_data['src_ip'] = packet['IP'].src
                    packet_data['dst_ip'] = packet['IP'].dst
                    print('Found username: {}'.format(username))

                if passwd != [] and 'password' not in packet_data:
                    password = passwd[0]
                    packet_data['password'] = password
                    packet_data['src_ip'] = packet['IP'].src
                    packet_data['dst_ip'] = packet['IP'].dst
                    print('Found password: {}'.format(password))

                if domain_re != [] and 'domain' not in packet_data:
                    domain = domain_re[0][0]
                    packet_data['domain'] = domain
                    packet_data['src_ip'] = packet['IP'].src
                    packet_data['dst_ip'] = packet['IP'].dst

            elif len(packet_data) >= 4:
                all_packets.append(packet_data)
                packet_data = {}

    return all_packets


def print_help():
    print('Usage: {} <pcap file>'.format(sys.argv[0]))

def main():
    if len(sys.argv) < 2:
        print_help()
        exit()

    data = readPacket(sys.argv[1])
    print(data)

if __name__ == '__main__':
    main()
