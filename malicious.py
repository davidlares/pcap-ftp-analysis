from scapy.all import *
from typing import Dict
import argparse
import json

# handing ftp packets (from the pcap file)
def handle_ftp(packets):
    client_login_attempts = {} # for storing success and failed login attempts
    for pkt in packets:
        # check if is an FTP response
        if Raw in pkt and pkt[TCP].sport == 21:
            load = pkt[Raw].load.decode()
            try:
                respond_code = int(load.split()[0]) # grabbing status code
            except:
                continue
            # failed or success
            if respond_code == 530 or respond_code == 230:
                client_ip = pkt[IP].dst # destination IP
                if client_ip not in client_login_attempts:
                    client_login_attempts[client_ip] = {'failed': 0, 'successful': 0, 'attacker': False, 'message': None} # filling the json
            # failed login
            if respond_code == 530:
                client_login_attempts[client_ip]['failed'] += 1
            # succesful login
            elif respond_code == 230:
                client_login_attempts[client_ip]['successful'] += 1
    return client_login_attempts

if __name__ == '__main__':

    # Wireshark intended protocols available (filtering) -> unencrpyted protocols
    app_filters = {'ftp': 'tcp port 21'}

    # analyze specific targetting (IPs) and a Pcap to filter
    parser = argparse.ArgumentParser(description="A network packet sniffer looking for attacks against specific applications")
    # parser.add_argument("-a", "--application", help="Application to filter packets for", required=True, choices=list(app_filters.keys()))
    parser.add_argument("-i", "--ip", help="IP address to filter packets for (source or destination)")
    parser.add_argument("-s", "--src-ip", help="Source IP address to filter packets for")
    parser.add_argument("-d", "--dst-ip", help="Destination IP address to filter packets for")
    parser.add_argument("-o", "--output", help="Output file to write to")
    parser.add_argument("pcap_file", help="PCAP file to read from")
    args = parser.parse_args()

    # handling the application (-a: Only works FTP)
    packet_filter = app_filters['ftp']

    # handling IP arg (-i)
    if args.ip:
        packet_filter = '{} and host {}'.format(packet_filter, args.ip)
    else:
        if args.src_ip:
            packet_filter = '{} and src host {}'.format(packet_filter, args.src_ip)
        elif args.dst_ip:
            packet_filter = '{} and dst host {}'.format(packet_filter, args.dst_ip)

    # handling the PCAP file
    pcap_file = args.pcap_file

    # handling the output (-o)
    output = args.output

    # handle_ftp execution (dinamically)
    handle_function = globals()['handle_{}'.format('ftp')]

    # read and analyze packets
    print('[+] Starting to read packets from file with filter "{}".'.format(packet_filter))
    # pcap reader object
    with PcapReader(tcpdump(pcap_file, args=["-w", "-", packet_filter], getfd=True)) as pcap_reader:
        client_login_attempts = handle_function(pcap_reader) # dynamic function assignation

    # check for "attacks"
    if client_login_attempts:
        print('Checking for brute force / dictionary attacks.')
        for k, v in client_login_attempts.items():
            failed = v['failed']
            if failed >= 5:
                v['attacker'] = True # attacker flag added after 5 wrong attempts
                successful = v['successful']
                if successful == 0:
                    v['message'] = '[!] WARNING: Likely attacker but no successful logins detected.'
                else:
                    v['message'] = '[!] ALERT: Likely attacker with {} successful logins detected!'.format(successful)

        # print attack info to output (-o)
        if args.output:
            with open(output, 'w') as of:
                json.dump(client_login_attempts, of, indent=2)
        else:
            print(json.dumps(client_login_attempts, indent=2))
