# Description : Script permettant de visualiser une connexion PEAP entre un client et un serveur
# Authors     : Géraud SILVESTI, Alexandre JAQUIER, Francesco MONTI
# Date        : 17.05.2023
# Usage       : peap_explore.py -f <PCAP file>

from scapy.all import *
import argparse
import binascii

parser = argparse.ArgumentParser(prog="PEAP Explore", description="Explore PEAP packets")
parser.add_argument("-f", "--file", required=True, help="PCAP file to explore")
args = parser.parse_args()

# Check si le paquet est un paquet PEAP
def check_peap(packet):
    if packet.haslayer(EAP):
        if packet[EAP].code == 2:  # EAP Response
            if packet.haslayer(EAP_TLS):
                if packet[EAP_TLS].data:
                    return True
    return False

# Process PCAP file
def process_pcap(file):
    packets = rdpcap(file)
    session_ids = set()
    for packet in packets:
        if check_peap(packet):
            tls_data = packet[EAP_TLS].data
            # if tls_data.startswith(b'\x17\x03\x01'):  # TLS Handshake
            #     session_id = binascii.hexlify(tls_data[43:59]).decode()
            #     session_ids.add(session_id)
            session_ids.add(tls_data)
    return session_ids

# Main function
def main():
    session_ids = process_pcap(args.file)
    print(f"Found {len(session_ids)} PEAP sessions:")
    for session_id in session_ids:
        print(session_id)

if __name__ == '__main__':
    main()