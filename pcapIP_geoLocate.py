from scapy.all import *
from geoip2.database import Reader

def ip_extract(pcap_file):
    ip_address=[]
    packets=rdpcap(pcap_file)
    for p in packets:
        if ip in p:
            // get source 
            // get destination


