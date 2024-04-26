from scapy.all import *
from geoip2.database import Reader

def ip_extract(pcap_file):
    ip_address=[]
    packets=rdpcap(pcap_file)
    for p in packets:
        if ip in p:
            ip_address.append(packet[ip].src)
            ip_address.append(packet[ip].dst)
        return ip_address

def get_geolocation(ip_addr):
    reader=Reader('GeoLite2-database')  //need latest version update
    try: 
        response=reader.city(ip_addr)
        country=response.country.name
        city=response.city.name
        latitude=response.location.latitude
        longtitude=response.location.longtitude
        return country,city,latitude,longitude
    except:
        return "INVALID","INVALID",null,null

# next: write ip.addr -> country,city,GPS (could add ASN num) && main function
# read_pcap
# extract <- .pcap file
