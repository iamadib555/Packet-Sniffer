import socket
import struct


def parse_packet(packet):
    
    ip_header = packet[0][0:20]
    
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    ttl = iph[5]
    protocol = iph[6]
    
    src_addr = socket.inet_ntoa(iph[8])
    dst_addr = socket.inet_ntoa(iph[9])
    
    print(f"Version: {version}, Header Length: {ihl}, TTL: {ttl}")
    print(f"Protocol: {protocol}, Source Address: {src_addr}, Destination Address: {dst_addr}")
    

def main():
    
    #Creating a Raw Socket
    
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sniffer.bind(('192.168.1.4', 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    #On windows, Set the Socket in Promiscuous Mode
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    
    while True:
        
        packet = sniffer.recvfrom(65565)
        parse_packet(packet)
        

if __name__== "__main__":
    
    main()
    


