import sys
import json
import struct
from scapy.all import *
from scapy.contrib.gtp import *

def generate_gtp_packets_for_pair(teidstart,teidstop, sgw_addr, pgw_addr,pcap_output_file,gsn_id):
    
    #print('tunels per pair is: '+str(tunnels_per_pair)+' and total: '+str(total_tunnels))

    # Prepare base packets from the baseline pcap
    packets = rdpcap("baseline.pcap")

    base_request = packets[0]
    base_response = packets[1]

    generated_packets = []

    gsn_half_start = 1111 # 2 second bytes of GSN in hex in request
    rgsn_half_start = 1211 # 2 sconds bytes of GSN in hex in response

    print('                            +STARTED pcap generation of sgw to pgw :'+sgw_addr+' to '+pgw_addr)

    for teid in range(teidstart, teidstop + 1):

        if teid % 10000 == 0:
            print('                            +REACHED this teid for sgw & pgw pair '+sgw_addr+' '+pgw_addr+' is: '+str(teid))
        #print('      busy with teid : '+str(teid))
        teid_bytes = struct.pack("!I", teid)
        gsn_half_bytes=struct.pack("!H",gsn_half_start+gsn_id)
        rgsn_half_bytes=struct.pack("!H",rgsn_half_start+gsn_id)

        req_pkt = base_request.copy()
        req_pkt[IP].src = sgw_addr
        req_pkt[IP].dst = pgw_addr

        # Modify values directly in bytes
        req_pkt_bytes = bytes(req_pkt)
        #req_pkt = Ether(req_pkt_bytes)
        req_pkt_bytes = (req_pkt_bytes[:72] +
                         teid_bytes + b'\x11' + teid_bytes +
                         req_pkt_bytes[81:137] + gsn_half_bytes + req_pkt_bytes[139:144] + gsn_half_bytes +
                         req_pkt_bytes[146:])
        req_pkt = Ether(req_pkt_bytes)
        
        #fix csum
        del req_pkt[IP].chksum
        del req_pkt[UDP].chksum

        generated_packets.append(req_pkt)

        # Update Response Packet
        resp_pkt = base_response.copy()
        resp_pkt[IP].src = pgw_addr
        resp_pkt[IP].dst = sgw_addr

        # Modify values directly in bytes
        resp_pkt_bytes = bytes(resp_pkt)
        resp_pkt_bytes = (resp_pkt_bytes[:50] + teid_bytes +
                          resp_pkt_bytes[54:65] + teid_bytes + b'\x11' + teid_bytes +
                          b'\x7f' + teid_bytes +
                          resp_pkt_bytes[79:93] + rgsn_half_bytes + resp_pkt_bytes[95:100] + rgsn_half_bytes +
                          resp_pkt_bytes[102:] )
        resp_pkt = Ether(resp_pkt_bytes)

        #fix csum
        del resp_pkt[IP].chksum
        del resp_pkt[UDP].chksum
        
        generated_packets.append(resp_pkt)

    wrpcap(pcap_output_file, generated_packets)



if __name__ == "__main__":
    if len(sys.argv) < 6:
        print(f"Usage: {sys.argv[0]} <sgw address> <pgw address> <teidstart> <teidstop> <output pcap file> <gsn_id>")
        exit(1)

    sgw_addr = sys.argv[1]
    pgw_addr = sys.argv[2]
    teidstart = int(sys.argv[3])
    teidstop = int(sys.argv[4])
    pcap_output_file = sys.argv[5]
    gsn_id = int(sys.argv[6])

    generate_gtp_packets_for_pair(teidstart,teidstop, sgw_addr, pgw_addr, pcap_output_file, gsn_id)

