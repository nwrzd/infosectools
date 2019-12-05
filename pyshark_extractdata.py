from __future__ import print_function
from scapy.all import *
import binascii
import sys
import argparse
import yenc


def start(file_name,output):

    data = ''
    hexdata = ''
    decoder = yenc.Decoder()

    cap = rdpcap(file_name)
    packet_len = len(cap)
    num_written = 0
    for i in cap:
        # If the ICMP packet is of type = request
        if i[ICMP].type==8:
            try:
                if output in ['a','h']:
                    # Get the raw payload from the ICMP packet. This i[Raw] returns the hex encoded payload as ascii, , hence we have to use '-o h' option to print literal hex values
                    data = data + str(i[Raw])
                if output == 'y':
                    decoder.feed(str(i[Raw]))
                num_written = num_written + 1
            except Exception as e:
                print("Exception: {}".format(e))
                continue

        
    if output == 'a':
        # Print raw payload
        print(data, end="")
        
    if output == 'h':
        # Get raw hex characters instead of printable ascii like how the '-o a' option returns becuase of i[Raw] returning ascii encoded characters
        print(str(binascii.hexlify(data)), end="")
        
        
    if output == 'y':
        print(decoder.getDecoded(), end="")
    
    
    print("\nInput File : {}".format(file_name),file=sys.stderr)
    print("Output Type : {}".format(output),file=sys.stderr)
    print("Packet Length : {}".format(packet_len),file=sys.stderr)
    print("Number of payload packets written : {}\n".format(num_written),file=sys.stderr)

    exit()



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-f","--file", help="Input pcap file", required=True)
    parser.add_argument("-o","--output", help="Type of output required - h=hex, a=ascii, y=yenc", required=True)
    args = parser.parse_args()
    
    if args.output in ['a','h','y']:
    
        start(file_name=args.file,output=args.output)
        
    else:
        
        parser.error("Option '{}' not recognized for -o/--output".format(args.output))

