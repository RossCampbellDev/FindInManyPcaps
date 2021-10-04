#!/usr/bin/python
import sys
import os
import argparse
from netaddr import IPNetwork
import pyshark

# take in IP or subnet mask [src and dest]
# optional protocol/ports
# loop through all pcap files in directory
# find matching traffic

# convert a CIDR notation to a subnet mask in string format
def cidr_convert(cidr):
    cidr = int(cidr)
    mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
    return (str((0xff000000 & mask) >> 24) + '.' +
          str((0x00ff0000 & mask) >> 16) + '.' +
          str((0x0000ff00 & mask) >> 8) + '.' +
          str((0x000000ff & mask)))


# check if an IP is valid against the subnet mask
def cidr_check(IP, mask):
    IP = IP.split('.')
    mask = mask.split('.')
    # do bitwise stuff
    return True


def find_all_packets(directory):
    packets = []
    for file in os.scandir(directory):
        if file.path.endswith('.cap') and file.is_file():
            for pkt in pyshark.FileCapture(file, only_summaries=True):
                packets.append(pkt)

    return packets


def search_packets(pkts, srcs, dsts, src_port, dst_port):
    result = []

    for pkt in pkts:
        append = True
        line = str(pkt).split(" ")
        src = line[2]
        dst = line[3]
        proto = line[4]

        if srcs is not None:
            if src not in srcs:
                append = False

        if dsts is not None:
            if dst not in dsts:
                append = False

        if proto != src_port and proto != dst_port:
            append = False

        if append:
            result.append(pkt)

    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Find traffic in all pcap files in directory that matches given IP/CIDR range, and port/protocol')
    parser.add_argument('-p', metavar='path', help='directory in which to search')
    parser.add_argument('-s', metavar='source IP/CIDR', help='[OPTIONAL] state an IP address or CIDR notation IP range for a source address')
    parser.add_argument('-d', metavar='dest IP/CIDR', help='[OPTIONAL] state an IP address or CIDR notation IP range for a destination address')
    parser.add_argument('-sp', metavar='srcport', help='[OPTIONAL] state a port number to match traffic against (src)')
    parser.add_argument('-dp', metavar='destport', help='[OPTIONAL] state a port number to match traffic against (dest)')

    args = parser.parse_args()
    path = args.p
    src = args.s
    dst = args.d
    src_prt = args.sp
    dst_prt = args.dp

    possible_sources = None
    possible_destinations = None

    if args.p is None:
        sys.exit("Must include the -p flag to provide a folder to search for PCAP files")

    if src is not None and src.index('/') is not None:  # CIDR src address
        possible_sources = IPNetwork(src)
    else:
        if src is not None:
            possible_sources = [src]

    if dst is not None and dst.index('/') is not None:  # CIDR src address
        possible_destinations = IPNetwork(dst)
    else:
        if dst is not None:
            possible_destinations = [dst]

    all_packets = find_all_packets(path)
    result = search_packets(all_packets, possible_sources, possible_destinations, src_prt, dst_prt)

    print("--------------------------")
    print(result)
