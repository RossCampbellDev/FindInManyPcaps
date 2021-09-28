#!/usr/bin/python
import argparse

# take in IP or subnet mask [src and dest]
# optional protocol/ports
# loop through all pcap files in directory
# find matching traffic

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Find traffic in all pcap files in directory that matches given IP/CIDR range, and port/protocol')
    parser.add_argument('-s', metavar='source IP/CIDR', help='[OPTIONAL] state an IP address or CIDR notation IP range for a source address')
    parser.add_argument('-d', metavar='dest IP/CIDR', help='[OPTIONAL] state an IP address or CIDR notation IP range for a destination address')
    parser.add_argument('-p', metavar='port', help='[OPTIONAL] state a port number to match traffic against (src or dest)')

    args = parser.parse_args()
    src = args.s
    dst = args.d
    prt = args.p

