#!/usr/bin/env python3
#-*-encoding:utf-8*-

import nmap
import sys
import argparse

from scanner_ip import Scanner

def get_cli_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-method", "-s", help="Method to use to scan targets on the network", default="syn")
    parser.add_argument("--deep", "-d", help="Launch fuzzing & enumeration scripts based on scan results", action="store_true")
    parser.add_argument("--tcp-only", help="Do not scan for UDP ports and services", action="store_true")
    parser.add_argument("--threads", "-t", help="Maximal number of scan threads to launch in parallel", default=10)
    parser.add_argument("--dirname", "-n", help="The name of the directory to create, where to store the results", default="")
    parser.add_argument("target", help="The target IP or range IP")

    args = parser.parse_args()

    ip_ranges = list()
    for n, el in enumerate(args.target.split(".")):
        if el == "*":
            ip_ranges.append([str(i) for i in range(1,256)])
        elif "-" in el:
            ip_ranges.append([str(i) for i in range(int(el.split("-")[0]), int(el.split("-")[1])+1)])
        else:
            ip_ranges.append([el])

    if n != 3:
        raise Exception("Wrong target, expected IPv4 format X.X.X.X")
    return args, ip_ranges

if __name__ == "__main__":
    scanner = Scanner(*get_cli_args())
    scanner.start()
