#!/usr/bin/env python3
#-*-encoding:utf-8*-

import nmap
import sys
import argparse

from scanner_ip import Scanner

def get_cli_args():
    parser = argparse.ArgumentParser(description="Automated scanner and enumeration tool", prog="sniffsnoof")
    parser.add_argument("--deep", "-d", help="Launch fuzzing & enumeration scripts based on scan results", action="store_true")
    parser.add_argument("--dirname", "-n", help="The name of the directory to create, where to store the results", default="")
    parser.add_argument("target", help="The target IP or range IP", nargs="+")

    args = parser.parse_args()

    targets_ips = list()

    for target in args.target:
        ip_ranges = [[], [], [], []]
        for n, el in enumerate(target.split(".")):
            if el == "*":
                ip_ranges[n] += [str(i) for i in range(1,256)]
            elif "-" in el:
                ip_ranges[n] += [str(i) for i in range(int(el.split("-")[0]), int(el.split("-")[1])+1)]
            elif "," in el:
                ip_ranges[n] += el.split(",")
            elif el not in ip_ranges[n]:
                ip_ranges[n].append(el)
        targets_ips.append(ip_ranges)

    if n != 3:
        raise Exception("Wrong target, expected IPv4 format X.X.X.X")
    return args, ip_ranges

if __name__ == "__main__":
    scanner = Scanner(*get_cli_args())
    scanner.start()
