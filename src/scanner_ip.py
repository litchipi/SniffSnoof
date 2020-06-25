#!/usr/bin/env python3
#-*-encoding:utf-8*-

from multiprocessing import Process
import time
import nmap

from gui import OutputHandler

class Scanner(OutputHandler):
    def __init__(self, args, ranges):
        OutputHandler.__init__(self, args)
        self.args = args
        self.ip_ranges = ranges

        self.childs = list()

    def start(self):
        self.msg("Starting scanner on target ", msglist=True)
        self.__scan_all(self.ip_ranges)
        self.msg("All scans started")
        self.run()
        self.msg("All scans finished")

    def run(self):
        while any([t.is_alive() for t in self.childs]):
            self.flush_results(0.1)
        for t in self.childs:
            try:
                t.join()
            except KeyboardInterrupt:
                self.msg("\r", end="", mtype="RAW")
                break

    def __scan_all(self, ranges, ip_nums=[]):
        if ranges == []:
            self.scan_ip(".".join(ip_nums))
            return
        for nip in ranges[0]:
            self.__scan_all(ranges[1:], ip_nums=ip_nums+[str(nip)])

    def scan_ip(self, ip):
        self.childs.append(ScanningRoutine(self.args, ip, self.result))
        self.msg(str(ip), msglist=True)
        self.childs[-1].start()

class ScanningRoutine(Process):
    def __init__(self, args, ip, outwrapper):
        Process.__init__(self)
        self.args = args
        self.target = ip
        self.out = outwrapper
        self.nmap = nmap.PortScanner()

    def get_name(self, name):
        return name + "__" + self.target.replace(".", "_")

    def check_allowed(self, name):
        n = "no_" + name.replace("scanfct_", "")
        if hasattr(self.args, n):
            return getattr(self.args, n)
        return True

    def run(self):
        try:
            self.syn_scan()
        except KeyboardInterrupt:
            pass

    def syn_scan(self):
        n = self.get_name("portscan")
        self.out("SYN scan start", n)
        res = self.nmap.scan(hosts=self.target, arguments='-sS', sudo=True)["scan"][self.target]
        isup = (res["status"]["state"] == "up")

        if not isup:
            self.out("Host is down")
            return

        if len(res["vendor"]) > 0:
            self.out("System data: " + str(res["vendor"]), n)

        if "tcp" in res.keys():
            list_tcp_ports = res["tcp"].keys()
            self.out("Open ports: ", n, msglist=True)
            portlist = list()
            for p, d in res["tcp"].items():
                if d['state'] != 'open':
                    continue
                self.out(str(p) + ": " + d['name'], n, msglist=True)
                portlist.append(p)
            self.port_inspect(",".join([str(p) for p in portlist]))

    def port_inspect(self, ports):
        n = self.get_name("portscan")
        self.out("Port inspection", n)
        res = self.nmap.scan(hosts=self.target, ports=ports, arguments='-sV', sudo=True)["scan"][self.target]
        self.out("Result keys: ", n, msglist=True)
        for k in res.keys():
            self.out(k, n, msglist=True)
        self.out("All: ", n)
        self.out(res, n)
