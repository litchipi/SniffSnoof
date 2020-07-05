#!/usr/bin/env python3
#-*-encoding:utf-8*-

import io
import os
import sys
import time
import nmap
import traceback
import subprocess

from threading import Thread
from multiprocessing import Process

from gui import OutputHandler, format_dict
from enumeration import get_enum_command

class Scanner(OutputHandler):
    def __init__(self, args, targets):
        OutputHandler.__init__(self, args)
        self.args = args
        self.targets_ranges = targets

        self.childs = list()

    def start(self):
        self.msg("Starting scanner on target ", msglist=True)
        for ip_range in self.targets_ranges:
            self.__scan_all(ip_range)
        self.msg("All scans started")
        if self.run():
            self.msg("All scans finished successfully")
        else:
            self.msg("Something went wrong on a scan")

    def run(self):
        while any([t.is_alive() for t in self.childs]):
            self.flush_results(0.5)
        for t in self.childs:
            try:
                t.join()
            except KeyboardInterrupt:
                self.msg("\r", end="", mtype="RAW")
                return True
        return all([t.success for t in self.childs])

    def __scan_all(self, ranges, ip_nums=[]):
        if ranges == []:
            self.scan_ip(".".join(ip_nums))
            return
        for nip in ranges[0]:
            self.__scan_all(ranges[1:], ip_nums=ip_nums+[str(nip)])

    def scan_ip(self, ip):
        self.childs.append(ScanningRoutine(self.args, ip, self.result, self.respath))
        self.msg(str(ip), msglist=True)
        self.childs[-1].start()



class ScanningRoutine(Process):
    def __init__(self, args, ip, outwrapper, path):
        Process.__init__(self)
        self.args = args
        self.target = ip
        self.success = False

        self.report_path = path + ip.replace(".", "_") + "/"
        if not os.path.isdir(self.report_path):
            os.mkdir(self.report_path)
        self.report_results = outwrapper
        self.nmap = nmap.PortScanner()
        self.threads = list()

    def get_path(self, n):
        return self.report_path + n

    def out(self, msg, n, **kwargs):
        self.report_results(msg, self.report_path, self.target, n, **kwargs)

    def check_allowed(self, name):
        n = "no_" + name.replace("scanfct_", "")
        if hasattr(self.args, n):
            return getattr(self.args, n)
        return True

    def run(self):
        self.scan()
        self.success = True

    def scan(self):
        n = "general"
        try:
            isup = self.syn_scan()
            if not isup:
                if self.report_path != "/": #You don't want this.
                    os.system("rm -r " + self.report_path)
                return
            self.os_detection()
            self.vuln_scanning()
            self.udp_scan()
            self.wait_end_threads()
            self.out("Scan finished successfully", n)
        except:
            s = io.StringIO()
            traceback.print_exc(file=s)
            s.seek(0)
            self.out(s.read(), n)

    def wait_end_threads(self, timeout=30):
        to = int(timeout/len(self.threads))
        oldn = -1
        while any([t.is_alive() for t in self.threads]):
            n = len([1 for t in self.threads if t.is_alive()])
            if n != oldn:
                self.out("Waiting for " + str(n) + " threads to finish...", "general")
                oldn = n
            for t in self.threads:
                t.join(timeout=to)

    def syn_scan(self):
        n = "general"
        res = self.nmap.scan(hosts=self.target, arguments='-sS --top-ports=32000', sudo=True)
        if self.target not in res["scan"]:return False
        res = res["scan"][self.target]
        isup = (res["status"]["state"] == "up")
        if not isup:
            self.out("Host is down", n)
            return False

        if len(res["vendor"]) > 0:
            self.out("System data: " + str(res["vendor"]), n)

        if "tcp" in res.keys():
            list_tcp_ports = res["tcp"].keys()
            self.out("Open TCP ports: ", n, msglist=True)
            portlist = list()
            for p, d in res["tcp"].items():
                if d['state'] != 'open':
                    continue
                self.out(str(p) + ": " + d['name'], n, msglist=True)
                portlist.append(p)
            self.port_inspect(",".join([str(p) for p in portlist]))

            s = format_dict(res)
            self.out("All SYN: ", "debug")
            self.out(s, "debug")
            return True
        return False

    def udp_scan(self):
        n = "general"
        self.out("UDP scanning", n)
        res = self.nmap.scan(hosts=self.target, arguments='-sU -F --top-ports 100', sudo=True)
        if self.target not in res["scan"]: return
        res = res["scan"][self.target]

        s = format_dict(res)
        self.out("All UDP: ", "debug")
        self.out(s, "debug")

    def os_detection(self):
        n = "os_detection"
        self.out("OS detection", "general")
        res = self.nmap.scan(hosts=self.target, arguments='-O', sudo=True)
        if self.target not in res["scan"]: return
        res = res["scan"][self.target]

        self.out("Possible OS of the target: ", n, msglist=True)
        for os in res["osmatch"]:
            self.out(os["name"] + " (" + os["accuracy"] + "%)", n, msglist=True)

        s = format_dict(res)
        self.out("All OS detection: ", "debug")
        self.out(s, "debug")

    def vuln_scanning(self):
        n = "vuln_scanning"
        self.out("Vulnerability scanning", "general")
        res = self.nmap.scan(hosts=self.target, arguments='--script vuln', sudo=True)
        if self.target not in res["scan"]: return
        res = res["scan"][self.target]

        for p, d in res["tcp"].items():
            if "script" not in d.keys(): continue
            self.out(str(p), n, msglist=True, stdout=False)
            for k, v in d["script"].items():
                self.out(str(k) +": " + str(v), n, msglist=True, stdout=False)
            self.out("\n", n, stdout=False)

        s = format_dict(res)
        self.out("All Vuln scanning: ", "debug")
        self.out(s, "debug")

    #Advanced

    def port_inspect(self, ports):
        n = "general"
        self.out("Port inspection", n)
        res = self.nmap.scan(hosts=self.target, ports=ports, arguments='-sV', sudo=True)
        if self.target not in res["scan"]: return
        res = res["scan"][self.target]

        if "tcp" in res.keys():
            for p in res["tcp"].keys():
                self.out("Port " + str(p), n, msglist=True)
                for key, val in res["tcp"][p].items():
                    self.out(key + ": " + str(val), n, msglist=True)
                self.out("", n)
                if self.args.deep:
                    self.enum_port(p, res["tcp"][p])

        s = format_dict(res)
        self.out("All port inspect: ", "debug")
        self.out(s, "debug")

    def enum_port(self, port, data):
        cmds = get_enum_command(port, data)
        if cmds is None: return
#        self.out("All enumeration commands for port " + str(port), "debug")
#        self.out(cmds, "debug")
        self.out(type(cmds), "debug")
        self.out(cmds, "debug")
        for name, cmd in cmds.items():
            cmd = cmd.replace("%TARGET%", self.target).replace("%OUTPUTFILE%", self.get_path(name))
            self.out("Executing " + name + " script on target, result stored in " + self.get_path(name), "general")
            self.launch_command(cmd, name=name)

    def launch_command(self, cmd, name=None):
        if name is None:
            name = "thread " + len(self.threads)
        t = Thread(target=subprocess.run, args=(cmd,), kwargs={"shell":True}, name=name)
        t.start()
        self.threads.append(t)
        self.out(cmd, "debug")

if __name__ == "__main__":
    cmds = get_enum_command(21, {"name":"ftp", "product":"test", "version":"0.3"})
    print(cmds, type(cmds))
