#!/usr/bin/env python3
#-*-encoding:utf-8*-

from multiprocessing.queues import Empty
from multiprocessing import Queue

import sys, time, os

NOCOLOR = "\033[0m"

NORMAL=0; BOLD=1

LGREEN=(106, 249, 84)
LBLUE=(74, 195, 221)
RED=(255, 45, 45)

COLOR = lambda s, rgb: "\033[{};38;2;{};{};{}m".format(s, rgb[0], rgb[1], rgb[2])
STYLE =  {"INFO":COLOR(NORMAL, LGREEN), "RAW":NOCOLOR, "RESULTS":COLOR(NORMAL, LBLUE), "ERR":COLOR(BOLD, RED)}
SYMBOLS = {"INFO":"[*] ", "RAW":"", "RESULTS":"[+] ", "ERR":"ERR "}
HEADER = lambda k: (STYLE[k] + SYMBOLS[k])


class OutputHandler:
    def __init__(self, args):
        self.misc_data = dict()
        if args.dirname == "":
            t = time.gmtime()
            self.respath = os.path.abspath(os.curdir) + \
                    "/{}_{}_{}__{}_{}_{}/".format(t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec)
        else:
            self.respath = args.dirname
        if not os.path.isdir(self.respath):
            os.mkdir(self.respath)

        self.message_queue = Queue()
        print("")
 
    def check_tag(self, key, ident):
        if key not in self.misc_data[ident]["tags"].keys():
            return False
        return self.misc_data[ident]["tags"][key]

    def msg(self, m, **kwargs):
         self.print_message(*self.format_msg(m, **kwargs))

    def format_msg(self, m, end="\n", mtype="INFO", msglist=False, ident="basiclist", offsetheader=True):
        offset = 0
        printheader=True

        if ident not in self.misc_data.keys():
            self.misc_data[ident] = {"tags":dict()}

        if msglist:
            if self.check_tag("msglist_started", ident):
                offset = self.misc_data[ident]["msglist_offset"]
                self.misc_data[ident]["tags"]["msglist_first"] = False
                printheader=False
            else:
                self.misc_data[ident]["tags"]["msglist_first"] = True
                self.misc_data[ident]["tags"]["msglist_started"] = True
                self.misc_data[ident]["msglist_offset"] = len(m)+(offsetheader*len(SYMBOLS[mtype]))+1
        else:
            self.misc_data[ident]["tags"]["msglist_started"] = False
            self.misc_data[ident]["tags"]["msglist_first"] = False
            self.misc_data[ident]["msglist_offset"] = 0
        return (offset, mtype, m, end, printheader)

    def print_message(self, offset, mtype, m, end, printheader, name=None):
        s = " "*offset
        if name is not None:
            s = name + "> " + s
        if printheader:
            s += HEADER(mtype)
        else:
            s += STYLE[mtype]
        s += str(m) + NOCOLOR
        print(s, end=end)

    def write_to_resfile(self, name, offset, mtype, m, end, printheader):
        with open(self.respath + name, "a") as f:
            f.write((" "*offset) + str(m) + end)

    def flush_results(self, timeout):
        try:
            d = self.message_queue.get(timeout=timeout)
            self.print_message(*d[0], name=d[1])
        except Empty:
            pass

    def result(self, res, name, stdout=True, **kwargs):
        kwargs.update({"mtype":"RESULTS"})
        self.write_to_resfile(name, *self.format_msg(res, ident=name + "_writefile", offsetheader=False, **kwargs))
        if stdout:
            self.message_queue.put((self.format_msg(res, ident=name + "_outputfile", **kwargs), name))
