#!/usr/bin/env python3
#-*-encoding:utf-8*-

SECLIST_PATH = "/usr/share/wordlists/seclists/"
CMDSUFFIX = "> %OUTPUTFILE% 2>&1"
BASE_NMAP_SCRIPT_CMD = lambda p, d: "nmap --script=\""+d["name"]+"* and safe\" -p " + str(p) + " %TARGET%"+CMDSUFFIX

def concat_commands(cmdlist):
    return "echo \"$(" + " && ".join(cmdlist) + ")\""

def enum_cmd(f, port, data):
    res = dict()
    cmd = perform_searchsploit(data["product"], data["version"])
    if cmd is not None:
        res["_searchsploit"] = cmd + CMDSUFFIX
    res["_base"] = f(port, data) + CMDSUFFIX
    res["_nmap"]=BASE_NMAP_SCRIPT_CMD(port, data)
    return res

def perform_searchsploit(product, version):
    if (product != "") and (version != ""):
        cmdlist = list()
        prefix = "searchsploit "
        cmdlist
        nwords_prod = len(product.split(" "))
        nwords_vers = len(version.split(" "))
        for i in range(nwords_prod):
            for o in range(nwords_vers):
                search =product.split(" ")[i] + " " + version.split(" ")[o]
                cmdlist.append("echo \"\\n\\n Search: " + search + "\"")
                cmdlist.append(prefix + search)
        return concat_commands(cmdlist)
    else:
        return None









def web_server_enum(port, data):
    return "gobuster dir -e -w " + SECLIST_PATH + "Discovery/Web-Content/directory-list-2.3-big.txt -u http://%TARGET%:" + str(port) + "/ -q -z -o %OUTPUTFILE%"

def ftp_server_enum(port, data):
    return "hydra -C " + SECLIST_PATH + "Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://%TARGET% -o %OUTPUTFILE%"

def smb_enumeration(port, data):
    if data["name"]=="netbios-ssn":
        return concat_commands(["nbtscan %TARGET%", "nmblookup -A %TARGET%"])
    else:
        return "enum4linux -a %TARGET%"

def nfs_enumeration(port, data):
    return "showmount -e %TARGET%"

def smtp_enumeration(port, data):
    return "smtp-user-enum -U " + SECLIST_PATH + "Usernames/xato-net-10-million-usernames-dup.txt -t %TARGET%"

def snmp_enumeration(port, data):
    return "onesixtyone -c " + SECLIST_PATH + "Discovery/SNMP/snmp-onesixtyone.txt %TARGET%"

def mysql_enumeration(port, data):
    return "nmap --script=mysql-enum %TARGET%"

def msrpc_enumeration(port, data):
    return "nmap %TARGET% --script=msrpc-enum"

def rdp_enumeration(port, data):
    return "nmap --script \"rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info\" -p " + str(port) + " %TARGET%"

def tns_enumeration(port, data):
    return "nmap --script \"oracle-tns-version\" -p " + str(port) + "-sV %TARGET%"

def ssh_enumeration(port, data):
    return "hydra -L " + SECLIST_PATH + "Usernames/top-usernames-shortlist.txt -P " + \
            SECLIST_PATH + "Passwords/Common-Credentials/top-20-common-SSH-passwords.txt %TARGET% -t 4 ssh"

TYPICAL_SERVICE_PORT = {
        "http":80
        }

ALL_ENUM_FCTS = {
        21:  {"ftp_enum":ftp_server_enum},
        22:  {"ssh_enum":ssh_enumeration},
        25:  {"smtp_enum":smtp_enumeration},
        80:  {"http_web_enum":web_server_enum},
        111: {"nfs_scripts":nfs_enumeration},
        135: {"msrpc_enum":msrpc_enumeration},
        139: {"smb_enum":smb_enumeration},
        161: {"snmp_enum":snmp_enumeration},
        443: {"https_web_enum":lambda p, d: web_server_enum(p, d).replace("-u http://", "-u https://")},
        445: {"smb_enum":smb_enumeration},
        3389:{"rdp_enum":rdp_enumeration},
        3396:{"mysql_enum":mysql_enumeration},
        }


def get_enum_command(port, data):
    if data["name"] in TYPICAL_SERVICE_PORT.keys():
        typ_port = TYPICAL_SERVICE_PORT[data["name"]]
    else:
        typ_port = port
    if (typ_port in ALL_ENUM_FCTS.keys()):
        res = dict()
        for n, cmd in ALL_ENUM_FCTS[typ_port].items():
            for k, v in enum_cmd(cmd, port, data).items():
                res[n + "_p" + str(port) + k] = v
        return res
    else:
        return {data["name"] + "_" + str(port) + "_nmap":BASE_NMAP_SCRIPT_CMD(port, data)}
