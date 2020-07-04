# SniffSnoof
Enumeration tool automated, written in Python, binding results of nmap to different commands.
Scan each IP in a separate process, create a thread for each enumeration commands passed.
Stores the results in files to be processed later "by hand"
Perform automatically searchsploit on every software detected
# Usage
```
usage: sniffsnoof [-h] [--deep] [--dirname DIRNAME] target [target ...]

Automated scanner and enumeration tool

positional arguments:
  target                The target IP or range IP

optional arguments:
  -h, --help            show this help message and exit
  --deep, -d            Launch fuzzing & enumeration scripts based on scan results
  --dirname DIRNAME, -n DIRNAME
                        The name of the directory to create, where to store the results
```
# Exemples
```
sniffsnoof --deep --dirname testdir 192.168.1.4-25
```
