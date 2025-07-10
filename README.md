## white-rabbit.htb

```
Hexada@hexada ~/Downloads$ sudo nmap -sS -sC -sV -p- -T5 --max-rate 10000 whiterabbit.htb                                                                                     
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-06 17:54 EEST
Warning: 10.10.11.63 giving up on port because retransmission cap hit (2).
Nmap scan report for whiterabbit.htb (10.10.11.63)
Host is up (0.20s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0f:b0:5e:9f:85:81:c6:ce:fa:f4:97:c2:99:c5:db:b3 (ECDSA)
|_  256 a9:19:c3:55:fe:6a:9a:1b:83:8f:9d:21:0a:08:95:47 (ED25519)
80/tcp   open  http    Caddy httpd
|_http-server-header: Caddy
|_http-title: White Rabbit - Pentesting Services
2222/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c8:28:4c:7a:6f:25:7b:58:76:65:d8:2e:d1:eb:4a:26 (ECDSA)
|_  256 ad:42:c0:28:77:dd:06:bd:19:62:d8:17:30:11:3c:87 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 559.42 seconds
```

```
Hexada@hexada ~/pentest-env/pentesting-wordlists$ ffuf -w ./SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://whiterabbit.htb -H "Host:FUZZ.whiterabbit.htb" -mc 200,302 -fs 0 


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://whiterabbit.htb
 :: Wordlist         : FUZZ: /home/Hexada/pentest-env/pentesting-wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.whiterabbit.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,302
 :: Filter           : Response size: 0
________________________________________________

status                  [Status: 302, Size: 32, Words: 4, Lines: 1, Duration: 147ms]
```

```
Hexada@hexada ~/pentest-env/pentesting-wordlists$ curl -I -H "Host: status.whiterabbit.htb" http://whiterabbit.htb                                                            
HTTP/1.1 302 Found
Content-Length: 32
Content-Type: text/plain; charset=utf-8
Date: Wed, 09 Jul 2025 21:08:17 GMT
Location: /dashboard
Server: Caddy
Vary: Accept
X-Frame-Options: SAMEORIGIN
```

![image](https://github.com/user-attachments/assets/a6cb4d1d-5422-464f-95d1-2f3bafa7e24e)

```
Hexada@hexada ~/pentest-env/pentesting-wordlists$ cat /etc/hosts                                                                                                              
# Static table lookup for hostnames.
# See hosts(5) for details.

127.0.0.1       localhost
::1             localhost
127.0.0.1       hexada.localdomain    hexada
10.10.11.63     status.whiterabbit.htb    whiterabbit.htb
```

```
Hexada@hexada ~/pentest-env/pentesting-wordlists$ curl -I http://status.whiterabbit.htb/dashboard                                                                             
HTTP/1.1 200 OK
Content-Length: 2444
Content-Type: text/html; charset=utf-8
Date: Wed, 09 Jul 2025 21:09:15 GMT
Etag: W/"98c-ZtpsWhPpFiP9p9Whm0aHolcREuk"
Server: Caddy
X-Frame-Options: SAMEORIGIN
```

![image](https://github.com/user-attachments/assets/c4c27cbc-130b-4319-ab5f-561cf0fa8db9)

```
xada@hexada ~/pentest-env/pentesting-wordlists$ ffuf -u http://status.whiterabbit.htb/FUZZ -w ./SecLists/Discovery/Web-Content/common.txt -e .php,.html,.js,.txt,.json -fs 2444 -ic

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://status.whiterabbit.htb/FUZZ
 :: Wordlist         : FUZZ: /home/Hexada/pentest-env/pentesting-wordlists/SecLists/Discovery/Web-Content/common.txt
 :: Extensions       : .php .html .js .txt .json 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 2444
________________________________________________

.well-known/change-password [Status: 302, Size: 89, Words: 4, Lines: 1, Duration: 118ms]
assets                  [Status: 301, Size: 179, Words: 7, Lines: 11, Duration: 61ms]
favicon.ico             [Status: 200, Size: 15086, Words: 14, Lines: 4, Duration: 107ms]
manifest.json           [Status: 200, Size: 415, Words: 147, Lines: 20, Duration: 83ms]
robots.txt              [Status: 200, Size: 25, Words: 3, Lines: 2, Duration: 70ms]
robots.txt              [Status: 200, Size: 25, Words: 3, Lines: 2, Duration: 74ms]
screenshots             [Status: 301, Size: 189, Words: 7, Lines: 11, Duration: 175ms]
upload                  [Status: 301, Size: 179, Words: 7, Lines: 11, Duration: 80ms]
:: Progress: [28404/28404] :: Job [1/1] :: 363 req/sec :: Duration: [0:00:53] :: Errors: 0 ::
```

```
Hexada@hexada ~/pentest-env/pentesting-wordlists$ ffuf -u http://status.whiterabbit.htb/FUZZ -w ./SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -e .php,.html,.js,.json,.txt -fs 2444 -ic

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://status.whiterabbit.htb/FUZZ
 :: Wordlist         : FUZZ: /home/Hexada/pentest-env/pentesting-wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .php .html .js .json .txt 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 2444
________________________________________________

                        [Status: 302, Size: 32, Words: 4, Lines: 1, Duration: 127ms]
screenshots             [Status: 301, Size: 189, Words: 7, Lines: 11, Duration: 61ms]
assets                  [Status: 301, Size: 179, Words: 7, Lines: 11, Duration: 60ms]
upload                  [Status: 301, Size: 179, Words: 7, Lines: 11, Duration: 61ms]
robots.txt              [Status: 200, Size: 25, Words: 3, Lines: 2, Duration: 188ms]
Screenshots             [Status: 301, Size: 189, Words: 7, Lines: 11, Duration: 60ms]
metrics                 [Status: 401, Size: 0, Words: 1, Lines: 1, Duration: 74ms]
Upload                  [Status: 301, Size: 179, Words: 7, Lines: 11, Duration: 113ms]
ScreenShots             [Status: 301, Size: 189, Words: 7, Lines: 11, Duration: 94ms]
Robots.txt              [Status: 200, Size: 25, Words: 3, Lines: 2, Duration: 142ms]
                        [Status: 302, Size: 32, Words: 4, Lines: 1, Duration: 97ms]
manifest.json           [Status: 200, Size: 415, Words: 147, Lines: 20, Duration: 69ms]
```

```
Hexada@hexada ~/pentest-env/pentesting-wordlists$ curl -I  http://status.whiterabbit.htb/.well-known/change-password                                                          
HTTP/1.1 302 Found
Content-Length: 89
Content-Type: text/plain; charset=utf-8
Date: Wed, 09 Jul 2025 21:30:32 GMT
Location: https://github.com/louislam/uptime-kuma/wiki/Reset-Password-via-CLI
Server: Caddy
Vary: Accept
X-Frame-Options: SAMEORIGIN
```

![image](https://github.com/user-attachments/assets/62250940-c15f-47d6-aaff-7b80d68789cb)

```
Bootstrap	5.1.3	  November 2021
vue-i18n	9.2.2	  January 2022
Font Awesome	5.15.4	  October 2021
vue-router	4.0.16	  January 2022
SortableJS	1.14.0	  December 2021
```

`Uptime Kuma v1.10–1.14`

<img width="1920" height="949" alt="image" src="https://github.com/user-attachments/assets/6f14c7b3-9f96-4b2c-8d03-a4cd6529da2f" />

```
Hexada@hexada ~/pentest-env/pentesting-wordlists$ cat /etc/hosts                                                                                                                           
# Static table lookup for hostnames.
# See hosts(5) for details.

127.0.0.1       localhost
::1             localhost
127.0.0.1       hexada.localdomain    hexada
192.168.0.101   cyberia
10.10.11.63     status.whiterabbit.htb   whiterabbit.htb   ddb09a8558c9.whiterabbit.htb   a668910b5514e.whiterabbit.htb
```




