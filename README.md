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

```
