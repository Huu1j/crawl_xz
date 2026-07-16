# CobaltStrike流量解密 - 总结-先知社区

> **来源**: https://xz.aliyun.com/news/18517  
> **文章ID**: 18517

---

将CTF中常见的几种CS流量解密方法总结了一下，有误请师傅们指正。

## 特征识别

### HTTP流量特征

**checksum8算法特征** CobaltStrike的HTTP请求路径经过checksum8算法计算后，32位后门结果为92，64位后门结果为93，这是其显著特征之一 。

> 该算法计算方式为路径字符ASCII码之和与256取余。

**固定URL模式** 未修改的CobaltStrike常出现特定URL路径如`/submit.php?id=xxx`、`/pixel.gif`、`/q.cgi`等，这些路径即使经过证书魔改也可能保留 。http-beacon通信中，默认使用GET方法向这些地址发起请求。

> tager下载阶段路径如`/Yle2`、`/cKTZ`等虽不固定但都符合checksum8规则。

筛选HTTP

![图片.png](images/20250804155034-b416defa-7107-1.png)

看到 路径 `/FJwV`，检验一下

**计算ASCII码之和**：

```
70 (F) + 74 (J) + 119 (w) + 86 (V) = 349
```

**取模运算**（和值对256取余）：

```
349 % 256 = 93
```

因此，路径 `/FJwV` 的checksum8值为 **93**，符合 **CobaltStrike 64位后门** 的流量特征。如果是未修改的CobaltStrike，此路径极可能是恶意请求。

此外，出现`/submit.php?id=1603726794`也是特征之一。

### TLS特征

**JA3/JA3s指纹**

* JA3指纹(Client Hello)：Windows 10 HTTPS Beacon的JA3指纹为`28a2c9bd18a11de089ef85a160da29e4`
* JA3S指纹(Server Hello)：CentOS CS4.4的JA3S指纹为`00447ab319e9d94ba2b4c1248e155917` 这些指纹与操作系统和CS版本相关，无法通过profile文件修改

![图片.png](images/20250804155035-b485509c-7107-1.png)

### 解密心跳包

工具包地址：<https://blog.didierstevens.com/didier-stevens-suite/>

在 CobaltStrike 的通信流程中，**最初的心跳包（Initial Check-in）通常由 Stager 发起，但它下载的 Beacon 才是后续持久通信的主体**

#### 首次心跳包的归属

1. Stager 发起的初始请求

* 行为：Stager 会向 C2 服务器发送一个 HTTP/HTTPS 请求（如 `GET /xxx`），该请求的路径符合 checksum8 算法（如 `/Yle2`）。
* 目的：下载完整的 Beacon 载荷（约 200-300KB 的反射 DLL 或 Shellcode）。
* 特征：

* 无加密或简单 XOR 加密
* 无固定心跳间隔（一次性行为）
* 返回内容为 Beacon 的二进制数据

2. Beacon 的首次心跳

* 触发时机：Stager 下载 Beacon 并注入内存后，由 Beacon 发起真正的首次心跳。
* 特征：

* 携带主机信息（如用户名、IP、进程名等），通过 RSA 加密后放在 Cookie 或 POST 数据中
* 后续开始周期性通信（心跳间隔由 C2 配置决定）

导出FJwV

![图片.png](images/20250804155035-b4ae012c-7107-1.png)

运行脚本1768.py

```
\DidierStevensSuite>python 1768.py ..\FJwV
File: ..\FJwV
xorkey(chain): 0x1f6828ff
length: 0x040e00ad
xorkey b'.' 2e
0x0001 payload type                     0x0001 0x0002 0 windows-beacon_http-reverse_http
0x0002 port                             0x0001 0x0002 80
0x0003 sleeptime                        0x0002 0x0004 60000
0x0004 maxgetsize                       0x0002 0x0004 1048576
0x0005 jitter                           0x0001 0x0002 0
0x0007 publickey                        0x0003 0x0100 30819f300d06092a864886f70d010101050003818d003081890281810093b4127271907b80352c6a15b6bb1701bd01657a2fba3ca1fba56d9a13e9f1f3121ac3aa70248f8621217fddfc0a484e78ebf4e5b48bb4804eababe5366cf4886b6ce2a5a113edd851fc5b2fb62a925043354000bbae7f2f75d7b0b7097a17b7c7de195174d4b17cee1499ae1e52e3ce3eec3f70011d971d022c0a8723def11d020301000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0x0008 server,get-uri                   0x0003 0x0100 '192.168.31.170,/en_US/all.js'
0x0043 DNS_STRATEGY                     0x0001 0x0002 0
0x0044 DNS_STRATEGY_ROTATE_SECONDS      0x0002 0x0004 -1
0x0045 DNS_STRATEGY_FAIL_X              0x0002 0x0004 -1
0x0046 DNS_STRATEGY_FAIL_SECONDS        0x0002 0x0004 -1
0x000e SpawnTo                          0x0003 0x0010 (NULL ...)
0x001d spawnto_x86                      0x0003 0x0040 '%windir%\syswow64\rundll32.exe'
0x001e spawnto_x64                      0x0003 0x0040 '%windir%\sysnative\rundll32.exe'
0x001f CryptoScheme                     0x0001 0x0002 0
0x001a get-verb                         0x0003 0x0010 'GET'
0x001b post-verb                        0x0003 0x0010 'POST'
0x001c HttpPostChunk                    0x0002 0x0004 0
0x0025 license-id                       0x0002 0x0004 666666 Stats uniques -> ips/hostnames: 27 publickeys: 25
0x0024 deprecated                       0x0003 0x0020 'MYhXSMGVvcr7PtOTMdABvA=='
0x0026 bStageCleanup                    0x0001 0x0002 0
0x0027 bCFGCaution                      0x0001 0x0002 0
0x0047 MAX_RETRY_STRATEGY_ATTEMPTS      0x0002 0x0004 0
0x0048 MAX_RETRY_STRATEGY_INCREASE      0x0002 0x0004 0
0x0049 MAX_RETRY_STRATEGY_DURATION      0x0002 0x0004 0
0x0009 useragent                        0x0003 0x0100 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0; MASP)'
0x000a post-uri                         0x0003 0x0040 '/submit.php'
0x000b Malleable_C2_Instructions        0x0003 0x0100
  Transform Input: [7:Input,4]
   Print
0x000c http_get_header                  0x0003 0x0200
  Build Metadata: [7:Metadata,3,6:Cookie]
   BASE64
   Header Cookie
0x000d http_post_header                 0x0003 0x0200
  Const_header Content-Type: application/octet-stream
  Build SessionId: [7:SessionId,5:id]
   Parameter id
  Build Output: [7:Output,4]
   Print
0x0036 HostHeader                       0x0003 0x0080 (NULL ...)
0x0032 UsesCookies                      0x0001 0x0002 1
0x0023 proxy_type                       0x0001 0x0002 2 IE settings
0x003a TCP_FRAME_HEADER                 0x0003 0x0080 '\x00\x04'
0x0039 SMB_FRAME_HEADER                 0x0003 0x0080 '\x00\x04'
0x0037 EXIT_FUNK                        0x0001 0x0002 0
0x0028 killdate                         0x0002 0x0004 0
0x0029 textSectionEnd                   0x0002 0x0004 0
0x002b process-inject-start-rwx         0x0001 0x0002 64 PAGE_EXECUTE_READWRITE
0x002c process-inject-use-rwx           0x0001 0x0002 64 PAGE_EXECUTE_READWRITE
0x002d process-inject-min_alloc         0x0002 0x0004 0
0x002e process-inject-transform-x86     0x0003 0x0100 (NULL ...)
0x002f process-inject-transform-x64     0x0003 0x0100 (NULL ...)
0x0035 process-inject-stub              0x0003 0x0010 '\x04à¡\x1bå\x91G¨×=+>\x9fê\x83,'
0x0033 process-inject-execute           0x0003 0x0080 '\x01\x02\x03\x04'
0x0034 process-inject-allocation-method 0x0001 0x0002 0
0x0000
Guessing Cobalt Strike version: 4.4 (max 0x0049)
Sanity check Cobalt Strike config: OK
Sleep mask 64-bit 4.2 deobfuscation routine found: 0x00010176 (LSFIF: b'tYE3')
Sleep mask 64-bit 4.2 deobfuscation routine found: 0x0001030e (LSFIF: b'tYE3')
Public key config entry found: 0x0003b65d (xorKey 0x2e) (LSFIF: b'././.,...,./.,.~.-.,.*..')
Public key header found: 0x0003b663 (xorKey 0x2e) (LSFIF: b'N.*.,.*.>...+./.,...).-/.')
```

得到了 对 **CobaltStrike Beacon 配置文件** 的解析结果

#### **基础通信设置**

|  |  |  |
| --- | --- | --- |
| **参数** | **值** | **说明** |
| `payload type` | `windows-beacon_http-reverse_http` | 载荷类型为 HTTP Beacon（反向连接） |
| `port` | `80` | C2 服务器监听端口（HTTP） |
| `sleeptime` | `60000`  (60秒) | Beacon 心跳间隔（毫秒） |
| `maxgetsize` | `1048576`  (1MB) | HTTP 请求最大数据大小 |
| `jitter` | `0` | 心跳时间抖动（0表示无随机延迟） |
| `publickey` | RSA 公钥（30819f30...） | 用于加密通信的 RSA 公钥（长度为 2048 位） |

#### **C2 服务器设置**

|  |  |  |
| --- | --- | --- |
| **参数** | **值** | **说明** |
| `server,get-uri` | `192.168.31.170,/en_US/all.js` | C2 服务器地址和请求路径（伪装为 JS 文件） |
| `useragent` | `Mozilla/5.0 (compatible; MSIE 10.0...)` | 伪装成 IE 浏览器的 User-Agent |
| `post-uri` | `/submit.php` | POST 请求路径（用于发送数据） |

#### **流量伪装与加密**

|  |  |  |
| --- | --- | --- |
| **参数** | **值** | **说明** |
| `http_get_header` | `Cookie`  + `BASE64` | GET 请求中元数据通过 Cookie 字段传递，并经过 Base64 编码 |
| `http_post_header` | `Content-Type: application/octet-stream` | POST 请求伪装为二进制数据传输 |
| `CryptoScheme` | `0` | 使用默认加密方案（AES + RSA） |

#### **进程注入与持久化**

|  |  |  |
| --- | --- | --- |
| **参数** | **值** | **说明** |
| `spawnto_x86` | `%windir%\\syswow64\ undll32.exe` | 32 位进程注入目标（rundll32.exe） |
| `spawnto_x64` | `%windir%\\sysnative\ undll32.exe` | 64 位进程注入目标 |
| `process-inject-execute` | `\x01\x02\x03\x04` | 进程注入的 Shellcode 前缀（可能用于混淆） |

#### **其他配置**

|  |  |  |
| --- | --- | --- |
| **参数** | **值** | **说明** |
| `killdate` | `0` | 载荷失效日期（0表示永久有效） |
| `license-id` | `666666` | CobaltStrike 许可证 ID（可能为伪造） |
| `UsesCookies` | `1` | 启用 Cookie 传递数据 |

可以看到payload type 为`windows-beacon_http-reverse_http`，也看到get-uri 为`/en_US/all.js`。

### 获取公私钥

#### 无.cobaltstrike.beacon\_keys

将publickey多余0去除得到公钥

```
30819f300d06092a864886f70d010101050003818d003081890281810093b4127271907b80352c6a15b6bb1701bd01657a2fba3ca1fba56d9a13e9f1f3121ac3aa70248f8621217fddfc0a484e78ebf4e5b48bb4804eababe5366cf4886b6ce2a5a113edd851fc5b2fb62a925043354000bbae7f2f75d7b0b7097a17b7c7de195174d4b17cee1499ae1e52e3ce3eec3f70011d971d022c0a8723def11d0203010001
```

用cs\_invert\_pub.py将公钥转为pem格式，并提取其中的n和e

```
from Crypto.PublicKey import RSA
import binascii

# 将你的16进制字符串放在这里
hex_key = "30819f300d06092a864886f70d010101050003818d003081890281810093b4127271907b80352c6a15b6bb1701bd01657a2fba3ca1fba56d9a13e9f1f3121ac3aa70248f8621217fddfc0a484e78ebf4e5b48bb4804eababe5366cf4886b6ce2a5a113edd851fc5b2fb62a925043354000bbae7f2f75d7b0b7097a17b7c7de195174d4b17cee1499ae1e52e3ce3eec3f70011d971d022c0a8723def11d0203010001"
# 将十六进制字符串转换为字节
key_bytes = binascii.unhexlify(hex_key)
# 导入RSA公钥
rsa_key = RSA.import_key(key_bytes)
# 提取模数(n)和指数(e)
n = rsa_key.n
e = rsa_key.e
# 打印模数和指数
print(f"Modulus (n): {n}")
print(f"Exponent (e): {e}")

# 将RSA公钥导出为PEM格式
pem_key = rsa_key.publickey().export_key(format='PEM')
# 打印PEM格式公钥
print(pem_key.decode('utf-8'))
```

运行脚本

```
m4rt3n@M4rt3n:~$ python cs_invert_pub.py
Modulus (n): 103720859306292228493187018335794719456704076702613648934820512721556915134407332273523620087297590638308487185636243050421776465571366028453861111400218515890201860005015546954677081983567089638559303489819418447930083602797597195659491558217965106724744145849368927955484176253258934021689357027136103182621
Exponent (e): 65537
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCTtBJycZB7gDUsahW2uxcBvQFl
ei+6PKH7pW2aE+nx8xIaw6pwJI+GISF/3fwKSE546/TltIu0gE6rq+U2bPSIa2zi
paET7dhR/FsvtiqSUEM1QAC7rn8vddewtwl6F7fH3hlRdNSxfO4Uma4eUuPOPuw/
cAEdlx0CLAqHI97xHQIDAQAB
-----END PUBLIC KEY-----
```

利用yafu将n进行模数分解，得到p和q

```
\yafu>yafu-x64.exe factor(103720859306292228493187018335794719456704076702613648934820512721556915134407332273523620087297590638308487185636243050421776465571366028453861111400218515890201860005015546954677081983567089638559303489819418447930083602797597195659491558217965106724744145849368927955484176253258934021689357027136103182621)
```

再用cs\_calc\_pri.py通过p和q计算私钥

```
# -*- coding: utf-8 -*-

from Crypto.PublicKey import RSA

def generate_rsa_keypair(p, q, e=65537):
    """
    生成RSA密钥对。

    :param p: 大素数p
    :param q: 大素数q
    :param e: 公钥指数，默认为65537
    :return: RSA私钥
    """
    # 计算模数N
    N = p * q
    # 计算欧拉函数phi(N)
    phi = (p - 1) * (q - 1)
    # 计算私钥d
    d = pow(e, -1, phi)
    # 构造RSA私钥
    pri_key = RSA.construct((N, e, d))
    return pri_key

def save_private_key_to_file(private_key, filename="id_rsa"):
    """
    将私钥保存到文件中。

    :param private_key: RSA私钥对象
    :param filename: 保存的文件名，默认为"id_rsa"
    """
    with open(filename, "wb") as f:
        f.write(private_key.export_key("PEM"))

# 示例：生成RSA密钥对并保存私钥
if __name__ == "__main__":
    # 输入大素数p和q
    p = 
    q = 

    private_key = generate_rsa_keypair(p, q)
    save_private_key_to_file(private_key)
    print(f"私钥已保存到文件：id_rsa")
```

这题分解不出来，私钥需要通过.cobaltstrike.beacon\_keys得到

`.cobaltstrike.beacon_keys` 是 **CobaltStrike** 团队服务器（Team Server）在首次运行时自动生成的关键文件，主要用于存储 **RSA 密钥对**（公钥和私钥），这些密钥用于加密 Beacon（客户端）与 C2 服务器之间的通信元数据。

#### 解密.cobaltstrike.beacon\_keys

```
import base64

import javaobj.v2 as javaobj

with open(".cobaltstrike.beacon_keys", "rb") as fd:
    pobj = javaobj.load(fd)
privateKey = pobj.array.value.privateKey.encoded.data
publicKey = pobj.array.value.publicKey.encoded.data


privateKey = (
    b"-----BEGIN PRIVATE KEY-----
"
    + base64.encodebytes(bytes(map(lambda x: x & 0xFF, privateKey)))
    + b"-----END PRIVATE KEY-----"
)
publicKey = (
    b"-----BEGIN PUBLIC KEY-----
"
    + base64.encodebytes(bytes(map(lambda x: x & 0xFF, publicKey)))
    + b"-----END PUBLIC KEY-----"
)
print(privateKey.decode())
print(publicKey.decode())
```

运行脚本（parse\_beacon\_keys.py内容如上），得到公私钥

```
-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJO0EnJxkHuANSxqFba7FwG9AWV6
L7o8ofulbZoT6fHzEhrDqnAkj4YhIX/d/ApITnjr9OW0i7SATqur5TZs9IhrbOKloRPt2FH8Wy+2
KpJQQzVAALuufy9117C3CXoXt8feGVF01LF87hSZrh5S484+7D9wAR2XHQIsCocj3vEdAgMBAAEC
gYBp/uTqGhNcfZIrMGoquzJ0feWdpETR+qcoBvyTgMz3Y79PU7FhTutsjyQSNgSkgGVII9SYb6t+
OkG6st4H48LLbsOm3sSo6KIoILuwIKPP4weXi8EdeFUeb8adwFgXC2XPs9Q0gnv148UDDNVf6UqO
S/ytp3rebDMCQXUJsuOSJQJBAPzIJvVfLlweOqNScH3/iUrkk/rFFXAlC/K4B0PkHsZuoI2B9/aM
VyGDdk4nUGzswLVizA8bfgqdoJ0vRyV12o8CQQCVlXS+qEOAUxiOiVwtosRP5UUw6lIv2+rMxSeX
VVNfitYanH88/n3sr4UDGizlKZAQC18TDlxeRXwKzWgyov+TAkAM+KxfHQJBAeAab2mMXaeK603Y
qXJfLdd+HglpZ3RY1GZyvH+f7DWwZ5GTkxribAe7hxVXlR6TpuEOD9YDyxdrAkAbDlN1gN3kwiL4
9SN1JbG4edHQDTIccfzAWRDWMJrJ90TOv2vMToPcYcr/SqbANIpYPJZPzhMrAgpzsb+dGRp9AkEA
zWFEOBKqLnfIZR4g6AtuIugScM67nU3Kpo6P9jFZsnLrMjhc6RvyfKWrnQkpeNx8GGagTrOKlTXe
XxcjlSvp0g==
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCTtBJycZB7gDUsahW2uxcBvQFlei+6PKH7pW2a
E+nx8xIaw6pwJI+GISF/3fwKSE546/TltIu0gE6rq+U2bPSIa2zipaET7dhR/FsvtiqSUEM1QAC7
rn8vddewtwl6F7fH3hlRdNSxfO4Uma4eUuPOPuw/cAEdlx0CLAqHI97xHQIDAQAB
-----END PUBLIC KEY-----
```

### 获取RAW/AES/HMAC KEY

#### 解密私钥获取

这里解私钥，取出存为key.pem

```
from Crypto.PublicKey import RSA
import binascii

# 读取 PEM 文件中的密钥
with open('private.key', 'r') as f:
    key = RSA.importKey(f.read())

# 将密钥转换为十六进制
hex_key = binascii.hexlify(key.exportKey(format='DER')).decode('utf-8')

print(hex_key)
```

得到

```
(base) m4rt3n@M4rt3n:~/CS_analysis$ python get_privatekey_hex.py
3082025c0201000281810093b4127271907b80352c6a15b6bb1701bd01657a2fba3ca1fba56d9a13e9f1f3121ac3aa70248f8621217fddfc0a484e78ebf4e5b48bb4804eababe5366cf4886b6ce2a5a113edd851fc5b2fb62a925043354000bbae7f2f75d7b0b7097a17b7c7de195174d4b17cee1499ae1e52e3ce3eec3f70011d971d022c0a8723def11d020301000102818069fee4ea1a135c7d922b306a2abb32747de59da444d1faa72806fc9380ccf763bf4f53b1614eeb6c8f24123604a480654823d4986fab7e3a41bab2de07e3c2cb6ec3a6dec4a8e8a22820bbb020a3cfe307978bc11d78551e6fc69dc058170b65cfb3d434827bf5e3c5030cd55fe94a8e4bfcada77ade6c3302417509b2e39225024100fcc826f55f2e5c1e3aa352707dff894ae493fac51570250bf2b80743e41ec66ea08d81f7f68c572183764e27506cecc0b562cc0f1b7e0a9da09d2f472575da8f024100959574bea8438053188e895c2da2c44fe54530ea522fdbeaccc5279755535f8ad61a9c7f3cfe7decaf85031a2ce52990100b5f130e5c5e457c0acd6832a2ff9302400cf8ac5f1d024101e01a6f698c5da78aeb4dd8a9725f2dd77e1e0969677458d46672bc7f9fec35b0679193931ae26c07bb871557951e93a6e10e0fd603cb176b02401b0e537580dde4c222f8f5237525b1b879d1d00d321c71fcc05910d6309ac9f744cebf6bcc4e83dc61caff4aa6c0348a583c964fce132b020a73b1bf9d191a7d024100cd61443812aa2e77c8651e20e80b6e22e81270cebb9d4dcaa68e8ff63159b272eb32385ce91bf27ca5ab9d092978dc7c1866a04eb38a9535de5f1723952be9d2
```

这时已经可以解密cookie中的元数据了，会遇到报错

```
cs-decrypt-metadata.py:553: SyntaxWarning: invalid escape sequence '\.'
  if not re.match(b'[0-9]+\.[0-9]+\t[0-9]+', peek):
```

只要修改为rb即可

![图片.png](images/20250804155035-b4c21edc-7107-1.png)

```
DidierStevensSuite>python cs-decrypt-metadata.py -p 3082025c0201000281810093b4127271907b80352c6a15b6bb1701bd01657a2fba3ca1fba56d9a13e9f1f3121ac3aa70248f8621217fddfc0a484e78ebf4e5b48bb4804eababe5366cf4886b6ce2a5a113edd851fc5b2fb62a925043354000bbae7f2f75d7b0b7097a17b7c7de195174d4b17cee1499ae1e52e3ce3eec3f70011d971d022c0a8723def11d020301000102818069fee4ea1a135c7d922b306a2abb32747de59da444d1faa72806fc9380ccf763bf4f53b1614eeb6c8f24123604a480654823d4986fab7e3a41bab2de07e3c2cb6ec3a6dec4a8e8a22820bbb020a3cfe307978bc11d78551e6fc69dc058170b65cfb3d434827bf5e3c5030cd55fe94a8e4bfcada77ade6c3302417509b2e39225024100fcc826f55f2e5c1e3aa352707dff894ae493fac51570250bf2b80743e41ec66ea08d81f7f68c572183764e27506cecc0b562cc0f1b7e0a9da09d2f472575da8f024100959574bea8438053188e895c2da2c44fe54530ea522fdbeaccc5279755535f8ad61a9c7f3cfe7decaf85031a2ce52990100b5f130e5c5e457c0acd6832a2ff9302400cf8ac5f1d024101e01a6f698c5da78aeb4dd8a9725f2dd77e1e0969677458d46672bc7f9fec35b0679193931ae26c07bb871557951e93a6e10e0fd603cb176b02401b0e537580dde4c222f8f5237525b1b879d1d00d321c71fcc05910d6309ac9f744cebf6bcc4e83dc61caff4aa6c0348a583c964fce132b020a73b1bf9d191a7d024100cd61443812aa2e77c8651e20e80b6e22e81270cebb9d4dcaa68e8ff63159b272eb32385ce91bf27ca5ab9d092978dc7c1866a04eb38a9535de5f1723952be9d2 IyltNSnpj6lSGi0WGIaJIsFWg6Ko6V+20xExzajz0A3AkRi2MMWjLSZvHltXLFJg5joFEKQ8lQYKh96XCYfDMO3yWWCzyZdpoCLdWRNzR8FN3Z3buww8afGOhKe+NVEWFzTPafNZh3kFlWUf5zk/etCn8WPy4qg4BArMvbx/yqM=
Input: IyltNSnpj6lSGi0WGIaJIsFWg6Ko6V+20xExzajz0A3AkRi2MMWjLSZvHltXLFJg5joFEKQ8lQYKh96XCYfDMO3yWWCzyZdpoCLdWRNzR8FN3Z3buww8afGOhKe+NVEWFzTPafNZh3kFlWUf5zk/etCn8WPy4qg4BArMvbx/yqM=
Encrypted metadata: 23296d3529e98fa9521a2d1618868922c15683a2a8e95fb6d31131cda8f3d00dc09118b630c5a32d266f1e5b572c5260e63a0510a43c95060a87de970987c330edf25960b3c99769a022dd59137347c14ddd9ddbbb0c3c69f18e84a7be3551161734cf69f35987790595651fe7393f7ad0a7f163f2e2a838040accbdbc7fcaa3
Decrypted:
Header: 0000beef
Datasize: 0000005d
Raw key:  a4553adf7a841e1dcf708afc912275ee
 aeskey:  a368237121ef51b094068a2e92304d46
 hmackey: b6315feb217bd87188d06870dd92855b
charset: 03a8 ANSI/OEM Simplified Chinese (PRC, Singapore); Chinese Simplified (GB2312)
charset_oem: 03a8 ANSI/OEM Simplified Chinese (PRC, Singapore); Chinese Simplified (GB2312)
bid: 5f96edca 1603726794
pid: 0acc 2764
port: 0
flags: 0e
var1: 6
var2: 2
var3: 9200
var4: 32760
var5: 265866928
var6: 265854304
Internal IPv4: 192.168.113.149
Field: b'WIN-8FC6TKPDPOR'
Field: b'Administrator'
Field: b'artifact.exe'
```

![图片.png](images/20250804155036-b4dfdbfa-7107-1.png)

也可以用这个脚本（encode\_data为cookie，base64\_key为私钥）

```
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64
import hexdump

PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
{}
-----END RSA PRIVATE KEY-----"""

encode_data = "IyltNSnpj6lSGi0WGIaJIsFWg6Ko6V+20xExzajz0A3AkRi2MMWjLSZvHltXLFJg5joFEKQ8lQYKh96XCYfDMO3yWWCzyZdpoCLdWRNzR8FN3Z3buww8afGOhKe+NVEWFzTPafNZh3kFlWUf5zk/etCn8WPy4qg4BArMvbx/yqM="
base64_key = """MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJO0EnJxkHuANSxqFba7FwG9AWV6
L7o8ofulbZoT6fHzEhrDqnAkj4YhIX/d/ApITnjr9OW0i7SATqur5TZs9IhrbOKloRPt2FH8Wy+2
KpJQQzVAALuufy9117C3CXoXt8feGVF01LF87hSZrh5S484+7D9wAR2XHQIsCocj3vEdAgMBAAEC
gYBp/uTqGhNcfZIrMGoquzJ0feWdpETR+qcoBvyTgMz3Y79PU7FhTutsjyQSNgSkgGVII9SYb6t+
OkG6st4H48LLbsOm3sSo6KIoILuwIKPP4weXi8EdeFUeb8adwFgXC2XPs9Q0gnv148UDDNVf6UqO
S/ytp3rebDMCQXUJsuOSJQJBAPzIJvVfLlweOqNScH3/iUrkk/rFFXAlC/K4B0PkHsZuoI2B9/aM
VyGDdk4nUGzswLVizA8bfgqdoJ0vRyV12o8CQQCVlXS+qEOAUxiOiVwtosRP5UUw6lIv2+rMxSeX
VVNfitYanH88/n3sr4UDGizlKZAQC18TDlxeRXwKzWgyov+TAkAM+KxfHQJBAeAab2mMXaeK603Y
qXJfLdd+HglpZ3RY1GZyvH+f7DWwZ5GTkxribAe7hxVXlR6TpuEOD9YDyxdrAkAbDlN1gN3kwiL4
9SN1JbG4edHQDTIccfzAWRDWMJrJ90TOv2vMToPcYcr/SqbANIpYPJZPzhMrAgpzsb+dGRp9AkEA
zWFEOBKqLnfIZR4g6AtuIugScM67nU3Kpo6P9jFZsnLrMjhc6RvyfKWrnQkpeNx8GGagTrOKlTXe
XxcjlSvp0g=="""

private_key = RSA.import_key(PRIVATE_KEY.format(base64_key).encode())
cipher = PKCS1_v1_5.new(private_key)
ciphertext = cipher.decrypt(base64.b64decode(encode_data), 0)

def isFlag(var, flag):
	return (var & flag) == flag


def toIP(var):
	var2 = (var & -16777216) >> 24
	var4 = (var & 16711680) >> 16
	var6 = (var & 65280) >> 8
	var8 = var & 255
	return str(var2) + "." + str(var4) + "." + str(var6) + "." + str(var8)


def getName(var0):
	if var0 == 37:
		return "IBM037"
	elif var0 == 437:
		return "IBM437"
	elif var0 == 500:
		return "IBM500"
	elif var0 == 708:
		return "ISO-8859-6"
	elif var0 == 709:
		return ""
	elif var0 == 710:
		return ""
	elif var0 == 720:
		return "IBM437"
	elif var0 == 737:
		return "x-IBM737"
	elif var0 == 775:
		return "IBM775"
	elif var0 == 850:
		return "IBM850"
	elif var0 == 852:
		return "IBM852"
	elif var0 == 855:
		return "IBM855"
	elif var0 == 857:
		return "IBM857"
	elif var0 == 858:
		return "IBM00858"
	elif var0 == 860:
		return "IBM860"
	elif var0 == 861:
		return "IBM861"
	elif var0 == 862:
		return "IBM862"
	elif var0 == 863:
		return "IBM863"
	elif var0 == 864:
		return "IBM864"
	elif var0 == 865:
		return "IBM865"
	elif var0 == 866:
		return "IBM866"
	elif var0 == 869:
		return "IBM869"
	elif var0 == 870:
		return "IBM870"
	elif var0 == 874:
		return "x-windows-874"
	elif var0 == 875:
		return "IBM875"
	elif var0 == 932:
		return "Shift_JIS"
	elif var0 == 936:
		return "x-mswin-936"
	elif var0 == 949:
		return "x-windows-949"
	elif var0 == 950:
		return "Big5"
	elif var0 == 1026:
		return "IBM1026"
	elif var0 == 1047:
		return "IBM1047"
	elif var0 == 1140:
		return "IBM01140"
	elif var0 == 1141:
		return "IBM01141"
	elif var0 == 1142:
		return "IBM01142"
	elif var0 == 1143:
		return "IBM01143"
	elif var0 == 1144:
		return "IBM01144"
	elif var0 == 1145:
		return "IBM01145"
	elif var0 == 1146:
		return "IBM01146"
	elif var0 == 1147:
		return "IBM01147"
	elif var0 == 1148:
		return "IBM01148"
	elif var0 == 1149:
		return "IBM01149"
	elif var0 == 1200:
		return "UTF-16LE"
	elif var0 == 1201:
		return "UTF-16BE"
	elif var0 == 1250:
		return "windows-1250"
	elif var0 == 1251:
		return "windows-1251"
	elif var0 == 1252:
		return "windows-1252"
	elif var0 == 1253:
		return "windows-1253"
	elif var0 == 1254:
		return "windows-1254"
	elif var0 == 1255:
		return "windows-1255"
	elif var0 == 1256:
		return "windows-1256"
	elif var0 == 1257:
		return "windows-1257"
	elif var0 == 1258:
		return "windows-1258"
	elif var0 == 1361:
		return "x-Johab"
	elif var0 == 10000:
		return "x-MacRoman"
	elif var0 == 10001:
		return ""
	elif var0 == 10002:
		return ""
	elif var0 == 10003:
		return ""
	elif var0 == 10004:
		return "x-MacArabic"
	elif var0 == 10005:
		return "x-MacHebrew"
	elif var0 == 10006:
		return "x-MacGreek"
	elif var0 == 10007:
		return "x-MacCyrillic"
	elif var0 == 10008:
		return ""
	elif var0 == 10010:
		return "x-MacRomania"
	elif var0 == 10017:
		return "x-MacUkraine"
	elif var0 == 10021:
		return "x-MacThai"
	elif var0 == 10029:
		return "x-MacCentralEurope"
	elif var0 == 10079:
		return "x-MacIceland"
	elif var0 == 10081:
		return "x-MacTurkish"
	elif var0 == 10082:
		return "x-MacCroatian"
	elif var0 == 12000:
		return "UTF-32LE"
	elif var0 == 12001:
		return "UTF-32BE"
	elif var0 == 20000:
		return "x-ISO-2022-CN-CNS"
	elif var0 == 20001:
		return ""
	elif var0 == 20002:
		return ""
	elif var0 == 20003:
		return ""
	elif var0 == 20004:
		return ""
	elif var0 == 20005:
		return ""
	elif var0 == 20105:
		return ""
	elif var0 == 20106:
		return ""
	elif var0 == 20107:
		return ""
	elif var0 == 20108:
		return ""
	elif var0 == 20127:
		return "US-ASCII"
	elif var0 == 20261:
		return ""
	elif var0 == 20269:
		return ""
	elif var0 == 20273:
		return "IBM273"
	elif var0 == 20277:
		return "IBM277"
	elif var0 == 20278:
		return "IBM278"
	elif var0 == 20280:
		return "IBM280"
	elif var0 == 20284:
		return "IBM284"
	elif var0 == 20285:
		return "IBM285"
	elif var0 == 20290:
		return "IBM290"
	elif var0 == 20297:
		return "IBM297"
	elif var0 == 20420:
		return "IBM420"
	elif var0 == 20423:
		return ""
	elif var0 == 20424:
		return "IBM424"
	elif var0 == 20833:
		return ""
	elif var0 == 20838:
		return "IBM-Thai"
	elif var0 == 20866:
		return "KOI8-R"
	elif var0 == 20871:
		return "IBM871"
	elif var0 == 20880:
		return ""
	elif var0 == 20905:
		return ""
	elif var0 == 20924:
		return ""
	elif var0 == 20932:
		return "EUC-JP"
	elif var0 == 20936:
		return "GB2312"
	elif var0 == 20949:
		return ""
	elif var0 == 21025:
		return "x-IBM1025"
	elif var0 == 21027:
		return ""
	elif var0 == 21866:
		return "KOI8-U"
	elif var0 == 28591:
		return "ISO-8859-1"
	elif var0 == 28592:
		return "ISO-8859-2"
	elif var0 == 28593:
		return "ISO-8859-3"
	elif var0 == 28594:
		return "ISO-8859-4"
	elif var0 == 28595:
		return "ISO-8859-5"
	elif var0 == 28596:
		return "ISO-8859-6"
	elif var0 == 28597:
		return "ISO-8859-7"
	elif var0 == 28598:
		return "ISO-8859-8"
	elif var0 == 28599:
		return "ISO-8859-9"
	elif var0 == 28603:
		return "ISO-8859-13"
	elif var0 == 28605:
		return "ISO-8859-15"
	elif var0 == 29001:
		return ""
	elif var0 == 38598:
		return "ISO-8859-8"
	elif var0 == 50220:
		return "ISO-2022-JP"
	elif var0 == 50221:
		return "ISO-2022-JP-2"
	elif var0 == 50222:
		return "ISO-2022-JP"
	elif var0 == 50225:
		return "ISO-2022-KR"
	elif var0 == 50227:
		return "ISO-2022-CN"
	elif var0 == 50229:
		return "ISO-2022-CN"
	elif var0 == 50930:
		return "x-IBM930"
	elif var0 == 50931:
		return ""
	elif var0 == 50933:
		return "x-IBM933"
	elif var0 == 50935:
		return "x-IBM935"
	elif var0 == 50936:
		return ""
	elif var0 == 50937:
		return "x-IBM937"
	elif var0 == 50939:
		return "x-IBM939"
	elif var0 == 51932:
		return "EUC-JP"
	elif var0 == 51936:
		return "GB2312"
	elif var0 == 51949:
		return "EUC-KR"
	elif var0 == 51950:
		return ""
	elif var0 == 52936:
		return "GB2312"
	elif var0 == 54936:
		return "GB18030"
	elif var0 == 57002:
		return "x-ISCII91"
	elif var0 == 57003:
		return "x-ISCII91"
	elif var0 == 57004:
		return "x-ISCII91"
	elif var0 == 57005:
		return "x-ISCII91"
	elif var0 == 57006:
		return "x-ISCII91"
	elif var0 == 57007:
		return "x-ISCII91"
	elif var0 == 57008:
		return "x-ISCII91"
	elif var0 == 57009:
		return "x-ISCII91"
	elif var0 == 57010:
		return "x-ISCII91"
	elif var0 == 57011:
		return "x-ISCII91"
	elif var0 == 65000:
		return ""
	elif var0 == 65001:
		return "UTF-8"


if ciphertext[0:4] == b'\x00\x00\xBE\xEF':

	# 16
	raw_aes_keys = ciphertext[8:24]

	# 2
	var9 = ciphertext[24:26]
	var9 = int.from_bytes(var9, byteorder='little', signed=False)
	var9 = getName(var9)
	# 2
	var10 = ciphertext[26:28]
	var10 = int.from_bytes(var10, byteorder='little', signed=False)
	var10 = getName(var10)

	# 4
	id = ciphertext[28:32]
	id = int.from_bytes(id, byteorder='big', signed=False)
	print("Beacon id:{}".format(id))

	# 4
	pid = ciphertext[32:36]
	pid = int.from_bytes(pid, byteorder='big', signed=False)
	print("pid:{}".format(pid))

	# 2
	port = ciphertext[36:38]
	port = int.from_bytes(port, byteorder='big', signed=False)
	print("port:{}".format(port))

	# 1
	flag = ciphertext[38:39]
	flag = int.from_bytes(flag, byteorder='big', signed=False)
	# print(flag)

	if isFlag(flag, 1):
		barch = ""
		pid = ""
		is64 = ""
	elif isFlag(flag, 2):
		barch = "x64"
	else:
		barch = "x86"

	if isFlag(flag, 4):
		is64 = "1"
	else:
		is64 = "0"

	if isFlag(flag, 8):
		bypassuac = "True"
	else:
		bypassuac = "False"

	print("barch:" + barch)
	print("is64:" + is64)
	print("bypass:" + bypassuac)

	# 2
	var_1 = ciphertext[39:40]
	var_2 = ciphertext[40:41]
	var_1 = int.from_bytes(var_1, byteorder='big', signed=False)
	var_2 = int.from_bytes(var_2, byteorder='big', signed=False)
	windows_var = str(var_1) + "." + str(var_2)
	print("windows var:" + windows_var)

	# 2
	windows_build = ciphertext[41:43]
	windows_build = int.from_bytes(windows_build, byteorder='big', signed=False)
	print("windows build:{}".format(windows_build))

	# 4
	x64_P = ciphertext[43:47]

	# 4
	ptr_gmh = ciphertext[47:51]
	# 4
	ptr_gpa = ciphertext[51:55]

	# if ("x64".equals(this.barch)) {
	# this.ptr_gmh = CommonUtils.join(var10, this.ptr_gmh)
	# this.ptr_gpa = CommonUtils.join(var10, this.ptr_gpa)
	# }
	#
	# this.ptr_gmh = CommonUtils.bswap(this.ptr_gmh)
	# this.ptr_gpa = CommonUtils.bswap(this.ptr_gpa)

	# 4
	intz = ciphertext[55:59]
	intz = int.from_bytes(intz, byteorder='little', signed=False)
	intz = toIP(intz)

	if intz == "0.0.0.0":
		intz = "unknown"
	print("host:" + intz)

	if var9 == None:
		ddata = ciphertext[59:len(ciphertext)].decode("ISO8859-1")
	else:
		# ??x-mswin-936
		# ddata = ciphertext[59:len(ciphertext)].decode(var9)
		ddata = ciphertext[59:len(ciphertext)].decode("ISO8859-1")

	ddata = ddata.split("\t")
	if len(ddata) > 0:
		computer = ddata[0]
	if len(ddata) > 1:
		username = ddata[1]
	if len(ddata) > 2:
		process = ddata[2]

	print("PC name:" + computer)
	print("username:" + username)
	print("process name:" + process)

	raw_aes_hash256 = hashlib.sha256(raw_aes_keys)
	digest = raw_aes_hash256.digest()
	aes_key = digest[0:16]
	hmac_key = digest[16:]

	print("AES key:{}".format(aes_key.hex()))
	print("HMAC key:{}".format(hmac_key.hex()))

	print(hexdump.hexdump(ciphertext))
```

输出如下

```
Beacon id:1603726794
pid:2764
port:0
barch:x64
is64:1
bypass:True
windows var:6.2
windows build:9200
host:192.168.113.149
PC name:WIN-8FC6TKPDPOR
username:Administrator
process name:artifact.exe
AES key:a368237121ef51b094068a2e92304d46
HMAC key:b6315feb217bd87188d06870dd92855b
00000000: 00 00 BE EF 00 00 00 5D  A4 55 3A DF 7A 84 1E 1D  .......].U:.z...
00000010: CF 70 8A FC 91 22 75 EE  A8 03 A8 03 5F 96 ED CA  .p..."u....._...
00000020: 00 00 0A CC 00 00 0E 06  02 23 F0 00 00 7F F8 0F  .........#......
00000030: D8 CE B0 0F D8 9D 60 95  71 A8 C0 57 49 4E 2D 38  ......`.q..WIN-8
00000040: 46 43 36 54 4B 50 44 50  4F 52 09 41 64 6D 69 6E  FC6TKPDPOR.Admin
00000050: 69 73 74 72 61 74 6F 72  09 61 72 74 69 66 61 63  istrator.artifac
00000060: 74 2E 65 78 65                                    t.exe
None
```

#### 通过进程内存提取

参考：

<https://www.secrss.com/articles/35756>

<https://www.secrss.com/articles/35601>

以nepctf2025的客服小美为例，附件是一个流量包和一个内存文件

![图片.png](images/20250804155036-b4fd11e2-7107-1.png)

明显的Cobalt Strike流量流量特征，给了内存考察点必然是通过进程内存提取密钥解密

```
┌──(kali㉿kali)-[~/取证/volatility3]
└─$ python3 vol.py -f '/home/kali/Desktop/DESKTOP.raw' windows.info

Variable        Value

Kernel Base     0xf8005161e000
DTB     0x1ad000
Symbols file:///home/kali/%E5%8F%96%E8%AF%81/volatility3/volatility3/symbols/windows/ntkrnlmp.pdb/68A17FAF3012B7846079AEECDBE0A583-1.json.xz
Is64Bit True
IsPAE   False
layer_name      0 WindowsIntel32e
memory_layer    1 FileLayer
KdVersionBlock  0xf8005222d398
Major/Minor     15.19041
MachineType     34404
KeNumberProcessors      2
SystemTime      2025-01-13 07:30:02+00:00
NtSystemRoot    C:\Windows
NtProductType   NtProductWinNt
NtMajorVersion  10
NtMinorVersion  0
PE MajorOperatingSystemVersion  10
PE MinorOperatingSystemVersion  0
PE Machine      34404
PE TimeDateStamp        Wed Jun 28 04:14:26 1995

```

通过查看命令行参数

```
┌──(kali㉿kali)-[~/取证/volatility3]
└─$ python3 vol.py -f '/home/kali/Desktop/DESKTOP.raw' windows.cmdline
Volatility 3 Framework 2.26.2
Progress:  100.00               PDB scanning finished                        
PID     Process Args

4       System  -
92      Registry        -
344     smss.exe        -
424     csrss.exe       -
500     wininit.exe     -
508     csrss.exe       %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16
568     winlogon.exe    winlogon.exe
636     services.exe    C:\Windows\system32\services.exe
652     lsass.exe       C:\Windows\system32\lsass.exe
760     svchost.exe     C:\Windows\system32\svchost.exe -k DcomLaunch -p
768     fontdrvhost.ex  -
772     fontdrvhost.ex  -
876     svchost.exe     C:\Windows\system32\svchost.exe -k RPCSS -p
956     dwm.exe "dwm.exe"
276     svchost.exe     C:\Windows\system32\svchost.exe -k netsvcs -p
448     svchost.exe     C:\Windows\system32\svchost.exe -k LocalServiceNoNetwork -p
512     svchost.exe     C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p
696     svchost.exe     C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p
1052    svchost.exe     -
1092    svchost.exe     C:\Windows\system32\svchost.exe -k LocalService -p
1184    svchost.exe     -
1220    svchost.exe     C:\Windows\System32\svchost.exe -k NetworkService -p
1372    MemCompression  -
1476    svchost.exe     C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p
1572    svchost.exe     C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p
1584    svchost.exe     -
1656    svchost.exe     -
1776    spoolsv.exe     -
1900    svchost.exe     -
2020    svchost.exe     -
2100    svchost.exe     -
2216    VGAuthService.  -
2244    vm3dservice.ex  -
2260    vmtoolsd.exe    -
2300    MsMpEng.exe     "C:\Program Files\Windows Defender\MsMpEng.exe"
2432    vm3dservice.ex  -
2672    dllhost.exe     -
2812    dllhost.exe     C:\Windows\system32\dllhost.exe /Processid:{02D4B3F1-FD88-11D1-960D-00805FC79235}
2856    WmiPrvSE.exe    C:\Windows\system32\wbem\wmiprvse.exe
360     svchost.exe     -
2576    dasHost.exe     -
3128    msdtc.exe       -
3356    VSSVC.exe       -
3364    sihost.exe      sihost.exe
3392    svchost.exe     C:\Windows\system32\svchost.exe -k UnistackSvcGroup
3452    taskhostw.exe   taskhostw.exe {222A245B-E637-4AE9-A93F-A59CA119A75E}
3652    ctfmon.exe      "ctfmon.exe"
3800    ChsIME.exe      -
3888    userinit.exe    -
3944    explorer.exe    C:\Windows\Explorer.EXE
1836    svchost.exe     -
4180    svchost.exe     -
4260    WmiPrvSE.exe    -
4392    NisSrv.exe      -
4692    TrustedInstall  -
4744    TiWorker.exe    -
796     WmiApSrv.exe    -
4120    StartMenuExper  "C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe" -ServerName:App.AppXywbrabmsek0gm3tkwpr5kwzbs55tkqay.mca
3512    RuntimeBroker.  -
5048    SearchApp.exe   "C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe" -ServerName:CortanaUI.AppX8z9r6jm96hw4bsbneegw0kyxx296wr9t.mca
5040    SearchIndexer.  -
5204    RuntimeBroker.  -
5828    TextInputHost.  "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TextInputHost.exe" -ServerName:InputApp.AppXjd5de1g66v206tj52m9d0dtpppx4cgpn.mca
6072    SearchProtocol  -
6112    SearchFilterHo  -
4324    taskhostw.exe   -
5940    RuntimeBroker.  -
2280    smartscreen.ex  -
4672    SecurityHealth  -
6060    SecurityHealth  -
436     vmtoolsd.exe    "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr
5456    OneDrive.exe    "C:\Users\JohnDoe\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background
6492    s       "C:\Users\JohnDoe\Desktop\关于2025年部分节假日安排的通知.exe" 
6848    ShellExperienc  "C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe" -ServerName:App.AppXtk181tbxbce2qsex02s8tw7hfxa9xb3t.mca
6964    audiodg.exe     C:\Windows\system32\AUDIODG.EXE 0x4d4
6980    RuntimeBroker.  C:\Windows\System32\RuntimeBroker.exe -Embedding
6240    RuntimeBroker.  -
6360    RuntimeBroker.  -
6344    svchost.exe     -
5200    svchost.exe     -
4884    SgrmBroker.exe  C:\Windows\system32\SgrmBroker.exe
1488    sppsvc.exe      -
2344    svchost.exe     C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p
3448    ChsIME.exe      C:\Windows\System32\InputMethod\CHS\ChsIME.exe -Embedding
5704    DumpIt.exe      "C:\Users\JohnDoe\Desktop\DumpIt.exe" 
544     conhost.exe     \??\C:\Windows\system32\conhost.exe 0x4

```

可以看到桌面的可疑exe文件，文件转储

```
┌──(kali㉿kali)-[~/取证/volatility3]
└─$ python3 vol.py -f '/home/kali/Desktop/DESKTOP.raw' windows.filescan | grep "关于2025年部分节假日安排的 通知.exe"
0xd804ad5794a0.0\Users\JohnDoe\Desktop\关于2025年部分节假日安排的通知.exe
0xd804ad581b00  \Users\JohnDoe\Desktop\关于2025年部分节假日安排的通知.exe

┌──(kali㉿kali)-[~/取证/volatility3]
└─$ python3 vol.py -f '/home/kali/Desktop/DESKTOP.raw' windows.dumpfiles
```

放入云沙箱，也可以检测出是cs

![图片.png](images/20250804155036-b527131e-7107-1.png)

这里需要的是内存转储

```
┌──(kali㉿kali)-[~/取证/volatility3]
└─$ python3 vol.py -f '/home/kali/Desktop/DESKTOP.raw' windows.pslist

6492    3944    s�2025t��G剒    0xd804acd6b080  5       -       1       False   2025-01-13 07:29:00.000000 UTC  N/ADisabled

┌──(kali㉿kali)-[~/取证/volatility3]
└─$ python3 vol.py -f '/home/kali/Desktop/DESKTOP.raw' windows.memmap --pid 6492 --dump

```

使用DidierStevensSuite的cs-extract-key.py 查找并解码元数据

```
DidierStevensSuite>python cs-extract-key.py pid.6492.dmp

Position: 0x1502bd0b
Header: 0000beef
Datasize: 0000c048
Raw key:  8b5f18baf00000c08b81280300003903
 aeskey:  838fc9895d21be302a0fb8bfe3014410
     hmackey: 9b18805cff981ea72c5df0416c2165c3
charset: b60f
charset_oem: 2c81
bid: 3000041 50331713
pid: f44f538 256177464
port: 17156
flags: 0f
Field: b'\xb6\x81-\x03\x00\x00\x0fE\xf28C\x05t\x08\x8dr\x01\xe9p\xff\xff\xff\x85\xf6\x0f\x88h\xff\xff\xff\x0f\xb6C\x07:\x81/\x03\x00\x00t(\x88\x81/\x03\x00\x00L\x8d\x05\xb7d\x03\x00D\x0f\xb6K\x07H\x8d\x15\x93d\x03\x00I\x8b\xce\xe8\xf3A\x05\x00I\x8b\x8ex\x04\x00\x00\x0f\xb6C\x06L\x8d\x059h\x03\x00\x88\x81.\x03\x00\x00H\x8d\x15ld\x03\x00D8k\x06I\x8b\xceA\x0f\x95\xc5E\x8dM\x02\xe8\xc0A\x05\x00\xe9\x03\xff\xff\xffA\xf6Fh\x01H\x8b\xd7I\x8b\xcf\x0f\x84\x98\xef\xff\xffL\x8b\xc3\xe8\x06\xab\x02\x00\x8b\xf0\xe9$\xef\xff\xffA\x8bT$\x10H\x8bG\x18\x83\xfa\x1cs
\xbe\r\x00\x00\xc0\xe9\xf0\xee\xff\xffD\x8b@\x10L\x8b\xe0\x8b@\x18I\x8dH\x1cH\x03\xc8H;\xd1s
\xbe\r\x00\x00\xc0\xe9\xd0\xee\xff\xffA\xf6Fh\x01u\x0cD8-O\x04\x04\x00\xe9
\xef\xff\xffI\x8b\x86\x08\x02\x00\x00\x83x\x1c\x10u*A\x8bD$\x04\x83\xf8\x19w
\xb9\x02\x00\x80\x02\x0f\xa3\xc1r
\x05\xed\xff\xff\x7f\x83\xf8\x03w\x0cD8-\x18\x04\x04\x00\xe9\xd3\xee\xff\xffA\x8bD$\x04=\x03\x00\x00\x80\x0f\x87\x9c\x02\x00\x00\x0f\x84\x86\x02\x00\x00\x83\xf8\x01\x0f\x84f\x02\x00\x00\x83\xf8\x04\x0f\x84M\x02\x00\x00\x83\xf8\x17\x0f\x841\x02\x00\x00\x83\xf8\x19\x0f\x84\x15\x02\x00\x00=\x02\x00\x00\x80\x0f\x85\x9e\x02\x00\x00I\x8b\x8ex\x04\x00\x00L9\xa9\xe0\x00\x00\x00\x0f\x84\x8a\x02\x00\x00A\x8bD$\x0cI\x8d4\x04\x83\xf8\x1c\x0f\x82x\x02\x00\x00\x8b\x06\x83\xf8\x1c\x0f\x82m\x02\x00\x00A;\xc0\x0f\x87d\x02\x00\x00\x83~\x08\x01\x0f\x85Z\x02\x00\x00H\x8bF\x0cH;\x05%l\x03\x00\x0f\x85I\x02\x00\x00H\x8bF\x14H;\x05\x1cl\x03\x00\x0f\x858\x02\x00\x00H\x8b\x89 \x01\x00\x00L\x8b\x15\x98B\x04\x00\xe8\xbb\x02\xe8\xfdE\x8bT$\x14\x8bF\x04M\x03\xd4L\x89T$H\xa8\x01\x0f\x84\x16\x01\x00\x00I\x8b\x96x\x04\x00\x00H\x81\xc2\x18\x01\x00\x00H\x8b
H\x85\xc9t/M\x8b\x02H\x8b\x01L;A\x18t\rH\x8b\xd1H\x8b\xc8H\x85\xc0u\xec\xeb\x16H\x89\x023\xd2L\x8b\x15\xb8A\x04\x00\xe8\xa3\xb0Y\xfeL\x8bT$HE\x8b\$\x18M\x8b\xc5M\x8b\xcdI\x8b\xd2K\x8d\x0c\x1aL;\xd1s8I\x8dC\x0fH\x83\xe0\xf0H\x83\xf8 r\x1aH\x8dA\xf0\x0f\x1fD\x00\x00L\x03B\x08L\x03J\x18H\x83\xc2 H;\xd0r\xefH;\xd1s\x04L\x8bj\x08K\x8d\x04\x08L\x03\xe8I\x83\xc3(I\x8b\xc5H\xc1\xe8\x0cA\xb8ScPC\xb9\x00\x02\x00\x00I\x8d\x04\x83H\x8b\xd0H\x89D$XL\x8b\x15\x1eA\x04\x00\xe8A\xb0Y\xfeH\x8b\xf0H\x85\xc0\x0f\x84\x8c\x00\x00\x00L\x8bD$X3\xd2H\x8b\xc8\xe8\xf6\x1a\x01\x00A\x8bL$\x18H\x8bT$H\x89N\x10H\x8dN\x18L\x89n\x08E\x8bD$\x18\xe8\x17\x18\x01\x00I\x8b\x8ex\x04\x00\x00H\x8b\x81\x18\x01\x00\x00H\x89\x06H\x89\xb1\x18\x01\x00\x00\xebD\xa8\x02t@I\x8b\x96x\x04\x00\x00H\x81\xc2\x18\x01\x00\x00H\x8b
H\x85\xc9t*M\x8b\x02H\x8b\x01L;A\x18t\rH\x8b\xd1H\x8b\xc8H\x85\xc0u\xec\xeb\x11H\x89\x023\xd2L\x8b\x15\x9e@\x04\x00\xe8\x89\xafY\xfeI\x8b\x8ex\x04\x00\x00H\x8b\x89 \x01\x00\x00L\x8b\x15\x14C\x04\x00\xe8\xef\x01\xe8\xfd\xe9\x94\x00\x00\x00L\x8b\xc3H\x8b\xd7I\x8b\xcf\xe8,\xd1\x02\x00\xe9h\x01\x00\x00L\x8b\xc3H\x8b\xd7I\x8b\xcf\xe8y\xcf\x02\x00\xe9U\x01\x00\x00H\x8b\xd7I\x8b\xcf\xe8}(\x05\x00\xe9E\x01\x00\x00L\x8b\xcbL\x8dE H\x8b\xd7I\x8b\xcf\xe8\x8a\xd3\xff\xff\xe9.\x01\x00\x00'

AES key:

HMAC key:

Position: 0x15d8788a
Header: 0000beef
Datasize: 0000b875
Raw key:  0600beef000047f00000c875060050f0
 aeskey:  e7fcb20b0d51b984fba68b15d5a3ad5b
 hmackey: 389a12e940bb43d9879d21324bfca49a
charset: 0000
charset_oem: f085
bid: 1876 6262
pid: 60090f0 100700400
port: 0
flags: a5
Field: b'\xf4\x00\x004v\x06\x00\xb0\xf4\x00\x00\x9e\xf5\x00\x00lv\x06\x00\x9e\xf5\x00\x00S\xf8\x00\x00\x84v\x06\x00S\xf8\x00\x00m\xf8\x00\x00\x98v\x06\x00\x80\xf8\x00\x00t\xfd\x00\x00\xe0v\x06\x00\x80\xfd\x00\x00\xf9\xfd\x00\x00\xbc\xac\x06\x00\x00\xfe\x00\x00/\xfe\x00\x00\x0cw\x06\x00/\xfe\x00\x00T\xff\x00\x00\x1cw\x06\x00T\xff\x00\x00c\xff\x00\x008w\x06\x00c\xff\x00\x00^\x00\x01\x00Lw\x06\x00d\x00\x01\x00\xa6\x01\x01\x00\xa8w\x06\x00\xb0\x01\x01\x00\xce\x01\x01\x00\xd0w\x06\x00\xce\x01\x01\x00\xaa\x02\x01\x00\xdcw\x06\x00\xaa\x02\x01\x00"\x04\x01\x00\xfcw\x06\x00"\x04\x01\x00>\x04\x01\x00\x10x\x06\x00>\x04\x01\x00?\x04\x01\x00$x\x06\x00?\x04\x01\x004\x05\x01\x004x\x06\x00@\x05\x01\x00\x8b'
Field: b'\x01\x00\xccx\x06\x00\xa0'
Field: b'\x01\x00n\r\x01\x00\x04y\x06\x00t\r\x01\x00"\x0e\x01\x004y\x06\x00(\x0e\x01\x00R\x10\x01\x00Ty\x06\x00`\x10\x01\x00\x13\x12\x01\x00\x84y\x06\x00 \x12\x01\x00U\x12\x01\x00\xb0y\x06\x00`\x12\x01\x00\x8e\x12\x01\x00\xccy\x06\x00\x8e\x12\x01\x00\xb7\x12\x01\x00\xe4y\x06\x00\xb7\x12\x01\x00\xe4\x14\x01\x00\xf8y\x06\x00\xe4\x14\x01\x00\x03\x15\x01\x00\x10z\x06\x00\x03\x15\x01\x00\x04\x15\x01\x00$z\x06\x00\x04\x15\x01\x00\x1e\x15\x01\x004z\x06\x000\x15\x01\x00\x9a\x15\x01\x00\x90z\x06\x00\x9a\x15\x01\x000\x1c\x01\x00\xa8z\x06\x000\x1c\x01\x001\x1c\x01\x00\xccz\x06\x00@\x1c\x01\x00x\x1c\x01\x00\x0c{\x06\x00x\x1c\x01\x00\xdc!\x01\x00({\x06\x00\xdc!\x01\x00\xdd!\x01\x00H{\x06\x00\xdd!\x01\x00\xff!\x01\x00X{\x06\x00\x10"\x01\x00\xec#\x01\x00\xa0{\x06\x00\x00$\x01\x00\xce%\x01\x00\xcc{\x06\x00\xe0%\x01\x00\xa1&\x01\x00\xf8{\x06\x00\xa8&\x01\x00\x06(\x01\x00\x10|\x06\x00\x10(\x01\x00X(\x01\x00<|\x06\x00X(\x01\x00\xf3)\x01\x00P|\x06\x00\xf3)\x01\x00\xf4)\x01\x00l|\x06\x00\xf4)\x01\x00\x92,\x01\x00||\x06\x00\x98,\x01\x00\xca-\x01\x00\xbc|\x06\x00\xd0-\x01\x00\xf3.\x01\x00\xe8|\x06\x00\xfc.\x01\x00P0\x01\x00\xe8|\x06\x00X0\x01\x00\xa81\x01\x00\xe8|\x06\x00\xb01\x01\x00/4\x01\x00\x04}\x06\x0084\x01\x00P5\x01\x000}\x06\x00X5\x01\x00\xd76\x01\x00P}\x06\x00\xe06\x01\x00\xfd6\x01\x00|}\x06\x00\xfd6\x01\x00\xa67\x01\x00\x88}\x06\x00\xa67\x01\x00\x868\x01\x00\xa0}\x06\x00\x868\x01\x00\x978\x01\x00\xb4}\x06\x00\x978\x01\x00\x988\x01\x00\xc8}\x06\x00\x988\x01\x00\xb48\x01\x00\xd8}\x06\x00\xb48\x01\x00\xb58\x01\x00\xf4}\x06\x00\xbc8\x01\x00\xb99\x01\x00T~\x06\x00\xc09\x01\x00\xd9:\x01\x00\x80~\x06\x00\xe0:\x01\x00\xd3<\x01\x00\xac~\x06\x00\xdc<\x01\x00\x95=\x01\x00\xdc~\x06\x00\xa0=\x01\x00\x01?\x01\x00\xf4~\x06\x00\x08?\x01\x00r?\x01\x00\xbc\xac\x06\x00\x80?\x01\x00\xa7@\x01\x00\x1c\x7f\x06\x00\xb0@\x01\x00\xe9@\x01\x00D\x7f\x06\x00\xe9@\x01\x00\x9fA\x01\x00T\x7f\x06\x00\x9fA\x01\x00\xa0A\x01\x00l\x7f\x06\x00\xa0A\x01\x00vB\x01\x00|\x7f\x06\x00\x80B\x01\x00\xafB\x01\x00\xb4\x7f\x06\x00\xafB\x01\x00^G\x01\x00\xcc\x7f\x06\x00^G\x01\x00_G\x01\x00\xf4\x7f\x06\x00_G\x01\x00\x04L\x01\x00\x04\x80\x06\x00\x0cL\x01\x00zM\x01\x00\\x80\x06\x00\x80M\x01\x00\xdaM\x01\x00\x88\x80\x06\x00\xe0M\x01\x00|N\x01\x00\xa4\x80\x06\x00\x84N\x01\x00cO\x01\x00\xc0\x80\x06\x00lO\x01\x00vP\x01\x00\xec\x80\x06\x00|P\x01\x00\x84Q\x01\x00\x18\x81\x06\x00\x8cQ\x01\x00\R\x01\x00\xe8|\x06\x00dR\x01\x00\xe0S'

AES key:

HMAC key:

```

这里的值解密有问题，尝试碰撞，最后通过包103得到

> 对于 Cobalt Strike 4.x 的 Beacon，通过内存直接提取未加密元数据的可能性变得极低了。因为此时已经没有数据头来进行标识了，单纯的 16 字节长序列没有可区分的特征。只能通过在进程内存中找到所有可能的 16 字节长非空序列作为密钥字典，不断尝试解密 C&C 通信，碰撞成功就找到了密钥。

```
\DidierStevensSuite>python cs-parse-traffic.py -k unknown ..\DESKTOP.pcapng > ..\key.txt

\DidierStevensSuite>python cs-extract-key.py -t 0253784ee86d3fc54693bb7ee14f40d64700446a4604ca0054103ba84e1a831d2a369c501e2a2522abdd9f5fe7652a16fd242669f6b10fb52e8b2b032a7ae00f6b25a8cecdffde72dadf1a18c1225f92 ..\pid.6492.dmp
File: ..\pid.6492.dmp
Searching for AES and HMAC keys
Found 2 instance(s) of string sha256\x00
Searching after sha256\x00 string (0x61a44)
AES key position: 0x00068c60
AES Key:  a6f4a04f8a6aa5ff27a5bcdd5ef3b9a7 ...O.j..'...^... 82.200000
HMAC key position: 0x00068c70
HMAC Key: 35d34ac8778482751682514436d71e09
SHA256 raw key: 35d34ac8778482751682514436d71e09:a6f4a04f8a6aa5ff27a5bcdd5ef3b9a7
AES key position: 0x000ffaa7
AES Key:  4df048894c242033c9ff1592a5000048 M.H.L$ 3.......H 89.266667
Searching for raw key
Searching after sha256\x00 string (0x27ee2f4)
Searching for raw key
```

成功解密

```
\DidierStevensSuite>python cs-parse-traffic.py -k 35d34ac8778482751682514436d71e09:a6f4a04f8a6aa5ff27a5bcdd5ef3b9a7 ..\DESKTOP.pcapng

Packet number: 25
HTTP response (for request 6 GET)
Length raw data: 296007
HMAC signature invalid

Packet number: 25
HTTP request 
http://192.168.27.132:12580/TJvI
Length raw data: 296007
HMAC signature invalid

Packet number: 47
HTTP response (for request 44 GET)
Length raw data: 48
Timestamp: 1736753356 20250113-072916
Data size: 12
Command: 32 COMMAND_PS
 Arguments length: 4
 b'\x00\x00\x00\x00'
 MD5: f1d3ff8443297732862df21dc4e57262

Packet number: 47
HTTP request 
http://192.168.27.132:12580/ca
Length raw data: 48
HMAC signature invalid

Packet number: 56
HTTP request POST
http://192.168.27.132:12580/submit.php?id=1389642286
Length raw data: 2532
Counter: 2
Callback: 17 CALLBACK_PROCESS_LIST
* An error occured
'utf-8' codec can't decode byte 0xb9 in position 2150: invalid start byte
Packet number: 83
HTTP response (for request 80 GET)
Length raw data: 48
Timestamp: 1736753476 20250113-073116
Data size: 19
Command: 53 COMMAND_LS
 Arguments length: 11
 b'\xff\xff\xff\xfe\x00\x00\x00\x03.\*'
 MD5: 4a2685ea905daff3380145bc124d7b2b

Packet number: 83
HTTP request 
http://192.168.27.132:12580/ca
Length raw data: 48
HMAC signature invalid

Packet number: 90
HTTP request POST
http://192.168.27.132:12580/submit.php?id=1389642286
Length raw data: 356
Counter: 3
Callback: 22 CALLBACK_PENDING
b'\xff\xff\xff\xfe'
----------------------------------------------------------------------------------------------------
C:\Users\JohnDoe\Desktop\*
D	0	01/13/2025 15:31:07	.
D	0	01/13/2025 15:31:07	..
F	282	01/13/2025 15:19:00	desktop.ini
F	207496	01/13/2025 11:49:56	DumpIt.exe
F	2332	01/13/2025 15:19:01	Microsoft Edge.lnk
F	36	01/13/2025 15:31:02	secret.txt
F	19456	01/13/2025 14:13:11	\xb9\xd8\xd3\xda2025\xc4  \xb2\xbf  \xd6\xbd\xda\xbc\xd9\xc8\xd5  \xb2\xc5\xc5\xb5\xc4\xcd  \xd6\xaa.exe

----------------------------------------------------------------------------------------------------
Extra packet data: b'\x00'

Packet number: 103
HTTP response (for request 100 GET)
Length raw data: 80
Timestamp: 1736753536 20250113-073216
Data size: 46
Command: 78 COMMAND_EXECUTE_JOB
 Command: b'%COMSPEC%'
 Arguments: b' /C type secret.txt'
 Integer: 0

Packet number: 103
HTTP request 
http://192.168.27.132:12580/ca
Length raw data: 80
HMAC signature invalid

Packet number: 110
HTTP request POST
http://192.168.27.132:12580/submit.php?id=1389642286
Length raw data: 84
Counter: 4
Callback: 30 CALLBACK_OUTPUT_OEM
5c1eb2c4-0b85-491f-8d50-4e965b9d8a43

Packet number: 123
HTTP response (for request 120 GET)
Length raw data: 784
Timestamp: 1736753596 20250113-073316
Data size: 755
Command: 77 COMMAND_GETPRIVS
 Arguments length: 747
 b'\x00\x1c\x00\x00\x00\x10SeDebugPrivilege\x00\x00\x00\x0eSeTcbPrivilege\x00\x00\x00\x16SeCreateToke
 MD5: 8b790ecaad62b13b5c2ccb1330abb9d7

Packet number: 123
HTTP request 
http://192.168.27.132:12580/ca
Length raw data: 784
HMAC signature invalid

Packet number: 130
HTTP request POST
http://192.168.27.132:12580/submit.php?id=1389642286
Length raw data: 100
Counter: 5
Callback: 0 CALLBACK_OUTPUT
----------------------------------------------------------------------------------------------------
SeShutdownPrivilege
SeChangeNotifyPrivilege
SeUndockPrivilege

----------------------------------------------------------------------------------------------------

Packet number: 144
HTTP response (for request 141 GET)
Length raw data: 48
Timestamp: 1736753656 20250113-073416
Data size: 8
Command: 27 COMMAND_GETUID
 Arguments length: 0

Packet number: 144
HTTP request 
http://192.168.27.132:12580/ca
Length raw data: 48
HMAC signature invalid

Packet number: 151
HTTP request POST
http://192.168.27.132:12580/submit.php?id=1389642286
Length raw data: 68
Counter: 6
Callback: 16 CALLBACK_TOKEN_GETUID
b'DESKTOP-OKEP6GL\JohnDoe'

Packet number: 169
HTTP response (for request 165 GET)
Length raw data: 3264
Timestamp: 1736753716 20250113-073516
Data size: 3239
Command: 100 COMMAND_INLINE_EXECUTE_OBJECT
 Arguments length: 3231
 b'\x00\x00\x04@\x00\x00\x00\x00\x00\x00\x05\xb2H\x83\xec8L\x8dL$ E3\xc0\xba\x01\x00\x00\x00\xb9\x14\
 MD5: 957b9ec334b8fd09dcc1d5330c5a4edb

Packet number: 169
HTTP request 
http://192.168.27.132:12580/ca
Length raw data: 3264
HMAC signature invalid

Packet number: 176
HTTP request POST
http://192.168.27.132:12580/submit.php?id=1389642286
Length raw data: 68
Counter: 7
Callback: 0 CALLBACK_OUTPUT
----------------------------------------------------------------------------------------------------
getsystem failed.
----------------------------------------------------------------------------------------------------
Extra packet data: b'\x00\x00\x00'

Commands summary:
 27 COMMAND_GETUID: 1
 32 COMMAND_PS: 1
 53 COMMAND_LS: 1
 77 COMMAND_GETPRIVS: 1
 78 COMMAND_EXECUTE_JOB: 1
 100 COMMAND_INLINE_EXECUTE_OBJECT: 1

Callbacks summary:
 0 CALLBACK_OUTPUT: 2
 16 CALLBACK_TOKEN_GETUID: 1
 17 CALLBACK_PROCESS_LIST: 1
 22 CALLBACK_PENDING: 1
 30 CALLBACK_OUTPUT_OEM: 1

```

### 扩展：Cobalt Strike 指令对照表

|  |  |  |  |
| --- | --- | --- | --- |
| **指令名** | **类型** | **用途** | **关联模块** |
| **基础控制指令** |  |  |  |
| `COMMAND_GET_SYSTEM_INFO` | 请求指令 | 获取系统信息（OS版本、主机名、用户名等） | 侦察阶段 |
| `COMMAND_SLEEP` | 请求指令 | 设置Beacon心跳间隔（如 `sleep 60`） | C2通信控制 |
| `COMMAND_CHECKIN` | 回调指令 | Beacon首次注册或重新连接TeamServer | 上线通知 |
| **文件操作** |  |  |  |
| `COMMAND_FILE_BROWSE` | 请求指令 | 列出目标目录文件 | 数据窃取准备 |
| `COMMAND_DOWNLOAD` | 请求指令 | 从目标下载文件到TeamServer | 数据外传 |
| `CALLBACK_FILE_WRITE` | 回调指令 | 向目标写入文件（上传恶意工具） | 投递Payload |
| `COMMAND_FILE_OPEN/CLOSE` | 请求指令 | 打开/关闭文件句柄 | 文件操作控制 |
| **进程操作** |  |  |  |
| `COMMAND_PROCESS_LIST` | 请求指令 | 列出运行中的进程 | 进程发现 |
| `COMMAND_PROCESS_INJECT` | 请求指令 | 注入Shellcode到指定进程（如 `explorer.exe`） | 进程注入 |
| `COMMAND_TOKEN_IMPERSONATE` | 请求指令 | 窃取令牌并模拟用户权限 | 权限提升 |
| **横向移动** |  |  |  |
| `COMMAND_PIVOT_CONNECT` | 请求指令 | 建立内网跳板连接（SMB/WMI） | 横向移动 |
| `COMMAND_PSEXEC` | 请求指令 | 通过PsExec横向扩散 | 横向移动 |
| `COMMAND_SSH_COMMAND` | 请求指令 | 在SSH会话中执行命令 | Linux横向移动 |
| **权限维持** |  |  |  |
| `COMMAND_MAKE_TOKEN` | 请求指令 | 创建新的登录会话令牌 | 黄金票据伪造 |
| `COMMAND_REGISTRY_MODIFY` | 请求指令 | 修改注册表（如 `UseLogonCredential=1`） | WDigest凭据缓存 |
| `COMMAND_PERSISTENCE` | 请求指令 | 设置持久化（计划任务、服务、启动项） | 后门植入 |
| **网络操作** |  |  |  |
| `COMMAND_PORT_SCAN` | 请求指令 | 执行端口扫描（TCP/UDP） | 内网侦察 |
| `COMMAND_NETVIEW` | 请求指令 | 枚举域内主机和共享资源 | 网络拓扑探测 |
| `COMMAND_SOCKS_PROXY` | 请求指令 | 启动SOCKS代理（如 `socks 1080`） | 内网穿透 |
| **交互式会话** |  |  |  |
| `COMMAND_INTERACTIVE_CMD` | 请求指令 | 启动交互式CMD会话 | 实时控制 |
| `COMMAND_POWERSHELL` | 请求指令 | 执行PowerShell命令（无窗口） | 绕过监控 |
| **Mimikatz集成** |  |  |  |
| `COMMAND_CREDENTIALS_DUMP` | 请求指令 | 调用Mimikatz转储凭据（`sekurlsa::logonpasswords`） | 凭据窃取 |
| `COMMAND_KERBEROS_TICKET` | 请求指令 | 导出Kerberos票据（`kerberos::list /export`） | 黄金票据攻击 |
| **日志清理** |  |  |  |
| `COMMAND_CLEAR_EVENTS` | 请求指令 | 清除安全事件日志（`wevtutil cl security`） | 痕迹清除 |
| **自定义模块** |  |  |  |
| `COMMAND_CUSTOM_PSH` | 请求指令 | 执行自定义PowerShell脚本（如内存加载恶意模块） | 无文件攻击 |
| `COMMAND_REFlective_DLL` | 请求指令 | 反射加载DLL（无磁盘写入） | 内存驻留 |

#### 向量结果类型

|  |  |
| --- | --- |
| 指令名称 | 含义 |
| `CALLBACK_OUTPUT` | 标准命令输出。 |
| `CALLBACK_KEYSTROKES` | 键盘记录数据。 |
| `CALLBACK_FILE` | 文件内容返回。 |
| `CALLBACK_SCREENSHOT` | 屏幕截图数据。 |
| `CALLBACK_CLOSE` | 会话关闭通知。 |
| `CALLBACK_READ` | 数据读取完成。 |
| `CALLBACK_CONNECT` | 连接建立通知。 |
| `CALLBACK_PING` | 存活确认响应。 |
| `CALLBACK_FILE_WRITE` | 文件写入完成。 |
| `CALLBACK_FILE_CLOSE` | 文件关闭通知。 |
| `CALLBACK_PIPE_OPEN` | 管道打开通知。 |
| `CALLBACK_PIPE_CLOSE` | 管道关闭通知。 |
| `CALLBACK_PIPE_READ` | 管道数据读取。 |
| `CALLBACK_POST_ERROR` | 错误信息返回。 |
| `CALLBACK_PIPE_PING` | 管道存活确认。 |
| `CALLBACK_TOKEN_STOLEN` | 令牌窃取成功通知。 |
| `CALLBACK_TOKEN_GETUID` | 返回令牌对应的用户身份。 |
| `CALLBACK_PROCESS_LIST` | 返回进程列表。 |
| `CALLBACK_POST_REPLAY_ERROR` | 重放攻击错误（如Kerberos）。 |
| `CALLBACK_PWD` | 返回当前目录路径。 |
| `CALLBACK_JOBS` | 返回后台任务状态。 |
| `CALLBACK_HASHDUMP` | 返回哈希值（如SAM）。 |
| `CALLBACK_PENDING` | 操作挂起中。 |
| `CALLBACK_ACCEPT` | 连接接受通知。 |
| `CALLBACK_NETVIEW` | 返回网络共享信息。 |
| `CALLBACK_PORTSCAN` | 返回端口扫描结果。 |
| `CALLBACK_DEAD` | 会话终止通知。 |
| `CALLBACK_SSH_STATUS` | SSH连接状态返回。 |
| `CALLBACK_CHUNK_ALLOCATE` | 内存块分配通知。 |
| `CALLBACK_CHUNK_SEND` | 内存块数据传输。 |
| `CALLBACK_OUTPUT_OEM` | OEM编码输出。 |
| `CALLBACK_ERROR` | 通用错误信息。 |
| `CALLBACK_OUTPUT_UTF8` | UTF-8编码输出。 |

#### 文件操作指令分类

1. 文件浏览与列表

|  |  |  |  |
| --- | --- | --- | --- |
| 指令名称 | 类型 | 功能描述 | 应用场景 |
| `COMMAND_FILE_BROWSE` | 请求指令 | 列出目标目录下的文件和子目录 | 数据窃取前的信息收集 |
| `COMMAND_LS` | 请求指令 | 同 `FILE_BROWSE`  （别名） | 快速查看目录内容 |
| `CALLBACK_PROCESS_LIST` | 回调指令 | 返回文件列表结果（需配合请求指令） | 接收目录结构数据 |

2. 文件下载（外传数据）

|  |  |  |  |
| --- | --- | --- | --- |
| 指令名称 | 类型 | 功能描述 | 应用场景 |
| `COMMAND_DOWNLOAD` | 请求指令 | 从目标主机下载文件到TeamServer | 窃取敏感文件 |
| `DOWNLOAD_START` | 请求指令 | 初始化下载任务（分块传输） | 大文件分片传输 |
| `DOWNLOAD_WRITE` | 回调指令 | 写入下载的文件数据块 | 接收文件内容 |
| `DOWNLOAD_COMPLETE` | 回调指令 | 通知下载完成 | 结束传输流程 |
| `CALLBACK_FILE` | 回调指令 | 返回下载的文件内容（完整模式） | 直接获取文件 |

3. 文件上传（投递Payload）

|  |  |  |  |
| --- | --- | --- | --- |
| 指令名称 | 类型 | 功能描述 | 应用场景 |
| `COMMAND_UPLOAD` | 请求指令 | 从TeamServer上传文件到目标 | 投递恶意工具或脚本 |
| `COMMAND_UPLOAD_CONTINUE` | 请求指令 | 继续中断的上传任务 | 断点续传 |
| `CALLBACK_FILE_WRITE` | 回调指令 | 向目标主机写入文件数据块 | 分块上传文件内容 |
| `CALLBACK_FILE_CLOSE` | 回调指令 | 关闭文件句柄（上传完成） | 结束上传流程 |

4. 文件操作控制

|  |  |  |  |
| --- | --- | --- | --- |
| 指令名称 | 类型 | 功能描述 | 应用场景 |
| `COMMAND_FILE_OPEN` | 请求指令 | 打开文件句柄（读写权限控制） | 准备读写文件 |
| `COMMAND_FILE_CLOSE` | 请求指令 | 关闭文件句柄 | 释放资源 |
| `COMMAND_RM` | 请求指令 | 删除目标文件或目录 | 清除痕迹 |
| `COMMAND_MKDIR` | 请求指令 | 创建目录 | 搭建恶意文件存储路径 |
| `COMMAND_CP` | 请求指令 | 复制文件 | 备份或扩散文件 |
| `COMMAND_MV` | 请求指令 | 移动/重命名文件 | 隐藏或替换关键文件 |

5. 文件元数据操作

|  |  |  |  |
| --- | --- | --- | --- |
| 指令名称 | 类型 | 功能描述 | 应用场景 |
| `COMMAND_TIMESTOMP` | 请求指令 | 修改文件时间戳（创建/修改时间） | 隐藏活动痕迹 |
| `COMMAND_GET_FILE_ATTR` | 请求指令 | 获取文件属性（如权限、所有者） | 权限探测 |
| `COMMAND_SET_FILE_ATTR` | 请求指令 | 设置文件属性（如只读/隐藏） | 保护恶意文件 |

6. 文件搜索与过滤

|  |  |  |  |
| --- | --- | --- | --- |
| 指令名称 | 类型 | 功能描述 | 应用场景 |
| `COMMAND_FIND_FILE` | 请求指令 | 按名称/扩展名搜索文件 | 定位特定文件（如`.docx`） |
| `COMMAND_GREP` | 请求指令 | 文件内容关键词搜索 | 快速提取敏感信息 |

7. 文件压缩与归档

|  |  |  |  |
| --- | --- | --- | --- |
| 指令名称 | 类型 | 功能描述 | 应用场景 |
| `COMMAND_ZIP` | 请求指令 | 压缩文件或目录 | 减少传输体积 |
| `COMMAND_UNZIP` | 请求指令 | 解压文件 | 释放投递的Payload |
