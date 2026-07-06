# Merlin Agent木马破绽：内存密钥暴露与加密流量破解全解-先知社区

> **来源**: https://xz.aliyun.com/news/18418  
> **文章ID**: 18418

---

## 概述

在上一篇《突破网络限制，Merlin Agent助你轻松搭建跳板网络！》文章中，我们尝试基于Merlin Agent远控木马模拟构建了多层跳板网络。成功构建跳板网络后，笔者就在琢磨：若在实战攻防场景中，我们能够捕获Merlin Agent的加密流量及对被控主机进行临检取证，那接下来我们能不能对加密流量进行解密还原呢？

于是，带着上述疑问，笔者就尝试从加密流量破解的角度对Merlin Agent进行了新的角度研究。

果然，功夫不负有心人，经过笔者的详细剖析，笔者**挖掘发现了Merlin Agent木马内存中存放加密协商后的通信密钥的破绽，可直接从内存dmp文件中快速提取Merlin Agent远控木马加密协商后的通信密钥。**

详细分析研究过程如下：

* 密钥协商过程剖析：Merlin Agent木马默认使用OPAQUE（**非对称密码身份验证密钥交换**）协议进行身份验证，身份验证过程中将使用Merlin Agent木马的psk配置信息作为通信密钥加密通信流量；协商成功后，将使用协商后的密钥加密通信流量；
* OPAQUE认证协议剖析：由于OPAQUE认证协议使用的是非对称算法，因此从通信数据包中是无法解密提取协商后的通信密钥的。进一步对OPAQUE认证协议库代码进行分析，发现**Merlin Agent项目中的OPAQUE认证协议使用的是Ed25519数字签名算法，而Ed25519数组签名算法的签名长度固定为64字节。**
* 密钥协商后的新通信密钥特征：剖析Merlin Agent项目代码，发现**密钥协商后获取的新通信密钥是以字符串方式存放于client.secret变量中的。**
* 加密流量破解初探：编写脚本在内存中匹配64字节长度的字符串，循环测试解密结果，发现基于内存中提取的通信密钥可成功对Merlin Agent木马的加密流量进行正常解密。
* 不同通信环节流量破解实践：基于解密脚本对HTTP上线通信流量、H2C上线通信流量、SMB跳板通信流量、TCP跳板通信流量、UDP跳板通信流量进行解密尝试，发现可正常解密。
* 不同transformers算法组合下的流量破解实践：基于transformers配置信息，组合不同通信加密算法，发现可正常解密。

## 密钥协商过程剖析

为了探究Merlin Agent木马加密流量破解的方法，我们首先需要梳理了解Merlin Agent木马通信的大致流程：

* 身份认证：使用Merlin Agent木马的psk配置信息作为通信密钥加密身份认证过程中的通信流量。
* 加密通信：使用协商后的新通信密钥加密后续正常通信流量。

因此，为了达到加密流量破解的目的，我们首先需要清楚密钥协商过程的具体实现方法。

结合笔者年初《揭秘Merlin Agent木马通信：操作方法与加解密过程一网打尽》文章中的“Merlin Agent通信加密代码逻辑”章节内容，我们可知Merlin Agent加密通信所使用的共享密钥存放于`client.secret`数据中。

`client.secret`数据将在两处被赋值：

* 使用Merlin Agent样本的psk配置信息做SHA256运算，得到预共享密钥；
* 若Merlin Agent样本开启身份认证，则使用OPAQUE协议（**非对称密码身份验证密钥交换**）进行用户认证，获得新的共享密钥；

相关代码截图如下：

![](images/20260326203444-2b00e9cb-2910-1.png)

## OPAQUE认证协议剖析

为了能够详细了解OPAQUE协议的认证过程，笔者尝试对Merlin Agent项目中使用的OPAQUE协议进行了分析，梳理如下：

* Merlin Agent项目中使用`https://github.com/cretz/gopaque`项目（最近一次更新是2020年）作为OPAQUE协议库；
* OPAQUE协议是一个**非对称密码身份验证密钥交换**协议，依赖于密码学中的离散对数问题来保障通信安全；（通俗的话讲：和RSA算法一样无法破解）
* 对`https://github.com/cretz/gopaque`项目进行分析，发现此项目使用了**Ed25519数字签名算法**；
* 对Ed25519数字签名算法进行剖析，发现**Ed25519签名长度固定为64字节**；

Merlin Agent项目使用`https://github.com/cretz/gopaque`作为OPAQUE协议库的代码截图如下：

![](images/20260326203444-2b42a9f6-2910-1.png)

`https://github.com/cretz/gopaque`项目截图如下：

![](images/20260326203445-2b8cccfa-2910-1.png)

网络中关于Ed25519数字签名算法的说明如下：

![](images/20260326203445-2bcc66a4-2910-1.png)

### 固定签名长度

为了验证上述使用`https://github.com/cretz/gopaque`项目生成的密钥长度固定为64字节的问题，笔者尝试基于此项目构建了一个测试脚本，经过多轮验证，确定使用此项目生成的密钥长度确实是64字节。

脚本运行效果如下：

![](images/20260326203446-2c0cf339-2910-1.png)

测试脚本内容如下：

```
package main

import (
    "fmt"
    "github.com/cretz/gopaque/gopaque"
    "go.dedis.ch/kyber/v3"
)

func pubKey(c gopaque.Crypto, priv kyber.Scalar) kyber.Point {
    return c.Point().Mul(priv, nil)
}

func getSharedSecret(userID []byte) string {
    crypto := gopaque.CryptoDefault
    userPriv, serverPriv := crypto.NewKey(nil), crypto.NewKey(nil)
    userPub, serverPub := pubKey(crypto, userPriv), pubKey(crypto, serverPriv)
    // Do the exchange
    userKex, serverKex := gopaque.NewKeyExchangeSigma(crypto), gopaque.NewKeyExchangeSigma(crypto)
    ke1, _ := userKex.UserKeyExchange1()
    ke2, _ := serverKex.ServerKeyExchange2(ke1, &gopaque.KeyExchangeInfo{
        UserID:         userID,
        MyPrivateKey:   serverPriv,
        TheirPublicKey: userPub,
    })
    ke3, _ := userKex.UserKeyExchange3(ke2, &gopaque.KeyExchangeInfo{
        UserID:         userID,
        MyPrivateKey:   userPriv,
        TheirPublicKey: serverPub,
    })
    _ = serverKex.ServerKeyExchange4(ke3)
    return fmt.Sprintf("%+v", serverKex.SharedSecret)
}

func main() {
    userIDs := []string{}
    userIDs = append(userIDs, "1")
    userIDs = append(userIDs, "22")
    userIDs = append(userIDs, "333")
    userIDs = append(userIDs, "4444")
    userIDs = append(userIDs, "55555")
    userIDs = append(userIDs, "4cd6b2b4a9900778cc733f0e810932480af25999db2a43759b451ad7b635296e4cd6b2b4a99007")
    for _, userID := range userIDs {
        key := getSharedSecret([]byte(userID))
        fmt.Println("userID:", userID, " SharedSecret:", key, " len:", len(key))
    }
}
```

## 密钥协商后的新通信密钥特征

通过对Merlin Agent使用的`https://github.com/cretz/gopaque`项目进行剖析，我们可知Merlin Agent项目中生成的共享密钥均为64字节。

进一步对Merlin Agent项目进行分析，笔者发现了一段有意思的代码：

**通信共享密钥是以字符串方式存放于client.secret变量中的！**

**于是，笔者开始大胆猜想：若直接在内存中匹配64字节的字符串数据，是否就能找到此共享密钥？**

相关代码截图如下：

![](images/20260326203446-2c4988cc-2910-1.png)

![](images/20260326203446-2c8c0a06-2910-1.png)

动态调试截图如下：

![](images/20260326203447-2cca1eb1-2910-1.png)

## 加密流量破解初探

为了验证上述思路，笔者尝试构建了一套自动化解密脚本，脚本大致逻辑如下：

* 提取加密流量载荷：基于手动或WireShark中的导出对象功能提取加密流量载荷；
* 身份认证通信解密：使用psk配置信息生成预共享通信密钥，循环解密流量载荷，遇到无法解密的载荷时，则进入【后续加密通信解密】环节；
* 后续加密通信解密：使用ProcessHacker或System Informer工具提取Merlin Agent木马运行过程中的内存dmp文件；
* 后续加密通信解密：使用正则表达式匹配内存dmp文件中的64字节字符串数据；
* 后续加密通信解密：基于内存中提取的64字节字符串数据循环进行解密尝试，若解密成功，则将其作为新通信密钥；
* 后续加密通信解密：使用`https://github.com/Ne0nd0g/merlin-agent`项目中的transformers库源码构建通信解密函数，配合新通信密钥对后续通信数据进行全解密；

自动化解密脚本运行效果如下：

![](images/20260326203447-2d1b9a6a-2910-1.png)

### 代码实现

代码结构如下：

![](images/20260326203448-2d53ee6e-2910-1.png)

其中，transformers库即为`https://github.com/Ne0nd0g/merlin-agent`项目中的部分源码，相关截图如下：

![](images/20260326203448-2d96aa46-2910-1.png)

* main.go

```
package main

import (
    "awesomeProject4/merlin_xx"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "io/ioutil"
    "os"
    "regexp"
    "strings"
)

func main() {
    dumpfile := "C:\Users\admin\Desktop\merlinAgent-Windows-x64.exe_2025-07-01_20-20-01.dmp"
    pcap_sessiondata := "C:\Users\admin\Desktop\1.txt"

    //从样本配置信息中提取transforms、psk信息
    merlin_transforms := "jwe,gob-base"
    datas := merlin_xx.FileToSlice(pcap_sessiondata)
    merlin_psk := "merlin"

    //初始化密钥，用于身份认证时通信加密使用，身份认证后则使用新的密钥
    merlin_pre_secret, _ := hex.DecodeString(HashData_sha256([]byte(merlin_psk)))
    datas2 := []string{}
    //解密身份认证前的数据
    for i, data := range datas {
        if DecryptData(data, merlin_transforms, string(merlin_pre_secret)) {
            continue
        } else {
            datas2 = append(datas2, datas[i:]...)
            break
        }
    }

    //查找身份认证后的新通信密钥
    merlin_secret := search_secretkey(dumpfile, datas2[0], merlin_transforms)
    fmt.Println()
    fmt.Println("secret_key:", merlin_secret)
    fmt.Println()
    //解密后续数据
    if merlin_secret != "" {
        for _, data := range datas2 {
            DecryptData(data, merlin_transforms, merlin_secret)
        }
    }
}

func search_secretkey(dumpfile string, data string, merlin_transforms string) (merlin_secret string) {
    // 内存中匹配64个字符的十六进制字符串
    data_dmp, _ := ioutil.ReadFile(dumpfile)
    re, err := regexp.Compile(`[0-9a-fA-F]{64}`)
    if err != nil {
        fmt.Println("正则表达式编译错误:", err)
        os.Exit(1)
    }

    matches := re.FindAllString(string(data_dmp), -1)
    matches_deduplication := merlin_xx.DedupStrings(matches)
    for _, match := range matches_deduplication {
        secret := []byte(match)
        transforms := strings.Split(merlin_transforms, ",")
        ret, err := merlin_xx.DeconstructMessages([]byte(data), secret, transforms)
        if err != nil {
            continue
        }
        str_ID := fmt.Sprintf("%+v", ret.ID)
        if str_ID != "00000000-0000-0000-0000-000000000000" {
            merlin_secret = string(secret)
            return merlin_secret
        }
    }
    return merlin_secret
}

func DecryptData(sessiondata string, merlin_transforms string, merlin_secret string) bool {
    secret := []byte(merlin_secret)
    transforms := strings.Split(merlin_transforms, ",")
    ret, err := merlin_xx.DeconstructMessages([]byte(sessiondata), secret, transforms)
    if err != nil {
        return false
    }
    fmt.Printf("ID:%+v\tType:%+v\tPayload:%+v\tDelegates:%+v
",
        ret.ID, ret.Type, ret.Payload, ret.Delegates)
    return true
}

func HashData_sha256(data []byte) string {
    // 创建 SHA256 哈希函数
    hash := sha256.New()

    // 将字符串转换为字节数组，并计算哈希值
    hash.Write(data)
    hashValue := hash.Sum(nil)

    // 将哈希值转换为十六进制字符串
    hashString := hex.EncodeToString(hashValue)
    return hashString
}
```

* merlin\_xx/merlin\_xx.go

```
package merlin_xx

import (
    transformer "awesomeProject4/merlin_xx/transformers"
    "awesomeProject4/merlin_xx/transformers/encoders/base64"
    "awesomeProject4/merlin_xx/transformers/encoders/gob"
    "awesomeProject4/merlin_xx/transformers/encoders/hex"
    "awesomeProject4/merlin_xx/transformers/encrypters/aes"
    "awesomeProject4/merlin_xx/transformers/encrypters/jwe"
    "awesomeProject4/merlin_xx/transformers/encrypters/rc4"
    "awesomeProject4/merlin_xx/transformers/encrypters/xor"
    "bufio"
    gogob "encoding/gob"
    "fmt"
    messages "github.com/Ne0nd0g/merlin-message"
    "github.com/Ne0nd0g/merlin-message/jobs"
    "github.com/Ne0nd0g/merlin-message/opaque"
    "os"
    "strings"
)

func DeconstructMessages(data []byte, secret []byte, transforms []string) (messages.Base, error) {
    var t transformer.Transformer

    gogob.Register(opaque.Opaque{})
    gogob.Register([]jobs.Job{})
    gogob.Register(jobs.Command{})
    gogob.Register(jobs.Shellcode{})
    gogob.Register(jobs.FileTransfer{})
    gogob.Register(jobs.Results{})
    gogob.Register(jobs.Socks{})

    for _, transform := range transforms {
        switch strings.ToLower(transform) {
        case "aes":
            t = aes.NewEncrypter()
        case "base64-byte":
            t = base64.NewEncoder(base64.BYTE)
        case "base64-string":
            t = base64.NewEncoder(base64.STRING)
        case "gob-base":
            t = gob.NewEncoder(gob.BASE)
        case "gob-string":
            t = gob.NewEncoder(gob.STRING)
        case "hex-byte":
            t = hex.NewEncoder(hex.BYTE)
        case "hex-string":
            t = hex.NewEncoder(hex.STRING)
        case "jwe":
            t = jwe.NewEncrypter()
        case "rc4":
            t = rc4.NewEncrypter()
        case "xor":
            t = xor.NewEncrypter()
        default:
            err := fmt.Errorf("unhandled transform type: %s", transform)
            if err != nil {
                return messages.Base{}, err
            }
        }

        ret, err := t.Deconstruct(data, secret)
        if err != nil {
            return messages.Base{}, fmt.Errorf("unable to deconstruct with Agent's secret, retrying with PSK")
        }

        switch ret.(type) {
        case []uint8:
            data = ret.([]byte)
        case string:
            data = []byte(ret.(string))
        case messages.Base:
            //fmt.Printf("ID:%+v\tType:%+v\tPayload:%+v\tDelegates:%+v
",
            //	ret.(messages.Base).ID, ret.(messages.Base).Type, ret.(messages.Base).Payload, ret.(messages.Base).Delegates)
            return ret.(messages.Base), nil
        default:
            return messages.Base{}, fmt.Errorf("unhandled data type for Deconstruct()")
        }
    }
    return messages.Base{}, fmt.Errorf("Deconstruct Messages Error")
}

func FileToSlice(file string) []string {
    fil, _ := os.Open(file)
    defer fil.Close()
    var lines []string
    scanner := bufio.NewScanner(fil)
    for scanner.Scan() {
        lines = append(lines, scanner.Text())
    }
    return lines
}

func DedupStrings(input []string) []string {
    // 使用 map 记录已出现的字符串
    seen := make(map[string]struct{})
    // 结果切片
    result := []string{}

    for _, s := range input {
        // 如果字符串未出现过，添加到结果
        if _, exists := seen[s]; !exists {
            seen[s] = struct{}{}
            result = append(result, s)
        }
    }
    return result
}
```

## 不同通信环节流量破解实践

基于笔者前期关于Merlin Agent的文章，我们可知Merlin Agent木马通信过程中，可构建多种不同通信环节（上线通信、跳板通信，代理通信）。

为了测试上述流量破解方法是否适用于不同通信环节，笔者对上线通信过程、跳板通信过程的流量进行了流量破解实践：

* 上线通信过程：默认transformers为jwe,gob-base

* 笔者挑选了无TLS通信的HTTP、H2C通信协议作为测试案例

* 跳板通信过程：默认transformers为jwe,gob-base
* **上述流量破解方法适用于上线通信、跳板通信过程中生成的加密流量。**

### HTTP上线通信解密

尝试对HTTP上线通信进行解密，解密效果如下：

![](images/20260326203447-2d1b9a6a-2910-1.png)

HTTP上线通信数据包截图如下：

![](images/20260326203449-2de08e03-2910-1.png)

使用WireShark导出HTTP通信载荷内容如下：

![](images/20260326203449-2e1e5deb-2910-1.png)

![](images/20260326203449-2e5be4ff-2910-1.png)

木马进程内存中存放的通信密钥截图如下：

![](images/20260326203450-2ea2e6f9-2910-1.png)

![](images/20260326203450-2ede2e56-2910-1.png)

### H2C上线通信解密

尝试对H2C上线通信进行解密，解密效果如下：

![](images/20260326203451-2f2d3fa5-2910-1.png)

H2C上线通信数据包截图如下：

![](images/20260326203451-2f78ff4a-2910-1.png)

使用WireShark导出H2C通信载荷内容如下：

![](images/20260326203452-2fb9b432-2910-1.png)

木马进程内存中存放的通信密钥截图如下：

![](images/20260326203452-2ff3a05b-2910-1.png)

![](images/20260326203452-302bda8b-2910-1.png)

### SMB跳板通信解密

尝试对SMB跳板通信进行解密，解密效果如下：

![](images/20260326203453-307bb55a-2910-1.png)

SMB跳板通信数据包截图如下：

![](images/20260326203454-30d08817-2910-1.png)

手动提取SMB通信载荷内容如下：

![](images/20260326203454-3127e426-2910-1.png)

木马进程内存中存放的通信密钥截图如下：

![](images/20260326203455-3170d2f8-2910-1.png)

![](images/20260326203455-31a9829e-2910-1.png)

### TCP跳板通信解密

尝试对TCP跳板通信进行解密，解密效果如下：

![](images/20260326203455-31f67725-2910-1.png)

TCP跳板通信数据包截图如下：

![](images/20260326203456-3245b45e-2910-1.png)

手动提取TCP通信载荷内容如下：

![](images/20260326203457-32987b1b-2910-1.png)

木马进程内存中存放的通信密钥截图如下：

![](images/20260326203457-32db81a9-2910-1.png)

![](images/20260326203457-3315d589-2910-1.png)

### UDP跳板通信解密

尝试对UDP跳板通信进行解密，解密效果如下：

![](images/20260326203458-3367ce1e-2910-1.png)

UDP跳板通信数据包截图如下：

![](images/20260326203458-33c11aa7-2910-1.png)

手动提取UDP通信载荷内容如下：

![](images/20260326203459-34158897-2910-1.png)

木马进程内存中存放的通信密钥截图如下：

![](images/20260326203459-3456ffc7-2910-1.png)

![](images/20260326203500-34913d35-2910-1.png)

## 不同transformers算法组合下的流量破解实践

在上一个章节中，由于使用的默认transformers配置jwe,gob-base，**因此其上线通信和跳板通信的流量载荷格式基本相同（例如：载荷字符串均以eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIiwicDJjIjozMDAwLCJwMnMiOiJ字符串开头）**。

那是否Merlin Agent的流量都是上述那种格式呢？不是的，Merlin Agent还支持根据配置不同transformers算法组合。

因此，为了更全面的展示Merlin Agent的流量格式及测试上述流量破解方法是否适用于不同transformers算法组合，笔者又对不同transformers算法组合下的上线通信过程、跳板通信过程的流量进行了流量破解实践，测试发现：

* 不同transformers算法组合下的通信流量格式均不相同
* **上述流量破解方法适用于不同transformers算法组合下的上线通信、跳板通信过程中生成的加密流量。**

备注：这里只展示通信流量格式对比截图

### aes,gob-base（HTTP）

![](images/20260326203500-34d1512f-2910-1.png)

### aes,gob-base（SMB）

![](images/20260326203501-351767c0-2910-1.png)

### aes,gob-base（TCP）

![](images/20260326203501-355dbf88-2910-1.png)

### aes,gob-base（UDP）

![](images/20260326203502-35ad9900-2910-1.png)

### base64-string,gob-base（HTTP）

![](images/20260326203502-35fc6dd3-2910-1.png)

### hex-byte,gob-base（HTTP）

![](images/20260326203503-365179c1-2910-1.png)

### hex-string,gob-base（HTTP）

![](images/20260326203503-36a8993a-2910-1.png)

### gob-string,gob-base（HTTP）

![](images/20260326203504-36ec1458-2910-1.png)

### rc4,gob-base（HTTP）

![](images/20260326203504-37379bf0-2910-1.png)

### xor,gob-base（HTTP）

![](images/20260326203505-378170ad-2910-1.png)
