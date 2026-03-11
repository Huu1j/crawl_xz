# Burpsuite 特征检测对抗-先知社区

> **来源**: https://xz.aliyun.com/news/17246  
> **文章ID**: 17246

---

​ BurpSuite 是一款广泛使用的 web 应用程序安全测试工具。然而，越来越多的站点、应用程序、安全设备开始部署检测机制，以识别和阻止通过Burp的流量，这种情况导致我们在进行测试时无法正常抓包，从而影响整个测试过程，所以本文主要研究burp的常见特征以及绕过检测的隐藏方式。

# HTTP特征

​ 当使用BurpSuite时，经常会访问`http://burp`和`http://burpsuite`这类页面。这些页面主要用于导出证书，当证书导入到浏览器后就不再有实际作用。然而，这些访问行为也成为了BurpSuite的典型流量特征之一。

## 证书页

​ 写个demo，模拟下检测过程

![image.png](images/f0f78f0f-4351-375a-ab31-bd046b6df598)

当攻击者访问index时，如果检测到burp流量特征，则直接跳转到check页面，防止进一步请求。这里使用的是iframe标签，不受跨域请求限制，除此外还有：

* img

favicon.ico在`resources/Media/`路径下，删除即可，但请求后仍会返回错误页回显burp特征

```
<img src="http://burp/favicon.ico" onload="window.location.href='/hack'" onerror="console.log('无法访问目标主机')">
```

* link

```
<link rel="stylesheet" href="http://burp/" onload="window.location.href='/hack'" onerror="console.log('无法访问目标主机')">
```

* script

```
<script src="http://burp/test.js" onload="window.location.href='/hack'" onerror="console.log('无法访问目标主机')"></script>
```

### 检测绕过

1、关闭`http://burp`代理

![image.png](images/79827b9a-1d2d-3013-a91e-b137b02e9f5e)

2、设置burp主机名不走代理

![image.png](images/650f015d-bb95-30af-bd05-30d25ae0c6e8)

## 报错页

​ 即使关闭`http://burp`后，通过报错页仍能显示burp特征

![image.png](images/6d1ea3d9-aeba-3b71-bc77-45c4e82c0ce5)

### 检测绕过

关闭报错在浏览器中显示即可

![image.png](images/1027cbe5-86f7-385b-b22f-0eaf4568885b)

# WebSocket请求头检测

## Sec-WebSocket-Extensions

​ Sec-WebSocket-Extensions是用于在 WebSocket 连接期间协商和传输 WebSocket 扩展的HTTP标头，当发起websocket连接时，会在 HTTP 请求中添加 `Sec-WebSocket-Extensions` 请求头，用于声明并协商使用的 WebSocket 扩展。而当websocket连接经过burp代理后会将其删除，因此这也便是明显特征之一。

开启burp代理时

![image.png](images/a81836c4-ce0b-33d8-ba84-d5c1164ca2c0)

关闭burp代理后

![image.png](images/d296ad12-e29e-3bb9-9139-e597d97a038f)

通过建立websocket连接，查看请求包中是否存在`Sec-WebSocket-Extensions`便可判断是否使用burp代理

### 检测绕过

​ 是否Sec-WebSocket-Extensions请求头是通过burp的`Strip Sec-WebSocket-Extensions headers in incoming requests`设置选项决定的。默认情况下,Burp 删除此标头以减少使用扩展名的机会.如果服务器要求特定的扩展名,则可取消选中此选项.

![image.png](images/9e2c0101-6b6c-346e-85ec-ae1e6d8909c5)

此时开启burp代理，进行抓包，Sec-WebSocket-Extensions请求头仍然存在

![image.png](images/c153d80a-148c-3e9c-a519-bfb2f17440a3)

# TLS指纹

​ 许多服务器使用 TLS 指纹技术来识别和检测客户端的特性。TLS 指纹包括客户端发送的 TLS 握手消息中的一系列参数，如：TLS 版本、加密套件、扩展等。通过抓包便可直观的看到这些信息：

![image.png](images/6a74a822-e635-3c0b-bedd-7884f1c5a5f8)

burp默认使用所有Cipher Suites，因此会有比较明显的特征

![image.png](images/ee0f99e6-ad69-36c8-a693-ca9b76940c64)

### 检测绕过

1、添加删除几个burp的Cipher套件

![image.png](images/dcd2e75e-45fa-313c-ac07-444e34d5b603)

2、使用burp插件：[burp-awesome-tls](https://github.com/sleeyax/burp-awesome-tls)

​ 该扩展可劫持 Burp 的 HTTP 和 TLS 堆栈，让您可以欺骗任何浏览器的 TLS 指纹 (JA3)。它增强了 Burp Suite 的功能，同时降低了各种 WAF（如 CloudFlare、PerimeterX、Akamai、DataDome 等）识别指纹的可能性。

可以通过[ja3](https://github.com/salesforce/ja3)工具查看下使用前后差异，ja3的主要原理是将TLS 握手时客户端发送的 Client Hello 里面的 Version + Cipher Suites + Extensions 提取出来进行MD5计算

```
python ja3.py burp.pcapng
```

使用前：

![image.png](images/f8c11faf-7f57-3656-9948-067840097d88)

使用后：

可以看到大部分ip都变为了ipv6的形式，并且hash从`8bd06f4341a65d44a68bd2cef7cbedc6`变成了`cd08e31494f9531f560d64c695473da9`

![image.png](images/5f023b07-64c4-39af-8c44-d2e0a49c2edc)

从前后数据包对比也不难看出

![image.png](images/db7e0880-e962-3ed4-b5ad-6d46348c46b1)
