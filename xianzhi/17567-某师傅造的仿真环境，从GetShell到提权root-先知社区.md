# 某师傅造的仿真环境，从GetShell到提权root-先知社区

> **来源**: https://xz.aliyun.com/news/17567  
> **文章ID**: 17567

---

## 某师傅造的仿真环境，从GetShell到提权root

### 0x00 文章背景

这是一个周五，正好没啥事干，发现群里有条消息，咦，是个靶场来的，看他的介绍来看似乎有点意思。为了防止涌入太多人我还是码一下，后面大家看到的没打码地址，是我在本地改了host来的，懒得一直打码了：

![1743312841969.png](images/20250403110140-f76199cb-1037-1.png)

那么那么那么，话不多少直接开干。

### 0x01 信息收集

既然是个仿真靶机，而且还会重置，那么八成是个Docker环境，一般扫端口没什么意义的。所以我们直接先扫目录，看是否能获取到一些敏感文件。打开页面如下，有个登录功能：

![image.png](images/20250403110142-f81b1e9c-1037-1.png)

不管他，直接先扫描目录。扫描后得到这些内容，我们逐个访问下：

![image.png](images/20250403110142-f8aebe29-1037-1.png)

settings.php与uoload.php在访问后，均跳转至登录页。没有直接报404，那么推测需要登录后台才能访问：

![image.png](images/20250403110143-f90854ae-1037-1.png)

database.sql可以直接下载，里面有两个用户的密文，密码是用的php的password\_hash()函数进行的加密，这个加密是不可逆的，只能进行碰撞：

![image.png](images/20250403110144-f953f1db-1037-1.png)

### 0x02 爆破密文

用cmd5查了一下这串密文，我焯，是有记录的：

![image.png](images/20250403110144-f9a49101-1037-1.png)

但是……嘻嘻，我没有会员，我只能用hashcat爆破了。这里咱们最好是可以获取到密文类型，这样用hashcat指定密文类型爆破，速度会更快：

<https://www.tunnelsup.com/hash-analyzer/>

![image.png](images/20250403110146-fa8107d1-1037-1.png)

啊？居然没识别到，不应该啊，毕竟下面都有：

![image.png](images/20250403110148-fbb108d2-1037-1.png)

无所谓哈，其实我知道这是什么类型，在hashcat wiki搜一下：

<https://hashcat.net/wiki/doku.php?id=example%20hashes>

![image.png](images/20250403110149-fc8cca64-1037-1.png)

那么编号是3200，将密文保存到txt，这是我用的字典：

<https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt>

hashcat指定密文类型、密文文件以及字典文件，开爆：

![image.png](images/20250403110150-fd20996a-1037-1.png)

大概，爆了几分钟的样子，已经出来了：

![image.png](images/20250403110151-fd8419d1-1037-1.png)

### 0x03 垂直越权

通过爆破出来的密文，成功登录后台，但是没什么功能：

![image.png](images/20250403110152-fe0e40f3-1037-1.png)

这个发布文章也是，没有利用点，目前通篇无SQL注入：

![image.png](images/20250403110152-fea0fbbe-1037-1.png)

还记得我们之前扫描到的upload与settings吗？尝试访问一下：

![image.png](images/20250403110153-ff0f8dbf-1037-1.png)

还是一样的，重定向到登录页。那说明需要越权，看下Cookie里面有没有东西，没有的话，我们就只能抓包再看看参数有没有点可以尝试了：

![image.png](images/20250403110154-ff8feb1e-1037-1.png)

Auth里面有一串base64编码后的内容，解码一下看看：

![image.png](images/20250403110155-ffff25af-1037-1.png)

我好像已经知道了，我们把它改成admin重新base64编码然后替换Auth的值：

![image.png](images/img_17567_016.png)

![image.png](images/20250403110156-00747210-1038-1.png)

重新访问upload.php，直接舒服了捏：

![image.png](images/20250403110156-00f52068-1038-1.png)

### 0x04 上传绕过

我们尝试上传一个包含php代码的png文件，然后bp拦截数据包，重新改回php后缀，看看能不能直接上去：

![image.png](images/20250403110157-01818c6e-1038-1.png)

啊？图片文件不能包含PHP代码：

![image.png](images/20250403110158-0227ae8b-1038-1.png)

这个应该不难，一般情况下，php的常见写法是这样的：

![image.png](images/20250403110159-028c7c09-1038-1.png)

其实php有好几种写法，这里应该是检测了php常规写法的格式：

![image.png](images/20250403110200-02e06864-1038-1.png)

我这里用的长标签来尝试，直接传：

![image.png](images/20250403110200-032c7eaf-1038-1.png)

![image.png](images/20250403110201-03a93dcf-1038-1.png)

OK上去了，舒服呀：

![image.png](images/20250403110202-045036e3-1038-1.png)

没有直接返回路径，查看源代码，发现了提示：

![image.png](images/20250403110203-04cffad8-1038-1.png)

### 0x05 获取路径

根据他这个提示，我原本以为格式应该是这样的：

![image.png](images/20250403110204-0551e017-1038-1.png)

这里我弄了大半个小时没出来，我终于忍不住了：

![image.png](images/20250403110204-05cad66c-1038-1.png)

你自己看看这是一个意思吗？那么应该是这样的：

![image.png](images/20250403110205-064c9589-1038-1.png)

我现在要传的文件，是61字节：

![image.png](images/20250403110206-0693ee05-1038-1.png)

不说了，直接上传，然后基于路径提示进行md5加密：

![image.png](images/20250403110207-070f05f0-1038-1.png)

![image.png](images/20250403110207-07907d25-1038-1.png)

取密文前10位，然后拼接到日期后面进行访问：

![image.png](images/20250403110208-07e7119d-1038-1.png)

接下来，把代码内容换成一句话木马再次上传：

![image.png](images/20250403110209-08660ccb-1038-1.png)

连接马子，成功成功，没毛病：

![image.png](images/20250403110210-08e49820-1038-1.png)

### 0x06 权限提升

马子已经连上了，不过是www权限：

![image.png](images/20250403110210-09487d37-1038-1.png)

通过搜索发现了flag，但是没权限读取：

![image.png](images/20250403110211-09aac5db-1038-1.png)

那就是要提权了，可以看看内核版本，搜一下有没有漏洞。我搜了，内核是没有洞的，那么我们可以搜索一下，看看有没有特权模式的文件，用特权文件来提权：

find / -perm -4000 -type f -exec ls -l {} \;

![image.png](images/20250403110212-0a318742-1038-1.png)

上面这些带S的文件，都具有SUID特权，且文件所有者为root用户，那么大概率可以用来提权到root权限：

![image.png](images/20250403110213-0aa788a1-1038-1.png)

这里有一个注意点哈，要执行/bin/bash并返回结果，需要用交互式shell才能执行。而目前我们使用的哥斯拉提供的命令执行，只是一个单命令执行的模式，就是你执行一次命令，他返回一次结果，所以目前在哥斯拉中是执行不了/bin/bash的：

![image.png](images/20250403110213-0b039ee5-1038-1.png)

![image.png](images/20250403110214-0b532188-1038-1.png)

但是，可以利用哥斯拉的RealCmd开启伪交互式Shell：

![image.png](images/20250403110214-0bb31918-1038-1.png)

然后，在本机使用netccat连接，即可获取伪交互式shell：

![image.png](images/20250403110215-0c1d37b9-1038-1.png)

至此，下机！感谢师傅的这个环境，还算是比较贴近真是系统的，因为这些漏洞，我基本都遇见过。
