# Gophish中转&Ewomail邮件服务器搭建与使用教程-先知社区

> **来源**: https://xz.aliyun.com/news/18293  
> **文章ID**: 18293

---

# 零.平台搭建

## 0.1.Ewomail邮件服务器搭建

```
参考链接：
http://doc.ewomail.com/docs/ewomail/install
https://blog.csdn.net/qq_41692307/article/details/88318365
```

部署前准备：

```
1、解决yum源的问题
https://www.qolome.com/system/centos8-yum-dnf.html

2、需要centos8.*版本
最新更新：2025年6月11日CentOS 7.7.1908 64bit成功 至少2核2G
```

### 0.1.0.Ewomail部署

**1.关闭selinux**

```
vi /etc/sysconfig/selinux
SELINUX=enforcing 改为 SELINUX=disabled
```

![m_9ba76510d0d3fd48064dd1d07dab241c_r.png](images/img_18293_000.png)

**2、检查swap**

如果没启动swap，这会导致EwoMail的防病毒组件不能启动，所以在安装前先检查swap是否已经启动，如已启动可跳过该步骤。

```
查看swap
free -m
```

如果swap位置都显示是0，那么系统还没创建swap  
![m_4179b6b847297e1672d5222e4bd87831_r.png](images/img_18293_001.png)

**3、创建swap分区（内存超过2G，可不配置）**

创建1G的swap，可以根据你的服务器配置来调整大小

```
dd if=/dev/zero of=/mnt/swap bs=1M count=1024  
```

设置交换分区文件

```
mkswap /mnt/swap
```

启动swap

```
swapon /mnt/swap
```

设置开机时自启用 swap 分区

```
需要修改文件 /etc/fstab 中的 swap 行，添加
/mnt/swap swap swap defaults 0 0
```

![m_baaf4a449aedf39b1faf3f17031472bb_r.png](images/img_18293_002.png)

**4、部署**

```
常规部署会出问题直接访问以下地址，将域名写为自己的域名http://www.ewomail.com/list-11.html，成功部署
 两种方式
 wget：wget -c https://down.ewomail.com/install-04.sh && sh install-04.sh 你的域名
 curl：curl -C - -o https://down.ewomail.com/install-04.sh && sh install-04.sh 你的域名
```

​

![image-20250619102421615-0299863.png](images/img_18293_003.png)

![image-20250619102500134-0299903.png](images/img_18293_004.png)

**5、验证**

```
访问地址（将IP更换成你服务器IP即可）

邮箱管理后台：[http://IP:8010](http://ip:8010/) （默认账号admin，密码ewomail123）
ssl端口 [https://IP:7010](https://ip:7010/)

web邮件系统：[http://IP:8000](http://ip:8000/)
ssl端口 [https://IP:7000](https://ip:7000/)

域名解析完成后，可以用子域名访问，例如下面
[http://mail.xxx.com:8000](http://mail.xxx.com:8000/) (http)
[https://mail.xxx.com:7000](https://mail.xxx.com:7000/) (ssl)
```

![image-20250619102539854.png](images/img_18293_005.png)

### 0.2.域名解析

**1、DKIM值配置**

```
服务器运行 amavisd -c /etc/amavisd/amavisd.conf showkeys
```

![image-20250619102616703.png](images/img_18293_006.png)

```
复制输出的信息，打开http://www.ewomail.com/list-20.html 整理dkim信息
```

![image-20250619102638948.png](images/img_18293_007.png)

```
等待10分钟运行amavisd  -c /etc/amavisd/amavisd.conf testkeys
输出pass则配置成功
```

![image-20240911221155931.png](images/img_18293_008.png)

**2、服务商配置域名解析**

```
按照以下表格配置
注意：ip换成自己vps的ip不然会被spf拦截
```

![image-20240911201733921.png](images/img_18293_009.png)

|  |  |  |  |  |  |  |
| --- | --- | --- | --- | --- | --- | --- |
| 记录类型 | 主机记录 | 解析线路 | 记录值 | MX优先级 | TTL值 | 状态(暂停/正常) |
| TXT | @ | 默认 | v=spf1 ip4:127.0.0.1 -all |  | 600 | 正常 |
| TXT | dkim.\_domainkey | 默认 | 这是存放DKIM的值 |  | 600 | 正常 |
| A | mail | 默认 | 127.0.0.1 |  | 600 | 正常 |
| CNAME | smtp | 默认 | mail.***.*** |  | 600 | 正常 |
| CNAME | pop | 默认 | mail.***.*** |  | 600 | 正常 |
| CNAME | imap | 默认 | mail.***.*** |  | 600 | 正常 |
| MX | @ | 默认 | mail.***.*** | 1 | 600 | 正常 |
| 备注：将127.0.0.1 替换成你的公网IP，mail.\*\*\*.***的***.\*\*\*替换成你的域名 |  |  |  |  |  |  |

### 0.3.创建账号验证

![image-20250619102911740-0300154.png](images/img_18293_010.png)

![image-20250619102929979.png](images/img_18293_011.png)

## 0.2.gophish中转服务搭建

### 0.2.1.服务搭建

```
1. 首先安装docker环境：
yum install docker -y
systemctl start docker
docker pull gophish/gophish

2. 这步很重要，docker有时的dns不对需要修改
vim /etc/resolv.conf
修改为：
nameserver 8.8.8.8
nameserver 114.114.114.114

3. 将3333特征端口映射到7878
docker run -it -d --name gophish -p 7878:3333 -p 80:80 -p 8080:8080 gophish/gophish:latest

```

### 0.2.2.特征消除（重要）

```
Email Headers必选项，记得设置X-Mailer头为任意头部，覆盖默认的X-Mailer:gophish
若不修改此字段的值，通过 gophish 发出的邮件，其邮件头的 X-Mailer 的值默认为 gophish。设置好我们发送一封邮件，查看邮件源码可以看到，X-Mailer头已经被修改。
```

![image-20250619103047492.png](images/img_18293_012.png)

![image-20250619103243475.png](images/img_18293_013.png)

### 0.2.3.邮件点击记录

1、进入gophish钓鱼控制台，进入Landing Pages点击Import Site

![image-20230711093553220.png](images/img_18293_014.png)

2、进入Email Templates，将显示的隐藏链接替换成{{.URL}}变量

![image-20250619103439516.png](images/img_18293_015.png)

3、选中Add Tracking Image，点击保存

![image-20250619103500636.png](images/img_18293_016.png)

4、在新建钓鱼邮件发送时，填写钓鱼控制台地址<https://39.107.252.65:8010>

![image-20230711132933649.png](images/img_18293_017.png)

5、成功记录点击邮件链接设备信息和点击时间

![image-20250619103536855.png](images/img_18293_018.png)

### 0.2.4.转发式钓鱼实施

```
#钓鱼邮件分为
1.篡改From字段：容易被SPF策略拦截
2.近似邮件域名：比较好用，但是无法应对集团性质的多域名企业
3.直接拿下目标邮箱：邮箱账号没有高级权限，容易被问询当成垃圾邮件处理
4.转发式钓鱼：好用，不需要近似域名，通过转发伪造真实域名绕过拦截。

#需要准备以下平台
1.自建邮件服务器
2.goblin、CS投毒平台
3.gophish发信平台
```

1、部署邮件服务器<http://mail.XXXX.in:8000/>

2、部署goblin或CS投毒平台，这个比较敏感就不讲咯

3、登录钓鱼平台，选择发送配置文件，配置如下，“SMTP来自”这一块儿需要配置成自建邮件服务器的域名，防止SPF校验域名与IP不一致邮件被拦截。

![image-20250619103739662.png](images/img_18293_019.png)

4、选择着陆页面，随意配置一个url

![image-20230413231452462.png](images/img_18293_020.png)

5、选择电子邮件模版，“信封发件人”伪造成受害者高权限邮箱的信息

![image-20230413233459785.png](images/img_18293_021.png)

6、点击链接，将显示路径改完真实路径，访问路径改为伪造的VPS路径https://haitongauto.com/download/360\_DUN\_install，下面放入VPS的挂马路径http://38.147.172.149:80/download/360\_DUN\_install.exe。

![image-20230413233816845.png](images/img_18293_022.png)

7、选择“用户与群组”，导入目标用户

![image-20250619103905391.png](images/img_18293_023.png)

8、选择“活动”，填写之前配置好的信息，批量发送钓鱼邮件

![image-20250619111035361.png](images/img_18293_024.png)

9、成功收到邮件，点击链接成功下载木马，就等受害者点击，CS就可以上线了。

```
注：如果要伪造的更像，这里的站点可以换成近似域名，但是相应的也有被溯源的风险，因为国外域名无法解析国内服务器，国内域名又需要实名。
```

![image-20250619104039295.png](images/img_18293_025.png)

![image-20230413232917191.png](images/img_18293_026.png)
