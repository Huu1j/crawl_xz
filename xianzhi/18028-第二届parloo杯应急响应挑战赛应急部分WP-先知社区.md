# 第二届parloo杯应急响应挑战赛应急部分WP-先知社区

> **来源**: https://xz.aliyun.com/news/18028  
> **文章ID**: 18028

---

# 应急响应之畸形的爱

## 应急响应1-1

题目描述

提交攻击者使用的攻击ip地址1  
flag格式为：palu{xxxx}

![image.png](images/img_18028_000.png)

日志中发现大量的192.168.31.240的访问日志，并且访问的是一句话木马

![image.png](images/img_18028_001.png)

palu{192.168.31.240}

## 应急响应1-2

题目描述

提交攻击者使用的攻击ip地址2.  
flag格式为：palu{xxxx}

在聊天记录中发现文件传输

![image.png](images/img_18028_002.png)

解压发现 简历.exe

![image.png](images/img_18028_003.png)

![image.png](images/img_18028_004.png)

不出所料，上传沙箱分析为恶意文件

palu{192.168.31.11}

## 应急响应1-3

题目描述

题解攻击者暴力破解开始时间。  
flag为:palu{xx:xx:xx:xx}

使用docker logs 680140查看docker日志

![image.png](images/img_18028_005.png)

根据前面获取的攻击者IP在docker日志中发现了暴力破解行为

网页的暴力破解一般通常跟登录框匹配可以配合POST来进行快速定位

![image.png](images/img_18028_006.png)

palu{2025-05-02-03:05:58}

## 应急响应1-4

题目描述

提交攻击者留下的flag1  
格式为palu{xxx}

计划任务中发现flag1

![image.png](images/img_18028_007.png)

![image.png](images/img_18028_008.png)

palu{pc3\_zgsfqwerlkssaw}

## 应急响应1-5

题目描述

提交攻击者留下的flag2  
格式为：palu{xxxx}

在最近使用的文件中发现a.bat，发现flag2

![image.png](images/img_18028_009.png)

palu{nizhidaowoyouduoainima}

## 应急响应1-6

题目描述

提交攻击者留下的flag3  
提交格式为：palu{xxxx}

在网页文件中找到数据库账户密码

![image.png](images/img_18028_010.png)

连接数据库，发现可疑信息

![image.png](images/img_18028_011.png)

![image.png](images/img_18028_012.png)

base64解密发现flag3

palu{sqlaabbccsbwindows}

## 应急响应1-7

题目描述

提交钓鱼文件的哈希32位大写

还是这个文件

![image.png](images/img_18028_013.png)

![image.png](images/img_18028_014.png)

转换为大写

palu{2977CDAB8F3EE5EFDDAE61AD9F6CF203}

## 应急响应1-8

题目描述

提交攻击者留下的webshell-1密码  
格式为：palu{xxxx}

![image.png](images/img_18028_015.png)

就是a.php

palu{00232}

## 应急响应1-9

题目描述

提交攻击者开放端口  
格式为：palu{xxx,xxx,xxx}

## 应急响应1-10

题目描述

提交攻击者留下的webshell密码2  
格式为：palu{xxxx}

在日志里发现了shell.php

![image.png](images/img_18028_016.png)

![image.png](images/img_18028_017.png)

palu{hack}

## 应急响应1-11

题目描述

提交攻击者留下的隐藏账户的密码  
flag格式为：palu{xxxx}

在win10中发现隐藏用户

![image.png](images/img_18028_018.png)

上传mimikatz查看用户密码

![image.png](images/img_18028_019.png)

但是sekurlsa::logonpasswords没看见system$用户的信息

使用lsadump:sam尝试查看hash值

![image.png](images/img_18028_020.png)

发现报错 ，错误代码`0x00000005`对应的是Windows系统错误中的“访问被拒绝”（ERROR\_ACCESS\_DENIED）。这表明Mimikatz在尝试访问注册表中的SAM账户信息时，权限不足，无法打开相应的注册表键。

使用`token::elevate`来进行提权，`token::elevate` 命令用于提升当前进程的权限令牌，原理就是Mimikatz 会查找以 `SYSTEM` 身份运行的进程使用 Windows API（如 `OpenProcessToken` + `DuplicateTokenEx`）复制目标进程的令牌然后将复制的 `SYSTEM` 令牌附加到当前进程（Mimikatz），替换原有令牌达到权限提升的目的。

权限提升后再次执行就可以看见system$用户的信息了

![image.png](images/img_18028_021.png)

最后将用户的hash值上传cmd5解密就是最终flag了

![image.png](images/img_18028_022.png)

palu{wmx\_love}

## 应急响应1-12

题目描述

[溯源]攻击者的邮箱.  
flag格式为：palu{xxx}

## 应急响应1-13

题目描述

提交溯源后得到的flag  
flag格式为：palu{xxx}

# solar\_Linux后门排查

题目描述

跳板机疑似被遗留后门,请排查  
1、找到可疑进程完整路径  
2、找到被横向的服务器IP  
3、连接被横向服务器  
flag格式为 flag{base64{完整路径}|服务器IP|服务器中flag文本}  
root:Solar@2025\_05\_palu!

攻击者IP:49.232.112.164

![image.png](images/img_18028_023.png)

![image.png](images/img_18028_024.png)

这台服务器与横向服务器的连接，在 MySQL、Redis、Nginx 和 SSH 等进程启动之前就已经完成了。

继续查看发现docker守护进程

![image.png](images/img_18028_025.png)

![image.png](images/img_18028_026.png)

然后再环境变量中发现了flag

![image.png](images/img_18028_027.png)

但是最后还是没交对

# 应急主线

## 应急响应2-1

题目描述

提交堡垒机中留下的flag

![](C:/Users/Tho/AppData/Roaming/Typora/typora-user-images/image-20250518174252421.png)![image.png](images/img_18028_029.png)

根据资产清单登录堡垒机admin/Skills@2020

![](C:/Users/Tho/AppData/Roaming/Typora/typora-user-images/image-20250518174401480.png)![image.png](images/img_18028_031.png)

在标签列表处发现flag

## 应急响应2-2

题目描述

提交WAF中隐藏的flag

![](C:/Users/Tho/AppData/Roaming/Typora/typora-user-images/image-20250518174442110.png)![image.png](images/img_18028_033.png)

同样根据资产清单信息登录waf admin/VF6NXMs7

![](C:/Users/Tho/AppData/Roaming/Typora/typora-user-images/image-20250518174550083.png)![image.png](images/img_18028_035.png)

在身份认证处发现flag

palu{2025\_waf}

## 应急响应2-3

题目描述

提交Mysql中留下的flag

![](C:/Users/Tho/AppData/Roaming/Typora/typora-user-images/image-20250518174638053.png)![image.png](images/img_18028_037.png)

使用资产清单给的账户密码连接数据库root/mysql\_QPiS8y

![](C:/Users/Tho/AppData/Roaming/Typora/typora-user-images/image-20250518174721070.png)![image.png](images/img_18028_039.png)

发现flag

palu{Mysql\_@2025}

## 应急响应2-4

题目描述

提交攻击者的攻击IP

在waf上看看有哪些攻击行为

![](C:/Users/Tho/AppData/Roaming/Typora/typora-user-images/image-20250518175733114.png)![image.png](images/img_18028_041.png)

发现192.168.20.107/192.168.20.108都存在攻击行为

最终提交192.168.20.107为flag

palu{192.168.20.107}

## 应急响应2-5

题目描述

提交攻攻击者最早攻击时间flag格式为palu{xxxx-xx-xx-xx-xx-xx}

![](C:/Users/Tho/AppData/Roaming/Typora/typora-user-images/image-20250518175929253.png)![image.png](images/img_18028_043.png)

进入攻击日志可以查看更详细的攻击行为和记录

![](C:/Users/Tho/AppData/Roaming/Typora/typora-user-images/image-20250518180028478.png)![image.png](images/img_18028_045.png)

直接翻到最后，找到最早攻击的时间。但是题目的flag格式有点问题按描述的格式提交不对

正确提交格式：palu{2025-05-05-00:04:40}

## 应急响应2-6

题目描述

提交web服务泄露的关键文件名

登录到waf主机的命令行，查看docker启动了哪些服务

![](C:/Users/Tho/AppData/Roaming/Typora/typora-user-images/image-20250518180346364.png)![image.png](images/img_18028_047.png)

发现nginx，进到服务器看看有什么

![](C:/Users/Tho/AppData/Roaming/Typora/typora-user-images/image-20250518180525024.png)![image.png](images/img_18028_049.png)

日志有点多，筛选状态码为200的访问日志

![](C:/Users/Tho/AppData/Roaming/Typora/typora-user-images/image-20250518180903355.png)![image.png](images/img_18028_051.png)

发现key.txt提交发现是正确flag

palu{key.txt}

## 应急响应2-7

题目描述

题解泄露的邮箱地址

![](C:/Users/Tho/AppData/Roaming/Typora/typora-user-images/image-20250518181045947.png)![image.png](images/img_18028_053.png)

根据上一题定位到文件位置，发现parloo@parloo.com

palu{parloo@parloo.com}

## 应急响应2-8

题目描述

提交立足点服务器ip地址

![](C:/Users/Tho/AppData/Roaming/Typora/typora-user-images/image-20250518182045594.png)![image.png](images/img_18028_055.png)

在攻击日志发现192.168.20.108一直在漏扫

palu{192.168.20.108}

## 应急响应2-9

题目描述

提交攻击者使用的提权的用户和密码

## 应急响应2-10

题目描述

提交攻击者留下的的文件内容作为flag提交

这里需要登录到sshserver

在登录的时候会发现一直卡着进不去，可以使用ctrl+c就能进去，后面会解释原因

![](C:/Users/Tho/AppData/Roaming/Typora/typora-user-images/image-20250518193550183.png)![image.png](images/img_18028_057.png)

但是原命令行交互体验实在不行，这时候我想xshell连接

![](C:/Users/Tho/AppData/Roaming/Typora/typora-user-images/image-20250518194059410.png)![image.png](images/img_18028_059.png)

不出意外，又卡住了，并且输入不了ctrl+c了

![](C:/Users/Tho/AppData/Roaming/Typora/typora-user-images/image-20250518194158196.png)![image.png](images/img_18028_061.png)

这时候就需要kill掉这个罪魁祸首了

![](C:/Users/Tho/AppData/Roaming/Typora/typora-user-images/image-20250518194214736.png)![image.png](images/img_18028_063.png)

成功连接

命令解释：

```
run-parts：运行指定目录（/etc/update-motd.d）中的所有可执行脚本。
--lsbsysinit：启用 LSB（Linux Standard Base）兼容模式，仅运行符合 LSB 命名规范的脚本（文件名需以数字开头，如 00-header、10-help-text）。

/etc/update-motd.d目录
├── 00-header         # 标题和基础信息
├── 10-help-text      # 帮助提示
├── 50-motd-news      # Ubuntu 安全公告
├── 90-updates-available  # 可更新软件包数量
└── 99-footer         # 结尾空行

这个命令是用来生成动态登录信息的。正常情况下，这个命令应该在用户登录时自动运行，显示欢迎信息。但如果登录卡住，可能是MOTD脚本执行时出现了问题。这时候就需要将进程停止
```

解决了交互问题后，正式做题

![image.png](images/img_18028_064.png)

在home目录下发现攻击者留下的的文件

palu{hi\_2025\_parloo\_is\_hack}

## 应急响应2-11

题目描述

提交权限维持方法服务的名称

## 应急响应2-12

题目描述

提交攻击者攻击恶意服务器连接地址作为flag提交

在parloo-子怡和parloo沉沉对话中发现可以文件，上传沙箱分析下

![image.png](images/img_18028_065.png)

![image.png](images/img_18028_066.png)

这里可以使用渊龙的导航站，里面收录了大量的优秀网站，需要什么直接搜很方便

![](C:/Users/Tho/AppData/Roaming/Typora/typora-user-images/image-20250518175109493.png)![image.png](images/img_18028_068.png)

在奇安信沙箱中发现了恶意服务器连接地址

![](C:/Users/Tho/AppData/Roaming/Typora/typora-user-images/image-20250518175312488.png)![image.png](images/img_18028_070.png)

![](C:/Users/Tho/AppData/Roaming/Typora/typora-user-images/image-20250518175339627.png)![image.png](images/img_18028_072.png)

palu{47.101.213.153}

## 应急响应2-13

题目描述

找到系统中被劫持的程序程序名作为flag提交

## 应急响应2-14

题目描述

找到系统中存在信息泄露的服务运行端口作为flag提交

![image.png](images/img_18028_073.png)

访问发现存在信息泄露

![image.png](images/img_18028_074.png)

palu{8081}

## 应急响应2-15

题目描述

提交Parloo公司项目经理的身份证号作为flag提交

根据上题的信息泄露，访问网页

![image.png](images/img_18028_075.png)

发现完整身份证信息

![image.png](images/img_18028_076.png)

palu{310105198512123456}

## 应急响应2-16

题目描述

提交存在危险功能的操作系统路径作为flag提交。flag格式为palu{/xxx/xxx}

发现一个路由

![image.png](images/img_18028_077.png)

访问发现可以执行命令

![image.png](images/img_18028_078.png)

palu{/admin/parloo}

## 应急响应2-17

题目描述

提交进源机器中恶意程序的MD5作为flag进行提交。 flag格式为palu{MD5小写}

## 应急响应2-18

题目描述

提交攻击者留下的恶意账户名称md5后作为flag进行提交。 格式为palu{md5{xxxxx}}

palu03开机发现恶意账户

![image.png](images/img_18028_079.png)

![image.png](images/img_18028_080.png)

palu{d78b6f30225cdc811adfe8d4e7c9fd34}

## 应急响应2-19

题目描述

提交内部群中留下的flag并提交

nwt进群聊看聊天记录就可以看到

![image.png](images/img_18028_081.png)

palu{nbq\_nbq\_parloo}

## 应急响应2-20

题目描述

请提交攻击者使用维护页面获取到的敏感内容作为flag进行提交

在日志里有一个palu{的关键字，但是我后面去找不知道去哪了

## 应急响应2-21

题目描述

提交获取敏感内容IP的第一次执行命令时间作为flag进行提交。flag格式为palu{xxxx-xx-xx:xx:xx:xx}

![image.png](images/img_18028_082.png)

在历史记录中发现查看了一个日志文件

![image.png](images/img_18028_083.png)

发现存在执行命令的操作，将首次攻击的时间作为flag提交

palu{2025-05-04-15:30:38}

## 应急响应2-22

题目描述

提交攻击者使用的恶意ip和端口flag格式为palu{xx.xx.xx.xx:xxxx}

同一个文件往下翻

![image.png](images/img_18028_084.png)

palu{10.12.12.13:9999}

## 应急响应2-23

题目描述

提交重要数据的名文内容作为flag提交

![image.png](images/img_18028_085.png)

桌面发现这个但是解密不了，文件属性也没发现可用信息

## 应急响应2-24

题目描述

提交恶意维权软件的名称作为flag进行提交

## 应急响应2-25

题目描述

提交恶意程序的外联地址

## 应急响应2-26

题目描述

提交攻击这使用的恶意dnslog域名作为flag进行提交

还是应急响应2-21的日志文件

![image.png](images/img_18028_086.png)

日志中发现域名前加里命令有点像dnslog

![image.png](images/img_18028_087.png)

palu{np85qqde.requestrepo.com}

## 应急响应2-27

题目描述

提交寻找反序列化漏洞的端口作为flag进行提交

![image.png](images/img_18028_088.png)

palu{9999}

## 应急响应2-28

题目描述

提交web服务泄露的密钥作为flag进行提交

## 应急响应2-29

题目描述

提交攻击者开始攻击的时间作为flag进行提交。flag各式为palu{xxxx/xx/xx:xx:xx:xx}

## 应急响应2-30

题目描述

提交攻击者在server中留下的账户密码作为flag进行提交。flag格式为palu{username/password}

## 应急响应2-31

题目描述

提交攻击者维权方法的名称作为flag进行提交

## 应急响应2-32

题目描述

提交攻击者留下的木马md5后作为flag进行提交

发现攻击者用户目录下存在可执行文件

![image.png](images/img_18028_089.png)

![image.png](images/img_18028_090.png)

palu{4123940b3911556d4bf79196cc008bf4}

## 应急响应2-33

题目描述

提交攻击者留下的溯源信息作为flag进行提交

在palu02的流量器中发现存在登录信息

![image.png](images/img_18028_091.png)

![image.png](images/img_18028_092.png)

![image.png](images/img_18028_093.png)

查看用户时发现攻击者留下的信息

palu{X5E1yklzoAdyHBZ}

## 应急响应2-34

题目描述

提交攻击者的githubID作为flag进行提交

## 应急响应2-35

题目描述

提交攻击者在github下留下的的内容作为flag进行提交

## 应急响应2-36

题目描述

提交恶意用户的数量作为flag进行提交

启动就发现大量用户存在

![image.png](images/img_18028_094.png)

![image.png](images/img_18028_095.png)

net user发现有99个

palu{99}

## 应急响应2-37

题目描述

提交恶意用户的默认密码作为flag进行提交

在palu01上打开，在根目录有隐藏文件

![image.png](images/img_18028_096.png)

![image.png](images/img_18028_097.png)

palu{123456}

## 应急响应2-38

题目描述

提交业务数据中攻击者留下的信息作为flag进行提交

在网站中发现flag关键字

![image.png](images/img_18028_098.png)

登录数据库在user表中发现flag信息

![image.png](images/img_18028_099.png)

## 应急响应2-39

题目描述

提交私人git仓库中留下的内容作为flag进行提交

在server01的docker服务中发现git

![image.png](images/img_18028_100.png)

![image.png](images/img_18028_101.png)

`git ls-tree -r main` 是 Git 中用于递归列出指定分支（这里是 `main` 分支）中所有文件和目录的命令。

![image.png](images/img_18028_102.png)

palu{FO65SruuTukdpBS5}

## 应急响应2-40

题目描述

提交存在在mysql服务器中的恶意程序的MD5作为flag进行提交

登录发现隐藏可执行文件

![image.png](images/img_18028_103.png)

palu{ba7c9fc1ff58b48d0df5c88d2fcc5cd1}

## 应急响应2-41

题目描述

提交恶意程序中模拟c2通信的函数名称作为flag进行提交

分析/root目录下.a文件

![image.png](images/img_18028_104.png)

![image.png](images/img_18028_105.png)

palu{simulate\_network\_communication}

## 应急响应2-42

题目描述

提交恶意程序创建隐藏文件的名称作为flag提交

分析/root目录下.a文件

![image.png](images/img_18028_106.png)

palu{.malware\_log.txt}

## 应急响应2-43

题目描述

提交恶意程序中模拟权限提升的函数作为flag进行提交

分析/root目录下.a文件

![image.png](images/img_18028_107.png)

palu{simulate\_privilege\_escalation}

## 应急响应2-44

题目描述

提交被钓鱼上线的用户名作为flag进行提交

## 应急响应2-45

题目描述

提交恶意程序的所在路径作为flag进行提交

这里就是上面应急响应2-12的文件

![image.png](images/img_18028_108.png)

![image.png](images/img_18028_109.png)

## 应急响应2-46

题目描述

分析恶意程序的反连地址作为flag进行提交

![image.png](images/img_18028_110.png)

![image.png](images/img_18028_111.png)

不多赘述跟应急响应2-12一样

## 应急响应2-47

题目描述

提交恶意c2的服务器登录的账号密码作为flag进行提交。flag格式为palu{username/password}
