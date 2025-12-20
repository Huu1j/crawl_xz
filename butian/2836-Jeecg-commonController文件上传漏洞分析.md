# Jeecg-commonController文件上传漏洞分析

> **来源**: https://forum.butian.net/share/2836  
> **文章ID**: 2836

---

0x01 前言
-------

朋友整了一个漏洞情报的钉钉机器人，这几天看到了一个最新推送的漏洞`Jeecg commonController 文件上传漏洞`。说是EXP已公开、但是网上找了一圈没找到，那就自己分析一下吧！

![image-20240326014820233](images/attach-98a7101067b868f52e0452c817d540dd93a04a37.png)

0x02 漏洞简介
---------

JEECG(J2EE Code Generation) 是开源的代码生成平台，目前官方已停止维护。由于 /api 接口鉴权时未过滤路径遍历，攻击者可构造包含 ../ 的url绕过鉴权。攻击者可构造恶意请求利用 commonController 接口进行文件上传攻击实现远程代码执行。

0x03 环境搭建
---------

**1）基础环境**

idea、java7、tomcat7

mysql5.7

jeecg3.8：<https://github.com/chen-tj/jeecg3.8>

**2）使用IDEA集成Tomcat7插件运行项目**

```xml
<plugin>
    <groupId>org.apache.tomcat.maven</groupId>
    <artifactId>tomcat7-maven-plugin</artifactId>
    <version>2.2</version>
    <configuration>
        <port>8080</port>
        <path>/demo</path>
        <uriEncoding>UTF-8</uriEncoding>
        <!--添加忽略war包检查标签，则可以让tomcat7：run指令正常启动tomcat-->
        <ignorePackaging>true</ignorePackaging>
        <contextFile>src/main/webapp/WEB-INF/context.xml</contextFile>
        <contextReloadable>true</contextReloadable>
    </configuration>
</plugin>
```

![image-20240325233557207](images/attach-17c71532c60d6d47e08ab3dec91293497b46b821.png)

**3）使用idea加载环境时可能会出现一些问题，可以参考：**

[https://blog.csdn.net/weixin\_43761325/article/details/105233037](https://blog.csdn.net/weixin_43761325/article/details/105233037)

**4）访问到如下页面就ok**

![image-20240325233718673](images/attach-28955fcd70dc3145c9eb2b5139931aeed2d50b80.png)

0x04 路由说明
---------

JEECG快速开发平台基于spring MVC 框架  
@Controller将一个类声明为控制器类，再通过@RequestMapping配置路由映射。

简单举例说明：  
项目中src/main/java/com/jeecg/demo/controller/MultiUploadController.java文件

```less
@RequestMapping("/multiUploadController")
    @RequestMapping(params = "list")
```

对应的url地址为：<http://localhost:8080/multiUploadController.do?list>

0x05 漏洞复现
---------

![image-20240326012438041](images/attach-4286754f01934cfc3fa0b1a46df43431bd282f93.png)

![image-20240326012503300](images/attach-05728f58124fa9384bef9096ce18142568c2671a.png)

![image-20240326012523537](images/attach-de1467e930e9e07f49de3d4ddffa02bb543c1826.png)

0x06 漏洞分析
---------

在漏洞描述中说是`在commonController 接口进行文件上传`

全局搜索commonController，最终定位到`org.jeecgframework.web.system.controller.core.CommonController`

![image-20240326011548536](images/attach-426148799fd7e9db0b40ded7bca3f275914a55fc.png)

在一番仔细的寻找之后，发现`commonController#parserXml`这个可疑的方法

很明显可以看出来其对上传文件后缀未做任何过滤

![image-20240326012639532](images/attach-ec1c9fc8e90ad9b4afcd68fe97455908ae6c0819.png)

根据0x03中对路由的分析，可以构造出，这个漏洞的路径

```php
http://127.0.0.1/demo/commonController.do?parserXml
```

直接发包访问该接口会鉴权被检测到没有登录，直接302跳转，要想办法绕过  
![image-20240326013625165](images/attach-dd0b5dd130a63f32d4acbbb48e4198ede968a6a9.png)

结合漏洞简介中提到的 `/api 接口鉴权时未过滤路径遍历，攻击者可构造包含 ../ 的url绕过鉴权`。

找到了`org.jeecgframework.core.interceptors.AuthInterceptor#preHandle`，提到包含`api/`的路径不做登录验证

![image-20240326014019009](images/attach-6721d11c352cdb31a45b0d5b3681ea960ec698c9.png)

查看引用的`Maven依赖`中的`alwaysUseFullPath`为值默认`false`，这样的话程序在处理发包中会对`uri`进行标准化处理。于是我们就可以使用`/api/../`的方式来进行`bypass`

![image-20240326014429364](images/attach-731b1fa2e3c1933298a6040727c1decffc20f903.png)

所以最终的漏洞地址就是：

```php
http://127.0.0.1/demo/api/../commonController.do?parserXml
```

0x07 总结
-------

文件上传漏洞，结合未授权

0x08 参考
-------

<https://avd.aliyun.com/detail?id=AVD-2024-1705554>

<https://www.cnblogs.com/yyhuni/p/14607471.html>

<https://www.hetianlab.com/specialized/20240311223801>
