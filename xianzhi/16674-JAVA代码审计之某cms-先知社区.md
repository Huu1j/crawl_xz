# JAVA代码审计之某cms-先知社区

> **来源**: https://xz.aliyun.com/news/16674  
> **文章ID**: 16674

---

## 环境配置

修改数据库用户名和密码。

![image.png](images/20250212171840-58fb5748-e922-1.png)

![image.png](images/20250212171841-59f306fd-e922-1.png)

导入数据库。

![image.png](images/20250212171842-5a9434f6-e922-1.png)

搭建完成，成功访问。

![image.png](images/20250212171844-5b429b75-e922-1.png)

![image.png](images/20250212171845-5c187029-e922-1.png)

## 目录结构

Jspxcms 的目录结构分为 3 个主文件夹，分别为 java、resource 和 webapp。java 文件夹中主要存放 Java 源码，resource 文件夹主要存放配置文件，webapp 文件主要存放 JSP 文件以及静态资源文件。

Java文件夹：

* com.jspxcms.common：主要存放公用组件代码

* util：工具类。
* web：Spring MVC 等 Web 相关类。

* com.jspxcms.core：主要存放站点功能的核心模块代码

* repository：数据库持久化层的代码
* security：安全防护相关的逻辑代码
* service：服务层的代码
* web：Controller 层的代码

resources文件夹：

* conf：主要存放各种类型的配置文件

* core：核心模块的配置文件
* conf.properties：系统 properties 的配置文件

* application.properties：Spring Boot 的配置文件

webapp 文件夹：

* jsp：主要存放单独的 JSP 页面文件
* static：主要存放静态资源文件
* template：主要存放前台 FreeMarker 的模板文件
* uploads：主要存放上传的文件
* views：主要存放后台的 JSP 页面

* commons：部分公用的 JSP 页面
* core：核心模块的 JSP 页面
* index.jsp：后台首页框架页
* login.jsp：后台登录的页面

* crossdomain.xml：跨域策略的配置文件

## 漏洞1：XSS漏洞

![image.png](images/20250212171846-5cc85076-e922-1.png)

请求路径是/comment\_submit。全局搜索

![image.png](images/20250212171847-5d90ef95-e922-1.png)

下个断点，调试模式运行：

![image.png](images/20250212171849-5e606323-e922-1.png)![image.png](images/20250212171850-5efaf4ed-e922-1.png)

跟进submit，在service层处理 text的位置 下断点

可以看到使用了 comment 对象的属性去保存 text 然后传递给 service.save ，text 的内容没有被改变![image.png](images/20250212171851-5f99d48f-e922-1.png)

发现未对其进行过滤。![image.png](images/20250212171852-60458cbb-e922-1.png)

全局搜索 /comment\_list

![image.png](images/20250212171853-6107fe68-e922-1.png)

跟进 list 方法，先从数据库里把评论信息读取出来，然后设置模板填充数据。

![image.png](images/20250212171855-61d3f3c6-e922-1.png)

### 漏洞复现：

在评论处输入payload

![image.png](images/20250212171856-629dc58d-e922-1.png)

http://127.0.0.1:8080/space/1?type=comment

![image.png](images/20250212171857-63756c57-e922-1.png)

​

## 漏洞2：SSRF漏洞

使用 IDEA 搜索`HttpClient.execute`

![image.png](images/20250212171859-64550ecc-e922-1.png)

找到了`fetchHtml`方法

![image.png](images/20250212171900-6536352d-e922-1.png)

查找用法

![image.png](images/20250212171902-65f0d2f9-e922-1.png)

继续查找用法

可以看到`fetchUrl`方法中url是直接通过参数传入的

![image.png](images/20250212171902-667e9614-e922-1.png)

构造相应URL传参即可：![image.png](images/20250212171903-670f22d8-e922-1.png)

### 漏洞复现：

利用成功。当然这里只能利用http 或 https 协议去扫描端口或探测内网服务。不支持其他协议。

![image.png](images/20250212171904-67a9041d-e922-1.png)

## 漏洞3：SSRF漏洞（2）：

![image.png](images/20250212171906-6874f0cf-e922-1.png)

定位到ueditorCatchImage函数，该函数的功能是获取并下载远程 URL 图片

![image.png](images/20250212171907-696111a0-e922-1.png)

可以看到url是通过 http请求里的 `source[]`参数获得到，并且对于传入的 URL 并没有进行过滤，在得到 URL 的值后， 直接带入 openConnection()，这就造成了SSRF漏洞。

查找`ueditorCatchImage`的用法

![image.png](images/20250212171909-6a3d2996-e922-1.png)

可以看到路径是`/ueditor`，并且`action`参数等于`catchimage`的话就会调用`ueditorCatchImage`方法

那么我们构造请求如下：

![image.png](images/20250212171910-6b111b4e-e922-1.png)

### 漏洞复现：

![image.png](images/20250212171911-6bcc73a1-e922-1.png)

访问dnslog。

![image.png](images/20250212171912-6c6d8c33-e922-1.png)

成功触发，收到监听。

![image.png](images/20250212171913-6cf53c88-e922-1.png)

## 漏洞4：命令执行漏洞：

这个漏洞在文件管理的压缩包上传功能，上传的压缩包会被自动解压，如果我们在压缩包中放入 war 包并配合解压后目录穿越，war包就会被移动到tomcat的webapps目标下，而tomcat会自动解压部署war包。

分析一下：

![image.png](images/20250212171914-6d8f8e46-e922-1.png)

对上传功能处，进行抓包

![image.png](images/20250212171915-6e3fe464-e922-1.png)

发现未对其过滤。

![image.png](images/20250212171917-6ef87520-e922-1.png)

### 漏洞复现：

![image.png](images/20250212171918-6f9672de-e922-1.png)

![image.png](images/20250212171918-700e05f2-e922-1.png)

成功上传后获取shell。

![image.png](images/20250212171919-709a885e-e922-1.png)

​

## 漏洞5：Freemarker模板注入

![image.png](images/20250212171921-7178ba0c-e922-1.png)

```
[#escape x as (x)!?html]
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
</head>
<body>

${"freemarker.template.utility.Execute"?new()("calc")}

</body>
</html>
[/#escape]

```

先新建一个test文件夹，然后上传index.html

![image.png](images/20250212171923-7292e573-e922-1.png)

![image.png](images/20250212171924-736ea45d-e922-1.png)

### 漏洞复现：

成功弹出计算器。

![image.png](images/20250212171925-741c7257-e922-1.png)

## 漏洞6：Shiro反序列化

发现 Shiro <= 1.2.4 ：存在shiro-550反序列化漏洞； 1.2.5 <= Shiro < 1.4.2 ：存在shiro-721反序列化漏洞； Shiro > = 1.4.2 ：如果⽤户使⽤弱密钥，即使升级⾄最新版本，仍然存在反序列化漏洞⼊⼝。

存在shiro漏洞。

![image.png](images/20250212171926-74af178f-e922-1.png)

![image.png](images/20250212171927-755b8981-e922-1.png)

![image.png](images/20250212171929-76294ef3-e922-1.png)

### 漏洞复现

![image.png](images/20250212171931-7751660a-e922-1.png)

![image.png](images/20250212171933-78b18ae2-e922-1.png)

也可以使用工具验证，记住密码之后，然后使用shiro-explot验证。

![image.png](images/20250212171934-795e0043-e922-1.png)
