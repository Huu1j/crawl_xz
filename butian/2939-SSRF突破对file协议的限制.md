# SSRF突破对file协议的限制

> **来源**: https://forum.butian.net/share/2939  
> **文章ID**: 2939

---

0x01 前言
-------

这两天在网上看到一个在java中ssrf绕过的小trick，主要就是以黑名单过滤了`file`协议的情况下，如何绕过！

0x02 环境搭建
---------

**jdk**：11.0.11

**demo**：

```java
@RequestMapping("/ssrf")
public String ssrf(String url) {
    String urlContent = "";
    try {
        // 检查URL是否以"file://"开头
        if (url.startsWith("file://")) {
            return "URL can't start with 'file://'";
        }

        // 读取URL内容
        URL u = new URL(url);
        BufferedReader in = new BufferedReader(new InputStreamReader(u.openStream()));
        String inputLine;
        while ((inputLine = in.readLine()) != null) {
            urlContent += inputLine + "\n";
        }
        in.close();
    } catch (Exception e) {
        e.printStackTrace();
    }

    return urlContent;
}
```

0x03 复现
-------

直接使用file协议，黑名单直接过滤，然后返回

![image-20240418195507488](images/attach-39d09ad365da5200c70518b2bb9483b75115649a.png)

poc：

```php
url:file://xxx
```

![image-20240418195546961](images/attach-23d6697ee478887e7dc61257f2a780eb2a12134b.png)

成功读取到文件！

0x04 分析
-------

可以看到我们传入的路径`url:file:///D://flag`在经过URL()处理之后返回了`file:///D://flag`

![image-20240418200508778](images/attach-84091b760d2ff329665a635700549170d35dadd2.png)

> `new URL()` 的作用是创建一个 URL 对象，该对象表示一个统一资源定位符（URL）。
> 
> 在Java中，URL类提供了一种方便的方式来处理URL，可以用于定位到互联网上的各种资源，例如网页、图像、视频等。
> 
> 通过 `new URL(String spec)` 构造函数，可以将一个字符串形式的URL转换为URL对象。
> 
> 这个字符串通常包含了URL的各个组成部分，如协议、主机名、端口、路径等。

具体的绕过逻辑就在`URL(String spec)`中，`Alt+Shift+F7`跟进去瞅瞅，一路向下走到`java.net.URL#URL(java.net.URL, java.lang.String, java.net.URLStreamHandler)`

在593行这段代码是在检查 URL 字符串是否以 "url:" 开头，并在匹配成后start+4（此时start=4）

![image-20240418202916816](images/attach-66cc2c437634c6d7cce54229b8ecff6c7b9866d1.png)

在603行，截取从start开始到了字符串 `spec` （即我们输入的地址url:file://xxx）的结尾或者下一个 `/` 字符，最终我们输入的url:file://xxx之类的构造会被解析为file

![image-20240418203612786](images/attach-cbad7e932affefdf79b858e36ae90e636b3fa3d2.png)

0x05 总结
-------

在对ssrf使用黑名单过过滤，我们可以使用正则匹配等手段来防御，但黑名单终归是不稳妥的！

想在java中若发起的请求时只支持使用HTTP/HTTPS协议，则可以使用以下几种方法！

```php
HttpURLConnection
HttpClient
OkHttpClient.newCall.execute
```
