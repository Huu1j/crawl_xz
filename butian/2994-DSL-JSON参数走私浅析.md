# DSL-JSON参数走私浅析

> **来源**: https://forum.butian.net/share/2994  
> **文章ID**: 2994

---

0x00 前言
=======

 DSL-JSON 是一个为 JVM（Java 虚拟机）平台设计的高性能 JSON 处理库，支持 Java、Android、Scala 和 Kotlin 语言。它被设计为比任何其他 Java JSON 库都快，与最快的二进制 JVM 编解码器性能相当。

![image.png](images/attach-2385fcee32263c1f2da028cfd6c5d772f70d58d6.png)

 在 DSL-JSON 库中，`deserialize` 方法和 `newReader` 都与 JSON 数据的反序列化有关。

- com.dslplatform.json.DslJson#deserialize可以直接将 JSON 字符串反序列化为指定的 Java 对象类型。这个方法通常用于简单场景，其中 JSON 数据可以直接映射到一个 POJO。
- com.dslplatform.json.DslJson#newReader会返回一个 `JsonReader` 对象，这个对象可以用来反序列化 JSON 数据。使用 `JsonReader` 提供了更细粒度的控制，允许你逐个处理 JSON 元素，而不是直接映射整个 JSON 文档到一个对象。

 下面简单看看具体的JSON解析过程。

0x01 DSL-JSON解析过程
=================

 不论是`deserialize` 还是`newReader`的方式，在反序列化时，都会先通过 typeLookup 查找与类型对应的 ReadObject 反序列化器。然后调用对应的read方法进行处理：

![image.png](images/attach-b9d20eeeb10af4d971c2bf0a0d6192ef1ac071c7.png)

![image.png](images/attach-b7757b8d9f0f0907481cafb67bc54e7b6c5e473a.png)

 在tryFindReader方法中，首先会在 readers 映射中查找是否已经存在与 manifest 对应的 ReadObject 反序列化器。如果存在,则直接返回，否则则调用 extractActualType 方法获取 manifest 的实际类型 actualType，这里一般是对自定义类型进行处理：

![image.png](images/attach-8e8c0118c03660591801c2e1c6ef12eeb14879fe.png)

 以HashMap的类型为例，对应的反序列化器为com.dslplatform.json.ObjectConverter，其主要支持以下数据类型：

![image.png](images/attach-b7e19799d1f1dda6737dc07c9503433f90825844.png)

 查看其read方法的调用逻辑，主要是在deserializeMap方法进行处理：

![image.png](images/attach-54bfbe3a909675ccf81ef62178f41d9790702e48.png)

 在deserializeMap方法中，首先检查当前的 JSON 标记是否为`{`(表示映射的开始)。如果不是,则抛出解析异常。如果下一个标记是`}`,则创建一个空的 LinkedHashMap 并返回。否则,创建一个新的 LinkedHashMap 对象 res等待进行内容（key-value）的解析：

![image.png](images/attach-c31f9baa71cb4643505a32f06c0e6c1c4859dec1.png)

 首先会调用com.dslplatform.json.JsonReader#readKey方法对键进行解析：

![image.png](images/attach-7b2376e719553bf6865f9ee5839629ff058634c6.png)

 具体的解析逻辑主要在com.dslplatform.json.JsonReader#parseString进行处理，首先检查当前字符是否以`"`(表示字符串的开始)。如果不是,则抛出解析异常：

![image.png](images/attach-9c971311e419d05ae6cc41e958af97162944792d.png)

 然后进入循环流程,从 JSON 数据流中读取字符,并将其复制到 `_tmp` 数组中。当遇到双引号 `"`(表示字符串的结束)，并返回复制的字符数。当遇到反斜杠 `\`(转义字符)时。会先退出循环,进入转义字符处理逻辑：

![image.png](images/attach-887fbdc970da13a12483b143f55e27df87e11801.png)

 对于转义字符,会根据后续字符的值进行不同的处理,包括普通转义字符、Unicode等：

![image.png](images/attach-72a9bd86793492df7b12ac1080bf91a80930902e.png)

 对于`\x61`的场景，DSL-JSON明显是不支持的，会抛出`Invalid escape combination detecte`异常。

 最后返回对应的length，获得当前的键属性。然后调用deserializeObject方法获取对应的值，这里会根据 JSON 值的类型,调用相应的反序列化逻辑,将 JSON 值转换为相应的 Java 对象，例如如果是`"`开头的话，会调用com.dslplatform.json.JsonReader#readString进行处理,如果均匹配不上，会调用NumberConverter.deserializeNumber当成数字进行处理，整个过程包含了一些错误处理逻辑,确保在遇到非法 JSON 数据时能够正确地抛出异常：

![image.png](images/attach-c69f6475dc56021402ee8c1c24b33ef5d94b7be6.png)

 获取完对应的值后，如果此时的标记是逗号 `,`,则继续读取下一个键值对,并将其存储到 res 中:

![image.png](images/attach-8685fbfbf8ee54df3ea7e65bd37cd9ca609cb883.png)

 最后检查最后一个标记是否为右大括号`}`,并返回前面填充的解析内容：

![image.png](images/attach-7cf3f717f2ae2569cefa5a8b6577e9dab0da86a8.png)

 以上是DSL-JSON大致的解析过程。

0x02 参数走私场景
===========

 在前面的分析过程中，DSL-JSON在调用deserializeMap处理时，会创建一个新的 LinkedHashMap 对象 res对JSON内容的解析结果进行存储：

![image.png](images/attach-64e99affdf559108c76809225cd025e031288a80.png)

 这里的res数据类型是LinkedHashMap，也就是说，如果在put操作时使用了已存在的键,则新值会替换旧值,原有的键值对会被新的键值对覆盖。**默认情况下在反序列化时，会取重复键值的后者**。

 下面结合JavaWeb中常见的JSON解析库的解析特性，看看其重复键值对情况下潜在的参数走私场景。

2.1 Unicode解码差异
---------------

 在前面分析的时候提到，在tryFindReader方法中，首先会在 readers 映射中查找是否已经存在与 manifest 对应的 ReadObject 反序列化器。如果存在,则直接返回，否则则调用 extractActualType 方法获取 manifest 的实际类型 actualType。这里获取到的反序列化器的解析方式是有区别的。例如这里指定序列化成自定义的User对象：

```Java
DslJson<Object> dslJson = new DslJson<Object>();
JsonReader<Object> jsonReader = dslJson.newReader(buff);
User user = jsonReader.next(User.class);
```

 跟进解析过程，可以看到获取到的反序列化器是跟ObjectFormatDescription相关的：

![image.png](images/attach-0ac3e659c4d16f5c40388b93f31d7c23f6f7d7a2.png)

 在其bind方法中，会调用bindContent方法对JSON内容进行处理封装：

![image.png](images/attach-f8ef3f18ff302f7aa59512f3eea9d6c319da968b.png)

 可以看到当满足WeakHash的匹配时，会调用User类的set方法对对应的属性进行赋值,value的获取是通过com.dslplatform.json.JsonReader#readString对JSON进行处理，实际上还是通过com.dslplatform.json.JsonReader#parseString进行解析：

![image.png](images/attach-43ec63bc6a69d4b04d0b413b9d0af352f5ee1469.png)

 简单看看ObjectFormatDescription#bindContent的逻辑，看看WeakHash的具体含义。在ObjectFormatDescription#bindContent的逻辑中,首先检查当前的 JSON 标记是否为`}`,如果是,则检查是否有必填属性未被赋值：

![image.png](images/attach-15e825871c2697587e4831fb2cdfe224dee372f2.png)

 否则进入JSON的解析，进入一个循环,遍历所有需要绑定的属性。在循环中,对于每个属性,计算属性名称的WeakHash,并与预计算的WeakHash进行比较。若两者匹配,则进一步比较属性名称是否完全匹配，若匹配则对对应的属性进行赋值，如果下一个标记是逗号`,`,则继续读取下一个属性。否则,退出循环：

![image.png](images/attach-0ca08a36b34bbeec845e57d1a5325dc05520dbdf.png)

 也就是说，WeakHash主要跟反序列化过程中匹配的属性有关。在fillNameWeakHash中，主要是通过calcWeakHash方法来计算Weakhash的，查看具体的计算方式：

![image.png](images/attach-3b9f31afd91674be532db791e14c54455d21ebe5.png)

 在calcWeakHash方法中，首先还是判断是否以`"`开头，然后进入一个循环,从 JSON 数据流中读取属性名称的字节,并将它们累加到 `hash` 中：

- **如果遇到反斜杠`\`(表示转义字符),则跳过下一个字节**
- 如果遇到双引号 `"`(表示属性名称的结束),则退出循环
- 如果读取到数据流的末尾,则调用 `calcWeakHashAndCopyName` 方法计算最终的哈希值并复制属性名称

![image.png](images/attach-8d7cd31356353591a906e5a5f8fbf624f294a242.png)

 这里有一个比较关键的节点是，当遇到**反斜杠`\`时，不会进一步对类似Unicod等字符进行额外的处理，直接跳过下一个字节**。那么是否说明当使用这种方式进行JSON解析时，无法识别Unicode编码的key呢？

![image.png](images/attach-89fb0f093fb6e6d117521b535c1bc1c60a472296.png)

 这里从debug信息可以看到，以属性activity为例，预计算的WeakHash为1050：

![image.png](images/attach-2f243c09527a521174a41d74edcffb9fdf421cf3.png)

 若经过Unicode编码处理后，获取到的WeakHash为1269，此时由于两者不一致，导致不会进一步调用对应属性的set方法，设置对应的内容:

![image.png](images/attach-5d9d0de97a55f7a45fd8ae107efb26ec7fd0802a.png)

 也就是说，跟基础类型Map相比，类似`User User = jsonReader.next(User.class);`自定义类型的解析，DSL-JSON仅仅支持值的Unicode编码，不像fastjson/jackson等也支持Key的Unicode编码。

 验证上述的猜想：

- 对key进行Unicode编码，此时输出的activityId内容为null：

```Java
String body = "{\"\\u0061ctivityId\":\"321\"}";
DslJson<Object> dslJson = new DslJson<Object>();
JsonReader<Object> jsonReader = dslJson.newReader(buff);
User user = jsonReader.next(User.class);
System.out.println(user.getActivityId());
```

![image.png](images/attach-c3bb494a6d1b572e9eeecea8c5a6adb5fb996d8d.png)

- 对value进行Unicode变么，此时正常输出activityId内容

```Java
String body = "{\"activityId\":\"\\u0033\\u0032\\u0031\"}";
DslJson<Object> dslJson = new DslJson<Object>();
JsonReader<Object> jsonReader = dslJson.newReader(buff);
User user = jsonReader.next(User.class);
System.out.println(user.getActivityId());
```

![image.png](images/attach-40fe3708895a03abf31f224e364b170ed0ad2a4d.png)

 默认情况下，类似重复键值的情况，Jackson/Fastjson等主流的解析器默认会保留最后一个出现的键值对。当相关安全措施（例如鉴权、参数检查等）使用了DSL-JSON进行JSON解析时，若与实际Controller的解析模式不一致，可以考虑结合重复键值+Unicode解码差异的特点来尝试绕过。

 例如上面的例子，由于无法识别自定义类型属性key的Unicode编码，对于下面的JSON重复键值内容只能取前者123，而其他解析器则默认获取后者，这里存在解析差异，在特定情况下可以达到参数走私的效果，在日常代码审计过程中需要额外的关注：

```JSON
{"activityId":"123","\u0061ctivityId":"321"}
```

2.2 注释符截断
---------

 部分JSON解析库支持在JSON中插入注释符，注释符中的任何字符不会被解析。例如gson支持/\*\*/（多行）、//（单行）、#（单行）这三类注释符，Fastjson支持除#以外的注释符等。而**DSL-JSON在自定义类型解析时，对注释符的解析“不敏感”。**在特定的情况下也会存在参数走私的风险。

 例如下面的例子：

```Java
String body ="{\"test\":1/*,\"activityId\":\"333\",\"test\":*/,\"activityId\":\"321\"}";
DslJson<Object> dslJson = new DslJson<Object>();
final byte[] buff = body.getBytes("UTF-8");
JsonReader<Object> jsonReader = dslJson.newReader(buff);
User user = jsonReader.next(User.class);
System.out.println("DSL-JSON parse result:"+user.getActivityId());
```

 最终获取到的内容是注释内的内容：

![image.png](images/attach-b2d31ac25a3822669f72502797653ba0d8970c74.png)

 原因也很简单，因为在计算WeakHash后，类似上面请求的json内容，test并不是是指定类型User的属性，并不会参与解析，经过`,`分割后，注释内容里的activityId被当成正常JSON内容参与了解析。

 对于Fastjson/Gson能支持注释解析的解析器会存在解析差异，存在参数走私的风险：

![image.png](images/attach-3b901f0aca25786584e985c4e22f983ecd1b9c3b.png)

0x03 其他
=======

 此外，部分畸形JSON在DSL-JSON仍可正常解析，例如额外的`}`并不会又影响JSON的解析，会直接截断对应的内容。通过畸形解析的差异，在特定的场景也可能达到参数走私的效果：

![image.png](images/attach-5dd4557c77892be5d0fff1737e66037321e69b53.png)
