# jsoniter参数走私浅析

> **来源**: https://forum.butian.net/share/3016  
> **文章ID**: 3016

---

0x00 前言
=======

 `json-iterator`（通常简称为 Jsoniter）是一个高性能的 JSON 解析库，它为 Java 和 Go 语言提供了简单而高效的 API 来进行 JSON 的序列化和反序列化操作。Jsoniter 旨在提供比传统 JSON 解析器更快的性能，同时保持 API 的灵活性和易用性。

![image.png](images/attach-50d69521e9feec4bee5e699106317e4d6956f5ba.png)

 对于Java的使用场景可以直接引入对应的依赖进行使用：

![image.png](images/attach-1283472fddd6582bc90ba376666f89596dda4513.png)

 其提供了简洁的API进行相关JSON的反序列化操作，例如下面的例子：

```Java
JsonIterator.deserialize(body,User.class);
```

 同时提供了 `Any` 类型,支持无需定义数据类即可方便地访问 JSON 数据：

```Java
try (JsonIterator iter = JsonIterator.parse(body)) {
        Any any = iter.readAny();
    String activityId = any.toString("activityId");
    ......
}
```

 下面简单看看具体的解析过程：

0x01 jsoniter解析过程
=================

 以com.jsoniter.JsonIterator#deserialize方法为例，查看指定类型时具体的解析过程，本质上调用的是com.jsoniter.JsonIterator#read进行处理：

![image.png](images/attach-70e4ac5314afd010b025f5d5018c342e5639a1a3.png)

 首先调用findLastNotSpacePos方法查找输入字节数组中最后一个非空白字符的位置，忽略 JSON 数据尾部的空白字符（包含空白符、\\t、\\n、\\r）：

![image.png](images/attach-e4f7b8ac9a0c2d803de7efec34fbe2d4f29b976d.png)

 然后使用 `JsonIterator` 读取 JSON 数据并反序列化成指定类 `clazz` 的实例，主要是通过IterImpl#read进行处理，这里实际上会通过ReflectionObjectDecoder 类的一个方法 `decode_`进行处理：

![image.png](images/attach-813f65b1ed37ac7c7ea64892a8e2ea8464d47eca.png)

 在decode\_方法中，如果 JSON 数据包含对象的开始标记,则进入循环读取每个属性，进行反序列化处理：

![image.png](images/attach-147787bfca5a58cfcced5992c24cf83663efdfaa.png)

 例如filedName会通过com.jsoniter.IterImpl#readObjectFieldAsSlice方法进行处理：

![image.png](images/attach-8897f91f71860c24dbdb213af9cfeb4983673afe.png)

 在readSlice方法中，如果标记不是双引号 `"`(表示字符串的开始),则抛出一个异常。 否则调用 IterImplString.findSliceEnd 方法查找字符串的结束位置：

![image.png](images/attach-1697abee6546000aa3d655906ab430a5d848c614.png)

 findSliceEnd这个方法会在 JSON 数据中搜索下一个双引号的位置,表示字符串的结束，如果对应的字符包含`\\`，则会抛出`slice does not support escape char`异常：

![image.png](images/attach-1edc0b620e1f2dca9eb3c3a1a14644e7b7553b9e.png)

 正常情况下，类似`{"\u0061ctivityId":"123"}`是可以正常解析的，但是由于findSliceEnd对`\\`的逻辑，导致com.jsoniter.JsonIterator#deserialize在指定类型解析时无法处理存在unicode编码的JSON字符串：

![image.png](images/attach-01a391266acb684eecf2d67ef3aa81fd4a9b7644.png)

 处理完fieldName后，使用 `decodeBinding` 方法反序列化属性值,并通过 `setToBinding` 方法将其设置到对象实例中：

![image.png](images/attach-e755a25d0c332eb729629c420a68e9ddb1152f17.png)

 解析完后，如果对应内容为`,`,则重复类似的过程：

![image.png](images/attach-6c51efbdb564e488c174ca9db9d1120f8fdd7405.png)

 对于重复键的情况，会调用invoke方法重新赋值，也就是说默认情况下对于重复键，jsoniter会默认取后者：

![image.png](images/attach-dd2332a2158ad591e89d7626a6ac3e15019c90e5.png)

 然后处理剩余的缺失属性，并且如果在反序列化过程中遇到任何未知属性,则将它们存储在 extra 映射中。在最后,使用 setExtra 方法将这些额外的属性设置到对象实例中。并返回反序列化后的对象实例：

![image.png](images/attach-fa90b05e8722500c410f2888879776b65abeba4e.png)

 **此外，jsoniter还提供了`Any`类型,支持无需定义数据模型类即可方便地访问 JSON 数据**。`Any` 是 Jsoniter 库中用于表示任意 JSON 值的一种数据结构。

```Java
Any any = JsonIterator.deserialize(body);
```

 主要是通过IterImpl#readAny方法进行处理：

![image.png](images/attach-0d032212870e8f610a3411a526b17d86e797ea54.png)

 在解析时首先会记录当前 JSON 数据缓冲区的起始位置 start，这里会剔除掉类似\\n这类的无关内容，然后根据对应的内容进行进一步的处理，类似Json一般会调用skipObject进行处理：

![image.png](images/attach-e5f756217984890451776567b95acaddf2e749d1.png)

 这里的逻辑主要是假设对象的开始位置已经被正确识别,负责跳过对应的内容的解析。然后调用对应的构造方法完成相关的封装：

![image.png](images/attach-13b153d3ae83bf84e2068ede6afafe29dbbba48e.png)

 整体的解析过程跟DSL-JSON比较类似。后续只需要调用对应的方法，即可获取对应的内容：

```Java
Any any = JsonIterator.deserialize(body);
any.toString("activityId");
any.asMap().get("activityId");
```

0x02 参数走私场景
===========

 下面结合JavaWeb中常见的JSON解析库的解析特性，看看其重复键值对情况下潜在的参数走私场景以及在日常审计过程中，需要特别关注的点。

2.1 重复键优先级不一致
-------------

 对于重复键的情况，当指定类型进行解析时，jsoniter会调用invoke方法重新赋值，也就是说默认情况下对于重复键，jsoniter会默认取后者。但是在Any类型解析时，会存在重复键优先级不一致的情况。例如下面的例子：

```Java
try (JsonIterator iter = JsonIterator.parse(body)) {
    Any any = iter.readAny();
    System.out.println("jsoniter parse toString result::"+any.toString("activityId"));
    System.out.println("jsoniter parse asMap() result:"+any.asMap().get("activityId"));
 }
```

 可以看到默认情况下，两种方式获取到的重复键优先级并不一致：

![image.png](images/attach-0c497ad656e9426f447bd6723b52e5c45ee1e231.png)

 对于`any.toString("activityId")`的解析，实际上是在com.jsoniter.any.ObjectLazyAny#fillCacheUntil方法处理的，在获取到当前JSON的field及value后，若对应field跟实际获取的target一致，则直接返回，也就是说这里**默认会获取重复键的前者内容**：

![image.png](images/attach-25cdd8dfef370445e0bf4e96b4f8a0d00efb4526.png)

 而对于`any.asMap().get("activityId")`，实际上是从cache属性获取内容：

![image.png](images/attach-d31e6ca97d46803708b8d4221dd9d3fb1907e0b0.png)

 而cache属性在解析时会通过HashMap的数据结构进行管理：

![image.png](images/attach-7491e46c97499e7f8e9844413b949023348aaa1b.png)

 在解析遇到`,`，会重复解析并调用put方法重新赋值，那么对于重复键的情况，会对原来的内容进行覆盖，这也是通过两种方式获取到的内容会不一致的原因：

![image.png](images/attach-70713e3b156c0dcfc22558628dad39ae70a24aa8.png)

 在实际代码审计过程中，尤其是一些通用安全措施，若使用any.toString()获取对应的业务参数进行安全检查，结合类似jackson等常见解析器的解析特点（重复键默认取后者），会存在参数走私的风险。可以重点关注这类的问题。

2.2 注释符截断
---------

 部分JSON解析库支持在JSON中插入注释符，注释符中的任何字符不会被解析。例如gson支持/\*\*/（多行）、//（单行）、#（单行）这三类注释符，Fastjson支持除#以外的注释符等。查看jsoniter的解析逻辑。

 以`any.toString()`为例，查看具体的解析过程，实际获取是在com.jsoniter.any.ObjectLazyAny#fillCacheUntil方法处理的：

![image.png](images/attach-4a54213cf5fae2c77a1a9be43fae34e67b7ce9d0.png)

 值的获取主要是在com.jsoniter.IterImpl#readAny方法处理的,这里会对`"`、`[`、`f`、`n`、`t`以及`{`开头的内容进行处理，实际上就是覆盖类似boolean等基础数据类型，若均不以类似的开头，则判断是否是Number，再进行进一步的处理：

![image.png](images/attach-2a8fc8cf21ad7754d0a00a9e0e833602302f62a7.png)

 在 skipNumber方法中，主要是判断当前值是否包含小数点或指数部分，然后完成对应的封装：

![image.png](images/attach-c7a82863a558971ffa6a51436f5e05b219548ad0.png)

 类似注释`/*`的值同样也可以正常解析成"数字"类型：

![image.png](images/attach-f91bb8f0e695a6f14219d81882bc188008f33825.png)

 也就是说**jsoniter Any 类型解析时，对注释符的解析“不敏感”。**在特定的情况下也会存在参数走私的风险。例如下面的例子：

```JSON
String body ="{\"test\":1/*,\"activityId\":\"333\",\"test\":*/,\"activityId\":\"321\"}";
Any any = JsonIterator.deserialize(body);
System.out.println("jsoniter parse result:"+any.asMap().get("activityId"));
```

 可以看到本该是注释内容的activityId，被当成正常内容进行解析，在特定的情况下可能会存在参数走私的风险：

![image.png](images/attach-47763fd3fce241b79d5e1a95ecd84c6a2f53e41f.png)

0x03 其他
=======

 jsoniter整体的解析过程跟DSL-JSON比较类似。但是由于findSliceEnd对`\\`的逻辑，导致**在指定类型解析**时无法处理存在unicode编码的JSON字符串：

![image.png](images/attach-91e7123002805adeb47e8f75433dba0bc05ff21b.png)

 而Any类型的解析，在通过readObjectFieldAsString获取对应属性时，本质上是通过IterImpl#readStringSlowPath方法进行处理的：

![image.png](images/attach-8ee9aadd030b22bb6d5a48726021857418547bb4.png)

 在IterImpl#readStringSlowPath方法会对unicode编码进行对应的处理：

![image.png](images/attach-0ecb5273494518a83c097007d2473f5385e0d220.png)

 不然还可以考虑结合类似DSL-JSON重复键值+Unicode解码差异的特点来尝试绕过。DSL-JSON的解析可见https://forum.butian.net/share/2994
