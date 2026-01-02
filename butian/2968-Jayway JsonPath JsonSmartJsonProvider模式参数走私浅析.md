# Jayway JsonPath JsonSmartJsonProvider模式参数走私浅析

> **来源**: https://forum.butian.net/share/2968  
> **文章ID**: 2968

---

0x00 前言
=======

 Jayway JsonPath是json-path开源的一个用于读取 Json 文档的 Java DSL。前面分享了一个Web应用中的鉴权判断措施在解析请求参数时（Jayway JsonPath解析）与Controller的解析方式存在差异，导致了权限绕过的案例。具体可以参考https://forum.butian.net/share/2948 。主要原因是因为在重复键值对的解析时，SpringWeb默认的jackson解析模式跟`JsonSmartJsonProvider`存在差异，导致了绕过。除了Jackson以外，类似Fastjson、gson这类组件也是常用的JSON解析库，当存在JSON解析模式不一致时，结合解析器本身的一些特点，同样也会存在类似的参数走私风险。下面看看Jayway JsonPath参数走私的一些姿势。

![image.png](images/attach-71efe6c14e8f0eadb9500c2f3e2c8d55824a450e.png)

0x01 参数走私场景
===========

 在Jayway JsonPath库中，支持多种JsonProvider，例如可以指定Jackson进行解析。`JsonSmartJsonProvider` 通常是默认的 `JsonProvider` 实现。主要用于解析和生成 JSON 数据。它是 JsonPath 库中的一个核心组件：

![image.png](images/attach-9ed8bd9fabd35da2318b86144e9910fa7b8a0454.png)

 `JsonSmartJsonProvider` 设置键值时，是通过Map进行维护的，也就是说**类似重复键值的情况，默认会保留最后一个出现的键值对**：

![image.png](images/attach-dd56ccf6d39df035a3ab754c1edd1d546db34ff1.png)

 下面结合JavaWeb中常见的JSON解析库的解析特性，看看其重复键值对情况下潜在的参数走私场景。

1.1 注释符
-------

 部分JSON解析库支持在JSON中插入注释符，注释符中的任何字符不会被解析。例如gson支持`/**/（多行）`、`//（单行）`、`#（单行）`这三类注释符，Fastjson支持除`#`以外的注释符等。若`JsonSmartJsonProvider`中，对注释符的解析“不敏感”的话，是否会存在参数走私的风险。做如下猜想，假设请求的JSON内容如下：

```JSON
{
"activityId":123/*,"activityId":"333",
"test":*/
}
```

 正常请求下，Fastjson获取到的activityId应该是123，后续的内容会作为注释忽略，不参与实际键值的解析。若`JsonSmartJsonProvider`中，对注释符的解析“不敏感”，那么实际的解析过程可能如下：

- 首先解析获取到activityId，对应的值为123/\*
- 其次再次解析获取到activityId，对应的值为333，同时结合Map的特点，会覆盖掉前面的值
- 最后解析获取到test，对应的值为\*/

 若猜想成立那么此时存在解析差异，存在参数走私的风险。以前面猜想的JSON内容为例查看具体的解析过程，印证前面的想法：

 在net.minidev.json.parser.JSONParserBase#readFirst方法中，若当前字符是 `{`，表示接下来的元素是一个对象，会调用 this.readObject(mapper) 来解析对象,一般Json解析都会走这个逻辑：

![image.png](images/attach-ab49a7e9172dcb7c9e2c908d164471b7d8f29ae2.png)

 如果当前字符是引号（双引号或单引号），则调用readString读取 JSON 内容，如果当前字符不是引号，方法会调用 `readNQString(stopKey)` 来读取非引号字符串作为key：

![image.png](images/attach-269a09d3d5d3db530d7e352f6404f3738cd1e69c.png)

 这里首先会读取到请求的键activityId，然后是具体值的解析,这里会通过net.minidev.json.parser.JSONParserBase#readMain方法进行处理：

![image.png](images/attach-b813a3f1ef4c98edc8669567d7f5f6c97360df44.png)

 如果内容是数字的话，会调用readNumber方法进行处理：

![image.png](images/attach-497a128d0bfced119f385d375b7a79fce8969bb1.png)

 在net.minidev.json.parser.JSONParserMemory#readNumber方法中，首先调用 `this.read()` 读取第一个字符，然后通过 `this.skipDigits()` 跳过连续的数字字符：

![image.png](images/attach-44e5ed4321f9c1b1554650242d43cb70ef523faf.png)

![image.png](images/attach-70c4f6fdca1fbf1512bfc944360ab71e2b3137fc.png)

 然后会检查小数点或科学计数法，如果当前字符不是`.`、E 或 e，表示可能正在读取一个整数，然后通过 `this.skipSpace()` 跳过空格字符：

![image.png](images/attach-ef634cc70c65b5b673e6df2f2586b72eb3b84dba.png)

 然后检查当前字符是否在有效字符范围内，解析过程中如果遇到非数字字符，调用 `this.skipNQString(stop)` 读取非引号字符串，并根据 this.acceptNonQuote 的值，决定是抛出 ParseException 还是将字符串作为结果返回：

![image.png](images/attach-cc55d3f5688e2cdcdb6f9b4cc58f91113b1b9325.png)

![image.png](images/attach-e85c85930219b4a17d138f9a098ab5b07d9e834a.png)

 最后使用 `this.extractStringTrim(start, this.pos)` 提取从起始位置到当前位置的字符串。注释符同样会作为值的内容参与解析并返回。

 可以看到，此时获取到的键值对如下，并没有对注释符内容进行处理：

![image.png](images/attach-1febb4eb15f4f7f1e9df7b6444cc25ee2cfc7f9a.png)

 对于字符类型的处理，会通过readString方法进行处理，这里同样没有对注释符内容进行处理：

![image.png](images/attach-d879142b2c47b1704127adf80554cb65db1b8aeb.png)

 类似上述的JSON内容，后续获取到的键值对分别为：

![image.png](images/attach-470aed875d9720c9bd54ae50739c78eef577ac84.png)

![image.png](images/attach-ab9d30008a61db93f91bb01c5f7a398a6e8054be.png)

 也就是说，跟前面的猜想是一致的。**在`JsonSmartJsonProvider`解析时，对注释符的解析“不敏感”**。对于Fastjson和Gson来说，默认情况下是支持注释符的，那么可以通过类似的方式进行参数走私。下面看一下具体的例子。这里通过拦截器的方式获取JsonSmartJsonProvider的处理结果：

```Java
DocumentContext context = JsonPath.parse(body);
System.out.println("JsonSmartJsonProvider parse result:"+(String)context.read("$.activityId", String.class, new Predicate[0]));
```

- **Fastjson(支持/\*\*/和//)**

 多行注释符的情况跟前面讨论的一致：

![image.png](images/attach-830cbb1df22cfbc8f451053a662a957567a47b98.png)

![image.png](images/attach-7a3c8e818ac9c3ad4f8ddad37e6484d5a4a44368.png)

 使用单行注释：

![image.png](images/attach-2de6a1ac56c22f2f582deaf2004692bdf896ebe7.png)

![image.png](images/attach-8f2cd19996fafaa0eb043a415f29c46b3874a344.png)

- **Gson（支持/\*\*/、#和//）**

 Gson还支持#的注释符，同理，可以通过如下JSON进行处理,此时Gson获取到的activityId为123，而JsonSmartJsonProvider却是333：

```Java
String body="{\n" +
        "\"activityId\":123#,\"activityId\":\"333\"\n" +
        "}";
```

 除此之外，还可以在实际请求中，加入多个重复键值进行混淆，保证走私的效果。

1.2 特殊字符截断
----------

 一般解析String类型的内容时，会调用net.minidev.json.parser.JSONParserMemory#readString进行处理。若解析的内容包含`\`时（ascii 92），会通过readString2方法进行解析：

![image.png](images/attach-e21e551178ecdf4d375c88018d2eb35aabf14a36.png)

 在readString2方法中可以看到，类似`\u0000`的字符默认情况下会进行截断处理，例如`\\u0061ctivityId\u0000`实际上跟activityId经过处理后是一致的：

```Java
case '\u0000':
case '\u0001':
case '\u0002':
case '\u0003':
case '\u0004':
case '\u0005':
case '\u0006':
case '\u0007':
case '\b':
case '\t':
case '\n':
case '\u000b':
case '\f':
case '\r':
case '\u000e':
case '\u000f':
case '\u0010':
case '\u0011':
case '\u0012':
case '\u0013':
case '\u0014':
case '\u0015':
case '\u0016':
case '\u0017':
case '\u0018':
case '\u0019':
case '\u001b':
case '\u001c':
case '\u001d':
case '\u001e':
case '\u001f':
    if (!this.ignoreControlChar) {
        throw new ParseException(this.pos, 0, this.c);
    }
    break;
case '\u001a':
    throw new ParseException(this.pos - 1, 3, (Object)null);
case '\u007f':
    if (this.ignoreControlChar) {
        break;
    }

    if (this.reject127) {
        throw new ParseException(this.pos, 0, this.c);
    }
```

 也就是说，**当json的key中出现unicode空字符时，Jayway JsonPath对空字符会做截断，但其他库会保留**。以fastjson为例,这里通过拦截器的方式获取JsonSmartJsonProvider的处理结果：

```Java
DocumentContext context = JsonPath.parse(body);
System.out.println("JsonSmartJsonProvider parse result:"+(String)context.read("$.activityId", String.class, new Predicate[0]));
```

 正常情况下返回如下，两者获取到的activityId均为123：

![image.png](images/attach-c85bc38b80c451cfe262849153049b2f04279a7d.png)

![image.png](images/attach-db943ed1b9ea2039a3a5f3b18e9aaa17864634d8.png)

 当引入额外的unicode空字符时，此时存在解析差异。fastjson会认为`\\u0061ctivityId\u0000`非对应的属性，不参与处理，获取到的activityId为123，而JsonSmartJsonProvider会进行截断，最终获取到的是非预期的值321：

![image.png](images/attach-712bef97ab4fd7bafcc4736963583b404760e789.png)

![image.png](images/attach-d6c0d3e54f80dd8d9afcfe8c1fa6ae37fa17ce3e.png)

 同理，在Gson和Jackson中也会有类似的问题。但是Jackson默认`ALLOW_UNESCAPED_CONTROL_CHARS`设置为false，如果该feature设置为false，若JSON字符串包含未转义的控制字符(值小于32的ASCII字符，包括制表符和换行符)则会抛出异常：

![image.png](images/attach-e07b006077cb2a932a72abadbec503eebde996b4.png)

 在https://forum.butian.net/share/2948 提及过，因为JsonSmartJsonProvider还会对`\u007F`（`\u007F`对应的是删除（Delete）控制字符，通常用作字符串的结束符。它是ASCII控制字符集中的一个成员，表示一个特殊的控制功能，而不是用来显示的字符）进行截断，所以同样也能利用截断的方法进行请求参数的走私。

![image.png](images/attach-176da18b8a64988084f62487dbdfd8fc796306e1.png)

0x02 其他
=======

 上面对字符截断和注释的走私场景进行了简单的分析，实际上通过阅读JsonSmartJsonProvider的解析过程，还有很多跟JSON解析器不一致的地方，例如浮点数和整数的特殊处理，请求值中额外空白字符的截断等等。在特定的场景下说不定也能达到参数走私的效果。在实际代码审计过程中，也可以多注意类似的场景，包括但不限于重复键的优先级（<https://forum.butian.net/share/2904>） 、解析容错机制等。
