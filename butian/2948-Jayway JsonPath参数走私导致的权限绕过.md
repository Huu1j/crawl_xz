# Jayway JsonPath参数走私导致的权限绕过

> **来源**: https://forum.butian.net/share/2948  
> **文章ID**: 2948

---

0x00 前言
=======

 前面分享了一个Web应用的安全处理措施在解析请求参数时与Controller的解析方式存在差异，导致了权限绕过的案例。具体可以参考https://forum.butian.net/share/2904 。在这个例子中，在拦截器会通过fastjson进行参数解析，对关键的资源ID进行权限校验处理，但是由于没有没有注册FastJsonHttpMessageConverter，SpringMVC在实际Controller中还是使用jackson进行参数的解析的。利用两者重复键值解析差异，通过类似如下的请求，在请求时引入额外的换行符即可利用解析差异绕过对应的权限检查：

```JSON
{"activityId"\n:123,"activityId":321}
```

 很多时候在修复的时候可能会选择直接过滤类似换行符等内容。实际上前面的案例还存在其他的方法进行参数走私。同样是上面的例子，**FastJson在反序列化的时候，是对大小写不敏感的。而在Jackson中，`MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES`默认设置为FALSE，在反序列化时是大小写敏感的**。

 在解析具有重复键的JSON对象时，Fastjson和jackson默认行为是保留最后一个出现的键值对，结合大小写不敏感的差异，通过如下JSON请求同样可利用解析差异完成参数走私，绕过对应的权限检查：

```JSON
{"activityId":123,"ActivityId":321}
```

 可能这里会有疑问，大写后的参数应该不满足Jackson的属性对齐特性，会抛出异常。实际上在**Spring/Spring Boot环境下，`DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES`默认其实是关闭的。**

 以springboot为例，如果在编码时没提供自定义的配置，会遵循springboot的默认配置，主要是在org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration类进行配置，这里通过Jackson2ObjectMapperBuilder来创建ObjectMapper：

![image.png](images/attach-2b65e07b1000847022154a1357388b07bab9d525.png)

 没有额外的配置的话，会使用默认的Jackson2ObjectMapperBuilder，查看具体build()的实现：

![image.png](images/attach-12bf9730a4c72916b0e3da7d449a4d2fe41ce9a7.png)

 在configure方法里进行了相关的配置，这里通过调用customizeDefaultFeatures()配置了一些feature：

![image.png](images/attach-21e02107759a0e1ba71f909f3437f5655b0ea155.png)

 查看customizeDefaultFeatures方法的具体实现，可以看到这里将`DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES`设置成了false，Jackson的属性对齐特性不生效了，所以可以通过同名参数的大小写重复键值来尝试参数走私：

![image.png](images/attach-21956f542006a1b44cfad9e64260a03174ff78d6.png)

 综上，可见在实际业务场景中，保持JSON解析模式的一致性是很有必要的。下面看另一个参数走私导致的权限绕过案例。

0x01 案例分析
=========

 同样是前面的场景，研发在修复时并没有选用jackson进行匹配，而是使用了Jayway JsonPath对请求的JsonBody进行处理，获取需要匹配的资源ID再进行鉴权处理。

```Java
DocumentContext context = JsonPath.parse(body);
String value = (String)context.read("$."+key, String.class, new Predicate[0]);
```

 Jayway JsonPath是json-path开源的一个用于读取 Json 文档的 Java DSL：

![image.png](images/attach-1c53027cac09798fe5a160014d93cadc60c777e7.png)

 在Jayway JsonPath库中，`JsonSmartJsonProvider` 通常是默认的 `JsonProvider` 实现。主要用于解析和生成 JSON 数据。它是 JsonPath 库中的一个核心组件：

![image.png](images/attach-8eb07c522365f48a64795de6b548762b87940e98.png)

 下面看看其具体的解析过程。

1.1 JsonSmartJsonProvider解析
---------------------------

 JsonSmartJsonProvider解析首先从com.jayway.jsonpath.spi.json.JsonSmartJsonProvider#parse方法开始：

![image.png](images/attach-bdaa813a481ffe152c35bd4ae71ce90d036ea788.png)

 最终会调用net.minidev.json.parser.JSONParserBase#parse方法进行处理，首先调用 read 方法来读取第一个字符，准备开始解析。然后调用 `readFirst` 方法开始解析过程，`mapper` 参数用于指导解析器如何将 JSON 数据映射到 Java 对象：

![image.png](images/attach-8731ff3c18c4741428808d6f0bf5f5321a5a84f8.png)

 在`readFirst` 方法中，会逐个字符读取进行处理，例如如果当前字符 `this.c` 是空白字符（如空格、制表符、换行符等），则通过 `this.read()` 读取下一个字符并继续循环：

![image.png](images/attach-017d1637c70abad2f369e3bb75dadacbceac841d.png)

 如果当前字符是 `{`，表示接下来的元素是一个对象，会调用 this.readObject(mapper) 来解析对象,一般Json解析都会走这个逻辑：

![image.png](images/attach-f053342e2e529b2e8f3bcfe8db737a0ebf2a4e4e.png)

 在readObject逻辑中，首先检查当前字符是否为 `{`，表示一个 JSON 对象的开始。如果不是，抛出 RuntimeException,并且会检查解析的深度是否超过了限制（默认设置为 400），以避免潜在的无限递归：

![image.png](images/attach-72861f61cec230f3960ef65b722a15f4699952ee.png)

 然后通过 `while(true)` 循环来持续读取 JSON 对象中的键和值。例如键和值之间的空白字符会进行跳过处理：

![image.png](images/attach-447339cdfc0b0d1eb152d58807da42827873bd69.png)

 如果当前字符是引号（双引号或单引号），则读取 JSON 内容，如果当前字符不是引号，方法会调用 `readNQString(stopKey)` 来读取非引号字符串作为key：

![image.png](images/attach-e506b61537dbb4f0ae77c3dbd5cb319069b6007a.png)

 在readString方法中，首先会对单引号或者非单引号的内容进行处理：

![image.png](images/attach-4556d04ea2e5c0b28cb927a9c4c5fb88114b21b1.png)

 如果找到了匹配的结束引号，则会调用extractString方法提取对应的值，如果包含转义字符 `\`（ASCII 码为 92），则调用readString2方法进行处理：

![image.png](images/attach-3a53e17982ed081f1caad9735daf432834eb676f.png)

 readString2主要用于读取和处理包含转义字符和非标准字符的字符串，主要通过 `while(true)` 循环来持续读取字符串，直到遇到匹配的结束引号。例如如果读取的字符是 ASCII 控制字符（如 `\u0000` 到 `\u001f`），并且没有设置 `ignoreControlChar`，则抛出 `ParseException`：

![image.png](images/attach-ff16801e48d2171492233d70ed9a8e0a06749de2.png)

 除此之外，还有做一系列的解码操作：

![image.png](images/attach-aadf967b617d6812de11cb6f8cbe5cf631f46d8a.png)

 在处理完key后，会调用net.minidev.json.parser.JSONParserBase#readMain方法处理对应key的值，在redaMain方法中,同样的会通过 `while(true)` 循环来持续读取 JSON 对象中的键和值，类似会跳过空白字符（如空格、制表符、换行符等）：

![image.png](images/attach-2fd70eff216dac90e0110cf715d44eff102f9f6c.png)

 同时还会对一些特殊的值进行处理，例如如果读取的字符串是 `NaN`，则返回 `0.0F / 0.0`：

![image.png](images/attach-dbb1f3c30ce99a066086ba3ebcd4ab483d2e21bc.png)

 最后使用 `mapper.setValue(current, key, value)` 将键值对设置到当前创建的 Java 对象中。如果下一个字符是 `}`，表示 JSON 对象结束，减少解析深度并返回转换后的 Java 对象:

![image.png](images/attach-8d35b2c34204e0a15edd85564d865fed75f7f4a6.png)

 同时在设置键值时，是通过Map进行维护的，也就是说类似重复键值的情况，跟Jackson类似默认会保留最后一个出现的键值对：

![image.png](images/attach-f67fafb70cb17fc56275521071157b06db0dee8f.png)

 以上是JsonSmartJsonProvider大致的解析过程。因为SpringMVC在实际Controller中默认使用jackson进行参数的解析的。如果能找到跟JsonSmartJsonProvider解析差异，就可以绕过当前的修复措施，下面是具体的绕过过程：

![image.png](images/attach-ad96f9d601f518acc928a2dd93c1a10b66e30a4f.png)

1.2 绕过过程
--------

 前面分析JsonSmartJsonProvider解析过程中，发现当解析的内容包含`\\`时，会通过readString2方法进行解析：

![image.png](images/attach-77108dd5ef726fccaf8b3b5243e1c7f5f9d7c662.png)

 在readString2方法中，类似`\u0000`的字符默认情况下会不参与解析：

![image.png](images/attach-7ce4d69015a920e4d9a562d6ed48757cfa51fed8.png)

 那么是不是可以尝试构造如下的请求boby，`activit\\u0079Id\u0000`在JsonSmartJsonProvider解析时会当成activity进行处理，而对于jackson来说会认为是另外的属性，结合前面重复键值解析取后者的场景，这里最终解析获取到的值两者会有差异，理论上是可以这么绕过对应的鉴权逻辑的:

```Java
{"activit\\u0079Id":1,"activit\\u0079Id\u0000":3}
```

 但是jackson在实际解析时会抛出异常：

![image.png](images/attach-73bf5b87fd298edea760f0baef6360fce285eb96.png)

 主要原因是Jackson在序列化和反序列化的过程中提供了很多特性（Feature），其中`ALLOW_UNESCAPED_CONTROL_CHARS`默认的值设置为false：

![image.png](images/attach-ea385d11ed7ed0802049da28025b8cc0dcb4a2f7.png)

 查阅官方文档，其主要作用是判断是否允许JSON字符串包含未转义的控制字符(值小于32的ASCII字符，包括制表符和换行符)。如果feature设置为false，则在遇到这样的字符时抛出异常：

![image.png](images/attach-550006048edaec8d4e479df8cacb05b34aa96dea.png)

 除此以外，JsonSmartJsonProvider还会对`\u007F`进行跳过处理：

![image.png](images/attach-8d7b6f7fd100a62a39d675c3657dd7f15606fe71.png)

 在ASCII编码中，`\u007F`对应的是删除（Delete）控制字符，通常用作字符串的结束符。它是ASCII控制字符集中的一个成员，表示一个特殊的控制功能，而不是用来显示的字符：

![image.png](images/attach-695d161cf4cc773b95fa8c321f070a04f28dd5a4.png)

 而jackson并没有对`\u007F`进行额外的处理，那么也就是说，可以尝试构造如下的body进行处理：

```Java
{"activit\\u0079Id":1,"activit\\u0079Id\u007F":3}
```

 例如下面的案例代码，可以看到最终的结果两者存在解析差异，那么只需要在首个参数设置他人的资源id，然后第二个在包含`\u007F`内容的重复参数里写入当前用户的资源ID，结合解析差异以及默认情况下重复键值取最后一个的特性，即可绕过对应的鉴权逻辑：

```Java
String body ="{\"activit\\u0079Id\":1,\"activit\\u0079Id\u007F\":3}";

//jackson解析
ObjectMapper objectMapper = new ObjectMapper();
objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);//模拟springboot的默认配置
User user = objectMapper.readValue(body, User.class);
System.out.println("jackson parse result:"+user.getActivityId());
//jackson parse result:1

//JsonSmartJsonProvider解析
DocumentContext context = JsonPath.parse(body);
System.out.println("JsonSmartJsonProvider parse result:"+(String)context.read("$.activityId", String.class, new Predicate[0]));
//JsonSmartJsonProvider parse result:3
```

0x02 其他
=======

 JsonPath还支持多种JsonProvider，这里可以指定Jackson进行解析，保证跟SpringWeb中的@RequestBody的解析模式一致，避免参数走私导致的绕过风险：

```Java
Configuration.setDefaults(new Configuration.Defaults() {

    private final JsonProvider jsonProvider = new JacksonJsonProvider();
    private final MappingProvider mappingProvider = new JacksonMappingProvider();

    @Override
    public JsonProvider jsonProvider() {
        return jsonProvider;
    }

    @Override
    public MappingProvider mappingProvider() {
        return mappingProvider;
    }

    @Override
    public Set<Option> options() {
        return EnumSet.noneOf(Option.class);
    }
});
```
