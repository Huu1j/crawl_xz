# HessianServlet、HessianServiceExporter场景下的Payload-先知社区

> **来源**: https://xz.aliyun.com/news/17811  
> **文章ID**: 17811

---

## Hession漏洞利用现状

目前 Java 开发框架里使用 Hessian 去做面向对象的 RPC 传输，大部分都是使用 HessianServlet 以及 spring-web 组件里的 `HessianServiceExporter` 去暴露 hessian 服务，但是使用现有工具生成 payload 去打就报各种错，实际上 HessianServlet、`HessianServiceExporter` 在解析 Hessian 序列化数据时会进行一些协议头判断，而 web-chiasn 生成的都是针对自封装调用的 Hessian 直接打的，并没有针对 HessianServlet、HessianServiceExporter 场景做 payload 封装，导致无法攻击成功。

报错如下:

![image.png](images/img_17811_000.png)  
![image.png](images/img_17811_001.png)

## 组件代码分析

### 访问特征

* 针对 `HessianServiceExporter` 发布的 Hessian 服务，一般都是这么写的

```
<bean name="/HessianService"
        class="org.springframework.remoting.caucho.HessianServiceExporter">
        <property name="service" ref="HessianService" />
</bean>
```

![image.png](images/img_17811_002.png)

访问特征如下

![image.png](images/img_17811_003.png)

![image.png](images/img_17811_004.png)

* 针对 Servlet 暴漏的服务

```
    <servlet>
        <servlet-name>hessian</servlet-name>
        <servlet-class>com.servletserver.ServletBasicService</servlet-class>
    </servlet>
    <servlet-mapping>
        <servlet-name>hessian</servlet-name>
        <url-pattern>/hessian</url-pattern>
    </servlet-mapping>

package com.servletserver;
import com.caucho.hessian.server.HessianServlet;
import java.util.HashMap;

public class ServletBasicService extends HessianServlet implements ServletBasic {
    @Override
    public String SayHello(HashMap o) {
        return "123"+ o.toString();
    }
}
```

访问特征如下

![image.png](images/img_17811_005.png)

### HessianServiceExporter 组件代码分析

POST 请求会进入到 invoke，对整个请求体(传入的序列化 payload)和响应体转发，跟进后赋值

![image.png](images/img_17811_006.png)

拿到输入流的第一位

![image.png](images/img_17811_007.png)首先进行第一位字符判断，是否是如下三种，H、C、c，若不是，直接产生第一种报错。

![image.png](images/img_17811_008.png)

倘若协议头为 H，还需要进行判断第二位是不是 `0x02`，也就是校验版本号是不是 Hessian2.0 是的话才会进行反序列化。这里因为正常生成的 payload 只是满足原生 Hessian 反序列化的要求，所以会报第二种错。

![image.png](images/img_17811_009.png)

进到 readCall 方法后，要满足第四位为 C (\x43)

![image.png](images/img_17811_010.png)

这样才能正常进入到 `skeleton.invoke(in, out);`

![image.png](images/img_17811_011.png)

然后后面就是正常的反序列化流程了，这里不再赘述反序列化流程，可以看下调用栈，有需要的自己查资料

![image.png](images/img_17811_012.png)

所以可构造出\x48\x02\x00\x43 ，此时即可不报错，并且执行 payload

![image.png](images/img_17811_013.png)

倘若协议头为 C，通过 reset() 回滚流的位置，重新读取数据，也没啥特殊处理的

![image.png](images/img_17811_014.png)

就加个\x43 就行

![image.png](images/img_17811_015.png)

倘若协议头为 c，创建 Hessian 1.0 输入流，如果主版本 ≥2，用 Hessian 2.0 输出,否则用 Hessian 1.0 输出

![image.png](images/img_17811_016.png)

那根据上文就可以构造出\x63\x02\x00，同时这里的 HessianInput 是用 1.0 的 payload 打，实际上这样是不能触发 payload 的，因为 HessianInput 的 readMethod 并不像 HessianInput2 一样里面可以调到 readObject

![image.png](images/img_17811_017.png)

所以反序列化点是在这里

![image.png](images/img_17811_018.png)

但是目前 `in.readHeader()` 获取到的是 null，导致无法反序列化，看下逻辑

![image.png](images/img_17811_019.png)

这段代码的意思就是判断首位是否是 H，如果是再根据第二位和第三位指定要读取的长度，使用 parseChar 解析出指定的长度并返回，就看到三个 read()，第一位需要是 H，然后第二位给个\x00 赋 0 值即可，第三位随意，给个几，后面就跟几个字符串（感觉可以天然的加垃圾数据）那也就是在原先的基础上加一个\x48\x00\x03abc 这样就满足了

![image.png](images/img_17811_020.png)

### HessianServlet 代码分析

先到 HessianServlet 的 service

![image.png](images/img_17811_021.png)

也是读取协议头，跟进看下

![image.png](images/img_17811_022.png)

不一样的地方是这里直接读了三位，且由之前的 c、C、H 换成了 c、r、H ，C 没了，r 后续也用不上。所以就两种，c、H，c 和之前的一样也是根据第二位判断回复版本，H 就是 Hessian2.0，第三位为\x00 即可

![image.png](images/img_17811_023.png)

通用的，逻辑还是一样，Hessian2.0 依然会多读一位 \x43

![image.png](images/img_17811_024.png)

然后到了 invoke 就一模一样了，不再赘述。

![image.png](images/img_17811_025.png)

## 总结

对于 chains 生成的 payload，针对的是入参点直接在 HessianInput()的情况，也就是自封装的比如 xxl-job 最后的调用点，如下代码，就没协议头的判断，就是正常的 Hessian 序列化流就行

```
// 直接反序列化用户输入的字节流
public class VulnerableService {
    public Object deserialize(byte[] data) throws IOException {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        HessianInput input = new HessianInput(bis);
        return input.readObject(); // 关键漏洞点：直接反序列化为Object
    }
}
```

而对于 Spring-web 包内，则是提供了 `org.springframework.remoting.caucho.HessianServiceExporter` 用来暴露远程调用的接口和实现类。

对于 Servlet，则是提供了 `com.caucho.hessian.server.HessianServlet` 用来暴露远程调用的接口和实现类。

使用该类则需要添加协议头处理，对应的协议头总结如下。

|  |  |  |  |  |  |  |
| --- | --- | --- | --- | --- | --- | --- |
| 协议头 | ascii | hex | 版本 | 输入流 | 输出流 | 备注 |
| `'H'` | 72 | \x48\x02\x00\x43 | Hessian 2.0 | `Hessian2Input` | `Hessian2Output` | Hessian2.0 稳定利用 |
| `'C'` | 67 | \x43 | Hessian 2.0 | `Hessian2Input` | `Hessian2Output` | 仅适用于 `HessianServiceExporter` |
| `'c'` | 99 | \x63\x02\x00\x48\x00\x03abc | Hessian 1.0 | `HessianInput` | `Hessian(2)Output` | 根据版本选择输出流。 |
