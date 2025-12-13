# SpringWeb中获取路径前缀的方式与潜在的权限绕过风险

> **来源**: https://forum.butian.net/share/2761  
> **文章ID**: 2761

---

0x00 前言
=======

 在实际业务中，为了防止越权操作，通常会根据对应的URL进行相关的鉴权操作。SpringWeb中获取当前请求路径的方式可以参考https://forum.butian.net/share/2606。

 除了实际访问的资源路径以外，通过动态配置资源权限时，很多时候在数据库或者权限中台配置的鉴权请求路径通常还会包含路径前缀。下面看看SpringWeb路径前缀具体内容。

0x01 SpringWeb路径前缀
==================

 DispatcherServlet从Tomcat中获取的Request中包含了完整的URL，并且会按照Servlet的映射路径把路径划分为contextPath、servletPath和pathInfo三部分。

![image.png](images/attach-127ec4ab222fd91ba8c478e54c7ce010fd147c1d.png)

 在Spring MVC中，`spring.mvc.servlet.path` 和 `server.servlet.context-path` 是两个配置属性，用于配置 contextPath、servletPath的相关信息。

1.1 contextPath
---------------

 `contextPath` 是Web应用程序在Web服务器上运行时的上下文路径。在一个Web容器中可以同时运行多个Web应用程序，为了区分它们，每个Web应用都有一个唯一的上下文路径。可以通过`server.servlet.context-path`属性进行配置。

通过下面的配置，会影响整个应用程序的上下文路径。此时个应用程序将在 `/myapp` 路径下访问，而不是根路径`/`:

```Java
server.servlet.context-path=/myapp
```

1.2 servletPath
---------------

 `servletPath` 是指请求中用于定位到Servlet的部分路径。在Spring MVC中，DispatcherServlet负责处理请求。一般指的是DispatcherServlet 的路径。可以通过`spring.mvc.servlet.path` 属性进行配置。（在 SpringBoot 的早期版本中，该属性位于 `ServerProperties` 类中，名称为 `server.servlet-path=/`。从 2.1.x 版开始，该属性被移至 `WebMvcProperties` 类，并更名为 `spring.mvc.servlet.path=/`）

 通过下面的配置，主要影响 DispatcherServlet 的路径， DispatcherServlet 的处理将映射到 `/api/*`，其下的所有请求都将由 DispatcherServlet 处理：

```Java
spring.mvc.servlet.path=/api
```

 结合上述的两个配置，DispatcherServlet 将处理 `/api/*` 的请求，而整个应用程序将在 `/myapp` 路径下访问。最终通过访问`http://localhost:8080/myapp/api/someEndpoint`来访问Controller中配置的资源。

0x02 servletPath的检查机制
=====================

 前面提到，可以通过配置`spring.mvc.servlet.path` 来影响 DispatcherServlet 的路径。Spring Web解析请求时，高版本会通过PathPattern进行解析。同样的这里会引入对servletPath的检查机制。下面是具体的过程。

 当Spring MVC接收到请求时，Servlet容器会调用DispatcherServlet的service方法（方法的实现在其父类FrameworkServlet中定义），这里会根据不同的请求方法，调用processRequest方法，例如GET请求会调用doGet方法。在执行doService方法后，继而调用doDispatch方法处理。

 而在doService方法中，根据parseRequestPath的值，会进行对应的处理：

![image.png](images/attach-39ece09d80a1add4ebdbca781716a3540b1b39eb.png)

 通过org.springframework.web.servlet.DispatcherServlet#initHandlerMapping可知,当使用了PathPattern进行路径匹配时，该值会设置为true：

![image.png](images/attach-252394e0f41e76ecf886eab92fad5ae64b7da6ae.png)

 继续跟进对应的处理逻辑，在parseAndCache方法中，会调用ServletRequestPathUtils对请求进行解析：

![image.png](images/attach-045daa14da86c72101accf5ef3c9a6a08b555f2b.png)

 在parse中会尝试获取servletPath，如果servletPathPrefix不为null，会处理`spring.mvc.servlet.path`配置的内容并返回：

![image.png](images/attach-17d66d8e4e2c4470af13d0da072e734decad6adf.png)

 这里主要是通过getServletPathPrefix来获取servletPathPrefix的，这里主要是通过request.getServletPath获取并进行编码操作：

![image.png](images/attach-bc463d5bfb8f85d8c697a8592aae5d03529401cd.png)

 当存在servletPathPrefix时，会创建ServletRequestPath对象：

![image.png](images/attach-b11f44001ad91468ee145e8787f696d7d641d244.png)

 这里将contextPath和servletPathPrefix拼接，然后调用RequestPath.parse方法进行处理：

![image.png](images/attach-1438eec820457e4970aec3d0834ffc5f08fb9538.png)

 在initContextPath方法中，这里调用了validateContextPath方法进行了相关的检查：

![image.png](images/attach-49f9d2f1651d9b1f1cdfa57901f54ab0724887fa.png)

 可以看到，当fullPath不以contextPath和servletPathPrefix拼接内容开头时，会抛出Invalid contextPath的异常：

![image.png](images/attach-f864ff7fe126808982c1ee80639f802087d4a56b.png)

 fullPath是从前面parse方法的request.getRequestURI()方法获取的，没有经过相关归一化的处理：

![image.png](images/attach-e1774c88fcf8c96d9f9d0b907e96c484d1a6a13b.png)

 那么也就是说，假设当前servletPath配置如下：

```Java
spring.mvc.servlet.path=/app
```

 当尝试以`/ap%70`(%70是p的URL编码)进行访问时，因为获取到的servletPathPrefix是经过URL解码处理的，在validateContextPath方法中会因为匹配不一致而抛出异常：

![image.png](images/attach-428940c0561f8aa6a84bd5feffd63c906313b5cf.png)

 同理`app;`的方式也是一样的。从一定的程度访问了通过编码等方式进行URL权限的绕过。

2.1 其他
------

 在实际的鉴权组件中，通常会获取当前请求的路径进行操作。获取到的请求路径没有经过规范化处理的话，结合对应的鉴权逻辑（白名单，模式匹配等）可能存在绕过的风险。跟资源路径一样，若路径前缀也是匹配的内容，不规范的获取方式同样会存在绕过风险。

 例如如下contextPath仍可正常访问对应的Controller资源接口：

```Java
server.servlet.context-path=/app/web
```

![image.png](images/attach-81d44627a9f643d423f14855502374daef358c31.png)

 上面的例子是在spring-boot-starter-2.7.12.jar下运行的。这里可能会有一个疑问，高版本SpringWeb在解析时使用的是PathPattern，会因为解析模式的不同导致在路径匹配时经过不同的处理。默认情况下PathPattern是无法处理类似//的情况的，但是上述案例明显正常获取到了对应的资源：

![image.png](images/attach-f41ac03e8c4e7e5cd416f798dc498a4392fb3a60.png)

 实际上在匹配路径时，contextPath并不会影响，因为在构建requestPath时会根据contextPath进行路径的分离：

![image.png](images/attach-c4691ecadca5ad93b03b6f791b5071eb82065b81.png)

![image.png](images/attach-a4ff80f8752a71ad6cb36560e648ca2046b57406.png)

 而从前面的分析也可以知道，当使用PathPattern进行解析时，会将contextPath和servletPathPrefix进行拼接合并，也就是说不论是contextPath还是servletPath都不会影响后续路径匹配的过程，contextPath的匹配在调用DispatcherServlet之前就已经处理了，所以上述例子中，即使是在contextPath中包含了//，使用PathPattern模式的SpringWeb仍可正常访问。

 而当低版本使用AntPathMatcher进行路径匹配时：

![image.png](images/attach-0eaec39eaab40a781b00ed2bdaafcac0eb162117.png)

 在getPathWithinApplication方法中，同样获取了contextPath进行路径的分离：

![image.png](images/attach-d45caa972a29e12f70e2136983aa83ed2c8ed0d1.png)

 只是这里并没有考虑servletPath：

![image.png](images/attach-09a601c4ed2c9a5fa38c47b5b41e21737f5f06e3.png)

 但是这里在获取contextPath时仅仅进行了解码操作，而获取requestUri时额外调用了getSanitizedPath方法对多个`/`进行了处理，也就是说如果contextPath包含多个`/`的话，可能会导致路径无法匹配：

![image.png](images/attach-b0a26607519e28f9672e50bb5fde1000561bd663.png)

 而servletPath的处理是主要依赖于alwaysUseFullPath属性，通过getPathWithinServletMapping方法进行额外处理：

![image.png](images/attach-91d9b7bad575a5d83051069f5bff5f7a6fa0a744.png)

 Spring也对类似的问题进行了说明，具体可见https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-servlet/handlermapping-path.html

0x03 获取路径前缀的方式
==============

 在SpringWeb中，一般获取当前请求路径前缀主要有以下方式：

- 通过`javax.servlet.http.HttpServletRequest`来获取请求的上下文
- SpringWeb中自带的方法

3.1 使用javax.servlet.http.HttpServletRequest
-------------------------------------------

 下面看看通过javax.servlet.http.HttpServletRequest分别是怎么获取对应的contextPath和servletPath的：

### 3.1.1 contextPath

 以如下配置为例，查看不同方法获取到的contextPath的区别：

```Java
server.servlet.context-path=/app/web
```

- **request.getContextPath()**

 这里获取到的上下文路径默认情况下是没有经过归一化处理的（SpringWeb默认使用tomcat进行解析）：

![image.png](images/attach-db25aefa20565f1757eb9807edfcdeb0d1045635.png)

 这种情况下获取到的路径前缀存在风险的，结合类似URL编码的方式可能可以绕过现有的鉴权措施。

- **request.getServletContext().getContextPath()**

 通过HttpServletRequest对象的getServletContext()方法获取ServletContext，然后再调用getContextPath()方法。

 同样是上面的例子，此时可以看到获取到的contextPath已经经过一系列的归一化处理：

![image.png](images/attach-176d0734b40d3e6af4a1e1a4e55b79a8e0640d2e.png)

### 3.1.2 servletPath

 以如下配置为例，查看不同方法获取到的servletPath的区别：

```Java
spring.mvc.servlet.path=/demo
server.servlet.context-path=/app/web
```

- **request.getServletPath()**

 `getServletPath()` 方法返回请求的Servlet路径。Servlet路径是请求的相对于上下文根的部分，不包括任何额外的路径信息。这个方法通常用于获取处理请求的Servlet路径。

 当尝试以畸形前缀进行请求时，可以看到听过request.getServletPath()获取到的servletPath已经经过一系列的归一化处理：

![image.png](images/attach-30d1e831f33926857947ee3d6d18bdc66ad9e6e7.png)

![image.png](images/attach-3f5b134908e9687a1070eb1403d488f9c1c1dfd1.png)

3.2 SpringWeb中自带的方法
-------------------

### 3.2.1 contextPath

#### 3.2.1.1 RequestContextUtils

 `org.springframework.web.servlet.support.RequestContextUtils` 是 Spring Web MVC 框架中的一个工具类，用于获取当前请求的`RequestContext`。最常用的方法是`findWebApplicationContext(request)`，一般用于查找当前请求的 `WebApplicationContext`，其是 Spring Web MVC 应用程序中的一个关键接口，它是Spring IoC容器的一种扩展，用于管理Web层的Bean：

![image.png](images/attach-c7042fc52791c057b6045bb7b860c6c8537442cb.png)

 这里可以获取ServletContext，然后再调用getContextPath()方法：

```Java
RequestContextUtils.findWebApplicationContext(request).getServletContext().getContextPath()
```

 得到的contextPath是经过归一化处理的。

#### 3.2.1.2 ServletRequestPathUtils

 `org.springframework.web.util.ServletRequestPathUtils` 是 Spring Framework 提供的一个工具类，用于处理`ServletRequest`（通常是`HttpServletRequest`）的请求路径信息。主要用于从请求中获取有关路径的信息，并提供了一些方法来处理和解析路径。

 前面在servletPath的检查机制时提到过，当使用PathPattern进行解析时，会进行一系列的处理并且将处理后的结果封装到PATH\_ATTRUBYTE属性中：

![image.png](images/attach-e9a13f28566cef0ad2d33afb1919e543becd38d5.png)

 而ServletRequestPathUtils可以通过getParsedRequestPath进行获取，并调用对应的方法获取contextPath：

![image.png](images/attach-6e8ebd3ca0787dde79a85f4a1d5165e976fbfa27.png)

```Java
ServletRequestPathUtils.getParsedRequestPath(request).contextPath().value()
```

 根据前面的分析，在处理过程中并没有对contextPath进行相关的归一化处理，所以通过这种方式获取到的contextPath在某种场景下也是存在风险的：

![image.png](images/attach-8a8c11a614cbfb36ba81c5c8f637060c1adeb270.png)

 同理，直接使用parseAndCache方法处理获取到的contextPath也是没有进行相关的归一化处理的：

```Java
ServletRequestPathUtils.parseAndCache(request).contextPath().value()
```

 以上是SpringWeb中常见的获取当前请求路径前缀的方式。在实际代码审计过程中可以根据不同的方式，结合实际场景判断是否存在绕过的可能。
