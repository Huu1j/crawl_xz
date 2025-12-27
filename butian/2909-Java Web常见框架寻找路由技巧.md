# Java Web常见框架寻找路由技巧

> **来源**: https://forum.butian.net/share/2909  
> **文章ID**: 2909

---

0x00 前言
=======

 在Java Web代码审计中，寻找和识别路由是很关键的部分。通过注册的路由可以找到当前应用对应的Controller，其作为MVC架构中的一个组件，可以说是每个用户交互的入口点。主要负责以下几个方面的任务：

1. 请求分发：控制器接收来自用户的HTTP请求，并根据请求的URL和HTTP方法（如GET、POST等）将请求分发到相应的处理方法。
2. 参数绑定：控制器将请求中的参数（如查询参数、表单数据、JSON对象等）绑定到处理方法的参数上。
3. 业务逻辑调用：控制器调用服务层（Service Layer）的组件来执行业务逻辑，如数据处理、计算等。
4. 异常处理：控制器负责处理业务逻辑中可能抛出的异常，并返回适当的错误响应或重定向。
5. 响应生成：控制器根据业务逻辑的结果生成响应，这可能包括渲染视图、返回JSON数据、重定向到其他页面等。

 一般在代码审计时都会逐个分析对应的实现，通过梳理对应的路由接口并检查对应的业务实现，能帮助我们快速的检索代码中存在的漏洞缺陷，发现潜在的业务风险。下面简单介绍下Java Web中常见框架（Spring Web、Jersey）寻找路由技巧。

0x01 获取路由的技巧
============

 大多数Java Web框架遵循MVC（Model-View-Controller）架构。了解框架的架构和约定可以快速定位。下面简单介绍下一些技巧：

1.1 关键字匹配
---------

 可以直接通过Controller的定义来寻找路由。

 大多数框架都有约定俗成的项目结构，控制器通常位于特定的包或目录中。例如，在Spring MVC项目中，控制器类可能位于controller包下。

 并且很多Java Web框架都会使用注解来标识控制器和映射请求。例如，在Spring MVC中，@Controller注解用于标记控制器类，@RequestMapping用于定义请求映射。在其他框架中，如Jersey（JAX-RS），就是@Path和@POST、@GET等注解。

 当然还有一些特定的配置类，例如在Spring中，在Jersey中，`ResourceConfig`类常用于配置路由。

 可以通过关键字匹配的方式获取到对应的资源目录，然后逐个进行审计。下面是一些关键字的总结：

### 1.1.1 Spring MVC

 常见的注解如下：

- @Controller
- @RestController
- @RequestMapping
- @GetMapping
- @PostMapping
- @PutMapping
- @DeleteMapping
- @PatchMapping

 除了使用注解的方式，还可以在对应的xml配置文件中通过配置Controller相关的bean来实现。例如下面的例子：

 在spring的配置文件中做如下配置：

```Plaintext
<!-- HandlerMapping -->
<bean class="org.springframework.web.servlet.handler.BeanNameUrlHandlerMapping" />
<!-- HandlerAdapter -->
<bean class="org.springframework.web.servlet.mvc.SimpleControllerHandlerAdapter" />
<!-- 处理器 -->
<bean name="/userInfo" class="com.springmvc.test.UserController" />
```

 相关的作用如下：

- BeanNameUrlHandlerMapping：表示将请求的URL与Bean名字进行映射。
- SimpleControllerHandlerAdapter：表示所有实现了org.springframework.web.servlet.mvc.Controller接口的Bean可以作为Spring Web MVC中的Controller。

### 1.1.2 Spring WebFlux

 上面提到的注解在 WebFlux 中依然还可以继续使用，不过 WebFlux 也提供了自己的方案Router。

 其定义Controller与传统的Spring MVC有所不同，因为WebFlux是基于响应式编程模型的。在WebFlux中，需要使用`RouterFunction`来路由请求到对应的处理方法。例如下面的例子：

```Java
@Configuration
public class RouterConfig {
    @Autowired
    private ShowAction showAction;

    @Bean
    public RouterFunction timerRouter() {
        return RouterFunctions.route(RequestPredicates.GET("/hello"), showAction::hello)
                .andRoute(RequestPredicates.GET("/time"), showAction::showTime)
                .andRoute(RequestPredicates.GET("/date"), showAction::showDate)
                .andRoute(RequestPredicates.GET("/times"), showAction::sendTimePerSec);
    }
}
```

### 1.1.3 Jersey

 在Jersey中在资源类上使用`@Path`注解来定义基础路径，然后在资源方法上使用额外的`@Path`注解来指定具体的子路径。例如下面的例子

```Java
@Component
@Path("/hello")
public class HelloWorldResource {

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public String sayHello() {
        return "hello world.";
    }
}
```

 然后通过`ResourceConfig`类来配置资源和路由即可：

```Java
@Component
public class AppConfig extends ResourceConfig {

    AppConfig() {
        register(HelloWorldResource.class);
    }
}
```

 常见的注解如下：

- @Path
- @GET
- @POST
- @PUT
- @PATCH
- @Delete
- @HttpMethod

1.2 相关IDE插件
-----------

 RestfulToolkit是一个RESTful 服务开发辅助工具集。可以根据 URI 直接跳转到对应的方法定义：

![image.png](images/attach-b481849e740f29d15eeca5eb805db86ec7567a84.png)

 通过这个插件可以快速查找到对应的接口位置，很多时候我们知道一个api接口，想知道这个接口对应的类和位置时，查找起来很麻烦，这个插件可以很方便解决这个问题：

![image.png](images/attach-80630f8fd92ff27bf8297987ba6d05f7a038eab4.png)

 通过该插件可以很方便的对应用注册的路由逐个进行分析。强迫症提出一个问题，通过上述方法获取到的路由就一定全吗，会不会有遗漏的地方，如果路由信息在jar依赖里引入的能保证获取全吗？

![image.png](images/attach-2f3352299c996eb264a58541b28dbeaf39f4ccda.png)

1.3 结合Debug断点获取
---------------

 结合上面的疑惑，很多时候应用会在框架的基础上进行魔改，然后对Controller进行拓展。例如下面的例子，自定义了一个注解@BuyerController：

![image.png](images/attach-8fa40047330162e958beea14be63f7518d274c0a.png)

 然后定义了具体的Controller以及业务逻辑：

![image.png](images/attach-cbe3fa21c3606a092597fc51fccd9ba0d1522896.png)

 但是通过RestfulToolkit并不能获取到对应路由的定义：

![image.png](images/attach-88a6a367afab10455e4573d9dfeb029402982e7b.png)

 而该路由对应的资源实际上是可以正常访问的：

![image.png](images/attach-e117792145cb51127be5a9434454235639d9b467.png)

 那么此时如果仅仅依赖关键字或者IDE插件的方式进行匹配的话，很可能会有遗漏。

 实际上我们可以通过分析代码，跟踪HTTP请求是如何被框架处理的，对识别负责处理特定请求的控制器也会有一定的帮助。如果可以对应用进行调试的话，通过在对应的位置下断点，即可获取对应框架所注册的全部路由：

### 1.2.1 Spring MVC

 当一个HTTP请求到达Spring Web应用程序时，`AbstractHandlerMethodMapping` 类（或其子类，如 `RequestMappingHandlerMapping`）会使用 `lookupHandlerMethod` 方法来确定哪个控制器（controller）中的方法应该被调用来处理该请求。通过org.springframework.web.servlet.handler.AbstractHandlerMethodMapping#lookupHandlerMethod的mappingRegistry可以快速的获取应用注册的路由信息：

![image.png](images/attach-8b7b188b353d517f11e1c8b5d71087f6af882f21.png)

 同样是上面对Controller进行拓展的例子，除了常规的路由以外，可以看到对应的拓展Controller的路由信息同样也获取到了：

![image.png](images/attach-9d18ca7704915635eca50f764d07532eeb65bbbe.png)

### 1.2.2 Spring WebFlux

 同样的，在Spring WebFlux中，则可以通过org.springframework.web.reactive.result.method.AbstractHandlerMethodMapping#lookupHandlerMethod进行注册路由的获取：

![image.png](images/attach-263c725cd58230e1e7d11cb90bb3e0a5f06870df.png)

 可以看到通过mappingRegistry可以获取到当前应用注册的路由信息：

![image.png](images/attach-7bb5784e721ae494238c52cc1d1d4410e8b50e30.png)

### 1.2.3 Jersey

 在Jersey中，则可以通过`org.glassfish.jersey.server.ApplicationHandler#initialize`获取jersey注册的router,其的作用是初始化应用程序的请求处理，通过该方法可以查找并注册应用程序中的资源类（Resources）和提供者（Providers），如异常处理器、拦截器、实体过滤器等。例如根据资源类上的注解（如 `@Path`）和其他配置信息，配置请求到资源方法的路由：

![image.png](images/attach-084c71f2b9cfe766a46917bcbda4ff6097a34281.png)

 可以看到通过routingStage可以获取到当前jersey注册的router：

![image.png](images/attach-5e36ae80ca399dce87018e654ee389c4ea562554.png)

0x02 其他
=======

 通过上面的几种方式，可以快速的定位并梳理对应的路由接口，快速的开展后续的审计工作。

 除了上面提到的框架以外，类似JFinal、Struts在Java生态中也有一定的占有量。对应的方法是类似的，例如JFinal会使用`Routes.add()`方法，向`Routes`添加`Controller`的router定义，这里就不再展开讨论了。
