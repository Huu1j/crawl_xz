# Jersey参数处理过程与常见风险

> **来源**: https://forum.butian.net/share/2881  
> **文章ID**: 2881

---

0x00 前言
=======

 Jersey是一个开源的RESTful Web服务框架，它实现了JAX-RS规范（JAX-RS是Java API for RESTful Web Services的简称，它是Java EE的一个规范，提供了一组用于创建RESTful Web服务的API。）中定义的API，并提供了许多额外的特性和工具来简化RESTful Web服务的开发。

 传统的 Java Web 项目，通常会通过 HttpServletRequest 来获取请求相关的参数。

```Java
request.getParameter("param")
```

 类似Spring MVC这类框架，其简化了请求参数的获取方式，直接将请求参数定义为Controller方法参数，配合相关的注解即可完成对应的解析操作。Jersey同样也支持类似的操作。当对应的方法被请求时，会根据请求上下文信息解析出给定类型的方法参数值，并自动进行类型转换和参数校验。

 在Jersey中，获取请求参数的方式主要依赖于请求的内容类型和请求的结构。以下是常见的处理请求参数的注解：

- @QueryParam：一般用于获取Get请求中的查询参数
- @FormPara：一般用于从Post请求的表单中获取数据
- @PathParam：一般用于从URI Path中获取请求内容，类似Spring的@PathVariable
- @HeaderParam：一般用于获取请求头的内容
- @MatrixParam：一般用于矩阵参数
- @FormDataPara：一般用来获取`multipart`请求中的数据（具体解析可以参考https://forum.butian.net/share/2331）

0x01 请求参数解析过程
=============

 前面简单列举了Jersey中常见的处理请求参数的注解，下面看看具体请求参数的解析过程。

 在Jersey框架中，`ParameterValueHelper` 是一个内部辅助类，它属于 `org.glassfish.jersey.server.spi.internal` 包。这个类的主要作用是帮助处理和提供请求参数的值给资源方法。它在Jersey的内部请求处理流程中扮演着重要角色，尤其是在处理`@PathParam`、`@QueryParam`、`@FormParam`等注解时。

 `org.glassfish.jersey.server.spi.internal.ParameterValueHelper#getParameterValues` 方法是 Jersey 框架内部使用的一个方法，主要用于从 `ContainerRequest` 对象中获取一组参数值。这个方法通常在处理请求时被内部调用，以便将请求中的参数值提供给资源方法。

 首先会遍历获取参数值列表的provider，然后调用apply方法进行解析：

![image.png](images/attach-b5915def83ca7dfaf4253e2cb769b174ddb0cd0a.png)

 以@FormPara为例，最终会调用FormParamValueParamProvider#apply进行解析：

![image.png](images/attach-8eefb33e6410de7688db28a88f96c14216d15c77.png)

 如果缓存中没有对应的内容，会调用getFormParameters方法对request进行进一步的处理：

![image.png](images/attach-c42606a7ce3d30d382d2a721b42dc28b2de019d4.png)

 首先会判断请求的MediaType是否与`MediaType.APPLICATION_FORM_URLENCODED_TYPE`一致，然后根据decode的值进行内容的读取，decode默认为true，从字面意思大概知道这里会做一层解码处理：

![image.png](images/attach-db490f4456b355e51d326984545b7f85004cbd91.png)

 这里主要是判断是否在解析参数时引入encodedAnnotation进行处理：

![image.png](images/attach-93d5c35ea312bdbf0f564c49a21bc43284f676b7.png)

 解析完成后会把对应的参数值注入到对应的资源方法中。除此以外，类似@PathParam注解也有对应的Provider进行解析处理，这里不一一列举了：

![image.png](images/attach-83f17678893a59f3f6b6cc40f7aa9e2a5da03be1.png)

0x02 常见风险
=========

 下面看一些实际代码审计过程中遇到的风险案例：

2.1 requestContext.getEntityStream()解析差异
----------------------------------------

 在实际业务场景中，确保请求参数的安全处理是非常重要的，尤其是在涉及数据库操作时。SQL注入是一种常见的安全威胁，它允许攻击者通过注入恶意SQL代码来破坏数据库的安全性。例如orderby的sql交互没办法进行预编译处理，若缺少安全措施的话会存在SQL注入风险。为了避免这种风险，考虑到可能大量的接口都存在类似的风险参数，有时候会使用Jersey框架提供的Filter机制来对请求参数进行过滤和验证。

 在Jersey中，`javax.ws.rs.core.UriInfo`提供了有关当前请求URI的各种信息。可以通过ContainerRequestContext的getUriInfo方法进行获取。然后即可调用getQueryParameters获取对应的参数和值进行相关的检查，但是这种**只能捕获普通GET请求的内容**：

```Java
uriInfo.getQueryParameters().entrySet()
```

 一般情况下会通过requestContext.getEntityStream()进行额外的处理，例如下面的例子，将请求的body通过&关键字进行分割，提取对应的参数内容，然后返回进行特定的检查：

```Java
private Set<String> parseParameterNames(String requestBody) {
    Set<String> parameterNames = new HashSet<>();
    String[] params = requestBody.split("&");
    for (String param : params) {
        int idx = param.indexOf("=");
        if (idx > -1) {
            String paramName = param.substring(0, idx);
            parameterNames.add(paramName);
        }
    }
    return parameterNames;
}

private String getEntityBody(ContainerRequestContext requestContext)
{
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    InputStream in = requestContext.getEntityStream();

    final StringBuilder b = new StringBuilder();
    try
    {
        ReaderWriter.writeTo(in, out);

        byte[] requestEntity = out.toByteArray();
        if (requestEntity.length == 0)
        {
            b.append("").append("\n");
        }
        else
        {
            b.append(new String(requestEntity)).append("\n");
        }
        requestContext.setEntityStream( new ByteArrayInputStream(requestEntity) );

    } catch (IOException ex) {
        //Handle logging error
    }
    return b.toString();
}
```

 前面提到过，Jersey在请求参数解析时，会对参数进行类似URL解码的参数并完成对应的封装。

 而requestContext.getEntityStream()解析出来内容是没有经过类似的处理的，例如下面的调试信息，假设post请求内容为`%73%6f%72%74=1+and+1=1`，requestContext.getEntityStream()会原样返回：

![image.png](images/attach-1b06d4b96998d8826d8de9b7062921b27c395de0.png)

 这里会存在解析差异的问题，例如大部分排序的参数sort存在sql注入的风险，希望通过Filter进行额外的安全处理。因为requestContext.getEntityStream()在解析时会原样返回请求的内容，而Jersey在请求参数解析时，会对参数进行类似URL解码的参数并完成对应的封装。

 例如@FormPara，那么只需要在请求时将sort参数替换成%73%6f%72%74即可绕过对应的安全检查，达到SQL注入利用的目的了。

2.2 @PathParam权限绕过
------------------

 在某些业务场景中，会对请求的URL根据具体的角色权限来进行对比，以达到访问不同的数据的效果。这里有可能会包含@PathParam 参数值。

 在SpringWeb中，不论是低版本还是高版本使用PathPattern的匹配逻辑，在实际匹配时都会对请求的URI进行URL解码后再进行匹配操作。但是在Jersey中，除了对尾部额外的`/`或者`;`进行处理外，并不会对请求的URI进行URL解码，Jersey具体的请求解析过程可以参考https://forum.butian.net/share/2381：

```Java
@Path("/admin")
public class AdminController {

    @GET
    @Path("/manage/getUser")
    public Response getUser(){
        return Response.ok().entity("user").build();
    }
}
```

 可以看到经过URL编码后的URL并不能匹配到具体的资源：

![image.png](images/attach-7419325e8254caaaa67d28b4811515dd26ba0526.png)

 但是@PathParam在实际处理时是有区别的。

在Jersey框架中，`PathParamValueParamProvider` 是一个用于提供路径参数值的`Provider`类。它是Jersey内置的组件之一，负责解析URL路径中的参数（`@PathParam`），并将其注入到资源方法中对应的参数上。

 查看`PathParamValueParamProvider`的处理过程，具体逻辑在PathParamValueProvider#apply：

![image.png](images/attach-573cec021af4457b03309b8380c3e32e5b4145b4.png)

 首先通过`javax.ws.rs.core.UriInfo`获取路径的参数信息，然后调用getPathParameters方法，根据decode的值（默认为true）返回不同的内容，从字面意思可以知道如果decode为true且decodedTemplateValuesView不为null的话会返回URL解码后的内容：

![image.png](images/attach-fdcfb4a9687dac521d992c7fd7051283e897c4e6.png)

 下面印证下前面的猜想：

![image.png](images/attach-7104bd3f50df1b19c5dec13bf728a27a9ac3ff25.png)

 可以看到编码内容经过处理后进行了解码操作：

![image.png](images/attach-409dc4743be19331ba20c5edb02c1f95e8b5c530.png)

![image.png](images/attach-726fdea4ca812d10e1a4b20babf545536da3a9b5.png)

![image.png](images/attach-50ddfb8e88b0bab6c5084eb10cd315f6a809faa0.png)

 在基于URL鉴权逻辑中，`javax.ws.rs.core.UriInfo`提供了有关当前请求URI的各种信息。可以通过ContainerRequestContext的getUriInfo方法进行获取。这里获取到的返回值均未进行标准化处理。跟@PathParam是存在解析差异的，在特定的情况下可能会存在权限绕过的风险。同样的还可能存在任意文件下载的风险，具体分析可见https://forum.butian.net/share/2381。

 此外，Spring也可以集成Jersey进行使用，在通过不同解析模式自带的方法解析时，同样可能存在解析差异的问题，具体可以参考https://forum.butian.net/share/2783。在实际审计过程中需要额外注意。

2.3 其他
------

 前面提到在进行解析时，会判断请求的MediaType是否跟对应Provider的一致，下面是具体的方法实现，可以看到这里在实际匹配时是忽略大小写的：

![image.png](images/attach-a06649cbd10100751c7ad374b204e64cfd800f61.png)

 那么可以尝试⼤小写混淆Content-Type的内容，在特定情况下可能就可以绕过对应的安全检测逻辑。
