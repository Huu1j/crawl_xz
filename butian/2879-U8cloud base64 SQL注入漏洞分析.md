# U8cloud base64 SQL注入漏洞分析

> **来源**: https://forum.butian.net/share/2879  
> **文章ID**: 2879

---

0x00 前言
-------

前段时间爆出一个`U8cloud`的SQL注入，路径为`/u8cloud/api/file/upload/base64`，在此之前也做过`U8cloud`的代码审计，没有发现和这个路径类似的路径，正好这次有时间，来复现分析一下这个漏洞到底是怎么回事。

0x01 漏洞复现
---------

按照网上给出的`POC`，利用结果如下图，注入点在请求头的`system`字段。

![image-20240328161532324.png](images/attach-16165211647bc929797ced0fe0ef5d89b5c4e1bc.png)

但是神奇的是，如果吧路径中的`file/upload/base64`随便替换为其他东西，会发现居然也能成功注入，这就很耐人寻味了，这个漏洞和`file/upload/base64`居然没有半毛钱关系。

![image-20240328161614286.png](images/attach-85beeb9160cdcb643758731729caae3cae3056f7.png)

0x02 漏洞分析
---------

接下来掏出朋友给的一份编译后的源码，全局搜索`u8cloud/api`，很快就在`webapps/u8c_web/WEB-INF/web.xml`中找到了这个路径，对应的`servlet`是`ExtSystemInvokerServlet`，除了他以外，`/u8cloud/openapi/*`、`/u8cloud/yls/*`、`/u8cloud/extsystem/dst/*`三个路径也都对应到了`ExtSystemInvokerServlet`。

![image-20240328161853625.png](images/attach-4c9d647d9d42b78f1a4548ca9dc129f8935f02d4.png)

而这个`ExtSystemInvokerServlet`的位置在`fw.jar!\nc\bs\framework\server\extsys\ExtSystemInvokerServlet`。

找到这个类，来看他的`doAction()`方法。重点关注一下`ExtSystemServerEnum`和`serviceName`

![image-20240328162232869.png](images/attach-e6669ace78c9b3d51ec502bcd1408b1212364402.png)

`ExtSystemServerEnum`是一个枚举类，包含`/u8cloud/yls`、`/u8cloud/extsystem/dst`、`/u8cloud/api/`、`/u8cloud/openapi/`四个常量。

![image-20240328162257202.png](images/attach-161ffad5779f1b7cea5636902d2d7cfce9a0c959.png)

回到上面的`doAction()`方法，我们要保证我们的`request.getRequestURI()`必须是以上述四个常量之一开头才可以，否则会抛出异常，也就是说不能按照一般的`/servlet/*`路径根据模块名和包名去调用，否则就会报错。

此时，如果我们访问的路径是`/u8cloud/api/file/upload/base64`，就会匹配到`/u8cloud/api/`，然后`serviceName`就被赋值为`u8cloud_api`。

接着一路向下，进入`getServiceObject()`。

![image-20240328163014414.png](images/attach-c17221eb8cd5c0229bd0b9f75011a1c6a7787719.png)

根据`serviceName`也就是`u8cloud_api`去找对应的类。这里具体逻辑感兴趣的可以自行去分析，偷了个懒。

![image-20240328163048771.png](images/attach-e46d6e4850d49456a9a3305baa81b81015ec2b85.png)

根据这项目的惯性，一般就是在各种配置文件中进行的配置。全局搜索一下`u8cloud_api`，在`/modules/uap/META-INF/P_API.upm`中找到如下所示的配置，找到`u8c.server.APIServletForJSON`这么一个类。

![image-20240328163229930.png](images/attach-13a66b468386e99841a2b3f4c2536004a6f74c7c.png)

继续跟进，在`doAction()`方法中，会先判断`request.getPathInfo()`，显然不是以`file.`开头，进入`APIController.forWard(request)`。

![image-20240328163340359.png](images/attach-511819cc286f5d0ead9e1c4215ae5717e07be206.png)

在`APIController.forWard()`中，会发现存在`checkUser()`进行校验，跟进看一下。

![image-20240328163524035.png](images/attach-dbc833150d6816095a481b56ca398257925725e6.png)

在这个地方，看到了本次分析的主角`system`，通过`inputData.getSystem()`获取，然后传入`APIOutSysUtil.getOutSysVOByCode()`中。

![image-20240328163600802.png](images/attach-954b8878d8a91d168a679a53b5ab4c75d5537059.png)

继续跟进一下，明晃晃的字符串拼接就出现了，就造成了`SQL`注入。

![image-20240328163649632.png](images/attach-47a41ec345fa4c90b36c24d1b347dd3fe6761660.png)

还在校验身份甚至没有到校验授权的时候就完成了注入，这也就是我们请求`/u8cloud/api/f`都可以成功注入的原因了。

![image-20240328163818819.png](images/attach-3c7f8c6490b1cd172295424ab714e664b75c1861.png)

0x03 后续
-------

自此，关于这个漏洞的一些情况就分析完毕了，但是也还是遗留了一些问题，比如`/u8cloud/api/`后的服务模块具体是怎么调用的，感兴趣的师傅们就自行去研究了。
