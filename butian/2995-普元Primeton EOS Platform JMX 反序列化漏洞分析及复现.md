# 普元Primeton EOS Platform JMX 反序列化漏洞分析及复现

> **来源**: https://forum.butian.net/share/2995  
> **文章ID**: 2995

---

普元 EOS 框架分析
===========

### 1、分析WEB应用的第一步首先看一下，web.xml文件。

 在**web.xml**中我们可以看到其中配置了一个**filter**，其对应的类为“com.eos.access.http.InterceptorFilter”，拦截了所有的请求。

![image.png](images/attach-d92bed281e4451237f68bb8e7acd6829bcfcb9b8.png)

### 2、跟进该拦截器的“doFilter”方法。

 可以看到**InterceptorFilter**创建了一个**WebInterceptorChain**，并将后续处理委托给了**WebInterceptorChain**。

![image-1.png](images/attach-11bdbb98acdf31e996fed2f23c6828738f257b3f.png)、

### 3、跟进createChain方法。

 可以看到**WebInterceptorChain**是通过获取当前请求的“**servletPath**”。遍历“**configs**”中的**WebInterceptorConfig**的对象。调用**WebInterceptorConfig**对象的“**getPattern()**”方法获取“**Pattern**”。将获取到的“**Pattern**”正则表达式与当前请求的“**servletPath**”进行正则匹配。匹配成功则从“**interceptors**”中获取对应的**IWebInterceptor**对象，添加进**Chain**中。

![image-2.png](images/attach-51c6d003ba66af34d3306cb92e0a4280388d51c2.png)

#### 3.1 那么“configs”对象和“interceptors”对象是从哪里来的呢？

 “**configs**”对象和“**interceptors**”对象有多种来源并且会在应用程序启动时配置完成。  
在**WebInterceptorManager**中我们可以看到**WebInterceptorConfig**对象部分是通过读取“**handler-web.xml**”文件生成。

![image-5.png](images/attach-ebf5fdb40dc33e2c7f36d86faf47b5ad7eab8248.png) 除此之外“**configs**”对象和“**interceptors**”对象还会在“**handler-processor.xml**”文件中进行配置，并且在**RequstProcessors**中读取并配置。文章篇幅有限，感兴趣的师傅可以自行分析一下。

![image-6.png](images/attach-9ac42f3197c006e0d342fbed3f7e1e75cccfaa96.png) 类似的配置文件还有“**contribution.eosinf**”（下文会用到，这里提一嘴）。

普元 EOS 鉴权
=========

### 分析完框架之后我们接下来分析一下，普元EOS的鉴权部分代码。

 普元EOS的鉴权代码主要位于“**UserLoginWebInterceptor**”和“**UserLoginCheckedFilter**”中。这两个“**interceptor**”分别在“**contribution.eosinf**”和“**handler-web.xml**”中进行配置。</br> 跟进**UserLoginCheckedFilter**的“**doIntercept()**”方法。首先判断是否处于登录状态，如果处于登录状态则直接放行。如果未登录则判断是否为“白名单”路径，如果是白名单路径则放行。再判断是否为“黑名单“路径，如果为黑名单路径则抛出异常。最后既不在”白名单“也不在”黑名单“也放行。</br> “**UserLoginWebInterceptor**”的代码逻辑与“**UserLoginCheckedFilter**”相似，本文不再重复分析。

![image-7.png](images/attach-e8c59c626486b5d14851cafa93ad1de6d03e753d.png) 黑白名单中的路径在”**user-config.xml**“中进行配置。

![image-8.png](images/attach-32b2b378f03aa9477bfdc8c8ed1403436cb82786.png)

普元EOS JMX 反序列化漏洞
================

### 接下来到了本文的重点。

 根据网上曝光的相关信息可以得知该漏洞的路由方式为”**\*.jmx**“,而在”**handler-processor.xml**“中我们可以看到与”**\*.jmx**“相关的配置。

![image-9.png](images/attach-80aa4c282443c0e6339ff3032df80b35f7fd6da3.png) 跟进配置文件中的”**JmxServiceProcessor**“类，我们可以看到在”**JmxServiceProcessor**“类的”**process()**“方法中直接从**request**中获取了请求体，作为参数生成了**ObjectInputStream**的对象，并且调用了它的”**readObject()**“方法，触发了反序列化漏洞。

![image-10.png](images/attach-a1cf969bf7971eb949b6373393fc9e4c0b6dc5d8.png)

复现
==

 利用该漏洞我们只需要向”**/default/.jmx**“路径，POST 发送payload。因为普元EOS存在”**commons-collections**“依赖，并且版本处于可利用范围内。因此直接使用CC链即可。

![image-12.png](images/attach-68759f20569288bad571a82118450a53ca50eb6b.png)

![image-11.png](images/attach-4bc9d04cdad84e044991ac3e1fd54c9036273bdc.png)

CC6变种
=====

### 在此和大家分享一个CC6的变种。

 在ysoserial中CC6是通过反射调用 ”*Runtime.getRuntime().exec()*“实现命令执行，不能执行复杂的操作。我们可以通过调用JS引擎的方式实现复杂的操作，例如注入内存马等，代码如下。

![image-13.png](images/attach-d41dfd4928a849ab96d21933b06a1dc1b9b1ec2d.png)
