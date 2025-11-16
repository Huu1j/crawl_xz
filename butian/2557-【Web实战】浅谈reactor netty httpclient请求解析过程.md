# 【Web实战】浅谈reactor netty httpclient请求解析过程

> **来源**: https://forum.butian.net/share/2557  
> **文章ID**: 2557

---

0x00 前言
=======

 Reactor Netty HttpClient 是 Reactor Netty 框架提供的一个用于进行异步 HTTP 请求的客户端库。它基于 Reactor 框架，采用响应式编程模型，允许以非阻塞的方式执行 HTTP 请求和处理响应。

![image.png](images/attach-6ba7485c31fa23a6d7396d77241628133f6a1f9b.png)

 通过引入对应的依赖，即可通过使用Reactor Netty从HttpClient获取目标的响应报文：

![image.png](images/attach-7b9e30a08763e0253f9db6955b44d070b8f1acf7.png)

 下面是一个具体的例子,首先创建了一个 HttpClient 对象，通过Reactor Netty 的链式调用 API 来构建我们的请求，发起了一个 GET 请求访问了target并打印对应响应的内容，完成了整个请求与响应处理过程：

```Java
HttpClient httpClient = HttpClient.create().wiretap(true);
httpClient.get().uri(target).responseContent().aggregate().asString().doOnSuccess(s -> {
    System.out.println("s1=" + s);
}).block();
```

 上述代码串联了多个Reactor Netty的方法，下面是简单的说明：

- `httpClient.get().uri(target)`：通过httpClient创建了一个HTTP GET请求，并指定了请访问的目标URL。
- `.responseContent()`:调用.responseContent()方法，会获取到一个表示HTTP响应内容（响应体）的Flux\\<ByteBuf>，其中Flux是Reactor中的一种反应式数据类型，表示异步流。异步处理响应体的数据信息。
- `.aggregate()`:因为HTTP响应的内容通常会被分成多个字节块，该方法用于将它们进行整合。
- `.asString()`:调用该方法将`ByteBuf`内容解码为字符串方便后续的处理。
- `doOnSuccess(s -> {` `System.out.println("s1=" + s);})`:使用.doOnSuccess()方法注册一个回调函数，当HTTP响应成功完成时，执行这个函数将HTTP响应的内容打印到控制台中。
- `.block()`:阻塞当前线程以等待HTTP响应的完成。.block()方法会触发实际的HTTP请求发送和响应处理，然后等待直到HTTP请求完成，并且只有在响应成功时才会解除阻塞。

 当然除了block以外，还可以通过类似subscribe获取响应报文。

0x01 "畸形scheme"HTTP请求
=====================

 以GET请求为例，下面对reactor netty httpclient请求解析过程进行简单的分析：

 在 Reactor Netty 框架中，MonoHttpConnect是一个用于表示 HTTP 连接的 Mono 类型。它代表了一个异步的 HTTP 请求，并返回一个 Mono 类型的结果。通过调用 subscribe 方法，可以触发实际的 HTTP 请求，并通过订阅者来处理响应结果：

![image.png](images/attach-4c363a05a8d49fadd2595cc9e49968f0eabc13cc.png)

 首先这里会实例化HttpClientConnect，这里会调用`uriEndpointFactory.createUriEndpoint`创建 UriEndpoint，UriEndpoint是一个用于表示网络请求的目标地址的类。它封装了 URI 的相关信息，包括协议、主机名、端口号、路径等。reactor.netty.http.client.UriEndpointFactory#createUriEndpoint方法根据传入的参数，创建一个 UriEndpoint 对象，并返回该对象：

![image.png](images/attach-c260dc37f9b111e207b707edc8d7f8a5002f048c.png)

 可以看到，在createUriEndpoint方法中，主要是通过正则匹配的方式获取URI 的相关信息：

![image.png](images/attach-0b4519a6b28ec1a25ca8d282f3661af615aba422.png)

 创建完HttpClientHandler后，会通过配置对象（\_config）来设置一些参数：

![image.png](images/attach-a92f90a2e5cc5bfd22ea237bce7f5a64d6500369.png)

 这里会调用resolverInternal方法用于获取地址解析器组。它负责将主机名解析为一个或多个 IP 地址，以便 HttpClient 可以与目标服务器建立连接：

![image.png](images/attach-0c56a32d3a7bd77d12d23f5f6e8641c5e6f62a6a.png)

 实际调用的是其父类ClientTransportConfig的方法：

![image.png](images/attach-6ba03085917a5584c807ff5c52c65f5b97aa2d71.png)

 这里会create一系列的组件：

![image.png](images/attach-312646d9f957be9d9be00a26266f9b96e77e12ff.png)

 例如创建ConnectionProvider用来管理连接池，Builer这里硬编码传入对应的name为http，后续会创建一组连接并存储在连接池中。 当需要进行网络通信时，可以从连接池中获取一个连接并使用它来发送请求：

![image.png](images/attach-068a9d9a20e3dd7de38f9ee8b4cc1762975e2864.png)

 又例如PooledConnectionProvider，这个在后面会用到：

![image.png](images/attach-d30a83de7af0133b4d32eaf63fc4c44229393975.png)

 调用完后，此时会调用`_config.httpConnectionProvider().acquire`从 HTTP 连接提供者中获取一个可用的连接。以便进行 HTTP 请求：

![image.png](images/attach-918797170c4d6b054c5b6637e6f2e588bbd1b73c.png)

 查看具体的过程，这里最终会调用PooledConnectionProvider的acquire方法：

![image.png](images/attach-c7509a5f1cc041de78839e12503a6cfb505b94d3.png)

![image.png](images/attach-deb3f4f4abd828f40cfc74df4554d4061672ad12.png)

 reactor.netty.resources.PooledConnectionProvider的作用是提供连接池管理功能。在使用 Reactor Netty 进行网络通信时，可以通过 PooledConnectionProvider 来管理和复用连接，以提高性能和资源利用率，这里会调用 acquire 方法获取一个可用的连接，以便进行网络通信。获取到的连接可以用于发送请求、接收响应等操作，如果连接池中没有可用的连接，它可能会创建一个新的连接：

![image.png](images/attach-5a493fa87684fcc3c8af867c9ce6f7cfeccb0749.png)

 从对应的调试信息可以知道，这里创建的是http client pool，结合前面解析请求target的过程，这里name的值并不是从请求target的schema获取的，是从前面Builer里硬编码获取的：

![image.png](images/attach-661436d79a6bd03dfb0f5078b64a18e53b99f436.png)

 后面是HttpClientOperations的处理，也没有对schema进行相应检查操作，那么这里有没有可能reactor netty httpclient可以以任意符合正则匹配的schema进行请求呢？

![image.png](images/attach-607a8c780f4a40b53161666cb256cd84cf8651f6.png)

 验证下前面的猜想：

![image.png](images/attach-ccb8edca74eceec11f38747e46b7e86cb4b774bb.png)

 正常情况下，通过reactor netty httpclient请求`http://127.0.0.1:8080/health`正常返回：

![image.png](images/attach-910e83a34d0b8a12f38f2219a52ba7fb0de4df4e.png)

 将scheme替换成任意字符，可以发现依旧能正常请求并返回：

![image.png](images/attach-fadeb3a28c39fde59ede707d1e9e8b4a11267345.png)

 查看reactor netty httpclient的日志，确实没有考虑用户输入的协议，在PooledConnectionProvider创建了新的http client pool，同时也没有发现关于schema的检查：

![image.png](images/attach-70e1b486c5bc3254d5e5d903ed615471a28ced7a.png)

![image.png](images/attach-1869051020bc226d37ae83480797652d6f8d6d84.png)

 结合前面请求target解析的正则：

![image.png](images/attach-b636c1e43eb37de20d340cdadc64ab5b8e435ccf.png)

![image.png](images/attach-e85f6e446ee0bf0e42408729be88e6faac34bd56.png)

 scheme还支持下划线匹配，所以类似`anyt____hing`的schema同样能正常请求：

![image.png](images/attach-3bf7bf1fbf8144398573864b587cfba2025ef862.png)

0x02 其他
=======

 WebClient是从Spring WebFlux 5.0版本开始提供的一个非阻塞的基于响应式编程的进行Http请求的客户端工具。 它的响应式编程的基于Reactor的。 WebClient中提供了标准Http请求方式对应的get、post、put、delete等方法，可以用来发起相应的请求。

 通过引入如下依赖即可使用WebClient:

![image.png](images/attach-fe2ee5238a5d6e2ed41c99b28001c65863c66382.png)

 从依赖关系可以看到，实际上spring-boot-starter-webflux也是基于reactor-netty-http来发起相应的请求的：

![image.png](images/attach-6e209afc8cd0d4af887220778abf7b88edcd18cc.png)

 下面的代码是一个简单的WebClient请求示例。可以通过`WebClient.create()`创建一个WebClient的实例，然后选择调用方式get，在`uri()`指定需要请求的路径，然后调用`retrieve()`发起请求并获得响应，`bodyToMono(String.class)`用来指定请求结果需要处理为String:

```Java
WebClient webClient = WebClient.builder().build();
String response = webClient.get().uri(url).retrieve().bodyToMono(String.class).block();
return response;
```

 简单看下WebClient的处理过程，首先会在org.springframework.web.util.UriComponentsBuilder#fromUriString方法处理需要请求的目标：

![image.png](images/attach-519106ad52a742b8a122aaff385db8508159e6d2.png)

 可以看到这里也是通过正则的方式进行匹配：

![image.png](images/attach-9090cd9640aa4c66e3badfb498d273fe9a516bd3.png)

 若未匹配相关信息，会抛出`throw new IllegalArgumentException("[" + uri + "] is not a valid URI");`异常，否则进行进一步的封装，同时这里对scheme和host进行了一定的合法性检查：

![image.png](images/attach-e499d11cfa2dd69299a58801603907dc1770ef1b.png)

 但是并没有强制校验scheme是否是http/https，所以同样的当尝试请求`anything://127.0.0.1:8080/health`，WebClient同样也是能正常解析并正常返回：

![image.png](images/attach-a785a00a83f1eeefb430a9903617571df93309f1.png)

 可以看到结合reactor netty httpclient解析过程中的一些处理方式，可以构造类似上述任意协议的“畸形”的请求样式，在某种情况下可以绕过现有ssrf的一些安全防护措施。开发人员应该避免将不受信任且未经验证的数据从 HTTP 请求传递给reactor netty httpclient，避免不必要的绕过导致ssrf风险。
