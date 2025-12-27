# 浅谈gaul/s3proxy authorization绕过

> **来源**: https://forum.butian.net/share/2908  
> **文章ID**: 2908

---

0x00 关于gaul/s3proxy
===================

 作为云计算的核心服务之一，存储服务是经常会用到的。

 <https://github.com/gaul/s3proxy> 是一个开源项目，它实现了S3 API，允许你通过这个API访问多种不同的存储，目前已经支持Azure Blob，Google Cloud Storage和OpenStack Swift等主流的云存储服务。

![image.png](images/attach-c5b48d42d598329df2677cca3a91b89be468f8b7.png)

 其本质是在本地提供了一个基于jetty的web服务，通过本地的web服务将aws s3的api调用请求转发到其他对应的云存储服务上。甚至可以通过aws s3的api来访问本地文件。或者通过中间件嵌入到Java应用程序中。

 s3proxy还可以通过Docker使用，Docker Hub上提供了Docker镜像，并且有详细的运行指南。即使不使用Docker，用户也可以从GitHub下载发布版本，并通过运行mvn package来构建项目，这将在target目录下生成一个可执行的二进制文件。

 配置s3proxy是通过一个属性文件s3proxy.conf完成的。例如，使用本地文件系统作为存储后端并允许匿名访问的配置如下：

```Java
s3proxy.authorization=none
s3proxy.endpoint=http://127.0.0.1:8080
jclouds.provider=filesystem
jclouds.filesystem.basedir=/tmp/s3proxy
```

 首先需要创建文件系统的基础目录，然后运行s3proxy。Linux和MacOS X用户可以通过给予执行权限后直接运行jar文件，而Windows用户需要使用java -jar命令来启动。

 整个使用过程十分的方便，很快就可以搭建完成对应的服务了：

![image.png](images/attach-e4dbeed7fdae4269cb4df68973b05790a278ab94.png)

0x01 authorization绕过
====================

 在对应的配置文件中，有这么一个属性`s3proxy.authorization`：

```Java
# authorization must be aws-v2, aws-v4, aws-v2-or-v4, or none
s3proxy.authorization=aws-v2-or-v4
```

 该配置项用于设置授权和认证机制，它决定了如何验证和授权对S3 API的请求。这个配置项可以设置为不同的值，以启用不同的认证策略，例如配置为none的话则不进行任何认证，允许所有请求通过。这适用于测试和开发环境。

 例如上面的例子，当在s3proxy.conf修改对应的属性时：

```Java
# authorization must be aws-v2, aws-v4, aws-v2-or-v4, or none
s3proxy.authorization=aws-v2-or-v4
s3proxy.identity=local-identity
s3proxy.credential=local-credential
s3proxy.keystore-path=keystore.jks
s3proxy.keystore-password=password
```

 此时再次访问`/`,会返回403 status：

![image.png](images/attach-af2b6f3232ccb07de52f3b8ae2e281b75175e70e.png)

 下面简单分析下具体的实现以及authorization绕过过程。

1.1 分析过程
--------

 对请求的处理主要是在org.gaul.s3proxy.S3ProxyHandler#doHandle方法实现的，首先会通过request.getRequestURI获取当前请求的URI，如果配置了servicePath的话，在URI中移除对应的内容，等待进一步的处理：

![image.png](images/attach-94eea68e7eed715b9882876dec6e9c3ee0fd4147.png)

 然后处理virtualHost，如果配置了virtualHost，会根据主机头和请求的URI来调整请求路径:

![image.png](images/attach-32a8faf464b31a7f5f4b902fb58294ec43a9ff19.png)

 接着检查请求头中的授权信息，以确定请求的认证类型:

![image.png](images/attach-f1865b96a19a85f43029e681c442c42f1460f7e2.png)

 对于匿名请求，返回所有公开可访问的信息；对于认证请求，根据凭证和签名进行进一步的处理：

![image.png](images/attach-7f97f50acc1c190f842b1f9315d6086e3a57cf68.png)

 并且会根据HTTP方法和URI路径，调用相应的处理函数来执行操作，如列出桶（容器）内容、获取对象（Blob）、删除对象、设置访问控制列表（ACL）等：

![image.png](images/attach-0ba984c7ba8394131b633639731a6ff044de2cad.png)

 对于匿名请求，当请求里的认证信息为空时，会通过doHandleAnonymous方法进行处理：

![image.png](images/attach-bfad9d9e6f94fc518db0d3a2b35a75a7932b29ae.png)

 如果当前请求的uri为`/`,那么则直接抛出`S3ErrorCode.ACCESS_DENIED`,否则会根据path切割的内容获取对应的Blob信息：

![image.png](images/attach-62ecbc720a665068acfd19962d334c022c0496c2.png)

 因为这里的uri是通过request.getRequestURI()获取的，并没有经过normalize处理。很容易就想到可以在路径中添加`;`即可绕过对应的检查，但是实际上这里即使绕过了也会返回`NoSuchBucket`：

![image.png](images/attach-1020f5c2635551930ecc64b62b82b445b1a431e6.png)

 因为这里会根据请求的uri进行切割`String[] path = uri.split("/", 3);`,然后返回所有公开可访问的信息，否则则说明需要根据凭证和签名进行进一步的处理：

![image.png](images/attach-75aac42e276221132481a2769fb2436c2876332f.png)

 基于前面搭建的环境，当获取到containerName时，进一步查看具体的解析过程,通过invoke，最终调用到的是org.jclouds.filesystem.strategy.internal.FilesystemStorageStrategyImpl#getContainerAccess方法：

![image.png](images/attach-e6db8c3e3df33db85c927270da5f87b2ea3e4338.png)

 在getContainerAccess方法中，首先调用buildPathStartingFromBaseDir对传递的containerName进行处理：

![image.png](images/attach-e77e29f54ee8753c8122f5d1219b852b59557cb8.png)

 调用removeFileSeparatorFromBorders对baseDirectory(jclouds.filesystem.basedir)移除位于路径开始或结束的文件分隔符（如Unix系统中的`/`或Windows系统中的`\`）：

![image.png](images/attach-8c5fd7cd59d5a1282e973206144bcd5a2ec7d592.png)

 这里会对containerName进行归一化的处理，例如对windows的路径进行统一：

![image.png](images/attach-e7da14c7e77c65abca45150d483dd39cdb15e362.png)

 然后将处理后的内容作为路径拼接到baseDirectory去并返回：

![image.png](images/attach-dadafa3a5928ff408484c3baf15661081e63ab55.png)

 如果文件存在，将其转换为Path对象，以便进行后续的文件系统权限检查。同时会根据操作系统的不同，采取不同的权限检查策略，例如在非Windows系统中，使用Files.getPosixFilePermissions方法获取文件的POSIX文件权限集合，然后检查这个集合是否包含Others\_READ权限。如果包含，表示是公开可读的，返回ContainerAccess.PUBLIC\_READ；如果不包含，表示是私有的，返回ContainerAccess.PRIVATE：

![image.png](images/attach-56f1f16b1ab8ee14db3566ba31ece84c4c4056ce.png)

 最终根据返回的权限级别判断是否抛出ACCESS\_DENIED异常：

![image.png](images/attach-b5c4b8ce452c19c6bc0b256ced015ea5114f6b7a.png)

 在文件系统中，`.`一般代表当前目录，在上述获取Path逻辑里，如果`.`拼接到对应的baseDirectory实际上是不影响的，那么也就是说可以尝试通过`/.`的方式进行请求，即可在绕过authorization逻辑的情况下，获取到相应的敏感信息了:

![image.png](images/attach-7c4b733406b00485a9fb3a2c749bb8448bb0f083.png)

 进而进一步获取对应的敏感信息了，例如这里的`/testbucket/test`:

![image.png](images/attach-3025a2edb9b2058a8a01c1ac1fea0e363bf481c5.png)

0x02 其他
=======

 在分析过程中，发现在设置`s3proxy.authorization=none`时，尝试访问`/.`并不能访问到具体的内容：

![image.png](images/attach-003bc9aabb0953312065fa0c45c43d5250c1e3fe.png)

 实际上这里会对containerName进行检查：

![image.png](images/attach-9c1b8e0c3f3c0db1ccc616b2f428da58c8677dcd.png)

 如果以`.`开头或者结尾的话，会返回false，然后抛出`S3ErrorCode.NO_SUCH_BUCKET`异常：

![image.png](images/attach-742a0db6151ad9c2c9cc44dcb94c8a027cb7d63e.png)

 但是在authorization的处理逻辑中，并没有进行校验，结合不规范的uri获取过程导致了绕过的问题。
