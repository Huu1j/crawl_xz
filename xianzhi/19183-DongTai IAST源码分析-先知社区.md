# DongTai IAST源码分析-先知社区

> **来源**: https://xz.aliyun.com/news/19183  
> **文章ID**: 19183

---

看一个商业方案：火线公司 洞态IAST

# 洞态IAST分析

## IAST简介

根据官方文档的描述，IAST 相当于 DAST 和 SAST 的组合，是一种相互关联的运行时安全检测技术。 它通过使用部署在 Web 应用程序上的 Agent 来监控运行时发送的流量并分析流量流以实时识别安全漏洞。

**IAST 能提供更高的测试准确性,并详细的标注漏洞在应用程序代码中的确切位置，来帮助开发人员达到实时修复。**

IAST检测工具分为被动式IAST和主动式IAST，洞态IAST就属于被动式IAST

## 被动式 IAST

原理：需要在安全测试环境中使用 Agent 对应用程序进行监控。它将利用功能测试如：`输入`、`请求`、`数据库访问`等来收集的数据后进行漏洞分析，因此**不需要主动运行专门的攻击测试**。

![图片.png](images/img_19183_000.png)

### 主动式 IAST

原理：将 DAST 解决方案（Web 扫描器）和在应用程序服务器内部的 Agent 相结合, Agent 将根据 Web 扫描器提供的功能验证现有漏洞。

![图片.png](images/img_19183_001.png)

相当于输入URL就开始扫描，把攻击测试的payload也嵌入在IAST里了的意思

洞态 IAST 是被动式 IAST；百度 OpenRASP-IAST 则是主动式 IAST

### 漏洞分析原理

![图片.png](images/img_19183_002.png)

* 【不信任数据采集】：首先将采集到的数据放到一个数据池子中，定义为污点池。
* 【不信任数据预处理】：接着从污点池里依定义的规则 hook 到函数的入参和出参。
* 【不信任数据传播图】：将污点池中的数据以树形结构串连起来形成传播图。
* 【不信任调用链查找】：最后以能够触达危险函数的链路即判定漏洞存在。

## 洞态IAST 安装

这里测试全部在linux中进行

### 安装server

Docker Compose部署，仅限测试环境，生产环境需要部署Kubernetes实现稳定测试

```
git clone https://github.com/HXSecurity/DongTai.git
git pull#更新代码
cd DongTai/deploy/docker-compose/
./dtctl install
```

另外也可以部署指定版本

```
./dtctl install -v 1.15.0
# 部署arm版本请使用dockerhub镜像，同时需要使用自定义数据库
./dtctl install -r dockerhub
```

如果报`curl: (60) SSL: no alternative certificate subject name matches target host name 'registry.hub.docker.com'`，忽视SSL`git config --global http.sslVerify false`

另外，如果报`未能连接到registry.hub.docker.com 端口 443: 连接超时`，请见对应issue

<https://github.com/HXSecurity/DongTai/issues/1459>

docker-compose 2.26.1-4会报错，这个核验版本的逻辑写的有问题，把

![图片.png](images/img_19183_003.png)

把check\_docker\_compose改成：

```
check_docker_compose() {
  Info "Checking docker-compose service status..."

  # 检查 docker-compose 是否安装
  if ! command -v docker-compose >/dev/null 2>&1; then
    Error "docker-compose not installed."
    exit 1
  fi

  # 获取版本号字符串
  RAW_VER=$(docker-compose --version | grep -Eo 'v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9]+)?')

  if [ -z "$RAW_VER" ]; then
    Error "Could not detect docker-compose version."
    exit 1
  fi

  # 清洗版本号：去掉前缀 v 和后缀 -xxx
  CLEAN_VER=$(echo "$RAW_VER" | sed -E 's/^v//' | cut -d'-' -f1)

  # 目标最低版本
  REQUIRED_VER="2.1.0"

  # 版本比较（CLEAN_VER >= REQUIRED_VER）
  if [ "$(printf '%s
' "$REQUIRED_VER" "$CLEAN_VER" | sort -V | head -n1)" = "$REQUIRED_VER" ]; then
    Info "docker-compose version is $CLEAN_VER (OK)"
  else
    Error "docker-compose version $CLEAN_VER is too low. Please install version >= $REQUIRED_VER: https://github.com/docker/compose"
    exit 1
  fi
}
```

即可顺利运行

![图片.png](images/img_19183_004.png)

环境启动成功后，通过部署过程中指定的 `web service port` 访问即可。

* 默认账号及密码: `admin` / `admin`;

然后下载agent

![图片.png](images/img_19183_005.png)

### openrasp测试用例

如何测试一个防护工具的效果？如果手测确实能测出一些特殊的漏洞，但是也会漏掉一些漏洞。

为了验证OpenRASP的漏洞检测效果，或者IAST工具的漏洞检测能力，openRASP提供了多个测试用例，覆盖常见高危漏洞。

<https://rasp.baidu.com/doc/install/testcase.html>

我们用这个测试用例去测试洞态IAST的效果

先安装Tomcat，洞态IAST只支持Tomcat 8/9，所以别装错了

去下面的链接下载openrasp测试用例，这里就下载vulns.war这个主要web漏洞的war包

<https://github.com/baidu-security/openrasp-testcases/releases>

把vulns.war放到tomcat的web目录，也就是webapps目录

然后配置agent.jar：<https://doc.dongtai.io/docs/getting-started/agent/install-java-agent>

![图片.png](images/img_19183_006.png)

```
if [ "$1" = "start" -o "$1" = "run" ]; then
JAVA_OPTS="-javaagent:'/home/kali/Desktop/apache-tomcat-8.5.57/iast-tool/agent.jar' ${JAVA_OPTS}"
fi
```

启动Tomcat服务器：

```
./catalina.sh start
```

openrasp测试用例启动后：

![图片.png](images/img_19183_007.png)

openrasp测试需要jdk11

Dongtai链接目标后：

![图片.png](images/img_19183_008.png)

不过我点击好像没什么用，不知道是JDK配错了还是没配openapi？不管了，直接分析了，能配上就算大功告成

## 源码分析

论文需要，写个IAST，DongTai IAST漏洞覆盖已经很全面了，直接把他工单的逻辑分离掉，把埋点逻辑搞出来

根据DongTai-Java-Agent的官方文档

<https://doc.dongtai.io/docs/development/dongtai-java-agent-doc/maven-build>

找到Agent的源码：<https://github.com/HXSecurity/DongTai-agent-java>

DongTai Java Agent 工作流：

![图片.png](images/img_19183_009.png)

DongTai Java Agent 由 dongTai-agent、dongtai-api、dongTai-core、dongtai-log、dongtai-spring-api、dongtai-spy 组成。

dongTai-agent：agent 模块，用于管理 Agent 的生命周期

dongtai-api：servlet 模块，用于获取请求体和响应体

dongTai-core：引擎模块，用于收集、上报信息

dongtai-log：日志模块，为其他模块提供日志打印输出

dongtai-spring-api：Spring API 模块，用于获取 Spring 应用的 API Sitemap

dongtai-spy ：间谍模块，将间谍类加载入 BootstrapClassLoader， 信息收集入口

结构简述如下：

<https://doc.dongtai.io/docs/development/dongtai-java-agent-doc/agent-structure>

这里主要是对源码进行一个解析，看下具体的代码实现

项目主要关心iast-agent、iast-core、iast-inject

### Agent.main动态attach

入口类为io.dongtai.iast.agent.Agent，挨着分析一下

在main函数里调用parseAgentArgs去解析参数，然后attach到进程

![图片.png](images/img_19183_010.png)

跟进到agentArgs，若提供了pid和mode，则构造Agent路径和参数字符串并返回

这里构造参数字符串为：遍历 IastProperties.ATTACH\_ARG\_MAP 中的键值对，如果命令行参数中包含对应的选项，则将该选项的值追加到 attachArgs 字符串中，格式为 &key=value。

![图片.png](images/img_19183_011.png)

IastProperties.ATTACH\_ARG\_MAP 就是一些iast的基本设置，不用看

![图片.png](images/img_19183_012.png)

![图片.png](images/img_19183_013.png)

extractJattach根据操作系统类型提取对应的 jattach 可执行文件到临时目录，并设置其权限为可执行。

![图片.png](images/img_19183_014.png)

![图片.png](images/img_19183_015.png)

doAttach是执行jattach去把iast attach到对应的pid

![图片.png](images/img_19183_016.png)

jattach是个开源JVM动态附加程序，根据其example如下

<https://github.com/jattach/jattach>

1. 装载本机代理

```
jattach <pid> load <.so-path> { true | false } [ options ]
```

其中 `true` 表示路径为绝对路径， `false` 表示路径为相对路径。

`options` 传递给代理。

1. 加载Java代理

```
$ jattach <pid> load instrument false "javaagent.jar=arguments"
```

但是根据官方给出的dongtai-agent启动参数

```
java -javaagent:/path/to/dongtai-agent.jar -Ddongtai.debug=true -jar app.jar
```

为什么已经用jattach加载java代理了，还要用-javaagent呢？

实际上，在用-javaagent指定时，是不会走Agent的main函数的，而是直接加载MANIFEST指定的premain类

所以可以推断出，Agent.main函数是用于动态attach，也就是用jattach对已经运行中的Java进程注入代理。所以Agent.main实际上默认会调用到agent-class，也就是agentmain，绝对不会调用到premain

这也是为什么官方给出的-javaagent启动方式不会去指定pid，跟Agent.main的逻辑完全对不上

由此可知：

-javaagent是静态attach，不会经过Agent.main

Agent.main启动是动态attach，需要指定pid

另外，我们并没有在agent模块中看到MANIFEST.MF这个清单文件，在pom.xml中用manifestEntries进行了打包时加入清单文件

![图片.png](images/img_19183_017.png)

### agent install

看下是怎么把agent.jar安装上去的

AgentLauncher中premain提供了install去安装agent

![图片.png](images/img_19183_018.png)

agentmain由于是动态attach，所以提供了install和uninstall功能，由mode参数指定

若为卸载（uninstall）：检查 Agent 状态，若已卸载则直接返回；否则调用 uninstall() 卸载引擎，并清理相关资源。  
若为安装（默认）：检查是否已运行，如未运行则注册 Agent、加载引擎并启动监控线程。

![图片.png](images/img_19183_019.png)

可以看到不管是agentmain还是premain，都是调用install去安装agent

跟进install，调用AgentRegisterReport.send()，与web端工单平台链接，提前调用shutdownhook去卸载一遍agent，最后调用loadEngine去安装agent

![图片.png](images/img_19183_020.png)

跟进loadEngine：

通过EngineManager获取引擎管理实例

接着初始化监控守护线程MonitorDaemonThread。如果延迟时间小于等于0，则调用startEngine立即启动引擎。

最后，若监控线程未创建，则新建一个低优先级的守护线程来运行监控任务。

![图片.png](images/img_19183_021.png)

startEngine调用extractPackage，然后调用install

![图片.png](images/img_19183_022.png)

extractPackage解析Inject/Engine/Api jar到本地

![图片.png](images/img_19183_023.png)

install获取spy包和core包的路径，并将spy包添加到Bootstrap ClassLoader中，用IastClassLoader加载core包。IastClassLoader参考jvm-sandbox做类加载，这里省略

主要注意到反射调用了AgentEngine#install

![图片.png](images/img_19183_024.png)

![图片.png](images/img_19183_025.png)

跟进AgentEngine#install，调用了agentEngine.run，也就是engines.start

![图片.png](images/img_19183_026.png)

![图片.png](images/img_19183_027.png)

engines包含ConfigEngine/TransformEngine

![图片.png](images/img_19183_028.png)

TransformEngine完成了字节码的插桩

![图片.png](images/img_19183_029.png)

自己写iast时也可以参考TransformEngine中卸载IAST的代码

![图片.png](images/img_19183_030.png)

### ClassFileTransformer.transform

上面说到，TransformEngine.start会对inst对进行插桩，插桩文件为classFileTransformer

根据这个iast demo

<https://github.com/iiiusky/java_iast_example/blob/main/iast/src/main/java/cn/org/javaweb/iast/Agent.java>

可以看到addTransformer添加了代理AgentTransform

![图片.png](images/img_19183_031.png)

AgentTransform继承了ClassFileTransformer并重写了transform方法，用自定义的IASTClassVistor去hook正则到的类

![图片.png](images/img_19183_032.png)

IASTClassVistor继承了ClassVisitor并重写了visitMethod处理各种hook

![图片.png](images/img_19183_033.png)

代码流为：

addTransformer -> ClassFileTransformer.transform -> ClassVisitor.visitMethod

那么洞态IAST的ClassFileTransformer又在哪呢？

TransfromEngine.init初始化了classFileTransformer

![图片.png](images/img_19183_034.png)

![图片.png](images/img_19183_035.png)

IastClassFileTransformer是继承ClassFileTransformer没错了

![图片.png](images/img_19183_036.png)

那么就看到IastClassFileTransformer.transform，公式化

IastClassFileTransformer.transform特别关键，逐行解析一下

首先，过滤了无需hook的类，比如iast本身的类，rasp的类

![图片.png](images/img_19183_037.png)

然后对QLExpress和Fastjson进行特殊照顾，设置单独的ClassLoader

![图片.png](images/img_19183_038.png)

由于这里设置的ClassLoader在sink点时才会进行处理，所以我们前瞻一手

在SinkImpl.solveSink中会调用很多scan，其中就包括了DynamicPropagatorScanner().scan(event, sinkNode);

![图片.png](images/img_19183_039.png)

DynamicPropagatorScanner().scan一进来就会去调用SinkSafeChecker.isSafe

![图片.png](images/img_19183_040.png)

比如fastjson对应的FastjsonCheck，判断了fastjson依赖的版本，还有有没有开启ParserConfig的safeMode，熟悉fastjson反序列化的同学们都知道

![图片.png](images/img_19183_041.png)

好继续回到IastClassFileTransformer.transform

首先获取了目标protectionDomain所在的代码路径，如果所在路径不包括sun包，就调用sacnForSCA

![图片.png](images/img_19183_042.png)

跟进到scanForSCA，其实该方法就是用于扫描软件组成（Software Composition Analysis），识别应用程序中使用的第三方依赖组件。

看下图圈起来的部分，扫描了JAR包(isJarLibs)，嵌套的Jar包也扫描了；扫描了War包；扫描了本地Maven仓库依赖，还扫描了普通JAR文件。所有扫描都是异步执行的

![图片.png](images/img_19183_043.png)

```
scaSet就是未扫描的
scannedClassSet就是已扫描的
```

那么对扫描到的类做了什么呢？

直接看下ScaScanThread线程run方法做了什么，ScaReport，就是把目标项目相关依赖信息上传到工单系统了

![图片.png](images/img_19183_044.png)

再次回到transform，这里有个canHook去判断是否可以hook对应类

![图片.png](images/img_19183_045.png)

canHook去判断了指定类是否可以hook，就是检查类名是否为数组、代理、CGLIB、Lamba等，agent自身和第三方框架的类也不hook

![图片.png](images/img_19183_046.png)

transform的最后，我们看到了熟悉的代码，生成ClassReader->ClassWriter->ClassVisitor去增强字节码

除了增强字节码，我们看下这部分代码额外还做了什么：

1. 先是备份了字节码sourceCodeBak，避免后续操作污染了原Jar包字节码
2. 中间过滤了接口类：通过Modifier.isInterface()判断该类是否为接口，若是则跳过处理。
3. 然后获取了该类的父类集合，父类不在黑名单（canHook）的也不能放过增强哦

![图片.png](images/img_19183_047.png)

注意到ClassVisitor的生成是用的plugins.initial

plugins是io.dongtai.iast.core.bytecode.enhance.plugin，那想必这应该是source/propagator/sink处理的分发点了

可以看到先是用DispatchHardcodePlugin.dispatch增强处理，根据这个plugin的名字可以推测，这个插件是用来处理代码中的硬编码敏感信息检测的。然后遍历所有plugins依次做增强，当然在循环中有break，若是被增强了则跳出循环

![图片.png](images/img_19183_048.png)

这里后续我也看了下，DispatchHardcodePlugin似乎只加了对Base64的检测（笑

![图片.png](images/img_19183_049.png)

构造函数中给出了这几个plugin

![图片.png](images/img_19183_050.png)

那么到这里，就理清楚了ClassFileTransformer.transform的作用

1. 过滤了一些不需要hook的类
2. 收集了项目的各个依赖组件
3. 特别关照了QLExpress和fastjson
4. 交给plugin去增强字节码

### plugin dispatch

这几个针对框架的hook plugin随便挑一个来看吧，就看最熟悉的Shiro和Jdbc plugin

![图片.png](images/img_19183_051.png)

#### Shiro增强

首先是DispatchShiro

classVisitor指向ShiroAdapter

![图片.png](images/img_19183_052.png)

ShiroAdapter去hook了readSession方法，shiro反序列化的关键方法了，调用了generateNewBody

![图片.png](images/img_19183_053.png)

先是通过INVOKEVIRTUAL调用AbstractSessionDAO的doReadSession方法，相当于调用原始的readSession

![图片.png](images/img_19183_054.png)

反射调用SpyDispatcherHandler.getDispatcher和SpyDispatcher.isReplayRequest

![图片.png](images/img_19183_055.png)

为什么这里只看到getDispatcher没看到setDispatcher呢？

![图片.png](images/img_19183_056.png)

在IastClassFileTransformer构造函数进行了set，dispatcher是SpyDispatcherImpl

![图片.png](images/img_19183_057.png)

isReplayRequest也是调用SpyDispatcherImpl.isReplayRequest，这是一个是否进入重放后的Endpoint的标志，默认为否

![图片.png](images/img_19183_058.png)

![图片.png](images/img_19183_059.png)

重放请求，获取第一个活跃会话并返回

![图片.png](images/img_19183_060.png)

原版doReadSession

```
// 原始doReadSession逻辑
public Session doReadSession(Serializable sessionId) {
    Session session = // 从存储中读取
    if (session == null) {
        throw new UnknownSessionException("There is no session with id [" + sessionId + "]");
    }
    return session;
}
```

更新后对应的java代码：

```
protected Session generateNewBody(Serializable sessionId) {
    // 行号169: 尝试读取会话
    Session s = this.doReadSession(sessionId);
    
    // 行号170: 检查会话是否存在
    if (s == null) {
        // 行号171: 检查是否为重放请求
        if (SpyDispatcherHandler.getDispatcher().isReplayRequest()) {
            // 行号172-173: 重放请求时返回第一个活跃会话
            s = this.doReadSession(
                this.getActiveSessions().stream()
                    .findFirst()
                    .get()
                    .getId()
            );
            return s;
        } else {
            // 行号175: 正常请求抛出异常
            throw new UnknownSessionException(
                "There is no session with id [" + sessionId + "]"
            );
        }
    }
    
    // 行号177: 正常返回找到的会话
    return s;
}
```

主要解决

* **会话过期中断**：在长时间安全测试中，原始会话可能过期
* **重放测试失败**：重放请求使用过期sessionId会导致测试中断
* **自动化扫描受阻**：安全扫描工具因会话问题无法完成测试

#### jdbc增强

再看下jdbc的增强

![图片.png](images/img_19183_061.png)

MysqlJdbcDriverAdapter的visitMethod会用MysqlJdbcDriverParseUrlAdviceAdapter

![图片.png](images/img_19183_062.png)

![图片.png](images/img_19183_063.png)

等效于

```
@Override
protected void onMethodExit(int opcode) {
    if (opcode != ATHROW) {  // 只在正常返回时执行
        // 假设方法返回Properties对象
        Properties dbConfig = (Properties) 返回值;
        
        if (dbConfig != null) {
            SpyDispatcher dispatcher = SpyDispatcherHandler.getDispatcher();
            String category = ServiceType.MYSQL.getCategory();
            String type = ServiceType.MYSQL.getType();
            String host = dbConfig.getProperty("HOST");
            String port = dbConfig.getProperty("PORT");
            String handler = "";  // 可能是处理器标识
            
            dispatcher.reportService(category, type, host, port, handler);
        }
    }
}
```

就是调用reportService去向平台汇报mysql连接的信息

如果要改造，这个reportService是个重点改造对象

其他两个jdbcAdaptor也大差不差

我们注意到这些plugins都没有source sink之类的埋点呢？只是做了些辅助功能的增强

主要到plugins的最后，加入了DispatchClassPlugin

![图片.png](images/img_19183_064.png)

#### DispatchClassPlugin增强

DispatchClassPlugin#dispatch对传入的classContext获取了父类，getMatchedClass查看有没有匹配的类

![图片.png](images/img_19183_065.png)

这里细看一下这个policy究竟是什么

Policy.getMatchedClass维护了一个classHooks，一个ancestorClassHooks，结合上一张图的setMatchedClassSet，可以知道classHooks就是标记了哪个类已经经历过DispatchClassPlugin增强过了，避免重复增强

![图片.png](images/img_19183_066.png)

dispatch最后返回了一个new ClassVisit

ClassVisit构造函数设置了Adapter，终于看到了我们想看的source/propagator/sink的处理

![图片.png](images/img_19183_067.png)

跟进ClassVisit#visitMethod

首先会跳过接口、抽象方法和静态初始化块

然后进行一个黑名单检查

![图片.png](images/img_19183_068.png)

这个黑名单就是之前canHook时建立的黑名单

![图片.png](images/img_19183_069.png)

然后通过各种set去创建上下文（比如当前的方法描述符、权限、参数之类的），调用getMatchedClassSet找到还没被增强的类，用lazyAop去做切面增强

![图片.png](images/img_19183_070.png)

跟进到lazyAop，这里的注解可以看一下，方便理解。

方法内，看下变量的流转

先是一个循环去遍历当前遇到的methodContext是否在policyNodeMap，如果在则调用MethodAdviceAdapter做增强

![图片.png](images/img_19183_071.png)

那么这个policyNodesMap是什么？

对应getPolicyNodesMap，addPolicyNode会去添加node，添加完node会调用addHooks

![图片.png](images/img_19183_072.png)

这里丢给gpt分析，可以知道洞态IAST用policy去进行策略配置，管理source/propagator/sink/validator的hook

比如举个例子，下面是配置一个policy的case：

```
Policy policy = new Policy();

// 1. 配置数据源点
SourceNode httpParamSource = new SourceNode();
httpParamSource.setMethodMatcher(new SignatureMethodMatcher(
    "javax/servlet/http/HttpServletRequest", 
    "getParameter", 
    "(Ljava/lang/String;)Ljava/lang/String;"
));
httpParamSource.setInheritable(Inheritable.ALL);  // 所有Servlet实现类
policy.addSource(httpParamSource);

// 2. 配置SQL注入汇聚点  
SinkNode sqlSink = new SinkNode();
sqlSink.setMethodMatcher(new SignatureMethodMatcher(
    "java/sql/Statement",
    "executeQuery",
    "(Ljava/lang/String;)Ljava/sql/ResultSet;"
));
sqlSink.setIgnoreInternal(true);  // 忽略框架内部调用
policy.addSink(sqlSink);

// 3. 配置字符串传播点
PropagatorNode stringConcat = new PropagatorNode();
stringConcat.setMethodMatcher(new SignatureMethodMatcher(
    "java/lang/String",
    "concat", 
    "(Ljava/lang/String;)Ljava/lang/String;"
));
stringConcat.setIgnoreBlacklist(true);  // 强制检测，即使String在黑名单中
policy.addPropagator(stringConcat);

// 4. 配置验证器点
ValidatorNode stringValidator = new ValidatorNode();
stringValidator.setMethodMatcher(new SignatureMethodMatcher(
    "org/springframework/util/StringUtils",
    "hasText",
    "(Ljava/lang/String;)Z"
));
policy.addValidator(stringValidator);
```

看到通过setMethodMatcher搭配SignatureMethodMatcher设置Hook点。

setIgnoreBlacklist 强制检测，即使对应的类在黑名单

setIgnoreInternal忽略框架内部调用

setInheritable有下面几个模式，

```
public enum Inheritable {
    SELF,      // 仅当前类
    SUBCLASS,  // 仅子类
    ALL        // 当前类和子类
}
```

比如下面这个就会检测Statement及其所有子类，也就是会记录并hook 其ancestors

```
// 检测Statement及其所有子类(PreparedStatement等)
addHooks("java/sql/Statement", Inheritable.ALL);
```

回看LazyAop，如果当前hook到的类属于policyNodesMap中的类，也就是属于预配置好的source/propagator/sink/validator的某个类。则会调用MethodAdviceAdapter

![图片.png](images/img_19183_073.png)

关于addSource，addPropagator，addSink，addValidator的调用，我们后面挑选特别的漏洞去整体叙述

下面先依照逻辑继续看MethodAdviceAdapter的实现

MethodAdviceAdapter的父类AbstractAdviceAdapter继承了AdviceAdapter，这是个针对方法进入和退出新增逻辑的hook类

![图片.png](images/img_19183_074.png)

MethodAdviceAdapter重载了许多方法，其中就包括onMethodEnter/enterMethod/onMethodExit等，hook点在方法进入和退出时

![图片.png](images/img_19183_075.png)

比如enterMethod执行的onMethodEnter，具体的实现会跳转到source/propagator/sink/validator Adapter

![图片.png](images/img_19183_076.png)

![图片.png](images/img_19183_077.png)

这样就把MethodAdviceAdapter和source/propagator/sink/validator串起来了

### 污点传播

进入与退出Source/Propagator/Sink/Validator Node

数据流从进入Node到退出一个Node触发的顺序：

```
DispatchClassPlugin#dispatch
    SourceAdviceAdapter#before/after
    PropagateAdviceAdapter#before/after
    SinkAdviceAdapter#before/after
    ValidatorAdapter#before/after
      AbstractAdviceAdapter#captureMethodState
          SpyDispatcherImpl#collectMethodPool
              HttpImpl.solveHttp
              SourceImpl.solveSource
              PropagatorImpl.solvePropagator
              SinkImpl.solveSink
              ValidatorImpl.solveValidator
```

而Node又分为Source/Propagator/Sink/Validator

上表每个缩进仅代表一个选择

污点传播的生命周期管理器EngineManager三个变量分别对应：污点路径、污点hash、污点范围

![图片.png](images/img_19183_078.png)

#### Adapter

先直接看SourceAdapter

方法进入时会调用enterScope

![图片.png](images/img_19183_079.png)

enterScope会用ASM去调用spy类的enterSource，这里的spy类毫无疑问是上文IastClassFileTransformer构造函数设置的SpyDispatcherImpl

![图片.png](images/img_19183_080.png)

SpyDispatcherImpl包含了所有hook点的处理逻辑

![图片.png](images/img_19183_081.png)

下面如果继续跟进enterSource逻辑会有点乱，因为一个事件到达sink点才会被上报

实际上Dongtai正是考虑到了这一点，因此分为了AdviceAdapter->Spy->Impl去做处理

数据流从进入Node到退出Node触发的顺序：

```
DispatchClassPlugin#dispatch
    SourceAdviceAdapter#before/after
    PropagateAdviceAdapter#before/after
    SinkAdviceAdapter#before/after
      AbstractAdviceAdapter#captureMethodState
          SpyDispatcherImpl#collectMethodPool
              HttpImpl.solveHttp
              SourceImpl.solveSource
              PropagatorImpl.solvePropagator
              SinkImpl.solveSink
```

比如看代码，虽然enterSource几乎什么也没做，只是单纯的在ScopeManager记录了生命周期。但是SourceAdapter在onMethodExit时会调用trackMethod（初步推测是记录方法路径，或许包含了压栈？），并调用leaveScope

![图片.png](images/img_19183_082.png)

leaveScope和enterScope是完全对称的，包括其在Spy中的leaveSource的实现

![图片.png](images/img_19183_083.png)

OnMethodEnter和OnMethodExit唯一的区别就是OnMethodExit多出了trackMethod方法

看一下trackMethod的实现

捕获了类名、方法名、签名等，调用Spy#collectMethod

![图片.png](images/img_19183_084.png)

collectMethod会根据node类型分别调用

SourceImpl.solveSource、PropagatorImpl.solvePropagator、SinkImpl.solveSink、ValidatorImpl.solveValidator

![图片.png](images/img_19183_085.png)

所以数据流如果会触发到sink，则从开始到结束，应该是这样一个路线：

```
DispatchClassPlugin#dispatch
    ServletDispatcherAdviceAdapter#before/after
              HttpImpl.solveHttp
    SourceAdviceAdapter#before/after
      AbstractAdviceAdapter#trackMethod
          SpyDispatcherImpl#collectMethod
              SourceImpl.solveSource
    PropagateAdviceAdapter#before/after
      AbstractAdviceAdapter#trackMethod
          SpyDispatcherImpl#collectMethod
              PropagatorImpl.solvePropagator
    SinkAdviceAdapter#before/after
      AbstractAdviceAdapter#trackMethod
          SpyDispatcherImpl#collectMethod
              SinkImpl.solveSink
    ValidatorAdapter#before/after
      AbstractAdviceAdapter#trackMethod
          SpyDispatcherImpl#collectMethod
              ValidatorImpl.solveValidator
```

下面也不用每个Adapter去看一遍了，快进到只看Impl的内容吧

#### SourceImpl

先看到io.dongtai.iast.core.handler.hookpoint.controller.impl.SourceImpl#solveSource

这里记录了一下调用栈（最大深度为4），并调用trackTarget跟踪Source

后面设置污点，直接看代码有点复杂

这里的event，是collectMethod创建的MethodEvent，MethodEvent支撑了污点传播的整个生命周期，我们先暂时略过对event设置污点的过程

![图片.png](images/img_19183_086.png)

![图片.png](images/img_19183_087.png)

这里可以标记一下event的几个变量的意思，方便理解

|  |  |
| --- | --- |
| 变量名 | 变量作用 |
| invokeId | 方法调用ID，唯一标识一个方法调用事件 |
| policyType | 表示该事件匹配的策略节点类型（如SOURCE、SINK等） |
| source | 表示该方法调用是否是一个污点源（Source） |
| sourcePositions | 表示污点源在方法中的位置（例如，可能是参数、返回值、对象等） |
| targetPositions | 表示污点目标在方法中的位置（同上） |
| originClassName | 当前方法所在类的实际类名 |
| matchedClassName | 在策略规则中匹配的类名 |
| methodName | 方法名 |
| signature | 方法签名，如（L[java.lang.String]V）包括参数类型和返回类型等信息 |
| objectInstance | 方法调用的对象实例（即调用该方法的对象） |
| objectValue | 对象实例的字符串表示，用于日志或显示 |
| parameterInstances | 方法参数的实例数组，即调用方法时传入的参数值 |
| parameterValues | 方法参数的字符串表示列表，每个参数封装为一个`Parameter`对象，可能包含参数索引和字符串值。 |
| returnInstance | 方法返回值的实例 |
| returnValue | 返回值的字符串表示 |
| sourceHashes | 污点源的哈希值 |
| targetHashes | 污点目标的哈希值 |
| targetRange | 目标范围列表，用于记录方法中污点目标的范围（例如，字符串的起始和结束位置） |
| sourceRanges | 源范围列表，用于记录方法中污点源的范围 |
| sourceTypes | 污点源类型列表，表示污点源的分类（如用户输入、文件读取等） |
| callStack | 方法调用时的栈帧信息 |

OK我们再回到SourceImpl.solveSource，可以逐句阅读代码了

先是调用trackTarget，这是su18大佬重点提到的函数，后续会详细跟进

![图片.png](images/img_19183_088.png)

后面的代码可以核对表，具体：

##### 第一个循环

![图片.png](images/img_19183_089.png)

先从配置对象获取了所有定义为Source源的对象

```
for (TaintPosition src : sourceNode.getSources())
```

> 这里就不得不提到，初始的Source/Propagater/Sink/Validator Node都是通过PolicyBuilder#buildSource/buildPropagater/buildSink/buildValidator添加的，而这几个函数，都是根据一个policyConfig来的
>
> ![图片.png](images/img_19183_090.png)
>
> 自己随便跟进一下，就能找到PolicyManager中加载了config，先从服务器上加载，服务器上没有才会从本地加载
>
> ![图片.png](images/img_19183_091.png)
>
> 而本地加载config是怎么加载的呢？继续跟进，发现是在启动时从命令行传进去的，这里clone的源代码是没有config文件的
>
> 只有几个测试的policy.json，让我们得以初窥DongTai对Node节点的持久化。从json文件加载Source/Propagater/Sink/Validator节点的方式，也使得在Web UI上用户自定义添加节点变得轻松许多
>
> ![图片.png](images/img_19183_092.png)

继续回到第一个循环，当遍历到当前节点属于Source Node时，将返回值（event.returnInstance）标记为对象实例，并指定污点布尔值为true

![图片.png](images/img_19183_093.png)

也就是当前节点为Source且为对象，则返回的对象也是污点；

但如果当前节点为Source却是个参数，则标记参数为污点

举个例子说明：

Source节点是findUserById方法，配置StudentStatement为对象污点源

```
public class UserRepository {
    // 这个方法本身是Source节点，且配置StudentStatement为对象污点源
    public void findUserById() {
        ...
        new StudentStatement();//污点对象
    }
}
```

同一个例子，Source节点还是是findUserById方法，如果配置为参数污点源，也就是参数id。

```
public class UserRepository {
    // 这个方法本身是Source节点，且配置为参数污点源
    public User findUserById(String id) {
        // 从数据库查询用户信息
        User user = executeQuery("SELECT * FROM users WHERE id = ?", id);//污点id会被传播到executeQuery内部
        return user; 
    }
}
```

也就是对象污点源更关心方法内部去创建某污点对象

对吧，对的

##### 第二个循环

注意这里的getTargets，说明了这个循环是处理了污点的传播目标

![图片.png](images/img_19183_094.png)

多了一个isReturn，也就是污点会影响到返回值

那么看起来两个循环是不是功能上有重叠？

说起来一个关心输入一个关心输出，那么必然有些场景是有输入没输出，而有些场景是由输出没输入的

场景1：纯输入

```
public void logUserInput(String userInput) {
    // 只接收污点输入，但不产生污点输出
    logger.info("User input: " + userInput);
}
```

那么配置就应该为：

```
Sources:
  - type: PARAMETER
    index: 0
Targets: []  # 没有输出目标
```

场景2：纯输出方法（只有Targets）

```
public String generateDefaultData() {
    // 不接收污点输入，但产生污点输出
    return "Default: " + System.currentTimeMillis();
}
```

配置：

```
Sources: []  # 没有输入源
Targets:
  - type: RETURN  # 只有输出目标
```

场景3：有输入有输出

```
Sources:
  - type: PARAMETER  # 输入源：第二个参数
    index: 1
Targets:
  - type: RETURN     # 输出目标：返回值
```

以上yaml都是帮助理解，具体见server上的config文件

##### 第三个循环

当源和目标配置中都没有涉及对象污点时，会清理污点，避免误报

![图片.png](images/img_19183_095.png)

从以上三个循环，可以深刻理解到：

一个SourceNode包含了几个重要的元素：

policyKey：指名了Node为SourceNode

Source：输入源

Target：污点输出目标

在完成三个循环后，会把满足条件的Source包装成一个MethodEvent，放到EngineManager.TRACK\_MAP，代表了一个污点路径

![图片.png](images/img_19183_096.png)

最后来看看前面提到的trackTarget方法（会调用到trackObject），如果source的结果是Map、Collection、Array之类的，会进一步遍历其所有值，都加入TAINT\_HASH\_CODES/TAINT\_RANGES\_POOL

![图片.png](images/img_19183_097.png)

#### SinkImpl

前面装填了TAINT\_HASH\_CODES，那么这里就会进入DynamicPropagatorScanner().scan(event, sinkNode)

![图片.png](images/img_19183_098.png)

跟进到scan，也是看到了我们开始plugin增强时遇到的对fastjson/QLExpression/XXE的isSafe校验

注意到sinkSourceHitTaintPool

![图片.png](images/img_19183_099.png)

跟进sinkSourceHitTaintPool，这里有中文注释，过滤未命中污点池的sink方法，设置污点源去向，代码就不看了

![图片.png](images/img_19183_100.png)

### 上报云端

请求结束时，会调用ServletDispatcherAdviceAdapter#leavHttp，跟进到Spy的实现，这个方法里会调用GraphBuilder.buildAndReport();去把信息上报云端

![图片.png](images/img_19183_101.png)

可以看到包含了协议，方法名，请求URL，远端地址，参数，body等信息

![图片.png](images/img_19183_102.png)

对应的ApiPath（虽然官方文档也有）

![图片.png](images/img_19183_103.png)

## others

具体的sink source的插桩结果可以把agent运行起来后，用Arthas从内存把类dump下来

另外dongtai agent安装时可以直接指定dump参数

<https://doc.dongtai.io/docs/development/dongtai-java-agent-doc/configuration-properties/>

![图片.png](images/img_19183_104.png)

分析下来，如果是想不通过web server去维护source之类的Node，也可以手动改policy.json，然后启动时命令行传入。

本次也并没有分析propagator传播的具体逻辑，我这个莽夫还没能力改造

参考：

<https://y4er.com/posts/dongtai-iast/>

<https://doc.dongtai.io/docs/development/dongtai-java-agent-doc/maven-build/>
