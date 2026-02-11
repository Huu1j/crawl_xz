# JAVA代审之crmeb_java-先知社区

> **来源**: https://xz.aliyun.com/news/16963  
> **文章ID**: 16963

---

# 项目介绍

Java商城 免费 开源 CRMEB商城JAVA版，SpringBoot + Maven + Swagger + Mybatis Plus + Redis + Uniapp +Vue+elementUI 包含移动端、小程序、PC后台、Api接口；有产品、用户、购物车、订单、积分、优惠券、营销、余额、权限、角色、系统设置、组合数据、可拖拉拽的form表单等模块，大量的减少了二开的成本。

# 环境搭建s

项目地址：<https://gitee.com/ZhongBangKeJi/crmeb_java/archive/refs/tags/v1.3.4.zip>

官方安装手册：

<https://doc.crmeb.com/java/crmeb_java/2211>

源码下载到本地后，等待maven加载

加载完成后，可以使用下面命令验证

```
mvn clean
```

![image.png](images/20250225152310-5e1fc87f-f349-1.png)

修改数据库配置信息

配置文件目录

crmeb\_java-v1.3.4\crmeb\crmeb-admin\src\main
esources\application.yml

![image.png](images/20250225152311-5eaf2acd-f349-1.png)

创建对应数据库，并且导入sql文件

sql文件：crmeb\_java-v1.3.4\crmeb\sql\Crmeb\_1.3.4.sql

![image.png](images/20250225152312-5f0d062e-f349-1.png)

然后启动项目

访问：<http://127.0.0.1:8080/doc.html>

出现下面页面，后端启动成功

![image.png](images/20250225152313-5ff1c93f-f349-1.png)

然后启动前端

先看下配置对应后台是否对应

配置文件：

crmeb\_java-v1.3.4\admin\.env.development

![image.png](images/20250225152315-611efdf4-f349-1.png)

接着cd到/admin目录下，执行`npm install`

项目依赖安装好后，执行`npm run dev`

![image.png](images/20250225152316-61b78d0e-f349-1.png)

访问对应地址，出现下面页面就搭建成功了

![image.png](images/20250225152319-633646ec-f349-1.png)

后台账户：admin/123456

# 漏洞挖掘

## 多处SQL注入

查看sql使用api

![image.png](images/20250225152320-640d3cfe-f349-1.png)

是mybatis，全局搜索${

![image.png](images/20250225152322-64f57586-f349-1.png)

有不少，这里随便点个

### 第一处

文件：src/main/resources/mapper/store/StoreOrderMapper.xml

跳转**getRefundPrice**方法

![image.png](images/20250225152323-659f1189-f349-1.png)

查看调用

![image.png](images/20250225152325-66bd6ea4-f349-1.png)

关注where

![image.png](images/20250225152327-68399694-f349-1.png)

在212行给where给了个默认值，关注下面的if条件，因为有where的赋值操作

分别是dateLimit.getStartTime() | request.getKeywords() | request.getStoreId()

这里其实我们可以优先看%%的，演示我们就一个个看了，第一个if

![image.png](images/20250225152329-6934dfae-f349-1.png)

判断request.getDateLimit()是否有值，对应的参数是dateLimit

![image.png](images/20250225152330-69c4d91c-f349-1.png)

这里有个DateUtil.getDateLimit方法，这个方法是什么呢，可以问下ai![image.png](images/20250225152331-6a9bfb06-f349-1.png)

那么也就是说这里它会对我们传入的数据进行格式转换，那么这里就不存在注入了，因为数据在传输的过程中被修改了

第二个if

![image.png](images/20250225152332-6b3fe1fb-f349-1.png)

这里我们看下request.getKeywords() ，是通过Keywords参数获取的

![image.png](images/20250225152334-6c17d2c6-f349-1.png)

并且这里获取到Keywords是直接拼接到where中的，那么这里我们只要满足if条件Keywords不为空就可以直接拼接sql语句，并且这里没有看到数据操作的点，那么这里是存在注入的

第三个if

![image.png](images/20250225152335-6cb145ba-f349-1.png)

这里和第二处一样，这里没有对传入的数据进行额外操作，我们看下request.getStoreId()，发现有类型限制

![image.png](images/20250225152336-6d16edab-f349-1.png)

那么这里只要第二处有，测试下，查看getWriteOffList方法使用

![image.png](images/20250225152336-6d69dcab-f349-1.png)

跟到路由层，通过注释也能知道功能点，或者自己感觉路由构造包也行

![image.png](images/20250225152337-6dd9f42e-f349-1.png)

使用数据库工具监控下，看下有没有找错

![image.png](images/20250225152337-6e2e4679-f349-1.png)

抓包，sqlmap搜哈

![image.png](images/20250225152338-6e8daf62-f349-1.png)

### 第二处

对应文件：

```
crmeb_java-v1.3.4\crmeb\crmeb-service\src\main\resources\mapper\user\UserMapper.xml
```

![image.png](images/20250225152339-6ef5d8e2-f349-1.png)

参数是groupId记一下，定位到**findAdminList**方法

![image.png](images/20250225152339-6f48c7bf-f349-1.png)

参数是个map，查看调用

![image.png](images/20250225152340-6fa37180-f349-1.png)

![image.png](images/20250225152340-6ffaf70c-f349-1.png)

关注map.put的参数，找**groupId**

![image.png](images/20250225152341-704d2a95-f349-1.png)

找到了，通过request.getGroupId获取

![image.png](images/20250225152341-709c4abb-f349-1.png)

查看上级调用

![image.png](images/20250225152342-70fde3d6-f349-1.png)

跟到功能层，发现是会员功能处，这套系统没发现会员功能点，有用户我们看下![image.png](images/20250225152343-7156dbed-f349-1.png)

随便搜索东西，抓包

![image.png](images/20250225152343-71a8b818-f349-1.png)

发现**groupId**，sqlmap搜哈

![image.png](images/20250225152344-72229053-f349-1.png)

除文中演示的还有很多处存在注入，可以自己下去分析下

## XXE

全局搜索xml解析关键词，测到**SAXReader()**

![image.png](images/20250225152345-72750a22-f349-1.png)

看下代码

![image.png](images/20250225152345-72cae83e-f349-1.png)

创建**SAXReader**，然后**read()**解析xml，in是我们传入的，查看上级调用

![image.png](images/20250225152346-731ef839-f349-1.png)

![image.png](images/20250225152346-7370c04f-f349-1.png)

构造请求路由，测试

![image.png](images/20250225152347-73e89e15-f349-1.png)

还有一处我就不写了各位自己下去测吧

## SSRF(未成功)

搜索关键词，openConnection()

![image.png](images/20250225152348-745eff1a-f349-1.png)

这里关键要关注的是url参数，这里还限定http请求

![image.png](images/20250225152348-74b53589-f349-1.png)

![image.png](images/20250225152349-74fb016a-f349-1.png)

接着往上跟

![image.png](images/20250225152349-7541192b-f349-1.png)

这里又有个要求图片要两张以上

![image.png](images/20250225152350-758a2c96-f349-1.png)

![image.png](images/20250225152350-75dfc14a-f349-1.png)

这里路由有了，要通过 POST 请求传递 list 参数，客户端需要发送一个包含 List<ImageMergeUtilVo> 对象的 JSON 数组![image.png](images/20250225152351-76355025-f349-1.png)

但是这里会提示没有相关权限应该是什么没配置没能解决，这里应该是有漏洞的，查了下发现有CVE编号

![image.png](images/20250225152351-7697a1df-f349-1.png)

应该是我传参的问题

## XSS(未成功)

这个是查SSRF的时候顺便看到的，发现有个XSS，想着复现下

![image.png](images/20250225152352-76ec4bf7-f349-1.png)

但是我本地复现没成功，给个参考链接感兴趣的师傅自己下去看看

<https://github.com/crmeb/crmeb_java/issues/12>

## druid未授权

存在druid组件，看配置文件发现不用登入就能访问

![image.png](images/20250225152353-774d0b59-f349-1.png)

## swagger文档泄露

![image.png](images/20250225152353-77be3db5-f349-1.png)
