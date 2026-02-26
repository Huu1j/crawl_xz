# 记一次传统javaweb项目审计-先知社区

> **来源**: https://xz.aliyun.com/news/17113  
> **文章ID**: 17113

---

# 环境搭建

下载地址：<https://gitee.com/huang-yk/student-manage/repository/archive/master.zip>

源码下载到本地后，IDEA打开等待maven加载

修改数据库配置文件

src/druid.properties

![image.png](images/20250307162612-d3fd0f1b-fb2d-1.png)

创建对应数据库

![image.png](images/20250307162614-d55d8ba7-fb2d-1.png)

然后由于项目的传统javaweb项目，不能直接tomcat配置启动，会有点麻烦

打开项目结构

![image.png](images/20250307162615-d63f26d6-fb2d-1.png)

先添加模块，配置web，指向对应web.xml文件

![image.png](images/20250307162617-d6f61ec4-fb2d-1.png)

然后配置tomcat，添加库，指向本地tomcat/lib

![image.png](images/20250307162617-d77b4325-fb2d-1.png)

最后配置工件

![image.png](images/20250307162618-d81aad3a-fb2d-1.png)

然后保存，配置tomcat启动

![image.png](images/20250307162619-d8a99260-fb2d-1.png)

这里路径要注意下，因为代码中路由是写死的

![image.png](images/20250307162620-d9057be6-fb2d-1.png)

![image.png](images/20250307162621-d9db3c1a-fb2d-1.png)

如果启动的时候出现缺少依赖的情况，自己从maven搜索对应依赖下载到本地添加为库就行

管理员账号：admin/123

# 代码审计

## 鉴权绕过

看下这套系统的鉴权逻辑，这套系统的鉴权是写在filter

![image.png](images/20250307162623-da9b5a8e-fb2d-1.png)

一共两个，一个是校验管理员的，一个是校验普通用户的，我们先来看管理员的

![image.png](images/20250307162623-db18c161-fb2d-1.png)

这里的逻辑是获取我们登录账号的UserType，判断值是否为1

![image.png](images/20250307162624-db8c867b-fb2d-1.png)

那么这里管理员接口不能未授权，我们只能尝试普通用户能否提权，也就是能否把usertype修改为1

全局搜索usertype,看下有没有可控的sql语句

![image.png](images/20250307162625-dc11d97b-fb2d-1.png)

![image.png](images/20250307162626-dc7b49a0-fb2d-1.png)

添加用户的功能点，关注user\_type

![image.png](images/20250307162627-dd1bc28d-fb2d-1.png)

默认写死了，那这里就没办法了

看下另一个后台鉴权

![image.png](images/20250307162628-dd98bf3e-fb2d-1.png)

重点关注下面这个不需要登入

```
for (String passUrl : passUrlList) {
    if(passUrl.equals(pageName) || passUrl.equals(endName)) {
       //不需要登录
       needLogin = false;
    }
}
```

看下这个静态资源是啥

![image.png](images/20250307162628-ddf4ebb5-fb2d-1.png)这里看着好像逻辑没问题，但是这里使用的是uri.lastIndexOf("/") 和 uri.lastIndexOf(".") 提取页面名称和后缀名，在tomcat中会对；进行特殊处理，例如：

```
http://example.com/resource;jsessionid=12345
```

在这个例子中，;jsessionid=12345 是一个路径参数，Tomcat 会将其解析为附加信息，而实际的资源路径是 /resource

Tomcat 等中间件在解析 URL 时，默认会忽略分号及其后面的内容

后端采用HttpServletRequest.getRequestURI() 获取请求的 URI

中间件会将 ;.png 忽略，不会将其传递给后端

也就是说传到后端的内容如下

```
http://example.com/resource
```

这里会照成中间件和后端解析不一致

这里动调下看着会清楚点

![image.png](images/46f1e238-afad-3a7f-81e6-92764fd381a7)

找个后端非管理员功能点测下

![image.png](images/20250307162629-de6824cb-fb2d-1.png)

获取教师信息的功能点

![image.png](images/20250307162630-def50a5f-fb2d-1.png)

## 多处SQL注入

先判断数据库使用技术，项目额外依赖中未发现其它数据库技术，判断为JDBC，全局搜索append或者+

![image.png](images/20250307162631-df6fe042-fb2d-1.png)

不少直接拼接的地方，随便点几个看看

![image.png](images/20250307162632-dff475cc-fb2d-1.png)

注释是获取学生信息的功能，看上级调用

![image.png](images/20250307162632-e060e9dc-fb2d-1.png)

![image.png](images/20250307162633-e0e01fee-fb2d-1.png)

get接收参数query，路由是/admin/adminStudentUrl，构造测试下

![image.png](images/20250307162634-e16444bb-fb2d-1.png)

sqlmap启动

![image.png](images/20250307162635-e1de1fdd-fb2d-1.png)

除了这处还有几处，这里就不演示了

## XSS

这种系统基本是XSS重灾区，随便插几个

### **学生管理**

![image.png](images/20250307162636-e25479bb-fb2d-1.png)![image.png](images/20250307162636-e2c10113-fb2d-1.png)

![image.png](images/20250307162637-e32dee99-fb2d-1.png)

### 课程管理

![image.png](images/20250307162638-e3a18959-fb2d-1.png)

![image.png](images/20250307162638-e4012efc-fb2d-1.png)

## CSRF

在代码中未发现CSRF防护，大概率存在

找个功能点测下

![image.png](images/20250307162639-e46777b5-fb2d-1.png)

抓包，生成poc

![image.png](images/20250307162640-e4d5bdd1-fb2d-1.png)

模拟管理员触发

![image.png](images/20250307162641-e541d8ae-fb2d-1.png)

![image.png](images/20250307162641-e5c027d3-fb2d-1.png)

成功添加，可配置前面的xss打组合拳
