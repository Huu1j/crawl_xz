# JAVA代审starsea-mall-先知社区

> **来源**: https://xz.aliyun.com/news/17148  
> **文章ID**: 17148

---

# 环境搭建

项目地址：<https://github.com/StarSea99/starsea-mall>

下载到本地，IDEA打开等待maven加载

修改对应配置文件：

src/main/resources/application.properties

![image.png](images/20250311144613-865bc980-fe44-1.png)

创建对应数据库并导入sql文件

![image.png](images/20250311144614-8713596c-fe44-1.png)

启动项目

![image.png](images/20250311144615-87b150ee-fe44-1.png)

后台地址：[http://127.0.0.1:8080/admin/login](http://192.168.21.1:8080/admin/login)

账号密码：admin/admin

# 代码审计

还是先看鉴权文件

![image.png](images/20250311144616-8840d1f6-fe44-1.png)

有三个拦截器，分别看下

**AdminLoginlnterceptor**

![image.png](images/20250311144617-88a65506-fe44-1.png)

校验后台的权限，if判断，访问地址/admin并且从seesion中获取loginUser，如果没有代表没登入

这里没办法绕过

**MallCartNumberInterceptor**

![image.png](images/20250311144618-89140519-fe44-1.png)看样子是更新购物车商品数量的一个方法

获取当前的session信息，然后带入数据库查询，获取购物车信息，修改购物车商品数量然后保存

**MallLoginInterceptor**

![image.png](images/20250311144618-8970932f-fe44-1.png)

判断前台用户是否登录的方法

优先测前台用户的功能点

![image.png](images/20250311144619-89e264a9-fe44-1.png)

## 任意会员登录

在更改个人信息的功能点，本来是打算测下xss，保存信息看下数据包

![image.png](images/20250311144620-8a52add9-fe44-1.png)

发现这里有个userid，想着能不能越用户修改信息，替换成其它会员的

![image.png](images/20250311144620-8aab642a-fe44-1.png)

![image.png](images/20250311144622-8b55a4b9-fe44-1.png)

这里发现信息变成对应id的用户了，看下代码

![image.png](images/20250311144622-8bcea634-fe44-1.png)![image.png](images/20250311144623-8c51e03c-fe44-1.png)

通过userid查询用户信息，然后if判断用户是否存在，然后更新我们设置的信息，从数据库查询更新后的用户信息，将数据库查询结果复制到 UserVO 对象中然后存取到会话中，然后返回 UserVO 对象，这里数据返回的时候获取的是我们设置的id

![image.png](images/20250311144624-8ccc0119-fe44-1.png)

然后通过我们设置的id获取数据

![image.png](images/20250311144625-8d3e058d-fe44-1.png)

那么这里等于任意会员登录了

## 支付逻辑0元购

既然是商城系统，支付逻辑可以说是必测的

### 任意订单状态修改

我们测试下正常的订单支付

![image.png](images/20250311144625-8da90d4b-fe44-1.png)

支付成功的数据包

![image.png](images/20250311144626-8e0b6b34-fe44-1.png)

![image.png](images/20250311144627-8e726c39-fe44-1.png)

![image.png](images/20250311144627-8edf38a6-fe44-1.png)

先查询对应订单，然后把订单的PayType设置为我们传入的值

![image.png](images/20250311144628-8f5b77ac-fe44-1.png)

支付成功后对应订单的pay\_type变为1，那么这里我们可以通过修改订单号实现0元购

新建一单

![image.png](images/20250311144629-8fcb2293-fe44-1.png)

把数据包改成新的单号

![image.png](images/20250311144630-903a0d94-fe44-1.png)

![image.png](images/20250311144630-90a5e874-fe44-1.png)

### 购物车商品负数

![image.png](images/20250311144631-910645cc-fe44-1.png)

修改商品数量为负数

![image.png](images/20250311144632-9160092e-fe44-1.png)

![image.png](images/20250311144632-91c490de-fe44-1.png)

![image.png](images/20250311144633-922c6e31-fe44-1.png)

分析代码

![image.png](images/20250311144634-9299a5f0-fe44-1.png)

![image.png](images/20250311144635-931e07df-fe44-1.png)

这里只会判断单个商品的最大数量，没有检测数量是否为正整数

## 任意文件上传

后台功能点

![image.png](images/20250311144635-93937bac-fe44-1.png)

![image.png](images/20250311144636-942f0570-fe44-1.png)

定位代码段

![image.png](images/20250311144637-949e0405-fe44-1.png)

这里获取我们的文件后缀，代码中没有看到关于后缀的检测，然后直接拼接到文件名中

![image.png](images/20250311144638-9524412a-fe44-1.png)

但是没有解析环境，可以上传html，执行JavaScript验证

## 多处XSS

![image.png](images/20250311144639-95dd6de0-fe44-1.png)![image.png](images/20250311144640-9643c719-fe44-1.png)![image.png](images/20250311144641-96fd6a40-fe44-1.png)

## CSRF

项目中未发现csrf防护组件，也没发现自写预防代码，基本判断存在

![image.png](images/20250311144642-978a7d5d-fe44-1.png)

随便找一处功能点测试下

![image.png](images/20250311144643-97e9555a-fe44-1.png)

修改用户名，抓包生成csrf\_poc

![image.png](images/20250311144644-986f1cc8-fe44-1.png)

模拟管理员点击

![image.png](images/20250311144644-98c3c7d7-fe44-1.png)

![image.png](images/20250311144645-990e9ae9-fe44-1.png)![image.png](images/20250311144645-996f65ec-fe44-1.png)
