# CookieShop商城代码审计小结-先知社区

> **来源**: https://xz.aliyun.com/news/18160  
> **文章ID**: 18160

---

#### 产品介绍

蛋糕商城JPA版本是一个开源的CMS系统，它主要基于Spring Boot 3.4.0进行开发，采用MariaDB数据库，涉及Jakarta Servlet、JSP、JSTL，同时使用了Java通用代码生成器来生成后台界面，使用方可以按需定制页面并对项目进行二开，总体是一个对使用者很友好的产品

​

#### 环境搭建

首先下载产品源代码并使用IDEA导入，随后进行加载项目：

![image.png](images/img_18160_000.png)

​

随后根据配置文件中的数据库连接信息创建数据库并导入/sql目录下的数据库文件

​

![image.png](images/img_18160_001.png)

随后更改项目的端口并启动项目即可：

​

![image.png](images/img_18160_002.png)

​

在浏览器中访问目标系统

​

![image.png](images/img_18160_003.png)

随后使用admin/admin登录系统后台

![image.png](images/img_18160_004.png)

![image.png](images/img_18160_005.png)

随后查看网站首页

​

![image.png](images/img_18160_006.png)

#### 代码审计

##### 硬编码风险

首先我们查看项目的配置文件，发现其中数据库账号密码存在硬编码风险

​

![image.png](images/img_18160_007.png)

##### 长密码拒绝服务

随后我们之间来查看Controller层的代码，在IndexController中我们看到很多都是展示的数据内容项，参数不可控，无可直接的利用点，继续往根据逻辑次序往下查看其他的Controller内容

​

![image.png](images/img_18160_008.png)

随后我们来到LoginController中可以看到这里是处理用户登录认证的Controller代码，我们重点看一下这里的登录认证部分，从下面可以看到这里使用用户的用户名作为salt(盐值)，随后调用UserRegisteAndLogin.getInputPasswordCiph来对用户的密码进行了加密，这里我们看一下加密方式

​

![image.png](images/img_18160_009.png)

可以看到这里使用了SHA-1对用户的密码进行了哈希处理，而且还是3迭代3次，而SHA-1作为不再特别安全的算法来说不是很推荐，不过这里使用了3次迭代增加了撞库的难度和资源消耗，不过正常情况下还是优先推荐使用SHA-512对用户的密码进行哈希后存储，另外这里在处理用户的密码字段数据信息时并未对用户的密码字段的长度进行校验检查导致存在DOS风险

![image.png](images/img_18160_010.png)

但是在我们对此进行验证时缺发现在调用接口进行处理时就已经有一个类似加密的字段数据过来

​

![image.png](images/img_18160_011.png)

刚开始没怎么去想就直接在输入框里面进行了一个简单的长密码填充，随后直接发送请求，然后发现这里不管输入多长的密码，后端报文捕获到的长度都是一致的，刚开始想着应该是表单做了长度限制，但是并不是，我们继续往下看

​

![image.png](images/img_18160_012.png)

表单一侧查看时并未做任何限制检查随后直接跟踪到Login

​

![image.png](images/img_18160_013.png)

发现这里通过Ajax对用户的请求进行了一次SHA-1处理并做了Hex转换也就是说这里不管用户表单中输入多长的数据最终都会在标单提交时转为固定长度的用户密码字段信息进行传递到后端进行登录认证处理

​

![image.png](images/img_18160_014.png)

![image.png](images/img_18160_015.png)

那么这里的利用也很简单我们在捕获到报文之后扩展password字段随后转到后端由后端进行三次SHA-1的迭代哈希计算即可，这里的修复方案也较为简单，在后端进行哈希计算之前对用户传入的密码字段进行校验检查规避长密码拒绝服务攻击，例如：限制密码在0-100bytes以内

​

![image.png](images/img_18160_016.png)

另外大家可能注意到了这里的回显当中的rememberMe，没错这里使用了Shiro进行用户的登录认证鉴权，但是这里并没有对remember进行入参，所以不可利用

​

![image.png](images/img_18160_017.png)

![image.png](images/img_18160_018.png)

底层调用为Shiro中的鉴权：

​

![image.png](images/img_18160_019.png)

##### SQL注入漏洞挖掘

在当前项目中我们在查看Controller时发现涉及到的后端的数据库查询总是使用Java Persistence API(JPA)查询方式并通过参数绑定来防止SQL注入

​

![image.png](images/img_18160_020.png)

参数化绑定查询

​

![image.png](images/img_18160_021.png)

为了便捷我们这边直接在DAO文件中进行检索可疑的SQL注入点，发现全部使用了预编译模式，无法进行SQL注入.....最终JPA类下的SQL注入以失败告终

​

![image.png](images/img_18160_022.png)

在我们即将宣布不存在SQL注入问题的时候我们查看到了一个ServiceImp，其中看到了关于直接进行SQL语句拼接的场景，重燃了我们对SQL注入挖掘的想法

​

![image.png](images/img_18160_023.png)

​

随后查看调用位置处可以上溯到CookieShop\src\main\java\org\javaforever\cookieshop\controller\CustOrderController.java中的searchCustOrdersByFieldsByPage方法，从中可以看到这里的入参可控，在结合我们后端的SQL语句凭借由此为SQL注入的前提打下了基础

​

![image.png](images/img_18160_024.png)

​

SQL查询执行

![image.png](images/img_18160_025.png)

随后进行漏洞的验证，首先是定位功能，功能位于后台的订单栏目中，查询是调用接口进行查询操作，随后使用SQLMAP跑即可

​

```
POST /custOrderController/searchCustOrdersByFieldsByPage HTTP/1.1
Host: 192.168.204.151:8080
Content-Length: 100
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://192.168.204.151:8080
Referer: http://192.168.204.151:8080/pages/custorders.html
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=cdbccbc0-f54a-4536-9220-80bccfdd5d97
Connection: close

name=1*&active=&total=&amount=&status=&paytype=&phone=&address=&orderDateTime=&user=&page=1&rows=10
```

##### XSS跨站脚本攻击

首先我们查看前端的html页面是否有可控的输入点从而导致XSS的情形，首先来查看用户注册的界面，这里会有用户的地址、描述、email可控的字段

![image.png](images/img_18160_026.png)

前端仅是对用户的userName和password进行检查，其余的字段并未进行入参校验检查：

![image.png](images/img_18160_027.png)

用户注册时填写恶意表单信息并提交，后台查看时触发恶意XSS，点位位于邮箱地址和描述信息，当然在下单的时候地址那里也存在XSS问题，这里就不再赘述了：

![image.png](images/img_18160_028.png)

![image.png](images/img_18160_029.png)

在商品搜索时根据keyword进行检索，可以看到这里的入参最终也作为了model的一个属性进行页面显示

![image.png](images/img_18160_030.png)

在页面中直接展示，期间未经过任何过滤处理，从而导致XSS

![image.png](images/img_18160_031.png)

![image.png](images/img_18160_032.png)

##### **越权漏洞挖掘示例**

CookieShop分管理员和非管理员两种形态

![image.png](images/img_18160_033.png)

下面我们以管理员后台的order删除为例进行越权的介绍，从这里可以看到入参id之后直接调用orderService.deleteCustOrder(id);进行订单的删除操作

​

![image.png](images/img_18160_034.png)

跟踪实现类

​

![image.png](images/img_18160_035.png)

随后调用dao.deletCustOrder进行删除操作

​

![image.png](images/img_18160_036.png)

后端SQL语句如下所示：

![image.png](images/img_18160_037.png)

![image.png](images/img_18160_038.png)

使用Burpsuite抓包

![](file:///F:/WizNote/MyKnowledge/temp/cc3e33d4-7ca4-4258-80ef-31e4c57ae5ae/128/index_files/f48c2a6b-aed8-402e-a64c-28cc1ed4cada.png)

![image.png](images/img_18160_040.png)![](file:///F:/WizNote/MyKnowledge/temp/cc3e33d4-7ca4-4258-80ef-31e4c57ae5ae/128/index_files/f48c2a6b-aed8-402e-a64c-28cc1ed4cada.png)

使用普通用户登录然后捕获其JESSIONID

​

![image.png](images/img_18160_042.png)

#### 

随后进行删除操作

![image.png](images/img_18160_043.png)
