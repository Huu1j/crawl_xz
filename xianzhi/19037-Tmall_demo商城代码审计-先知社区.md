# Tmall_demo商城代码审计-先知社区

> **来源**: https://xz.aliyun.com/news/19037  
> **文章ID**: 19037

---

# 环境搭建

项目地址：<https://gitee.com/project_team/Tmall_demo>

修改src/main/resources/application.properties中的对应数据库配置信息，创建对应数据库，导入sql文件。

jdk版本1.8

前台地址：http://127.0.0.1:8080/tmall

后台地址：http://127.0.0.1:8080/tmall/admin

后台管理员账户密码：admin/123456

​

如果登录后台出现500，系统错误的提示，可以将src/main/resources/mybatis/mapper/ProductMapper.xml中的最后一条select语句改成如下即可

```
    <select id="selectTotalByGroupCategory" resultType="map">
        SELECT category.category_name name, COUNT(0) value
        FROM product
        LEFT JOIN category ON category.category_id = product.product_category_id
        GROUP BY category.category_id, category.category_name
        ORDER BY category.category_id
    </select>
```

# 代码审计

## 鉴权绕过

在pom.xml中没有发现jwt或者shiro之类的鉴权关键字，看一下目录结构是否有filter或者Interceptor

可以看到存在filter，里面只有一个鉴权文件

![image.png](images/20250928114550-a03c014c-9c1d-1.png)

里面只有一段，可以看到这里，只有url中包含`/admin/login`或`/admin/account`即可直接放行，绕过鉴权。

![image.png](images/20250928114550-a0880b02-9c1d-1.png)

在后台找个需要登录才能查看的功能点

![image.png](images/20250928114551-a0a6402c-9c1d-1.png)

抓包看一下

![image.png](images/20250928114551-a0d5a506-9c1d-1.png)

接着我们退出登录，可以看到直接访问是无法查看人员信息的

![image.png](images/20250928114551-a11d2fde-9c1d-1.png)

在前面加上/admin/login或/admin/account结合目录穿越即可绕过鉴权

![image.png](images/20250928114552-a15b3e9e-9c1d-1.png)

## 前台文件上传

在前台个人资料处的头像上传功能存在文件上传。

在前端校验文件后缀，可以看到使用了uploadImage函数，

![image.png](images/20250928114552-a17a4f02-9c1d-1.png)

在js中搜一下这个函数，可以看到只校验了MIME类型和大小

![image.png](images/20250928114552-a1928e14-9c1d-1.png)

哥斯拉生成个jsp马，后缀改成png，抓包之后再改成jsp即可。

![image.png](images/20250928114553-a1c7d9ac-9c1d-1.png)

抓包可以看到对应的路由为`/user/uploadUserHeadImage`，去源码里全局搜索一下，发现没有对文件进行检测过滤，只是对文件名进行了uuid编码，并且也给了文件路径，也会返回文件名。

![image.png](images/20250928114553-a1f3391c-9c1d-1.png)

在pom.xml文件中也可以看到有jsp解析依赖，传马也能解析。

![image.png](images/20250928114553-a21c39ac-9c1d-1.png)

在前台查看头像地址，再拼接jsp马即可。

```
http://localhost:8080/tmall/res/images/item/userProfilePicture/ac5f3dcf-b85f-4360-b610-59bdbcfcb455.jsp
```

![image.png](images/20250928114553-a24ac100-9c1d-1.png)

![image.png](images/20250928114554-a28176e6-9c1d-1.png)

## 多处sql注入

翻一下pom.xml，可以看到使用了Mybatis，那么大概率会使用

![image.png](images/20250928114554-a2918946-9c1d-1.png)

直接全局搜`${`，可以看到好几处都是使用`orderUtil.orderBy`这个参数，随便找一个跟进去看一下

![image.png](images/20250928114554-a2b82c9a-9c1d-1.png)

![image.png](images/20250928114554-a2cfae38-9c1d-1.png)

搜索一下orderUtil类，这里有两个OrderUtil方法，第一个没有引用，看第二个的使用

![image.png](images/20250928114554-a2ec338c-9c1d-1.png)

优先看一下orderBy参数是否可控，看一下使用

![image.png](images/20250928114555-a30325f6-9c1d-1.png)

这里跟进第二条看一下，可以看到参数是orderBy，通过get方法获取参数，也是可控的。（其他几条也和这种类似）

![image.png](images/20250928114555-a3325fec-9c1d-1.png)

在查询订单这里搜索

![image.png](images/20250928114555-a3526f9e-9c1d-1.png)

可抓到下面这个包，并且有orderBy参数

![image.png](images/20250928114556-a386f430-9c1d-1.png)

直接sqlmap一把梭哈

![image.png](images/20250928114556-a3f661d0-9c1d-1.png)

同样的`admin/product/{index}/{count}`、`admin/user/{index}/{count}`、`admin/reward/{index}/{count}`、`product/{index}/{count}`路由也一样存在sql注入

![image.png](images/20250928114557-a4329f4c-9c1d-1.png)

![image.png](images/20250928114557-a4596a8c-9c1d-1.png)

![image.png](images/20250928114557-a482454c-9c1d-1.png)

![image.png](images/20250928114558-a4bda4ca-9c1d-1.png)

## 

## 多处xss

### 所有产品处

添加商品这里见框就插

![image.png](images/20250928114558-a4d893f4-9c1d-1.png)

然后搜搜产品名称`<script>alert(1)</script>`即可弹出多个xss弹窗

![image.png](images/20250928114558-a4f01770-9c1d-1.png)

### 前台下单/后台查询订单处

![image.png](images/20250928114558-a5111ad8-9c1d-1.png)

提交订单即可弹出xss弹窗

![image.png](images/20250928114558-a523944c-9c1d-1.png)

后台在全部订单这里查看刚刚的订单详情，也会弹窗

![image.png](images/20250928114558-a5420ccc-9c1d-1.png)

### 管理员昵称处

![image.png](images/20250928114559-a559e308-9c1d-1.png)

重新登录，也会弹窗

![image.png](images/20250928114559-a56e2cdc-9c1d-1.png)
