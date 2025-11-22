# 记一次前端加解密到sql注入过waf的实战

> **来源**: https://forum.butian.net/share/2618  
> **文章ID**: 2618

---

### 信息收集阶段

- - - - - -

开启日常渗透工作，第一步，打开爱企查、天眼查、对准测试资产开始狂飙！找到一个授权范围内的资产，按理说应该收集一波域名、跑一下子域名的，再fofa、hunter搞起的。那天心血来潮直接访问了一下主站，没想到burp一上来就开始飙绿\\~~~~

![图片.png](images/attach-368dd983b6dc27aff51277690c9d04b0b4148d1d.png)

我的burp安装了HaE插件，自定义了一些容易出洞的关键字。发现这个主站，出现了很多排序的关键字，而且还没做映射（挺随意的）。（排序注入是sql注入中，高频出洞模块，目前mybatis对排序的方案中，只能使用${}传入排序字段，所以必定有注入。除非接口做了映射，例如：用户只能传 枚举类型参数 ，后台代码程序把这个 枚举类型参数 使用case when转化为排序关键字拼接到mybatis的xml文件中，不在 枚举中的参数，直接拼装default参数）

![图片.png](images/attach-9e2a1bbb54e36cdca07f3fa4f87a9752cb2cece7.png)

- - - - - -

### 发现验签

- - - - - -

查看排序注入是否存在，直接重放接口，返回正常

![图片.png](images/attach-7ab42962c5f444a5445ea223ab0ea56574110758.png)

排序字段加 ,0 ,1 看看是否有报错

![图片.png](images/attach-abb5ea9188f0a8963f33e31b919fafca877da69a.png)

验签了，碰到验签，按经验来说，盲猜是sign这个头。Fuzz一下，Sign去掉后报错，不能为空！  
Sign:   
Sign: 1  
Sign: 2  
Sign: test

![图片.png](images/attach-d81b70d65129b1d613b6a93623187ab76b76ab5d.png)

这些都有可能绕过验签，因为开发前期测试的时候肯定不会改一下参数，还自己去计算一下sign值的。如果请求头有 encryptType:1 这种参数也可以试着修改，一般这个参数控制着后台加密类型。具体这个绕过参数是啥？要么就去fuzz，要么就去看一下js源码，可能会有。我这个案例没这么幸运，没绕过，只能开启 F12 硬刚。

- - - - - -

### 开启 F12 ，vue的前端

- - - - - -

![图片.png](images/attach-dabb5be2b72d3a165d39f532b3de91a0db7ebc47.png)

全局搜索关键字 Sign，找到一处可疑点

![图片.png](images/attach-046c5863de29d0d61c0f0cb19a8273b92c0db98c.png)

打上断点，成功命中！（如果没有命中的话，可以在network中搜索请求的url关键字，看一下调用栈，找一下sign生成点函数）

![图片.png](images/attach-c8b69790b8373f1e6ac54999f90cb6fe2a25ac2a.png)

分析代码，它其实只用到了 2 个参数，post请求体（或者url传的参数）+时间戳。进行了一下字符串组装，然后md5加密转大写。

![图片.png](images/attach-fc0ebcc3d8a0496c43dd09620789c3d5c55c62d1.png)

- - - - - -

原理知道了，接下来就是 “一点点的工作”。

- 方案一  
    我的目的是：burp-repeater 模块重放数据包，因为我要修改里面的参数，所以每次修改完之后，必须要重新计算sign值。接下来就是构思下数据流程：python启动一个flask，相当于一个web服务，作用是拆解出 我所需要的 timestamp 和 post请求体（或者url的传参）；并且会把参数发给node服务，node服务返回计算结果，python程序替换sign值。Node启动一个web服务，计算这个sign值。

使用 burp-autodecoder插件，把repeater里面的数据包发给我的 python程序，python程序提取一下我所需要的 timestamp 和 post请求体（或者url的传参），然后把数据发给webstorm程序（这个程序就是node启动一个web服务）

![图片.png](images/attach-b7bf948a7ba1a55fc045ad7769b410d7e0f65337.png)

Autodecoder：

![图片.png](images/attach-3076839e961cd3df59b929051c1bedb134013a52.png)

![图片.png](images/attach-ad2e9be6860062d6b08c358137ce5f4b86993e93.png)

Python启动：

![图片.png](images/attach-2f70dbc1f08a6af7dba1c91326a1dd9823dd4fa1.png)

Node启动：

![图片.png](images/attach-3fcc2dd963abf4d05ea44e8f5e18bc63c8467d71.png)

测试一下，老铁给力不

![图片.png](images/attach-6de7ced543681c57c141715245c138396075ee87.png)

![图片.png](images/attach-1efc9d2cfed0007bb8312d575f79390c93792b48.png)

验签搞定了，而且存在注入（ps：oder排序注入，查询结果必须要有数据，空表查询的话，payload不会被触发）。使用布尔注入

- 方案二  
    直接使用 jsrpc，在内存中直接调用这个加密函数，因为这个插件技术是后期才接触到的，所以用了方案一（有丢丢复杂）。方案二适合网页版，可打断点的场景。方案一适合知道加密原理但是不好打断点的场景，例如分包小程序。
    ---------------------------------------------------------------------------------------------------------------
    
    ### sql注入阶段
    
    - - - - - -

看看if能不能用

![图片.png](images/attach-1d8c1016c0ceeb18467f10ace5fcb64d9760956f.png)

看看 iif 能不能用

![图片.png](images/attach-ec90b5e7dc2d5b1a189d7403db566559cdc1bb3b.png)

看看case when能不能用

![图片.png](images/attach-4963cf3be037f26f4a3ab161f1d9dca9623069fe.png)

还发现有个waf

![图片.png](images/attach-89108ac00513db0b48bf197d659e67fc7c367bfc.png)

都不能用，使用大招 rlike 报错

![图片.png](images/attach-3c680ec9aef12933097d9fdc9294aa92383f0bc9.png)

![图片.png](images/attach-27828908416498fc91966eb1e8bac8b70315508e.png)

可行可行，构建条件语句

![图片.png](images/attach-2277652064fd479f1cdfd5b710c6f26cab18b685.png)

又是waf，试试注释符号绕过

![图片.png](images/attach-20bc79df91f79ad7b00b51f2d32c50ee7615138f.png)

完美！！！！！

![图片.png](images/attach-3e2fdf75567b57d20f3addc1ded7b288ffa817df.png)

好了！Payload搞定了，接下来就是注出用户名就行了！！！！！

因为怕触发waf直接使用常量 like

![图片.png](images/attach-da1e55a2a2156a69ffdd7c54eae3fc43756edb94.png)

![图片.png](images/attach-2fff491c131cc12ec6211377bd40030b936362f4.png)

![图片.png](images/attach-55e2d6ed6cebd531cb1f4a00ae5e4cc9a3a10a43.png)

注入出数据库用户名：jr\_% 收工收工。
