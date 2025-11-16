# 【Web实战】新手入门java审计

> **来源**: https://forum.butian.net/share/2555  
> **文章ID**: 2555

---

jsherpcms审计
-----------

### 环境搭建

源码：<https://github.com/jishenghua/jshERP/releases/tag/2.3>

下载之后用idea导入

![image.png](images/attach-e5e8bf89e51679379a59f550f976bd3059ee1a55.png)  
导入数据库文件

![image.png](images/attach-fd9d8de93835bceb7841d2591887f99e27a4a80b.png)  
然后修改配置文件

![image.png](images/attach-3128f10040f8a85f619c991327f30c5b552d5b9e.png)  
然后启动

测试用户：jsh，密码：123456

![image.png](images/attach-337e6f1959983ae9fa4a184ad4203faef22ba708.png)

### sql注入

因为是审计 在加上该cms用的是mybatis 那当然是sql注入最容易审了

因为mybatis的$ # 号的区别 一个拼接一个预编译 具体区别可自行百度

直接全局搜索${ 寻找拼接sql的地方

![image.png](images/attach-74fb6aca6ef64747593fc29a7ab89a6765e92c6b.png)

![image.png](images/attach-07d080370c743a1fb6592d14e787707faf7a0892.png)  
在这里发现一个在like后面进行拼接sql的 然后全局搜索countsByUser这个

![image.png](images/attach-6299b30d44cda0189ede20099da2ac3f9dd48f89.png)

![image.png](images/attach-927bd79f188e8eb20d190933800de256ef65f5ef.png)  
发现在UserService里面的countUser函数调用了这个sql 然后全局找UserService调用countUser的地方

![image.png](images/attach-c2549c89e5a309c646108dcf7e5f1515a527eab6.png)

### 未授权

查看filter文件

![image.png](images/attach-1551ef3084af299e385f99ea6dc0ce7774eb21d5.png)  
.css#.js#.jpg#.png#.gif#.ico，/user/login#/user/registerUser#/v2/api-docs资源请求不拦截

继续往下看

![image.png](images/attach-9f734a3a1cc59203ec245865b0a4d67378ff73c6.png)  
因为是通过getRequestURI();来获取的

在看55行 只要包含这几个路径就放行 那么可以通过../来进行绕过

测试

![image.png](images/attach-42379bb7fadcf5d549e2f86bac3ddde36fe358a2.png)  
没登录的情况下 访问home会302跳转

![image.png](images/attach-7ca0a760a4e0b613399c3c9d16d65de6b425b886.png)  
成功绕过

下面对于静态资源的校验也是一样的

![image.png](images/attach-a5367df5bd3e8c64214a56647dd4024ff895e863.png)

![image.png](images/attach-97da4edb8403c07adc3213d2cd2c4809280c9479.png)  
跟进这个函数

![image.png](images/attach-27d68ccced3c9f7795eae07a95fc2b8729997f50.png)  
返回true

![image.png](images/attach-ddfb21f62d91c2115413f5290345fc10812074a6.png)  
也是成功绕过

后续其他接口啥的该方式都可对鉴权进行绕过 未授权对接口进行操作

比如

![image.png](images/attach-3f04b62c862dffec9586cfc654bb83f8a7470aee.png)

### 存储xss

这个点是结合黑盒一起看的

先演示

![image.png](images/attach-ec0574e48856f65b6d2aa67b51be87afe9b60e38.png)

![image.png](images/attach-6d91c9aa37302bddc8ea35a492973f69684ff670.png)  
修改备注 然后保存会发现直接弹xss了

![image.png](images/attach-cde6aac5efde4032c88581a0625befaaf88d4981.png)  
然后每次点进来也会弹

分析

首先抓到保存的时候的包

![image.png](images/attach-e16a6ace42a82c3b5b1193d6511cd879d6c6ede0.png)  
从数据包也可以看到前端也是没有过滤的 然后根据数据包路由找到代码

![image.png](images/attach-a5348504e2376569408490ccebf30ae12b61d2e3.png)  
找到controller层 然后跟进分析

![image.png](images/attach-7626f6889bbdf9b07234e23f4d03daa793439245.png)  
可以看到获取到body参数的row 然后直接调用depotHeadService.updateDepotHeadAndDetail函数 继续跟进

因为从数据包里面看到xss语句是在row里面 直接看row传的地方

![image.png](images/attach-c09641a3a8940d686abc462a628e8d341386d1b2.png)  
继续跟进函数

![image.png](images/attach-468762135c444a8be6c9817e6a67d655e40988a4.png)  
从数据包里面可以看到xss payload是在remark参数里面 继续找

![image.png](images/attach-28f4c7c3897bc8e8f2586cca23edcee3971c7728.png)  
一直跟到这里

![image.png](images/attach-4e66e861e16bed79daee547e482d1a8d0ca48ebd.png)  
最后来到这里 然后前面没有看到过滤的操作 继续跟进

![image.png](images/attach-dc3bdcaa1d0b540656a83ae4f798289d621cb7e9.png)  
就直接调用mapper执行数据库插入了 没有进行过滤

打断点 调试到这里也可以看到

![image.png](images/attach-ad88b78c0151d275b627471896cf66833bb13d5d.png)  
这是存入的时候没有过滤 下面看输出的时候

点击编辑的时候会抓到这个包

![image.png](images/attach-c120bcf807f57fa31c247c09378fa091979a3baf.png)  
根据路由全局找到代码

![image.png](images/attach-f62339650211952b288bce80d4aba75ceb683f23.png)  
根据headerId来进行查询数据

![image.png](images/attach-e38d47195245d5b98b5ffdf7d37cf42df1b4112d.png)  
查到数据也是直接返回 没有过滤 然后返回给前端

![image.png](images/attach-108d93e0496267ba580038ce1af58bff3f55cbf2.png)  
返回的json格式

![image.png](images/attach-2249d51eaa78977232bb81f1d5ca3e600a456595.png)  
然后来到前端页面 因为返回的是json格式前端肯定是发出ajax请求来获取数据的 直接来到页面搜索api：/depotItem/getDetailList

![image.png](images/attach-52b71183e000dd7c9b0c869e35d61035f6e8b69a.png)

![image.png](images/attach-006661042afaac90edeaa89304717a9a0ff08818.png)

![image.png](images/attach-9aa96bcda4c57b209f7118258196ab4c28fe1211.png)  
拿到数据后是通过datagrid来渲染的 也就没有过滤 所以造成了xss

datagrid可以自行百度一下

![image.png](images/attach-b3d1a438b1d73c162cb8932ec9e6fc506300f3f2.png)  
也就是说 其他地方也都是这种 存在存储xss 不止这一个页面

![image.png](images/attach-4d9d78568edd85ebb8f7e59bbf6c26101907516c.png)

### 越权

进入账号用户管理 然后编辑用户 重置密码

可以看到这里有一个id

![image.png](images/attach-8292381f68c9b222695374694e3d153e1e74acdc.png)  
然后根据路由来到代码的地方

![image.png](images/attach-73035bdcd78b06b325d73a886e1b7b669dcfc14c.png)

![image.png](images/attach-e6ad908d42bfb630ea695ee1484848c55c1d5233.png)  
在这里就校验了重置的账号是不是admin 没有其他鉴权操作 也就是说可以直接重置admin开外的所有账户

测试

登录test3

![image.png](images/attach-ebb0afb478d450f15117f48f04b9a760e88f3c63.png)  
抓到cookie 替换到刚才的包

![image.png](images/attach-c4f46d32b1a96280c39d36ab826991fae5771ef5.png)  
test2 id为135

![image.png](images/attach-a61bf5d7a391fc3336aeb9e1ed39a6772f8f2b93.png)  
这里越权重置密码之后 可以越权修改

越权2

越权修改密码

在第一个越权重置之后 修改密码的地方同样也可以越权

![image.png](images/attach-030be476bf3bede1b2b913f82a59490564e9c3d1.png)

![image.png](images/attach-cbb7bcd963c61039257219ee3024a9217f5d1b1d.png)  
同样也没有什么鉴权

比对了一下旧密码 但因为之前已经重置 所以 也可以修改

像什么删除这些也是同样可以的

![image.png](images/attach-0dedc001c58dcfa083c7fa4e7bb57672196069be.png)

### 接口泄露

![image.png](images/attach-3f284c658cbca3ed44dc72a27daa200259f6cfd4.png)  
这个是直接能够访问的 通过接口泄露 也就可以知道前面越权的api接口

3.1新版都已修复  
如sql注入

![image.png](images/attach-4ff263fbbb9d530ae1ef82eaa074f525b7b14690.png)

![image.png](images/attach-cfed3479fee5c08b5e073bae3da50b10560585e3.png)  
${ 改成了#{  
**\#{} :** 对读取到的参数先使用?来占位，然后去预编译SQL，最后再将?替换为形参值。

**${} :** 直接替换读取到的形参值，没有预编译的过程。

接口泄露的url也没了

![image.png](images/attach-c51282fb9056cfaa87ae96be09e2d9e5a6aaafdc.png)

其他也都类似
