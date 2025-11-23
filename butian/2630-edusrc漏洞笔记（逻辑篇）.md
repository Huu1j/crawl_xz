# edusrc漏洞笔记（逻辑篇）

> **来源**: https://forum.butian.net/share/2630  
> **文章ID**: 2630

---

刚接触挖洞的时候记录的一些漏洞，全文比较基础，各位大佬轻喷

话不多说直接进入正题，首先是fofa搜到了某学校后勤管理界面

![](images/attach-76848a699ef6b56de1b3f8358cfa716697cfedbb.png)

弱口令直接进入后台，可以直接看到学生信息，包括详细敏感信息全部囊括其中，因为涉及敏感加上弱口令已被修复，不方便给大家上图，请见谅

![](images/attach-36b4af20bf76057fd29b4b8ddf5746b437976de1.png)

因为在此之前学生系统的漏洞均已被我提交，所以突发奇想，看看能不能用初始密码进入教职工系统。

在这个模块下记录了教职工各类敏感信息以及工号一类

![](images/attach-052e96ef28d8298384083856aefba61cf5a9c5ae.png)

然后开始去搜集资产，寻找登录入口，如下

![](images/attach-86d733b2df50494347a4046c00f4ce66524ca91a.png)

这种站一般都是用身份证后六位作为初始密码

所以我们开始尝试使用工号+身份证后六位尝试初始密码登录

![](images/attach-2cfdfe7f6d956b115b813941ac922ca68ee8cf3d.png)

好像不太行。。。

因为此时弱口令被修复，无法再进入后勤系统寻找账号，不过好在我把登录日志记在了脑子里然后写在表格上方便看，找到一个工号登陆成功的日志，推测没有修改初始密码，

再次进入后台寻找此账号用户（此时是实战经过时漏洞暂未被修复）

![](images/attach-26562b538ee4d4632288f8093733987072ec5cec.png)

拿到账号密码 继续尝试登陆，成功进入教师系统

![](images/attach-be5f16fd9129238e04de378f1323c77545051660.png)

找到一处功能点，用bp开始抓包

![](images/attach-615d8b8bacf999c0ab768863b233dea6108de394.png)

可以看到这里有一个userkey的参数，对应刚才的职工号，

![](images/attach-6a443085afb78fa6843bbfa39c9692a1bf312394.png)

发送到repeater看看，从这里可以看到职工的敏感信息

![](images/attach-e92fae77f387a822d182cff415f30e28cd4fe665.png)

尝试修改参数看看能不能越权查看敏感信息

![](images/attach-eb2962492195c4ed3a85fd27d53ea16bd451bb67.png)

成功越权，到了这里我们可以尝试一下bp的intruder模块进行爆破，看看能不能批量爆破出敏感信息，从而扩大危害

不难发现这些工号都是有一定的规律的，可以尝试构造字典，不过我比较懒，而且构造出来很大一部分都是没有敏感信息的，所以另寻他径，开始寻找存储教职工信息的模块

抽了根烟，冷静了一下，终于找到一处功能点，发现存储了大量任职人员信息

![](images/attach-fbc3c69a75a0f25cf76a5a2b4021f60b3d27a905.png)

![](images/attach-2ce7763b2b2fe856b66ff7faef1ac5d3cd735969.png)

字典有了，我们导出

把刚才抓到的包发送到intruder，准备开始爆破

给userkey参数添加payload

![](images/attach-e862a5540eba03f562d3d9e8de5d79c133ca0513.png)

导入字典，数据量大概在五千条左右开始爆破

![](images/attach-f0b2f53bde273eddbb0e3cfd77e7215bfef3c9a5.png)

成功爆破出五千条敏感信息

![](images/attach-328e2bbfe21b151655b3153e2ca99bde852d1a1c.png)

第一个功能点测试完毕

继续干下一个

![](images/attach-ab3a422e99615cff56bed7a9516c33ed89cc1c8c.png)

发现上传点，尝试上传图片马

![](images/attach-213906ebf36c6d3742b2a2b233cdde795b0e0caa.png)

上传成功，发现对内容没有进行过滤，但是有后缀白名单限制，不对上传的脚本文件进行解析，这里修改为jsp文件也是上传成功

![](images/attach-c77b0758a800a6ef733f0d5a286ff03c4355e433.png)

访问，不解析，只下载

![](images/attach-1734847540ce0eaee87d4a7b5ab115462b687d77.png)

尝试了大部分常用的bypass的办法，发现这里可以解析html文件

![](images/attach-486e9ef8324f3963c28564ad2e8aae1b8622ca29.png)

修改后缀为html拿到返回路径

![](images/attach-1a74e2a7851a0b3bbb92f68a78288b9247c4a6bd.png)

访问，成功造成xss

![](images/attach-031a9f53f173489e818541bd1412099a94835a83.png)

看到几个参数像是路径映射路径,不过我比较懒，混个低危了就没继续深挖了，能存储xss 钓鱼 挂黑页 等等这些

继续往下挖

依旧是一个登录入口，老规矩先抓包

![](images/attach-cdbb9cf6ced2ecf1cbebdbb0feb896ef4f2b9056.png)

这里抓到的手机号替换成自己的试试，看看能不能越权收到验证码

![](images/attach-86433e81b6d269bbb72f12a985f820dad9c66dbd.png)

放包，但是自己的手机号并没有收到验证码，所以开两个页面试一下看看能不能获取到

![](images/attach-ed67091d5f9f185b0e484961494be1fda363f24f.png)

a手机号抓包，修改为b手机号接收，b手机号获取验证码

重复上述改包操作，尝试验证码复用

![](images/attach-c0588eb83815041227de3d8b427628544ae9349b.png)

但此时抓包放包之后系统显示验证码在发送中，其实验证码已经发出去了

拦截放包

![](images/attach-920b220037cf0162b1f34c088ed399ef2689d403.png)

刷新一下尝试用刚才接收的验证码登陆，登陆成功

![](images/attach-e73967425ea4a20f885b9e25b11af544ae9c400a.png)

简单来说过程就是，a手机号验证码登录，抓包替换b手机号，b手机号收到的验证码（此时是第二个页面正常业务功能获取到的验证码）能用a手机号正常登录，原因是系统开发的时候可能是没有校验验证码接收者的用户身份，只校验了验证码发出的时间，导致b手机号接收的验证码越权登录a手机号的账号造成逻辑漏洞出现。

其实我挖洞一直都是佛系，挖的到就挖，挖不到就换，全文比较基础，各位大佬轻喷。
