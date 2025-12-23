# 记一次差点给Jadx提Issues的踩坑日记

> **来源**: https://forum.butian.net/share/2869  
> **文章ID**: 2869

---

前言
==

本篇文章首发在先知社区 作者Zjacky(本人) 先知社区名称: `Zjacky` 转载原文链接为‍<https://xz.aliyun.com/t/13859>

好心酸写这篇文章的时候，因为已经是下午四点整了，从早上的10点开始审这个代码，到现在只解决了一个问题，想SI的心都有了，还是含泪记录下本次`Java`​的踩坑记录吧，可能有师傅遇到过可能也觉得我很逗比，但还是发出来减少大家遇到这种问题的情况吧

‍

‍

踩坑日记
====

起因是因为有套Java被催着审，于是买了杯维他命水就开始看了，常规简单的操作就不说了什么上依赖反编译啥的，因为这些老生常谈而且作为审计Java的师傅来说真的就是家常便饭，所以我反编译啥的只是时间问题，于是就快速一顿操作进行基础环境的搭建就开始审计了

‍

文件上传
----

搜索`upload`​一个一个找 发现了在这里

`@RequestMapping({"/attachment/*"})`​

有个`fileUpload.action`​映射

![image](images/attach-3d7b7f3ba92c6992d6ec8d2dd4b0261faf000863.png)​​

![image](images/attach-a7ff650adb4aa614ad645d22a0315d60db6a85f0.png)​

跟进`saveFile`​方法 发现是接口的方法，寻找实现接口的类重写的`saveFile`​方法

‍

![image](images/attach-0fd205db154c617f72071ce542528722f52be94c.png)​

‍

跟到`\service\impl\AttachmentServiceImpl.java`​

‍

![image](images/attach-c7547e8086e30770d295ec8a55cf7165db4a2891.png)​​

关键代码就是

‍

```java
String fileSuffix = FileUtil.getFileSuffix(uFile.getOriginalFilename()); // 直接获取用户上传的文件名后缀
String fileName = String.valueOf(DateUtils.formatNow("yyyyMMddHHmmssSSS")) + fileSuffix; // 并且与时间进行拼接
 String url = String.valueOf(basePath) + "uploadFile/" + attachment.getMark() + "/" + attachment.getUsername() + "/" + fileName; // 生成文件的路径

//接着就是真正的将上传的文件写入到一个File对象当中存储
byte0 = uFile.getBytes();
File targetFile = new File(pathUrl, fileName);
uFile.transferTo(targetFile);
targetFile.setReadOnly();
```

‍

所以代码逻辑就清楚了，后续的关于`Attachment`​其实就是存储文件信息而已，实际已经上传成功了，但是其实这个上传是后台的上传

‍

因为在`web.xml`​中发现过滤器是需要鉴权的

```xml
    <filter>
    <filter-name>sessionFilter</filter-name>
    <filter-class>com.xxx.xxx.filter.SessionFilter</filter-class>
  </filter>
<filter-mapping>
    <filter-name>sessionFilter</filter-name>
    <url-pattern>*.action</url-pattern>
  </filter-mapping>
```

‍

![image](images/attach-cff83421cf813b4857fdcab7c0c9a4b499ce6893.png)​

就是个判断登录的逻辑，所以只能是后台了，由于是很早很早之前的就拿到的源码，当时是找到了账号的初始密码，所以通过默认密码+账号爆破再一次进入到该站的后台当中

‍

上传附件抓到报文

![](images/attach-494747848e31b2d88c9dc4d83fe3cf7b9483c8ee.png)

可以发现他的接口如下

```bash
/xxxx/xxxxx/fileUpload.action;jsessionid=xxxxxx?mark=xxxxx&fileUUID=xxxxx
```

说明`fileUUID`​ 跟 `mark`​ 都为可控点并且是某个处理逻辑进行处理的，比较轻松的就是他返回了上传地址

‍

但是上传jsp的时候就返回了

`上传材料格式不正确`​

![image](images/attach-bd6f9cdd4deeae742cb9ae1499b4762299e31150.png)​​​

‍

虽然源码比较久远，但是马子还在，于是上去再看了下改过的代码下来 发现他有一个很奇葩的写法

![image](images/attach-8ce23151cabfdedafc687113f3e5f6467d4bc466.png)​​

我一开始以为是黑名单，但是仔细一看，发现是白名单啊！

```java
   if (!fileSuffix2.endsWith("jpg") && !fileSuffix2.endsWith("jpeg") && !fileSuffix2.endsWith("gif") && !fileSuffix2.endsWith("png") && !fileSuffix2.endsWith("bmp") && !fileSuffix2.endsWith("jsp") && !fileSuffix2.endsWith("js") && !fileSuffix2.endsWith("html")) {
msg = "上传材料格式不正确";} 
```

但是可是事实就是传不上去，难道是有什么限制吗？于是全局搜索了下`上传材料格式不正确`​ 关键词 ，发现仅仅只有四处存在

![image](images/attach-b09068afb6a9357890d06e656c76cd44a0d38317.png)​​

然后本地测了一下第一个`上传材料格式不正确`​ 发现肯定是能走进去的

![image](images/attach-63b9258eeebefc8516143fbc7187445318641ccc.png)​

第二个`上传材料格式不正确`​也不可能 因为根本走不到这里，因为只要后缀名为空就会被`catch`​捕捉到报错而进行报错，并不会因为后缀名为空就进入到这个`上传材料格式不正确`​中

![image](images/attach-1876700f1884dc9f0e5cfc8122a4efe16d2f775b.png)​

那么其他的就是不是这个接口或者没引用到了，那么回顾下，种种的测试都指向了，我的后缀名`.jsp`​并没有被白名单所匹配到 emmmm。。。存疑？可是我本地没问题啊。。。一样的代码，根本不需要考虑过滤器的原因，如果过滤器这地方拦了就不会显示`上传材料格式不正确`​了，好奇怪

‍

然后经过了两三四五个小时，最终经过了几个小伙伴的帮忙，终于找到了问题！真的x了，找到问题的前一个小时里头，我还写了以下笔记

‍

![image](images/attach-86da1c69edad3e8ae13ebd0ceb5cb76ee6deb357.png)

‍

小丑想法
----

‍

最终发现TMD是`Jadx`​的问题，我发现他针对单文件的反编译是很正常的，但是只要是一个目录下，他就发生了一些错乱，比如 增加莫名其妙的代码或者是反编译错误把别的地方的代码混杂在一起，以下是踩坑记录

‍

首先目录结构如下

![image](images/attach-e7b1543d6d1731ef90c0ef0021feff57d4b1562d.png)

‍

(![](images/attach-5cdb049b7b1607f7fda6c173636720897be72a4a.png))

‍

‍

此时以`IDEA的反编译`​ + `jd-gui.exe`​ + `jadx`​ 三个反编译工具进行演示

‍

以下都关注方法`fileUpload`​内容

IDEA直接打开`AttachmentController.class`​

![image](images/attach-8a14f36bb1d9610a4a6ed7051882fcf130dac2c8.png)​​

`jd-gui.exe`​ 直接打开`AttachmentController.class`​

![image](images/attach-3e5a4c68fe1e028cacaa5753ca5c324fad20a91c.png)​

此时使用`Jadx`​打开单文件

![image](images/attach-e5b78fa668dc0b3f70fc3ef7f63791fc0947bbff.png)​

‍

![image](images/attach-e2c23482331703da18ec8dec22f6460693c889f2.png)​

接下来就是坑点了，使用`Jadx`​打开当前的目录

![image](images/attach-abeaccb03afb0090b51590c97d02c78693975711.png)​

‍

正当我准备搞清楚问题之后，我满脑子已经想好了如何给`Jadx`​进行提交`Issues`​认为百分百是`Jadx`​的多文件目录反编译问题 然后得到@[skylot](https://github.com/skylot) 那牛子的感谢然后觉得今天一天的踩坑非常的值得，可惜做梦是美好的 然而，当我一打开整个目录发现一样可以正常反编译一点毛病都没我当场已经裂开了，真的不知道用什么心情可以形容当时的我

‍

![](images/attach-6a0071273811ad296cb5be9bfe4cf81df6c8778e.png)

然后我去洗了把脸重新去看我反编译的目录的时候，我发现了一个东西---->缓存/备份

![image](images/attach-9a0b2a667a05475438054055cf4516514016f142.png)​

我的妈耶，220627 220926 的`classbak`​ 我没仔细看直接就反编译了，我一口老血吐出来，然后带着这些文件我再次打开这个目录

![image](images/attach-cfdecf3e8a7a434832dbd9d6096986fbc1e94150.png)​

果然万恶之源就是这个备份！！

最终问题解决，一天时间又这样子没了，害，这就是`Java`​吧

‍

总结
==

果然`Java`​真是个神奇的东西，稍微不细心一天就没了，原来时间就这么流逝的，好开心，因为`Java`​又活了一天啦，谢谢你`Java`​

回归正题，以后反编译还是要先留个心眼吧，以后TMD先看看有无缓存 别上来就直接反编译了，害 裂开，为了避免自己二次踩坑，也是写了个非常简单的脚本，源码第一步！先扫扫看看有无可以的文件后缀吧呜呜呜

```python
"""
Author: Zjacky
Date: 2024/1/9
Name: bak_finder.py
"""

# rest of the code goes here

import os
import argparse

parser = argparse.ArgumentParser(description='Scan files for keywords.')
parser.add_argument('-r', '--root', help='the root directory to scan')
args = parser.parse_args()

# 定义你想要匹配的关键字列表
keywords = ['bak', 'beifen']

for dirpath, dirnames, filenames in os.walk(args.root):
    for filename in filenames:
        if any(keyword in filename for keyword in keywords):
            print(os.path.join(dirpath, filename))

# python3 back.py -r 目录
```

![image](images/attach-b601c0bf2383bfcbbd3d6db8064fd5473963fca9.png)​

‍

‍

所以最后回看代码，发现是进行了白名单的限制的 所以上传的洞就没了，于是整个流程下来一天又没了。。。。害，又要继续被迫营业了

‍

‍

‍
