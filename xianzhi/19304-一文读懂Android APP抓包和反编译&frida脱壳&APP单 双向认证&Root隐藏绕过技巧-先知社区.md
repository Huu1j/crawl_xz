# 一文读懂Android APP抓包和反编译&frida脱壳&APP单/双向认证&Root隐藏绕过技巧-先知社区

> **来源**: https://xz.aliyun.com/news/19304  
> **文章ID**: 19304

---

## 0x1 前言

哈咯，师傅们！这次又又又给大家分享文章来了，这篇文章主要是写AndroidAPP抓包和反编译&frida脱壳&APP单/双向认证绕过技巧相关的，总字数有一万字了。emmm之前学习安卓APP抓包，包括最近做APP的众测项目多，所以这里抽几天时间给师傅们分享下相关文章，因为网上这方面总结的文章很少，都是很多年前比较老的文章了，所以就想着分享一篇Android APP相关文章。

![](images/20251119150643-4da9a7d4-c516-1.png)

然后这里师傅们可以看很多渗透测试工程师岗位的招聘，包括后面的工作中，都是需要移动端，Android、IOS进行相关APP测试。所以这里还是建议师傅们可以多学习下APP相关渗透测试，这个后面也是招聘的一个需求。

![](images/20251119150643-4def2c00-c516-1.png)

包括平常我们圈子接的一些渗透测试、众测项目，有时候也会有APP的资产，像这样的很多师傅们都没有真机，没有root，也没有安装一些hook模块插件，就导致很多师傅测试不了，抓不了APP数据包，所以这个还是蛮重要的。

![](images/20251119150643-4e18f71a-c516-1.png)

## 0x2 APP抓包

### 一、浅谈

这里给师傅们来浅谈下APP抓包，因为这篇文章是一个大系列，得先从APP抓包开始写起。

抓包是流量分析的基础，也是安全研究重要的一环。抓包软件有很多种，如 Burpsuite、mitmproxy 以及 Fiddle，抓包方式常见的有设置系统代理、AP 热点抓包、透明代理等。不同方式有不同优缺点，也有不同的应用场景。相信很多安全研究者一定会遇到各种无法抓取流量的问题，本次就来简单总结一下 Android 环境中常用的抓包技术，包括一些应用常用的 SSLpinning、不走系统代理等对抗逆向技术。

这里考虑到很多师傅都是刚学习APP相关的，且没有买真机进行刷机root等操作，所以先拿模拟器给师傅们演示下操作，后续师傅们要是看完文章觉得感兴趣，建议买一个真机来测试下，体验感也是蛮不错的。

![](images/20251119150644-4e2e1366-c516-1.png)

### 二、Android各版本抓包区别

Android抓包版本分为：Android<7和Android≥7两个，其中以前的老版本比如Android6抓包是比较简单的，因为他导入证书师傅方便，直接可以把我们抓包工具，比如burpsuit、Yakit等证书直接导入"用户证书"里面即可。

但是Android≥7你这样导入，开启抓包，数据包是走不过去的，因为这样的导入证书方式安卓系统就不信任“用户证书”里面的证书，你直接安装到用户证书是无效的，他只信任“系统证书”里面的证书，并且系统证书都是 xxxx.0 这种格式。

![](images/20251119150644-4e5692c8-c516-1.png)

不过可以通过多种方式进行导入证书，上面这个截屏是小黄鸟自带的，导入以后也是使用集成化的xxxx.0格式的证书。需要将证书改造成 xxxxx.0 格式，然后再导入到系统证书里面。

![](images/20251119150644-4e87ad4a-c516-1.png)

成功以后就是下面的样子，在信任凭据中系统和用户都有证书即可。

### 三、安装证书移动模块Move Certificate

#### 1、Move Certificate模块简介

这是一个`Magisk/KernelSU/APatch`模块，用于移动用户证书到系统证书。支持`Android 7-15` 如果手机是官方镜像，可能就需要借助模块，如果是自己编译的直接内置或者`remount`手动移一下就行了。

官方项目GitHub地址：<https://github.com/ys1231/MoveCertificate>，下载最新版本即可使用。

![](images/20251119150645-4ef15574-c516-1.png)

#### 2、Move Certificate模块安装

首先，我们下载下来以后是一个zip的压缩包。

![](images/20251119150645-4f43043a-c516-1.png)

然后这里需要我们师傅们先安装adb功能，直接在自己电脑安装即可，这里师傅们可以直接使用我们下载的模拟器自带的adb，下面我是MUMU模拟器，给大家看下自带的（每个模拟器都自带）：

![](images/20251119150646-4f6de242-c516-1.png)

windows的电脑也是一样的，模拟器安装目录下都自带的，然后师傅们可以把这个加入到环境变量中，方便后续直接使用。

![](images/20251119150646-4fb1070c-c516-1.png)

adb常用命令，前提得手机和电脑连接统一Wi-Fi，手机且开启了USB调试模式。

```
 ~  adb push /MoveCertificate-v1.5.5.zip  /sdcard/Download/        //电脑上传文件到手机
 
 ~  adb pull /sdcard/Download/ /电脑路径       //从手机上传文件到电脑
 
 ~  adb install /AppShare-4.0.5\(370\).apk     //直接从电脑端，安装app软件

```

![](images/20251119150646-4fd8604a-c516-1.png)

### 四、Magisk面具安装

安装了Magisk面具，也就相当于设备进行了root操作了，所以这里需要师傅们进行root操作刷机，可以在网上购买已经刷好了的二手手机，这里推荐Google的pixel3-4和小米的8-10，这几个手机都是公认目前最好用的几个刷机安卓手机了，安装的安卓版本基本上都是10-13之间了，版本太低和版本太高都不好操作，买这几个都是可以的。

![](images/20251119150646-4ff5700c-c516-1.png)

一般买了像Google的pixel系列手机，大家也基本上知道你是买来做测试机，所以都有免费帮你刷root的服务，直接问卖家即可，发过来我们拿到手就是已经root了的，且Magisk面具都是已经安装好了的。

![](images/20251119150647-5015af68-c516-1.png)

然后下面就来给师傅们讲解下模拟器安装Magisk面具的操作，需要一个面具的安装包即可。GitHub下载地址：<https://github.com/topjohnwu/Magisk>

![](images/20251119150647-506f08c6-c516-1.png)

下载之后是一个apk的格式，直接利用adb导入手机即可，双击即可安装跟手机一样的操作。

![](images/20251119150648-50bdde18-c516-1.png)

还有一个就是大家常说的狐狸面具，其实功能和上面的一样，只是长的不一样，下面把需要用到的工具都百度网盘打包给大家来，需要的师傅直接下载即可。

```
通过网盘分享的文件：狐狸面具+LSPosed
链接: https://pan.baidu.com/s/1bzdRMqxJdUb5shtHbervQA?pwd=src6 提取码: src6 
--来自百度网盘超级会员v5的分享
```

![](images/20251119150648-50fce6a8-c516-1.png)

安装教程，师傅看这个B站视频即可。

```
【mumu模拟器root安装面具与lsposed框架，修改机型教程】 https://www.bilibili.com/video/BV1fRaUeGE37/?share_source=copy_web&vd_source=268f8d699ac32cf11e9bdc248399c5bd
```

### 五、burpsuit&Yakit证书生成

#### 1、前期准备

上面已经通过介绍，把证书移动安装模块和Magisk面具都已经安装完成了。现在给师傅们演示下模拟器的操作，然后开启模拟器，方便后面使用adb进行相关操作。

模拟器的硬盘切换成可写系统盘 模式：

![](images/20251119150648-512205b4-c516-1.png)

如果使用`adb devices`查看不到模拟器设备的话，我们可以手动开启一下 ADB：

![](images/20251119150649-5143fd68-c516-1.png)

查看 adb 的连接端口

![](images/20251119150649-5162462e-c516-1.png)

这会开启一个局域网的 adb 连接，我们可以使用 connect 连连模拟器：

```
adb devices   //列出模拟器设备
adb connect 127.0.0.1:16384   //连接
```

![](images/20251119150649-518e4ae4-c516-1.png)

这里再给大家看下要是真机该怎么操作，这个肯定是首先得root后的安卓手机，首先得一直连续按七次版本号，然后就可以开启开发者模式。

![](images/20251119150649-51b28c4c-c516-1.png)

然后进入开发者模式，开启USB调试功能。

![](images/20251119150650-51e4e5c0-c516-1.png)

#### 2、证书生成

先讲一个简单的模拟器证书生成和导入，直接不需要知道过程，几条命令就可以直接导入模拟器，进行抓包证书导入。

下载 burp 的证书，并将下载的 der 格式证书转换成 pem 格式，然后转换成 $hash.0 格式，通过 adb push 到模拟器上。

```
# cer 证书转为 pem 证书
openssl x509 -inform DER -in cacert.der -out cacert.pem

# 获取证书的 hash 值
hash=$(openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -n 1)

# 将 pem 证书改成 hash + .0 的格式
new_hash="${hash}.0"
mv cacert.pem "$new_hash"  

# 将证书直接放到系统证书文件夹下
adb push "$new_hash" /system/etc/security/cacerts/
```

上面的操作直接在终端执行即可。

下面的演示，是真机上面的操作，真机且现在安卓版本高点的，都没有那么容易直接导入证书成功的，需要按照下面的步骤来。

Yakit安装证书到移动设备 ，导出证书。

![](images/20251119150650-52506f34-c516-1.png)

下面命令，进行计算证书hash值

```
openssl x509 -inform PEM -subject_hash_old -in yakit证书.crt.pem
```

![](images/20251119150651-52acf986-c516-1.png)

然后直接直接重新命名yakit证书.crt.pem ⇒ 10fb1fcc.0，因为安卓≥7手机证书必须得xxxx.0格式的。

下面是burpsuit导出证书

![](images/20251119150652-5318a1ac-c516-1.png)

导出为cer后缀，所以还需要多一个步骤，改成.pem格式。

```
openssl x509 -inform DER -in cacert.cer -out cacert.pem      //转换格式
openssl x509 -inform PEM -subject_hash_old -in cacert.pem    //计算证书hash值

```

![](images/20251119150652-534023c6-c516-1.png)

/sdcard/Download/是pixel手机的下载目录，方便查找。

```
 ~  adb push /MoveCertificate-v1.5.5.zip  /sdcard/Download/        //电脑上传文件到手机

```

![](images/20251119150652-536830fa-c516-1.png)

直接把zip压缩包通过adb上传到手机的下载文件夹，然后Magisk面具直接从本地安装，选择这个MoveCertificate-v1.5.5.zip压缩包即可，每次通过面具安装完模块都得重启手机才可以生效。

![](images/20251119150653-539238f0-c516-1.png)

我们从burpsuit、yaket改的证书，需要放到目录：/data/local/tmp/cert。

![](images/20251119150653-53bc1c24-c516-1.png)

然后重启模拟器。

![](images/20251119150653-53e1ac6e-c516-1.png)

系统证书目录，已安装成功

![](images/20251119150653-540ada8a-c516-1.png)

burpsuit、yakit等的证书导入成功了。

![](images/20251119150654-5431e11e-c516-1.png)

### 六、抓包测试

这里先按照顺序，来拿模拟器给师傅们演示下简单的抓包流程，因为大部分师傅都还是使用模拟器，并没有使用真机刷root，模拟器的抓包其实是很简单的，详细流程师傅们可以参考我以前写的文章：<https://blog.csdn.net/SENMINGya/article/details/148830397>

首先我们得使用burpsuit开启局域网监听，然后将模拟器的代理指向 burpsuit 的监听端口，选择192.168的IP即可，然后端口9090就好了。

![](images/20251119150654-547a60f8-c516-1.png)

![](images/20251119150654-54a62b98-c516-1.png)

模拟器直接修改网络，手动配置。

![](images/20251119150655-54d1564c-c516-1.png)

IP和端口修改成burpsuit抓包的相同即可。

![](images/20251119150655-5528c99a-c516-1.png)

然后就可以进行抓APP包测试了，过程算是非常简单的操作。

![](images/20251119150656-55998d4c-c516-1.png)

![](images/20251119150657-5614af40-c516-1.png)

## 0x3 pixel 真机APP抓包分享

### 一、浅谈

抓包软件有很多种，如 Burpsuite、mitmproxy 以及 Fiddle，抓包方式常见的有设置系统代理、AP 热点抓包、透明代理等。对于目前简单的抓包，也是目前主流的抓包工具小黄鸟用的最多了，也是最简单方便的一个工具。

小黄鸟官方网站：<https://reqable.com/zh-CN/>，电脑端和手机端都有对应的版本下载，且是免费的。

![](images/20251119150658-56a30f4c-c516-1.png)

### 二、Reqable证书

首先电脑安装完成以后，需要安装本地的根证书，操作很简单，直接一键点击安装即可，Reqable直接会给我们导入。

![](images/20251119150658-5707fde4-c516-1.png)

其次再进行安装安卓手机的证书，手机也是可以直接下载的，安装完成以后，用数据线连接电脑，开启USB调试，且开启adb模式。

![](images/20251119150659-5760ff3e-c516-1.png)

小黄鸟直接按照给的教程来导入手机即可

![](images/20251119150659-579302f4-c516-1.png)

下载下来的小黄鸟文件：reqable-ca.crt

```
openssl x509 -in reqable-ca.crt -out reqable-ca.pem     //改成.pem格式

openssl x509 -inform PEM -subject_hash_old -in reqable-ca.pem    //显示开头的字母再+.0即可
```

然后直接直接重新命名小黄鸟证书 ⇒ xxxxx.0，因为安卓≥7手机证书必须得xxxx.0格式的。

然后按照上面bp和yakit使用证书移动模块一样的操作，导入到/data/local/tmp/cert目录

![](images/20251119150653-53e1ac6e-c516-1.png)

重启手机，即可成功导入证书，小黄鸟这里也显示成功导入用户证书了。

![](images/20251119150700-57fb83e2-c516-1.png)

这里有个手机端证书导入最简单的方法，手机这里直接使用Magisk面具导入Reqable小黄鸟自带的模块即可，里面自带了Reqable证书，且这个操作是最方便的。

![](images/20251119150700-582e9c3a-c516-1.png)

使用Magisk本地模块导入，然后重启手机就好了。

![](images/20251119150701-5857820a-c516-1.png)

手机这里直接生成了证书，且显示成功即可。

![](images/20251119150701-587c3294-c516-1.png)

### 三、使用Reqable抓包

IP地址要选择和手机同一个WIFI的地址，再把全局代理关掉。

打开手机端，使用扫码功能扫一下电脑端的二维码。

![](images/20251119150701-58cd14b6-c516-1.png)

手机端开启增强模式，点击右下角的开启抓包。

![](images/20251119150702-5930fe7a-c516-1.png)

即可显示抓包成功。

![](images/20251119150703-59a3b2fa-c516-1.png)

然后把Reqable抓到数据包，导入到我们的burpsuit中，开启二级代理。

![](images/20251119150703-59e843de-c516-1.png)

burpsuit上面就有流量数据包了，成功抓包。

![](images/20251119150704-5a264de6-c516-1.png)

## 0x4 冷门小众化的代理软件Brook

### 一、Brook简介

在主流代理软件被针对的现在，推荐一个小众好用的代理软件——Brook。

Brook 是一个高效的 Socks5 代理软件，官方支持**Windows、Linux、MacOS、IOS、Android、树莓派等设备**，同时是使用 **Golang** 语言编写，安装、使用异常简单。

Brook 支持 **自主研发 Brook（新版） 协议+Stream Brook（旧版）协议、Shadowsocks 协议、SOCKS5 协议、TCP/UDP 转发、SOCKS5代理转HTTP代理 等**功能。

Brook 支持 **UDP转发**，无需任何设置。

支持单端口和多端口(每个端口可以单独设定密码)，这点类似于 Shadowsocks 和 ShadowsocksR 的单用户服务端。

**Github项目：**[**https://github.com/txthinking/brook**](https://github.com/txthinking/brook)

![](images/20251119150704-5a874698-c516-1.png)

自己的安卓手机直接下载这个apk文件即可，然后利用adb上传到手机，进行安装就好了。

![](images/20251119150705-5ad1a966-c516-1.png)

![](images/20251119150705-5af47c48-c516-1.png)

### 二、抓包APP教程

安装完成以后，直接打开即可，点击右上角的添加按钮。

![](images/20251119150705-5b12cdc6-c516-1.png)

选择socks5代理服务。

![](images/20251119150705-5b33e9fa-c516-1.png)

IP和端口选择和Reqable设置的一样，就可以进行抓包尝试了。

![](images/20251119150706-5b64a0ae-c516-1.png)

也是可以成功抓取到数据包的。

![](images/20251119150706-5bc1bb18-c516-1.png)

再去查看burpsuit的二级代理，成功抓取数据流量包。

![](images/20251119150707-5c3c78c6-c516-1.png)

## 0x5 APP 反编译&frida脱壳

### 一、 APK 查壳

Android APK 查壳工具：

```
通过网盘分享的文件：Android APK 查壳工具
链接: https://pan.baidu.com/s/1bzdRMqxJdUb5shtHbervQA?pwd=src6 提取码: src6 
--来自百度网盘超级会员v5的分享
```

需要有java环境，使用Java运行jar包，启动工具

使用方法，只需要把apk文件拖入便会自动识壳。

![](images/20251119150707-5c78f6d4-c516-1.png)

### 二、APK静态反编译

在渗透测试过程中，我们总会遇到需要反编译进行分析的情况，反编译顾名思义就是将apk反编译成静态资源以及源码

而静态反编译，则apk文件其实就是一个压缩包文件，我们可以直接将apk后缀名修改为zip解压得到其静态资源

![](images/20251119150708-5ca46d6e-c516-1.png)

之后我们就会发现以下文件内容：

* assets文件夹:

* 英文单词为资产、资源的意思，里面放的是一些源文件，并且里面存放的是不进行编译加工的原生文件，即该文件夹里的文件不会像xm1、java、文件被预编译，可以存放一些图片、html、、js、css等文件。

* res:

* 规定的指定文件，图标，图片资源等，且res下文件都会生成对应的资源id,但是assets下是不会的。

* lib:

* so文件，底层c/c++实现的依赖库。

* META-INF:

* 包括应用程序所用到的签名文件，sdk版本信息等。

* AndroidManifest.xml:

* 系统清单文件，包含四大组件，应用信息，包名，版本等。

* class.dex:

* 应用的可执行文件，方法数超过65535后会进行分包处理。没有的话就只有一个dex文件。

* resource.arsc:

* 资源索引表，用来描述具有id属性的资源配置信息。

在此之前我们将apk修改为zip，我们得到apk的静态资源之后，文件夹里存在一个classes.dex文件。

![](images/20251119150708-5cc63390-c516-1.png)

那么我们就可以使用 dex2jar工具 来进行反编译。

```
# classes.dex 文件转换成 jar 文件
$ cd dex-tools-2.1
$ sh d2j-dex2jar.sh classes.dex
# 默认会生成 classes-dex2jar.jar 文件
```

执行完命令成功后，就会生成一个叫classes-dex2jar.jar的文件，这个就是我们后面需要查看的文件了。

![](images/20251119150708-5cf6a3cc-c516-1.png)

jadx-gui工具：

使用 jadx-gui，它支持很多方便快捷的交互式操作(例如可以直接把一个 apk 文件拖到 jadx-gui 后，它会直接打开这个文件，之后高亮显示反编译后的代码)，以及代码搜索、定位等。

像上面使用dex2jar工具进行反编译后，就可以把jar反编译后的文件拖入里面即可。

![](images/20251119150709-5d6cf482-c516-1.png)

### 三、安卓静态脱壳BlackDex.apk

BlackDex是一个运行在Android手机上的脱壳工具，支持5.0～12，无需依赖任何环境任何手机都可以使用，包括模拟器。只需几秒，即可对已安装包括未安装的APK进行脱壳。

![](images/20251119150710-5dc8fcf0-c516-1.png)

GitHub链接地址：<https://github.com/CodingGay/BlackDex>，直接下载32位和64位的，项目区分32位与64位，目前是2个不同的app，如在Demo已安装列表内无法找到需要开启的app说明不支持，请使用另一个版本。

![](images/20251119150710-5e0ed718-c516-1.png)

我们需要将BlackDex.apk文件导入到模拟器当中，打开文件，之后选择我们需要脱壳的apk文件即可。

![](images/20251119150710-5e39c7b4-c516-1.png)

脱壳成功之后，它会告诉你dex文件在哪个位置，我们只需要使用adb pull把文件拉出来就好了，之后在通过上面的方法将dex文件进行转换为jar处理。

### 四、动态脱壳frida

#### 1、frida客户端/服务端安装

这里推荐师傅们跟我一样安装这个版本，因为frida版本过高，就会导致后面一些之前大佬写的hook脚本使用不了，我这里也是踩过坑的，所以这里可以安装我给的命令版本来安装。

```
# 安装frida
pip install --user -i https://pypi.tuna.tsinghua.edu.cn/simple frida==16.1.0
# 安装frida-tools
pip install --user -i https://pypi.tuna.tsinghua.edu.cn/simple frida-tools==12.1.3
# 安装hexdump
pip install --user -i https://pypi.tuna.tsinghua.edu.cn/simple hexdump
# 查看pip安装哪些工具
pip list
```

![](images/20251119150711-5e809a90-c516-1.png)

首先可以使用下面的命令看自己的手机是什么框架的。

```
getprop ro.product.cpu.abi
```

![](images/20251119150711-5ea77278-c516-1.png)

根据frida版本和手机CPU版本下载对应的frida-server。

GitHub下载地址：<https://github.com/frida/frida/releases/>。

![](images/20251119150711-5ed66f10-c516-1.png)

下载完后，直接解压，然后修改名称为frida-server。

![](images/20251119150712-5f028898-c516-1.png)

#### 2、frida启动服务端

这里我拿模拟器给师傅们演示，然后师傅们也可以跟着一起实操，MUMU模拟器端口显示：

![](images/20251119150712-5f4226cc-c516-1.png)

运用 mumu模拟器，自带的 abd 工具，进入 shell模式

此时就是连接成功了，在输入shell即可加入shell操作。

```
 ~  adb devices
List of devices attached

 ~  adb tcpip 5555
restarting in TCP mode port: 5555

 ~  adb connect 127.0.0.1:5555
connected to 127.0.0.1:5555

 ~   adb devices
List of devices attached
127.0.0.1:5555  device

 ~  adb -s 127.0.0.1:5555 shell
Welcome! If you need help getting started, check out our developer FAQ page at:
Thanks for using our emulator, happy coding!
SM-S7310:/ #
```

如果adb出现卡顿，连接不上：

```
# 停止 adb 服务
adb kill-server

# 启动 adb 服务（会自动重新监听端口）
adb start-server
```

把**frida**服务端文件上传到模拟器 /data/local/tmp目录下

```
 ~  adb push /xxx/xxxx/frida-server /data/local/tmp/

```

进入shell 进到下载的那个frida目录，并给予权限，在执行frida。

```
SM-S7310:/ # cd /data/local/tmp
SM-S7310:/data/local/tmp # ls
cert  fridasever
SM-S7310:/data/local/tmp # chmod 777 frida-server
SM-S7310:/data/local/tmp # ./frida-server
```

#### 3、frida-dexdump脱壳

执行frida，然后回到shell页面使用ps命令 找到我们要反编译的apk文件其对应的进程。

```
frida-ps -Ua    //查看当前运行 app 包名
```

![](images/20251119150713-5f97296c-c516-1.png)

注意！！：shell里的frida server 要启动并保持连接 才能使用 frida-dexdump进行动态脱壳。

```
frida-dexdump -U -f com.xxxxxx.xxxx.android
```

![](images/20251119150714-60180050-c516-1.png)

还可以使用下面的命令脱壳，pid为5718

```
~  frida-ps -Ua | grep com.xxxx.xxxx.android
5718        app名称         com.xxxx.xxxx.android

~  frida-dexdump -U -p 5718
```

![](images/20251119150715-60e8f9ba-c516-1.png)

![](images/20251119150716-6148624c-c516-1.png)

成功后目录下会有 我们拖的进程文件的dex文件，然后在通过 dex2jar 进行静态编译成jar文件，在用jadx-gui工具查看源码即可。

![](images/20251119150716-61b0d52c-c516-1.png)

## 0x6 LSP安装+APP单向认证绕过

### 一、Lsposed模块安装

首先需要我们先安装Lsposed模块和这个APP，然后通过这个app进行相关hook插件的安装。

LSPosed是基于Xposed开发的一个框架，支持android8.0以上的高版本，可以在不修改 APK 文件的情况下，通过模块改变系统和应用程序的行为。

GitHub下载地址：<https://github.com/LSPosed/LSPosed>

![](images/20251119150717-62008a0c-c516-1.png)

首先得先进入Magisk，然后从里面进行本地模块安装。

![](images/20251119150717-623b0c42-c516-1.png)

然后选择本地导入。

![](images/20251119150717-6256f79a-c516-1.png)

每次模块安装完以后都需要进行重启手机，才可以生效模块。

![](images/20251119150718-627155a4-c516-1.png)

然后在Lsposed的zip包中找到manager.apk，安装到设备即可。

![](images/20251119150718-6296e1ca-c516-1.png)

之后就可以在手机页面找到LSP的应用了。

![](images/20251119150718-62c72f24-c516-1.png)

### 二、APP单项检测绕过

这里需要给师傅们分享的是针对我们平常在做APP渗透测试，抓包过程中，APP做了对客户端进行一个证书校验，就会导致我们在抓包过程中没有网络，为了解决这个问题，需要安装几个LSP的插件。&#x20;

在一次项目APP渗透测试中，开始测试了几个APP都是正常的，但是在测试一个公司APP中，发现burpsuit总是抓不到数据包。

![](images/20251119150718-630469de-c516-1.png)

然后去手机端的小黄鸟进行查看，发现小黄鸟没有问题，其他的流量都在正常走。

![](images/20251119150719-63530d9e-c516-1.png)

于是换了一个抓包软件yakit发现还是网络异常。

更换上面的Brook抓包app，也还是可以正常抓包，但是还是没有办法抓这个项目测试的APP。

![](images/20251119150719-6379991e-c516-1.png)

后来上网一搜，看了下一些师傅写的文章，再看了下B站师傅的视频，发现这里可以导入一些hook插件到LSP应用中，直接可以绕过这个APP的客户端证书校验。

第一步，安装以下三个apk：TrustMeAlready.apk、JustTrustMe.apk、JustMePlush.apk；注：安装只会出现一个应用图标

* [点击获取TrustMeAlready.apk](https://link.zhihu.com/?target=https://note.youdao.com/s/2FANgyXR)
* [点击获取JustTrustMe.apk](https://link.zhihu.com/?target=https://note.youdao.com/s/L0JJyMKe)
* [点击获取JustMePlush.apk](https://link.zhihu.com/?target=https://note.youdao.com/s/4WY17I91)

![](images/20251119150720-63a4454c-c516-1.png)

然后进行挨个插件测试，发现有些APP开启里面三个其中一个就可以正常测试了，也不会显示网络异常，可以正常抓包。

![](images/20251119150720-63c64ebe-c516-1.png)

但是还有有个APP发现使用这三个插件hook之后，还是绕不了单项证书校验，还是抓不了数据包，于是我又在网上找相关的插件，GitHub插件地址：<https://github.com/JunGe-Y/JustTrustMePP/tree/master>

需要捕获应用网络流量信息的时候(简称抓包)，若应用采用是Https加密传输，便很有可能进行SSL证书验证，使你无法进行抓包，而JustTrustMe模块就是通过Xposed对应用进行Hook，使目标应用无法进行SSL验证，以达到顺利抓包;

![](images/20251119150720-6411d780-c516-1.png)

安装的方式跟上面一样，下载的apk格式，直接导入手机安装即可。

![](images/20251119150721-644e2d52-c516-1.png)

把对应的app勾选上即可，然后重启APP，进行抓包测试。

![](images/20251119150721-64775ede-c516-1.png)

成功绕过单项验证，抓取数据包。

![](images/20251119150721-64c60a0c-c516-1.png)

## 0x7 APP 双向证书hook绕过技巧

### 一、400 No required SSL certificate was sent报错

开始在测试某APP的时候，手机可以正常打开。

![](images/20251119150722-64f2e270-c516-1.png)

但是一打开小黄鸟抓包测试，然后把流量导到burpsuit抓包时，刷新app发现没有网络了。

![](images/20251119150722-6525e846-c516-1.png)

这里开始推测是单项证书校验，所以直接打开手机的LSPosed功能的绕过单项证书检测的几个模块

![](images/20251119150722-6560baa2-c516-1.png)

但是还是没有什么效果，这里开始分析数据包。观察上述response数据，发现有"400 No required SSL certificate was sent"提示信息，是说服务端未接收到所需要的SSL证书信息，也就是说服务端对客户端进行了证书校验。

![](images/20251119150723-6595b34c-c516-1.png)

通过上面的返回和证明，也就更能确定它使用的是双向证书。

双向证书主要是在通讯过程中，服务端校验了客户端证书是否正确，同样客户端也校验了服务端证书是否正确。

### 二、r0capture：安卓应用层抓包通杀脚本

#### 1、**工具简介**

* 仅限安卓平台，测试安卓7、8、9、10、11、12、13、14 可用 ；
* 无视所有证书校验或绑定，不用考虑任何证书的事情；
* 通杀TCP/IP四层模型中的应用层中的全部协议；
* 通杀协议包括：Http,WebSocket,Ftp,Xmpp,Imap,Smtp,Protobuf等等、以及它们的SSL版本；
* 通杀所有应用层框架，包括HttpUrlConnection、Okhttp1/3/4、Retrofit/Volley等等；
* 无视加固，不管是整体壳还是二代壳或VMP，不用考虑加固的事情；

这里推荐使用r0capture工具，安卓应用层抓包通杀脚本，实用性很强，针对市场上很多双向证书校验的app都有用，GitHub链接地址：<https://github.com/r0ysue/r0capture>

![](images/20251119150723-65e697f8-c516-1.png)

**TIPS：**

* r0capture脚本建议用最新的2.1版本的
* 这里不建议使用frida高版本的，因为我这里测试过了，17.4.4版本用这个脚本会报错
* 这里建议使用16点几的版本，也可以像我一样使用Frida16.1.0，命令如下：

```
# 安装frida
pip install --user -i https://pypi.tuna.tsinghua.edu.cn/simple frida==16.1.0
# 安装frida-tools
pip install --user -i https://pypi.tuna.tsinghua.edu.cn/simple frida-tools==12.1.3
# 安装hexdump
pip install --user -i https://pypi.tuna.tsinghua.edu.cn/simple hexdump

```

* 根据frida版本和手机CPU版本下载对应的frida-server

![](images/20251119150711-5ed66f10-c516-1.png)

#### 2、先使用frida开启服务端

```
 ~/tooks/tools/APP/frida  adb devices
List of devices attached

 ~/tooks/tools/APP/frida  adb connect 192.168.45.130:42967

```

把frida-server上传到手机的/data/local/tmp/目录下，这个目录是临时目录，再给777权限，就可以执行了。

```
adb push xxxx/xxx/frida-server /data/local/tmp/
```

利用adb连接功能，直接进行手机的shell终端。

```
 ~/tooks/tools/APP/frida  adb -s 192.168.45.130:42967 shell
flame:/ $ su
flame:/ # cd /data/local/tmp/
flame:/data/local/tmp # ls
cert  frida-server
flame:/data/local/tmp # ./frida-server
```

#### 3、运行frida客户

找到开始在手机上运行的APP，是com.xxxx.xxxx格式的

```
frida-ps -Ua
```

![](images/20251119150724-667f7950-c516-1.png)

#### 4、开启APP的存储功能

运行脚本之前必须手动给App加上存储卡读写权限；

![](images/20251119150725-66eccdc0-c516-1.png)

然后把下面的存储功能都开启

![](images/20251119150725-6723228a-c516-1.png)

#### 5、r0capture脚本运行

从GitHub下载后，解压文件夹，主要功能就是这个python脚本。

![](images/20251119150726-6745b5fa-c516-1.png)

下面这个就是r0capture.py的脚本了，主要就是解决SSL证书双向验证的报错问题。

![](images/20251119150726-6796e54c-c516-1.png)

运行r0capture.py脚本以及命令：

```
python r0capture.py -U -f com.xxxx.xxxxxx.android -v
```

![](images/20251119150727-680c956e-c516-1.png)

运行成功脚本会自动运行 app，并且疯狂弹出日志记录。

![](images/20251119150728-68799bbe-c516-1.png)

导出后的证书位于/sdcard/Download/包名xxx.p12路径，导出多次，每一份均可用，密码默认为：r0ysue。

![](images/20251119150728-68c16110-c516-1.png)

#### 6、导出.p12证书

可以你可以在 MT、NP 管理器使用微信分享，直接发到电脑微信，也可以使用 adb 命令直接拿到。

```
 ~  adb pull /sdcard/Download/xxxxxxx.p12 /xxxxxx/Downloads
/sdcard/Download/com.xxxxx.xxxxxx.android...lled, 0 skipped. 1.3 MB/s (2643 bytes in 0.002s)
```

![](images/20251119150728-68fe8982-c516-1.png)

这样我们就成功把这个app的证书给导出成功了。

![](images/20251119150729-69260b88-c516-1.png)

输入密码：r0ysue。

![](images/20251119150729-695040d8-c516-1.png)

### 三、证书导入burpsuit & Reqable

#### 1、burpsuit证书导入

直接打开burpsuit的设置，按照下面的步骤，直接导入。

![](images/20251119150729-69897326-c516-1.png)

直接输入 \*，然后选择第一个。

![](images/20251119150730-69b5758c-c516-1.png)

这里选择我们上面手机导出的r0capture生成的APP证书，密码都是默认的：r0ysue。

![](images/20251119150730-69da80cc-c516-1.png)

直接导入显示成功。

![](images/20251119150730-69f8b592-c516-1.png)

![](images/20251119150730-6a2d4bae-c516-1.png)

#### 2、Reqable证书导入

之前看网上有师傅说是从小黄鸟这里导入该手机APP的证书。

![](images/20251119150731-6a5d4bf6-c516-1.png)

但是我尝试导入以后，自己电脑的小黄鸟证书直接乱了，直接显示很多证书失效了，且手机端端小黄鸟证书也变了。

![](images/20251119150731-6a99fc06-c516-1.png)

虽然说，这样导入可以抓app的数据包了，但是抓本机电脑就有问题，且证书导入混乱。

这样的解决方法就是，重新生成根证书，然后再重新安装以前的方法，导入证书到电脑和手机端证书。

![](images/20251119150732-6acdae14-c516-1.png)

手机也是重新导入即可，然后Magisk导入这个zip证书，然后重启手机就好了。

![](images/20251119150644-4e5692c8-c516-1.png)

![](images/20251119150732-6b314c62-c516-1.png)

然后我看小黄鸟的这个SSL证书导入模块介绍：<https://reqable.com/zh-CN/docs/capture/ssl#ssl-certificates>。

![](images/20251119150733-6b899e8a-c516-1.png)

* 配置客户端证书，主要用于双向验证场景。Reqable代理客户端在与服务器进行SSL握手协商时，会将证书发给服务器进行验证。
* 配置服务端证书，主要用户固定证书场景。Reqable代理服务器在与客户端进行SSL握手协商时，会将证书发给客户端进行验证。

因为我们这里是存在双向证书验证的情况，所以我们导入客户端证书即可。

![](images/20251119150733-6bcd8f9e-c516-1.png)

然后再把电脑端的小黄鸟都重新打开，再把burpsuit开启二级代理，就可以成功抓包了。

![](images/20251119150734-6c25ffc8-c516-1.png)

像最常见的登陆口，就可以开始抓包测试了，总体上跟测试微信小程序差不多，就是有些APP有做限制。

![](images/20251119150735-6c944bae-c516-1.png)

像上面的操作，基本上市场上的大部分APP都是可以直接抓包测试的了，还有一个就是大家在测试的时候抓不到数据包，或者工具有问题，直接重启手机即可，不建议使用模拟器，一大推bug！

## 0x8 Root检测绕过

### 一、Root 及 SafetyNet 测试工具

**PP 检测 ROOT 的常用方法：**

* 文件检查：看系统里有没有“/system/bin/su”或“/system/xbin/su”文件。
* 权限判断：检查“/system”目录是不是可读写。
* 命令测试：执行“id”命令，出现“uid=0 (root)”或者执行“su”命令后能访问特殊文件，可能已经ROOT。
* 属性查看：读取“ro.secure”属性，值为0可能ROOT；对比Build指纹和官方的是否不同。
* 工具使用：用RootBeer等开源库或系统安全接口检测。
* 签名验证：检查APP自身和系统镜像的签名是否和官方一致。

root检测工具下载：<https://play.google.com/store/apps/details?id=com.atominvention.rootchecker&hl=zh>

![](images/20251119150735-6d091ab0-c516-1.png)

magisk有个默认的超级用户模块，可以通过这个模块决定是否给用户root权限，前提是该app向系统要了root权限，很多app检测root并不是通过向系统要root权限来检测的，是通过检测su命令或者其他方式，所以这种方法适用范围较小。

像我这里就是检测到了Root权限。

![](images/20251119150736-6d3fdc8a-c516-1.png)

把这里尝试关闭，然后再试试检测权限。

![](images/20251119150736-6d6d4a6c-c516-1.png)

直接显示未取得Root权限，那么我们一些APP要是躲避root检测，就可以这样陪着。

![](images/20251119150736-6d93da10-c516-1.png)

Magisk面具官方还有一种隐藏Root的方法。

![](images/20251119150736-6db82992-c516-1.png)

然后选择下面两个按钮都要打开，再重启手机生效。

![](images/20251119150737-6dde80ba-c516-1.png)

然后点击陪着排除列表，就是说选中了的APP就会被面具自带隐藏root。

![](images/20251119150737-6e08ef08-c516-1.png)

勾选完，一定要点击返回按钮，才能生效。

![](images/20251119150737-6e305386-c516-1.png)

直接成功隐藏root了。

![](images/20251119150737-6e5635f6-c516-1.png)

### 二、Shamiko-防root检测模块

GitHub下载地址：<https://github.com/LSPosed/LSPosed.github.io/releases>

![](images/20251119150738-6e99ec9c-c516-1.png)

但是使用这个模块插件之前，必须得先把遵守排除列表这个开关关闭，然后重启。

![](images/20251119150738-6ebe5886-c516-1.png)

我这里推荐0.6版本的，因为其他高版本会报错。

下载好之后，通过共享目录放进模拟器里面，然后打开Magisk–>模块–>从本地安装–>选择Shamiko模块安装，然后重启即可。

![](images/20251119150738-6edf9d00-c516-1.png)

![](images/20251119150739-6f0af586-c516-1.png)

安装好之后重启模拟器，Magisk–>模块里，就表示已经安装并且激活成功。

![](images/20251119150739-6f295fee-c516-1.png)

在排除列表中勾选想要对他隐藏root的app，这里以root检测工具为例。

![](images/20251119150739-6f4d58c2-c516-1.png)

![](images/20251119150739-6f72daa2-c516-1.png)

然后使用root检测工具进行root检测，发现已经没有了root权限（如果未生效，可以重启手机再进行尝试）。

![](images/20251119150740-6f980cb4-c516-1.png)

只不过无论是Magisk还是Shamiko都无法在模拟器上100%隐藏root，如果用了模块那就可能会更难隐藏了，效果得自己测试。

## 0x9 总结

最后这篇一万字的移动安全Android APP抓包和反编译&frida脱壳&APP单/双向认证绕过相关知识点，都已经很详细的给师傅们分享完了。

文章当中有很多地方在实操过程中有坑点，里面都进行了备注，师傅们详细查看。针对Magisk面具和LSP模块和一些插件，还有很多功能点，网上也有一些好用的工具，但是很多文章都是比较老的，包括抓包工具小黄鸟，这个目前算是很方便的抓包APP工具了，其次就是一些大牛写的脚本，hook插件，真的很不错。

最后希望师傅们看完这篇文章都有收获，祝愿师傅们都可以找到好工作，天天出洞！

![](images/20251119150740-6fa9e63a-c516-1.png)
