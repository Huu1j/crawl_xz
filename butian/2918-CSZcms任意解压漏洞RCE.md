# CSZcms任意解压漏洞RCE

> **来源**: https://forum.butian.net/share/2918  
> **文章ID**: 2918

---

官网

<https://www.cszcms.com/product/download>

下载地址

<https://jaist.dl.sourceforge.net/project/cszcms/install/CSZCMS-V1.3.0.zip>

安装过程

访问web目录，然后填下下面的表

![image.png](images/attach-9b52af0638eaa3e6ebae6b21ac31b69f1d9e7202.png)

登录后台

![image.png](images/attach-fd46adced444f0854d57b459e2feae958f3a7ff3.png)

![image.png](images/attach-c0c008a7731abd74559e6be9c737743de5d87918.png)  
然后进入maintenance System中，选择文件进行上传

![image.png](images/attach-a46779385f5b0a273e75ae9f97314827acc8f5ca.png)  
此时写一个test.php，然后压缩成.zip格式

![image.png](images/attach-8f466eeffa8ad7429fea586cbe9be52e7853a251.png)

上传成功

![image.png](images/attach-f0d2a081a53092e9ddb4ef5ea7f5b4b677469efe.png)

访问目录下的test.php，成功RCE

![image.png](images/attach-253894792a1efe22babe25269595be4587e83298.png)  
PS: 因为笔者是黑盒测完就立马审了，本文是边审边写的，所以一些临时文件名和随机数可能会上下文不一致，但不会影响审计逻辑与阅读

下面是代审环节，通过路由定位到install函数，在do\_upload函数前，是一些检测语句，比如194行判断是否登录，202行判断上传的是否是压缩包

![image.png](images/attach-dd2893c1d49269568cfc76e4bbf4629af784f0e1.png)

进入到211行do\_upload函数中，先是405行判断了下路径是否能上传，然后412行判断文件是否可以上传

![image.png](images/attach-aaee934ab25ba9c7a6242af67e6d8b965dbfc2c6.png)

在do\_upload函数中继续往下跟，一些平常的赋值与正常的判断，获取了文件名与后缀

![image.png](images/attach-58621222843ba7fc39a454795952214fa1d8699f.png)

再往下走就可以看到上传点，这里是先用copy函数将存储的临时文件复制到正常的上传目录，如果不行的话再用move\_uploaded\_file进行上传

![image.png](images/attach-f88236a9119d837a89a264058e0e464efb473df7.png)  
出来后，跟着逻辑往下走，进入到217行unzip->extract进行解压

![image.png](images/attach-c8848a25dd0bc952d832dcf3e3af3ba758c37c55.png)  
然后进入到84行\_list\_files

![image.png](images/attach-cd4e687358a0f308e744199a184e92a1b6cb7a75.png)

在\_list\_files函数中，208行打开该压缩包

![image.png](images/attach-f0829bf9d2773d8d31ade6b7658cde9ab2477438.png)

然后进入到216行\_load\_file\_list\_by\_eof函数，在404行获取到了压缩包的文件名

![image.png](images/attach-5c18edb4e71f00a684e94deaf884bcc233eb1ef5.png)

![image.png](images/attach-87508b49d9ee31dba35af395c22b06569b8a68c0.png)

然后回到上级函数，将compressed\_list里面的参数继续return回去

![image.png](images/attach-454e38088eb84c05d9ea7b75ede1eeb81f9a0974.png)

这里有个循环，判断压缩包里的文件

![image.png](images/attach-c175aa9895be871b51cc792c6aaa73b4e92eb231.png)

继续往下走，进入到\_extract\_file函数中，其中用刚刚的compressed\_file\_name赋值给了$fdetails

![image.png](images/attach-12ab265f9c9a275cb590637c260ef18a4e4f484a.png)

![image.png](images/attach-7f2a1303db33e4661987b670914ae1eb71f546d5.png)

往下走进入到\_uncompress函数中

![image.png](images/attach-fd2530080b7c7cbf0a6eab481db61e1d94dca47a.png)

最后，判断mode为8，通过三目运算符判断有值，即用file\_put\_contents写入文件

![image.png](images/attach-64c902ec84405d2cd22b9028abd74c85831d1b8d.png)  
最后return回去文件地址

![image.png](images/attach-e410f047d515684f1cd2131d1bba084431cd6b4d.png)  
成功写入

![image.png](images/attach-12eb360988c92c24aab6e1c34ac4ceac0d3508da.png)
