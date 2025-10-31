# ISCC 练武初赛re+mobile wp-先知社区

> **来源**: https://xz.aliyun.com/news/18015  
> **文章ID**: 18015

---

返回文档

mobile  
   
ISCC mobile 邦布出击  
   
安装apk

![Screenshot_2025-05-13-22-40-44-151_com.example.mobile01.jpg](images/32b61961-bad7-3fbd-ad30-79701a13dd6c)

点击右下角的按钮，进入图鉴界面，百度各种邦布的种类，一个一个试，可以得到三段base64加密的文本
[邦布图鉴 - 绝区零WIKI\_BWIKI\_哔哩](https://wiki.biligame.com/zzz/%E9%82%A6%E5%B8%83%E5%9B%BE%E9%89%B4)

![Screenshot_2025-05-13-22-41-10-584_com.example.mobile01.jpg](images/100d2d18-6954-332c-973f-3967025cabd4)

[哔哩](https://wiki.biligame.com/zzz/%E9%82%A6%E5%B8%83%E5%9B%BE%E9%89%B4)
  
   
然后将三段base64拼接起来，循环解码三次base64

![Pasted image 20250513224531.png](images/6110f2ed-e8f6-3fab-975e-9d388ecb137f)

得到一串明文
尝试打开解压得到的db文件，提示非数据库文件，经查询是经过sqlcipher加密，那么此前得到的明文应该就是解密的key  
   

![Pasted image 20250513231432.png](images/608da054-4eb0-3ddf-9bf1-1c934aa9e68d)

flag是假的，实际应该留意的是key以及info中的blowfish（一种加密方式）
使用jadx打开apk  
   

![Pasted image 20250513231609.png](images/41684733-2f88-36ab-81c2-ad028fe1d7bb)

  
![Pasted image 20250513231752.png](images/15b2ed9e-7ef8-33e7-b024-a4f7930c7aa4)

将上图中的密文通过blowfish解密之后得到的内容就是DES的明文

![aaba312c1f03dfea7d3674c177dfafb.png](images/8073ed7c-cf2a-3b83-876e-5a1aeb20625f)

根据apk的逻辑，只有当该明文DES加密的结果和输入内容去掉flag格式后的内容相同才正确
已知明文、key、加密方式，那么对于DES加密，还需要具备的就是iv，但是iv是通过native函数生成的

![Pasted image 20250513231925.png](images/14c04986-4868-3d9d-9f88-bbeaa2ca22d5)

方法一：分析so文件iv的生成逻辑 -- 生成逻辑比较复杂，放弃
方法二：hook native function，在调用getiv时输出iv
这里使用frida hook（要在手机上先运行frida-server）  
   

![36d18bc1966d379871006775c89bc9d.png](images/aee9c4a2-88dc-398c-b977-2ba44b413f29)

  
![Pasted image 20250514001958.png](images/36b1ec63-b2a5-3b1e-8aba-363580880567)

  
ISCC mobile detective  
   
附件是一个apk文件，用jadx打开

![Pasted image 20250515210819.png](images/a8461f8b-d600-3933-8254-e0fc4a12731f)

可以看到关键是这个stringFromJNI函数，跟进之后发现是native函数，因此用IDA打开so文件

![Pasted image 20250515211008.png](images/5f7884e2-eae1-36ff-b094-b64fc3e06eb5)

关键是这个xorEncrypt函数

![Pasted image 20250515211202.png](images/bb8b0a5c-ba0e-35b9-ada7-1ebfc3882dad)

通过分析代码可知，该函数先将字符串转换为十六进制，再将输入与key异或之后转为字符串，然后从每4个字符中提取前2个字符，然后再根据一定规律打乱字符串的位置信息，最后替换特定位置的字符  
   
  
HolyGrail  
   
附件为apk安装包

![Screenshot_2025-05-15-21-43-03-306_com.example.holygrail.jpg](images/a4b06c0a-13ac-39bb-a26a-24fe446230ba)

使用jadx打开apk，发现其中有许多checkbox，点击checkbox的响应如下

![Pasted image 20250515213902.png](images/ab0c8f5d-a660-3686-a06c-01e15c46044b)

每点击一个checkbox就会在userSequence末尾添加当前checkbox的资源名称

![Pasted image 20250515214905.png](images/4fad1aa9-66eb-3744-af0a-c6c275679a55)

  
而根据app的提示，需要按照特定顺序点击checkbox，才能进入验证flag的页面，并且返回在native层加密后的密文
关于顺序，可以自行百度，也可以问ai，最终顺序如下

![Screenshot_2025-05-15-21-44-59-275_com.example.holygrail.jpg](images/fc45a923-4bbb-338e-9fb4-8e3e1cedbd67)

如何获得密文：通过frida hook，手动传入特定顺序的参数（每个checkbox的参数也需要通过frida hook得到），然后输出返回的密文  
   
然后分析验证flag的页面

![Pasted image 20250515215910.png](images/03921277-a0e1-3234-8028-ff0cc3856095)

首先检查flag格式，然后调用a类的validateFlag方法

![Pasted image 20250515220011.png](images/f2963690-2add-3307-bca9-75e72772958c)

大概流程  
    
●getEncryptionKey  
   
●vigenereEncrypt  
   
●processWithNative  
   
● b.a

![Pasted image 20250515220234.png](images/3b8faf20-b314-3306-975f-bace08dea95e)

由于processWithNative是JNI函数，因此尝试frida hook该函数，尝试传入不同的值，发现每个字符对应的加密结果和顺序无关，因此可以直接生成所有字符加密的结果，再对目标字符串进行匹配   
    
解密思路  
    
●转十六进制  
   
●字符替换  
   
●字符偏移  
    
exp  
   
whereisflag  
   

![Screenshot_2025-05-13-16-53-52-316_com.example.whereisflag.jpg](images/1fbc0001-9512-3cc5-90af-b50b577aaafd)

jadx打开apk可以看到具体逻辑

![Pasted image 20250510172253.png](images/06f3bcf2-2ed0-3a4d-9b99-e97e5f03f3c7)

分析之后发现核心函数是native函数
Native 函数基本介绍  
    
● 定义：Native 函数通过 native 关键字在 Java 中声明，实际代码编译在 .so 动态库（ELF 格式）中。   
   
● JNI 桥梁：Java 层通过 JNI（Java Native Interface）调用 Native 函数，函数名和参数需遵循 JNI 规范。

![Pasted image 20250510172314.png](images/8bf44b68-a929-311a-bbb6-3b07469b0689)

用解压软件直接解压apk文件，然后进入\lib\arm64-v8a目录找到so文件，使用IDA64打开so文件，在其中找到Java\_开头的函数便是native导出函数
在加密函数中首先将输入倒序

![Pasted image 20250510173251.png](images/b0a24495-8a43-3ffe-9fee-33a8e8add260)

然后根据字符表查找输入的字符

![Pasted image 20250510172352.png](images/ee11d1cf-8fd8-35db-b691-8f19f40268c7)

字符表需要动态调试得到

![Pasted image 20250510172434.png](images/ff20107b-9d0a-3182-8272-0bd449058006)


![Pasted image 20250510172447.png](images/9c6240ed-c7ee-3c46-b358-1d89d05c7a9f)

而根据encrypt、charToIndex、indexToChar函数的逻辑，可以看到在索引转换时有固定偏移，为2
从jadx反编译的结果得到目标密文iB3A7kSISR，解密   
    
exp  
   
  
RE  
   
打出flag  
   
从可执行程序的图标判断为pyinstaller编译的程序，使用pyinstxtractor反编译  
   
然后打开反编译的文件夹，打开同名pyc文件，反编译（uncompyle6或者在线）
[python反编译 - 在线工具](https://tool.lu/pyc/)  
   
可以将decompress之后的内容写入文件（以下为部分）  
   
叫AI写个脚本去混淆  
   
有趣的小游戏  
   
附件是一个exe和两个txt，其中txt内容为非打印字符
main函数中定义了许多常量

![Pasted image 20250515201119.png](images/a580dcdb-13fb-3a9e-a1f0-36c79c2d58cd)

通过查看附近函数，发现其他地方也定义了常数

![Pasted image 20250515201232.png](images/5a014b28-01b1-30db-80c7-b79378ec25d1)

查看字符串表，可以在其中找到两个txt的文件名，交叉引用查看

![Pasted image 20250515201327.png](images/44ac8451-165e-3005-ba86-29a59599bf70)


![Pasted image 20250515201410.png](images/e2d6077e-5add-325b-8b86-bbbbccf58dbb)

其中process是我重命名的结果
可以看到其中比较奇怪的一点是程序将文件的内容作为函数执行，也就是说原本内容不可见的txt其实是函数的二进制数据，要想知道该函数的具体逻辑，需要动态调试，在此处下断点，触发断点之后在汇编步进就可以看到其中逻辑

![Pasted image 20250515201657.png](images/0eadfa9a-eac2-3d4b-9733-85e3786363d4)

可以将汇编扔给ai判断函数逻辑
deekseek：“这段汇编代码实现的是 XXTEA（eXtended TEA）算法的解密过程……”
于是知道了加解密逻辑，并且根据xxtea的密钥格式可以判断先前的两处常量中位数较短的是key，而位数较长的是密文
接下来有两种解题方式：  
    
1手动分析解密逻辑，自己编写代码  
   
2交给ai
xxtea的加解密逻辑网上有很多就不细说了，直接给出解密脚本  
    
真？复杂  
   
题目附件是一个raw文件，010editor查看发现JFIF文件头，提取图片

![Pasted image 20250512005827.png](images/cf35dd5f-a026-38f7-a8fd-ea5d6ee4d1df)


![123.jpg](images/4d99ed64-0fb0-3893-9449-e3a20b0c20a6)

然后使用cyberchef解密，解密之前要先把原raw文件中附加的图片信息删除
解密之后得到压缩包一个，解密得exe文件和enc文件各一个

![ae6879ff3782f8795ec50198ebe6a61.png](images/6176c2e7-cd2f-3fc5-8c0c-5e2f5e1a8606)

虽然流程图长这个样，但是是可以手动去除的

![Pasted image 20250513163628.png](images/e3e1e5e6-e4ab-3ce0-ba37-4211f4f643a6)

第一种方法：（直接忽略和输入无关的语句和函数，对于涉及到修改输入的语句统统下断点）
第二种方法：直接分析加密函数的switch逻辑，可以发现是对奇偶索引的字符做不同的变换，核心变量为v4（索引）和v5（控制跳转的case），通过v4&1的操作判断奇偶
通过分析exe文件可知原本逻辑是给定flag.txt，用exe加密得到enc文件，而现在只有enc文件，故需要逆向推解密逻辑
通过分析得到解密脚本  
   
faze  
   
题目附件：faze.exe
使用IDA打开附件

![Pasted image 20250515173145.png](images/666c9c83-6cfa-3a14-9cf3-658598064bb3)

  
一眼C++，通过判断代码可以发现目标字符串在用户输入之前（getline）已经完成了目标字符串的初始化，所以这里有多种解法  
    
1在sprintf上下断点，直接查看写入目标字符串的内容  
   
2 在比较的时候（operator==）下断点，查看比较的数据
这里选择前者，在程序暂停时跳转到rcx所在地址

![Pasted image 20250515173555.png](images/a290d291-5d47-3e91-8955-addade30774f)

   
greeting  
   
首先IDA打开可执行文件，会发现有些函数反编译的结果不正确，且提示错误，因此可以查看目标函数附近的汇编代码，找到类似加密逻辑的代码

![Pasted image 20250513180229.png](images/3f435ec5-db42-3e3c-9a40-d85766c2d944)

明显的异或和循环左移操作，大概率是加密逻辑
通过分析可知，代码首先是计算一个偏移，然后将目标数据对应索引的字节在异或i+0x5a之后（esi为索引）循环左移该计算出来的偏移，因此目标可以分为两步：  
    
1分析该偏移的计算方式  
   
2 反推整个加密逻辑
这里的r15其实是一个固定的值

![Pasted image 20250513180747.png](images/29342997-2c18-331e-964c-bb26028c464c)

关于偏移量的计算   
    
●通过手动分析  
    
○ mul r15 和 shr dl, 2 的组合实际上执行的是整数除法 i / 5   
   
○ lea eax, [rax+rax\*4] 计算的是 (i/5)\*5   
   
○ sub ecx, eax 计算的是 i - (i/5)\*5   
   
○ 以上逻辑等价于i%5   
    
●直接动态调试可以发现rol操作中cl的取值是0、1、2、3、4、0……，所以其实偏移的计算方式是索引对5取余  
   
然后就是逆向整个加密逻辑，有了偏移的计算方式，解密的逻辑很好推，就是对每个字节先循环右移再异或(i+0x5a)
对于密文，通过交叉引用和人肉分析等方式最终可以找到位于0x014001B390  
   
因此完整的解密脚本如下

​
