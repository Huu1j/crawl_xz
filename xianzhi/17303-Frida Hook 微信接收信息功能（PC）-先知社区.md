# Frida Hook 微信接收信息功能（PC）-先知社区

> **来源**: https://xz.aliyun.com/news/17303  
> **文章ID**: 17303

---

微信版本：3.9.12.51

​

hook微信接收功能的大概思路：定位新消息在内存的位置，然后定位到调用的函数，再下断点查看寄存器和栈，在其中找消息的位置，最后获取目标函数的偏移，再编写frida脚本hook目标函数并打印消息

# 准备

* CheatEngine
* x64dbg
* 安装python、frida
* 一台root的手机/模拟器
* adb push frida-server到手机并运行

# 定位内存

首先是定位到发送的消息存储的位置，方法是使用CheatEngine，用小号发送消息，然后用CE在内存空间中搜索消息

![Pasted image 20250318004800.png](images/657f702a-259e-3401-96f0-c762a320828a)

搜索的结果可能不止一个，这时候就用小号多发几条信息，上图的Value字段会不断发生变化，不变化的说明不是目标内存地址

![Pasted image 20250318004943.png](images/cf2ba02a-1788-39f7-ac23-72f5857a0114)

可以看到当我使用小号发送信息“imatest”的时候，只有几个地址的内容变了，说明这些是我们想要的，当然还可以等一会，有一些临时空间可能会被回收再利用导致内容变化，从而减少我们的目标

> 但是最后筛选出来还是不止一个，怎么办？

右键左边列表的地址，点击“Browse in this memory region”

![Pasted image 20250318005404.png](images/8c5d06ca-6454-34bd-b5b9-9218766794d2)

我们最终的目标，是找到像上图一样，既带有微信id和消息内容，也具有xml标签的地址，因为新消息接收时，肯定是带有发送者的信息的，所以一定会有微信id（这里有可能会遇到两个地址打开都是这样的内容，其中一个应该是临时空间，稍等一下内容应该就会改变）

找到之后回到刚刚的页面，右键目标地址选择“Copy selected addresses”

​

关闭CE修改器，打开x64dbg，附加到wechat.exe，选择汇编窗口，按快捷键“Alt+E”打开模块菜单，双击选择“wechatwin.dll”

![Pasted image 20250318010350.png](images/753f79af-eabd-343b-aa3b-68387b137cef)

然后选择内存窗口，按快捷键“Ctrl+G”打开跳转地址的窗口，输入刚刚在CE修改器复制的地址

![Pasted image 20250318010320.png](images/eaf3b5d7-70c6-3662-bde0-5b578efdf175)

跳转之后右键左边的地址，选择硬件断点（1字节），然后按F9继续运行（如果还暂停就继续按F9）

# 定位调用的函数

接着再次使用小号发送新消息，如果触发断点，说明程序在对我们下断点的地方修改内容，而修改的内容很有可能就是我们新发送的消息  
然后是观察右下角的栈窗口，往下滑

![Pasted image 20250318010608.png](images/8d9bf7e8-14c7-34f0-a5d1-ffda7bb90e62)

![Pasted image 20250318010643.png](images/8ce22888-fddb-355b-9bb8-59d25a232848)

可以看到有许多sql语句，这是因为在接收到信息时程序会将其存入数据库，而我们要做的就是定位到在存入数据库之前的函数，至于为什么不是直接定位最近的函数而是在存入数据库之前的函数，是因为最近的函数在接收到一条新消息时可能会触发多次，而存入数据库这一操作则应该是每接收到一条消息就存入一次，而为什么不可以在存入数据库之后，是因为在存入之后原本消息的内容就可能会发生改变，因为这时原本的信息完全可以通过读取数据库得到

接着往下看

![Pasted image 20250318013919.png](images/3ee9e437-0cd3-3e3a-81df-e64b86b3e5bc)

可以看到这里出现了数据库的名称，因此我们需要定位到在这个名称之前的最近的函数（数据库名称往上最近的）

![Pasted image 20250318013950.png](images/6408edf9-e3a8-3d92-be94-0507c0e5d569)

然后右键红色字体左边（函数返回的地址），选择“在反汇编中转到指定QWORD”，这时候会在汇编窗口跳转到该函数的返回地址

![Pasted image 20250318014037.png](images/9d5aa8c7-c359-366b-97da-21d8f1bedb59)

然后在这条语句的上一句（函数调用的语句）下断点（点击最左边的点），同时取消内存的硬件断点（在内存窗口原本的位置右键“删除硬件断点”）

![Pasted image 20250318012907.png](images/a521140f-ce7b-3736-8883-ff9419855941)

关于为什么要在返回地址的上一句下断点，是因为程序在返回到指定地址时可能会清理现场，更重要的是要在消息存储到数据库之前获取新消息的值，而栈顶的地址是随着函数返回从小到大变化的，所以要在数据库名称之前（栈地址相比更小）的位置下断点，而在返回地址之前的函数调用语句对应的栈帧就是

![Pasted image 20250318013919.png](images/69ded622-591a-398a-8c9b-5522aa6469d4)

这个地址往上的范围

# 定位消息位置

在下断点并取消硬件断点之后，F9让程序继续运行  
然后用小号再次发送新消息，此时会再次触发断点，这时候选择右上角的寄存器窗口，右键rdi的地址，选择“在内存窗口中转到”

![Pasted image 20250318014157.png](images/dfdbba12-a061-3da8-a50b-1eea5c08932c)

![Pasted image 20250318014320.png](images/e3a2f4a3-4c95-31e0-bcf5-201e8c814994)

为什么是rdi？

因为微信是64位程序，而64位程序的传参顺序是“RDI - RSI - RDX - RCX - R8 - R9 - stack”

即第一个参数由rdi传递，第二个参数由rsi传递，依此类推，直到如果存在6个以上参数，则超出6个的部分由栈传递

​

这时候其实已经能看到我们发送的新消息的内容了，但是再仔细观察一下会发现内存中存在其他和消息内容地址相近的地址，此时可以跳转过去看看

![Pasted image 20250318014450.png](images/3dd8082e-4594-3662-bcea-05db49d69ef7)

可以看到其实是微信id的内容

这样我们就定位到了接收新消息时触发的函数以及对应消息内容的位置

此时双击rdi指向的地址

![Pasted image 20250318014740.png](images/00109395-d416-3402-9082-3cb0605d37e2)

会发现地址显示的方式发生了改变，这样可以更方便的定位到消息的位置，即

rdi + 0x48 -> 微信id

rdi + 0x88 -> 消息内容

# 获取地址偏移

在知道了应该hook哪个地址之后，还需要获取该地址的文件偏移，并在frida脚本中计算每次运行时真正的地址  
至于为什么不可以直接hook复制的地址，是因为Windows每次运行程序时都会初始化一个基址，将文件的数据加载到这个基址之上，所以如果直接使用复制的地址的话，下次运行程序时，加载的基址和当前基址不一定是同一个

右键到下断点位置的地址，选择复制地址，然后点击菜单栏的计算器图标，将地址复制进去

![Pasted image 20250318015452.png](images/85976d18-1e44-3f02-b281-888a9619b7b4)

然后按快捷键“Alt+E”再次打开模块菜单，右键wechatwin.dll，选择复制基址

![Pasted image 20250318015604.png](images/fbd70fd9-3a9e-3a81-ba2c-7f4e832d6f93)

![Pasted image 20250318015629.png](images/a5611538-7163-340d-9200-ac7596ae0fd4)

两者相减就是该代码在文件中的位置了

​

然后选择菜单中的文件--脱离，开始编写frida代码

# 编写frida脚本

frida脚本的编写思路是：先获取到dll的基址，然后加上刚刚计算出来的偏移，再hook最终计算的地址，hook到之后再打印出rdi寄存器加上0x48（微信id）和0x88（消息内容）的内容

完整代码

```
import frida
import sys

def on_message(message, data):
    return

def main(target_process):
    session = frida.attach(target_process)
    with open("hookmsg.js") as f:
        script = session.create_script(f.read())
    script.on("message", on_message)
    script.load()
    sys.stdin.read()

if __name__ == "__main__":
    main("WeChat.exe")
```

```
var dllbase = Module.findBaseAddress("WeChatWin.dll");
console.log(dllbase);

var addr = dllbase.add(0x5D9135F);
Interceptor.attach(addr, {
    onEnter: function (args) {
        var id = this.context.rdi.add(0x48).readPointer().readUtf16String();
        var msg = this.context.rdi.add(0x88).readPointer().readUtf16String();
        console.log(id + ": " + msg)
    }
});
```

```
python hookmsg.py
```

其中python代码只是一个模板，在其中传入需要加载的js文件名称即可

​

效果

![Pasted image 20250318174707.png](images/ad648c3b-8245-3eaa-b771-b2ef401524ff)

![Pasted image 20250318174649.png](images/40dfc32b-f454-3c30-bbd8-e0eeff93ff37)

​

ps：因为是hook消息接收，所以就算发送的新消息被撤回了，控制台也能看到
