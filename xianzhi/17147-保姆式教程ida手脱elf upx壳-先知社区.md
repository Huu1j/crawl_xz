# 保姆式教程ida手脱elf upx壳-先知社区

> **来源**: https://xz.aliyun.com/news/17147  
> **文章ID**: 17147

---

之前看文章一直都是单步调试F8 F7去找OEP，但是操作的时候中间会经过很多函数，一个个F8跑飞了再F7，重新调试的时候有些烦躁和耗时间。

## 正文

在开头处下断点，打开虚拟机，启动调试

![image.png](images/ecbf5c5a-c4b2-3f30-934f-c78a84edb0c6)

在工具栏如下 函数跟踪，然后F9运行

![2daba224a44095f810ea0e1e51ef3cc.png](images/c95ec429-d32a-34b8-99b6-7d5b7a3cdfcf)

调试结束之后我们在这里查看调用的函数

![6ecbf82390783f1fdd65eb902890e98.png](images/8b50c3d7-c7e0-346c-9156-9d546e2c028d)

函数如下

![image.png](images/d2037887-51a3-3e55-81a6-1e96e72ecd1e)

mprotect 系统调用通常用于需要更改内存页权限的场景，例如使某个区域可执行以实现自修改代码或即时编译。upx解压的时候肯定会调用，我们跟踪过去

![image.png](images/078227a9-3ac5-318a-b404-336900cd160f)

下断点开始跑，个人觉得这样可以方便很多

![image.png](images/3faec16c-1899-33ff-9053-dd479c92d7eb)

一路F8/F7

![image.png](images/56ad6d68-f2cf-3f28-ac01-93d7aab1f3d7)

来到jmp这里F7步入

![image.png](images/9de8f0c5-7368-3a47-b12a-4a253f4b118c)

看到popa那快成功了

![image.png](images/9021393e-c01b-3fb9-adda-af1789d4c13b)

F8过来

![image.png](images/795c9cc5-020c-3501-9674-be4d3a70f385)

查看程序入口发现上面那就是入口OEP了

![image.png](images/7805e9cd-568d-338e-ba4c-55dbf3dca880)

内存快照，（这里也可以用idc脚本dump下来）

![1ad208d97dceba1d81ffa5ce114d9b8.png](images/e256a6f2-f20c-3d5a-b833-422eea9c03ad)

停止调试，回到入口处汇编那里重新P定义一下函数就可以了

![image.png](images/c87ba966-0de5-3ec4-8232-9f755c915ed5)

下面是此例题的flag

![image.png](images/c5adc31d-b96d-3815-9be2-4db166c6c221)
