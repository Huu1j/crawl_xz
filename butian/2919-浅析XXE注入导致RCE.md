# 浅析XXE注入导致RCE

> **来源**: https://forum.butian.net/share/2919  
> **文章ID**: 2919

---

XXE（XML 外部实体注入）漏洞，可以使攻击者能够干扰 Web 应用程序中 XML 数据的处理。利用此漏洞后，XXE 可允许攻击者访问敏感数据、执行远程代码或干扰 Web 应用程序中 XML 数据的处理。

先用php进行简单的案例示范

![image.png](images/attach-f6248bbb9d4bdd026426c90f04b88dc9950eaa92.png)

可以看到访问成功的输出1.txt文件

![image.png](images/attach-186d8491faa7b0a2c17926d45343a94c81fa1cb4.png)

利用expect协议可以成功打rce，但因为windows不好安装扩展所以改用centos做测试

以下是环境配置教程

安装EPEL仓库

sudo yum install epel-release

![image.png](images/attach-20daf49dcdde06f5d43c08a85a62506267abf2d7.png)

使用以下命令安装php开发工具和expect

sudo yum install php-devel expect

![image.png](images/attach-7c44dfad7307ceec88885bfb59384936cd192af5.png)

sudo yum install tcl-devel

sudo yum install expect-devel

![image.png](images/attach-bb2e42e9f6d2929599ed00fe92aa15aff91c4b9d.png)

![image.png](images/attach-8dd93bda9560f8037ddd6d0c034eb01e9cdc4260.png)

然后安装pecl

sudo yum install php-pear

![image.png](images/attach-979bef98a67fd41ac3bfa5b441030a453a8ff5b9.png)

最后使用pecl进行安装expect

![image.png](images/attach-63d3a74abfe2c3c31c187d31e3577811aa92875f.png)

出现下面的消息说明安装成功

![image.png](images/attach-5b62c1b07708a742403105b42f944cdac3a96ae3.png)

然后开始进行配置

Vim /etc/php.ini

加一行

Extension=expect.so

![image.png](images/attach-7c71a8a2b1e32898c8084b0bda17c7b4e0a4a2eb.png)

然后进行RCE复现

<?xml version="1.0"?>

\[

\]>

&xxe;

![image.png](images/attach-1e0e738576cf815189ce21f3074dbfbc18f45a34.png)

那么为何能执行命令呢，我们下载下来源码进行分析

<https://pecl.php.net/get/expect-0.4.0.tgz>

在expect\_fopen\_wrapper.c文件中

35行开始，首先检查命令字符串是否以"expect://"开头，如果是，则移除这个前缀，然后使用exp\_popen函数尝试启动命令指定的外部进程

![image.png](images/attach-b3f239d6677d97688b527b4b2af619b8f415a345.png)

而在expect库中

<https://core.tcl-lang.org/expect/index>

exp\_clib.c文件中定义了exp\_popen

![image.png](images/attach-7c0584274d80f4d2695ddbf9367c061ecb240869.png)

跟进exp\_spawnl，初始化后使用malloc为参数组”argv”分配内存，然后调用exp\_spawnv

![image.png](images/attach-c7c99d614c56ad7424c528447c9704da86c68c78.png)

继续跟进

file是要执行的程序的路径，argv是传递给该程序的参数列表，以NULL终止。然后初始化伪终端（pty）

![image.png](images/attach-d90435b3e33dcce2181995732d80d40ecd55a7d4.png)

往下走，发现在1909中使用fork创建了子进程

![image.png](images/attach-c9b53a8ed5d19a915835b6702c4dc728e5f50e43.png)

那么最终执行点在哪呢？在2217中使用execvp执行命令，其中file与argv都是我们传的参数，至此流程结束
