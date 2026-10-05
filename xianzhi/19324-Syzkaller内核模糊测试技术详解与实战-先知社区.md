# Syzkaller内核模糊测试技术详解与实战-先知社区

> **来源**: https://xz.aliyun.com/news/19324  
> **文章ID**: 19324

---

## 简介

### 基本知识

Syzkaller 是 Google 的安全研究人员开发并维护的开源内核 Fuzz 工具，目前主要由 [dvyukov](https://github.com/dvyukov) 维护。它是使用 Go 语言编写的，也有少部分 C 代码，具有部署快速、使用简便的特点，同时还支持多种操作系统如：Linux、Android、Windows、openbsd、darwin 等系统。不过它支持最全面的还是 Linux 系统。

众所周知内核是通过系统调用进行交互的，因此 Syzkaller 的 Fuzzing 是通过**不断构造系统调用序列**来驱动内核执行。这些系统调用组合会触发内核中的各种逻辑路径，进而暴露潜在的安全漏洞。

为了生成更高效的测试用例，通过内核插桩机制获取覆盖率反馈用于引导 Fuzzing。内核通过 KCOV 插桩内核代码，获得边覆盖。被 KCOV 编译的内核运行起来后，会在`sys/kernel/debug/kcov`目录下生成对应的接口文件，Syzkaller 程序会通过`ioctl`接口与该文件交互，获取内核的执行路径信息，从而作为覆盖率反馈。

Google 还维护了一个公开的 Syzkaller 平台——[syzbot](https://syzkaller.appspot.com/)，用于持续自动 Fuzzing 最新的 Linux 内核主线。我们可以通过 syzbot 查看 Linux 系统中常见的漏洞的分布区域。

### 架构信息

下面是 Syzkaller 的架构图，主要分为二个组件，分别是 syz-manager 和 syz-executor（新版取消了 syz-fuzzer 组件）：

![Pasted image 20250521160056.png](images/img_19324_000.png)

**syz-manager**：主控模块，运行在 VM 外。

* 在宿主机上运行，每个虚拟机对应一个 syz-manager 启动的管理进程。
* 内置 fuzzing 核心逻辑（包括系统调用生成、变异、语料更新等）；
* 收集并记录覆盖率和崩溃信息。
* 提供 Web UI 展示统计信息。

**syz-executor**：在 VM 内执行。

* 运行于每个虚拟机内部。
* 接收 syz-manager 下发的系统调用程序（syscall sequence）。
* 启动临时子进程执行单一测试输入（即一系列系统调用）。
* 收集 KCOV 覆盖率信息，反馈执行结果。
* 报告崩溃、挂起或异常状态。
* 以 C++ 静态编译方式实现，进程间通过共享内存通信，保证简洁、高效。

### 工作流程

* syz-manager 生成系统调用序列，封装成二进制文件。
* 通过 SSH 将测试程序传输到目标虚拟机。
* syz-executor 接收程序，执行系统调用组合以触发内核不同代码路径。
* 利用内核的 KCOV 插桩收集覆盖率信息，作为反馈引导 Fuzz。
* syz-manager 监控虚拟机运行状态，遇内核 panic 自动重启虚拟机（借助虚拟机快照和 watchdog 机制）。
* 崩溃和覆盖率数据被收集并持久化，便于后续分析和复现。

**架构示意图**：

```
+----------------------+
|     syz-manager      |    ⇽ 宿主机（管理者）
|----------------------|
| - 管理虚拟机实例      |
| - 系统调用生成与变异  |
| - 收集覆盖率与崩溃    |
| - Web UI 展示        |
+----------+-----------+
           |
           | RPC 通信
           v
+----------+-----------+
|    syz-executor      |    ⇽ 虚拟机内部执行
|----------------------|
| - 执行系统调用程序    |
| - 收集 KCOV 覆盖率    |
| - 上报崩溃与反馈结果   |
+----------------------+
```

### 崩溃报告

Syzkaller 对每一种唯一的内核崩溃（Crash）都会保存一个专属目录，目录名是崩溃的唯一标识（hash），方便归类和去重。

目录结构示例：

```
syzkaller_workdir/crashes/
   ├── 6e512290efa36515a7a27e53623304d20d1c3e/
   │     ├── description    # 崩溃简短描述
   │     ├── log0           # 原始内核日志及测试输入（第一次崩溃）
   │     ├── report0        # 后处理符号化报告（第一次崩溃）
   │     ├── log1           # 原始日志（重复崩溃）
   │     ├── report1        # 后处理报告（重复崩溃）
   │ 	 ├── report.prog    # 复现某次 fuzz 触发的内核 crash 的程序
   │     └── report.cprog   # repro.prog 的 C 可执行复现程序
   ├── 77c578906abe311d06227b9dc3bffa4c52676f/
   │     ├── description
   │     ├── log0
   │     ├── report0
   │     └── ...
```

三种特殊崩溃类型：

这类崩溃通常没有正常的日志和报告，但也是内核异常的信号。

|  |  |
| --- | --- |
| 崩溃类型 | 说明 |
| `no output from test machine` | 测试机无任何输出，通常指内核死锁、严重挂起或崩溃。 |
| `lost connection to test machine` | SSH 连接中断，可能内核 panic 或网络故障导致。 |
| `test machine is not executing programs` | 测试机看似在线，但长时间未执行测试程序，可能挂起或陷入死循环。 |

* 这些情况可能没有对应的`logN`或`reportN`文件。
* 日志中如出现 Go runtime panic 等异常，也是一种重要的错误信号。

大部分情况下这些崩溃表明内核死机或类似的环境问题。

## 环境配置

使用 Syzkaller 进行 Linux 内核的 Fuzzing 需要以下环境：

* 硬件支持
* 编译 Syzkaller 项目
* 编译 Linux 内核
* 配置 Qemu 虚拟机

### 硬件支持

使用 Syzkaller 进行内核模糊测试，需要满足以下硬件和内核条件：

* **CPU 支持虚拟化**

检查 CPU 是否支持虚拟化技术：

```
egrep -wo 'vmx|svm' /proc/cpuinfo | sort | uniq
```

* 有输出 `vmx` → Intel 支持虚拟化
* 有输出 `svm` → AMD 支持虚拟化
* 没输出 → CPU 虚拟化关闭，需在 BIOS 开启（Intel VT-x 或 AMD-V）
* **内核支持 KVM**

Syzkaller 依赖 KVM 进行虚拟化测试，因此需要加载相应模块：

```
sudo modprobe kvm  
sudo modprobe kvm_intel   # Intel CPU  
# 或者  
sudo modprobe kvm_amd     # AMD CPU
```

### 编译Syzkaller

编译 Syzkaller 需安装 Go 编译器和 C 编译器：

```
# 下载 Go 1.23.7
wget https://go.dev/dl/go1.23.7.linux-amd64.tar.gz

# 解压到 /usr/local
sudo tar -C /usr/local -xzf go1.23.7.linux-amd64.tar.gz

# 设置环境变量
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$GOROOT/bin:$GOPATH/bin:$PATH

sudo apt install gcc

# 不开代理建议配置 Go 国内代理
export GOPROXY=https://goproxy.cn,direct
```

安装所需的依赖：

```
# 安装所需的依赖
sudo apt update
sudo apt install build-essential clang llvm libncurses5-dev libssl-dev libelf-dev bc
sudo apt install make flex bison libncurses-dev libelf-dev libssl-dev
```

编译 Syzkaller：

```
git clone https://github.com/google/syzkaller
cd syzkaller
make all
```

如果我们需要对其它架构下的目标进行 Fuzz，那么我们需要进行交叉编译。

```
#如 arm 架构的目标
make CC=aarch64-linux-gnu-g++ TARGETARCH=arm64
```

编译完成后，生成的执行文件会放在`syzkaller/bin/`目录中。

### 编译Linux内核

以内核版本 5.15 为例：

```
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.38.tar.xz
tar -xvf linux-5.15.186.tar.xz && cd linux-5.15

make defconfig         # 生成默认配置（根据架构）
make kvm_guest.config  #开启适合 KVM 来宾系统的选项
```

syzkaller 所需的功能主要是启用`KCOV`来收集内核覆盖，并启用`KASAN`来检测内存错误。

修改内核配置，通过`scripts/config`启用所需选项，以便于让内核更好的被 Fuzz。

```
scripts/config --enable CONFIG_KCOV         # 启用 KCOV
scripts/config --enable CONFIG_KASAN        # 启用 KASAN  
scripts/config --enable CONFIG_KASAN_INLINE # 允许内联检测代码
scripts/config --enable CONFIG_DEBUG_INFO

scripts/config --disable CONFIG_DEBUG_INFO_NONE 
scripts/config --enable CONFIG_DEBUG_INFO_DWARF4 # 开启内核调试信息生成

scripts/config --enable CONFIG_NET_SCHED
scripts/config --enable CONFIG_NET_CLS_ACT
scripts/config --enable CONFIG_NET_SCH_FQ
scripts/config --enable CONFIG_NET_SCH_NETEM
scripts/config --enable CONFIG_NET_SCH_INGRESS
scripts/config --enable CONFIG_NET_SCH_HTB
scripts/config --enable CONFIG_NET_SCH_PRIO

scripts/config --enable CONFIG_CONFIGFS_FS  # 启用 configfs 文件系统支持
scripts/config --enable CONFIG_SECURITYFS   # 启用 securityfs 文件系统
scripts/config --enable CONFIG_KCOV_JIT
scripts/config --enable CONFIG_DEBUG_KERNEL
scripts/config --enable CONFIG_LOCKDEP
```

重新生成配置文件并编译：

```
#修改完成后更新配置
make olddefconfig

#编译
make -j$(nproc)
```

编译后会生成以下文件：

* `bzImage`：经过压缩的可启动内核镜像，位于`arch`目录中相应架构的目录下。
* `vmlinux`：带有调试符号的未压缩内核镜像。

### Qemu配置

Syzkaller 主要通过 Qemu 来运行 Linux 内核。

安装 qemu：

```
sudo apt install qemu-system-x86
```

创建虚拟机镜像：

使用`debootstrap`来创建一个最小的 Debian 系统根文件系统。

```
sudo apt install debootstrap
cd /linux

#下载 syzkaller 项目 tools 目录下的 create-image.sh 文件
wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh -O create-image.sh  
chmod +x create-image.sh

#Linux 项目不能存在于挂载目录上，否则会报错
./create-image.sh
```

脚本运行完后，当前目录下多了几个文件：

```
❯ ls
bullseye  bullseye.id_rsa  bullseye.id_rsa.pub  bullseye.img  create-image.sh
```

主要文件：

* `bullseye.img`：虚拟机硬盘镜像文件
* `bullseye.id_rsa`：SSH 私钥
* `bullseye.id_rsa.pub`：SSH 公钥

启动虚拟机：

修改指定`bzImage`文件和`bullseye.img`文件，其余参数不变。

```
qemu-system-x86_64 \                                   
  -m 2G \                                         
  -smp 2 \                                        
  -kernel /linux/arch/x86/boot/bzImage \             #指定bzImage文件
  -append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0" \   
  -drive file=/linux/bullseye.img,format=raw \  #指定文件系统
  -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \  
  -net nic,model=e1000 \  
  -enable-kvm \  
  -nographic \  
  -pidfile vm.pid \  
  2>&1 | tee vm.log
```

如果成功的话，就会出现 syzkaller login。用户名键入`root`，无需输入密码，即可进入终端。  
![Pasted image 20250713081526.png](images/img_19324_001.png)  
我们需要测试 ssh 是否能正常工作，因为 syzkaller 是通过 ssh 向 VM 传输文件的。

```
ssh -i /linux/bullseye.id_rsa -p 10021 -o "StrictHostKeyChecking no" root@localhost
```

![Pasted image 20250713081635.png](images/img_19324_002.png)然后我们可以通过`poweroff`命令关闭虚拟机模拟的系统。

## 基本用法

### 配置文件

当以上环境搭建完成后，为 Syzkaller 创建一个配置文件`test.cfg`，这个配置文件将指定一些参数，如目标内核、内核调试符号、执行的测试类型等。以下是官方的配置示例：

```
{
  "target": "linux/amd64",                    // 目标平台架构
  "http": "127.0.0.1:56741",                  // WebUI接口
  "workdir": "/linux/workdir/",               // 工作目录
  "kernel_obj": "/linux/",                    // 内核路径
  "image": "/linux/bullseye.img",             // QEMU 虚拟机镜像
  "sshkey": "/linux/bullseye.id_rsa",         // 连接 虚拟机 用的私钥
  "syzkaller": "/syzkaller/",                 // syzkaller 源码路径
  "procs": 8,                                 // 每个 VM 中并发 fuzz 实例数量
  "type": "qemu",                             // 虚拟机类型
  "vm": {
    "count": 4,                               // 启动的 VM 数量
    "kernel": "/linux/arch/x86/boot/bzImage", // bzImage 路径
    "cmdline": "net.ifnames=0",               // 内核参数（简化网络设备名）
    "cpu": 2,                                 // 每个 VM 的 CPU 数量
    "mem": 2048                               // 每个 VM 的内存（单位：MB）
  }
}
```

### 启动运行

执行以下命令来运行 Syzkaller：

```
syz-manager -config test.cfg
```

一但 Syzkaller 在其中一个 VM 中检测到内核崩溃，它将自动重现此崩溃的过程。默认情况下，它将使用 4 个 VM 来重新崩溃，然后最小化导致崩溃的重新。

启动后可以通过`http://localhost:56741`访问 WebUI 界面，看到以下界面代码启动成功。  
![Pasted image 20250823191402.png](images/img_19324_003.png)

如果出错，加上`-debug`参数可以排查 Syzkaller 运行失败的问题。

```
syz-manager -config test.cfg --debug
```

它会输出`syz-manager`的日志信息，包括虚拟机启动、SSH 连接尝试以及`syz-executor`的运行状态等详细内容。

### KCOV

Syzkaller 使用 KCOV 接口收集代码覆盖信息，可以通过访问以下地址查看覆盖率信息：

```
http://127.0.0.1:$(PORT)/cover
```

我们可以选择想要查看的文件查看更具体的覆盖率。

![Pasted image 20250930211622.png](images/img_19324_004.png)

KCOV 会使用不同颜色高亮显示已覆盖的分支，颜色标注说明：

* 已覆盖：黑色
* 部分覆盖：橙色
* 函数未执行：暗红色
* 未覆盖：红色
* 未插桩：灰色

Syzkaller 项目提供了 syz-cover 工具，可以基于原始覆盖率数据生成报告。

构建方法：

```
make cover
```

原始覆盖率数据可通过 syz-manager 获取：

```
wget http://localhost:<syz-manager端口>/rawcover
```

将数据输入 syz-cover 生成报告：

```
bin/syz-cover --config <syzkaller配置文件路径> rawcover
```

导出函数覆盖率 CSV 文件：

```
bin/syz-cover --config <syzkaller配置文件路径> --csv <输出文件名> rawcover
```

导出源码行覆盖率 JSON 文件：

```
bin/syz-cover --config <syzkaller配置文件路径> --json <输出文件名> rawcover
```

## syzlang

Syzkaller 自己定义了一套声明式语言，称为 syzlang，用于描述系统调用（syscall）的接口和参数格式。每个目标设备节点通常对应一个专门的 syzlang 声明文件（txt 格式）。通过通过定制 syzlang 文件，Syzkaller 能精准理解目标内核或子系统的系统调用参数及行为，从而提高模糊测试的效率和覆盖率。

### 基本结构

syzlang 文件基于 Syzkaller 设计的语法，描述包括：系统调用名称与编号、参数类型、参数的可选值、返回值类型以及常量与宏定义引用。

一个 syzlang 描述文件通常包含以下元素：

|  |  |  |
| --- | --- | --- |
| 元素 | 示例 | 说明 |
| `include` | `include <linux/fs.h>` | 引用头文件，仅作为标注 |
| `syscall` | `open(file filename, flags flags[open_flags], mode flags[open_mode]) fd` | 定义 syscall |
| 返回值 | `fd`, `intptr`, `void` | 返回类型（通常是 `resource`） |
| `flags` | `open_flags = O_RDONLY, O_RDWR, O_CREAT` | 枚举值集合 |
| `bitmask` | `prot_flags = PROT_READ, PROT_WRITE` | 按位或组合 |
| `struct` | `sock_fprog { len len[filter, int16]; filter ptr[in, array[sock_filter]] }` | 定义结构体 |
| `union` | `union u [ type1, type2 ]` | 定义联合体 |
| 别名 | `type buffer ptr[in, array[int8]]` | 类型模板/别名 |
| 注释 | `# comment` | 单行注释 |

例：

```
open(file filename, flags flags[open_flags], mode flags[open_mode]) fd
read(fd fd, buf buffer[out], count len[buf])
close(fd fd)

open_flags = O_RDONLY, O_WRONLY, O_RDWR, O_APPEND, O_CREAT
open_mode = S_IRUSR, S_IWUSR, S_IXUSR, S_IRGRP
```

syzlang 中的注释与 Shell 脚本注释形式相同，为以`#`开头的单行注释。在 syzlang 中，我们可以额外引入内核源码文件作为参数、系统调用等一系列的补充，形式与 C 语言的 include 语句大致相同，不过没有了开头的`#`号

```
openat(fd fd, path ptr[in, filename], flags flags[open_flags], mode mode[octal]) fd
```

* `openat`：系统调用名称
* 参数说明：

* `fd fd`：一个文件描述符类型参数。
* `path ptr[in, filename]`：输入参数指针，指向一个文件名
* `flags flags[open_flags]`：带有符号集合的 flags
* `mode mode[octal]`：八进制表示的权限

* 返回值：类型为 `fd`（文件描述符）

### syscall描述基本格式

```
syscallname(argname1 type1, argname2 type2, ...) return_type
```

常用类型包括：

* `intN` / `intptr`：普通整数类型（带有可选范围、对齐）
* `flags[flagname]`：枚举或位标志
* `ptr[in, type]`：指针（方向可选 in/out/inout）
* `array[type, size]`：数组（长度可选固定/范围）
* `string[filename]`：字符串（例如生成文件路径）
* `len[fieldname]` / `bytesize[fieldname]`：指定字段长度

类型模板与别名：

```
type buffer[DIR] ptr[DIR, array[int8]]
type optional[T] [
  val	T
  void	void
] [varlen]
```

这可以大大简化重复结构的写法，增强可读性和复读性。

调用属性：

可选关键字修饰 syscall 调用行为：

* `no_generate`: 不自动生成调用（用于 seed 触发）
* `no_minimize`: 崩溃最小化时跳过该调用
* `ignore_return`: 不使用返回值作为反馈路径
* `timeout[N]`, `prog_timeout[N]`: 增加 fuzz 超时时间
* `disabled`: 禁用该 syscall（调试或逐步启用时有用）

条件字段语法与路径引用：

```
field2 int32 (if[value[header:haveInteger] == 1])
```

* 使用 `value[path]` 可引用嵌套结构字段
* 可组合逻辑运算：`==`, `!=`, `&`, `||`
* `syscall:argname` 可引用 syscall 外部参数
* 注意：不支持条件字段嵌套引用链（如字段本身带 if）

### 类型系统

* 基本类型：

```
int8, int16, int32, int64
const[123, int32]   # 常量
bool8, bool32       # 布尔类型
```

* 指针类型：

```
ptr[in, struct_name]   # 输入指针
ptr[out, buffer]       # 输出指针
```

* 数组：

```
array[int32, 4]      # 固定长度数组
array[int8, VAR]     # 动态数组
```

* union

```
union my_union [
  type1
  type2
  type3
]
```

最后一个 union 项不能加条件（必须有 fallback），`[varlen]` 表示大小依赖于所选字段。

* struct：

```
my_struct {
  field1   int32
  field2   ptr[in, buffer]
  ...
}
```

可以使用条件字段 `(if[...])`、可以定义为 `[packed]` 结构以避免自动对齐、支持`out_overlay`字段区分输入输出共享内存布局。

### 常量和flags

* const

```
define SOME_CONST  0x1000
```

* flags

```
flags open_flags = O_RDONLY, O_WRONLY, O_CREAT, O_APPEND
```

* bitmask

`bitmask`是一种 flags 类型修饰符，表示这些 flag 标志可以通过按位或的方式组成多个取值。

```
bitmask prot_flags = PROT_READ, PROT_WRITE, PROT_EXEC
```

### 资源类型

用于管理系统资源，如文件描述符、socket、eventfd 等。资源是 syzkaller 建立 syscall 顺序依赖关系的关键。

```
resource fd[int32]: 0xffffffffffffffff, AT_FDCWD

open(...) fd
read(fd fd, ...)
close(fd fd)
```

资源的使用可以帮助 Syzkaller 自动构建合法调用链。

### 高级特性

* `define`宏定义：

可定义魔数、长度、特殊常量，用于结构体或验证。

```
define XT_BPF_MAX_NUM_INSTR 64
```

* `[align[x]]`对齐约束：

```
my_struct {
  field1 int32
  field2 ptr[in, buffer]
} [align[8]]
```

* `[packed]`与`[varlen]`修饰符

* `[packed]`：紧凑布局，取消默认 padding。
* `[varlen]`：用于描述变长结构体或联合体的尾部。

描述文件还包含指向 Linux 内核头文件的`include`指令、指向自定义 Linux 内核头文件目录的`incdir`指令和定义符号常量值的`define`指令。

### 编写技巧

* 系统调用 / 结构体 / 字段 / 标志命名：遵循内核已有命名，不要创造新名字；
* 系统调用顺序中的资源：`in`/`out`/`inout`决定调用顺序；
* 使用未声明的值：不要随意添加`-1`、`INT_MAX`这种特殊值；
* Flags / Enums：flag类型可用于枚举、位标志、混合模式。
* 声明顺序：不要求先声明后使用，推荐按重要性排序。与 C 相反，最重要的放最前面。

### 使用流程

编写系统调用描述文件时我们需要调研接口，了解相关 syscalls。然后将编写的描述文件放入`syzkaller/sys/linux`这个目录下。最后我们需要使用 syz-extract 和 syz-gen 来生成 Go 描述代码。

后面我们会通过实例来学习这个流程的具体操作。

### Headerparser

由于手工编写 syzlang 描述成本较高，人们开始研究自动化生成系统调用描述的方法。headerparser 就是一个比较成熟的辅助工具，可自动生成 syzlang 描述。

为了让 Syzkaller 在 fuzz 某个设备节点时更加智能，你可以提供该设备所需的`ioctl`参数结构体类型信息。然而，当结构体类型数量庞大时，手动编写描述文件的工作量会很大。

为减轻这种负担，`headerlib`会尽量自动生成这些描述文件。不过，你仍需从 [类型列表](https://chatgpt.com/docs/syscall_descriptions_syntax.md) 中手动选择适合的 syzkaller 数据类型。

下载：[Headerparser](https://github.com/google/syzkaller/tree/master/tools/syz-headerparser)

环境配置：

```
pip3 install pycparser
```

基本用法：

```
python3 headerparser.py --filenames=./test_headers/th_b.h    
B {    
          B1     len|fileoff|flags|intN     #(unsigned long)    
          B2     len|fileoff|flags|intN     #(unsigned long)    
}    
struct_containing_union {    
          something          len|fileoff|flags|int32                   #(int)    
          a_union.a_char     ptr[in|out, string]|ptr[in, filename]     #(char*)    
          a_union.B_ptr      ptr|buffer|array                          #(struct B*)    
}
```

你可以直接复制`Structure Metadata`部分的内容到 syzkaller 的设备描述文件中。

## 实例

这里我们使用一个存在漏洞的驱动模块代码来测试我们是否可以使用 Syzkaller 将其 Fuzzing 出来。

### 漏洞驱动

初始加载驱动时，会在`/proc`文件夹下创建一个名为`test`的伪设备节点。然后支持用户空间的`read`和`write`操作。

```
#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#define MY_DEV_NAME "test"
#define DEBUG_FLAG "PROC_DEV"

static ssize_t proc_read(struct file *proc_file, char __user *proc_user, size_t n, loff_t *loff);
static ssize_t proc_write(struct file *proc_file, const char __user *proc_user, size_t n, loff_t *loff);
static int proc_open(struct inode *proc_inode, struct file *proc_file);

// file_operations 结构体，用于注册读写操作
static const struct proc_ops proc_fops = {
    .proc_open = proc_open,
    .proc_read = proc_read,
    .proc_write = proc_write,
};

// 模块初始化函数，在 insmod 加载模块时被调用
static int __init mod_init(void)
{
    struct proc_dir_entry *test_entry;

    printk(DEBUG_FLAG ": proc init start!
");

    test_entry = proc_create(MY_DEV_NAME, 0666, NULL, &proc_fops);
    if (!test_entry)
        printk(DEBUG_FLAG ": failed to create /proc entry!
");
    else
        printk(DEBUG_FLAG ": proc init over!
");

    return 0;
}

// 打开操作，仅打印调试信息
static int proc_open(struct inode *proc_inode, struct file *proc_file)
{
    printk(DEBUG_FLAG ": into open!
");
    return 0;
}

// 读操作函数：当前没有真正实现任何功能，仅打印调试信息
static ssize_t proc_read(struct file *proc_file, char __user *proc_user, size_t n, loff_t *loff)
{
    printk(DEBUG_FLAG":finish copy_from_use,the string of newbuf is");
    return 0;
}

// 写操作函数：存在严重的堆溢出漏洞
static ssize_t proc_write(struct file *proc_file, const char __user *proc_user, size_t n, loff_t *loff)
{
    char *c = kmalloc(n + 512, GFP_KERNEL);  
    
    //溢出，原先只有 512 字节，但是复制了 4096
    size_t size = copy_from_user(c, proc_user, n + 4096);  
    printk(DEBUG_FLAG":into write %ld!
", size);
    return 0;
}

// 注册模块初始化函数
module_init(mod_init);
MODULE_LICENSE("GPL");
```

在`proc_write`函数中，`kmalloc`函数（`kmalloc`是内核的内存分配函数）申请了`n+512`字节的内核缓冲区。`copy_from_user`从用户空间复制`n+4096`字节到这个缓冲区中，超出其分配内存导致了堆溢出。

### 编译进内核

将漏洞驱动编译进内核中。

```
# 将漏洞驱动文件复制到 linux/drivers/char/ 目录下
mv test.c linux/drivers/char/

# 修改 Makefile   
echo "obj-y += test.o" >> linux/drivers/char/Makefile  

# 编译  
make -j$(nproc)
```

运行内核后可用在`/proc/test`下可以找到目标：

```
root@syzkaller:~# cat /proc/test
[   61.660874] PROC_DEV: into open!
```

### 编写syzlang

接下来我们给漏洞驱动编写 syzlang 描述文件，在`syzkaller/sys/linux/`创建一个对应于这个漏洞驱动的描述文件`vuln.txt`，内容如下：

```
include <linux/fs.h>  
   
open$proc(file ptr[in, string["/proc/test"]], flags flags[proc_open_flags], mode flags[proc_open_mode]) fd  
read$proc(fd fd, buf buffer[out], count len[buf])  
write$proc(fd fd, buf buffer[in], count len[buf])  
close$proc(fd fd)  
   
proc_open_flags = O_RDONLY, O_WRONLY, O_RDWR, O_APPEND, FASYNC, O_CLOEXEC, O_CREAT, O_DIRECT, O_DIRECTORY, O_EXCL, O_LARGEFILE, O_NOATIME, O_NOCTTY, O_NOFOLLOW, O_NONBLOCK, O_PATH, O_SYNC, O_TRUNC, __O_TMPFILE  
proc_open_mode = S_IRUSR, S_IWUSR, S_IXUSR, S_IRGRP, S_IWGRP, S_IXGRP, S_IROTH, S_IWOTH, S_IXOTH
```

* `include <linux/fs.h>`：表示引用`linux/fs.h`中定义的常量、结构体、宏等。
* `open$proc(...)`：使用系统调用`open`，并通过`$proc`做 “符号变种” 标识。表示这个`open`是专用于`/proc/test`的。
* `file ptr[in, string["/proc/test"]]`：固定路径参数，仅允许 open `/proc/test`，是一个常量字符串。
* `bitmask proc_open_flags`：定义了一组打开文件时的选项。
* `bitmask proc_open_mode`：定义了文件权限。

在 Syzkaller 项目根目录下执行以下命令以创建对应的`.const`文件：

```
bin/syz-extract -os linux -sourcedir /root/linux-6.12.38 -arch amd64 vuln.txt
```

然后就会在`sys/linux`目录下生成`*.const`文件，然后通过 syz-sysgen 将描述文件翻译成 go 代码结构。而且由于我们新增了 syscall 描述文件所以我们需要重建 Syzkaller。

```
#将 syscall 描述文件转换为 go 代码结构
bin/syz-sysgen

#重建 syzkaller
make all
```

### Fuzzing

限定 Fuzz 的 syscall 集合，进一步缩小 Fuzz 的范围，提高精度。

即让 Syzkaller 只 Fuzz 有漏洞的接口，提高测试效率。

在开始 Fuzz 之前我们需要修改 Syzkaller 的运行配置启用这些系统调用。修改`test.cfg`，添加以下内容：

```
{
  "target": "linux/amd64",
  "http": "127.0.0.1:56741",
  "workdir": "/linux/workdir/",
  "kernel_obj": "/linux/",
  "image": "/linux/bullseye.img",
  "sshkey": "/linux/bullseye.id_rsa",
  "syzkaller": "/syzkaller/",
  "procs": 8,
  "type": "qemu",
  //开启的系统调用
  "enable_syscalls": [
    "open$proc",
    "read$proc",
    "write$proc",
    "close$proc"
  ],
  "vm": {
    "count": 4,
    "kernel": "/linux/arch/x86/boot/bzImage",
    "cmdline": "net.ifnames=0",
    "cpu": 2,
    "mem": 2048
  }
}
```

开始 Fuzzing：

```
syz-manager -config test.cfg -vv 10
```

很快就 Fuzzing 出了这个洞：

![Pasted image 20250823191616.png](images/img_19324_005.png)

然后 Syzkaller 就会复现 crash，`reproducing=1`表示有一个正在复现的 crash。

一旦 Syzkaller 在某个 VM 中检测到内核崩溃，它将自动开始重现该崩溃全过程（除非你在配置中指定 `"reproduce": false`）。 默认情况下，它将使用 4 个 VM 来重现内核崩溃，并缩小引起内核崩溃的程序。 这可能会停止模糊测试，因为所有的 VM 可能都在忙于重现检测到的内核崩溃。

重现一个内核崩溃的过程可能需要几分钟到一个小时不等，这取决于内核崩溃是否容易重现或根本不可重现。 由于这个过程并不完美，有一种尝试手动重现崩溃的方法，详见[此处](typora://app/docs/reproducing_crashes.md)描述。

如果成功找到复现程序，它将以 syzkaller 程序或 C 程序 进行呈现。 Syzkaller 总是尝试生成更用户友好的 C 语言复现程序，但有时因为各种原因失败（例如轻微不同的执行时序）。 如果 Syzkaller 仅生成 Syzkaller 程序，你可以通过[一种方式](typora://app/docs/reproducing_crashes.md)执行这些程序来手动重现和调试内核崩溃。

![Pasted image 20250823195558.png](images/img_19324_006.png)

点击 has C repro 可以看到最小化的 crash：

![Pasted image 20250823195624.png](images/img_19324_007.png)

### 复现Crash

在我们运行 Syzkaller fuzzing 出 crash 的时候，Syzkaller 会调用 syz-execprog 执行 prog 程序并调用 syz-prog2c 尝试生成 C 代码。

同样我们也可以自己将 syz-execprog push 到虚拟机中去运行我们要复现的 crash 的 prog 程序，但是这样效率较低而且效果不好，所以 Syzkaller 的工具链中集成了更好用的一些工具。

#### syz-crush

syz-crush 用于读取 crash 的 prog 程序，然后重复执行该程序复现 crash。

构建：

```
make crush

```

运行工具：

```
mkdir workdir  
bin/syz-crush -config ./test.cfg ./crashes/736f88e1c13700f40338df50cd9a6364a46963cf/repro.cprog
```

其它参数：

* `-debug`：开启调试模式，将虚拟机的所有标准输出打印到本地控制台；
* `-infinite`：控制是否持续执行测试，默认一直执行，值为`true`或`false`；
* `-strace`：在 strace 模式下运行被测程序；
* `-vv int`：日志详细级别，由 0 到 3。

![](file:///D:/Security/Binary/workdir/assets/image-20251110232117182.png?lastModify=1762966662)![image-20251110232117182.png](images/img_19324_009.png)

手动停止后观察 syz-crush 输出的信息发现，它在运行过程中进行了 104 次崩溃复现，其中成功稳定复现了 101 次（约 97.12%），并将这些经过验证的 crash 保存到了`crashes/736f88e1c13700f40338df50cd9a6364a46963cf/crashes/439c37d288d4f26a33a6c7e5c57a97791453a447` 目录下。

![](file:///D:/Security/Binary/workdir/assets/image-20251110232754412.png?lastModify=1762966662)![image-20251110232754412.png](images/img_19324_011.png)

#### syz-repro

使用 repro 复现 crash：

```
bin/syz-repro -config=test.cfg ./crashes/736f88e1c13700f40338df50cd9a6364a46963cf/repro.prog
```

其它参数：

* `-count int`：用于并行复现的 VM 数量，会覆盖配置文件；
* `-crepro string`：制定输出的 C Poc 文件名，默认为 repro.c。
* `-debug`：打印更详细的调试信息。
* `-output string`：制定输出的 syz 复现文件，默认为 repro.txt；
* `-strace string`：将执行过程的 strace 日志输出到指定文件；
* `-title string`：把复现到的 crash 摘要写入指定文件；
* `-vv int`：日志详细级别，由 0 到 2。

运行成功后 syz-repro 会解析 prog 文件并开始复现程序。

![](file:///D:/Security/Binary/workdir/assets/image-20251113002116233.png?lastModify=1762966662)![image-20251113002116233.png](images/img_19324_013.png)

分析 KASAN 报错头部发现`inline_copy_from_user`和`_copy_from_user`，说明越界发生在内核从用户空间读取数据时；跟踪调用栈发现`copy_from_user`（内核访问用户空间数据统一接口函数），`proc_write`函数紧跟在`copy_from_user`上方，说明它是调用`copy_from_user`的函数。也就是说，用户空间写入的数据经过`proc_write`进入内核，而越界正是在这个函数分配的缓冲区内发生的。

![](file:///D:/Security/Binary/workdir/assets/image-20251113003843934.png?lastModify=1762966662)![image-20251113003843934.png](images/img_19324_015.png)

分析输出信息发现内核分配了 512 字节的对象，但是程序写入了 4096 字节导致了越界：

![](file:///D:/Security/Binary/workdir/assets/image-20251113004150801.png?lastModify=1762966662)![image-20251113004150801.png](images/img_19324_017.png)

最后会在当前目录生成`repro.txt`文件，并描述复现 crash 中进行的一系列操作。

![](file:///D:/Security/Binary/workdir/assets/image-20251113003538827.png?lastModify=1762966662)![image-20251113003538827.png](images/img_19324_019.png)

repro.txt 文件内容：

```
r0 = open$proc(&(0x7f0000000580), 0x2, 0x24)  
write$proc(r0, 0x0, 0x0)
```

这是最小化后的 syz 程序。

## 总结

深入理解 Syzkaller，可以发现它不仅是一个简单的内核模糊测试工具，更是一种系统化、闭环化的内核安全研究框架。它通过精心设计的 syzlang 描述系统调用接口，并结合覆盖率驱动（KCOV）和内存检测（KASAN/KCOV/UBSAN）形成反馈闭环，使模糊测试从随机尝试升级为“智能探索”。这种探索不仅依赖于单个测试用例的执行，更依赖于对整个内核状态空间的动态感知与迭代优化，体现了“测试用例驱动漏洞发现”的思想。

总的来说，Syzkaller 的力量不仅在于它发现漏洞的能力，更在于它提供了一种“理解内核、建模内核接口、用数据驱动探索”的研究范式。这种方法论对任何从事内核安全研究的开发者而言，都具有深远的启发意义：它强调自动化、反馈驱动和系统化设计，让 Fuzzing 不再是盲目的尝试，而是有策略、有方向的漏洞探索。

## Reference

> [文章 - linux下fuzz初试 - 先知社区](https://xz.aliyun.com/news/2394)  
> [Syzkaller入门知识总结 - FreeBuf网络安全行业门户](https://www.freebuf.com/sectool/323886.html)  
>  [syzkaller fuzz 工具的使用方法及实践实例 | blingbling's blog](https://blingblingxuanxuan.github.io/2019/10/26/syzkaller/#x86-64-linux%E8%99%9A%E6%8B%9F%E6%9C%BA)  
>  [syzkaller 环境搭建 | Kiprey's Blog](https://kiprey.github.io/2021/11/syzkaller_1/#1-%E5%B0%86%E6%BC%8F%E6%B4%9E%E9%A9%B1%E5%8A%A8%E7%BC%96%E8%AF%91%E8%BF%9B-kernel)
