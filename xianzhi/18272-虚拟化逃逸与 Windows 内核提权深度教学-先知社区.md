# 虚拟化逃逸与 Windows 内核提权深度教学-先知社区

> **来源**: https://xz.aliyun.com/news/18272  
> **文章ID**: 18272

---

## 感受

来到山石网科研究院也有几个月了,院长和几位大手子大师傅的陪伴让我受益匪浅,感谢他们的培养,除了研究了windows的dll劫持以及数个深度学习的大模型,也给AWD线下决赛pwn出了个题,此外还有一个安全防御系统1.0被收录了,也算是成果颇丰,接下来还是要加油学习,不能虚度光阴,争取早日成为内核高手.如果后续有很多的人想学习pwn的内容,那么打算做一个长期的视频,pwn的堆栈就不讲了,直接从vm开始.那么还是老样子先是大体概述一下,然后我会将所有的细节放在文章后面,当然本次全部过程包括漏洞如何利用以及利用思路我以视频的形式录制下来了,但是视频文件太大,时间有限,具体细节还是参考文章最后给出的漏洞点,然后慢慢进行测试实现漏洞的复现.(佬们轻点骂)

> 视频后续会放到**线上课程**

## 目录

1. 引言与背景
2. 攻击链总体概述
3. 漏洞一：CVE-2024-22270 — HGFS 未初始化堆数据泄露
4. 漏洞二：CVE-2024-22267 — VBluetooth URB Use-After-Free
5. 漏洞三：CVE-2024-30085 — CLDFLT 堆缓冲区溢出
6. 核心技术点与提权机制详解
7. 串联利用与逃逸示例
8. 环境搭建与复现指南
9. 防护与检测策略
10. 附录：PoC 代码与脚本
11. 虚拟化逃逸与 Windows 内核提权完整过程

## 1. 引言与背景

虚拟化平台尤其是 VMware Workstation/Fusion 长期以来被广泛使用，其安全性也备受关注。客机（Guest）到宿主（Host）攻击一旦成功，攻击者就可突破 VM 沙箱，直接影响宿主机甚至整个物理环境。2024 年，多位研究者在 Pwn2Own 等竞赛中演示了 VMware Workstation/Fusion 中的多重漏洞链：其中包含客机获取宿主执行权限的关键缺陷。例如，根据官方通告，**CVE-2024-22267** 是 VMware 的 vBluetooth 设备中的 Use-After-Free 漏洞，具有“本地管理员权限的攻击者可作为宿主上 VMX 进程执行任意代码”；**CVE-2024-22270** 是 Host-Guest 文件共享（HGFS）功能中的信息泄露漏洞，可导致客机读取到宿主的敏感内存。这些漏洞需要**客机内具有管理员权限**（已被攻陷）才能利用，一旦成功链式利用，攻击者可在宿主系统上获得任意代码执行和提权能力。现代云环境下，这类逃逸攻击非常危险：一旦攻击者在客户机内网中取得特权，即可能突破到宿主并危及同一宿主上其他虚拟机，实现“多客机”级别的破坏。

## 2. 攻击链总体概述

完整攻击链利用了三大漏洞：

1. **信息泄露**（CVE-2024-22270） — 泄露宿主机堆中未初始化数据
2. **VM Escape**（CVE-2024-22267） — 利用虚拟蓝牙 UAF 在 `vmware-vmx` 进程中执行 ROP
3. **内核提权**（CVE-2024-30085） — Cloud Files 驱动堆溢出取得任意写，劫持 Token

* **CVE-2024-22270（HGFS 信息泄露）**：在 Host-Guest 文件共享功能中，由于分配的内存未完全初始化，宿主内存数据被泄露到客机中（信息泄露）。利用此漏洞可在客机中泄露宿主地址空间布局（ASLR 洞）等敏感信息。
* **CVE-2024-22267（VBluetooth Use-After-Free）**：在 VMware 的模拟蓝牙设备中存在 UAF 漏洞，攻击者可借此在宿主上 VMX 进程中执行代码，形成真正的“虚拟化逃逸”通道。通常先利用 HGFS 泄漏得到宿主地址信息，方便后续利用 UAF 实现 ROP 或 Shellcode 执行。
* **CVE-2024-30085（Windows CLDFLT 堆溢出）**：宿主操作系统上的 Windows Cloud Files Mini Filter 驱动 `cldflt.sys` 存在堆缓冲区溢出，攻击者可通过构造特殊的 Reparse Point 触发溢出，从而在内核态获得任意读写能力，最终替换进程的 System 令牌提权为 SYSTEM。

攻击链的逻辑顺序为：客机管理员在虚拟机内首先利用 **HGFS 泄漏** 漏洞获取宿主内存信息（如内核基址、函数地址等）；接着借助 **VBluetooth UAF** 漏洞在宿主上执行代码（通常构造 ROP 或直接加载 shellcode）；最后在宿主系统的 Windows 内核环境中触发 **CLDFLT 堆溢出** 进行提权，将当前进程（可能是驻留在宿主的恶意服务或伪造的 Windows 服务）提升至 SYSTEM 权限，从而完全控制宿主系统。在 Pwn2Own 2024 中，Theori 团队和 STAR Labs 等已实验证明了这一整条链路。

## 3. 漏洞一：CVE-2024-22270 — HGFS 未初始化堆数据泄露

### 3.1 漏洞成因与代码剖析

```
int hgfs_fileread(request *req) {
    size_t data_size = (req->version == 1) ? 0x29 : 
                       (req->version == 2 ? 0x51 : 0);
    char *resp = malloc(data_size + 0x18);
    // 仅初始化前 0x18+data_size 字节
    // 剩余部分含有堆残留
    return send_response(resp, data_size + 0x18);
}
```

* `malloc` 未清零，新分配堆空间包含旧数据残留；
* HGFS v1 响应只写入有效数据，未初始化部分返回给 Guest。

### 3.2 利用前准备

* 在 Guest 安装 `open-vm-tools`，启用 HGFS 和 VMCI：

```
sudo apt install open-vm-tools open-vm-tools-desktop
sudo modprobe vmci
```

* 虚拟机 `.vmx` 配置：

```
vmci0.present = "TRUE"
isolation.tools.hgfsServerSet.enable = "TRUE"
```

### 3.3 利用代码（PoC）

```
#include <stdint.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>
...
sock = socket(AF_VSOCK, SOCK_STREAM, 0);
addr.svm_cid = VMADDR_CID_HOST; addr.svm_port = 9025;
connect(sock, (struct sockaddr*)&addr, sizeof(addr));
build_hgfs_v1_request(buffer);
send(sock, buffer, req_len, 0);
int len = recv(sock, buffer, buf_size, 0);
// 打印 buffer 中多余字节
```

### 3.4 泄露数据分析

* 搜索 0xfffff8... 等指针模式；
* 识别 PE header（MZ）或 ASCII 文件路径；
* 利用泄露地址计算 `vmware-vmx` 基址。

## 4. 漏洞二：CVE-2024-22267 — VBluetooth URB Use-After-Free

### 4.1 漏洞原理

```
node = AllocNode(pool->node_len);
memcpy(&node->pUrb, &urb, node_len-8);
// 未调用增计数
...
free_node(curr_node);
Poll_Callback(..., VUsbCompleteUrb, urb);
```

* `SubmitURB` 中复制 URB 指针未增引用计数；
* `HandleURBs` 释放节点后异步回调，使用已释放的 URB。

### 4.2 利用步骤

1. Guest 发送 URB(data) — 入队并注册回调
2. 发送 URB(reset) — 调用 `PutURB` 释放所有 URB
3. Poll 回调触发 UAF；
4. 通过控制 URB 结构中的虚表指针实现间接调用。

### 4.3 绕过 CFG 技巧

* 寻找符合 CFG 要求的 ROP gadget；
* 将客机物理内存页映射到 VMX 数据段中，控制回调地址。

### 4.4 PoC 要点

* 构造 URB packet 并发送至 VMCI `/dev/vsock` 端口对应 USB 控制器；
* 调用脚本同步两个 URB。

## 5. 漏洞三：CVE-2024-30085 — CLDFLT 堆缓冲区溢出

### 5.1 驱动源码与漏洞定位

```
if (elem4_length - 1 <= 0xFFF) { ... }
else {
    buf = ExAllocatePoolWithTag(PagedPool, 0x1000, ...);
    memmove(buf, elem4_buffer, elem4_length);
}
```

* 当 `elem4_length == 0x1001`，分配 0x1000，复制 0x1001 → 堆溢出。

### 5.2 构造 ReparsePoint 数据

* 通过 `FSCTL_GET_REPARSE_POINT` 控制码发送大 buffer；
* 伪造两次溢出：第一次破坏 `_WNF_STATE_DATA` 泄露地址；第二次控制管道对象实现任意写。

### 5.3 任意写原语

* 修改 `_WNF_STATE_DATA::Data` 和 `Length` 字段；
* 得到读写原语。

### 5.4 Token 劫持与 SYSTEM 权限

```
// 利用任意写
write64(currentEPROCESS+TokenOffset, systemToken);
```

* 将 winlogon 的 Token 覆盖当前进程；
* 获取 SYSTEM。

## 6. 核心技术点与提权机制详解

### 6.1 EPROCESS 结构

* `EPROCESS.Token` 偏移；
* `KTHREAD` 与 `ETHREAD` 权限检查。

### 6.2 PagedPool 分配

* 大小为 0x1000 的分页池块；
* Free List 与 PoolSpray。

### 6.3 WNF & Mailslot 对象

* WNF subscription table 布局；
* Mailslot 用于喷洒稳定对象。

## 7. 串联利用与逃逸示例

```
HGFS 泄露 → ROP 逃逸 → CLDFLT 提权 → SYSTEM
放在后面说
```

## 8. 环境搭建与复现指南

1. VMware Tools & VMCI 设置
2. 编译 PoC 并运行
3. 调试：Windbg 附加 vmware-vmx
4. 数据分析脚本。

## 9. 防护与检测策略

* 打补丁，禁用 HGFS、VMCI
* 启用 HVCI、CFG
* IDS/EDR 监测异常 VMCI、HGFS 请求

## 10. 附录：PoC 源码与脚本

* `Windows_VM_Escape_Full_Report`
* `Comprehensive_VM_Escape_Report`
* `Detailed_VM_Escape_Report`
* `cve_2024_22270_poc.c`
* `check_vsorkserve.sh`
* `check_vmtools.ps1`
* `check_vmci_all.sh`
* `fakefile`

脚本中每个环节均添加注释,里面有一些东西需要本地测试并无具体poc,可以通过windbg自行调试,此外ubuntu一定选择linux,因为此漏洞是linux有关,而且版本号必须符合,打了补丁的注意重装软件,端口号不通的原因有可能是ubuntu的原因,复现过程若ubuntu别的版本都不行,建议使用ubuntu24.04,去官网下载iso配置vmx.

## 虚拟化逃逸与 Windows 内核提权完整过程

## 漏洞分析：CVE-2024-22270 (HGFS 信息泄露)

**CVE-2024-22270** 影响 VMware Workstation/Fusion 的 Host-Guest 文件共享（HGFS）功能。这个漏洞的根本原因是 **堆内存未初始化**。在处理文件共享请求时，宿主进程（VMX）会为返回给客机的数据分配一个缓冲区（通过 `_malloc` 或 `malloc`），但并没有对分配到的整个缓冲区进行填充。在某些分支下，只有部分字段被赋值，其余字节保持“老数据”状态，包含了宿主内核或用户空间的残留信息。例如，从黑客演示可知，在调用 `hgfs_fileread()` 函数时，代码中有 `resp = _malloc(data_size + 0x18)` 但没有清零，对 `resp` 的字段只按需赋值，导致分配区间内字节泄露以前分配的内存内容。这意味着客机管理员可以通过标准的 HGFS 文件读操作，将这些未初始化的内存内容读出，从而“窥视”到宿主的内核堆内容。官方通报也指出：攻击者可以“读取宿主中超级用户级别的信息”。PoC 利用过程为：在虚拟机中开启共享文件夹并放置特制文件，利用普通读写函数触发上述代码路径，然后从返回的数据中提取可用于绕过内核地址随机化（KASLR）的指针。这样，攻击者就获得了宿主内核地址信息，为后续的攻击链提供了重要先决条件。

## 漏洞分析：CVE-2024-22267 (VBluetooth Use-After-Free)

**CVE-2024-22267** 是 VMware 中 vBluetooth 设备的一个严重 Use-After-Free 漏洞。该漏洞允许客机管理员在宿主上执行任意代码，前提是已经获得宿主的地址信息。官方说明：攻击者可“在宿主上作为虚拟机的 VMX 进程执行代码”。漏洞原因是 vBluetooth 设备驱动在处理 USB 请求包（URB）时的释放逻辑不当：当 URB 被重复释放或使用后，仍可能被后续使用，从而攻击者可以控制释放后重新分配回该内存区域的过程。利用此漏洞常见手段是构造精心的 USB 请求，触发 Use-After-Free；然后通过 **ROP（返回导向编程）** 或直接Shellcode，在宿主的 VMX 进程上下文中执行恶意代码。通过 HGFS 泄露的地址信息可用于定位有效的可利用代码段和数据地址，例如 KernelBase 或特定函数地址，确保 ROP 链或 shellcode 能正确运行。一旦执行完毕，攻击者就能在宿主上拥有执行权限，接着便可触发 Windows 系统内的下一个漏洞（CLDFLT）继续提权。可用来源指出：如果这一漏洞被利用成功，将作为 VMX 进程执行（宿主上具有特权的进程）。

## 漏洞分析：CVE-2024-30085 (Windows CLDFLT 堆溢出)

**CVE-2024-30085** 是宿主系统（Windows 11 23H2 及以上）的 **Cloud Files Mini Filter Driver** (`cldflt.sys`) 中的堆溢出漏洞。该驱动用于管理云文件占位符（Placeholder）和重解析点（Reparse Point）。漏洞发生在 `HsmIBitmapNORMALOpen` 函数中：驱动会为一个大小固定（0x1000 字节）的 `HsBm` 对象分配缓冲区，并将重解析点数据复制进去。然而代码中对于复制长度 `elem4_length` 的校验逻辑有缺陷：只有在满足某些条件时才检查长度是否超过 0x1000，而攻击者可以通过设置重解析点数据中特定元素（element0）使得校验分支被跳过。未修补的代码示例（逆向后）为：

```
if (elem4_buffer && elem4_length - 1 <= 0xFFE) { … }
else {
    Dst = ExAllocatePoolWithTag(PagedPool, 0x1000, ...);
    if (Dst) {
        memmove(Dst, elem4_buffer, elem4_length); // 如果 elem4_length > 0x1000 则发生溢出
        …
    }
}
```

而前置函数 `HsmpBitmapIsReparseBufferSupported` 在 `elem2[0] == 0` 时不会对 `elem4_length` 做限制检查，导致当设置 `elem0_type=0`（跳过校验）后，`elem4_length` 即可任意大。这就造成了 **向 0x1000 大小的堆内存拷贝超长数据** 的漏洞，发生堆溢出。通过构造精确控制的重解析点数据（包含多个 `HSM_ELEMENT_INFO` 结构），攻击者就可以利用这一溢出写入宿主内核堆数据。引用资料指出，一旦触发，攻击者可将目标结构溢出至相邻对象，例如 **WNF 状态数据** 或管道属性对象，从而获得随后的读写原语。

PoC 流程大致为：在宿主创建一个文件并用 `IO_REPARSE_TAG_CLOUD_6` 标记（调用 `FSCTL_SET_REPARSE_POINT`），重解析数据包含恶意 `elem4_length`，第一轮触发堆溢出后可获得一次 8 字节的 OOB 读写；随后的第二次溢出则可利用 **WNF****STATE****DATA** 对象和 **管道属性（PipeAttribute）** 对象技术实现任意读写。最终通过上述任意写改写进程的令牌指针（Token）来提升权限至 SYSTEM。

## 技术细节讲解

* **EPROCESS 结构与 Token 劫持**：Windows 内核使用 `_EPROCESS` 结构描述每个进程，其中包含一个指向 `_TOKEN` 的指针。每个进程拥有自己的安全令牌（Token），用于定义权限和用户身份。在提权利用中，常见手法是获取低权限进程和 SYSTEM 进程的令牌地址，随后将低权令牌替换为高权令牌。具体来说，攻击者在内核态找到当前进程对应的 `_EPROCESS`，修改其 `Token` 字段，使其指向 SYSTEM 进程的 `_TOKEN`。这样一来，被劫持进程就拥有了系统级权限。本链路中，溢出利用最终也是定位并修改目标进程的 `EPROCESS->Token`，获得 SYSTEM 权限。
* **WNF/Mailslot 对象喷射**：为了实现可控的堆布局，漏洞利用常采用内核对象喷射技术。在此利用中使用了 **WNF（Windows Notification Facility）** 对象作为喷射目标。`_WNF_STATE_DATA` 对象位于分页池，大小可达 0x1000 字节。利用原理为：调用 `NtCreateWnfStateName` 并不断 `NtUpdateWnfStateData` 分配大量 `WNF_STATE_DATA` 对象，形成连续的堆块（见图1）。然后释放其中的交替对象，在内存中留下“洞”。当触发漏洞时，分配的目标对象会落入这些洞中，并溢出到邻近的 WNF 对象，从而实现对 WNF 对象头部（如 `DataSize` 字段）的越界写入或读出。利用修改后的 WNF 对象可以进行 **OOB 读写**，用来泄露内核指针（比如通过 ALPC 表或其他对象）或进行进一步的内存篡改。旧技术中也曾使用过 **Mailslot** 对象进行喷射，即利用过载的 Mailslot 结构来分配可控大小的堆对象。本攻击链中主要使用 WNF，因为其尺寸固定且易于管理。上文引用的研究中详细演示了 WNF 对象喷射的过程（见）。
* **PagedPool 管理**：Windows 内核中的分页池（Paged Pool）是分配可换出的内存区域，许多驱动对象都从中分配。在 CLDFLT 漏洞中，`ExAllocatePoolWithTag(PagedPool, 0x1000, ...)` 分配出的堆块承载了可溢出的 `HsBm` 对象。同时，WNFStateData 和 ALPC 句柄表等对象也位于分页池。这要求攻击者对分页池的分配策略、块大小对齐以及空闲链有一定了解，以便精确定位和控制不同对象之间的相对位置。通过大量喷射已知大小（0x1000）的对象，并交替释放，可以形成可预测的池布局，为溢出后的读写提供稳定基础。
* **ROP（返回导向编程）**：在 VB蓝牙漏洞中，利用者可在宿主 VMX 进程上下文执行代码。由于现代 Windows 内核启用了一些安全防护（如 SMEP/SMAP），直接执行 shellcode 可能受限，所以通常需要构造 ROP 链。ROP 通过串联内核已有的返回指令序列（gadgets），绕过禁用执行位或直接修改控制流。利用 HGFS 泄露的信息常被用来定位这些 gadget 和模块基址，从而创建稳定的 ROP 链达到任意代码执行的目的。虽然本技术方案中重点在 CLDFLT 利用链上，对 ROP 这里不展开细节，但在 VB漏洞利用上可能会用到该技术。

## 漏洞利用串联流程

完整攻击流程如下图所示：首先在虚拟机内建立大量 WNFSTATEDATA 对象，形成堆布局（见图1）；随后释放交替的对象，留下空洞（图2）。然后在宿主上触发 CLDFLT 漏洞时，目标对象被分配到空洞并溢出到相邻的 WNF 对象，实现对其头部的溢写（图3）。释放目标对象后，堆布局如图4所示。通过对第一个损坏的 WNF 对象的 OOB 读，我们可读取相邻 ALPC 或其他对象中的内核指针，完成地址泄露。然后第二次触发溢出并借助第二个 WNF 对象进一步操控一个 **PipeAttribute** 对象，将其指向用户态伪造的结构，获得任意读。最终，利用任意写原语定位并改写当前进程的 Token 字段，将其替换为 SYSTEM 进程的 Token，实现权限提升。如下时序流程图（简要示意）总结了各阶段的关系：

1. **HGFS 泄漏阶段**：客机读写共享文件，触发 HGFS 未初始化内存读出，获得宿主内核地址布局。
2. **VB 漏洞阶段**：构造特定蓝牙请求，触发 UAF，在宿主 VMX 进程中执行 ROP，获取内核读写能力。
3. **内核提权阶段**：在宿主环境下创建并触发特制的 CLDFLT Reparse Point，两次触发溢出并结合 WNF 对象喷射实现 Arbitrary RW，最后劫持 EPROCESS->Token 提权。

> *流程图：虚拟机客机（Guest）→VMware Hypervisor→宿主 Windows 内核（Host）中的攻击流程（流程从 HGFS 泄漏到内核提权）。*

## 环境搭建与复现指南

* **虚拟机配置 (.vmx)**：使用 VMware Workstation 17.0.x（或 Fusion 13.x），在虚拟机设置中确保 **共享文件夹（Shared Folders/HGFS）功能开启**。在 `.vmx` 配置文件中可设置如 `sharedFolder0.present = "TRUE"`、`guestOS = "windows9-64"` 等参数。为了触发 VB 漏洞，需要在 VM 上启用蓝牙支持（可通过 USB 适配器或指定虚拟蓝牙设备）。3D 加速可关闭（本链路不涉及 3D 漏洞）。建议虚拟机使用 NTFS 或 exFAT 分区作为共享盘符，以免影响 HGFS 驱动功能。
* **模块加载**：宿主系统使用 Windows 11 23H2，确保 **Cloud Files 驱动（cldflt.sys）已经加载**，并且文件资源管理器处于普通模式。同时，要在宿主启用 WinDbg 调试等内核调试环境时，可加载相应的符号文件（`.pdb`）以分析结构。对于内存泄露，可在虚拟机内使用调试工具（如 x64dbg）监测返回数据。
* **PoC 编译命令**：

* **HGFS 漏洞利用**：可在客机 Windows 上使用 Visual Studio 编译，示例命令：`cl hgfs_leak_poc.cpp /O2 /EHsc`。PoC 会通过调用 HGFS API（如 `VMHGFS_GetFileInfo`）来触发泄漏。
* **VB 漏洞利用**：通常通过在客机上发起特制的 USB/蓝牙 URB 请求。需编写 VMware Tools 交互代码或使用内核驱动来构造 USB 包，可用 VS 编译：`cl vbluetooth_exploit.cpp /O2 /EHsc`。
* **CLDFLT 漏洞利用**：在宿主 Windows 上编写本地程序（需以管理员或 SYSTEM 权限执行）触发重解析点。示例编译命令：`cl cldflt_exploit.cpp /O2 /EHsc /link advapi32.lib`。此程序会调用 `CreateFile` + `SetFileSecurity` + `DeviceIoControl` 等 Win32 API 来创建 Reparse Point 并设置恶意数据块。

* **调试与检测**：在宿主使用 WinDbg 内核调试时，可附加到 VMX 进程或内核进行动态分析：

* 使用 `!process 0 0` 列出进程并确认 VMX 进程（一般 PID 可在 VMware 服务中找到），再使用 `!process <地址> 1f` 查看其上下文。
* 对于 CLDFLT 利用，可在 WinDbg 中执行 `!uniqstack`、`!pool` 等命令跟踪分页池的分配；使用 `!object` 检查 WNF 对象或通过 `!token` 验证当前进程权限是否为 SYSTEM。
* 可编写脚本自动监控虚拟机通信：如监听 Vsock/HGFS 通道中的异常数据包，或在宿主运行 WMI 脚本检查 `cldflt.sys` 版本、已加载状态等。

## 防护建议与检测策略

* **禁用或更新**：强烈建议关闭不必要的功能。针对 CVE-2024-22270，可考虑**禁用 HGFS 共享文件夹**（在虚拟机设置中移除共享），因为官方指出该漏洞没有其他缓解手段。针对 CVE-2024-22267，可在暂时不需要时**关闭虚拟蓝牙设备**或断开 USB 蓝牙适配器。Windows 端及时安装补丁，更新到 VMware Workstation 17.5.2+ 与 Fusion 13.5.2+ 版本。
* **启用安全特性**：在宿主 Windows 上启用内核 **CFG/HVCI**（控制流保护/Hypervisor 强制代码完整性）可以限制 ROP 和内核注入攻击。HVCI 通过由硬件辅助验证代码安全性，令内核可执行页面受到更强保护。SGX、SECCOMP 等并不适用于 Windows，但 HVCI 可大幅增加打击难度。
* **监控检测**：部署入侵检测机制时，可重点监控虚拟机与宿主间的异常通信。比如禁用或记录 Vsock/HGFS 的非标准读写。可使用 VMware 内部日志或 SIEM 系统监测 `vmware-hostd` 服务的异常活动。宿主上，可监控 `cldflt.sys`（Cloud Files Filter）相关的可疑注册表项或驱动更新操作。利用行为检测（EDR）时，应关注下列指标：频繁调用 `NtSetEaFile`/`NtFsControlFile` 产生的重解析点操作；异常的 `NtCreateWnfStateName` 或 `NtUpdateWnfStateData` 调用序列；以及进程令牌突然提升为 SYSTEM 的可疑事件。一旦检测到类似攻击特征，应立即隔离虚拟机并更新补丁。

## 附录：关键 PoC 源码与脚本

* **HGFS 泄漏 PoC (客机)**：使用 VMware Host-Guest API 读取共享文件。示例代码可调用 `VMHGFS_OpenHandle`, `VMHGFS_Read`，并打印返回的未初始化数据（包括内核指针）。
* **VB 漏洞 PoC (客机)**：模拟 USB/蓝牙设备发送特制 URB。可以使用 `WinUSB` 或原始 `IOCTL` 接口，通过 `HID` 类设备来触发 vBluetooth UAF。
* **CLDFLT 漏洞 PoC (宿主)**：参考 STAR Labs 提供的示例。核心思路是创建文件并 `DeviceIoControl` 调用 `FSCTL_SET_REPARSE_POINT`：

```
HANDLE hFile = CreateFile(path, ...);
REPARSE_DATA_BUFFER rdb = {0};
rdb.ReparseTag = IO_REPARSE_TAG_CLOUD_6;
// 填充 rdb 中的 HSM_ELEMENT_INFO，设置 element0=0，element4 长度>0x1000
rdb.HsmData.Length = sizeof(rdb.HsmData) + element0.Length + ...;
DeviceIoControl(hFile, FSCTL_SET_REPARSE_POINT, &rdb, ...);
```

使用大量 `NtCreateWnfStateName/Update` 进行 WNF 喷射以配合利用。PoC 在成功后会弹出 SYSTEM 权限的 cmd 窗口。完整源码及注释可参考 STAR Labs 仓库。

* **检测脚本**：可编写 PowerShell 或 C 脚本监测内核对象异常。比如用 `ZwOpenKey`+`ZwQueryKey` 访问 WNF 状态名称注册表项以确认是否存在异常大对象，或调用 `NtQuerySystemInformation` 检测分页池异常分配。

## 附件

[Windows 内核提权攻击在Vmware上的全链漏洞利用.zip](https://xzfile.aliyuncs.com/2025/06/23/0752/ZKqp0bciT8wxx8CLgYqD0zKVjSshLH98oIYpP5vsyaGARHhbZJRS7QZjRtGjnsHv.zip)
