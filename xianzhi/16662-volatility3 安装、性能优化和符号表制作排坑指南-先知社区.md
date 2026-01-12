# volatility3 安装、性能优化和符号表制作排坑指南-先知社区

> **来源**: https://xz.aliyun.com/news/16662  
> **文章ID**: 16662

---

# volatility 3

## 前言

​ volatility2 Github 仓库的[最后一次提交](https://github.com/volatilityfoundation/volatility/commit/a438e768194a9e05eb4d9ee9338b881c0fa25937)已经是五年前（**Dec 11, 2020**）。2019 年，Volatility Foundation 发布了框架的重写版，Volatility 3。该项目旨在解决与原始代码库相关的许多技术和性能挑战，这些问题在过去 10 年中逐渐显现。

​

​ 虽然 volatility2 已经停止维护了，但还有很多用户仍在继续使用。原因之一是早期的 volatility3 插件较少，很多 volatility2 上的功能还没有重写完成，不过现在 volatility3 的插件也逐渐丰富了起来。另一个原因可能是大多数用户已经习惯了 volatility2，对 volatility3 并不熟悉，且 volatility3 并没有非常非常耀眼的功能。

​

​ 在我这段时间的体验过程中，最明显的感觉是 volatility3 的性能有非常显著的提升，扫描速度加快了。volatility3 抛弃了构建起来较为复杂的 profile，转而使用符号表。volatility3 提供的 Windows 符号表非常全面，MacOS 的符号表也在逐步增加，Linux 版本很多很杂，并没有提供非常全面的符号表，不过自行构建符号表非常简单。

​

​ 这篇文章教学在 Windows 和 Linux 下安装 volatility3（稳定版 / 开发版），介绍 volatility3 的基础使用，以及通过 --save-config 来重用我们扫描的内容，以到达加速扫描的目的，最后使用 dwarf2json 构建 Linux 符号表。

## 安装

### Ubuntu 24.04

Volatility 3 需要 Python 3.8.0 或更高版本。

```
apt-get update
apt -y install python3.12 python3.12-venv
```

​

建议**使用虚拟环境**以将已安装的依赖项与系统包分开。

```
# 创建 Python 虚拟环境
python3 -m venv venv
```

注：如果默认不存在 **python、python3**，可以使用 `python3.12 -m venv venv`。

**​**

**（方法一）**Volatility 3 在 [PyPi registry](https://pypi.org/project/volatility3/) 中发布，直接安装。

```
source ./venv/bin/activate
pip install volatility3
```

**​**

**（方法二）**如果想安装 Volatility 3 的最新开发版本，需要克隆 Volatility 3 Github 仓库项目。

**最新稳定版本仓库的 stable 分支。默认分支是 develop 。**

**​**

克隆 Github 仓库

```
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3/
```

​

切换到指定的版本

```
# 切换到 develop （默认）
git checkout develop

# 切换到 stable 分支
git checkout stable

# 切换到特定版本
git checkout v2.11.0
```

​

`git tag` 输出的标签信息，**按照字符串排序**，**此处最新稳定版本为 v2.11.0**。

![image.png](images/bb2f8217-4d07-3296-9a1c-925357fa91c3)

​

使用 Python3 虚拟环境，并安装 Volatility 3。

```
python3 -m venv venv
source ./venv/bin/activate
pip install -e .[dev]
```

​

验证效果

```
(venv) root@c6ea20950124:/opt/volatility3# vol -h | head -n 5
Volatility 3 Framework 2.11.0
usage: volatility [-h] [-c CONFIG] [--parallelism [{processes,threads,off}]]
                  [-e EXTEND] [-p PLUGIN_DIRS] [-s SYMBOL_DIRS] [-v] [-l LOG]
                  [-o OUTPUT_DIR] [-q] [-r RENDERER] [-f FILE]
                  [--write-config] [--save-config SAVE_CONFIG] [--clear-cache]
```

### Windows 10

下载 **Python 3.12.7** Windows embeddable package (**64-bit**)，自行合适的 CPU 架构。

下载链接：[Python Release Python 3.12.7 | Python.org](https://www.python.org/downloads/release/python-3127/)（**网页最下面**）

![image.png](images/13fdb9dd-91e5-3b2a-9f1e-00cbfc558016)

​

解压为文件夹，并添加到环境变量。

![1737709426506.jpg](images/3e7197f2-e58d-312b-baf6-0abf79913413)

![1737709442452.jpg](images/8a947b39-ba3c-3e65-b012-a93075f5c2f8)

​

下载 **get-pip.py** 脚本，并安装。

下载链接：<https://bootstrap.pypa.io/pip/get-pip.py>

![1737709453595.jpg](images/99b626be-9b45-33b0-a36f-786ee90a1b79)

​

修改 **Python** 安装路径中的 **python39.\_pth** 文件，添加 **Lib\site-packages** 。

![1737709480226.jpg](images/4f750080-b3f6-3b97-bf9b-f4535ac9daec)

​

将 **D:\python-3.12.7\Scripts** 添加到环境变量中（需要重新打开 cmd，否则环境变量不会生效）。

![1737709492059.jpg](images/a4d55d35-2986-3294-8a01-8a4293739be7)

​

克隆 volatility 3 仓库

```
git clone https://github.com/volatilityfoundation/volatility3.git
cd .\volatility3
```

​

创建虚拟环境

```
pip install virtualenv
virtualenv venv
.\venv\Scripts\activate.bat
```

​

安装 volatility 3

```
cd .\volatility3
pip install -e .[dev]
```

​

验证

![1737709511190.jpg](images/33ad5195-d646-3ff0-bb3e-4c0da355504b)

## 基础选项

```
volatility [-h] [-c CONFIG] [–parallelism [{processes,threads,off}]]
        [-e EXTEND] [-p PLUGIN_DIRS] [-s SYMBOL_DIRS] [-v] [-l LOG] [-o OUTPUT_DIR] [-q]
        [-r RENDERER] [-f FILE] [–write-config] [–save-config SAVE_CONFIG] [–clear-cache]
        [–cache-path CACHE_PATH] [–offline] [–single-location SINGLE_LOCATION]
        [–stackers [STACKERS …]] [–single-swap-locations SINGLE_SWAP_LOCATIONS]
        <plugin> …
```

​

-h, --help

​ 显示帮助信息，列出选项以及可用的插件。如果在插件之后使用 **( vol windows.info -h )**，则**显示指定插件的帮助信息**。

​

--parallelism [{processes,threads,off}]

​ 启用并行处理（如果没有提供参数，默认为不启用）。并行处理可以是**关闭状态**、**多线程**（但由于 Python 的全局解释器锁（GIL），仍然只占用一个 CPU）、**多进程**（这会生成其他进程，可以使用整个 CPU）。目前**并行处理效果不显著**，仍在开发中。

​ **注：我测试启用并行处理后，没有感觉到速度有提升，有时还会出现 bug。**

​

-p PLUGIN\_DIRS, --plugin-dirs PLUGIN\_DIRS

​ 指定一个以分号分隔的路径列表，其中包含可能找到插件的目录。在**加载内置插件之前，会先搜索这些路径。因此，可以用来覆盖内置插件。**

​

-s SYMBOL\_DIRS, --symbol-dirs SYMBOL\_DIRS

​ SYMBOL\_DIRS 是一个分号分隔的路径列表，包含符号文件或符号 zip 包。符号文件必须根据**它们所属的操作系统，放在特定的目录结构中。**

​

--single-location SINGLE\_LOCATION

​ 指定一个 URL，如果需要，将会从远程进行下载。

​

-f FILE, --file FILE

​ 接受一个文件路径，并将其格式化为 file:// URL，然后用作 --single-location 字段的值。

​ 简单来说，`-f FILE` 是将本地文件路径转换为 `file://` URL 后再提供给 `--single-location` 使用，而 `--single-location` 可以直接接受一个远程或本地的 URL。

​

--save-config SAVE\_CONFIG

​ 将配置以 JSON 格式保存到文件。此配置可能被其他插件接受，但无法保证插件使用相同的配置选项。

​

-c CONFIG, --config CONFIG

​ 从文件加载 JSON 格式的配置。

**​**

**-c 和 --save-config 一般结合一起使用，后续会详细的介绍。**

​

--clear-cache

​ 清除所有短期缓存项。

​

--cache-path

​ 修改用于存储缓存的默认路径。

​

--offline

​ 不要在网上搜索额外的 JSON 文件、Windows 符号表等。以离线离线模式（默认为 false）运行。

​ **下面会详细讨论符号表。**

​

`<plugin>`

​ 指定要执行的插件名称。这些插件通常按照操作系统分类，例如 **windows.pslist linux.pslist** 。

## 覆盖选项

命令行界面**部分参数的默认值，在源代码中由常量定义的**，但可以通过创建一个 JSON 格式的文件来覆盖这些默认值。

* Windows 系统中路径为： `%APPDATA%/volatility3/vol.json`
* 其他系统中路径为： `~/.config/volatility3/vol.json` 或 `volshell.json`

​

请注意，顺序是（< 表示被覆盖）：

*内置默认值 < 配置文件值 < 命令行指定配置文件 < 命令行参数*

## 提升扫描速度

正常情况下对对内存转储文件进行扫描，经过了以下几个步骤。

**vol3 -f memdump.mem windows.info**

```
Scanning FileLayer using PageMapScanner
Stacking attempts finished
Scanning memory_layer using BytesScanner
Scanning layer_name using PdbSignatureScanner
PDB scanning finished
```

**​**

**vol3 --save-config config.json -f memdump.mem windows.info**

通过 **--save-config config.json** 参数，可以将配置**以 JSON 格式保存到当前路径的 config.json 文件**中。

```
vol3 --save-config config.json -f memdump.mem windows.info 

Volatility 3 Framework 2.16.0
Progress:  100.00		PDB scanning finished                        
Variable	Value

Kernel Base	0xf800ca419000
DTB	0x1ad000
...
```

​

查看 config.json 配置文件的内容。

```
{
  "kernel.class": "volatility3.framework.contexts.Module",
  "kernel.layer_name.class": "volatility3.framework.layers.intel.WindowsIntel32e",
  "kernel.layer_name.kernel_virtual_offset": 272682276982784,
  "kernel.layer_name.memory_layer.class": "volatility3.framework.layers.physical.FileLayer",
  "kernel.layer_name.memory_layer.location": "file:///xxx/memdump.mem",
  "kernel.layer_name.page_map_offset": 1757184,
  "kernel.layer_name.swap_layers": true,
  "kernel.layer_name.swap_layers.number_of_elements": 0,
  "kernel.offset": 272682276982784,
  "kernel.symbol_table_name.class": "volatility3.framework.symbols.windows.WindowsKernelIntermedSymbols",
  "kernel.symbol_table_name.isf_url": "file:///xxx/volatility3/framework/symbols/windows/ntkrnlmp.pdb/1E158A6041094205BE17F93E54DD5E51-1.json.xz",
  "kernel.symbol_table_name.symbol_mask": 0
}
```

配置文件中保存了一些信息：

* **kernel.layer\_name.memory\_layer.location**：这里**路径为 -f 指定的内存转储文件的路径**。
* **kernel.symbol\_table\_name.isf\_url**：符号文件URL
* **kernel.offset**：偏移量

​

使用 -c 指定 config.json 配置文件再次进行扫描，没有进行扫描操作，直接显示完成。

**vol3 -c config.json windows.info**

注意：**config.json 中已经指定了内存转储文件的位置**，此处无需再通过 -f 进行指定。

```
Reconstruction finished
PDB scanning finished
```

**​**

**对比两个的速度（简单的对比）**

```
root@xiaoshae:~# time vol3 -f memdump.mem windows.info 
Volatility 3 Framework 2.16.0
Progress:  100.00		PDB scanning finished                     

real	0m11.270s
user	0m1.892s
sys	0m1.823s


root@xiaoshae:~# time vol3 -c config.json windows.info 
Volatility 3 Framework 2.16.0
Progress:  100.00		PDB scanning finished  

real	0m0.971s
user	0m0.778s
sys	0m0.190s
```

### 深入探讨

在使用 **windows.pslist 插件使用 --pid 参数指定 pid**，并将配置写入 config.json 文件中。

**vol3 --save-config config.json -f memdump.mem windows.pslist --pid 4400 2416 3316**

```
Volatility 3 Framework 2.18.0
Progress:  100.00		PDB scanning finished  
PID	PPID	ImageFileName	Offset(V)	Threads	Handles	SessionId	Wow64	CreateTime	ExitTime	File output

4400	804	svchost.exe	0xc20c6c766080	4	-	0	False	2018-08-01 19:20:56.000000 UTC	N/A	Disabled
3316	6028	SearchFilterHo	0xc20c6c82a580	5	-	0	False	2018-08-06 18:12:26.000000 UTC	N/A	Disabled
2416	4096		0xc20c6d756580	1157079040	-	1	True	2018-08-06 18:12:13.000000 UTC	1601-01-01 00:03:18.000000 UTC	Disabled
```

​

此时 config.json 配置文件存在 --pid 参数的配置。

```
{
  "dump": false,
  "kernel.class": "volatility3.framework.contexts.Module",
  "kernel.layer_name.class": "volatility3.framework.layers.intel.WindowsIntel32e",
  "kernel.layer_name.kernel_virtual_offset": 272682276982784,
  "kernel.layer_name.memory_layer.class": "volatility3.framework.layers.physical.FileLayer",
  "kernel.layer_name.memory_layer.location": "file:///xxx/memdump.mem",
  "kernel.layer_name.page_map_offset": 1757184,
  "kernel.layer_name.swap_layers": true,
  "kernel.layer_name.swap_layers.number_of_elements": 0,
  "kernel.offset": 272682276982784,
  "kernel.symbol_table_name.class": "volatility3.framework.symbols.windows.WindowsKernelIntermedSymbols",
  "kernel.symbol_table_name.isf_url": "file:///xxx/vol3/lib/python3.12/site-packages/volatility3/symbols/windows/ntkrnlmp.pdb/1E158A6041094205BE17F93E54DD5E51-1.json.xz",
  "kernel.symbol_table_name.symbol_mask": 0,
  "physical": false,
  "pid": [
    4400,
    2416,
    3316
  ]
}
```

​

我在 volatility3 Github 仓库的 issue 上看到这样一个讨论**（注：翻译为AI翻译，可能出现不准确的地方）**。

> 在使用 `--save-config` 时 `plugin parameters` 也会被保存。这是 bug 还是特性？保存它们的用例是什么？
>
> 例如，我们可以运行 `pslist --pid 1` 以快速完成并保存配置。然而，由于插件参数也被保存，后续测试用例运行对于也接受 `--pid` 的插件将继承 `--pid 1` 参数，导致剩余测试用例断言失败。
>
> 保存的插件参数可能在保存时与下次插件重用配置时的类型不同。例如，保存配置的插件可能接受 PID 列表，但重用此配置的插件可能只接受单个 PID（整型），这可能导致由于类型不匹配而出现意外行为或崩溃。

​

> 问题在于 `--save-config` 从未打算用于加快速度（正如 ikelos 在另一张票据中解释的那样），但它也从未被记录下来，所以我们（me、MHL、Dave）认为它是 Vol2 性能选项的替代品。显然，我们需要某种机制来重复使用我们扫描的内容，因为否则插件运行得非常慢。但是默认情况下，你必须小心使用 `--config` 。你可以只运行 windows.info 或 windows.pslist 而不使用 --pid，然后你得到一个与所有内容都兼容但与 mftscan 和 yarascan 不兼容的配置。这就是我一直用于大规模测试的方法。

**​**

**我测试了很多 windows 的插件，没有找到仅支持单个 pid 的插件，这里提出来是为了防止大家以后遇到这个问题。**

**另外一个目的是大家不要将 --save-config 当成”万能药”，在另一个 issua 中有人提出。**

**​**

> 遗憾的是，“修复它”并不是一个真正的选项。我很乐意更清楚地记录它的功能，但我担心如果人们没有自己真正理解它是如何工作的，它可能被当作某种万能药，而不是它实际上是从特定插件重建单个运行状态的一种机制。

​

你也可以尝试在指定 config.json 文件的情况下，使用 windows.psscan 插件，你会发现它依然要等待很久。

​

如果你对这个部分感兴趣，可以围观这两个 issue：

* <https://github.com/volatilityfoundation/volatility3/issues/1505#issue-2765440851>
* <https://github.com/volatilityfoundation/volatility3/issues/1294>

## 符号表

在上面提到了一个选项 --offline，不要在网上搜索额外的 JSON 文件、Windows 符号表等。以离线离线模式（默认为 false）运行。

​

如果你在无网络的环境下运行 volatility3 分析文件，他可能会出现如下错误。

**vol -v -f memdump.mem windows.info**

```
Volatility 3 Framework 2.18.0
INFO     volatility3.cli: Volatility plugins path: ['/opt/volatility3/volatility3/plugins', '/opt/volatility3/volatility3/framework/plugins']
INFO     volatility3.cli: Volatility symbols path: ['/opt/volatility3/volatility3/symbols', '/opt/volatility3/volatility3/framework/symbols']
...
WARNING  volatility3.framework.symbols.windows.pdbutil: Symbol file could not be downloaded from remote server                                                                                                    
INFO     volatility3.framework.symbols.windows.pdbutil: The symbols can be downloaded later using pdbconv.py -p ntkrnlmp.pdb -g 1E158A6041094205BE17F93E54DD5E511
INFO     volatility3.framework.automagic: Running automagic: SymbolFinder                                                                         
INFO     volatility3.framework.automagic: Running automagic: KernelModule

Unsatisfied requirement plugins.Info.kernel.symbol_table_name: 

A symbol table requirement was not fulfilled.  Please verify that:
    The associated translation layer requirement was fulfilled
    You have the correct symbol file for the requirement
    The symbol file is under the correct directory or zip file
    The symbol file is named appropriately or contains the correct banner

Unable to validate the plugin requirements: ['plugins.Info.kernel.symbol_table_name']
```

​

上面的错误信息为**“无法连接到远程服务器”**，此错误不会在 volatility2 中发生，它使用的 profile 包含分析内存镜像所需的信息。而在 volatility3 中使用的是符号表，它会在每次内存分析中自动生成的，**创建符号表时需要从微软网站下载 NT 内核的符号文件**。

​

在上面的提示信息中，使用 **pdbconv.py -p ntkrnlmp.pdb -g 1E158A6041094205BE17F93E54DD5E511** 可以下载所需的文件。**pdbconv.py** 是 **volatility3** 项目中的一个脚本，位于 **volatility3/framework/symbols/windows/pdbconv.py**。

​

使用一台**有网络**且安装了 volatility3 的工具的机器，切换到 **volatility3/framework/symbols/windows/** 目录。

**python3 pdbconv.py -p ntkrnlmp.pdb -g 1E158A6041094205BE17F93E54DD5E511**

在当前工作路径下会生成 **1E158A6041094205BE17F93E54DD5E51-1.json.xz** 文件。

​

将其复制到 **volatility3/volatility3/framework/symbols/windows/ntkrnlmp.pdb/** 路径中（默认可能不存在，需要手动创建）

​

运行命令，再次进行分析，成功。

**vol -v -f memdump.mem windows.info**

```
(vol3) root@xiaoshae:/mnt/data/memory# vol -v -f memdump.mem windows.info
Volatility 3 Framework 2.18.0
INFO     volatility3.cli: Volatility plugins path: ['/opt/volatility3/volatility3/plugins', '/opt/volatility3/volatility3/framework/plugins']
INFO     volatility3.cli: Volatility symbols path: ['/opt/volatility3/volatility3/symbols', '/opt/volatility3/volatility3/framework/symbols']
INFO     volatility3.framework.automagic: Detected a windows category plugin
INFO     volatility3.framework.automagic: Running automagic: ConstructionMagic
INFO     volatility3.framework.automagic: Running automagic: SymbolCacheMagic
INFO     volatility3.framework.automagic: Running automagic: LayerStacker
INFO     volatility3.framework.automagic: Running automagic: WinSwapLayers
INFO     volatility3.framework.automagic: Running automagic: KernelPDBScanner
INFO     volatility3.framework.automagic: Running automagic: SymbolFinder    
INFO     volatility3.framework.automagic: Running automagic: KernelModule

Variable	Value

Kernel Base	0xf800ca419000
DTB	0x1ad000
Symbols	file:///opt/volatility3/volatility3/framework/symbols/windows/ntkrnlmp.pdb/1E158A6041094205BE17F93E54DD5E51-1.json.xz
Is64Bit	True
IsPAE	False
layer_name	0 WindowsIntel32e
memory_layer	1 FileLayer
KdVersionBlock	0xf800ca7c0d50
Major/Minor	15.17134
MachineType	34404
KeNumberProcessors	1
SystemTime	2018-08-06 18:13:42+00:00
NtSystemRoot	C:\Windows
NtProductType	NtProductWinNt
NtMajorVersion	10
NtMinorVersion	0
PE MajorOperatingSystemVersion	10
PE MinorOperatingSystemVersion	0
PE Machine	34404
PE TimeDateStamp	Sat Jul 14 03:53:27 2018
```

​

每次都手动下载过于麻烦，好在 volatility3 提供了各类操作系统的符号表。

符号表打包文件适用于各种操作系统，可在以下地址下载：

* <https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip>
* <https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip>
* <https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip>

用于验证符号包文件的哈希值可在以下网址找到：

* <https://downloads.volatilityfoundation.org/volatility3/symbols/SHA256SUMS>
* <https://downloads.volatilityfoundation.org/volatility3/symbols/SHA1SUMS>
* <https://downloads.volatilityfoundation.org/volatility3/symbols/MD5SUMS>

​

符号表 zip 文件必须按照名称放置到 `volatility3/framework/symbols` 目录中（或者放置在可执行文件旁边的符号目录中）。

​

Windows 中找不到的符号将被查询、下载、生成并缓存。Mac 和 Linux 的符号表必须通过 dwarf2json 等工具手动生成。

重要：使用新的符号文件运行 volatility 分析第一次需要更新缓存。符号包包含大量符号文件，因此更新可能需要一些时间！然而，这个过程只需在每个新的符号文件上运行一次，所以如果包保持在同一位置，则无需再次运行。请注意，这个过程可以被中断，下次运行将自动重启。

这些符号表已经包含了 Windows 和 Mac 系统所需的所有重要部分，由于构建 Linux 上的符号表非常方便，而且不同的 Linux 版本之间难以区分，所以无法轻易提供一个详尽和完整的 Linux 符号表集合。

​

## dwarf2json

`dwarf2json` 是一个 Go 工具，用于处理包含符号和类型信息的文件，以生成适用于 Linux 和 macOS 分析的 Volatility3 中间符号文件（ISF）JSON 输出。

​

构建 dwarf2json （需要 Go 1.18+）：

```
go build
```

​

注意：处理大型 DWARF 文件至少需要 8GB RAM。

​

用户可以选择从输入文件中提取符号信息、类型信息或同时提取这两种信息。

```
./dwarf2json linux --help
  Usage: dwarf2json linux [OPTIONS]

        --elf PATH           从指定的 ELF 文件中提取符号和类型信息。
        --elf-symbols PATH   从指定的 ELF 文件中仅提取符号信息。
        --elf-types PATH     从指定的 ELF 文件中仅提取类型信息。
        --system-map PATH    从指定的 System.Map 文件中提取符号信息。
```

​

例如，要提取指定 Linux 内核 DWARF 文件的符号和类型，可以使用：

```
$ ./dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-4.4.0-137-generic > output.json
```

​

使用 --system-map 从 System.Map 中提取，或者使用 --elf-symbols 或 --elf 从 ELF 文件中提取符号信息。

如果**三者提取出来的符号信息有冲突**，则 `--system-map` 标志指定的 System.Map 文件中的符号偏移量具有最高优先级：

***--elf < --elf-symbols < --system-map***

***​***

允许为给定标志提供多个输入文件。例如， `./dwarf2json --elf file1 --elf file2 ...` 会处理 `file1` 和 `file2` 。当遇到冲突的符号或类型信息时，则优先使用命令调用中指定的最后一个文件的数据。

​

### 排坑

如果你直接将 **/boot** 路径下的内核文件提供给 dwarf2json，则大概率会出现如下错误。

**./dwarf2json linux --elf /boot/vmlinuz-6.8.0-51-generic**

```
Failed linux processing: could not open /boot/vmlinuz-6.8.0-51-generic: bad magic number '[77 90 0 0]' in record at byte 0x0
```

​

使用 **file 命令**查看这个文件的类型

**file /boot/vmlinuz-6.8.0-51-generic**

```
/boot/vmlinuz-6.8.0-51-generic: Linux kernel x86 boot executable bzImage, version 6.8.0-51-generic (buildd@lcy02-amd64-091) #52-Ubuntu SMP PREEMPT_DYNAMIC Thu Dec  5 13:09:44 UTC 2024, RO-rootFS, swap_dev 0XE, Normal VGA
```

这个内核文件，就是当前操作系统运行的内核，**该内核已压缩**（这就是为什么文件将其**识别为 bzImage** 而不是 ELF 文件）

​

使用 extract-vmlinux 脚本将 bzImage 类型的内核文件，提取为未压缩的内核文件。

**./extract-vmlinux.sh /boot/vmlinuz-6.8.0-51-generic > vmlinuz**

**file vmlinuz**

```
vmlinuz: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=5e5f2968a7b14c5d4f2bd9198acc14479c284559, stripped
```

此时得到了一个 ELF 文件，extract-vmlinux.sh 是我在另一个 Github 项目中找到的 shell 脚本。

* <https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux>

​

尝试使用 dwarf2json 生成符号表。

**./dwarf2json linux --elf /tmp/vmlinuz**

```
Failed linux processing: could not get DWARF from /tmp/vmlinuz: decoding dwarf section info at offset 0x0: too short
```

虽然第二个文件是第一个文件的解压版本，但这两个都不是调试内核（debug kernel）

​

由于 debug kernel 可能比正常内核大 100 倍，它们通常不会安装在大多数系统上，且不同 Linux 发行版中 debug kernel 包的名称也不一样。一些 Linux 发行版，甚至默认源不含 debug kernel 软件包，需要额外添加源（例如：ubuntu server 24.04）

​

volatility Github 中的 **dwarf2json 项目的 README 文件提供的示例命令中**，指定的 **--elf 路径为 /usr/lib/debug/boot/**，安装 debug kernel 软件包，默认会将调试内核放置在该路径下，但是 README 中没有明确的说明 --elf 需要一个调试内核（而不是普通内核），对于不熟悉的人来说，非常容易遇到这个问题。

​

在 dwarf2json 项目的一个 issue 中，ikelos 明确指出 --elf 需要一个调试内核，如果有兴趣，可以围观这个 issue。

* <https://github.com/volatilityfoundation/dwarf2json/issues/37>

​

在这个 issue 中还提出 Debian 如何安装调试内核，但并不适用 Ubuntu。以下是我在 Ubuntu server 24.04 中安装调试内核的方法。

​

1. 导入签名密钥

从 Ubuntu 服务器导入调试符号存档签名密钥。在 Ubuntu 18.04 LTS 及更高版本上，运行以下命令：

```
apt install ubuntu-dbgsym-keyring
```

2. 创建一个 ddebs.list 文件

创建一个 `/etc/apt/sources.list.d/ddebs.list` 文件 ，并添加以下配置：

```
deb http://ddebs.ubuntu.com noble main restricted universe multiverse
deb http://ddebs.ubuntu.com noble-updates main restricted universe multiverse
deb http://ddebs.ubuntu.com noble-proposed main restricted universe multiverse
```

3. 更新软件包列表

```
apt-get update
```

4. 使用以下命令安装调试内核

```
apt -y install linux-image-`uname -r`-dbgsym
```

如果想详细了解，可以围观这两篇文章，ubuntu 官方文档和 askubuntu 网站上的一个 questions：

* <https://ubuntu.com/server/docs/debug-symbol-packages>
* <https://askubuntu.com/questions/197016/how-to-install-a-package-that-contains-ubuntu-kernel-debug-symbols>

​

再次使用 dwarf2json 制作符号表，成功！！

**./dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-6.8.0-51-generic > symbols.json**

**​**

## Example

在 ubuntu server 24.04 编译 lime，并创建内存转储文件。使用 dwarf2json 制作适合的符号表，并使用 volatility3 进行分析。

​

我编写的一个 Dockerfile 用于编译 lime 模块（注意：需要能访问 GitHub 仓库）

```
FROM ubuntu:24.04

RUN sed -i 's|http://[^/]\+\.ubuntu\.com/ubuntu/|http://mirrors.tuna.tsinghua.edu.cn/ubuntu/|g' /etc/apt/sources.list.d/ubuntu.sources && \
    apt-get update && \
    apt -y install gcc make git linux-headers-$(uname -r) && \
    git clone https://github.com/504ensicsLabs/LiME.git /opt/lime && \
    cd /opt/lime/src && \
    make
```

​

构造容器镜像

```
docker build -t lime .
```

​

运行容器，将 lime-6.8.0-51-generic.ko 模块复制出来

```
docker run --name lime -itd lime
docker cp lime:/opt/lime/src/lime-6.8.0-51-generic.ko .
```

​

将 lime-6.8.0-51-generic.ko 模块加载到内核执行，生成内存转储文件。

```
insmod lime-6.8.0-51-generic.ko "path=./mem.padded format=padded" 
```

format：这也是一个必需的参数，它指定了内存获取的格式。可选的值包括raw、padded和lime。

* raw 格式：这种格式将所有系统 RAM 区域连接在一起。但是需要注意的是，原始内存的位置信息可能会丢失。
* padded 格式：这种格式会用 0 填充所有非系统 RAM 区域。
* lime 格式：这种格式会在每个范围前加上固定大小的头部，包含地址空间信息。

​

注：**实测 lime 和 padded 格式生成的内存转储文件，volatility3 可以分析**，raw 格式则存在问题。

​

我编写的另一个 Dockerfile 用于生成符号表。

```
FROM ubuntu:24.04

RUN sed -i 's|http://[^/]\+\.ubuntu\.com/ubuntu/|http://mirrors.tuna.tsinghua.edu.cn/ubuntu/|g' /etc/apt/sources.list.d/ubuntu.sources && \
    apt-get update && \
    apt install ubuntu-dbgsym-keyring && \
    echo " \
    deb http://ddebs.ubuntu.com noble main restricted universe multiverse
 \
    deb http://ddebs.ubuntu.com noble-updates main restricted universe multiverse
 \
    deb http://ddebs.ubuntu.com noble-proposed main restricted universe multiverse
 \
    " | tee -a /etc/apt/sources.list.d/ddebs.list && \
    apt-get update

RUN apt -y install linux-image-`uname -r` linux-image-`uname -r`-dbgsym wget

RUN apt -y install  && \
    wget -O /usr/bin/dwarf2json https://github.com/volatilityfoundation/dwarf2json/releases/download/v0.9.0/dwarf2json-linux-amd64 && \
    chmod +x /usr/bin/dwarf2json

RUN dwarf2json linux --system-map /boot/System.map-`uname -r` --elf /usr/lib/debug/boot/vmlinux-`uname -r` > /symbols.json
```

​

构造容器镜像

```
docker build -t symbols .
```

​

运行容器，将生成的符号表文件复制出来

```
docker run --symbols lime -itd symbols
docker cp symbols:/symbols.json .
```

​

使用 volatility3 分析 mem.padded

**vol3 -f mem.padded -s . linux.pslist**

```
Volatility 3 Framework 2.18.0
Progress:  100.00		Stacking attempts finished                 
OFFSET (V)	PID	TID	PPID	COMM	UID	GID	EUID	EGID	CREATION TIME	File output

0x9b1e808a8000	1	1	0	systemd	0	0	0	0	2025-01-24 04:19:01.120948 UTC	Disabled
0x9b1e808aa900	2	2	0	kthreadd	0	0	0	0	2025-01-24 04:19:01.121948 UTC	Disabled
0x9b1e808ad200	3	3	2	pool_workqueue_	0	0	0	0	2025-01-24 04:19:01.121948 UTC	Disabled
0x9b1e808c8000	4	4	2	kworker/R-rcu_g	0	0	0	0	2025-01-24 04:19:01.121948 UTC	Disabled
0x9b1e808ca900	5	5	2	kworker/R-rcu_p	0	0	0	0	2025-01-24 04:19:01.121948 UTC	Disabled
0x9b1e808cd200	6	6	2	kworker/R-slub_	0	0	0	0	2025-01-24 04:19:01.121948 UTC	Disabled
0x9b1e808d5200	7	7	2	kworker/R-netns	0	0	0	0	2025-01-24 04:19:01.121948 UTC	Disabled
...
```

​

因为 symbols.json 放置在当前工作路径下，**-s 参数指定当前工作路径为符号文件的搜索路径**。

​

## 参考链接汇总

* <https://github.com/volatilityfoundation/volatility3/issues/1505#issue-2765440851>
* <https://github.com/volatilityfoundation/volatility3/issues/1294>
* <https://github.com/volatilityfoundation/dwarf2json/issues/37>

* <https://ubuntu.com/server/docs/debug-symbol-packages>
* <https://askubuntu.com/questions/197016/how-to-install-a-package-that-contains-ubuntu-kernel-debug-symbols>
* <https://github.com/volatilityfoundation/volatility3/blob/develop/README.md>
* <https://github.com/volatilityfoundation/dwarf2json/blob/master/README.md>
* <https://volatility3.readthedocs.io/en/v2.11.0/vol-cli.html>
* <https://blogs.jpcert.or.jp/en/2021/09/volatility3_offline.html>
