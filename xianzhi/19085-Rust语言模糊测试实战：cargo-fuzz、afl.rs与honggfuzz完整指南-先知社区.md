# Rust语言模糊测试实战：cargo-fuzz、afl.rs与honggfuzz完整指南-先知社区

> **来源**: https://xz.aliyun.com/news/19085  
> **文章ID**: 19085

---

## 技术背景

传统的AFL、libFuzzer和honggfuzz主要支持用C/C++语言开发的项目。随着Rust、Go等新兴编译型语言的兴起，出现了对这些语言开发项目进行模糊测试的需求。因此，基于传统Fuzz工具的基础，逐步为这些语言构建了专用的Fuzz工具。

Rust生态中的模糊测试工具主要包括cargo-fuzz、afl.rs和honggfuzz。cargo-fuzz是官方推荐的模糊测试工具，基于libFuzzer提供简洁的接口；afl.rs将经典的AFL模糊测试器移植到Rust生态；honggfuzz则提供基于硬件反馈的高效模糊测试能力。这些工具各有特色，适用于不同的测试场景和性能要求。

## Step 1：Rust环境配置与基础准备

### Step 1.1：Rust工具链安装

安装Rust工具链是进行模糊测试的前提条件：

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

安装过程中选择选项1（默认安装），然后设置环境变量：

```
source $HOME/.cargo/env
```

### Step 1.2：编译器版本要求

由于模糊测试工具需要LLVM sanitizer支持，必须使用nightly版本的Rust编译器：

```
# 安装nightly版本
rustup install nightly

# 设置为默认编译器
rustup default nightly
```

nightly版本包含了模糊测试所需的编译时插桩和sanitizer功能，这是稳定版本尚未包含的实验性特性。

## Step 2：cargo-fuzz深度解析与实践

### Step 2.1：工具特性与架构设计

cargo-fuzz是Rust代码模糊测试的官方推荐工具。需要注意的是，cargo-fuzz本身并不是一个fuzzer，而是一个调用fuzzer的工具。目前，它仅支持通过libfuzzer-sys crate调用LibFuzzer。

这种设计架构的优势在于：

* 复用成熟的LibFuzzer引擎
* 提供Rust生态的标准化接口
* 简化模糊测试的配置和管理

### Step 2.2：环境搭建与工具安装

安装cargo-fuzz工具：

```
cargo install cargo-fuzz
```

### Step 2.3：实战案例：rust-url库模糊测试

选择rust-url作为测试目标，这是一个广泛使用的URL解析库，具有复杂的输入处理逻辑。

**环境准备**：

```
git clone https://github.com/servo/rust-url.git
cd rust-url
git checkout bfa167b4e0253642b6766a7aa74a99df60a94048
```

**初始化模糊测试环境**：

```
cargo fuzz init
```

**查看现有的fuzz目标**：

```
cargo fuzz list
```

执行后显示默认创建的测试目标：

```
fuzz_target_1
```

![](C:\Users\K\AppData\Roaming\Typora\typora-user-images\image-20250928191957073.png)

### Step 2.4：编写模糊测试目标

编辑fuzz-targets/fuzz\_target\_1.rs文件：

```
#![no_main] //禁用默认 main 函数入口
extern crate libfuzzer_sys; //导入 libfuzzer_sys
use libfuzzer_sys::fuzz_target;
extern crate url; //引入 url crate

//模糊测试接口函数
fuzz_target!(|data: &[u8]| {
    // 忽略非 UTF-8 输入
    if let Ok(s) = std::str::from_utf8(data) {
        // 测试目标函数
        let _ = url::Url::parse(s);
    }
});
```

关键要点分析：

* `fuzz_target!`是cargo-fuzz提供的宏，用于定义Fuzz入口
* libFuzzer会持续调用该函数，并传入生成的数据
* 类似于C/C++中的`LLVMTestOneInput`函数

### Step 2.5：语料库构建与管理

创建种子语料库：

```
cd fuzz
mkdir -p corpus/fuzz_target_1
mv seed.txt corpus/fuzz_target_1   
```

高质量的种子语料可以显著提高模糊测试的效率和覆盖率。

### Step 2.6：执行模糊测试

启动模糊测试：

```
cargo fuzz run fuzz_target_1
```

cargo fuzz会自动编译带插桩的目标程序，并开始模糊测试。在测试过程中，程序检测到了一个整数溢出漏洞，输出如下调用栈信息：

![](C:\Users\K\AppData\Roaming\Typora\typora-user-images\image-20250928192448736.png)

```
thread '<unnamed>' panicked at ... attempt to subtract with overflow
#18 ... rust-url/src/parser.rs:287:46
```

说明某个地方发生了`x - y`的运算，其中`x < y`，在 release 模式下没有检查，但是我们通过 ASan 捕捉到了

### Step 2.7：Crash分析与复现

当检测到crash时，样本会自动保存到artifacts目录：

```
cargo fuzz run fuzz_target_1 artifacts/fuzz_target_1/crash-7336c41a88a07fc4343d1cea44ddc092589caff9
```

这种整数下溢问题在release模式下可能不被检查，但通过sanitizer可以有效捕获

### Step 2.8：高级参数配置

cargo-fuzz支持通过--传递libFuzzer参数：

```
cargo fuzz run fuzz_target_1 -- -max_len=512 -only_ascii=1
```

常用参数说明：

* `-ignore_crashes=1`：即使遇到崩溃也继续 Fuzz
* `-s,--sanitizer`：选择 Sanitizer
* `-max_len=<len>`：限制输入最大长度
* `-runs=<number>`：限制运行次数
* `-max_total_time=<sec>`：限制总运行时间（秒）
* `-timeout=<sec>`：单次运行超时时间（秒）
* `-only_ascii=1`：仅生成 ASCII 输入
* `-dict=<file>`：使用字典文件
* `-c, --careful`：开启额外的安全检查
* `--no-cfg-fuzzing`：禁用默认的`cfg(fuzzing)`编译配置

其他实用功能：

* `cargo fuzz add target`：创建新的模糊测试目标
* `cargo fuzz fmt target input`：打印测试用例的输入
* `cargo fuz tmin target input`：缩小crash
* `cargo fuzz cmin target`：缩小输入语料库
* `cargo fuzz coverage`：生成覆盖率信息
* 可以设置环境变量`RUST_BACKTRACE=1`来决定是否打印调用栈

**案例：Rust regex ReDoS漏洞（CVE-2022-24713）**

安全研究员Addison Crump发现了Rust regex库中的一个ReDoS（正则表达式拒绝服务）漏洞。根据官方GitHub Security Advisory (GHSA-m5pq-gvj9-9vr8)和CVE-2022-24713，该漏洞允许攻击者通过特制的正则表达式对使用regex crate解析不可信正则表达式的服务发起拒绝服务攻击。

**漏洞详情**（来源：<https://github.com/advisories/GHSA-m5pq-gvj9-9vr8）：>

regex crate虽然内置了防止DoS攻击的缓解措施，但存在一个bug使得攻击者可以构造绕过这些缓解措施的正则表达式。这些恶意正则表达式在解析时会消耗过量的时间和资源，导致服务拒绝服务。

**官方确认信息**：

* **CVE编号**：CVE-2022-24713
* **GHSA编号**：GHSA-m5pq-gvj9-9vr8
* **发现者**：Addison Crump
* **影响版本**：regex <= 1.5.4
* **修复版本**：1.5.5
* **严重程度**：High (解析不可信正则表达式时)

**cargo-fuzz的关键优势**：

* **结构化输入生成**：通过Arbitrary trait生成语法正确的测试输入
* **覆盖率引导**：libFuzzer的反馈机制快速定位到问题代码路径
* **快速发现**：Crump仅用20秒就发现了执行时间异常

这个案例说明了cargo-fuzz在发现深层逻辑漏洞方面的有效性，特别是那些需要特定输入结构才能触发的问题。

## Step 3：afl.rs模糊测试框架实践

### Step 3.1：框架特性与技术架构

afl.rs是基于AFL（American Fuzzy Lop）的Rust语言模糊测试框架，它允许在Rust项目中复用AFL强大的变异引擎和崩溃检测能力。相比cargo-fuzz，afl.rs提供了更多的控制选项和优化策略。

### Step 3.2：环境搭建与依赖安装

安装cargo-afl工具：

afl.rs 也要求 Rust 编译器为 nightly 版本

```
#切换至 nightly
rustup install nightly
rustup default nightly
```

```
cargo install cargo-afl
```

如果安装过程中出现问题，可以添加`--debug`参数进行调试：

```
cargo install cargo-afl --debug
```

### Step 3.3：项目配置与代码编写

**创建测试项目**：

```
cargo new --bin url-fuzz
cd url-fuzz
```

**配置Cargo.toml依赖**：

我们需要在该项目中添加两个依赖项：

* `url`：我们要测试的库
* `afl`：提供了一些辅助函数，帮助编写模糊测试目标

将这些添加到`Cargo.toml`文件中

```
[dependencies]
afl = "*"
url = { git = "https://github.com/servo/rust-url.git", rev = "bfa167b4e0253642b6766a7aa74a99df60a94048" }
```

**编写模糊测试源文件src/main.rs**：

```
#[macro_use]
extern crate afl;
extern crate url;

fn main() {
    fuzz!(|data: &[u8]| {
        if let Ok(s) = std::str::from_utf8(data) {
            let _ = url::Url::parse(&s);
        }
    });
}
```

`fuzz!`宏的工作机制：

* 从AFL运行时提供的标准输入中读取数据
* 内部使用`catch_unwind`捕获panic，确保不会导致fuzzer进程退出

### Step 3.4：构建与编译配置

执行构建命令：

```
cargo afl build
```

如果遇到运行时构建错误：

```
#如果报错FL LLVM runtime was not built for Rust rustc-1.89.0-nightly-99e7c15; run `cargo afl config --build` to build it.
cargo afl config --build
```

这个命令会为当前的rustc版本构建AFL LLVM运行时。

### Step 3.5：语料库准备与测试执行

**创建输入语料**：

```
mkdir in
echo "tcp://example.com/" > in/url1
echo "ssh://192.168.1.1" > in/url2
echo "http://www.example.com:80/foo?hi=bar" > in/url3
```

**启动模糊测试**：

```
cargo afl fuzz -i in -o out target/debug/url-fuzz
```

![](C:\Users\K\AppData\Roaming\Typora\typora-user-images\image-20250928194334835.png)

AFL会显示详细的运行统计信息，包括执行速度、覆盖率和发现的crash数量

### Step 3.6：Crash分析与调试

**复现crash**：

在运行模糊测试程序中收集到一些 crash 后，可以通过以下命令将其重现

```
RUST_BACKTRACE=full cargo run < out/default/crashes/id:000000
#`RUST_BACKTRACE=full`用于打印函数调用栈，可以通过调用栈定位到漏洞存在的位置
```

或使用afl run命令：

```
RUST_BACKTRACE=full cargo afl run url-fuzz -- < out/default/crashes/id:000000
```

**案例：zlib-rs栈溢出漏洞（RUSTSEC-2024-0401）**

2024年11月，安全研究员@inahga使用模糊测试发现了zlib-rs库中的栈溢出漏洞，该案例完美展示了模糊测试在发现编译器层面问题方面的威力。根据GitHub Security Advisory (GHSA-j3px-q95c-9683)，这个漏洞是通过fuzzer发现的："After stack overflows were found by @inahga with a fuzzer"。

**技术根因**：  
问题源于LLVM对zlib-rs代码库的处理方式——尾调用优化未能保证，导致某些输入模式需要大量栈帧，最终引发栈溢出。虽然这类输入模式在实践中不太可能出现，但专门的攻击者可以构造恶意输入文件来触发。

**AFL类工具的发现优势**：  
这类漏洞特别适合AFL的发现模式：

* **字节级盲目变异**：不需要理解zstd格式规范，通过系统性的字节修改探索边界
* **分支覆盖反馈**：引导变异器探索不同的解压代码路径
* **高效执行**：能够快速测试大量压缩数据变体
* **深层路径探索**：发现需要特定字节组合才能触发的编译器优化问题

**漏洞详情**（GHSA-j3px-q95c-9683）：

```
漏洞类型：栈溢出导致拒绝服务
影响版本：zlib-rs <= 0.3.1
根本原因：LLVM尾调用优化缺失
修复版本：0.4.0
CVSS评分：5.3 (中等)
```

**汇编层面的问题**：

```
.LBB109_326: 
    mov rdi, rbx 
    call zlib_rs::inflate::State::type_do 
    jmp .LBB109_311 
.LBB109_311: 
    lea rsp, [rbp - 40] 
    # 清理代码阻止了尾调用优化
```

这个案例说明模糊测试不仅能发现算法逻辑问题，还能揭示编译器优化层面的安全隐患，体现了模糊测试在现代软件安全测试中的深度价值。

### Step 3.7：AFL高级功能应用

**语料库优化**：

```
# 最小化语料库
cargo afl cmin -i in -o out -- target/debug/url-fuzz

# 最小化单个crash文件
cargo afl tmin -i ./out/default/crashes/id:000000 -o crash -- target/debug/url-fuzz
```

**字典驱动测试**：

```
cargo afl fuzz -i in -o out -x dict.txt target/debug/url-fuzz
```

**并行化模糊测试**：

```
# 启动master fuzzer（主节点）
cargo afl fuzz -i in -o out -M fuzzer01 target/debug/url-fuzz

# 启动多个slave fuzzer（辅助节点）
cargo afl fuzz -i in -o out -S fuzzer02 target/debug/url-fuzz
cargo afl fuzz -i in -o out -S fuzzer03 target/debug/url-fuzz
```

**开启AddressSanitizer**：

```
RUSTFLAGS="-Z sanitizer=address" cargo afl build
ASAN_OPTIONS=detect_leaks=0 cargo afl fuzz -i in -o out target/debug/url-fuzz
```

**持久模式优化**：

```
let mut input = vec![];
loop {
    afl::read_stdio_into(&mut input);
    // 测试逻辑...
    input.clear();
}
```

**延迟插桩配置**：

```
fn main() {
    #[cfg(feature = "afl")]
    afl::afl_manual_init(); // 手动触发AFL初始化

    afl::fuzz!(|data: &[u8]| {
        fuzz_target(data);
    });
}
```

## Step 4：honggfuzz模糊测试工具应用

### Step 4.1：工具特性与技术优势

honggfuzz是一个多平台的模糊测试工具，支持基于硬件反馈的覆盖率收集。它的主要优势包括：

* 支持硬件分支跟踪（Intel PT）
* 提供无插桩的模糊测试能力
* 内置多种sanitizer支持
* 高效的并行化执行

### Step 4.2：环境搭建与依赖安装

**安装honggfuzz**：

```
cargo install honggfuzz
```

**安装系统依赖（Linux）**：

```
sudo apt install libunwind-dev  # 用于回溯解析
```

### Step 4.3：项目配置与实现

**创建测试项目**：

```
cargo new --bin url-fuzz
cd url-fuzz
```

**配置Cargo.toml**：

```
[dependencies]
honggfuzz = "0.5"
url = { git = "https://github.com/servo/rust-url.git", rev = "bfa167b4e0253642b6766a7aa74a99df60a94048" }
```

**编写测试代码src/main.rs**：

```
use honggfuzz::fuzz;
use url::Url;

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            if let Ok(s) = std::str::from_utf8(data) {
                let _ = Url::parse(s);
            }
        });
    }
}
```

`honggfuzz::fuzz!`宏负责从共享内存读取输入数据，并执行提供的闭包

### Step 4.4：执行模糊测试

启动测试：

```
cargo hfuzz run url-fuzz
```

honggfuzz会自动编译插桩版本，启动并管理输入语料和输出结果

![](C:\Users\K\AppData\Roaming\Typora\typora-user-images\image-20250928195345086.png)

### Step 4.5：Crash分析与复现

复现发现的crash：

```
RUST_BACKTRACE=1 cargo hfuzz run hfuzz_workspace/url-fuzz/SIGABRT.PC....fuzz
```

### Step 4.6：高级功能配置

**硬件反馈模糊测试**：

```
HFUZZ_RUN_ARGS="--linux_perf_ipt_block --linux_perf_instr --linux_perf_branch" cargo hfuzz run url-fuzz
```

这种方式利用Intel PT硬件分支跟踪进行覆盖率感知模糊测试，无需软件插桩，但需要支持Intel PT的新CPU和Linux系统。

**并行执行配置**：

```
HFUZZ_RUN_ARGS="-n 12" cargo hfuzz run url-fuzz
```

**启用AddressSanitizer**：

```
RUSTFLAGS="-Z sanitizer=address" cargo hfuzz run url-fuzz
```

**字典驱动测试**：

```
HFUZZ_RUN_ARGS="-D ./url.dict" cargo hfuzz run url-fuzz
```

**案例：Cap'n Proto越界读取漏洞（CVE-2022-46149）**

Cap'n Proto的Rust实现维护者David Renshaw在运行自己的fuzzer时发现了一个严重的越界读取漏洞。根据GitHub Security Advisory (GHSA-qqff-4vw4-f6hx)："David discovered this bug while running his own fuzzer"。这个案例展示了模糊测试在发现复杂序列化协议漏洞方面的威力。

虽然具体使用的fuzzer工具未明确披露，但该漏洞的特征非常适合honggfuzz等高性能模糊测试工具的发现模式。当程序处理恶意构造的capnproto消息时，会在解析嵌套结构的过程中访问到缓冲区边界之外的内存区域。capnproto使用了复杂的指针算术来高效地解析二进制协议格式，但在某些边界条件下，计算出的偏移量会超出分配的内存范围。这类深层次的问题需要模糊测试器快速探索大量的输入变体，而honggfuzz基于硬件反馈的高执行速度和Intel PT分支追踪能力，特别适合发现这类需要特定输入组合才能触发的协议解析漏洞。

**漏洞详情**（来源：<https://github.com/capnproto/capnproto/blob/master/security-advisories/2022-11-30-0-pointer-list-bounds.md）：>

问题的核心在于处理list-of-pointer类型时的逻辑错误。当一个list-of-structs被降级为list-of-pointers时，边界检查处理不一致导致特制的指针可以逃脱边界检查。

触发条件：

1. 应用程序必须接受包含list-of-pointer类型字段的schema（如`List(Text)`、`List(Data)`、`List(List(T))`）
2. 攻击者可以恶意编码表示该字段的指针
3. 应用程序调用`getFoo()`获取`List<T>::Reader`，然后执行以下操作之一：

* 将其传递给另一个消息的`setFoo()`，复制字段到新消息
* 将其转换为`AnyList::Reader`并尝试通过该接口访问

成功利用可能导致：

* 远程使对等方段错误
* 可能泄露最多512 KiB的消息缓冲区后面的内存
* 攻击者必须准确指定要泄露的数据量，需要猜测有效指针的确切位置

## Step 5：代码覆盖率测量与分析

### Step 5.1：覆盖率工具链配置

**安装必要工具**：

```
# 安装LLVM工具集
rustup component add --toolchain nightly llvm-tools-preview
cargo install cargo-binutils
cargo install rustfilt
```

### Step 5.2：覆盖率数据收集

**手动插桩编译**：

```
RUSTFLAGS="-C instrument-coverage" cargo build --release
```

**测量覆盖率**：

```
cargo fuzz coverage fuzz_target_1
```

cargo fuzz会自动测试corpus/fuzz\_target\_1目录下的所有语料，生成覆盖率数据文件coverage.profdata

![](C:\Users\K\AppData\Roaming\Typora\typora-user-images\image-20250928195703565.png)

### Step 5.3：可视化覆盖率信息

**生成HTML格式报告**：

```
cargo cov -- show fuzz/target/x86_64-unknown-linux-gnu/release/fuzz_target_1 \
  --format=html \
  --Xdemangler=rustfilt \
  --instr-profile=fuzz/coverage/fuzz_target_1/coverage.profdata \
  > coverage.html
```

![](C:\Users\K\AppData\Roaming\Typora\typora-user-images\image-20250928195807744.png)

**终端查看覆盖率**：

```
cargo cov -- show --use-color \
  --instr-profile=fuzz/coverage/fuzz_target_1/coverage.profdata \
  fuzz/target/x86_64-unknown-linux-gnu/release/fuzz_target_1 \
  --show-regions --show-instantiations
```

![](C:\Users\K\AppData\Roaming\Typora\typora-user-images\image-20250928195840074.png)

终端输出会以颜色标识不同的覆盖率状态：

* 红色：未覆盖的代码行
* 绿色：已覆盖的代码行
* 数字：执行次数统计

**真实案例分析库：Rust Fuzz Trophy Case**

想要深入了解不同类型的模糊测试问题，可以参考Rust社区维护的"Trophy Case"（<https://github.com/rust-fuzz/trophy-case>），这是一个按问题类型分类的真实案例收集库。这个资源库将发现的漏洞按照arith（算术错误）、utf-8（编码问题）、oom（内存耗尽）、oor（越界访问）、logic（逻辑错误）、panic（程序崩溃）等类别进行归档，每个条目都包含了具体的issue链接和修复提交。通过分析这些案例，可以发现一个有趣的模式：大多数问题都集中在输入解析、数据转换、边界检查等"边界处理"逻辑上。这反映了一个重要的测试策略：在为自己的项目设计模糊测试时，应该重点关注那些处理外部输入、进行格式转换、或者涉及复杂计算的代码模块。同时，观察同类项目已发现的问题类型，可以帮助你为自己的fuzzer配置更有针对性的种子语料和字典文件，大大提高发现相似问题的效率。

覆盖率分析的价值在于帮助开发者了解模糊测试的有效性，识别未被充分测试的代码路径。通过定期分析覆盖率报告，可以优化种子语料库和字典配置，提高模糊测试的效率。同时，覆盖率数据也是评估不同模糊测试工具效果的重要指标。

## Step 6：工具选择与最佳实践

### Step 6.1：工具特性对比分析

|  |  |  |  |
| --- | --- | --- | --- |
| 特性 | cargo-fuzz | afl.rs | honggfuzz |
| **底层引擎** | libFuzzer | AFL/AFL++ | honggfuzz |
| **安装复杂度** | 简单 | 中等 | 简单 |
| **硬件支持** | 否 | 否 | 是（Intel PT） |
| **并行能力** | 有限 | 强大 | 强大 |
| **字典支持** | 是 | 是 | 是 |
| **Sanitizer集成** | 优秀 | 良好 | 优秀 |
| **覆盖率分析** | 内置 | 需配置 | 内置 |

### Step 6.2：选择建议与使用场景

**cargo-fuzz适用场景**：

* 快速原型和概念验证
* 与CI/CD系统集成
* 需要详细覆盖率分析
* Rust新手用户

**afl.rs适用场景**：

* 需要大规模并行测试
* 要求精细的参数控制
* 已有AFL使用经验
* 长期持续测试

**honggfuzz适用场景**：

* 硬件资源充足的环境
* 需要无插桩测试
* 对性能要求极高
* 系统级测试场景

### Step 6.3：实践经验总结

**种子语料质量是关键**：

* 提供多样化的有效输入
* 覆盖主要的代码路径
* 包含边界条件测试用例

**合理配置sanitizer**：

* AddressSanitizer检测内存错误
* 根据测试目标选择适当的检测级别
* 平衡检测能力与性能开销

**持续监控与优化**：

* 定期分析覆盖率数据
* 根据结果调整测试策略
* 及时处理发现的安全问题

## 结论与展望

本文供师傅们学习介绍了Rust语言模糊测试的三种主流工具及其应用方法。cargo-fuzz提供了简洁易用的接口，适合快速集成和日常开发；afl.rs继承了AFL的强大功能，适合大规模专业测试；honggfuzz则提供了基于硬件的高效测试能力。

通过分析三个真实的漏洞发现案例——Addison Crump用cargo-fuzz发现的Rust regex ReDoS漏洞（2023年）、@inahga用fuzzer发现的zlib-rs栈溢出问题（RUSTSEC-2024-0401），以及David Renshaw发现的Cap'n Proto越界读取漏洞（CVE-2022-46149）——也表述了这些工具在发现真实安全漏洞方面的有效性。每个工具都展现了其独特优势：cargo-fuzz的结构化模糊测试、AFL类工具的深层路径探索、以及honggfuzz的高性能协议解析测试能力。选择合适的工具组合可以显著提高Rust项目的安全性和可靠性。

随着Rust生态的不断发展，模糊测试工具链也在持续演进。未来的发展方向可能包括更智能的变异策略、更高效的覆盖率收集、以及与开发工具链的深度集成。掌握这些工具的使用方法，对于构建安全可靠的Rust应用具有重要意义。
