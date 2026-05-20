# 【二进制静态分析工具-Binabsinspector】从入门到进阶-先知社区

> **来源**: https://xz.aliyun.com/news/17945  
> **文章ID**: 17945

---

# 前言

Binabsinspector是一款是由Keenlab开发的一款基于ghidra的二进制静态分析工具。**现有文章主要介绍安装部署以及如何基于GUI插件的方式使用该工具，但是对如何基于该工具进行二次开发着墨较少。**因此，本文旨在通过介绍该工具的常见接口，基于笔者日常使用过程中的实际需求，剖析其代码实现，希望能够为安全研究人员使用该工具和二次开发提供参考。

## BinAbsInspector 是什么？

一款基于Ghidra的中间语言P-code实现的过程间数据流分析框架，内置了污点分析引擎，支持以下CWE类型漏洞的检测：

* [CWE119](https://cwe.mitre.org/data/definitions/119.html) (Buffer Overflow (generic case))
* [CWE125](https://cwe.mitre.org/data/definitions/125.html) (Buffer Overflow (Out-of-bounds Read))
* [CWE134](https://cwe.mitre.org/data/definitions/134.html) (Use of Externally-Controlled Format string)
* [CWE190](https://cwe.mitre.org/data/definitions/190.html) (Integer overflow or wraparound)
* [CWE367](https://cwe.mitre.org/data/definitions/367.html) (Time-of-check Time-of-use (TOCTOU))
* [CWE415](https://cwe.mitre.org/data/definitions/415.html) (Double free)
* [CWE416](https://cwe.mitre.org/data/definitions/416.html) (Use After Free)
* [CWE426](https://cwe.mitre.org/data/definitions/426.html) (Untrusted Search Path)
* [CWE467](https://cwe.mitre.org/data/definitions/467.html) (Use of sizeof() on a pointer type)
* [CWE476](https://cwe.mitre.org/data/definitions/476.htmll) (NULL Pointer Dereference)
* [CWE676](https://cwe.mitre.org/data/definitions/676.html) (Use of Potentially Dangerous Function)
* [CWE787](https://cwe.mitre.org/data/definitions/787.html) (Buffer Overflow (Out-of-bounds Write))

## BinAbsInspector 能做什么？

BinAbsInspector实现了过程间的数据流分析。因此，能够基于该工具实现一系列基于过程间数据流分析的应用。例如，BinAbsInspector通过内置实现的静态污点分析引擎和漏洞Checker实现不同类型漏洞的检测。

# 安装&开发环境

在官方的[README](https://github.com/KeenSecurityLab/BinAbsInspector)中提供了release或者手工build的步骤，在开发指南中提供了开发环境的设置过程，可以便捷的基于Intellj IDEA和Eclipse进行开发，本文就不再赘述。

# 背景知识

**BinAbsInspector** 的数据流分析主要基于Ghidra的P-code实现。一条二进制上的汇编指令可能会被中间代码翻译为多条P-code。目前，BinAbsInspector仅支持x86、x64、armv7 和 aarch64架构下的二进制文件分析，本文在后续会介绍如何为BinAbsInspector 快速添加新架构（MIPS）的扩展支持。

## 数据流分析

数据流分析是一种用于收集计算机程序在不同程序点计算的值的信息的技术。一个程序的控制流图（control flow graph, CFG）被用来确定对变量的一次赋值可能传播到程序中的哪些部分。简单来说，以污点分析为例，实际上就是通过沿着CFG分析污点源在经过不同的程序语句后，是否能够到达污点汇聚点的代码位置。污点汇聚点因检测漏洞类型而异，比如在缓冲区溢出检测中，污点源是引入外部输入的位置，而污点汇聚点则是内存操作函数或者循环中的内存读写。关于数据流分析的具体概念和定义可以参考龙书。

# BinAbsInspector.java

在分析程序时个人感觉最好的习惯就是先有一个全局视角，然后基于某个功能或者执行流程，逐渐细化所关注的重点部分，这样不容易迷失在海量的代码和复杂的各种逻辑及数据结构实现中，先整体再部分。

以开发指南中的给出的代码为例，BinAbsInspector.java是整个工具分析的入口，通过继承Ghidra的GhidraScript类并重写analyze方法，根据headless或者gui模式下传输的参数执行分析。BinAbsInspector的分析流程和主要代码如下主要如下：

1. analyze
2. runCheckers()

```
public class BinAbsInspector extends GhidraScript {

    protected boolean prepareProgram() {
        GlobalState.currentProgram = this.currentProgram;
        GlobalState.flatAPI = this;
        Language language = GlobalState.currentProgram.getLanguage();
        return language != null;
    }

    protected boolean analyzeFromMain() {
        ...
    }

    protected boolean analyzeFromAddress(Address entryAddress) {
        Function entryFunction = GlobalState.flatAPI.getFunctionAt(entryAddress);
        if (entryAddress == null) {
            Logging.error("Could not find entry function at " + entryAddress);
            return false;
        }
        Logging.info("Running solver on "" + entryFunction + "()" function");
        InterSolver solver = new InterSolver(entryFunction, false);
        solver.run();
        return true;
    }

    /**
     * Start analysis with following steps:
     * 1. Start from specific address if user provided, the address must be the entrypoint of a function.
     * 2. Start from "main" function if step 1 fails.
     * 3. Start from "e_entry" address from ELF header if step 2 fails.
     * @return
     */
    protected boolean analyze() {
        Program program = GlobalState.currentProgram;
        ...
        String entryAddressStr = GlobalState.config.getEntryAddress();
        if (entryAddressStr != null) {
            Address entryAddress = GlobalState.flatAPI.toAddr(entryAddressStr);
            return analyzeFromAddress(entryAddress);
        } else {
            ...
        }
        return true;
    }

    @Override
    public void run() throws Exception {
        GlobalState.config = new Config();
        ...
        FunctionModelManager.initAll();
        ...
        GlobalState.arch = new Architecture(GlobalState.currentProgram);
        boolean success = analyze();
        ...
        CheckerManager.runCheckers(GlobalState.config);
        guiProcessResult();
        GlobalState.reset();
    }
}
```

## BinAbsInspector.java 关键接口

|  |  |
| --- | --- |
| **接口** | **功能** |
| public void run() | 初始化配置并调用analyze方法执行分析 |
| protected boolean analyze() | 设置分析入口（默认是程序入口点) |
| protected boolean analyzeFromAddress(Address entryAddress) | 获取给定地址所在的函数，并将其作为分析的入口函数 |

## BinAbsInspector.java 关键数据结构

BinAbsInspector具有以下几个关键全局数据结构(类)，这些数据结构在后续的数据流分析框架和Checker中会普遍用到：

|  |  |
| --- | --- |
| **名称** | **功能** |
| GlobalState | 记录当前分析的配置参数(config)，记录当前的currentProgram对象、常用API对象(flatAPI)以及其他的基本结构 |
| FunctionModelManager | 管理所建模的函数，以便于在分析时遇到这些函数直接执行相应的处理逻辑。可以理解为函数摘要，其实现的代码主要是该函数对当前数据流的副作用/影响 |
| CheckerManager | 管理实现的检测器（Checker）的类 |

# 基本分析流程

BinAbsInspector的分析时上下文敏感的，大体上的运行流程是analyze() -> Pcodevisitor.visit()，其分析流程包括过程内分析和过程间分析：

* **过程内分析：**沿着CFG，遍历函数的所有基本块中的P-code，在Pcodevisitor类中的visit实现了对不同P-code指令的遍历，通过Worklist算法进行迭代分析，当数据流到达不动点时结束分析
* **过程间分析：**当分析到函数调用时，通过上下文切换分析子函数，即在函数调用点位置生成一份当前数据流状态的拷贝，并将其作为分析子函数的初始状态，并最后分析结束时基于Call string与子函数返回点处的数据流状态合并

# 常见接口和数据结构

在深入阅读BinAbsInspector代码时，最好明确以下几个数据结构的基本概念，特别是该工具如何设计变量、内存、数据流值的抽象，以及如何对于不同的P-code语句实现相应的数据流转换函数。

## 程序抽象结构设计

该工具主要参考了 THOMAS REPS 的[经典论文](https://dl.acm.org/doi/pdf/10.1145/1749608.1749612)，根据对象或位置的不同，将变量抽象为五种，即栈、堆、全局变量或数值、临时变量和寄存器变量，这些抽象变量统一用Aloc表示，并用region成员区分不同的抽象变量。

### Aloc

```
public class ALoc implements Comparable<ALoc> {
    private ALoc(RegionBase region, long begin, int len) {
        assert (len != 0);
        this.region = region;
        this.begin = begin;
        this.len = len;
    }
}
```

### AbsEnv

BinAbsInspector使用 AbsEnv 类表示不同程序点的数据流状态，即存在的抽象变量（Aloc）及其对应的数据流值（Kset）。这里使用JImmutableTreeMap结构实现AbsEnv，其key为抽象变量，value为其对应的Kset值

```
public class AbsEnv {

    private JImmutableTreeMap<ALoc, KSet> envMap;

    /**
     * Constructor for an empty abstract environment
     */
    public AbsEnv() {
        envMap = JImmutableTreeMap.of();
    }
}
```

### KSet

Kset是抽象数据流值的集合，一个抽象变量在实际过程中可能对应多个抽象的数据流值。例如，同一个变量在不同分支中会有不同的取值，那么BinAbsInspector在分析是会将这些数据流值都记录在Kset中。

**收敛：**一个抽象变量的抽象数据流值可能具有无穷多个，例如无法确定上限的循环中，每次循环可能都要为抽象变量生成一个数据流值。因此，为了保证分析收敛以达到不动点，Kset集合的元素个数会被设置一个上限，一旦超过上限，即将其记录为Top。（参见龙书中有关数据流分析的单调性定义）

**代码实现：**在Kset中，实现了数据流值的插入、合并、删除以及一系列针对抽象数据流值算数运算和逻辑运算的方法，以便于在分析到不同的P-code语句时直接调用。以下表的or运算为例，将两个集合中的元素分别进行or操作，然后做结果返回。类似的运算都要根据P-code语义的不同重新实现一遍，同时需要考虑数据流值为Top以及是污点值的情况。

|  |  |
| --- | --- |
| **接口** | **功能** |
| public KSet insert(AbsVal val) | 往集合中插入一个抽象数据流值AbsVal |
| public KSet remove(AbsVal val) | 从集合中删除一个抽象数据流值AbsVal |
| public KSet int\_or(KSet rhs) | 处理两个Kset的or操作，将两个集合中的元素分别进行or逻辑运算 |

### AbsVal

AbsVal是抽象的数据流值，其Region可能是全局的、堆或栈

```
public class AbsVal {

    protected RegionBase region;

    protected BigInteger bigVal;

    protected long value;
}
```

## 污点分析引擎

**TaintMap**

污点分析（Taint Analysis）中的TaintMap是用于记录和管理污点分析中的污点源信息，并记录相应的引入位置，以便于在sink点时可以根据taint id值获取当前sink点的数据受哪些污点源影响。其主要成员变量如下：

* Source 类唯一标识一个污点源
* TaintID标识当前引入的污点源数量
* MAX\_TAINT\_CNT 定义了最大支持的污点源数量
* taintSourceToIdMap 记录Source到TaintID的映射，便于在sink点检索污点信息的来源

```
public class TaintMap {

    /**
     * Description for each taint source, consisting of a function and its context
     */
    public static class Source {

        private final Address callSite;
        private final Context context;
        private final Function function;

        public Source(Address callSite, Context context, Function function) {
            this.callSite = callSite;
            this.context = context;
            this.function = function;
        }
    }

    private static int taintId = 0;
    private static final int MAX_TAINT_CNT = 64;
    private static final Map<Source, Integer> taintSourceToIdMap = new HashMap<>();
}
```

主要接口如下：

|  |  |
| --- | --- |
| **接口** | **介绍** |
| public static long getTaints(Address callSite, Context context, Function function) | 在给定的位置新引入一个污点源 |
| reset | 重置TaintMap |

​

## Checker实现

在路径com.bai.checkers下定义了CheckerManager类，以注册各类漏洞的检测器

```
public class CheckerManager {

    private static final Map<String, CheckerBase> CHECKER_MAP = Map.ofEntries(
            Map.entry("CWE134", new CWE134()),
            Map.entry("CWE190", new CWE190()),
            Map.entry("CWE367", new CWE367()),
            Map.entry("CWE426", new CWE426()),
            Map.entry("CWE467", new CWE467()),
            Map.entry("CWE676", new CWE676()),
            Map.entry("CWE78", new CWE78())
    );
}
```

### CWE190 整数溢出检测

以整数溢出检测CWE190为例，可以看到该类主要实现了check方法实现整数溢出漏洞检测，该函数通过检查程序中，所有调用interestingSymbols的函数调用位置（例如malloc等函数），并检查其调用点所在block是否存在左移操作或者乘法操作（因为这样的操作更容易导致整数溢出），通过以下代码可以看出其检查规则实际非常宽松，并没有检查malloc的参数是否可能受污点源影响。因此在检测实际应用程序的时候可能会产生大量误报 : (

```
public class CWE190 extends CheckerBase {

    private static final Set<String> interestingSymbols = Set.of("malloc", "xmalloc", "calloc", "realloc");

    public CWE190() {
        super("CWE190", "0.1");
        description = "Integer Overflow or Wraparound: The software performs a calculation that "
                + "can produce an integer overflow or wraparound, when the logic assumes that the resulting value "
                + "will always be larger than the original value. This can introduce other weaknesses "
                + "when the calculation is used for resource management or execution control.";
    }

    private boolean checkCodeBlock(CodeBlock codeBlock, Reference ref) {
        boolean foundWrapAround = false;
        for (Address address : codeBlock.getAddresses(true)) {
            Instruction instruction = GlobalState.flatAPI.getInstructionAt(address);
            if (instruction == null) {
                continue;
            }
            for (PcodeOp pCode : instruction.getPcode(true)) {
                if (pCode.getOpcode() == PcodeOp.INT_LEFT || pCode.getOpcode() == PcodeOp.INT_MULT) {
                    foundWrapAround = true;
                }
                if (pCode.getOpcode() == PcodeOp.CALL && foundWrapAround && pCode.getInput(0).getAddress()
                        .equals(ref.getToAddress())) {
                    CWEReport report = getNewReport(
                            "(Integer Overflow or Wraparound) Potential overflow "
                                    + "due to multiplication before call to malloc").setAddress(
                            Utils.getAddress(pCode));
                    Logging.report(report);
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public boolean check() {
        boolean hasWarning = false;
        try {
            BasicBlockModel basicBlockModel = new BasicBlockModel(GlobalState.currentProgram);
            for (Reference reference : Utils.getReferences(new ArrayList<>(interestingSymbols))) {
                Logging.debug(reference.getFromAddress() + "->" + reference.getToAddress());
                for (CodeBlock codeBlock : basicBlockModel.getCodeBlocksContaining(reference.getFromAddress(),
                        TaskMonitor.DUMMY)) {
                    hasWarning |= checkCodeBlock(codeBlock, reference);
                }
            }
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        return hasWarning;
    }
}
```

### CWE-676 危险函数使用

CWE-676是危险函数调用，例如gets、strcpy、std::cin等，这些函数经常出现于CTF题目？以及一些比较古旧的项目/固件中，CWE-676的Checker实现代码如下，这些Checker的统一入口都是check函数，但是实际上感觉一些类型漏洞的检测可以在数据流迭代的时候直接生成报告，而不必等数据流分析收敛：

```
    public boolean check() {
        boolean hasWarning = false;
        try {
            SymbolTable symbolTable = GlobalState.currentProgram.getSymbolTable();
            if (symbolTable == null) {
                Logging.debug("Empty symbols table");
                return false;
            }
            Function entryFunction = null;
            if (GlobalState.config.getEntryAddress() != null) {
                entryFunction = GlobalState.flatAPI.getFunctionAt(
                        GlobalState.flatAPI.toAddr(GlobalState.config.getEntryAddress()));
            } else {
                List<Function> mainFunctions = GlobalState.flatAPI.getGlobalFunctions("main");
                if (mainFunctions.isEmpty()) {
                    return false;
                }
                entryFunction = mainFunctions.get(0);
            }
            // Build a callgraph starting from the `main()` function.
            CallGraph callGraph = CallGraph.getCallGraph(entryFunction);
            SymbolIterator stdCins = symbolTable.getSymbols("cin");
            SymbolIterator stdioWidths = symbolTable.getSymbols("width");
            for (Reference reference: Utils.getReferences(new ArrayList<>(dangerousFunctions))) {
                Address toAddress = reference.getToAddress();
                Address fromAddress = reference.getFromAddress();
                Function callee = GlobalState.flatAPI.getFunctionAt(toAddress);
                Function caller = GlobalState.flatAPI.getFunctionContaining(fromAddress);
                if (callee == null || caller == null) {
                    continue;
                }
                Logging.debug(fromAddress + " -> " + toAddress + " " + callee.getName());
                // We have two cases - simple and complex (with std::cin)
                if (!callee.getName().equals("operator>>")) {
                    // Show report for the simple case
                    CWEReport report = getNewReport("Use of the dangerous function ""
                            + callee + "()"").setAddress(fromAddress);
                    Logging.report(report);
                    hasWarning = true;
                    continue;
                }
                Logging.debug("std::operator>> case");
                if (stdCins == null) {
                    Logging.debug("std::cin not found");
                    continue;
                }
                // Now we process the more complex case of `std::cin >>`
                // Get the list of contexts for the current function
                for (Context context : Context.getContext(caller)) {
                    AbsEnv absEnv = context.getAbsEnvIn().get(fromAddress);
                    if (absEnv == null) {
                        continue;
                    }
                    hasWarning |= handleStdCin(absEnv, callGraph,
                            fromAddress, callee, caller, stdCins, stdioWidths);
                }
            }
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        return hasWarning;
    }
```

# 架构扩展支持

BinAbsInspector仅支持x86、x64、armv7 和 aarch64架构，为了添加对其他架构的支持，这里我们需要修改Architecture.java文件，由于BinAbsInspector是一个过程间的数据流分析框架，在分析的时候会通过栈指针恢复栈变量和结构，因此在扩展新架构时，需要添加该架构下SP寄存器的索引以及FLAG寄存器的索引，同时MIPS32架构的固件有时候会混合16位的指令集，因此getPcKSet函数获取PC的时候，需要基于Ghidra的接口获取当前分析上下文ISA Mode，以得到正确的PC地址。

```
    // from: https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Processors/MIPS/data/languages/mips.sinc
    private static final int MIPS32_SP_INDEX = 0x74;
    private static final int[] MIPS_FLAG_INDEXES = {
            0x0, // zero register
    };

    public Architecture(Program program) {
        processor = program.getLanguage().getProcessor().toString();
        isLittleEndian = !program.getMemory().isBigEndian();
        wordBits = program.getAddressFactory().getDefaultAddressSpace().getSize();
        defaultPointerSize = program.getDefaultPointerSize();
        pcIndex = program.getLanguage().getProgramCounter().getOffset();
        switch (processor) {
            case "ARM":
                flagIndexes = ARMV7_FLAG_INDEXES;
                spIndex = ARMV7_SP_INDEX;
                break;
            case "AARCH64":
                flagIndexes = ARMV8_FLAG_INDEXES;
                spIndex = ARMV8_SP_INDEX;
                break;
            case "x86":
                flagIndexes = X86_FLAG_INDEXES;
                if (defaultPointerSize == 4) {
                    spIndex = X86_32_SP_INDEX;
                    break;
                } else if (defaultPointerSize == 8) {
                    spIndex = X86_64_SP_INDEX;
                    break;
                }
            case "MIPS":
                if(defaultPointerSize == 4){
                    spIndex = MIPS32_SP_INDEX;
                    flagIndexes = MIPS_FLAG_INDEXES;
                    break;
                }
                // fallthrough to error if invalid defaultPointerSize
            default:
                Logging.error("Unsupported architecture. " + processor + wordBits);
                System.exit(-1);
        }
    }


    public KSet getPcKSet(Address currentAddress) {
        long pcValue;
        KSet pcKSet = new KSet(defaultPointerSize * 8);
        switch (processor) {
            case "ARM":
                Register tMode = GlobalState.currentProgram.getProgramContext().getRegister("TMode");
                boolean isThumb = GlobalState.currentProgram.getProgramContext().getRegisterValue(tMode, currentAddress)
                        .getUnsignedValue().testBit(0);
                if (isThumb) {
                    pcValue = currentAddress.getOffset() & 0xFFFFFFFCL + 4;
                } else {
                    pcValue = currentAddress.getOffset() + 8;
                }
                break;
            case "AARCH64":
                pcValue = currentAddress.getOffset();
                break;
            case "x86":
                pcValue = GlobalState.flatAPI.getInstructionAfter(currentAddress).getAddress().getOffset();
                break;
            case "MIPS":
                Register isa_mode = GlobalState.currentProgram.getProgramContext().getRegister("ISA_MODE");
                boolean ismips16e = GlobalState.currentProgram.getProgramContext().getRegisterValue(isa_mode, currentAddress)
                        .getUnsignedValue().testBit(0);
                if (ismips16e) {
                    pcValue = currentAddress.getOffset() & 0xFFFFFFFCL + 4;
                } else {
                    pcValue = currentAddress.getOffset() + 8;
                }
                break;
            default:
                Logging.error("getPCKSet(): unsupported architecture");
                return pcKSet;
        }
        pcKSet = pcKSet.insert(AbsVal.getPtr(Global.getInstance(), pcValue));
        return pcKSet;
    }

```

# 进阶使用

本节将以我日常使用过程中的一些常见需求，介绍如何在现有BinabsInspector的基础上进行功能的扩展和二次开发。

## 自定义漏洞检测器

需要在CheckerManager类中注册自定义Checker，并在com.bai.checkers路径下实现Checker类

* com.bai.checkers 下的 CheckerManager.java

```
    private static final Map<String, CheckerBase> CHECKER_MAP = Map.ofEntries(
            Map.entry("CWE134", new CWE134()),
            Map.entry("CWE190", new CWE190()),
            Map.entry("CWE367", new CWE367()),
            Map.entry("CWE426", new CWE426()),
            Map.entry("CWE467", new CWE467()),
            Map.entry("CWE676", new CWE676()),
            Map.entry("CWE78", new CWE78())，
            Map.entry("MyChecker", new MyChecker())
    );
```

* com.bai.checkers 下的 MyChecker.java

```
public class MyChecker extends CheckerBase {

    private static final Set<String> interestingSymbols = Set.of();

    public MyChecker() {
        super("MyChecker", "0.1");
        description = "MyChecker";
    }

    @Override
    public boolean check() {
        boolean hasWarning = false;
        // 实现自定义的检查逻辑
}

```

实际上，有些类型漏洞可以在迭代分析的过程中直接输出结果，因此我们可以通过修改PcodeVisitor.java中各类语句的visit函数，在分析到特定类型的pcode时调用Mychecker下的特定检测逻辑。

## 自定义污点源

BinAbsInspector仅将常见的一些库函数内置为污点源函数，但是在分析固件时，污点源函数通常是一些包装函数或者用户自定义实现的函数，甚至是一些特定的内存地址，因此，在分析时我们可以通过自定义污点源函数，或者修改PcodeVisitor.java，直接生成污点源。

### 自定义污点源函数

参考com.bai.env.funcs.externalfuncs路径下的GetsFunction函数：

```
public class GetsFunction extends InputFunctionBase {

    private static final Set<String> staticSymbols = Set.of("gets");

    public static Set<String> getStaticSymbols() {
        return staticSymbols;
    }

    public GetsFunction() {
        // char *gets(char *s)
        super(staticSymbols);
        addDefaultParam("s", PointerDataType.dataType);
        setTaintedBufParamIndex(0);
        setReturnType(PointerDataType.dataType);
        setReturnNewTaint(false);
    }
}
```

* addDefaultParam("s", PointerDataType.dataType); addDefaultParam函数可以设置了参数的类型
* setTaintedBufParamIndex 设置引入污点源的参数索引，在gets函数中，会将输入读入第一个参数，因此设置为0
* setReturnNewTaint 设置是否为该函数的不同调用位置生成新的TaintID

当函数是通过返回值引入污点源时，可以通过实现以下函数，实现在函数的返回位置引入初始污点信息

```
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function callFunc) {
        ALoc retALoc = getReturnALoc(callFunc, false);
        if (retALoc == null) {
            return;
        }
        Address callAddress = getAddress(pcode);
        long taints = TaintMap.getTaints(callAddress, context, callFunc);
        inOutEnv.set(retALoc, KSet.getTop(taints), true);
    }
```

### 直接引入污点源

可以通过调用TaintMap.getTaints(addr, context, GlobalState.flatAPI.getFunctionContaining(addr));直接在特定的P-code位置为抽象变量生成一个污点信息，并通过getTop函数和setKSet函数，将污点信息赋值给P-code语句左部

```
newTaints = TaintMap.getTaints(addr, context, GlobalState.flatAPI.getFunctionContaining(addr));
resKSet = KSet.getTop(newTaints);
setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
```

​

## 其他

BinAbsInspector 在缓冲区溢出检测时仅检测了特定内存操作函数的调用是否受污点源影响，但是在许多文件解析或者网络协议报文解析中，一些越界读写的位置往往是在循环中，后续有时间的话会更新下BinAbsInspector如何识别循环，并如何为循环解析导致的越界读写漏洞建模及检测。

# 总结

BinAbsInspector 是科恩实验室开源的一款基于迭代数据流分析的Ghidra插件，其代码可读性和可扩展性非常良好，并且有Ghidra作为分析基座，非常适合快速上手并定制开发。在缺乏有效的、针对二进制程序的静态数据流分析工具的当下，显得难能可贵，非常感谢BinAbsInspector项目的所有开发人员和贡献者！
