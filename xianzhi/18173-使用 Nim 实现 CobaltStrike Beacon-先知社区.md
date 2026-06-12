# 使用 Nim 实现 CobaltStrike Beacon-先知社区

> **来源**: https://xz.aliyun.com/news/18173  
> **文章ID**: 18173

---

先把项目端上来：[GitHub - L4zyD0g/NimBeacon: A Cobalt Strike beacon implemented in Nim-lang.](https://github.com/L4zyD0g/NimBeacon)。  
起因是感觉自己最近摸鱼严重，想给自己个项目来干一下。刚好看到了一些 Nim 武器化的项目，感觉这个语言是又强大又优雅，有了想用 Nim 来实现 CS Beacon 的想法，然后就有了这个项目，如果大家觉得有用就点个Star8。  
这篇文章主要给大家介绍开发的过程，帮助想要做CS二开或者想用Nim做武器化的兄弟们少踩坑。尽量少废话，多引用，不重复记录。有任何问题喷我就行。

## 环境搭建

1. 使用 [choosenim](https://github.com/dom96/choosenim) 安装 Nim
2. 安装 Vscode 或其他基于 Vscode 的编辑器，我这里使用的是 Trae CN，感觉还行
3. 安装扩展，我这里用的是官方的 nim-lang.org。如果你用的是其他基于 Vscode 的编辑器，记得改一下插件市场的配置，否则搜不到。参考 [这篇文章](https://blog.xiqi.site/archives/windsurf-shi-yong-vscode-cha-jian-cang-ku-an-zhuang-geng-xin-cha-jian)，是 Windsurf 的，Trae 之类的都差不多。
4. 找个 CS4.5 的原始 Jar 包，记得去 [verify.cobaltstrike.com](https://verify.cobaltstrike.com/) 验一下哈希，别自己上线了。
5. 配置下二开环境，网上文章很多，比如：[GitHub - atomxw/cobaltstrike4.5cdf](https://github.com/atomxw/cobaltstrike4.5_cdf) 和 [调试CobaltStrike环境搭建](https://radishes-nine.vercel.app/cobaltstrike)。
6. 准备个测试用虚拟机，没啥可说的

## 开发

开发之前先学习下 Nim 的语法的。Nim 官方每年有个社区调查来收集大家的反馈，[Nim Community Survey 2024 Results - Nim Blog](https://nim-lang.org/blog/2025/01/23/community-survey-results-2024.html)，2024 年的调查显示最受欢迎的是官方教程 [Nim Tutorial](https://nim-lang.org/docs/tut1.html) 和 [Nim by Example](https://nim-by-example.github.io/getting_started/)，简单看下就行，哪里不会了再去搜，最重要的是先动手。（这个项目就是边学边干的，所以你可能看到很多东西在不同模块里的写法不一样- -，后面可能会改一下）。  
我自己整理了一些小 Tips，仅供参考：

* 使用 winim [GitHub - khchen/winim](https://github.com/khchen/winim/tree/6fdee629140baa0d7060ddf86662457d11f50d35) 调 API，非常方便，而且支持 com/clr，强烈推荐。
* 一些功能 Offensive Nim [GitHub - byt3bl33d3r/OffensiveNim](https://github.com/byt3bl33d3r/OffensiveNim) 已经实现过了，做功能前先看一下，不要重复造轮子。
* 调用有字符串入参的 Win32 API 时，使用 winim/winstr，非常方便，比如 `CreateProcess(+$app, +$cmdline, ...)`，这里的 app 和 cmdline 都是 Nim 的 string 类型。对于出参，可以使用 `array[<length>, TCHAR]`，具体参考项目即可。
* 如果需要动态分配内存，Nim 提供了 alloc/dealloc/realloc，项目里面也用到过，配合 cast 强制类型转换。例如 `cast[PSTRUCT](alloc(size))`。
* 释放资源时使用 defer，相当于 try finally，帮助释放资源，比如：`defer: CloseHandle(hProcess)`。用过 go 的应该比较熟悉这个。
* Nim中的 `.`（访问结构体成员）会隐式解引用。说人话就是，`pStruct.member` 和 `struct.member` 是相同的。
* 调用函数有多种语法，例如 `len x_list` 和 `x_list.len` 都是合法的，`stdout.writeLine("hello")` 和 `writeLine(stdout, "hello")` 也都是合法的，选择自己喜欢的并保持统一即可。
* Nim 中有类似 python 的 f-string，在 std/strformat 中，可以使用 `fmt"id: {id}"` 或 `&"id: {id}"`，区别在于 fmt 不进行转义，前者会原样输出，后者才能输出换行和Tab。
* 使用 when 在编译期生成不同的代码，比如使用 `when defined(windows): import xxx` 来进行跨平台等。
* 可以先将 Nim 代码编译为 C/CPP，然后用 LLVM Pass 进一步处理达到更好的免杀效果。

## 调试

如果前面环境搭建搞得没问题的话，直接在 IDEA 里面下断点就能调试 Client 和 Server 了。这里最重要的问题是我们需要知道在哪里下断点，这里推荐一个系列文章，[CobaltStrike逆向学习系列](https://mp.weixin.qq.com/mp/appmsgalbum?__biz=MzkxMTMxMjI2OQ==&action=getalbum&album_id=2174670809724747778&scene=173&from_msgid=2247483983&from_itemidx=1&count=3&nolastread=1#wechat_redirect)。  
对于 Beacon 端，最简单就是直接 echo 出来，也可以使用 std/sugar 中的 dump。  
我实际开发的时候偷了个懒，没搞懂的地方直接就看看 [GitHub - Z3ratu1/geaconplus](https://github.com/Z3ratu1/geacon_plus) 是咋写的。而且大佬还写了两篇文章 [CobaltStrike beacon二开指南 Z3ratu1's blog](https://blog.z3ratu1.top/CobaltStrike%20beacon%E4%BA%8C%E5%BC%80%E6%8C%87%E5%8D%97.html) 和 [CS DNS beacon二次开发指北 Z3ratu1's blog](https://blog.z3ratu1.top/CS%20DNS%20beacon%E4%BA%8C%E6%AC%A1%E5%BC%80%E5%8F%91%E6%8C%87%E5%8C%97.html) 帮助理解，这里表示真诚感谢，不然还不知道一个个调试起来得写到什么时候。。

## 总结

这个项目写下来，感觉 Nim 作为一门红队开发语言是非常合适的，我就不秀我的浅薄理解了，直接引用 OffensiveNim：

* Compiles *directly* to C, C++, Objective-C and Javascript.
* Since it doesn't rely on a VM/runtime does not produce what I like to call "T H I C C malwarez" as supposed to other languages (e.g. Golang)
* Python inspired syntax, allows rapid native payload creation & prototyping.
* Has **extremely** mature [FFI](https://nim-lang.org/docs/manual.html#foreign-function-interface) (Foreign Function Interface) capabilities.
* Avoids making you actually write in C/C++ and subsequently avoids introducing a lot of security issues into your software.
* Super easy cross compilation to Windows from \*nix/MacOS, only requires you to install the `mingw` toolchain and passing a single flag to the nim compiler.
* The Nim compiler and the generated executables support all major platforms like Windows, Linux, BSD and macOS. Can even compile to Nintendo switch , IOS & Android. See the cross-compilation section in the [Nim compiler usage guide](https://nim-lang.github.io/Nim/nimc.html#crossminuscompilation)
* You could *technically* write your implant and c2 backend both in Nim as you can compile your code directly to Javascript. Even has some [initial support for WebAssembly's](https://forum.nim-lang.org/t/4779)​

不过除此之外我也发现了一些问题：

* 三方库不够丰富，比如写进程/网络操作的时候没有合适的库（psutil-nim 基本没实现啥功能且很久没更新了），导致只能拿 API 撸。如果有时间的话可能会 fork 一下 psutil-nim 把已经实现的一些先放进去。
* IDE 插件不太好用，频繁更新的目前就是官方的 VSCode 插件 nim-lang.org，是我体验过的几个里面最好的了，但是还是存在查找引用慢和内存/CPU占用高的问题，有时需要手动 kill 掉 nimsuggest 进程，和成熟语言的插件比起来还有不小差距。如果哪位哥用过更好用的麻烦踢我一下。  
  瑕不掩瑜，我依然觉得 Nim 挺有前途的。  
  由于我目前的工作并不是端上对抗相关的，项目只能业余时间随缘更新。目前计划了一些内容也写在项目的 README 里面了，欢迎大家 Star，感谢观看。
