# fuzz初战-fuzz Xpdf3.02详解-先知社区

> **来源**: https://xz.aliyun.com/news/17206  
> **文章ID**: 17206

---

## 安装AFL++

### 安装依赖项

```
sudo apt-get update
sudo apt-get install -y build-essential python3-dev automake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools
sudo apt-get install -y lld-11 llvm-11 llvm-11-dev clang-11 || sudo apt-get install -y lld llvm llvm-dev clang 
sudo apt-get install -y gcc-$(gcc --version|head -n1|sed 's/.* //'|sed 's/\..*//')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/.* //'|sed 's/\..*//')-dev
```

### 检验和构建AFL++

```
cd $HOME
git clone https://github.com/AFLplusplus/AFLplusplus && cd AFLplusplus
export LLVM_CONFIG="llvm-config-11"
make distrib
sudo make install
```

输入AFL\_fuzz进行验证

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250309115322442.png)![image.png](images/a5b34f06-df48-3c0b-8a77-279f2acd3838)

AFL 是一个覆盖引导的fuzzer，这意味着它为每个变异的输入收集覆盖信息，可以进行插桩，当源代码可用时，AFL 可以使用检测，在每个基本块（函数、循环等）的开头插入函数调用。

### fuzz使用说明

```
afl-fuzz++4.32a 基于 Michal Zalewski 和一个庞大的在线社区的 afl

afl-fuzz [选项] -- /path/to/fuzzed_app [ ... ]

必需的参数：
-i dir - 测试用例的输入目录（或使用 - 来恢复，也可以参考 AFL_AUTORESUME）
-o dir - 模糊测试结果的输出目录
执行控制设置：
-P strategy - 设置固定的变异策略：explore（专注于新覆盖范围），exploit（专注于触发崩溃）。您还可以设置一个时间（秒），当超过该时间且未发现新结果时，自动切换到 exploit 模式，并在找到新覆盖时返回 explore 模式（默认：1000秒）。
-p schedule - 功率调度计算种子的性能评分：explore（默认）、fast、exploit、seek、rare、mmopt、coe、lin、quad -- 请参阅 docs/FAQ.md 获取更多信息。
-f file - 被模糊程序读取的文件位置（默认：stdin 或 @@）
-t msec - 每次运行的超时时间（自动缩放，默认 1000 毫秒）。加上 + 表示自动计算超时，值为最大值。
-m megs - 子进程的内存限制（0 MB，0 = 无限制 [默认]）
-O - 使用仅二进制的插桩（FRIDA 模式）
-Q - 使用仅二进制的插桩（QEMU 模式）
-U - 使用基于 Unicorn 的插桩（Unicorn 模式）
-W - 使用基于 QEMU 的插桩与 Wine 配合（Wine 模式）
-X - 使用虚拟机模糊测试（NYX 模式 - 独立模式）
-Y - 使用虚拟机模糊测试（NYX 模式 - 多实例模式）
变异器设置：
-a type - 目标输入格式，"text" 或 "binary"（默认：generic）
-g minlength - 设置生成的模糊输入的最小长度（默认：1）
-G maxlength - 设置生成的模糊输入的最大长度（默认：1048576）
-L minutes - 使用 MOpt（优化）模式并设置进入心跳模式的时间限制（无新发现的分钟数）。0 = 立即，-1 = 立即并与正常变异一起进行。 注意：此选项通常效果不大。
-u - 启用测试用例拼接
-c program - 通过指定已编译的二进制文件启用 CmpLog。 如果使用 QEMU/FRIDA 或模糊目标已为 CmpLog 编译，请使用 '-c 0'。禁用 CMPLOG 请使用 '-c -'。
-l cmplog_opts - CmpLog 配置值（例如 "2ATR"）： 1=小文件，2=大文件（默认），3=所有文件， A=算术求解，T=变换求解， X=极限变换求解，R=随机着色字节。
模糊测试行为设置：
-Z - 按顺序选择队列，而不是加权随机
-N - 不解除链接模糊输入文件（用于设备等）
-n - 无插桩模糊测试（非插桩模式）
-x dict_file - 模糊器字典（参见 README.md，可以指定最多 4 次）
-w san_binary - 指定额外的经过 sanitizer 插桩的二进制文件， 可以多次指定。 阅读 docs/SAND.md 获取详细信息。
测试设置：
-s seed - 使用固定的随机种子
-V seconds - 模糊指定时间后终止（仅限模糊时间！）
-E execs - 模糊指定总执行次数后终止 注意：不精确，可能会有更多的执行次数。
其他设置：
-M/-S id - 分布式模式（-M 设置 -Z 并禁用修剪） 请参阅 docs/fuzzing_in_depth.md#c-using-multiple-cores 获取并行模糊测试的有效建议。
-F path - 与外部模糊器队列目录同步（需要 -M，最多可指定 32 次）
-z - 跳过增强的确定性模糊测试 （请注意，旧的 -d 和 -D 标志被忽略。）
-T text - 在屏幕上显示的文本横幅
-I command - 当发现新崩溃时执行此命令/脚本
-C - 崩溃探索模式（秘鲁兔子模式）
-b cpu_id - 将模糊测试进程绑定到指定的 CPU 核心（0-...）
-e ext - 模糊测试输入文件的扩展名（如果需要）
要查看 afl-fuzz 支持的环境变量，请使用 "-hh"。

编译时支持 Python 3.12.3 模块支持，详细信息请参见 docs/custom_mutators.md。
未编译 AFL_PERSISTENT_RECORD 支持。
已编译支持 shmat。
有关更多帮助，请参阅 /usr/local/share/doc/afl/README.md :)
```

## Xpdf编译

```
cd xpdf-3.02
sudo apt update && sudo apt install -y build-essential gcc
./configure --prefix="$HOME/fuzzing_xpdf/install/"
make
make install
```

正常编译之后就可以使用

## Xpdf使用

```
root@muxuecen-VMware-Virtual-Platform:/home/muxuecen/fuzzing_xpdf/install/bin# ./pdfinfo --help
pdfinfo 版本 3.02
版权 1996-2007 Glyph & Cog, LLC
使用方法： pdfinfo [选项] <PDF-文件>
  -f <整数>       : 转换的起始页
  -l <整数>       : 转换的结束页
  -box           : 打印页面边界框
  -meta          : 打印文档元数据（XML格式）
  -enc <字符串>  : 输出文本编码名称
  -opw <字符串>  : 拥有者密码（适用于加密文件）
  -upw <字符串>  : 用户密码（适用于加密文件）
  -cfg <字符串>  : 使用指定的配置文件代替 .xpdfrc
  -v             : 打印版权和版本信息
  -h             : 打印使用信息
  -help          : 打印使用信息
  --help         : 打印使用信息
  -?             : 打印使用信息

```

这里可以看到我们编译成功了 但是这个是没有进行插桩直接编译的 因此我们要删掉 重新用构建XPDF

## **afl-clang-fast** 编译器构建 xpdf

```
export LLVM_CONFIG="llvm-config-11"
CC=$HOME/AFLplusplus/afl-clang-fast CXX=$HOME/AFLplusplus/afl-clang-fast++ ./configure --prefix="$HOME/fuzzing_xpdf/install/"
make
make install
```

## fuzz过程

遇到了一个报错用这个指令就好

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250309122006203.png)![image.png](images/1a5ab6d4-16d2-3f88-8044-1c84435c3b99)

它表明系统的核心转储（core dump）通知已配置为发送到一个外部实用工具

我们关闭核心转储就好

```
echo core >/proc/sys/kernel/core_pattern
```

```
afl-fuzz -i $HOME/fuzzing_xpdf/pdf_examples/ -o $HOME/fuzzing_xpdf/out/ -s 123 -- $HOME/fuzzing_xpdf/install/bin/pdftotext @@ $HOME/fuzzing_xpdf/output
```

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250309121758996.png)![image.png](images/0c8b9f33-a764-3929-ae1b-c740d5664fdc)

大概跑个几分钟就会出现一个crash 我们的fuzz就成功了

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250309122306904.png)![image.png](images/f377d506-1126-318f-8f78-15ca57576efe)

这里是三个crashes 我们可以测试一下 这个是不是会出现崩溃

```
./pdftotext /home/muxuecen/fuzzing_xpdf/out/default/crashes/'id:000001,sig:11,src:001009,time:160099,execs:109316,op:havoc,rep:10' /home/muxuecen/fuzzing_xpdf/install/bin/error
```

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250309123103976.png)

接下来我们就进一步调试跟进分析这个Xpdf的CVE漏洞

先看一下CVE官方描述

```
在 Xpdf 4.01.01 中，Parser.cc 中的 Parser：：getObj（） 函数可能会通过构建的文件导致无限递归。远程攻击者可利用此漏洞进行 DoS 攻击。这与 CVE-2018-16646 类似。
```

接下来删掉之前插桩的Xpdf 重新编译正常并且可以调试的xpdf

```
rm -r $HOME/fuzzing_xpdf/install
cd $HOME/fuzzing_xpdf/xpdf-3.02/
make clean
CFLAGS="-g -O0" CXXFLAGS="-g -O0" ./configure --prefix="$HOME/fuzzing_xpdf/install/"
make
make install
```

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250309124821279.png)![image.png](images/801673ff-4722-3b04-976f-d15f1c5ea3a7)

直接c发现程序卡在了这个位置 此时已经崩溃出现错误 然后看一下函数调用栈发现

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250309124920357.png)![image.png](images/eede52d0-6983-36a6-8385-a41e89d737c4)

如果CVE描述的一样在无限制的递归

我们通过一步步调试去查看原因

先静态分析看流程

```
............前面是一些验证参数
uMap = GlobalParams::getTextEncoding(globalParams);
if ( uMap )
  {
    if ( ownerPassword[0] == 1 )
    {
      ownerPW = 0LL;
    }
    else
    {
      v6 = (GString *)operator new(0x10uLL);
      GString::GString(v6, ownerPassword);
      ownerPW = v6;
    }
    if ( userPassword[0] == 1 )
    {
      userPW = 0LL;
    }
    else
    {
      v7 = (GString *)operator new(0x10uLL);
      GString::GString(v7, userPassword);
      userPW = v7;
    }
    v8 = (PDFDoc *)operator new(0x48uLL);
    PDFDoc::PDFDoc(v8, fileName, ownerPW, userPW, 0LL);
```

这里因为我们这个xpdf 是没有设置密码的 所以ownerpassword和userpassword 都是0 然后进入PDFDoc

```
PDFDoc::PDFDoc(GString *fileNameA, GString *ownerPassword,
           GString *userPassword, void *guiDataA) {
  Object obj;
  GString *fileName1, *fileName2;

  ok = gFalse;
  errCode = errNone;

  guiData = guiDataA;

  file = NULL;
  str = NULL;
  xref = NULL;
  catalog = NULL;
#ifndef DISABLE_OUTLINE
  outline = NULL;
#endif

  fileName = fileNameA;
  fileName1 = fileName;


  // try to open file
  fileName2 = NULL;
#ifdef VMS
  if (!(file = fopen(fileName1->getCString(), "rb", "ctx=stm"))) {
    error(-1, "Couldn't open file '%s'", fileName1->getCString());
    errCode = errOpenFile;
    return;
  }
#else
  if (!(file = fopen(fileName1->getCString(), "rb"))) {
    fileName2 = fileName->copy();
    fileName2->lowerCase();
    if (!(file = fopen(fileName2->getCString(), "rb"))) {
      fileName2->upperCase();
      if (!(file = fopen(fileName2->getCString(), "rb"))) {
    error(-1, "Couldn't open file '%s'", fileName->getCString());
    delete fileName2;
    errCode = errOpenFile;
    return;
      }
    }
    delete fileName2;
  }
#endif

  // create stream
  obj.initNull();
  str = new FileStream(file, 0, gFalse, 0, &obj);

  ok = setup(ownerPassword, userPassword);
}
```

这里基本就是会通过一次修改为小写大写来判断文件是否存在 如果存在的化就进入setup这部分

```
GBool PDFDoc::setup(GString *ownerPassword, GString *userPassword) {
  str->reset();

  // check header
  checkHeader();

  // read xref table
  xref = new XRef(str);
  if (!xref->isOk()) {
    error(-1, "Couldn't read xref table");
    errCode = xref->getErrorCode();
    return gFalse;
  }

  // check for encryption
  if (!checkEncryption(ownerPassword, userPassword)) {
    errCode = errEncrypted;
    return gFalse;
  }

  // read catalog
  catalog = new Catalog(xref);
  if (!catalog->isOk()) {
    error(-1, "Couldn't read page catalog");
    errCode = errBadCatalog;
    return gFalse;
  }

#ifndef DISABLE_OUTLINE
  // read outline
  outline = new Outline(catalog->getOutline(), xref);
#endif

  // done
  return gTrue;
}

```

这部分检测你的header 和 xref 表 还有catalog

简单介绍一下

`Catalog`是 PDF 文件结构中的一个重要对象，它是 PDF 文档的根目录对象，通常位于 PDF 文件的最顶层，负责指向文档的其他重要部分。PDF 文件的结构是层次化的， 就是其中的“根”对象

交叉引用表（xref table）是 PDF 文件中的一个重要结构，它用于描述文件中的对象如何相互引用。

这部分也基本是一些检测 我们继续走

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250309190033839.png)![image.png](images/c98519ae-c992-372b-a95b-2f0585ca004b)

```
void PDFDoc::displayPages(OutputDev *out, int firstPage, int lastPage,
              double hDPI, double vDPI, int rotate,
              GBool useMediaBox, GBool crop, GBool printing,
              GBool (*abortCheckCbk)(void *data),
              void *abortCheckCbkData) {
  int page;

  for (page = firstPage; page <= lastPage; ++page) {
    displayPage(out, page, hDPI, vDPI, rotate, useMediaBox, crop, printing,
        abortCheckCbk, abortCheckCbkData);
  }
}
```

　　也就是对于 pdf 中的每一页，调用 `displayPage` 将其转文字输出。跟进 `displayPage` ：

```
void PDFDoc::displayPage(OutputDev *out, int page,
             double hDPI, double vDPI, int rotate,
             GBool useMediaBox, GBool crop, GBool printing,
             GBool (*abortCheckCbk)(void *data),
             void *abortCheckCbkData) {
  if (globalParams->getPrintCommands()) {
    printf("***** page %d *****
", page);
  }
  catalog->getPage(page)->display(out, hDPI, vDPI,
                  rotate, useMediaBox, crop, printing, catalog,
                  abortCheckCbk, abortCheckCbkData);
}
```

catalog->getPage(page)来获取页码 我们这里只有一页所以是1 然后执行 Page:display

　　是直接调用 `displaySlice` 输出。跟进：

```
void Page::displaySlice(OutputDev *out, double hDPI, double vDPI,
            int rotate, GBool useMediaBox, GBool crop,
            int sliceX, int sliceY, int sliceW, int sliceH,
            GBool printing, Catalog *catalog,
            GBool (*abortCheckCbk)(void *data),
            void *abortCheckCbkData) {
#ifndef PDF_PARSER_ONLY
  PDFRectangle *mediaBox, *cropBox;
  PDFRectangle box;
  Gfx *gfx;
  Object obj;
  Annots *annotList;
  Dict *acroForm;
  int i;

  if (!out->checkPageSlice(this, hDPI, vDPI, rotate, useMediaBox, crop,
               sliceX, sliceY, sliceW, sliceH,
               printing, catalog,
               abortCheckCbk, abortCheckCbkData)) {
    return;
  }

  rotate += getRotate();
  if (rotate >= 360) {
    rotate -= 360;
  } else if (rotate < 0) {
    rotate += 360;
  }

  makeBox(hDPI, vDPI, rotate, useMediaBox, out->upsideDown(),
      sliceX, sliceY, sliceW, sliceH, &box, &crop);
  cropBox = getCropBox();

  if (globalParams->getPrintCommands()) {
    mediaBox = getMediaBox();
    printf("***** MediaBox = ll:%g,%g ur:%g,%g
",
       mediaBox->x1, mediaBox->y1, mediaBox->x2, mediaBox->y2);
    printf("***** CropBox = ll:%g,%g ur:%g,%g
",
       cropBox->x1, cropBox->y1, cropBox->x2, cropBox->y2);
    printf("***** Rotate = %d
", attrs->getRotate());
  }

  gfx = new Gfx(xref, out, num, attrs->getResourceDict(),
        hDPI, vDPI, &box, crop ? cropBox : (PDFRectangle *)NULL,
        rotate, abortCheckCbk, abortCheckCbkData);
  contents.fetch(xref, &obj);
  
  
  if (!obj.isNull()) {
    gfx->saveState();
    gfx->display(&obj);
    gfx->restoreState();
  }
  obj.free();

  // draw annotations
  annotList = new Annots(xref, catalog, getAnnots(&obj));
  obj.free();
  acroForm = catalog->getAcroForm()->isDict() ?
               catalog->getAcroForm()->getDict() : NULL;
  if (acroForm) {
    if (acroForm->lookup("NeedAppearances", &obj)) {
      if (obj.isBool() && obj.getBool()) {
    annotList->generateAppearances(acroForm);
      }
    }
    obj.free();
  }
  if (annotList->getNumAnnots() > 0) {
    if (globalParams->getPrintCommands()) {
      printf("***** Annotations
");
    }
    for (i = 0; i < annotList->getNumAnnots(); ++i) {
      annotList->getAnnot(i)->draw(gfx, printing);
    }
    out->dump();
  }
  delete annotList;

  delete gfx;
#endif
}
```

在调试过程中 是在这一段导致的 contents.fetch(xref, &obj); 无限递归

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250309222858317.png)![image.png](images/d79e4a03-c4b4-3259-b5c9-078f357e06d9)

content是object， `Ref` 二元组为 (num=7, gen=0）

我们这里可以分析一下函数调用连 有一个思路是 在确定已经会循坏的位置断点 连续c几次 这样可以保证有循坏节追踪的同时 程序不会崩溃

```
#30 0x000055555559cfe4 in Dict::lookup (this=0x5555556d3cc0, key=0x55555564fa7f "Length", obj=0x7fffffffba00) at Dict.cc:76
#31 0x00005555555fcaad in Object::dictLookup (this=0x7fffffffbcd0, key=0x55555564fa7f "Length", obj=0x7fffffffba00) at /home/muxuecen/fuzzing_xpdf/xpdf-3.02/xpdf/Object.h:253
#32 0x0000555555601337 in Parser::makeStream (this=0x5555556d3940, dict=0x7fffffffbcd0, fileKey=0x0, encAlgorithm=cryptRC4, keyLength=0, objNum=7, objGen=0) at Parser.cc:156
#33 0x0000555555600ec7 in Parser::getObj (this=0x5555556d3940, obj=0x7fffffffbcd0, fileKey=0x0, encAlgorithm=cryptRC4, keyLength=0, objNum=7, objGen=0) at Parser.cc:94
#34 0x0000555555625951 in XRef::fetch (this=0x5555556ce630, num=7, gen=0, obj=0x7fffffffbcd0) at XRef.cc:823
#35 0x00005555555fbdd6 in Object::fetch (this=0x5555556d3838, xref=0x5555556ce630, obj=0x7fffffffbcd0) at Object.cc:106
#36 0x000055555559cfe4 in Dict::lookup (this=0x5555556d37e0, key=0x55555564fa7f "Length", obj=0x7fffffffbcd0) at Dict.cc:76
#37 0x00005555555fcaad in Object::dictLookup (this=0x7fffffffbfa0, key=0x55555564fa7f "Length", obj=0x7fffffffbcd0) at /home/muxuecen/fuzzing_xpdf/xpdf-3.02/xpdf/Object.h:253
#38 0x0000555555601337 in Parser::makeStream (this=0x5555556d3460, dict=0x7fffffffbfa0, fileKey=0x0, encAlgorithm=cryptRC4, keyLength=0, objNum=7, objGen=0) at Parser.cc:156
#39 0x0000555555600ec7 in Parser::getObj (this=0x5555556d3460, obj=0x7fffffffbfa0, fileKey=0x0, encAlgorithm=cryptRC4, keyLength=0, objNum=7, objGen=0) at Parser.cc:94
#40 0x0000555555625951 in XRef::fetch (this=0x5555556ce630, num=7, gen=0, obj=0x7fffffffbfa0) at XRef.cc:823
#41 0x00005555555fbdd6 in Object::fetch (this=0x5555556d3358, xref=0x5555556ce630, obj=0x7fffffffbfa0) at Object.cc:106
```

可以看出是

Object::fetch --> XRef::fetch --> Parser::getObj --> Parser::makeStream --> Object::dictLookup--> Dict :: lookup --> Object::fetch

我们照着这个思路去跟进 可以加快我们的调试速度

Object::fetch

```
Object *Object::fetch(XRef *xref, Object *obj) {
  return (type == objRef && xref) ?
         xref->fetch(ref.num, ref.gen, obj) : copy(obj);
}
```

这里的type就是objRef 还记得我们ptype看的contents吗 是object类型的 因此我们用\*Object::fetch(XRef \*xref, Object \*obj)调用的时候 其实是用的contents的变量

XRef::fetch

```
bject *XRef::fetch(int num, int gen, Object *obj) {
  XRefEntry *e;
  Parser *parser;
  Object obj1, obj2, obj3;

  // check for bogus ref - this can happen in corrupted PDF files
  if (num < 0 || num >= size) {
    goto err;
  }

  e = &entries[num];
  switch (e->type) {

  case xrefEntryUncompressed:
    if (e->gen != gen) {
      goto err;
    }
    obj1.initNull();
    parser = new Parser(this,
           new Lexer(this,
         str->makeSubStream(start + e->offset, gFalse, 0, &obj1)),
           gTrue);
    parser->getObj(&obj1);
    parser->getObj(&obj2);
    parser->getObj(&obj3);
    if (!obj1.isInt() || obj1.getInt() != num ||
    !obj2.isInt() || obj2.getInt() != gen ||
    !obj3.isCmd("obj")) {
      obj1.free();
      obj2.free();
      obj3.free();
      delete parser;
      goto err;
    }
    parser->getObj(obj, encrypted ? fileKey : (Guchar *)NULL,
           encAlgorithm, keyLength, num, gen);
    obj1.free();
    obj2.free();
    obj3.free();
    delete parser;
    break;

  case xrefEntryCompressed:
    if (gen != 0) {
      goto err;
    }
    if (!objStr || objStr->getObjStrNum() != (int)e->offset) {
      if (objStr) {
    delete objStr;
      }
      objStr = new ObjectStream(this, e->offset);
    }
    objStr->getObject(e->gen, num, obj);
    break;

  default:
    goto err;
  }

  return obj;

 err:
  return obj->initNull();
}

```

Parser::getObj

```
Object *Parser::getObj(Object *obj, Guchar *fileKey,
               CryptAlgorithm encAlgorithm, int keyLength,
               int objNum, int objGen) {
  char *key;
  Stream *str;
  Object obj2;
  int num;
  DecryptStream *decrypt;
  GString *s, *s2;
  int c;

  // refill buffer after inline image data
  if (inlineImg == 2) {
    buf1.free();
    buf2.free();
    lexer->getObj(&buf1);
    lexer->getObj(&buf2);
    inlineImg = 0;
  }

  // array
  if (buf1.isCmd("[")) {
    shift();
    obj->initArray(xref);
    while (!buf1.isCmd("]") && !buf1.isEOF())
      obj->arrayAdd(getObj(&obj2, fileKey, encAlgorithm, keyLength,
               objNum, objGen));
    if (buf1.isEOF())
      error(getPos(), "End of file inside array");
    shift();

  // dictionary or stream
  } else if (buf1.isCmd("<<")) {
    shift();
    obj->initDict(xref);
    while (!buf1.isCmd(">>") && !buf1.isEOF()) {
      if (!buf1.isName()) {
    error(getPos(), "Dictionary key must be a name object");
    shift();
      } else {
    key = copyString(buf1.getName());
    shift();
    if (buf1.isEOF() || buf1.isError()) {
      gfree(key);
      break;
    }
    obj->dictAdd(key, getObj(&obj2, fileKey, encAlgorithm, keyLength,
                 objNum, objGen));
      }
    }
    if (buf1.isEOF())
      error(getPos(), "End of file inside dictionary");
    // stream objects are not allowed inside content streams or
    // object streams
    if (allowStreams && buf2.isCmd("stream")) {
      if ((str = makeStream(obj, fileKey, encAlgorithm, keyLength,
                objNum, objGen))) {
    obj->initStream(str);
      } else {
    obj->free();
    obj->initError();
      }
    } else {
      shift();
    }

  // indirect reference or integer
  } else if (buf1.isInt()) {
    num = buf1.getInt();
    shift();
    if (buf1.isInt() && buf2.isCmd("R")) {
      obj->initRef(num, buf1.getInt());
      shift();
      shift();
    } else {
      obj->initInt(num);
    }

  // string
  } else if (buf1.isString() && fileKey) {
    s = buf1.getString();
    s2 = new GString();
    obj2.initNull();
    decrypt = new DecryptStream(new MemStream(s->getCString(), 0,
                          s->getLength(), &obj2),
                fileKey, encAlgorithm, keyLength,
                objNum, objGen);
    decrypt->reset();
    while ((c = decrypt->getChar()) != EOF) {
      s2->append((char)c);
    }
    delete decrypt;
    obj->initString(s2);
    shift();

  // simple object
  } else {
    buf1.copy(obj);
    shift();
  }

  return obj;
}
```

Parser::makeStream

```
Stream *Parser::makeStream(Object *dict, Guchar *fileKey,
               CryptAlgorithm encAlgorithm, int keyLength,
               int objNum, int objGen) {
  Object obj;
  BaseStream *baseStr;
  Stream *str;
  Guint pos, endPos, length;

  // get stream start position
  lexer->skipToNextLine();
  pos = lexer->getPos();

  // get length
  dict->dictLookup("Length", &obj);
  if (obj.isInt()) {
    length = (Guint)obj.getInt();
    obj.free();
  } else {
    error(getPos(), "Bad 'Length' attribute in stream");
    obj.free();
    return NULL;
  }

  // check for length in damaged file
  if (xref && xref->getStreamEnd(pos, &endPos)) {
    length = endPos - pos;
  }

  // in badly damaged PDF files, we can run off the end of the input
  // stream immediately after the "stream" token
  if (!lexer->getStream()) {
    return NULL;
  }
  baseStr = lexer->getStream()->getBaseStream();

  // skip over stream data
  lexer->setPos(pos + length);

  // refill token buffers and check for 'endstream'
  shift();  // kill '>>'
  shift();  // kill 'stream'
  if (buf1.isCmd("endstream")) {
    shift();
  } else {
    error(getPos(), "Missing 'endstream'");
    // kludge for broken PDF files: just add 5k to the length, and
    // hope its enough
    length += 5000;
  }

  // make base stream
  str = baseStr->makeSubStream(pos, gTrue, length, dict);

  // handle decryption
  if (fileKey) {
    str = new DecryptStream(str, fileKey, encAlgorithm, keyLength,
                objNum, objGen);
  }

  // get filters
  str = str->addFilters(dict);

  return str;
}
```

dict->dictLookup("Length", &obj);这里是通过查找Length然后赋值给obj

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250310005120523.png)![image.png](images/b5a5df21-aad2-35c9-bcc8-1018f45fd19a)

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250310005136492.png)![image.png](images/cae95401-0a1b-34b5-aebf-873275f1062d)

dictLookup的参数也就是dict的变量

```
   252 inline Object *Object::dictLookup(char *key, Object *obj)
 ► 253   { return dict->lookup(key, obj); }
```

Dict :: lookup

```
Object *Dict::lookup(char *key, Object *obj) {
  DictEntry *e;

  return (e = find(key)) ? e->val.fetch(xref, obj) : obj->initNull();
}

```

这里也是关键点 可以看到e->val也是object类型 并且此时的二元组为num=7 gen=0

## image.png

继续跟进发现：

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250310005908166.png)![image.png](images/7062be67-f61d-37d9-8479-b406b9540166)

实际调用的是 `xref->fetch(7, 0, &newobj)`，和我们一开始调用的一样 至此形成闭环

递归链条：

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250310011248545.png)![image.png](images/b734cb72-bbea-3b39-a0fb-4a89db0a580f)

## 修复

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250310131945592.png)

可以看到官方修复是把循坏加了一个限制 循坏到一定次数就会跳转

![image.png](images/3d41656a-5f29-39b5-9f40-b512f3ad1c74)

​
