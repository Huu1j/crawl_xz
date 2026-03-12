# fuzz模糊测试libexif详细解析-先知社区

> **来源**: https://xz.aliyun.com/news/17255  
> **文章ID**: 17255

---

## libexif介绍

```
  libexif是一个用于解析、编辑和保存EXIF数据的库。它支持EXIF 2.1标准(以及2.2中的大多数)中描述的所有EXIF标签。它是用纯C语言编写的，不需要任何额外的库
```

## 漏洞介绍

```
CVE-2009-3895
在 libexif 0.6.18 的 libexif/exif-entry.c 中，exif_entry_fix函数（又称标记修复例程）中存在基于堆的缓冲区溢出，可允许远程攻击者通过无效的 EXIF 图像造成拒绝服务或可能执行任意代码。注意：其中一些详细信息是从第三方信息中获得的。
```

## 环境搭建

### libexif环境搭建

```
wget https://sourceforge.net/projects/libexif/files/libexif/0.6.14/libexif-0.6.14.tar.gz
tar -xzvf libexif-0.6.14.tar.gz
```

```
sudo apt-get install autopoint libtool gettext libpopt-dev
autoreconf -fvi		# 自动生成 Makefile
./configure  --prefix="路径" --disable-dls
make
make install
```

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250312213539873.png)

![image.png](https://xz.aliyun.com/api/v2/files/d92e4111-47ec-31af-bc86-1492340e6a0f)

搭建libexif成功

### exif环境搭建

```
autoreconf -fvi
 ./configure --prefix="/home/muxuecen/fuzz101/libxif/install/exif-0.6.18/install" --disable-dls
make
make install
```

第一次的时候报错了 缺少popt

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250312214945479.png)![image.png](images/bbbf5000-690d-3caa-9af1-290d036488c9)

安装一下再执行就可以了

```
sudo apt-get install libpopt-dev
```

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250312215203048.png)![image.png](https://xz.aliyun.com/api/v2/files/1ce28018-cd5b-357c-9913-b3272b7afd7b)

现在我们的环境就搭建完成了

## 漏洞分析-踩坑

以下是我的踩坑经历(想看正确分析 请跳转漏洞分析-正确)

根据漏洞描述可以发现在exif\_entry\_fix函数中

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250313091854455.png)![image.png](images/80294959-3184-3e17-ac67-958c2f17a77f)

去静态分析加漏扫 定位到： ps(后面根据crashes分析 发现漏扫定位错了 当个思路参考一下)

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250313091950800.png)![image.png](images/ddd1b059-6339-38e2-863e-6115cd71c93a)

![image.png](images/c94fee09-d6dd-3f9a-ada9-ff8ec4e83625)

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250313092530688.png)![image.png](https://xz.aliyun.com/api/v2/files/905d3cb7-7181-3fe6-a841-4d7d9f27991c)

接下来用`afl-clang-lto`重新编译：

libexif

```
sudo rm -rf install
make clean
CC=afl-clang-lto ./configure  --prefix="/home/muxuecen/fuzz101/libxif/install/libexif-libexif-0_6_18-release/install" --disable-nls
make
make install
```

exif

```
sudo rm -rf install
make clean
CC=afl-clang-lto ./configure --enable-shared=no --prefix="/home/muxuecen/fuzz101/libxif/install/exif-0.6.18/install" --disable-nls
make
make install
```

开始fuzz

```
afl-fuzz -i ~/fuzz101/libxif/install/sample/exif-samples/jpg/ -o ~/fuzz101/libxif/install/exif-0.6.18/install/bin/out -s 123 -- ./exif @@

```

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250313172845010.png)![image.png](images/40eb65db-8004-3854-bb36-09277901c0e0)

验证之后发现确实把程序打崩了 我们这里通过调试去看一下

![image.png](images/fac8bb0a-a1b4-33ad-8761-ad10ec638229)

从这个调用栈可以看出来 exif\_entry\_fix - > exif\_entry\_realloc 导致的报错

继续跟踪发现就三个地方调用了 exif\_entry\_realloc 分别断点看逻辑发现最后是断在了0x014D9D这个位置 帮助我们更好的分析

但是跟进到后面 我感觉 非常的怪异 因为是进入realloc导致分配地址不对而形成的中止，并不符合上面两条CVE的描述 仔细看了一下 发现是我crash太少了 这可能是因为我只fuzz几分钟的原因....... 有点太急着调了 但是还是不对 跑了1小时还是有问题 并没有和cve描述的报错一样

这里踩坑发现是用的0.6.18版本去弄的 如果要复现的话建议是用0.6.14

## 漏洞分析-正确

换版本重新编译 具体指令和上面一样

这里提一个小tips虽然麻烦但会方便我们调试 此时已经有了crash能导致崩溃的样本 此时我们尽量不要用插桩的代码去分析了 利用已有样本 去调试正常编译的 会比较方便

我们可以通过下面的图直观的看出插桩对代码审计造成的影响、

fuzz前

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250313102057329.png)![image.png](https://xz.aliyun.com/api/v2/files/b674903e-26c2-3b2c-92a7-62c952a76218)

fuzz后

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250313102034851.png)![image.png](images/3051ff3c-f2cd-3f95-8936-48753e2afd9f)

这回fuzz了一个小时：

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250313195350447.png)![image.png](https://xz.aliyun.com/api/v2/files/fa111436-4b56-34b1-8d8d-04c4481a008d)

fuzz出了三个 测试一下

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250313195458786.png)![image.png](images/5ae9e9b1-bcb4-3483-8b71-d1a375ddba48)

并且分别看了几个样本

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250313195706618.png)![image.png](images/e98c5fa7-82d2-326e-9281-d2c1dadcaf2d)

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250313195822430.png)![image.png](https://xz.aliyun.com/api/v2/files/7584155f-4242-3cf0-9d44-a2faef61a303)

发现这回没啥问题了 然后我们把样本都保存下来 最后 正常编译进行分析

先对第二个样本进行分析

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250313201437025.png)![image.png](images/f69b247d-dab9-33bb-9c95-48202a0224c6)

## 调用链二分析

main->->exif\_data\_load\_data->exif\_data\_load\_data\_content->memcpy\_xxx

通过漏扫快速定位

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250313205713521.png)![image.png](https://xz.aliyun.com/api/v2/files/944a3be4-192b-31f2-812f-d6706b98fe0a)

问题就在memcpy这里

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250313203729060.png)![image.png](images/51944052-54d4-3758-ba67-6649c07b47b5)

这里exif\_data\_alloc是自定义的一个创建堆块 这里v35是堆地址 我们直接断点断到这里可以发现 memcpy了多次 最后一次在0x21这个位置 出现了一字节溢出

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250313205027300.png)![image.png](images/a67f1f13-8c52-3c26-9830-5769727e84f2)

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250313205046240.png)![image.png](images/9a03d9f0-e760-357a-8efa-8f7ccffeae55)

这条路线的成因基本就到这里 但要是就这么结束了 那功利性就有点太强了，我们仔细去分析一下整个路线的逻辑 以及什么参数导致的这个漏洞产生

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250313221340799.png)![image.png](images/dfcfbe6b-7b63-3ff9-85da-946c57e7b98e)

这里分别设置了本地日志 然后取出参数 并且把这个参数进行检测 如果小于等于1 就弹出 帮助也就是--help的输出 然后

处理 IFD 字符串，使用 将字符串转换为 IFD 类型，并检查该 IFD 是否有效。如果无效，记录一条日志。`exif_ifd_from_string`

处理 EXIF 标签字符串，将其转换为实际的 EXIF 标签。如果标签无效，则记录错误日志。

这里加一点IFD和EXIF这方面的知识补充

```
1. IFD（Image File Directory）字符串
IFD是一个目录结构，用来存储和组织图像文件中的各种元数据。每个IFD包含多个条目，每个条目都指向一个特定的元数据标签（Tag）。这些标签包含关于图像的信息，如拍摄时间、设备型号、曝光时间、GPS信息等。

在EXIF数据中，IFD可以看作是一个容器，它将相关的元数据标签组合在一起。不同类型的IFD存储不同种类的元数据，常见的IFD包括：

0 IFD：存储图像的基本信息，例如图像的宽度和高度。
1 IFD：存储图像的EXIF数据，比如相机的设置、曝光时间、ISO等。
EXIF IFD：存储与图像相关的EXIF元数据，如拍摄设备、拍摄参数等。
GPS IFD：存储图像的地理位置信息，例如经度、纬度、高度等。
Interoperability IFD：存储用于EXIF数据互作的信息。
在代码中，IFD字符串如， ， ， 等用来指定要访问的特定IFD。"0""1""EXIF""GPS"

2. Exif标签（Exif Tag）
Exif标签是EXIF数据格式中的基本元素，用于存储图像的元数据。每个标签代表一个具体的元数据项，例如图像的拍摄日期、相机型号、镜头信息等。标签在EXIF数据中是通过整数标识的，每个标签都有一个唯一的编号。

常见的Exif标签包括：

拍摄日期和时间（Tag 0x9003）：记录图像拍摄的日期和时间。
相机型号（Tag 0x0110）：记录拍摄图像的相机型号。
曝光时间（Tag 0x829a）：记录图像的曝光时间。
ISO（Tag 0x8827）：记录图像拍摄时使用的ISO感光度。
GPS信息（Tag 0x0000等）：记录图像拍摄时的地理坐标。
在代码中，是将标签名称（如“ISO”）或标签值（如“0x829a”）转换为对应的标签ID，并进行处理。exif_tag_from_string(tag_string)
```

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250313222026469.png)![image.png](images/6817ba41-343b-35d3-b48f-275ae68c6468)

这个是-s指令

```
获取并显示与某个EXIF标签相关的描述、名称、标题等信息。
通过调用 , , 和 等函数来获取不同的标签元数据。exif_tag_get_description_in_ifdexif_tag_get_name_in_ifdexif_tag_get_title_in_ifd
转换字符编码（从UTF-8到LAT1）。
格式化并输出标签的详细信息。
```

然后就进到了这个部分

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250313222829517.png)![image.png](images/8a99cf0a-e546-308c-b389-581162084ad3)

前面是创建一个内存管理实例 和 日志 然后把内容写入到创建的实例中

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250313223827023.png)![image.png](https://xz.aliyun.com/api/v2/files/1508b177-1f5e-3b3e-8eb3-13c13e1f077b)

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250313223929373.png)![image.png](images/8f77c551-2ec9-3f52-b973-7cfc3dbe0006)

这里和上面的逻辑基本一样 都是创建一个实例 然后读入日志 和 内容

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250313224104057.png)![image.png](images/5e5e0771-bb57-33af-9d20-4f1de46023c6)

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250313224543638.png)![image.png](images/67e1f2bd-6f13-3055-9e30-e9b8212bb66b)

这里的话就是检测你loader的几个部分 buf bytes 是否都有 况且还有对字节的限制 如果太小会报错

```
  if ( *(_DWORD *)d_orig != 1718188101 || *((_WORD *)d_orig + 2) )
  {
    while ( 1 )
    {
      v7 = *v5;
      if ( *v5 == 0xFF )
      {
LABEL_13:
        if ( !v6 )
        {
LABEL_14:
          v10 = "EXIF marker not found.";
          goto LABEL_15;
        }
      }
      else
      {
        while ( v7 != 0xD8 )
        {
          if ( v7 != 0xE0 )
          {
            if ( v7 != 0xE1 )
              goto LABEL_14;
            if ( v6 - 1 > 1 )
            {
              v6 -= 3;
              exif_log(
                data->priv->log,
                EXIF_LOG_CODE_DEBUG,
                "ExifData",
                "We have to deal with %i byte(s) of EXIF data.",
                (unsigned __int16)__ROL2__(*(_WORD *)(v5 + 1), 8));
              if ( v6 > 5 )
              {
                v5 += 3;
                goto LABEL_19;
              }
            }
            goto LABEL_23;
          }
          v8 = v6 - 1;
          v9 = (unsigned __int16)__ROL2__(*(_WORD *)(v5 + 1), 8);
          if ( v8 < (unsigned __int16)v9 )
            return;
          v6 = v8 - v9;
          v5 += v9 + 1;
          v7 = *v5;
          if ( *v5 == 0xFF )
            goto LABEL_13;
        }
      }
      ++v5;
      --v6;
    }
  }
  exif_log(data->priv->log, EXIF_LOG_CODE_DEBUG, "ExifData", "Found EXIF header.");
LABEL_19:
  if ( *(_DWORD *)v5 != 1718188101 || *((_WORD *)v5 + 2) )
  {
    v10 = "EXIF header not found.";
    goto LABEL_15;
  }
  exif_log(data->priv->log, EXIF_LOG_CODE_DEBUG, "ExifData", "Found EXIF header.");
  if ( v6 <= 0xD )
    return;
  if ( *((_WORD *)v5 + 3) != 18761 )
  {
    if ( *((_WORD *)v5 + 3) == 19789 )
    {
      v13 = EXIF_BYTE_ORDER_MOTOROLA;
      data->priv->order = EXIF_BYTE_ORDER_MOTOROLA;
      goto LABEL_28;
    }
    v10 = "Unknown encoding.";
LABEL_15:
    v11 = dcgettext("libexif-12", v10, 5);
    log = data->priv->log;
LABEL_16:
    exif_log(log, EXIF_LOG_CODE_CORRUPT_DATA, "ExifData", v11);
    return;
  }
  v13 = EXIF_BYTE_ORDER_INTEL;
  data->priv->order = EXIF_BYTE_ORDER_INTEL;
LABEL_28:
  if ( exif_get_short(v5 + 8, v13) != 42 )
    return;
  v14 = v6 - 6;
  v15 = exif_get_long(v5 + 10, data->priv->order);
  exif_log(data->priv->log, EXIF_LOG_CODE_DEBUG, "ExifData", "IFD 0 at %i.", v15);
  exif_data_load_data_content(data, EXIF_IFD_0, v5 + 6, v6 - 6, v15, 0);
  if ( v6 < (int)v15 + 8 )
    return;
  v16 = 12 * exif_get_short(&v5[(unsigned int)v15 + 6], data->priv->order);
  if ( v6 < (int)v15 + v16 + 12 )
    return;
  v17 = exif_get_long(&v5[(unsigned int)v15 + 8 + (__int64)v16], data->priv->order);
  v18 = v17;
  if ( !v17 )
    goto LABEL_34;
  exif_log(data->priv->log, EXIF_LOG_CODE_DEBUG, "ExifData", "IFD 1 at %i.", v17);
  if ( v14 < v18 )
  {
    v11 = "Bogus offset.";
    log = data->priv->log;
    goto LABEL_16;
  }
```

上面这代码 就是各种检测和输出

```
void __fastcall exif_data_load_data_content(
        ExifData *data,
        ExifIfd ifd,
        const unsigned __int8 *d,
        unsigned int ds_0,
        unsigned int offset,
        unsigned int recursion_depth)
{
  ExifDataPrivate *priv; // rax
  __int64 v9; // rbp
  ExifShort v10; // ax
  unsigned int v11; // r12d
  unsigned int v12; // r8d
  unsigned int v13; // r9d
  unsigned int v14; // r14d
  ExifShort v15; // ax
  unsigned int v16; // r12d
  ExifLong v17; // r15d
  ExifDataPrivate *v18; // rax
  ExifEntry *v19; // r12
  ExifLong v20; // eax
  ExifTag tag; // edi
  const char *v22; // rax
  unsigned int v23; // edx
  ExifLong v24; // r10d
  unsigned int v25; // ecx
  unsigned int v26; // eax
  unsigned int v27; // eax
  ExifIfd v28; // edi
  const char *v29; // rax
  unsigned int v30; // eax
  const char *v31; // rax
  const char *v32; // rax
  unsigned int v33; // eax
  ExifLong v34; // eax
  unsigned __int8 *v35; // rax
  unsigned int v36; // r10d
  ExifIfd v37; // edi
  const char *name; // rax
  unsigned __int8 *v39; // rax
  unsigned int ds_0b; // [rsp+4h] [rbp-54h]
  unsigned int recursion_depthb; // [rsp+8h] [rbp-50h]
  unsigned int na; // [rsp+Ch] [rbp-4Ch]
  ExifLong n; // [rsp+Ch] [rbp-4Ch]
  ExifLong thumbnail_offset; // [rsp+10h] [rbp-48h]
  unsigned int v47; // [rsp+14h] [rbp-44h]
  unsigned int v48; // [rsp+18h] [rbp-40h]
  unsigned int v49; // [rsp+18h] [rbp-40h]
  unsigned int v50; // [rsp+18h] [rbp-40h]
  int v51; // [rsp+1Ch] [rbp-3Ch]

  if ( data )
  {
    priv = data->priv;
    if ( priv )
    {
      if ( recursion_depth == 151 )
      {
        exif_log(priv->log, EXIF_LOG_CODE_CORRUPT_DATA, "ExifData", "Deep recursion detected!", offset);
      }
      else if ( offset < ds_0 - 1 )
      {
        v9 = offset + 2;
        v10 = exif_get_short(&d[offset], priv->order);
        na = v10;
        LOWORD(v11) = v10;
        exif_log(data->priv->log, EXIF_LOG_CODE_DEBUG, "ExifData", "Loading %i entries...", v10);
        v12 = na;
        v13 = recursion_depth;
        if ( ds_0 < (unsigned int)v9 + 12 * na )
        {
          v11 = (ds_0 - (unsigned int)v9) / 0xC;
          v12 = (unsigned __int16)v11;
        }
        if ( (_WORD)v11 )
        {
          n = 0;
          v14 = 0;
          thumbnail_offset = 0;
          recursion_depthb = ds_0;
          v47 = v13;
          ds_0b = v12;
          while ( 1 )
          {
            v15 = exif_get_short(&d[v9], data->priv->order);
            v16 = v15;
            if ( v15 == 0x8825 )
              break;
            if ( v15 > 0x8825u )
            {
              if ( v15 == 0xA005 )
              {
                v27 = exif_get_long(&d[v9 + 8], data->priv->order);
                if ( ifd == EXIF_IFD_INTEROPERABILITY )
                {
                  v37 = EXIF_IFD_INTEROPERABILITY;
LABEL_58:
                  name = exif_ifd_get_name(v37);
                  exif_log(
                    data->priv->log,
                    EXIF_LOG_CODE_DEBUG,
                    "ExifData",
                    "Recursive entry in IFD '%s' detected. Skipping...",
                    name);
                  goto LABEL_29;
                }
                if ( !data->ifd[4]->count )
                {
                  exif_data_load_data_content(data, EXIF_IFD_INTEROPERABILITY, d, recursion_depthb, v27, v47 + 1);
                  goto LABEL_29;
                }
                v28 = EXIF_IFD_INTEROPERABILITY;
LABEL_35:
                v29 = exif_ifd_get_name(v28);
                exif_log(
                  data->priv->log,
                  EXIF_LOG_CODE_DEBUG,
                  "ExifData",
                  "Attemt to load IFD '%s' multiple times detected. Skipping...",
                  v29);
                goto LABEL_29;
              }
            }
            else if ( v15 > 0x202u )
            {
              if ( v15 == 0x8769 )
              {
                v30 = exif_get_long(&d[v9 + 8], data->priv->order);
                if ( ifd == EXIF_IFD_EXIF )
                {
                  v37 = EXIF_IFD_EXIF;
                  goto LABEL_58;
                }
                v28 = EXIF_IFD_EXIF;
                if ( !data->ifd[2]->count )
                {
                  exif_data_load_data_content(data, EXIF_IFD_EXIF, d, recursion_depthb, v30, v47 + 1);
                  goto LABEL_29;
                }
                goto LABEL_35;
              }
            }
            else if ( v15 > 0x200u )
            {
              v17 = exif_get_long(&d[v9 + 8], data->priv->order);
              if ( (_WORD)v16 == 513 )
              {
                if ( v17 && n )
                  exif_data_load_data_thumbnail(data, d, recursion_depthb, v17, n);
                thumbnail_offset = v17;
              }
              else if ( thumbnail_offset && v17 )
              {
                exif_data_load_data_thumbnail(data, d, recursion_depthb, thumbnail_offset, v17);
                n = v17;
              }
              else
              {
                n = v17;
              }
              goto LABEL_29;
            }
            if ( exif_tag_get_name_in_ifd((ExifTag)v15, ifd) )
            {
              v18 = data->priv;
LABEL_21:
              v19 = exif_entry_new_mem(v18->mem);
              v19->tag = exif_get_short(&d[(unsigned int)v9], data->priv->order);
              v19->format = exif_get_short(&d[(unsigned int)v9 + 2], data->priv->order);
              v20 = exif_get_long(&d[(unsigned int)v9 + 4], data->priv->order);
              tag = v19->tag;
              v19->components = v20;
              v22 = exif_tag_get_name(tag);
              exif_log(
                data->priv->log,
                EXIF_LOG_CODE_DEBUG,
                "ExifData",
                "Loading entry 0x%x ('%s')...",
                (unsigned int)v19->tag,
                v22);
              v23 = LODWORD(v19->components) * exif_format_get_size(v19->format);
              if ( v23 )
              {
                v24 = v9 + 8;
                if ( v23 > 4 )
                {
                  v48 = v23;
                  v34 = exif_get_long(&d[(unsigned int)v9 + 8], data->priv->order);
                  v23 = v48;
                  v24 = v34;
                }
                v25 = v24;
                v26 = v23 + v24;
                if ( v23 >= v24 )
                  v25 = v23;
                if ( v26 >= v25 && recursion_depthb >= v26 )
                {
                  v49 = v24;
                  v51 = v23;
                  v35 = (unsigned __int8 *)exif_data_alloc(data, v23);
                  v36 = v49;
                  v19->data = v35;
                  if ( v35 )
                  {
                    v19->size = v51;
                    memcpy(v35, (void *)&d[v49], v51);
                    v36 = v49;
                  }
                  if ( v19->tag == EXIF_TAG_MAKER_NOTE )
                  {
                    if ( v19->size > 6 )
                    {
                      v39 = v19->data;
                      v50 = v36;
                      exif_log(
                        data->priv->log,
                        EXIF_LOG_CODE_DEBUG,
                        "ExifData",
                        "MakerNote found (%02x %02x %02x %02x %02x %02x %02x...).",
                        *v39,
                        v39[1],
                        v39[2],
                        v39[3],
                        v39[4],
                        v39[5],
                        v39[6]);
                      v36 = v50;
                    }
                    data->priv->offset_mnote = v36;
                  }
                  exif_content_add_entry(data->ifd[ifd], v19);
                }
              }
              exif_entry_unref(v19);
              goto LABEL_29;
            }
            if ( *(_DWORD *)&d[v9] )
            {
              v32 = exif_ifd_get_name(ifd);
              exif_log(
                data->priv->log,
                EXIF_LOG_CODE_DEBUG,
                "ExifData",
                "Unknown tag 0x%04x (entry %i in '%s'). Please report this tag to <libexif-devel@lists.sourceforge.net>.",
                v16,
                v14,
                v32);
              v18 = data->priv;
              if ( (v18->options & 1) == 0 )
                goto LABEL_21;
            }
            else
            {
              v31 = exif_ifd_get_name(ifd);
              exif_log(
                data->priv->log,
                EXIF_LOG_CODE_DEBUG,
                "ExifData",
                "Skipping empty entry at position %i in '%s'.",
                v14,
                v31);
            }
LABEL_29:
            ++v14;
            v9 += 12LL;
            if ( v14 == ds_0b )
              return;
          }
          v33 = exif_get_long(&d[v9 + 8], data->priv->order);
          if ( ifd == EXIF_IFD_GPS )
          {
            v37 = EXIF_IFD_GPS;
            goto LABEL_58;
          }
          v28 = EXIF_IFD_GPS;
          if ( !data->ifd[3]->count )
          {
            exif_data_load_data_content(data, EXIF_IFD_GPS, d, recursion_depthb, v33, v47 + 1);
            goto LABEL_29;
          }
          goto LABEL_35;
        }
      }
    }
  }
}
```

这段代码从给定的数据块中读取 EXIF 信息，并按条目逐一存储。每个条目由 结构体表示，并包含标签、格式、组件数等信息。如果条目包含数据，还会分配内存并将数据存储在 中。特殊的 标签会单独处理，确保相关数据被正确存储。整个过程通过递归加载数据，直到所有的 EXIF 数据都被处理并存储到对应的 IFD 中

## 调用链一分析

main->exif\_loader\_get\_data->exif\_data\_load\_data->exif\_get\_sshort

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250314073951921.png)![image.png](images/14a1945f-5f25-3f98-9fa2-330aac322fa3)

这里就是访问到不存在地址buf的代码 这里由于gdb优化代码编译我们不能直接调出 所以手动gdb调试查看一下参数

![](C:\Users\muxuecen\AppData\Roaming\Typora\typora-user-images\image-20250314074709850.png)![image.png](images/17eaf52d-ffee-3602-8258-5df4e7345f1a)

可以看到offset的值是0xffffffff

前面对offset只有一个检测就是offset+6+2 要小于0x7c3很明显满足

```
if (offset + 6 + 2 > ds) {
   817                 return;
   818         }

```

就导致buf这段 直接加了0xffffffff 自然就不存在这个地址

## 修复

修复的话很简单

关于调用链一 就只需要加一个offset的检测就行、

关于调用链二 加一个对size大小和堆大小方面的检测 防止溢出
