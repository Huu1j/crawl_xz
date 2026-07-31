# 探究python中pickle，_pickle和pickletools的解析差异问题-先知社区

> **来源**: https://xz.aliyun.com/news/18669  
> **文章ID**: 18669

---

## 前言

来看SEKAI 2025的一道题目

```
### IMPORTS ###
from pickle import _Unpickler as py_unpickler
from _pickle import Unpickler as c_unpickler
from pickletools import dis
from io import BytesIO
DEBUG = False


### HELPER FUNCTIONS ###
def py_pickle_wrapper(data: bytes) -> bool:
    """
    Wrapper function for Python's pickle.loads.
    """

    class SafePyUnpickler(py_unpickler):
        def find_class(self, module_name: str, global_name: str):
            print("no no no")
            exit(1)

    try:
        SafePyUnpickler(BytesIO(data)).load()
        return True
    except Exception:
        if DEBUG:
            print("Failed SafePyUnpickler")
        return False

def c_pickle_wrapper(data: bytes) -> bool:
    """
    Wrapper function for C's pickle.loads.
    """

    class SafeCUnpickler(c_unpickler):
        def find_class(self, module_name: str, global_name: str):
            print("no no no")
            exit(1)

    try:
        SafeCUnpickler(BytesIO(data)).load()
        return True
    except Exception:
        if DEBUG:
            print("Failed SafeCUnpickler")
        return False

def pickletools_wrapper(data: bytes) -> bool:
    """
    Wrapper function for pickletools.genops.
    """
    try:
        dis(data)
        return True
    except Exception:
        if DEBUG:
            print("Failed genops")
        return False

def get_input() -> bytes:
    inp = input("Pickle bytes in hexadecimal format: ")
    if inp.startswith("0x"):
        inp = inp[2:]

    b = bytes.fromhex(inp)[:8]
    return b


### MAIN ###
if __name__ == "__main__":
    # Check 1
    print("Check 1")
    b1 = get_input()
    if py_pickle_wrapper(b1) and c_pickle_wrapper(b1) and not pickletools_wrapper(b1):
        print("Passed check 1")
    else:
        print("Failed check 1")
        exit(1)

    # Check 2
    print("Check 2")
    b2 = get_input()
    if not py_pickle_wrapper(b2) and c_pickle_wrapper(b2) and pickletools_wrapper(b2):
        print("Passed check 2")
    else:
        print("Failed check 2")
        exit(1)

    # Check 3
    print("Check 3")
    b3 = get_input()
    if py_pickle_wrapper(b3) and not c_pickle_wrapper(b3) and pickletools_wrapper(b3):
        print("Passed check 3")
    else:
        print("Failed check 3")
        exit(1)

    # Check 4
    print("Check 4")
    b4 = get_input()
    if not py_pickle_wrapper(b4) and not c_pickle_wrapper(b4) and pickletools_wrapper(b4):
        print("Passed check 4")
    else:
        print("Failed check 4")
        exit(1)

    # Check 5
    print("Check 5")
    b5 = get_input()
    if not py_pickle_wrapper(b5) and c_pickle_wrapper(b5) and not pickletools_wrapper(b5):
        print("Passed check 5")
    else:
        print("Failed check 5")
        exit(1)

    # get flag
    print("All checks passed")
    FLAG = open("flag.txt", "r").read()
    print(FLAG)
```

先来分析这道题，这道题import了三个不同的pickle库

```
from pickle import _Unpickler as py_unpickler
from _pickle import Unpickler as c_unpickler
from pickletools import dis
```

并且要求选手输入十六进制数据，程序会用三个库进行解析，并设置了5个关卡进行验证，要求选手找到三个库的解析差异。

需要一部分库解析成功，一部分库解析失败

而且题目限制了用户输入长度，只能输入8位，也就是4字节

## 第一关

```
print("Check 1")
b1 = get_input()
if py_pickle_wrapper(b1) and c_pickle_wrapper(b1) and not pickletools_wrapper(b1):
    print("Passed check 1")
else:
    print("Failed check 1")
    exit(1)
```

第一关要求解析时pickle和\_pickle正常但是pickletools报错

我们可以修改题目代码进行测试

```
from pickle import _Unpickler as py_unpickler
from _pickle import Unpickler as c_unpickler
from pickletools import dis
from io import BytesIO
DEBUG = 1

def py_pickle_wrapper(data: bytes) -> bool:
    class SafePyUnpickler(py_unpickler):
        def find_class(self, module_name: str, global_name: str):
            print("no no no")
            exit(1)
    try:
        SafePyUnpickler(BytesIO(data)).load()
        return True
    except Exception as e:
        if DEBUG:
            print("Failed SafePyUnpickler：", e)
        return False

def c_pickle_wrapper(data: bytes) -> bool:
    class SafeCUnpickler(c_unpickler):
        def find_class(self, module_name: str, global_name: str):
            print("no no no")
            exit(1)
    try:
        SafeCUnpickler(BytesIO(data)).load()
        return True
    except Exception as e:
        if DEBUG:
            print("Failed SafeCUnpickler：", e)
        return False

def pickletools_wrapper(data: bytes) -> bool:
    try:
        dis(data)
        return True
    except Exception as e:
        if DEBUG:
            print("Failed genops：", e)

        return False

data = b''

print(py_pickle_wrapper(data))
print(c_pickle_wrapper(data))
print(pickletools_wrapper(data))
```

其中data是我们输入的数据，输出是三个解码的成功与否

先看dis函数的具体实现

```
def dis(pickle, out=None, memo=None, indentlevel=4, annotate=0):
    #省略
    stack = []          # 定义了一个栈
    #具体实现

    print("highest protocol among opcodes =", maxproto, file=out)
    #检查栈是否为空
    if stack:
        raise ValueError("stack not empty after STOP: %r" % stack)
```

dis的实现中有对栈的模拟，如果程序结束后栈不为空那么就会报错，从而通过检查1

在源码的opcodes数组中定义了不同操作码的行为

为了不让另外两个也报错，我们末尾需要STOP命令表示结束，那么可以先看看STOP命令的行为

```
I(name='STOP',
  code='.',
  arg=None,
  stack_before=[anyobject],
  stack_after=[],
  proto=0,
  doc="""Stop the unpickling machine.

      Every pickle ends with this opcode.  The object at the top of the stack
      is popped, and that's the result of unpickling.  The stack should be
      empty then.
      """)
```

可以看到会从栈中弹出一个对象，那么只需要在此之前压入两个对象即可

我们随便从操作码中选一个即可，这里我选择的NONE

```
I(name='NONE',
  code='N',
  arg=None,
  stack_before=[],
  stack_after=[pynone],
  proto=0,
  doc="Push None on the stack."),

# Ways to spell bools, starting with proto 2.  See INT for how this was
# done before proto 2.
```

这个操作码会将None压入栈中

那么最后的data就是"NN."，我们运行一下程序看看效果

```
True
True
    0: N    NONE
    1: N    NONE
    2: .    STOP
highest protocol among opcodes = 0
Failed genops： stack not empty after STOP: [None]
False
```

可以看到成功让pickletools报错，报错就是我们想要的stack not empty

然后将payload转换为16进制输入即可通过关卡1

## 第二关

第二关要求py\_pickle报错但是其他不报错

这里我们可以参考[PickleAPPENDS和ADDITEMS缺少检查 · 问题 #135573 · python/cpython --- PickleAPPENDSandADDITEMSmissing check · Issue #135573 · python/cpython](https://github.com/python/cpython/issues/135573)

这里我们直接引用原文

**pickle** **和** **\_pickle** **在行为上存在一个小的不一致，对于** **ADDITEMS** **和** **APPENDS** **操作码。这两个操作码的目的是通过弹出由** **MARK** **对象分隔的所有对象来向集合或列表添加项目。然后，调用** **add()** **/** **extend()** **/** **append()** **属性函数将新项目添加到对象中。****在 C 中，添加的项目数量在两个操作码中都进行了明确检查，如果为 0 则提前返回。**

```
if (len == mark)  /* nothing to do */ 
    return 0;
```

```
if (len == x)  /* nothing to do */ 
    return 0;
```

**然而在 Python 版本中，没有检查 0 个元素的情况。**

```
def load_additems(self): 
    items = self.pop_mark() 
    set_obj = self.stack[-1] 
    if isinstance(set_obj, set): 
        set_obj.update(items) 
    else: 
        add = set_obj.add 
        for item in items: 
            add(item)
```

```
def load_appends(self): 
    items = self.pop_mark() 
    list_obj = self.stack[-1] 
    try: 
        extend = list_obj.extend 
    except AttributeError: 
        pass 
    else: 
        extend(items) 
        return 
    append = list_obj.append 
    for item in items: 
        append(item)
```

**这通常不会导致任何不一致，除非堆栈顶部的项目（即要追加到的列表或集合）实际上不是一个列表或集合。例如，如果我们把一个整数而不是列表压入堆栈，并使用** **APPENDS** **指令码来添加 0 个项目，它会在** **pickle** **时出错，因为整数没有** **append()** **属性，但会由于检查而在** **\_pickle** **时直接返回。**

根据这篇文章，我们构造4字节的payload为N(e.

首先先了解一下另外两个操作码

( (全名: MARK)将一个特殊的、内部使用的 markobject 对象压入栈顶

```
def load_mark(self):
    self.metastack.append(self.stack)
    self.stack = []
    self.append = self.stack.append
dispatch[MARK[0]] = load_mark
```

e (全名: APPENDS)用来将一系列对象追加到一个列表 (list) 中

源码中items = self.pop\_mark()可以看到这个操作码会先将markobject弹出

在这个payload中，会先将None和markobject压入，然后 APPENDS 将markobject弹出。由于pickle缺少检查会对栈中剩下的None调用append方法，从而触发AttributeError

我们可以将data修改然后运行来验证

```
Failed SafePyUnpickler： 'NoneType' object has no attribute 'append'
False
True
    0: N    NONE
    1: (    MARK
    2: e        APPENDS    (MARK at 1)
    3: .    STOP
highest protocol among opcodes = 1
True
```

可以看到报错信息证明了我们的猜想

## 第三关

第三关要求c\_pickle报错

参考[pickleload\_buildfunction checks ifstateis None, not False · Issue #128965 · python/cpython](https://github.com/python/cpython/issues/128965)

**在 pickle 的** **BUILD** **操作码的** **load\_build()** **函数内部，C accelerator 在某个时刻检查** **state** **是否为** **Py\_None** **，而 Python 版本仅检查** **if state**

[cpython/Modules/\_pickle.c](https://github.com/python/cpython/blob/34ded1a1a10204635cad27830fcbee2f8547e8ed/Modules/_pickle.c#L6638)

if (state != Py\_None) {

[cpython/Lib/pickle.py](https://github.com/python/cpython/blob/34ded1a1a10204635cad27830fcbee2f8547e8ed/Lib/pickle.py#L1765)

if state:

也就是说如果 state 类似于空字典或元组， if 语句下的代码块将在 \_pickle.c 中运行，但在 pickle.py 中不会运行

所以只需要压入空字典然后BUILD即可，其中BUILD会弹出两个对象，一个作为state另一个作为instance，所以我们需要压入两个空字典

我们可以通过分析源码得到这一点

```
load_build(PickleState *st, UnpicklerObject *self)
{
    PyObject *inst, *slotstate;
    PyObject *setstate;
    int status = 0;
    //省略

    PyObject *state;
    PDATA_POP(st, self->stack, state);// 从栈顶弹出一个元素给 state
    if (state == NULL)
        return -1;

    inst = self->stack->data[Py_SIZE(self->stack) - 1]; // 从栈顶弹出一个元素给 inst
    //省略

    if (state != Py_None) {
        PyObject *dict;
        PyObject *d_key, *d_value;
        Py_ssize_t i;
        if (!PyDict_Check(state)) {
            PyErr_SetString(st->UnpicklingError, "state is not a dictionary");  //错误
            goto error;
        }
        //省略    
        error:
        status = -1;

        return status;
    }
```

所以我们使用]]b.，结果如下

```
True
Failed SafeCUnpickler： state is not a dictionary
False
    0: ]    EMPTY_LIST
    1: ]    EMPTY_LIST
    2: b    BUILD
    3: .    STOP
highest protocol among opcodes = 1
True
```

成功让c\_pickle报错

## 第四关

第四关要求只有pickletools不报错

pickletools 是一个**静态分析器和反汇编器**，只会模拟操作而不会真正执行，所以只要写一个语法正确但是执行会出错的即可

我们这次使用payload为(.

先来看pickletools的行为，它遇到MARK，在它的模拟栈上放了一个 markobject。这只是在栈上增加了一个元素而已。然后遇到STOP从栈顶弹出一个对象作为结果，于是它模拟弹出这个对象，没有检查对象类型

但是pickle和\_pickle来运行都会有一定问题

先来看\_pickle的源码

```
Pdata_stack_underflow(PickleState *st, Pdata *self)
{
    PyErr_SetString(st->UnpicklingError,
                    self->mark_set ?
                    "unexpected MARK found" :
                    "unpickling stack underflow");
    return -1;
}
```

在这里会有校验，检查mark\_set标志位，而MARK会将标志位设置为1。因此会报错unexpected MARK found

pickle的错误则来自于最后的STOP

```
def load_mark(self):
    self.metastack.append(self.stack)
    self.stack = []
    self.append = self.stack.append
dispatch[MARK[0]] = load_mark

def load_stop(self):
    value = self.stack.pop()
    raise _Stop(value)
dispatch[STOP[0]] = load_stop
```

这里MARK会将当前整个 self.stack 列表作为一个元素，压入 self.metastack，然后创建新栈

然而此时stack为空，直接STOP会导致IndexError: pop from empty list

## 第五关

第五关要求只有\_pickle不报错

\_pickle底层是c语言实现，我们可以利用c语言的特性

参考[Pickle 反序列化空字节差异 · 问题 #126996 · python/cpython --- Pickle deserialization null byte discrepancy · Issue #126996 · python/cpython](https://github.com/python/cpython/issues/126996)

这篇Issues讲解了在c的实现下由于空字节造成的差异问题

On [line 5208](https://github.com/python/cpython/blob/main/Modules/_pickle.c#L5208) (for INT) and [line 5362](https://github.com/python/cpython/blob/main/Modules/_pickle.c#L5362) (for LONG), \_Unpickler\_Readline(state, self, &s) reads everything (including a null byte) into the s variable, which is char \*. However, [strtol](https://github.com/python/cpython/blob/main/Modules/_pickle.c#L5216) or PyLong\_FromString ([1](https://github.com/python/cpython/blob/main/Modules/_pickle.c#L5223), [2](https://github.com/python/cpython/blob/main/Modules/_pickle.c#L5374)) stop when the first null byte is encountered, meaning everything including and after the null byte is ignored, returning 1 (in the above example).

我们参考文章并修改payload为4字节即可I .

pickle和pickletools会读取I到换行符的内容并转化成int，然而遇到空字节会直接报错invalid literal for int() with base 0: b' '

\_pickle底层实现是c，因此将空字节视为了字符串的结束符并返回了0，因此不会报错

```
Failed SafePyUnpickler： invalid literal for int() with base 0: b'\x00
'
False
True
Failed genops： invalid literal for int() with base 10: b'\x00'
False
```

## 总结

pickle，\_pickle以及pickletools由于在实现方式与具体功能上存在差异，会导致一定的解析差异

正常开发时一般无需在意，但是在部分情况下却可能造成一定的安全问题

例如用一个库检验另一个库加载，就可能导致程序崩溃等
