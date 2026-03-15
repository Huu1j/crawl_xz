# Frida Windows API Hook 原理和实践 - 实战 PicoCTF 2025 两道re题-先知社区

> **来源**: https://xz.aliyun.com/news/17283  
> **文章ID**: 17283

---

## 前言

Frida 作为一款强大的动态插桩工具，在安全研究和 CTF 竞赛中得到了广泛应用。本文结合 PicoCTF 2025 的两道 Binary Instrumentation 题目，详细介绍 Frida 的环境配置、Windows API Hook 原理，并通过案例展示如何利用 Frida 解决问题。

## Frida 环境配置

安装 Python：下载地址（[Python 官网](https://www.python.org/downloads/)），安装时，勾选“Add Python to PATH”选项，确保可以通过命令行调用 python 和 pip。

安装 Frida 工具

1. 打开命令提示符（CMD）或 PowerShell。
2. 使用以下命令安装 frida-tools：`pip install frida-tools`
3. 安装完成后，验证安装是否成功：`frida --version`，如果成功，你会看到类似 16.x.x 的版本号输出。

## Frida Hook Windows API 原理

### 原理介绍

Frida 是一个动态插桩工具，它允许你将 JavaScript 代码注入到正在运行的进程中，并拦截、修改函数调用。对于 Windows API Hook，Frida 的原理大致如下：

1. 查找目标函数地址： 首先，Frida 需要找到目标 Windows API 函数在内存中的地址。这通常通过加载相应的 DLL (例如 `kernel32.dll`、`user32.dll` 等) 并使用 `Module.findExportByName()` 或 `Module.getExportByName()` 来实现。
2. 保存原始指令： 为了在 Hook 之后还能调用原始函数，Frida 会保存目标函数开头的几条指令 (通常是 5-10 字节)。
3. 写入跳转指令： Frida 会用一条跳转指令 (通常是 `JMP` 指令) 覆盖目标函数开头的指令，将执行流重定向到 Frida 的 JavaScript Hook 函数。
4. JavaScript Hook 函数： 当目标函数被调用时，执行流会跳转到 Frida 的 JavaScript Hook 函数。在这个函数中，你可以：

* 读取和修改函数参数。
* 执行自定义的逻辑。
* 决定是否调用原始函数 (通过调用 Frida 保存的原始指令)。
* 读取和修改函数的返回值。

1. 调用原始函数 (可选)： 如果需要调用原始函数，Frida 会将参数传递给原始函数，执行原始函数，并获取其返回值。
2. 恢复执行： 在 Hook 函数执行完毕后，控制权返回到调用方。

![image.png](images/61a93bc8-e167-3fba-a369-304c707fd664)

接下来通过实验来验证这个流程

### 测试程序

frida\_test\_sleep.c：

```
#include <windows.h>
#include <stdio.h>

int main() {
    printf("Sleep1
");
    Sleep(15000);  // 睡眠 15 秒
    system("pause");
    printf("Sleep2
");
    Sleep(15000);  // 睡眠 15 秒
    system("pause");
    return 0;
}
```

frida\_sleep.js：

```
console.log("[*] Starting script...");
const Sleep = Module.getExportByName("kernel32.dll", "Sleep");
Interceptor.attach(Sleep, {
    onEnter: function (args) {
        console.log("[*] Sleep called with original argument: " + args[0].toInt32() + " ms");
        args[0] = ptr(1);
        console.log("[*] Argument modified to: 1 ms");
    },
    onLeave: function (retval) {
        console.log("[*] Sleep returned");
    }
});
console.log("[*] Hook installed, waiting for Sleep calls...");
```

### 调试分析

正常运行，需要等15s显示输出结果，使用frida脚本运行：`frida -l .rida_sleep.js .rida_test_sleep.exe`，一瞬间就完成了运行，跳过了等待：

```
Spawning `.\frida_test_sleep.exe`...
[*] Starting script...
[*] Hook installed, waiting for Sleep calls...
Spawned `.\frida_test_sleep.exe`. Resuming main thread!
Sleep1
[*] Sleep called with original argument: 15000 ms
[*] Argument modified to: 1 ms
[Local::frida_test_sleep.exe ]-> [*] Sleep returned
请按任意键继续. . . 
Sleep2
[*] Sleep called with original argument: 15000 ms
[*] Argument modified to: 1 ms
[*] Sleep returned
请按任意键继续. . . 
Process terminated
```

调试器附加观察，正常情况下的Sleep函数：跳转到SleepEx里去了

```
00007FFF766AA630 | 33D2                     | xor edx,edx                                        |
00007FFF766AA632 | E9 09000000              | jmp <kernelbase.SleepEx>                           |
00007FFF766AA637 | CC                       | int3                                               |
00007FFF766AA638 | 71 28                    | jno kernelbase.7FFF766AA662                        |
00007FFF766AA63A | DE14CD 8EECF248          | ficom word ptr ds:[rcx*8+48F2EC8E]                 |
```

frida下的Sleep函数：跳转到了一个其他的地方，这里是inline hook的方式进行的

```
00007FFF766AA630 | E9 D35A6002              | jmp 7FFF78CB0108                                   |
00007FFF766AA635 | 66:90                    | nop                                                |
00007FFF766AA637 | CC                       | int3                                               |
00007FFF766AA638 | 71 28                    | jno kernelbase.7FFF766AA662                        |
00007FFF766AA63A | DE14CD 8EECF248          | ficom word ptr ds:[rcx*8+48F2EC8E]                 |
```

跳转目标：

```
00007FFF78CB0108 | FF35 F2FFFFFF            | push qword ptr ds:[7FFF78CB0100]                   |	// 保存Sleep原始地址
00007FFF78CB010E | FF25 02000000            | jmp qword ptr ds:[7FFF78CB0116]                    |
```

继续跳转：这里开头是保存运行上下文，然后后面是恢复上下文，说明这里即将要进入Hook部分了

```
00000180D5FD0000 | 9C                       | pushfq                                             |
00000180D5FD0001 | FC                       | cld                                                |
00000180D5FD0002 | 50                       | push rax                                           |
00000180D5FD0003 | 51                       | push rcx                                           |
00000180D5FD0004 | 52                       | push rdx                                           |
00000180D5FD0005 | 53                       | push rbx                                           | rbx:&".\frida_test_sleep.exe"
00000180D5FD0006 | 48:8D8424 20000000       | lea rax,qword ptr ss:[rsp+20]                      |
00000180D5FD000E | 50                       | push rax                                           |
00000180D5FD000F | 48:8B4424 20             | mov rax,qword ptr ss:[rsp+20]                      |
00000180D5FD0014 | 55                       | push rbp                                           |
00000180D5FD0015 | 56                       | push rsi                                           |
00000180D5FD0016 | 57                       | push rdi                                           | rdi:&"ALLUSERSPROFILE=C:\ProgramData"
00000180D5FD0017 | 41:50                    | push r8                                            | r8:_wctype+34B40
00000180D5FD0019 | 41:51                    | push r9                                            |
00000180D5FD001B | 41:52                    | push r10                                           |
00000180D5FD001D | 41:53                    | push r11                                           |
00000180D5FD001F | 41:54                    | push r12                                           |
00000180D5FD0021 | 41:55                    | push r13                                           |
00000180D5FD0023 | 41:56                    | push r14                                           |
00000180D5FD0025 | 41:57                    | push r15                                           |
00000180D5FD0027 | 48:8DA424 F8FFFFFF       | lea rsp,qword ptr ss:[rsp-8]                       |
00000180D5FD002F | 48:8D8424 98000000       | lea rax,qword ptr ss:[rsp+98]                      |
00000180D5FD0037 | 48:894424 60             | mov qword ptr ss:[rsp+60],rax                      |
00000180D5FD003C | 48:8B9C24 90000000       | mov rbx,qword ptr ss:[rsp+90]                      |
00000180D5FD0044 | 48:89E5                  | mov rbp,rsp                                        |
00000180D5FD0047 | 48:81E4 F0FFFFFF         | and rsp,FFFFFFFFFFFFFFF0                           |
00000180D5FD004E | 48:81EC 00020000         | sub rsp,200                                        |
00000180D5FD0055 | 0FAE0424                 | fxsave ss:[rsp]                                    |
00000180D5FD0059 | 48:8DB5 00000000         | lea rsi,qword ptr ss:[rbp]                         |
00000180D5FD0060 | 48:8D95 98000000         | lea rdx,qword ptr ss:[rbp+98]                      |
00000180D5FD0067 | 48:8D8D 90000000         | lea rcx,qword ptr ss:[rbp+90]                      |
00000180D5FD006E | 49:89C9                  | mov r9,rcx                                         |
00000180D5FD0071 | 49:89D0                  | mov r8,rdx                                         | r8:_wctype+34B40
00000180D5FD0074 | 48:89F2                  | mov rdx,rsi                                        |
00000180D5FD0077 | 48:89D9                  | mov rcx,rbx                                        | rbx:&".\frida_test_sleep.exe"
00000180D5FD007A | 48:83EC 20               | sub rsp,20                                         |
00000180D5FD007E | FF15 02000000            | call qword ptr ds:[180D5FD0086]                    |	// 会进入 frida-agent.dll
00000180D5FD0084 | EB 08                    | jmp 180D5FD008E                                    |
00000180D5FD0086 | B0 C5                    | mov al,C5                                          |
00000180D5FD0088 | 1AF0                     | sbb dh,al                                          |
00000180D5FD008A | FD                       | std                                                |
00000180D5FD008B | 7F 00                    | jg 180D5FD008D                                     |
00000180D5FD008D | 0048 83                  | add byte ptr ds:[rax-7D],cl                        |
00000180D5FD0090 | C4                       | ???                                                |
00000180D5FD0091 | 2085 C0753D0F            | and byte ptr ss:[rbp+F3D75C0],al                   |
00000180D5FD0097 | AE                       | scasb                                              |
00000180D5FD0098 | 0C 24                    | or al,24                                           |
00000180D5FD009A | 48:89EC                  | mov rsp,rbp                                        |
00000180D5FD009D | 48:8DA424 08000000       | lea rsp,qword ptr ss:[rsp+8]                       | [rsp+08]:main+3F
00000180D5FD00A5 | 41:5F                    | pop r15                                            |
00000180D5FD00A7 | 41:5E                    | pop r14                                            |
00000180D5FD00A9 | 41:5D                    | pop r13                                            |
00000180D5FD00AB | 41:5C                    | pop r12                                            |
00000180D5FD00AD | 41:5B                    | pop r11                                            |
00000180D5FD00AF | 41:5A                    | pop r10                                            |
00000180D5FD00B1 | 41:59                    | pop r9                                             |
00000180D5FD00B3 | 41:58                    | pop r8                                             | r8:_wctype+34B40
00000180D5FD00B5 | 5F                       | pop rdi                                            | rdi:&"ALLUSERSPROFILE=C:\ProgramData"
00000180D5FD00B6 | 5E                       | pop rsi                                            |
00000180D5FD00B7 | 5D                       | pop rbp                                            |
00000180D5FD00B8 | 48:8DA424 08000000       | lea rsp,qword ptr ss:[rsp+8]                       | [rsp+08]:main+3F
00000180D5FD00C0 | 5B                       | pop rbx                                            | rbx:&".\frida_test_sleep.exe"
00000180D5FD00C1 | 5A                       | pop rdx                                            |
00000180D5FD00C2 | 59                       | pop rcx                                            |
00000180D5FD00C3 | 58                       | pop rax                                            |
00000180D5FD00C4 | 9D                       | popfq                                              |
00000180D5FD00C5 | 48:8DA424 08000000       | lea rsp,qword ptr ss:[rsp+8]                       | [rsp+08]:main+3F
00000180D5FD00CD | FF6424 F8                | jmp qword ptr ss:[rsp-8]                           |
00000180D5FD00D1 | 0F0B                     | ud2                                                |
00000180D5FD00D3 | 48:B8 9600FDD580010000   | mov rax,180D5FD0096                                |
00000180D5FD00DD | FFA3 98000000            | jmp qword ptr ds:[rbx+98]                          |
00000180D5FD00E3 | 0F0B                     | ud2                                                |
```

调用完函数之后，恢复寄存器环境的时候，将rcx设置为了1，最终进入如下代码，这里是恢复了原本被inline hook覆盖的字节，进入正常流程

```
00007FFF78CB0145 | 33D2                     | xor edx,edx                                        |
00007FFF78CB0147 | E9 F4A49FFD              | jmp <kernelbase.SleepEx>                           |
```

**综上，关于Frida Hook Windows API的方式就是，通过Inline hook的方式进行的，跳转到frida-agent.dll处理寄存器环境，从而实现对参数进行修改，最后恢复覆盖的字节完成函数调用**

## PicoCTF 2025 - Binary Instumentation 1 (200 pts)

### 题目描述

I have been learning to use the Windows API to do cool stuff! Can you wake up my program to get the flag?

运行：一直卡在这里

```
Hi, I have the flag for you just right here!
I'll just take a quick nap before I print it out for you, should only take me a decade or so!
zzzzzzzz....
```

### 逆向分析求解过程

start函数一看很不想看，但仔细看会发现，这里通过API读取PEB结构体，然后通过PEB拿到ImageBase，最终进入函数sub\_140001DC0

```
__int64 start()
{
  struct _PEB *v0; // rbx
  HANDLE ProcessHeap; // rax
  void *v2; // rdi
  HANDLE v3; // rax
  __int64 v4; // rdi
  int *ImageBaseAddress; // rbp
  __int64 v6; // rsi
  char *i; // rbx
  __int64 v9; // rdi
  __int64 v10; // rbx
  char *v11; // rdi
  __int64 v12; // [rsp+50h] [rbp+8h] BYREF
  __int64 v13; // [rsp+58h] [rbp+10h] BYREF

  v0 = NtCurrentPeb();                          // 读取PEB
  ProcessHeap = GetProcessHeap();
  v2 = HeapAlloc(ProcessHeap, 8u, 0x400ui64);
  if ( GetLastError() == 13852 )
  {
    ReleaseSRWLockExclusive(0i64);
    ReleaseSRWLockShared(0i64);
    SetCriticalSectionSpinCount(0i64, 0);
    TryAcquireSRWLockExclusive(0i64);
    WakeAllConditionVariable(0i64);
    SetUnhandledExceptionFilter(0i64);
    UnhandledExceptionFilter(0i64);
    CheckMenuItem(0i64, 0, 0);
    GetMenu(0i64);
    GetSystemMenu(0i64, 0);
    GetMenuItemID(0i64, 0);
    EnableMenuItem(0i64, 0, 0);
    MessageBeep(0);
    GetLastError();
    MessageBoxW(0i64, 0i64, 0i64, 0);
    MessageBoxA(0i64, 0i64, 0i64, 0);
    UpdateWindow(0i64);
    GetWindowContextHelpId(0i64);
  }
  else
  {
    v3 = GetProcessHeap();
    HeapFree(v3, 0, v2);
  }
  if ( !v0 || v0->OSMajorVersion != 10 )
    return 0xFFFFFFFFi64;
  v4 = 0i64;
  v13 = 0i64;
  v12 = 0i64;
  ImageBaseAddress = (int *)v0->ImageBaseAddress;
  v6 = ImageBaseAddress[15];
  for ( i = (char *)ImageBaseAddress + v6 + 264; (unsigned int)sub_1400014B0(i) != -1622013139; i += 40 )
  {
    if ( ++v4 > (unsigned __int64)*(unsigned __int16 *)((char *)ImageBaseAddress + v6 + 6) )
      return 0xFFFFFFFFi64;
  }
  v9 = *((unsigned int *)i + 3);
  v10 = *((unsigned int *)i + 4);
  v11 = (char *)ImageBaseAddress + v9;
  if ( !v11
    || !v10
    || !(unsigned int)sub_1400018B0()
    || (unsigned int)sub_140001300(1, (_DWORD)v11, v10, (unsigned int)&v13, (__int64)&v12) )
  {
    return 0xFFFFFFFFi64;
  }
  sub_140001DC0(v13, v12, 1i64);
  return 0i64;
}
```

函数sub\_140001DC0：依然非常不想看，这里可以看到，刚开始通过偏移在定位些什么，然后经过一系列修改，最终调入v35()，一个函数指针

了解的人知道这是PE格式内存映射过程，不了解的朋友可以猜测这是个壳，最后解密完在v35进入真正的程序

```
void __fastcall sub_140001DC0(__int64 a1, __int64 a2)
{
  unsigned __int64 v2; // r12
  __int64 v4; // r14
  unsigned int *v5; // r13
  unsigned int *v6; // r15
  __int64 v7; // rdi
  __int64 v8; // rdx
  __int64 v9; // rcx
  unsigned int *v10; // r8
  __int64 v11; // r9
  int v12; // esi
  unsigned int *v13; // rbx
  unsigned __int64 v14; // rax
  unsigned int v15; // ebp
  unsigned __int64 v16; // rsi
  __int64 v17; // r13
  __int64 v18; // rbx
  __int64 *v19; // r14
  __int64 *v20; // rsi
  __int64 v21; // rdx
  __int64 v22; // rax
  unsigned int v23; // eax
  __int64 v24; // rax
  __int64 v25; // r11
  unsigned int *i; // r10
  __int64 v27; // rbx
  __int64 v28; // rax
  unsigned int j; // ebx
  _DWORD *v30; // rdx
  int v31; // ecx
  int v32; // r9d
  void (__fastcall **v33)(__int64, __int64); // rbx
  void (__fastcall *k)(__int64, __int64); // rax
  void (*v35)(void); // rbx
  unsigned int *v36; // [rsp+30h] [rbp-98h]
  __int64 v37; // [rsp+D0h] [rbp+8h]
  unsigned int *v38; // [rsp+E8h] [rbp+20h]

  if ( a1 )
  {
    v2 = 0i64;
    if ( a2 )
    {
      if ( *(_WORD *)a1 == 23117 )
      {
        v4 = a1 + *(int *)(a1 + 60);
        v37 = v4;
        if ( *(_DWORD *)v4 == 17744 )
        {
          v5 = (unsigned int *)(v4 + 176);
          v6 = (unsigned int *)(v4 + 144);
          v36 = (unsigned int *)(v4 + 144);
          v38 = (unsigned int *)(v4 + 176);
          if ( v4 )
          {
            if ( v4 != -144 && v4 != -208 && v4 != -176 && v4 != -160 && v4 != -264 )
            {
              sub_140004D60(0i64, *(_QWORD *)(v4 + 48), 0i64);
              v7 = sub_1400048D0(0, *(_QWORD *)(v4 + 48), *(_DWORD *)(v4 + 80), 0, 0, 0i64);
              if ( v7 || (v7 = sub_140004A00(*(unsigned int *)(v4 + 80), 0i64)) != 0 )
              {
                sub_1400010D0(v7, a1, *(unsigned int *)(v4 + 84));
                v12 = 0;
                if ( *(_WORD *)(v4 + 6) )
                {
                  v13 = (unsigned int *)(v4 + 284);
                  do
                  {
                    sub_1400010D0(v7 + *(v13 - 2), a1 + *v13, *(v13 - 1));
                    v13 += 10;
                    ++v12;
                  }
                  while ( v12 < *(unsigned __int16 *)(v4 + 6) );
                }
                if ( *(_DWORD *)(v4 + 148) )
                {
                  while ( 1 )
                  {
                    v14 = v2 + *v6;
                    v15 = *(_DWORD *)(v14 + v7);
                    v16 = v14 + v7;
                    if ( !v15 && !*(_DWORD *)(v16 + 16) )
                    {
LABEL_30:
                      v5 = v38;
                      v4 = v37;
                      goto LABEL_31;
                    }
                    v17 = *(unsigned int *)(v16 + 16);
                    v18 = sub_140001900(v7 + *(unsigned int *)(v14 + v7 + 12));
                    if ( !v18 )
                      return;
                    if ( !v15 )
                      v15 = *(_DWORD *)(v16 + 16);
                    v19 = (__int64 *)(v7 + v17);
                    v8 = v15 + v7;
                    if ( *(_QWORD *)(v7 + v17) )
                      break;
LABEL_29:
                    v6 = v36;
                    v2 += 20i64;
                    if ( v2 >= v36[1] )
                      goto LABEL_30;
                  }
                  v20 = (__int64 *)(v7 + v17);
                  while ( 1 )
                  {
                    v21 = *(_QWORD *)v8;
                    if ( v21 >= 0 )
                    {
                      v23 = sub_1400014B0(v7 + v21 + 2);
                      v22 = sub_140001730(v18, v23);
                    }
                    else
                    {
                      v9 = v18 + *(unsigned int *)(*(unsigned int *)(*(int *)(v18 + 60) + v18 + 136) + v18 + 28);
                      v22 = v18 + *(unsigned int *)(v9 + 4 * v21);
                    }
                    if ( !v22 )
                      break;
                    ++v20;
                    *v19 = v22;
                    v19 = v20;
                    v8 = (__int64)v20 + v15 - v17;
                    if ( !*v20 )
                      goto LABEL_29;
                  }
                }
                else
                {
LABEL_31:
                  v24 = *(_QWORD *)(v4 + 48);
                  if ( v7 != v24 )
                  {
                    v10 = (unsigned int *)(v7 + *v5);
                    v25 = v7 - v24;
                    if ( *v10 )
                    {
                      do
                      {
                        for ( i = v10 + 2; i != (unsigned int *)((char *)v10 + v10[1]); i = (unsigned int *)((char *)i + 2) )
                        {
                          v11 = *(unsigned __int16 *)i;
                          v8 = (unsigned __int16)v11;
                          if ( (unsigned int)v11 >> 12 )
                          {
                            switch ( (unsigned int)v11 >> 12 )
                            {
                              case 1u:
                                v9 = *v10;
                                v8 = v9 + v7 + (v11 & 0xFFF);
                                *(_WORD *)v8 += WORD1(v25);
                                break;
                              case 2u:
                                v9 = *v10;
                                v8 = v11 & 0xFFF;
                                *(_WORD *)(v9 + v7 + v8) += v25;
                                break;
                              case 3u:
                                v9 = *v10;
                                v8 = v11 & 0xFFF;
                                *(_DWORD *)(v9 + v7 + v8) += v25;
                                break;
                              case 0xAu:
                                v9 = *v10;
                                v11 &= 0xFFFu;
                                *(_QWORD *)(v9 + v7 + v11) += v25;
                                break;
                              default:
                                return;
                            }
                          }
                        }
                        v10 = i;
                      }
                      while ( *i );
                    }
                  }
                  if ( *(_DWORD *)(v4 + 164) )
                  {
                    v27 = v7 + *(unsigned int *)(v4 + 160);
                    v28 = sub_140001650("KERNEL32.DLL", v8, v10);
                    v11 = sub_140001730(v28, 2451134556i64);
                    if ( v11 )
                      ((void (__fastcall *)(__int64, _QWORD, __int64))v11)(v27, *(_DWORD *)(v4 + 164) / 0xCu - 1, v7);
                  }
                  sub_1400019C0(v9, v8, v10, v11);
                  for ( j = 0; j < *(unsigned __int16 *)(v4 + 6); ++j )
                  {
                    v30 = (_DWORD *)(v4 + 40i64 * j);
                    v31 = v30[75];
                    v32 = (v31 >> 31) & 8;
                    if ( (v31 & 0x40000000) != 0 )
                      v32 = 2;
                    if ( (v30[75] & 0xC0000000) == -1073741824 )
                      v32 = 4;
                    if ( (v31 & 0x20000000) != 0 )
                      v32 = 16;
                    if ( (v31 & 0xA0000000) == -1610612736 )
                      v32 = 128;
                    if ( (v31 & 0x60000000) == 1610612736 )
                      v32 = 32;
                    if ( (v31 & 0xE0000000) == -536870912 )
                      v32 = 64;
                    sub_140004C70(0, v7 + v30[69], v30[70], v32, 0i64);
                  }
                  if ( *(_DWORD *)(v4 + 212) )
                  {
                    v33 = *(void (__fastcall ***)(__int64, __int64))(*(unsigned int *)(v4 + 208) + v7 + 24);
                    for ( k = *v33; k; ++v33 )
                    {
                      k(v7, 1i64);
                      k = v33[1];
                    }
                  }
                  v35 = (void (*)(void))(v7 + *(unsigned int *)(v4 + 40));
                  sub_1400015A0(v7, *(unsigned int *)(v4 + 276));
                  v35();
                }
              }
            }
          }
        }
      }
    }
  }
}
```

真正的程序：

```
0000000140001004 | 48:8B0D 85200000         | mov rcx,qword ptr ds:[<&class std::basic_ostream<char, struct std::char_traits<char>> std::cou |
000000014000100B | 48:8D15 AE220000         | lea rdx,qword ptr ds:[1400032C0]                                                               | rdx:&"C:\Users\Admin\Downloads\PicoCTF 2025\re\bininst1\bininst1.exe", 00000001400032C0:"Hi, I have the flag for you just right here!"
0000000140001012 | E8 39040000              | call 140001450                                                                                 |
0000000140001017 | 48:8BC8                  | mov rcx,rax                                                                                    | rax:_mbcasemap+610
000000014000101A | 48:8D15 0F060000         | lea rdx,qword ptr ds:[140001630]                                                               | rdx:&"C:\Users\Admin\Downloads\PicoCTF 2025\re\bininst1\bininst1.exe"
0000000140001021 | FF15 89200000            | call qword ptr ds:[<&public: class std::basic_ostream<unsigned short, struct std::char_traits< |
0000000140001027 | 48:8B0D 62200000         | mov rcx,qword ptr ds:[<&class std::basic_ostream<char, struct std::char_traits<char>> std::cou |
000000014000102E | 48:8D15 BB220000         | lea rdx,qword ptr ds:[1400032F0]                                                               | rdx:&"C:\Users\Admin\Downloads\PicoCTF 2025\re\bininst1\bininst1.exe", 00000001400032F0:"I'll just take a quick nap before I print it out for you, should only take me a decade or so!"
0000000140001035 | E8 16040000              | call 140001450                                                                                 |
000000014000103A | 48:8BC8                  | mov rcx,rax                                                                                    | rax:_mbcasemap+610
000000014000103D | 48:8D15 EC050000         | lea rdx,qword ptr ds:[140001630]                                                               | rdx:&"C:\Users\Admin\Downloads\PicoCTF 2025\re\bininst1\bininst1.exe"
0000000140001044 | FF15 66200000            | call qword ptr ds:[<&public: class std::basic_ostream<unsigned short, struct std::char_traits< |
000000014000104A | 48:8B0D 3F200000         | mov rcx,qword ptr ds:[<&class std::basic_ostream<char, struct std::char_traits<char>> std::cou |
0000000140001051 | 48:8D15 F8220000         | lea rdx,qword ptr ds:[140003350]                                                               | rdx:&"C:\Users\Admin\Downloads\PicoCTF 2025\re\bininst1\bininst1.exe", 0000000140003350:"zzzzzzzz...."
0000000140001058 | E8 F3030000              | call 140001450                                                                                 |
000000014000105D | 48:8BC8                  | mov rcx,rax                                                                                    | rax:_mbcasemap+610
0000000140001060 | 48:8D15 C9050000         | lea rdx,qword ptr ds:[140001630]                                                               | rdx:&"C:\Users\Admin\Downloads\PicoCTF 2025\re\bininst1\bininst1.exe"
0000000140001067 | FF15 43200000            | call qword ptr ds:[<&public: class std::basic_ostream<unsigned short, struct std::char_traits< |
000000014000106D | B9 FEFFFFFF              | mov ecx,FFFFFFFE                                                                               |
0000000140001072 | FF15 881F0000            | call qword ptr ds:[<&Sleep>]                                                                   |
0000000140001078 | B9 FEFFFFFF              | mov ecx,FFFFFFFE                                                                               |
000000014000107D | FF15 7D1F0000            | call qword ptr ds:[<&Sleep>]                                                                   |
0000000140001083 | B9 FEFFFFFF              | mov ecx,FFFFFFFE                                                                               |
...
超级多Sleep函数的调用
...
000000014000141F | 48:8B0D 6A1C0000         | mov rcx,qword ptr ds:[<&class std::basic_ostream<char, struct std::char_traits<char>> std::cou |
0000000140001426 | 48:8D15 331F0000         | lea rdx,qword ptr ds:[140003360]                                                               | rdx:&"C:\Users\Admin\Downloads\PicoCTF 2025\re\bininst1\bininst1.exe", 0000000140003360:"Ok, I'm Up! The flag is: cGljb0NURnt3NGtlX20zX3VwX3cxdGhfZnIxZGFfZjI3YWNjMzh9"
000000014000142D | E8 1E000000              | call 140001450                                                                                 |
0000000140001432 | 48:8BC8                  | mov rcx,rax                                                                                    | rax:_mbcasemap+610
0000000140001435 | 48:8D15 F4010000         | lea rdx,qword ptr ds:[140001630]                                                               | rdx:&"C:\Users\Admin\Downloads\PicoCTF 2025\re\bininst1\bininst1.exe"
000000014000143C | FF15 6E1C0000            | call qword ptr ds:[<&public: class std::basic_ostream<unsigned short, struct std::char_traits< |
0000000140001442 | 33C0                     | xor eax,eax                                                                                    |
0000000140001444 | 48:83C4 28               | add rsp,28                                                                                     |
0000000140001448 | C3                       | ret                                                                                            |
```

很显然，这里是c++打印了一些东西，然后进入超级多的Sleep函数，然后最终输出flag

其实执行到这里的时候，已经可以在字符串里搜到了：

```
地址=000000014000100B
反汇编=lea rdx,qword ptr ds:[1400032C0]
字符串地址=00000001400032C0
字符串="Hi, I have the flag for you just right here!"
地址=000000014000102E
反汇编=lea rdx,qword ptr ds:[1400032F0]
字符串地址=00000001400032F0
字符串="I'll just take a quick nap before I print it out for you, should only take me a decade or so!"
地址=0000000140001051
反汇编=lea rdx,qword ptr ds:[140003350]
字符串地址=0000000140003350
字符串="zzzzzzzz...."
地址=0000000140001426
反汇编=lea rdx,qword ptr ds:[140003360]
字符串地址=0000000140003360
字符串="Ok, I'm Up! The flag is: cGljb0NURnt3NGtlX20zX3VwX3cxdGhfZnIxZGFfZjI3YWNjMzh9"
地址=0000000140001A79
反汇编=lea rcx,qword ptr ds:[1400032A0]
字符串地址=00000001400032A0
字符串="€P"
```

### Frida Hook 求解过程

因为程序执行起来之后很久都没有动静，猜测用到了Sleep之类的函数，frida-trace测试：`frida-trace.exe -i "!Sleep*" -f .ininst1.exe`

```
Hi, I have the flag for you just right here!
I'll just take a quick nap before I print it out for you, should only take me a decade or so!
zzzzzzzz....
           /* TID 0x76e8 */
    20 ms  Sleep()
    20 ms     | Sleep()
    20 ms     |    | SleepEx()
    20 ms     |    |    | SleepEx()
```

发现调用了Sleep，应该是参数巨大，所以要等很久，编写frida脚本：

```
Interceptor.attach(Module.findExportByName('kernel32.dll', 'Sleep'), {
    onEnter: function (args) {
        // 修改第一个参数的值为 1
        args[0] = ptr(1);
    },
});
```

通过frida执行：`frida -l .rida_WinAPI_Sleep_hook.js .ininst1.exe`

```
     ____
    / _  |   Frida 16.6.6 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Local System (id=local)
Spawned `.\bininst1.exe`. Resuming main thread!
[Local::bininst1.exe ]-> Hi, I have the flag for you just right here!
I'll just take a quick nap before I print it out for you, should only take me a decade or so!
zzzzzzzz....
Ok, I'm Up! The flag is: cGljb0NURnt3NGtlX20zX3VwX3cxdGhfZnIxZGFfZjI3YWNjMzh9
Process terminated
[Local::bininst1.exe ]->

Thank you for using Frida!
```

直接拿到flag：cGljb0NURnt3NGtlX20zX3VwX3cxdGhfZnIxZGFfZjI3YWNjMzh9，base64解码得到答案

## PicoCTF 2025 - Binary Instumentation 2 (300 pts)

### 题目描述

I've been learning more Windows API functions to do my bidding. Hmm... I swear this program was supposed to create a file and write the flag directly to the file. Can you try and intercept the file writing function to see what went wrong?

这里提到了Windows API，以及Create File和Write File

应该就是通过这种方式输出flag，但是又说存在问题，应该是函数参数错了让我们修补？

### 逆向分析求解过程

这个题目和上个题目一样，是个PE文件内存映射加载的过程，然后调入OEP进行执行，通过调试器进入到真正执行的部分：

```
0000000140001000 | 48:83EC 48               | sub rsp,48                                                                                     |
0000000140001004 | 48:C74424 30 00000000    | mov qword ptr ss:[rsp+30],0                                                                    | HANDLE hTemplateFile = NULL
000000014000100D | 48:8D0D 3C120000         | lea rcx,qword ptr ds:[140002250]                                                               | LPCTSTR lpFileName = "<Insert path here>"
0000000140001014 | C74424 28 80000000       | mov dword ptr ss:[rsp+28],80                                                                   | DWORD dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL
000000014000101C | 45:33C9                  | xor r9d,r9d                                                                                    | LPSECURITY_ATTRIBUTES lpSecurityAttributes
000000014000101F | 45:33C0                  | xor r8d,r8d                                                                                    | DWORD dwShareMode
0000000140001022 | C74424 20 02000000       | mov dword ptr ss:[rsp+20],2                                                                    | DWORD dwCreationDisposition = CREATE_ALWAYS
000000014000102A | BA 00000040              | mov edx,40000000                                                                               | DWORD dwDesiredAccess = GENERIC_WRITE
000000014000102F | FF15 D30F0000            | call qword ptr ds:[<&CreateFileA>]                                                             | CreateFileA
0000000140001035 | 48:83F8 FF               | cmp rax,FFFFFFFFFFFFFFFF                                                                       | rax:_mbcasemap+610
0000000140001039 | 75 05                    | jne 140001040                                                                                  |
000000014000103B | 48:83C4 48               | add rsp,48                                                                                     |
000000014000103F | C3                       | ret                                                                                            |
0000000140001040 | 45:33C9                  | xor r9d,r9d                                                                                    |
0000000140001043 | 48:C74424 20 00000000    | mov qword ptr ss:[rsp+20],0                                                                    |
000000014000104C | 45:33C0                  | xor r8d,r8d                                                                                    |
000000014000104F | 48:8D15 1A120000         | lea rdx,qword ptr ds:[140002270]                                                               | rdx:&"C:\Users\Admin\Downloads\PicoCTF 2025\re\bininst2\bininst2.exe", 0000000140002270:"cGljb0NURntmcjFkYV9mMHJfYjFuX2luNXRydW0zbnQ0dGlvbiFfYjIxYWVmMzl9"
0000000140001056 | 48:8BC8                  | mov rcx,rax                                                                                    | rax:_mbcasemap+610
0000000140001059 | FF15 A10F0000            | call qword ptr ds:[<&WriteFile>]                                                               |
000000014000105F | 33C0                     | xor eax,eax                                                                                    |
0000000140001061 | 48:83C4 48               | add rsp,48                                                                                     |
0000000140001065 | C3                       | ret                                                                                            |
0000000140001066 | CC                       | int3                                                                                           |
```

和猜测的一样，是CreateFileA然后WriteFile的调用

可以看到，这里的文件名是：`<Insert path here>`，文件名不允许出现尖括号，所以这里会调用失败，需要修改为正常文件名

然后调用WriteFile应该就是写入flag了，此时的字符串也能直接搜到：

```
地址=000000014000100D
反汇编=lea rcx,qword ptr ds:[140002250]
字符串地址=0000000140002250
字符串="<Insert path here>"
地址=000000014000104F
反汇编=lea rdx,qword ptr ds:[140002270]
字符串地址=0000000140002270
字符串="cGljb0NURntmcjFkYV9mMHJfYjFuX2luNXRydW0zbnQ0dGlvbiFfYjIxYWVmMzl9"
地址=0000000140001409
反汇编=lea rcx,qword ptr ds:[140002230]
字符串地址=0000000140002230
字符串="€0"
```

如果搜不到，就修改文件名，然后追踪到写文件的地方看看写了啥

### Frida Hook 求解过程

我们猜到了可能用到了CreateFile和WriteFile函数，frida-trace看看：`frida-trace -f bininst2.exe -i CreateFile* -i WriteFile*`

```
           /* TID 0x1e08 */
    28 ms  CreateFileA()
    28 ms     | CreateFileA()
Process terminated
```

可以看到，这里调用了CreateFileA，但是程序退出了，通过修改frida-trace生成的脚本：

```
/*
 * Auto-generated by Frida. Please modify to match the signature of CreateFileA.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler({
  onEnter: function (log, args, state) {
    log("CreateFileA called:");
    log("  lpFileName: " + Memory.readUtf8String(args[0])); // 文件名
    log("  dwDesiredAccess: " + args[1].toInt32());        // 访问权限
    log("  dwShareMode: " + args[2].toInt32());           // 共享模式
    log("  lpSecurityAttributes: " + args[3]);           // 安全属性
    log("  dwCreationDisposition: " + args[4].toInt32()); // 创建选项
    log("  dwFlagsAndAttributes: " + args[5].toInt32());  // 文件属性
    log("  hTemplateFile: " + args[6]);                  // 模板文件句柄
},
onLeave: function (log, retval, state) {
    log("CreateFileA returned: " + retval); 
}
});

```

再次使用frida-trace，输出结果：

```
           /* TID 0x9e8c */
    18 ms  CreateFileA()
    18 ms     | CreateFileA called:
    18 ms     |   lpFileName: <Insert path here>
    18 ms     |   dwDesiredAccess: 1073741824
    18 ms     |   dwShareMode: 0
    18 ms     |   lpSecurityAttributes: 0x0
    18 ms     |   dwCreationDisposition: 2
    18 ms     |   dwFlagsAndAttributes: 128
    18 ms     |   hTemplateFile: 0x0
    18 ms  CreateFileA returned: 0xffffffffffffffff
Process terminated
```

知道参数1有问题了，修改参数1，再继续观察：

CreateFileA.js：

```
defineHandler({
  onEnter: function (log, args, state) {
    log("CreateFileA modified");
    this.filename = Memory.allocUtf8String("1.txt");
    args[0] = this.filename;
    log("CreateFileA called:");
    log("  lpFileName: " + Memory.readUtf8String(args[0])); // 文件名
    log("  dwDesiredAccess: " + args[1].toInt32());        // 访问权限
    log("  dwShareMode: " + args[2].toInt32());           // 共享模式
    log("  lpSecurityAttributes: " + args[3]);           // 安全属性
    log("  dwCreationDisposition: " + args[4].toInt32()); // 创建选项
    log("  dwFlagsAndAttributes: " + args[5].toInt32());  // 文件属性
    log("  hTemplateFile: " + args[6]);                  // 模板文件句柄
},
onLeave: function (log, retval, state) {
    log("CreateFileA returned: " + retval); 
}
});

```

WriteFile.js：

```
/*
 * Auto-generated by Frida. Please modify to match the signature of WriteFile.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler({
  onEnter(log, args, state) {
    log('WriteFile()');
    log("  Buffer: " + Memory.readUtf8String(args[1])); // 缓冲区内容

  },

  onLeave(log, retval, state) {
  }
});

```

输出结果：

```
           /* TID 0x9d2c */
    19 ms  CreateFileA()
    19 ms     | CreateFileA modified
    19 ms     | CreateFileA called:
    19 ms     |   lpFileName: 1.txt
    19 ms     |   dwDesiredAccess: 1073741824
    19 ms     |   dwShareMode: 0
    19 ms     |   lpSecurityAttributes: 0x0
    19 ms     |   dwCreationDisposition: 2
    19 ms     |   dwFlagsAndAttributes: 128
    19 ms     |   hTemplateFile: 0x0
    20 ms  CreateFileA returned: 0x2a0
    20 ms  WriteFile()
    20 ms     | WriteFile()
    20 ms     |   Buffer: cGljb0NURntmcjFkYV9mMHJfYjFuX2luNXRydW0zbnQ0dGlvbiFfYjIxYWVmMzl9
Process terminated
```

拿到flag：cGljb0NURntmcjFkYV9mMHJfYjFuX2luNXRydW0zbnQ0dGlvbiFfYjIxYWVmMzl9，base64解码后就是flag

## 总结

本文通过 PicoCTF 2025 的两道题目，展示了 Frida 在 Windows API Hook 中的应用：

1. **Binary Instrumentation 1**：通过 Hook Sleep，跳过长时间等待，直接获取 Flag。
2. **Binary Instrumentation 2**：通过 Hook CreateFileA 和 WriteFile，修复文件名并拦截 Flag。

Frida 真好玩，后续我要陆续开始深入研究 Frida 的应用！
