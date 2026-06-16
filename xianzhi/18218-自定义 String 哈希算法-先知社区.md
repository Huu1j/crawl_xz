# 自定义 String 哈希算法-先知社区

> **来源**: https://xz.aliyun.com/news/18218  
> **文章ID**: 18218

---

先水一篇文章，这篇文章只是开胃前菜。

**自定义 String 哈希算法的定义**：将字符串映射为唯一的整数（哈希值）

**公式**：H(s)=唯一HASH值

**特点**：

1. **唯一性（抗碰撞性）​**：理想状态下，不同输入应生成唯一哈希值，根据 `鸽巢原理`，哈希冲突必然存在，但是碰撞的概率是非常低的。
2. **不可逆性（单向性）**：哈希函数设计为单向映射，从哈希值反推原始输入在计算上不可行（即使已知算法），大部分在线的HASH算法解密网站都是通过建立庞大的数据库，然后通过撞库的方式找到输入值对于的HASH值。

学过密码学的师傅，肯定对哈希算法不陌生，就比如在实际的生成环境中就有 `MD5`、`SHA256`、`NTLM` 等等HASH算法。在本节中我们不必考虑这些算法，而是使用简单的自定义 String 哈希算法，比如说 `ROTR32`，`CRC32` 算法。

为什么要使用String 哈希算法呢？其理由如下

1. **避免检测**：主要的原因还是我们在很多情况下是需要动态获取API的，直接使用模块（`kernel32.dll`）API名称（如 `"VirtualAlloc"`）会在二进制文件中留下明文字符串，容易被杀毒软件的静态签名检测识别，将模块和API名称转换为整数哈希值（如 `0xA779563A`），消除可读字符串特征，大幅降低静态分析风险。
2. **减小shellcode体积**：整数哈希值的大小大多数情况下都是32位（4个字节），而API和模块名称的一般都是比较长的且不固定，大多数是大于4个字节的（一个字符一个字节）。

# 一、ROTR32

`ROTR32` 算法是一种位运算操作，全称为“32位循环右移”（Rotate Right 32-bit）。其核心功能是将一个32位整数（unsigned int）的二进制表示向右循环移动指定的位数，移出的位从左侧重新填充。其计算**公式**如下

```
ROTR32(x,n)=(x≫n)∣(x≪(32−n))
```

1. ​**​右移操作（x≫n)​**​： 将 x 的二进制表示向右移动 n 位，​**​高位补0​**​，移出的低位直接丢弃。
2. **左移操作（x≪(32−n))​**：将 x 向左移动 32−n 位，​**​低位补0​**​，移出的高位丢弃。​
3. **位或合并（∣)**：将右移和左移的结果按位合并，​**​循环填充空缺位​**​，最终实现“移出的低位补充到高位”的循环效果

这个算法在MSF和CS的的stager中被广泛使用，是一种高效且抗碰撞性良好的字符串哈希算法，可以用C语言、python和Go等高级语言实现，在x86/x64汇编中，已经将其浓缩成一个指令 `ror`

我这里实现的ROTR32算法计算出的hash值与在MSF和CS的的stager中的hash值不一样的，因为我改了部分计算逻辑。

## 1.1 C语言

```
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

// rot hash 算法
#define ROTR32(value, shift)	(((DWORD) value >> (BYTE) shift) | ((DWORD) value << (32 - (BYTE) shift)))
DWORD CalculateHash(const wchar_t* pModuleName, PCSTR pApiName) {

    PCSTR pTempChar;
    DWORD dwModuleHash = 0;
    DWORD dwFunctionHash = 0;
    size_t ModuleNameLength = wcslen(pModuleName) * 2;
    CHAR* ModuleName = (CHAR*)pModuleName;

    for (DWORD i = 0; i < ModuleNameLength; i++) {

        // 取字符
        CHAR c = ModuleName[i];

        // 如果为小写字母，则转成大写字母
        if (c >= 0x61) {
            c -= 0x20;
        }
        dwModuleHash = ROTR32(dwModuleHash, 13);
        dwModuleHash += c;
    }

    pTempChar = pApiName;

    while (*pTempChar != '\0') {
        dwFunctionHash = ROTR32(dwFunctionHash, 13);
        dwFunctionHash += *pTempChar;
        pTempChar++;
    }
    return dwModuleHash+dwFunctionHash;
}

int main()
{
    const wchar_t* pModuleName = L"kernel32.dll";
    PCSTR pApiName = "ExitProcess";
    DWORD dwModule_function_Hash = CalculateHash(pModuleName, pApiName);
    printf("dwModule_function_Hash is 0x%x", dwModule_function_Hash);
    return 0;
}
```

## 1.2 python

因为Python有动态整数类型，所以rotr32算法需要稍微处理，

1. `shift %= 32`，确保移动的位数固定在[0,31]里面，此操作非必须
2. `一个数 & 0xFFFFFFFF`：强制锁定32位范围（避免Python大整数干扰）

```
def rotr32(value, shift):
    shift %= 32
    right = (value >> shift) & 0xFFFFFFFF
    left = (value << (32 - shift)) & 0xFFFFFFFF
    return (right | left) & 0xFFFFFFFF

def get_module_function_hash(module_name, api_name):
    # 转换模块名为UTF-16LE字节序列
    module_bytes = module_name.encode('utf-16le')
    dw_module_hash = 0
    for byte in module_bytes:
        # 处理每个字节
        if byte >= 0x61:  # 小写字母
            c = byte - 0x20
        else:
            c = byte
        dw_module_hash = rotr32(dw_module_hash, 13)
        dw_module_hash = (dw_module_hash + c) & 0xFFFFFFFF  # 确保32位
    
    # 处理函数名
    dw_function_hash = 0
    for char in api_name.encode('ascii'):
        dw_function_hash = rotr32(dw_function_hash, 13)
        dw_function_hash = (dw_function_hash + char) & 0xFFFFFFFF
    
    total_hash = (dw_module_hash + dw_function_hash) & 0xFFFFFFFF
    return total_hash

if __name__ == "__main__":
    module_name = "kernel32.dll"
    api_name = "ExitProcess"
    hash_value = get_module_function_hash(module_name, api_name)
    print(f"dwModuleFunctionHash is 0x{hash_value:08x}")
```

## 1.3 Go

```
package main  
  
import (  
    "encoding/binary"  
    "fmt"    
    "unicode/utf16")  
  
// ROTR32 实现32位循环右移  
func ROTR32(value uint32, shift uint8) uint32 {  
    shift %= 32  
    return (value >> shift) | (value << (32 - shift))  
}  
  
func EncodeUTF16LE(s string) []byte {  
    // 将字符串转为UTF-16的uint16切片  
    runes := []rune(s)  
    utf16Runes := utf16.Encode(runes)  
  
    // 转为小端序字节序列  
    bytes := make([]byte, 2*len(utf16Runes))  
    for i, r := range utf16Runes {  
       binary.LittleEndian.PutUint16(bytes[i*2:], r)  
    }  
    return bytes  
}  
  
func CalculateHash(moduleName []byte, apiName string) uint32 {  
    var moduleHash uint32  
    var funtionHash uint32  
    var c byte  
    for _, char := range moduleName {  
       // 获取当前字符（宽字符）  
  
       // 如果是小写字母则转为大写  
       if char >= 0x61 {  
          c = char - 0x20  
       } else {  
          c = char  
       }  
       moduleHash = ROTR32(moduleHash, 13)  
       moduleHash += uint32(c)  
    }  
  
    // 处理API名称  
    for _, char := range apiName {  
       funtionHash = ROTR32(funtionHash, 13)  
       funtionHash += uint32(char)  
    }  
  
    fmt.Printf("0x%x
", moduleHash+funtionHash)  
    return moduleHash + funtionHash  
}  
  
func main() {  
    // 将字符串转换为UTF-16格式  
    moduleName := "kernel32.dll"  
    apiName := "ExitProcess"  
    moduleNameUTF16 := EncodeUTF16LE(moduleName)  
    CalculateHash(moduleNameUTF16, apiName)  
}
```

## 1.4 MASM汇编

ws2\_32.dll+WSAStartup = 4645344Ch  
ws2\_32.dll+WSASocketA = 0B83D505Ah  
ws2\_32.dll+connect = 6AF3406Dh  
ws2\_32.dll+recv = 0F1606037h  
kernel32.dll+LoadLibraryA = 56590AE9h  
kernel32.dll+VirtualAlloc = 0FBFA86AFh  
kernel32.dll+GetProcAddress = 0E658B905h  
kernel32.dll+VirtualProtect = 0E3918276h  
Ekernel32.dll+xitProcess = 0DE2D94D9h

汇编loop\_modname做了部分修改，主要是与高级语言保持一致，**不兼容**往前文章给出的HASH值，**请注意甄别**！

```
.386
.model flat, stdcall
option casemap:none

.data
dll_name db 'u',0,'s',0,'e',0,'r',0,'3',0,'2',0,'.',0,'d',0,'l',0,'l',0
func_name db 'MessageBoxA', 0  ; 定义函数名称，以0结尾

.code

; 计算DLL名称的哈希（转为大写处理）
loop_modname:
    xor eax, eax               ; 清空EAX
    lodsb                      ; 加载字符到AL，ESI++
    cmp al, 'a'                ; 检查是否为字符串结尾                
    jl not_lowercase           ; 检查是否是小写字母
    sub al, 20h                ; 转为大写
not_lowercase:
    ror edi, 0Dh               ; 右移13位
    add edi, eax               ; 累加到哈希值
    dec ecx
    jnz loop_modname          ; 继续循环
end_modname:
    ret

; 计算函数名称的哈希（原样处理）
loop_funcname:
    xor eax, eax               ; 清空EAX
    lodsb                      ; 加载字符到AL，ESI++
    test al, al
    jz end_funcname            ; 先检查结束符
    ror edi, 0Dh               ; 右移13位
    add edi, eax               ; 累加到哈希值
    jmp loop_funcname
end_funcname:
    ret

main:
    ; 计算DLL名称的哈希
    mov esi, offset dll_name   ; ESI指向DLL名称
    xor edi, edi               ; 初始化哈希值为0
    mov ecx,sizeof dll_name
    call loop_modname          ; 调用计算DLL哈希
    push edi                   ; 保存DLL哈希结果

    ; 计算函数名称的哈希
    mov esi, offset func_name  ; ESI指向函数名称
    xor edi, edi               ; 初始化哈希值为0
    call loop_funcname         ; 调用计算函数哈希

    ; 计算哈希之和
    pop eax                    ; 恢复DLL的哈希值到EAX
    add edi, eax               ; 将两者相加，结果在EDI中
    mov eax, edi               ; 结果存入EAX用于返回

    ret                        ; 返回，EAX包含哈希之和

end main
```

# 二、CRC32

在线CRC32检验：[CRC在线计算](https://www.lddgo.net/encrypt/crc)

学过计算机网络的师傅对CRC冗余校验码不陌生，CRC32（Cyclic Redundancy Check 32）是一种广泛应用的​**​32位循环冗余校验算法​**​，主要用于检测数据传输或存储过程中的意外错误（如网络传输、文件完整性校验）。其核心是通过多项式除法生成固定长度的校验码（32位），可以用做自定义String哈希算法。

这个算法我是在 [pe\_to\_shellcode/loader\_v1/hldr64/hldr64.asm at master · hasherezade/pe\_to\_shellcode](https://github.com/hasherezade/pe_to_shellcode/blob/master/loader_v1/hldr64/hldr64.asm) 中看到的，各位师傅可以参考项目给出的代码，自己去实现汇编代码。

**大致流程**：

1. ​**​初始化​**​：`crc = 0xFFFFFFFF`
2. ​**​混合字节​**​：`crc ^ 0x01 = 0xFFFFFFFE`
3. ​**​8 轮位操作​**​：

* 第 1 轮：`0xFFFFFFFE & 1 = 0` → 右移 → `0x7FFFFFFF`
* 第 2 轮：`0x7FFFFFFF & 1 = 1` → 右移并异或多项式 → `(0x3FFFFFFF) ^ 0xEDB88320` ...（重复 8 次）

1. ​**​最终取反​**​：得到校验码

## 2.1 C语言

```
#include <stdio.h>
#include <stdint.h>

// CRC32 哈希函数实现
uint32_t crc32_hash(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;  // 初始值

    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];  // 与当前字节异或

        // 进行 8 轮位操作
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            }
            else {
                crc = crc >> 1;
            }
        }
    }

    return crc ^ 0xFFFFFFFF;  // 最终结果取反
}

// 测试函数
int main() {

    // 测试函数名 "ExitProcess"
    uint32_t exit_process_hash = crc32_hash((const uint8_t*)"ExitProcess", 11);
    printf("ExitProcess 的哈希: 0x%08x
", exit_process_hash);

    return 0;
}
```

## 2.2 python

```
def crc32_hash(data: bytes) -> int:

    crc = 0xFFFFFFFF
    
    for byte in data:

        crc ^= byte
        
        # 进行 8 轮位操作
        for _ in range(8):
            # 检查最低位是否为 1
            if crc & 1:
                crc = (crc >> 1) ^ 0xEDB88320
            else:
                crc = crc >> 1
                
            # 确保结果为 32 位
            crc &= 0xFFFFFFFF
    
    # 最终结果取反
    return crc ^ 0xFFFFFFFF

if __name__ == "__main__":
 
    # 测试函数名 "ExitProcess"
    exit_process_hash = crc32_hash(b"ExitProcess")
    print(f"ExitProcess 的哈希: 0x{exit_process_hash:08x}")
 
```

## 2.3 go

```
package main

import (
    "fmt"
)

func crc32Hash(data []byte) uint32 {
    crc := uint32(0xFFFFFFFF) // 初始值

    for _, b := range data {
        crc ^= uint32(b) // 与当前字节异或

        // 进行 8 轮位操作
        for j := 0; j < 8; j++ {
            if crc&1 == 1 {
                crc = (crc >> 1) ^ 0xEDB88320 // 多项式异或
            } else {
                crc = crc >> 1
            }
        }
    }

    return crc ^ 0xFFFFFFFF // 最终结果取反
}

func main() {
    exit_process_hash := crc32Hash([]byte("ExitProcess"))
    fmt.Printf("ExitProcess hash: %x
", exit_process_hash)
}
```

# 三、下一步计划

我将燃尽自己、全力以赴，倾注全部心血完成承诺已久的SRDI技术解析长文。这是一篇技术性非常强的文章，我是以写论文的态度去认真对待的，它的质量绝对不会让各位师傅失望，甚至可以说是整个互联网独一份的。

其实文章已经写好了，我还在做最后的精修，还有一些心里话我就放在下一篇文章了，文章很快就会发出来。
