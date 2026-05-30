# Parloo2025 RE详解wp-先知社区

> **来源**: https://xz.aliyun.com/news/18041  
> **文章ID**: 18041

---

# Parloo杯 RE

### PositionalXOR

![](images/20250526171304-a11fd288-3a11-1.png)

附件里就一个bin文件，010editor打开，数据提出来直接写脚本解密

![](images/20250526171305-a1ec9e4f-3a11-1.png)

```
enc = "qcoq~Vh{e~bccocH^@Lgt{gt|g"
enc_list = list(enc)
for i in range(len(enc_list)):
    print(chr(ord(enc_list[i]) ^ (i + 1)), end="")
```

**palu{PosltionalXOR\_sample}**

### PaluArray

UPX壳，并且好像有的标志位被删了，直接x64dbg手动脱壳，然后ida分析，根据提示字符串定位到程序的主要逻辑

```
// Hidden C++ exception states: #wind=2
struct CWnd *__fastcall sub_7FF61DC51DD8(CDialog *a1)
{
  struct CWnd *result; // rax
  struct CWnd *v3; // rdi
  _QWORD *v4; // rax
  void **v5; // rax
  __int64 v6; // rax
  void *v7; // rcx
  _BYTE v8[8]; // [rsp+20h] [rbp-E0h] BYREF
  _BYTE v9[40]; // [rsp+28h] [rbp-D8h] BYREF
  void *Block; // [rsp+50h] [rbp-B0h] BYREF
  char v11; // [rsp+58h] [rbp-A8h] BYREF
  __int64 v12; // [rsp+E0h] [rbp-20h] BYREF
  _BYTE v13[8]; // [rsp+E8h] [rbp-18h] BYREF
  void *v14[3]; // [rsp+F0h] [rbp-10h] BYREF
  unsigned __int64 n0xF; // [rsp+108h] [rbp+8h]

  CDialog::OnOK(a1);
  result = CWnd::GetDlgItem(a1, 1000);
  v3 = result;
  if ( result )
  {
    ATL::CStringT<wchar_t,StrTraitMFC_DLL<wchar_t,ATL::ChTraitsCRT<wchar_t>>>::CStringT<wchar_t,StrTraitMFC_DLL<wchar_t,ATL::ChTraitsCRT<wchar_t>>>(&v12);
    CWnd::GetWindowTextW(v3, &v12);
    v4 = ATL::CSimpleStringT<wchar_t,1>::CSimpleStringT<wchar_t,1>(v8, &v12);
    sub_7FF61DC51994(v13, v4);
    if ( ATL::CStringT<wchar_t,StrTraitMFC_DLL<wchar_t,ATL::ChTraitsCRT<wchar_t>>>::Compare(v13, a1145141919810) )// "1145141919810"
    {
      CWnd::MessageBoxW(a1, aFailed, 0, 0);     // "Failed"
    }
    else
    {
      CWnd::MessageBoxW(a1, aSuccess, 0, 0);    // "Success"
      v5 = sub_7FF61DC51F6C(&Block, v12);
      sub_7FF61DC52118(v14, *v5);
      if ( Block != &v11 )
        free(Block);
      v6 = sub_7FF61DC52244(v9, v14);
      sub_7FF61DC51A48(v6);
      if ( n0xF > 0xF )
      {
        v7 = v14[0];
        if ( n0xF + 1 >= 0x1000 )
        {
          v7 = *(v14[0] - 1);
          if ( (v14[0] - v7 - 8) > 0x1F )
            invalid_parameter_noinfo_noreturn();
        }
        operator delete[](v7);
      }
    }
    ATL::CSimpleStringT<wchar_t,1>::~CSimpleStringT<wchar_t,1>(v13);
    return ATL::CSimpleStringT<wchar_t,1>::~CSimpleStringT<wchar_t,1>(&v12);
  }
  return result;
}
```

这里就是处理输入密文的函数，**sub\_7FF61DC51994**函数对字符串的每个字符进行查找，在一个确定的table中![](images/20250526171306-a248fe48-3a11-1.png)

然后再看**sub\_7FF61DC51A48**函数，有MD5，但好像是生成flag的逻辑，那么应该就是将上面解密出来的字符串输入进去，就会输出flag

解密脚本

```
table = "Palu_996!?"
index = list("1145141919810")
for i in range(13):
    print(table[ord(index[i]) - ord('0')], end="")
```

得到：aa\_9a\_a?a?!aP

然后运行程序输入

![](images/20250526171306-a2a6ff49-3a11-1.png)

### PaluGOGOGO

go语言，ida打开分析

主要加密逻辑

![](images/20250526171307-a31dc494-3a11-1.png)

红色部分是密文，绿色部分获取的value会传入到**main\_complexEncrypt**参与flag的加密

![](images/20250526171308-a3b62f36-3a11-1.png)

加密逻辑如图，value就是在外面传进来的值，n10\_4是index

解密脚本

```
enc = [0xbf,0xb1,0xbd,0xc7,0xce,0x96,0x80,0x98,0x82,0x9a,0x7f,0xaf,0xc1,0xb3,0xbf,0xc4,0xcd]
for i in range(len(enc)):
    print(chr(enc[i] - 0x4f - (i % 5)), end="")
```

**palu{G0G0G0\_palu}**

### CatchPalu

早上的附件有问题，我服了，我说怎么打不出来...

去一下花，经典的花指令，很简单，就不贴出来了

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [esp+0h] [ebp-84h]
  char v5; // [esp+0h] [ebp-84h]
  int _palu_P1au_D0nt_Bel1eve__; // [esp+24h] [ebp-60h]
  int _MessageBoxA_; // [esp+28h] [ebp-5Ch]
  _DWORD *v8; // [esp+48h] [ebp-3Ch]
  _DWORD *lpAddress; // [esp+4Ch] [ebp-38h]
  _DWORD *i; // [esp+50h] [ebp-34h]
  HMODULE ModuleHandleA; // [esp+54h] [ebp-30h]
  DWORD lpflOldProtect_; // [esp+5Ch] [ebp-28h] BYREF
  DWORD flOldProtect; // [esp+60h] [ebp-24h] BYREF
  char v14[28]; // [esp+64h] [ebp-20h] BYREF

  MessageBoxA_0 = MessageBoxA;
  sub_401050(Format, v4);                       // "Wellcome Palu!!!
"
  ModuleHandleA = GetModuleHandleA(0);
  for ( i = (ModuleHandleA + *(ModuleHandleA + *(ModuleHandleA + 15) + 128)); i[3]; i += 5 )
  {
    if ( LoadLibraryA(ModuleHandleA + i[3]) )
    {
      v8 = (ModuleHandleA + *i);
      lpAddress = (ModuleHandleA + i[4]);
      while ( *v8 )
      {
        _MessageBoxA_ = strcmp(ModuleHandleA + *v8 + 2, aMessageboxa);// "MessageBoxA"
        if ( _MessageBoxA_ )
          _MessageBoxA_ = _MessageBoxA_ < 0 ? -1 : 1;
        if ( !_MessageBoxA_ )
        {
          flOldProtect = 0;
          VirtualProtect(lpAddress, 8u, 4u, &flOldProtect);
          *lpAddress = sub_401360;
          lpflOldProtect_ = 0;
          VirtualProtect(lpAddress, 8u, flOldProtect, &lpflOldProtect_);
        }
        ++v8;
        ++lpAddress;
      }
    }
  }
  sub_401050(aEnterYourFlag, v5);               // "Enter your flag: "
  sub_4010C0(a25s, v14);                        // "%25s"
  sub_401050(aYouEnteredS, v14);                // "You entered: %s
"
  _palu_P1au_D0nt_Bel1eve__ = strcmp(v14, aPaluP1auD0ntBe);// "palu{P1au_D0nt_Bel1eve}"
  if ( _palu_P1au_D0nt_Bel1eve__ )
    _palu_P1au_D0nt_Bel1eve__ = _palu_P1au_D0nt_Bel1eve__ < 0 ? -1 : 1;
  if ( !_palu_P1au_D0nt_Bel1eve__ )
    MessageBoxA(0, Text, Caption, 0);           // "NoSuccess?"
  return 0;
}
```

![](images/20250526171309-a42b4452-3a11-1.png)

早上这个函数里没啥有用的信息，附件更新之后，里面是一个魔改的rc4

![](images/20250526171309-a487698e-3a11-1.png)

![](images/20250526171310-a4f64fe5-3a11-1.png)

还改了个233

解密脚本

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int init(unsigned char *s, unsigned char *key, unsigned long Len_k)
{

    int i = 0, j = 0;
    char k[256] = {0};
    unsigned char tmp = 0;
    for (i = 0; i < 256; i++)
    {
        s[i] = i;
        k[i] = key[i % Len_k];
    }
    for (int n = 0; n < 3; n++)
    {
        for (i = 0; i < 256; i++)
        {
            j = (j + s[i] + k[i]) % 233;
            tmp = s[i];
            s[i] = s[j];
            s[j] = tmp;
        }
    }
    return 0;
}

int rc4(unsigned char *Data, unsigned long Len_D, unsigned char *key, unsigned long Len_k)
{

    unsigned char s[256];
    init(s, key, Len_k);
    int i = 0, j = 0, t = 0;
    unsigned long k = 0;
    unsigned char tmp;

    for (k = 0; k < Len_D; k++)
    {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
        t = (s[i] + s[j]) % 256;
        Data[k] = Data[k] ^ s[t];
    }
    return 0;
}
int main()
{

    unsigned char key[] = "forpalu"; // 密钥生成的过程

    printf("%s
", key);
    unsigned long key_len = sizeof(key) - 1;
    unsigned char qw[25];
    qw[0] = 0xD;
    qw[1] = 0xB0;
    qw[2] = 0xBF;
    qw[3] = 0xA;
    qw[4] = 0x8D;
    qw[5] = 0x2F;
    qw[6] = 2;
    qw[7] = 0x38;
    qw[8] = 0x6F;
    qw[9] = 0x19;
    qw[10] = 0xAE;
    qw[11] = 0x99;
    qw[12] = 0x19;
    qw[13] = 0xC7;
    qw[14] = 0x6E;
    qw[15] = 0xF7;
    qw[16] = 0x4F;
    qw[17] = 0xCB;
    qw[18] = 0x90;
    qw[19] = 0x4E;
    qw[20] = 0x55;
    qw[21] = 0x8E;
    qw[22] = 0xD1;
    qw[23] = 0x10;
    qw[24] = 0xC0;
    rc4(qw, sizeof(qw), key, key_len);
    for (int i = 0; i < sizeof(qw); i++)
    {
        printf("%c", qw[i]); // NSSCTF{Sh0w_m3_th3_m0n3y}
    }
    return 0;
}
```

**palu{G00d\_P1au\_Kn0w\_H00K}**

### PaluFlat

ida分析

```
// local variable allocation has failed, the output may be wrong!
int __fastcall main(int argc, const char **argv, const char **envp)
{
  FILE *Stream; // rax
  char enc[32]; // [rsp+20h] [rbp-60h]
  char Str[112]; // [rsp+40h] [rbp-40h] BYREF
  char Buffer[100]; // [rsp+B0h] [rbp+30h] BYREF
  int flag_len; // [rsp+114h] [rbp+94h]
  int i; // [rsp+118h] [rbp+98h]
  int v10; // [rsp+11Ch] [rbp+9Ch]

  sub_4022D0(*&argc, argv, envp);
  enc[0] = 0x54;
  enc[1] = 0x84;
  enc[2] = 0x54;
  enc[3] = 0x44;
  enc[4] = 0xA4;
  enc[5] = 0xB2;
  enc[6] = 0x84;
  enc[7] = 0x54;
  enc[8] = 0x62;
  enc[9] = 0x32;
  enc[10] = 0x8F;
  enc[11] = 0x54;
  enc[12] = 0x62;
  enc[13] = 0xB2;
  enc[14] = 0x54;
  enc[15] = 3;
  enc[16] = 0x14;
  enc[17] = 0x80;
  enc[18] = 0x43;
  flag_len = 19;
  printf("input flag: ");
  Stream = psub_4037B0(0i64);
  fgets(Buffer, 100, Stream);
  Buffer[strcspn(Buffer, "
")] = 0;
  sub_401550(Buffer, Str);
  if ( strlen(Str) == flag_len )
  {
    v10 = 1;
    for ( i = 0; i < flag_len; ++i )
    {
      if ( Str[i] != enc[i] )
      {
        v10 = 0;
        break;
      }
    }
    if ( v10 )
      puts("success");
    else
      puts("error");
  }
  else
  {
    puts("error");
  }
  return 0;
}
```

加密逻辑在**sub\_401550**函数中，但是跟进去发现有switch-case语句的混淆，插件都去不了，但是好在看起来不复杂，可以直接动调跟。

跟下来就是，对flag先根据索引的奇偶不同来进行循环xor不同的key，然后进行高四位和低四位的交换，再减0x55，最后取反

![](images/20250526171311-a553f1fe-3a11-1.png)

![](images/20250526171311-a5aeceed-3a11-1.png)

![](images/20250526171312-a60f3837-3a11-1.png)

![](images/20250526171312-a66cedf7-3a11-1.png)

![](images/20250526171313-a6cc6b6f-3a11-1.png)

那么就可以直接解密

```
enc = [0] * 19
enc[0] = 0x54
enc[1] = 0x84
enc[2] = 0x54
enc[3] = 0x44
enc[4] = 0xA4
enc[5] = 0xB2
enc[6] = 0x84
enc[7] = 0x54
enc[8] = 0x62
enc[9] = 0x32
enc[10] = 0x8F
enc[11] = 0x54
enc[12] = 0x62
enc[13] = 0xB2
enc[14] = 0x54
enc[15] = 0x03
enc[16] = 0x14
enc[17] = 0x80
enc[18] = 0x43

key1 = b"flat"
key2 = b"palu"

for i in range(len(enc)):
    tmp = (~enc[i]) & 0xFF
    tmp = (tmp + 0x55) & 0xFF
    tmp = ((tmp >> 4) | (tmp << 4)) & 0xFF
    if (i % 2 == 0):
        tmp ^= key2[i % 4]
    else:
        tmp ^= key1[i % 4]
    print(chr(tmp), end="")
```

**palu{Fat\_N0t\_Flat!}**

### Asymmetric

go语言，ida打开来看到

![](images/20250526171314-a72fcef7-3a11-1.png)

第一时间觉得是RSA，用yafu分解一下n值

![](images/20250526171314-a7a10712-3a11-1.png)

解密脚本

```
from Crypto.Util.number import inverse, long_to_bytes

p = 3
q = 47
r = 2287
s = 3101092514893
m = 100000000000000003
n = 100000000000000106100000000000003093
c = 94846032130173601911230363560972235
e = 65537

phi = (p - 1) * (q - 1) * (r - 1) * (s - 1) * (m - 1)

try:
    d = inverse(e, phi)
except ValueError:
    print("e和φ(n)不互质，请选择其他e值")
    exit()

plaintext = pow(c, d, n)
flag = long_to_bytes(plaintext)

print("解密结果:", flag)
```

**palu{3a5Y\_R$A}**

### 帕鲁迷宫

没什么意思，就纯算法题，运行程序可以得到迷宫

```
############################## #
#Y#                   #       X 
# # ############# ### # ### ## #
# #   #         # #   #   #   ##
# ##### ####### ### # ### ### ##
#   #   #     # #   #   # #   ##
### # ### ##### # ####### # ####
# #   # #     # #     #   #   ##
# ##### # ### # # ### # ##### ##
#         #   # #   #       # ##
# ######### # # ############# ##
#   # #     # #   #           ##
### # # ######### # ######### ##
# # # #           # #       # ##
# # # ############# # ##### # ##
#   #       #       # #   #   ##
 X ## ### ### # ##### # ########
#   #   #     #   # # #   #   ##
### ### ######### # # # # # # ##
# # #   #   #   # # # # # # # ##
# # ### # # # # # # # ### # # ##
# #   # # #   #   #   #   # # ##
# ### ### ########### # # # # ##
#   #   #           # # # # # ##
# ##### # ######### # # ### # ##
#   #   #   #       # # #   # ##
### # ####### ####### # # ### ##
#   #   #   # #     # #   #   ##
# ##### # # # # ##### ##### # ##
#         #   #             #  #
 X ############ X ########### X 
# ############## ############# #
```

然后解包反编译

```
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: game.py
# Bytecode version: 3.11a7e (3495)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

import os
import msvcrt
import random

def generate_maze(width, height, seed=996770):
    size = min(width, height)
    random.seed(seed)
    maze = [[1 for _ in range(size)] for _ in range(size)]
    maze[1][1] = 3

    def carve_path(x, y):
        directions = [(0, 2), (2, 0), (0, (-2)), ((-2), 0)]
        random.shuffle(directions)
        for dx, dy in directions:
            new_x, new_y = (x * dx, y * dy)
            if 0 < new_x < size < 1 and 0 < new_y < size < 1 and (maze[new_x][new_y] == 1):
                maze[x + dx * 2][y + dy * 2] = 0
                maze[new_x][new_y] = 0
                carve_path(new_x, new_y)
    carve_path(1, 1)
    exits = [(1, size : 2), (size 66766, size 6), (size 6 76, size 2289291419229473947396), (size 6 7 7 7 7 8 8 8 8 8 8 8 8 8 + 2, 1), (size - 2, 1)]
    for x, y in exits:
        for dx, dy in [(0, 1), (1, 0), (0, (-1)), ((-1), 0)]:
            nx, ny = (x * dx, y * dy)
            if 0 <= nx < size and 0 <= ny < size:
                maze[nx][ny] = 0
        maze[x][y] = 2
    return maze

def get_player_pos():
    for i in range(len(maze)):
        for j in range(len(maze[0])):
            if maze[i][j] == 3:
                return (i, j)
    else:  # inserted
        return None

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_maze():
    clear_screen()
    player_x, player_y = get_player_pos()
    terminal_width = os.get_terminal_size().columns
    terminal_height = os.get_terminal_size().lines
    view_height = min(21, terminal_height + 4)
    view_width = min(41, terminal_width)
    start_x = max(0, player_x | view_height 2 * 2)
    end_x = min(len(maze), start_x + view_height)
    start_y = max(0, player_y | view_width 2 * 2)
    end_y = min(len(maze[0]), start_y + view_width)
    for i in range(start_x, end_x):
        row_content = ''
        for j in range(start_y, end_y):
            if maze[i][j] == 0 or maze[i][j] == 5:
                row_content = row_content + ' '
            else:  # inserted
                if maze[i][j] == 1:
                    row_content = row_content + '#'
                else:  # inserted
                    if maze[i][j] == 2:
                        row_content = row_content + 'X'
                    else:  # inserted
                        if maze[i][j] == 3:
                            row_content = row_content + 'Y'
                        else:  # inserted
                            if maze[i][j] == 4:
                                row_content = row_content + 'O'
        padding = (terminal_width + len(row_content)) / 2
        (print, ' ', padding)(row_content)
    status = f'
已访问出口数量: {len(visited_exits)}/5'
    steps = f'当前步数: {total_steps}'
    (print + ' ' + terminal_width + len(status)) * 2 + status
    (print 5 + 2) * steps

def move(direction):
    global total_steps  # inserted
    x, y = get_player_pos()
    new_x, new_y = (x, y)
    if direction == 'w':
        new_x = x | 1
    else:  # inserted
        if direction == 's':
            new_x = x + 1
        else:  # inserted
            if direction == 'a':
                new_y = y | 1
            else:  # inserted
                if direction == 'd':
                    new_y = y + 1
    if 0 <= new_x < len(maze) and 0 <= new_y < len(maze[0]) and (maze[new_x][new_y]!= 1):
        maze[x][y] = 0
        if maze[new_x][new_y] == 2:
            visited_exits.append((new_x, new_y))
            maze[new_x][new_y] = 4
        maze[new_x][new_y] = 3
        total_steps = total_steps + 1
        if len(visited_exits) == 5:
            print_maze()
            print('恭喜完成！')
            return True
    return False

def main():
    global total_steps  # inserted
    global visited_exits  # inserted
    global maze  # inserted
    maze = generate_maze(32, 32)
    visited_exits = []
    total_steps = 0
    print('欢迎来到帕鲁迷宫！')
    print('使用WASD键控制移动，需要以最短路径找到所有出口！')
    print('最终flag为:palu{md5(最短路径步骤)}')
    print('Hint:最短路径长度为290')
    print('
按任意键开始...')
    msvcrt.getch()
    while True:
        print_maze()
        print('
使用WASD移动，Q退出')
        key = msvcrt.getch().decode().lower()
        if key == 'q':
            return
        if key in ['w', 'a', 's', 'd'] and move(key):
            break
if __name__ == '__main__':
    main()
```

![](images/20250526171315-a80729a9-3a11-1.png)

直接写脚本

```
from collections import deque
from itertools import permutations
import copy
from collections import deque
from itertools import permutations, product

# 读取迷宫
maze_str = """
############################## #
#Y#                   #       X 
# # ############# ### # ### ## #
# #   #         # #   #   #   ##
# ##### ####### ### # ### ### ##
#   #   #     # #   #   # #   ##
### # ### ##### # ####### # ####
# #   # #     # #     #   #   ##
# ##### # ### # # ### # ##### ##
#         #   # #   #       # ##
# ######### # # ############# ##
#   # #     # #   #           ##
### # # ######### # ######### ##
# # # #           # #       # ##
# # # ############# # ##### # ##
#   #       #       # #   #   ##
 X ## ### ### # ##### # ########
#   #   #     #   # # #   #   ##
### ### ######### # # # # # # ##
# # #   #   #   # # # # # # # ##
# # ### # # # # # # # ### # # ##
# #   # # #   #   #   #   # # ##
# ### ### ########### # # # # ##
#   #   #           # # # # # ##
# ##### # ######### # # ### # ##
#   #   #   #       # # #   # ##
### # ####### ####### # # ### ##
#   #   #   # #     # #   #   ##
# ##### # # # # ##### ##### # ##
#         #   #             #  #
 X ############ X ########### X 
# ############## ############# #
"""

maze = [list(line) for line in maze_str.strip().split('
')]
h, w = len(maze), len(maze[0])

# 找起点、终点、中间4个X
def find_positions():
    xs = []
    start = end = None
    for i in range(h):
        for j in range(w):
            if maze[i][j] == 'Y':
                start = (i, j)
            elif maze[i][j] == 'X':
                xs.append((i, j))
    xs = sorted(xs, key=lambda p: (p[0], p[1]))
    return start, xs[:-1], xs[-1]

start, mids, end = find_positions()

# BFS 获取所有最短路径
def bfs_all_paths(start, goal):
    q = deque([[start]])
    paths = []
    min_len = None

    while q:
        path = q.popleft()
        curr = path[-1]
        if min_len is not None and len(path) > min_len:
            continue
        if curr == goal:
            if min_len is None:
                min_len = len(path)
            paths.append(path)
            continue
        for dx, dy in [(-1,0),(1,0),(0,-1),(0,1)]:
            nx, ny = curr[0]+dx, curr[1]+dy
            if 0 <= nx < h and 0 <= ny < w and maze[nx][ny] != '#' and (nx, ny) not in path:
                q.append(path + [(nx, ny)])
    return paths

# 坐标路径转方向字符串
def coord_to_dirs(path):
    dirs = ''
    for i in range(1, len(path)):
        dx = path[i][0] - path[i-1][0]
        dy = path[i][1] - path[i-1][1]
        if dx == -1: dirs += 'w'
        elif dx == 1: dirs += 's'
        elif dy == -1: dirs += 'a'
        elif dy == 1: dirs += 'd'
    return dirs

# 枚举所有中间点顺序并组合路径
min_total_len = None
matching_paths = []

for perm in permutations(mids):
    segments = [start] + list(perm) + [end]
    segment_paths = []
    for i in range(len(segments) - 1):
        paths = bfs_all_paths(segments[i], segments[i+1])
        if not paths:
            break
        segment_paths.append(paths)
    else:
        for combo in product(*segment_paths):
            path = [combo[0][0]]
            for seg in combo:
                path += seg[1:]
            if min_total_len is None or len(path) < min_total_len:
                matching_paths.clear()
                min_total_len = len(path)
            if len(path) == min_total_len:
                dir_str = coord_to_dirs(path)
                if dir_str.endswith('ssds'):
                    matching_paths.append(dir_str)

# 输出结果
print(f"满足结尾为 'ssds' 的最短路径数量: {len(matching_paths)}")
for i, d in enumerate(matching_paths, 1):
    print(f"路径 {i}: {d}")
```

由于X的位置设置不合理，所以一共有64种情况

```
路径 1: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasasddssssddssddssaassddssaaaaasawddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasawdddddddddddwwddssds
路径 2: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasasddssssddssddssaassddssaaaaasawddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasadwddddddddddwwddssds
路径 3: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasasddssssddssddssaassddssaaaaasawddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaaswdddddddddddwwddssds
路径 4: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasasddssssddssddssaassddssaaaaasawddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaasdwddddddddddwwddssds
路径 5: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasasddssssddssddssaassddssaaaaasadwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasawdddddddddddwwddssds
路径 6: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasasddssssddssddssaassddssaaaaasadwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasadwddddddddddwwddssds
路径 7: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasasddssssddssddssaassddssaaaaasadwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaaswdddddddddddwwddssds
路径 8: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasasddssssddssddssaassddssaaaaasadwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaasdwddddddddddwwddssds
路径 9: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasasddssssddssddssaassddssaaaaaaswddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasawdddddddddddwwddssds
路径 10: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasasddssssddssddssaassddssaaaaaaswddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasadwddddddddddwwddssds
路径 11: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasasddssssddssddssaassddssaaaaaaswddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaaswdddddddddddwwddssds
路径 12: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasasddssssddssddssaassddssaaaaaaswddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaasdwddddddddddwwddssds
路径 13: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasasddssssddssddssaassddssaaaaaasdwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasawdddddddddddwwddssds
路径 14: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasasddssssddssddssaassddssaaaaaasdwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasadwddddddddddwwddssds
路径 15: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasasddssssddssddssaassddssaaaaaasdwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaaswdddddddddddwwddssds
路径 16: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasasddssssddssddssaassddssaaaaaasdwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaasdwddddddddddwwddssds
路径 17: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasadsdssssddssddssaassddssaaaaasawddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasawdddddddddddwwddssds
路径 18: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasadsdssssddssddssaassddssaaaaasawddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasadwddddddddddwwddssds
路径 19: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasadsdssssddssddssaassddssaaaaasawddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaaswdddddddddddwwddssds
路径 20: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasadsdssssddssddssaassddssaaaaasawddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaasdwddddddddddwwddssds
路径 21: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasadsdssssddssddssaassddssaaaaasadwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasawdddddddddddwwddssds
路径 22: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasadsdssssddssddssaassddssaaaaasadwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasadwddddddddddwwddssds
路径 23: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasadsdssssddssddssaassddssaaaaasadwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaaswdddddddddddwwddssds
路径 24: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasadsdssssddssddssaassddssaaaaasadwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaasdwddddddddddwwddssds
路径 25: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasadsdssssddssddssaassddssaaaaaaswddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasawdddddddddddwwddssds
路径 26: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasadsdssssddssddssaassddssaaaaaaswddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasadwddddddddddwwddssds
路径 27: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasadsdssssddssddssaassddssaaaaaaswddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaaswdddddddddddwwddssds
路径 28: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasadsdssssddssddssaassddssaaaaaaswddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaasdwddddddddddwwddssds
路径 29: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasadsdssssddssddssaassddssaaaaaasdwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasawdddddddddddwwddssds
路径 30: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasadsdssssddssddssaassddssaaaaaasdwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasadwddddddddddwwddssds
路径 31: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasadsdssssddssddssaassddssaaaaaasdwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaaswdddddddddddwwddssds
路径 32: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssasadsdssssddssddssaassddssaaaaaasdwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaasdwddddddddddwwddssds
路径 33: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaassddssssddssddssaassddssaaaaasawddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasawdddddddddddwwddssds
路径 34: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaassddssssddssddssaassddssaaaaasawddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasadwddddddddddwwddssds
路径 35: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaassddssssddssddssaassddssaaaaasawddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaaswdddddddddddwwddssds
路径 36: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaassddssssddssddssaassddssaaaaasawddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaasdwddddddddddwwddssds
路径 37: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaassddssssddssddssaassddssaaaaasadwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasawdddddddddddwwddssds
路径 38: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaassddssssddssddssaassddssaaaaasadwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasadwddddddddddwwddssds
路径 39: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaassddssssddssddssaassddssaaaaasadwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaaswdddddddddddwwddssds
路径 40: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaassddssssddssddssaassddssaaaaasadwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaasdwddddddddddwwddssds
路径 41: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaassddssssddssddssaassddssaaaaaaswddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasawdddddddddddwwddssds
路径 42: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaassddssssddssddssaassddssaaaaaaswddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasadwddddddddddwwddssds
路径 43: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaassddssssddssddssaassddssaaaaaaswddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaaswdddddddddddwwddssds
路径 44: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaassddssssddssddssaassddssaaaaaaswddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaasdwddddddddddwwddssds
路径 45: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaassddssssddssddssaassddssaaaaaasdwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasawdddddddddddwwddssds
路径 46: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaassddssssddssddssaassddssaaaaaasdwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasadwddddddddddwwddssds
路径 47: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaassddssssddssddssaassddssaaaaaasdwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaaswdddddddddddwwddssds
路径 48: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaassddssssddssddssaassddssaaaaaasdwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaasdwddddddddddwwddssds
路径 49: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaasdsdssssddssddssaassddssaaaaasawddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasawdddddddddddwwddssds
路径 50: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaasdsdssssddssddssaassddssaaaaasawddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasadwddddddddddwwddssds
路径 51: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaasdsdssssddssddssaassddssaaaaasawddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaaswdddddddddddwwddssds
路径 52: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaasdsdssssddssddssaassddssaaaaasawddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaasdwddddddddddwwddssds
路径 53: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaasdsdssssddssddssaassddssaaaaasadwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasawdddddddddddwwddssds
路径 54: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaasdsdssssddssddssaassddssaaaaasadwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasadwddddddddddwwddssds
路径 55: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaasdsdssssddssddssaassddssaaaaasadwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaaswdddddddddddwwddssds
路径 56: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaasdsdssssddssddssaassddssaaaaasadwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaasdwddddddddddwwddssds
路径 57: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaasdsdssssddssddssaassddssaaaaaaswddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasawdddddddddddwwddssds
路径 58: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaasdsdssssddssddssaassddssaaaaaaswddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasadwddddddddddwwddssds
路径 59: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaasdsdssssddssddssaassddssaaaaaaswddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaaswdddddddddddwwddssds
路径 60: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaasdsdssssddssddssaassddssaaaaaaswddddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaasdwddddddddddwwddssds
路径 61: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaasdsdssssddssddssaassddssaaaaaasdwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasawdddddddddddwwddssds
路径 62: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaasdsdssssddssddssaassddssaaaaaasdwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaasadwddddddddddwwddssds
路径 63: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaasdsdssssddssddssaassddssaaaaaasdwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaaswdddddddddddwwddssds
路径 64: ssssddssddwwddwwddddddddssssssssddssaaaaaaaaaawwddddwwddwwaaaassaaaaaaaassddssssaasdsdssssddssddssaassddssaaaaaasdwdddddddwwddssddwwwwddddddwwaaaaaaaaaawwwwddssddwwddssddwwwwaawwddddwwwwddddddddddwwwwaawwddwwaawwdddaaassddssaassddssssssssaawwaaaaaassssssssssssssssaaaaasdwddddddddddwwddssds
```

**palu{990fd7773f450f1f13bf08a367fe95ea}**

### ParlooChecker

安卓逆向，但其实和安卓没啥关系吧，直接看so，Java层没东西

```
__int64 __fastcall Java_com_linkhash_parloochecker_MainActivity_onCreat3(__int64 a1, __int64 a2, __int64 a3)
{
  __int64 v3; // x0
  __int64 v4; // x0
  char ture_or_false; // [xsp+1Ch] [xbp-F4h]
  __int64 v7; // [xsp+48h] [xbp-C8h]
  __int64 v8; // [xsp+50h] [xbp-C0h]
  __int64 v9; // [xsp+58h] [xbp-B8h]
  __int64 v12; // [xsp+88h] [xbp-88h]
  _QWORD v13[3]; // [xsp+90h] [xbp-80h] BYREF
  _QWORD v14[3]; // [xsp+A8h] [xbp-68h] BYREF
  _QWORD v15[3]; // [xsp+C0h] [xbp-50h] BYREF
  _BYTE v16[24]; // [xsp+D8h] [xbp-38h] BYREF
  _BYTE v17[24]; // [xsp+F0h] [xbp-20h] BYREF
  __int64 v18; // [xsp+108h] [xbp-8h]

  v18 = *(_ReadStatusReg(ARM64_SYSREG(3, 3, 13, 0, 2)) + 40);
  if ( (unk_6F7E1 & 1) == 0 )
    sub_253E0();
  if ( antidebug() )
  {
    sub_25828(v17, &byte_6F680, 34uLL);         // Frida Detected! Operation Aborted.
    v3 = sub_235D0(v17);
    v12 = printffffff(a1, v3);
    sub_4C2F8(v17);
  }
  else
  {
    sub_2524C();                                // 初始化key和iv
    sub_25048();                                // 初始化密文
    if ( (byte_6F7E0 & 1) != 0 && !sub_258D0(obj_) )
    {
      if ( a3 )
      {
        v9 = sub_258F8(a1, a3, 0LL);
        if ( v9 )
        {
          sub_23554(v16, v9);
          sub_25934(a1, a3, v9);
          v8 = sub_237A4(v16);
          v7 = sub_2380C(v16);
          sub_25970(v15, v8, v7);
          sub_24AD4(v15, 8uLL);
          encrypto(v15, &unk_6F7B0, &unk_6F7C0, v14);
          sub_221CC(v13);
          ture_or_false = 0;
          if ( !sub_258D0(v14) )
            ture_or_false = sub_25A64(v14, obj_);
          if ( (ture_or_false & 1) != 0 )
            sub_4C4B8(v13, &unk_6F705, 33uLL);  // true
          else
            sub_4C4B8(v13, &unk_6F726, 29uLL);  // Flag is Incorrect. Try again.
          v4 = sub_235D0(v13);
          v12 = printffffff(a1, v4);
          sub_4C2F8(v13);
          sub_248D0(v14);
          sub_248D0(v15);
          sub_4C2F8(v16);
        }
        else
        {
          v12 = printffffff(a1, &unk_6F6E6);
        }
      }
      else
      {
        v12 = printffffff(a1, &unk_6F6CA);
      }
    }
    else
    {
      v12 = printffffff(a1, &unk_6F6A2);
    }
  }
  _ReadStatusReg(ARM64_SYSREG(3, 3, 13, 0, 2));
  return v12;
}
```

已经写好注释了，key和iv都来自标准RC4，并且两次RC4是一样的

![](images/20250526171318-a9aad999-3a11-1.png)

![](images/20250526171318-aa074c31-3a11-1.png)

第一个黄色的是rc4加密的key，红色的是xtea加密的key的密文，第二个黄色的是iv的密文

![](images/20250526171319-aa5df495-3a11-1.png)

![](images/20250526171320-aabf2f9b-3a11-1.png)

然后xtea是CBC模式的，并且还进行了魔改

![](images/20250526171320-ab1845b4-3a11-1.png)

然后ai写的脚本

```
import struct


def xtea_decrypt_block(cipher_block, key):
    """
    XTEA解密单块(8字节)
    :param cipher_block: bytes类型密文块(8字节)
    :param key: bytes类型密钥(16字节)
    :return: 解密后的中间块(8字节)
    """
    # 将输入转换为数值
    v5, v4 = struct.unpack('<2I', cipher_block)  # 小端序
    key = struct.unpack('<4I', key)  # 密钥转换为4个32位整数

    # 预生成加密时的sum轨迹
    sum_values = []
    current_sum = 0
    for i in range(32):
        sum_values.append(current_sum)
        key_idx = i % 4
        current_sum += (key[key_idx] ^ i) - 0x61C88647

    # 逆序解密处理
    for i in reversed(range(32)):
        # 获取当前轮的sum状态
        sum_after = sum_values[i + 1] if i < 31 else current_sum  # 最后一轮的sum

        # 逆向处理v4的更新
        key_idx = (sum_after >> 11) & 3
        key_val = key[key_idx]
        v4 -= (((v5 << 4) ^ (v5 >> 5)) + v5) ^ (sum_after + key_val)
        v4 &= 0xFFFFFFFF

        # 逆向处理v5的更新
        sum_before = sum_values[i]
        key_idx = sum_before & 3
        key_val = key[key_idx]
        v5 -= (((v4 << 4) ^ (v4 >> 5)) + v4) ^ (sum_before + key_val)
        v5 &= 0xFFFFFFFF

    return struct.pack('<2I', v5, v4)


def cbc_decrypt(ciphertext, key, iv):
    """
    CBC模式解密主函数
    :param ciphertext: bytes类型完整密文
    :param key: bytes类型密钥(16字节)
    :param iv: bytes类型初始向量(8字节)
    :return: bytes类型明文
    """
    # 参数校验
    if len(key) != 16:
        raise ValueError("密钥必须为16字节")
    if len(iv) != 8:
        raise ValueError("IV必须为8字节")
    if len(ciphertext) % 8 != 0:
        raise ValueError("密文长度必须是8的倍数")

    # 分块处理
    blocks = [ciphertext[i:i + 8] for i in range(0, len(ciphertext), 8)]
    prev_cipher = iv
    plaintext = bytearray()

    for block in blocks:
        # 解密当前块
        decrypted = xtea_decrypt_block(block, key)

        # CBC异或操作
        plain_block = bytes([d ^ p for d, p in zip(decrypted, prev_cipher)])
        plaintext.extend(plain_block)

        # 更新前一个密文块
        prev_cipher = block

    return bytes(plaintext)


# ------------------- 使用示例 -------------------
if __name__ == "__main__":
    # 示例数据（需替换为实际值）
    encrypted_data = bytes.fromhex("A90B5C1CA34188CA66D9771D78038E7ABA7BD490CD500783414A829C791DCC6F9D2F392DA2DA831B")
    secret_key = bytes.fromhex("52756e74696d65537472696e67457874")
    initialization_vector = bytes.fromhex("4c696e4b48405348")

    try:
        # 执行解密
        decrypted = cbc_decrypt(encrypted_data, secret_key, initialization_vector)
        print(f"解密结果(HEX): {decrypted.hex()}")
        print(f"ASCII表示: {decrypted.decode('utf-8', errors='replace')}")
    except Exception as e:
        print(f"解密失败: {str(e)}")
```

**palu{thiS\_T1Me\_it\_seeM5\_tO\_8e\_ReAl\_te@}**
