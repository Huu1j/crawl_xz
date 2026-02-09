# ctf_crypto_多项式题目浅析-先知社区

> **来源**: https://xz.aliyun.com/news/16950  
> **文章ID**: 16950

---

# 多项式rsa

## 知识点杂谈

首先理解这样一条公式  
φ(n) == φ(p)*φ(q)  
平常简写为  
φ(n) == (p-1)*(q-1)  
但是在这些题里面  
n为多项式  
则分解出来的p,q也是多项式  
对于不可约多项式p(x)，显然φ(p(x))=x-1是不成立的  
已知欧拉函数是小于或等于n的正整数中与n的数的数目。

### 以下是个人理解

假设存在一个次数小于 n 的多项式 f(x) 与 p(x) 不互素  
假设 f(x) 和 p(x) 有一个非常数的公因式 d(x)。由于 p(x) 是不可约的， d(x) 只能是p(x) 本身或其倍数。

d(x) 的可能性：如果 d(x)=p(x)，那么 p(x) 是 f(x) 的因式。但是， f(x) 的次数小于 p(x)，所以这是不可能的。

如果 d(x) 是 p(x) 的倍数，那么 d(x)=k⋅p(x)，其中 k 是一个非零常数。但是，d(x) 作为 f(x) 的因式，次数仍然大于或等于 p(x) 的次数，这与 f(x) 的次数小于 n 矛盾。

因此，不存在一个次数小于 n 的多项式 f(x) 与 p(x) 有非常数的公因式。这意味着f(x) 和 p(x) 的最大公因式是1，即它们互素。

由此可以得出结论：在有限域GF(p)上,不可约多项式p(x)，除了0，长度为n每一个多项式都与p(x)互素  
所以φ(p(x)) == p^n - 1

## 例题 [watevrCTF 2019]Swedish RSA

### 题目

```
flag = bytearray(raw_input())
flag = list(flag)
length = len(flag)
bits = 16

## Prime for Finite Field.
p = random_prime(2^bits-1, False, 2^(bits-1))

file_out = open("downloads/polynomial_rsa.txt", "w")
file_out.write("Prime: " + str(p) + "
")

## Univariate Polynomial Ring in y over Finite Field of size p
R.<y> = PolynomialRing(GF(p))

## Analogous to the primes in Z
def gen_irreducable_poly(deg):
    while True:
        out = R.random_element(degree=deg)
        if out.is_irreducible():
            return out


## Polynomial "primes"
P = gen_irreducable_poly(ZZ.random_element(length, 2*length))
Q = gen_irreducable_poly(ZZ.random_element(length, 2*length))

## Public exponent key
e = 65537

## Modulus
N = P*Q
file_out.write("Modulus: " + str(N) + "
")

## Univariate Quotient Polynomial Ring in x over Finite Field of size 659 with modulus N(x)
S.<x> = R.quotient(N)

## Encrypt
m = S(flag)
c = m^e

file_out.write("Ciphertext: " + str(c))
file_out.close()

```

### 分析

因为是有限域上多项式的问题，所以参照上面给出的方法

### 解答

```
# sage

R.<y> = PolynomialRing(GF(43753))
n = R("34036*y^177 + 23068*y^176 + 13147*y^175 + 36344*y^174 + 10045*y^173 + 41049*y^172 + 17786*y^171 + 16601*y^170 + 7929*y^169 + 37570*y^168 + 990*y^167 + 9622*y^166 + 39273*y^165 + 35284*y^164 + 15632*y^163 + 18850*y^162 + 8800*y^161 + 33148*y^160 + 12147*y^159 + 40487*y^158 + 6407*y^157 + 34111*y^156 + 8446*y^155 + 21908*y^154 + 16812*y^153 + 40624*y^152 + 43506*y^151 + 39116*y^150 + 33011*y^149 + 23914*y^148 + 2210*y^147 + 23196*y^146 + 43359*y^145 + 34455*y^144 + 17684*y^143 + 25262*y^142 + 982*y^141 + 24015*y^140 + 27968*y^139 + 37463*y^138 + 10667*y^137 + 39519*y^136 + 31176*y^135 + 27520*y^134 + 32118*y^133 + 8333*y^132 + 38945*y^131 + 34713*y^130 + 1107*y^129 + 43604*y^128 + 4433*y^127 + 18110*y^126 + 17658*y^125 + 32354*y^124 + 3219*y^123 + 40238*y^122 + 10439*y^121 + 3669*y^120 + 8713*y^119 + 21027*y^118 + 29480*y^117 + 5477*y^116 + 24332*y^115 + 43480*y^114 + 33406*y^113 + 43121*y^112 + 1114*y^111 + 17198*y^110 + 22829*y^109 + 24424*y^108 + 16523*y^107 + 20424*y^106 + 36206*y^105 + 41849*y^104 + 3584*y^103 + 26500*y^102 + 31897*y^101 + 34640*y^100 + 27449*y^99 + 30962*y^98 + 41434*y^97 + 22125*y^96 + 24314*y^95 + 3944*y^94 + 18400*y^93 + 38476*y^92 + 28904*y^91 + 27936*y^90 + 41867*y^89 + 25573*y^88 + 25659*y^87 + 33443*y^86 + 18435*y^85 + 5934*y^84 + 38030*y^83 + 17563*y^82 + 24086*y^81 + 36782*y^80 + 20922*y^79 + 38933*y^78 + 23448*y^77 + 10599*y^76 + 7156*y^75 + 29044*y^74 + 23605*y^73 + 7657*y^72 + 28200*y^71 + 2431*y^70 + 3860*y^69 + 23259*y^68 + 14590*y^67 + 33631*y^66 + 15673*y^65 + 36049*y^64 + 29728*y^63 + 22413*y^62 + 18602*y^61 + 18557*y^60 + 23505*y^59 + 17642*y^58 + 12595*y^57 + 17255*y^56 + 15316*y^55 + 8948*y^54 + 38*y^53 + 40329*y^52 + 9823*y^51 + 5798*y^50 + 6379*y^49 + 8662*y^48 + 34640*y^47 + 38321*y^46 + 18760*y^45 + 13135*y^44 + 15926*y^43 + 34952*y^42 + 28940*y^41 + 13558*y^40 + 42579*y^39 + 38015*y^38 + 33788*y^37 + 12381*y^36 + 195*y^35 + 13709*y^34 + 31500*y^33 + 32994*y^32 + 30486*y^31 + 40414*y^30 + 2578*y^29 + 30525*y^28 + 43067*y^27 + 6195*y^26 + 36288*y^25 + 23236*y^24 + 21493*y^23 + 15808*y^22 + 34500*y^21 + 6390*y^20 + 42994*y^19 + 42151*y^18 + 19248*y^17 + 19291*y^16 + 8124*y^15 + 40161*y^14 + 24726*y^13 + 31874*y^12 + 30272*y^11 + 30761*y^10 + 2296*y^9 + 11017*y^8 + 16559*y^7 + 28949*y^6 + 40499*y^5 + 22377*y^4 + 33628*y^3 + 30598*y^2 + 4386*y + 23814")
c = R("5209*y^176 + 10881*y^175 + 31096*y^174 + 23354*y^173 + 28337*y^172 + 15982*y^171 + 13515*y^170 + 21641*y^169 + 10254*y^168 + 34588*y^167 + 27434*y^166 + 29552*y^165 + 7105*y^164 + 22604*y^163 + 41253*y^162 + 42675*y^161 + 21153*y^160 + 32838*y^159 + 34391*y^158 + 832*y^157 + 720*y^156 + 22883*y^155 + 19236*y^154 + 33772*y^153 + 5020*y^152 + 17943*y^151 + 26967*y^150 + 30847*y^149 + 10306*y^148 + 33966*y^147 + 43255*y^146 + 20342*y^145 + 4474*y^144 + 3490*y^143 + 38033*y^142 + 11224*y^141 + 30565*y^140 + 31967*y^139 + 32382*y^138 + 9759*y^137 + 1030*y^136 + 32122*y^135 + 42614*y^134 + 14280*y^133 + 16533*y^132 + 32676*y^131 + 43070*y^130 + 36009*y^129 + 28497*y^128 + 2940*y^127 + 9747*y^126 + 22758*y^125 + 16615*y^124 + 14086*y^123 + 13038*y^122 + 39603*y^121 + 36260*y^120 + 32502*y^119 + 17619*y^118 + 17700*y^117 + 15083*y^116 + 11311*y^115 + 36496*y^114 + 1300*y^113 + 13601*y^112 + 43425*y^111 + 10376*y^110 + 11551*y^109 + 13684*y^108 + 14955*y^107 + 6661*y^106 + 12674*y^105 + 21534*y^104 + 32132*y^103 + 34135*y^102 + 43684*y^101 + 837*y^100 + 29311*y^99 + 4849*y^98 + 26632*y^97 + 26662*y^96 + 10159*y^95 + 32657*y^94 + 12149*y^93 + 17858*y^92 + 35805*y^91 + 19391*y^90 + 30884*y^89 + 42039*y^88 + 17292*y^87 + 4694*y^86 + 1497*y^85 + 1744*y^84 + 31071*y^83 + 26246*y^82 + 24402*y^81 + 22068*y^80 + 39263*y^79 + 23703*y^78 + 21484*y^77 + 12241*y^76 + 28821*y^75 + 32886*y^74 + 43075*y^73 + 35741*y^72 + 19936*y^71 + 37219*y^70 + 33411*y^69 + 8301*y^68 + 12949*y^67 + 28611*y^66 + 42654*y^65 + 6910*y^64 + 18523*y^63 + 31144*y^62 + 21398*y^61 + 36298*y^60 + 27158*y^59 + 918*y^58 + 38601*y^57 + 4269*y^56 + 5699*y^55 + 36444*y^54 + 34791*y^53 + 37978*y^52 + 32481*y^51 + 8039*y^50 + 11012*y^49 + 11454*y^48 + 30450*y^47 + 1381*y^46 + 32403*y^45 + 8202*y^44 + 8404*y^43 + 37648*y^42 + 43696*y^41 + 34237*y^40 + 36490*y^39 + 41423*y^38 + 35792*y^37 + 36950*y^36 + 31086*y^35 + 38970*y^34 + 12439*y^33 + 7963*y^32 + 16150*y^31 + 11382*y^30 + 3038*y^29 + 20157*y^28 + 23531*y^27 + 32866*y^26 + 5428*y^25 + 21132*y^24 + 13443*y^23 + 28909*y^22 + 42716*y^21 + 6567*y^20 + 24744*y^19 + 8727*y^18 + 14895*y^17 + 28172*y^16 + 30903*y^15 + 26608*y^14 + 27314*y^13 + 42224*y^12 + 42551*y^11 + 37726*y^10 + 11203*y^9 + 36816*y^8 + 5537*y^7 + 20301*y^6 + 17591*y^5 + 41279*y^4 + 7999*y^3 + 33753*y^2 + 34551*y + 9659")
e = 65537

p = n.factor()[0][0]
q = n.factor()[1][0]
fai_n = (pow(43753,p.degree())-1) * (pow(43753,q.degree())-1)
d = inverse_mod(e,fai_n)

temp_result = R("1")
while True:
    if d % 2 == 1:
        temp_result = (temp_result * c) % n
        d = d - 1
    c = (c * c) % n
    d = d / 2
    if d == 0:
        break
print(temp_result)

import re
# result = str(temp_result)
result = "125*y^62 + 111*y^61 + 114*y^60 + 117*y^59 + 53*y^58 + 51*y^57 + 51*y^56 + 100*y^55 + 106*y^54 + 110*y^53 + 102*y^52 + 106*y^51 + 100*y^50 + 104*y^49 + 101*y^48 + 117*y^47 + 52*y^46 + 52*y^45 + 57*y^44 + 48*y^43 + 50*y^42 + 107*y^41 + 35*y^40 + 101*y^39 + 114*y^38 + 117*y^37 + 99*y^36 + 101*y^35 + 115*y^34 + 110*y^33 + 105*y^32 + 95*y^31 + 116*y^30 + 117*y^29 + 98*y^28 + 95*y^27 + 110*y^26 + 117*y^25 + 102*y^24 + 95*y^23 + 115*y^22 + 105*y^21 + 95*y^20 + 97*y^19 + 101*y^18 + 107*y^17 + 105*y^16 + 95*y^15 + 109*y^14 + 111*y^13 + 114*y^12 + 102*y^11 + 95*y^10 + 65*y^9 + 83*y^8 + 82*y^7 + 123*y^6 + 114*y^5 + 118*y^4 + 101*y^3 + 116*y^2 + 97*y + 119"

li_result = re.findall(r'\d+',result)
li_flag = []
# print(li_result)
for i in range(0,len(li_result),2):
    li_flag.append(li_result[i])
li_flag.append("119")
# print(li_flag)
for i in li_flag[::-1]:
    print(chr(int(i)),end="")
```

# 多项式插值

## 知识点杂谈

思路：通过已知的多个点值对 (xi,yi)，恢复一个次数最低的多项式 P(x)，使得P(x i)=y i ，并从该多项式中提取关键信息，通常是系数可以提取信息。  
解题思路：  
观察要使用哪一个插值法，常用的有拉格朗日插值法和牛顿插值法，如果是拉格朗日插值法可以直接调用SageMath的lagrange\_polynomial()函数

## 例题 angstrom CTF 2023 - Lazy Lagrange

### 题目

```
N = len(FLAG)
assert N <= 18, 'I\'m too lazy to store a flag that long.'
p = None
a = None
M = (1 << 127) - 1
 
def query1(s):
    if len(s) > 100:
        return 'I\'m too lazy to read a query that long.'
    x = s.split()
    if len(x) > 10:
        return 'I\'m too lazy to process that many inputs.'
    if any(not x_i.isdecimal() for x_i in x):
        return 'I\'m too lazy to decipher strange inputs.'
    x = (int(x_i) for x_i in x)
    global p, a
    p = random.sample(range(N), k=N)
    a = [ord(FLAG[p[i]]) for i in range(N)]
    res = ''
    for x_i in x:
        res += f'{sum(a[j] * x_i ** j for j in range(N)) % M}
'
    return res
 
query1('0')
 
def query2(s):
    if len(s) > 100:
        return 'I\'m too lazy to read a query that long.'
    x = s.split()
    if any(not x_i.isdecimal() for x_i in x):
        return 'I\'m too lazy to decipher strange inputs.'
    x = [int(x_i) for x_i in x]
    while len(x) < N:
        x.append(0)
    z = 1
    for i in range(N):
        z *= not x[i] - a[i]
    return ' '.join(str(p_i * z) for p_i in p)
 
while True:
    try:
        choice = int(input(": "))
        assert 1 <= choice <= 2
        match choice:
            case 1:
                print(query1(input("\t> ")))
            case 2:
                print(query2(input("\t> ")))
    except Exception as e:
        print("Bad input, exiting", e)
        break
```

### 分析

允许用户提交 x值获取计算结果或验证系数序列  
注意到，当 x=128=2^7，多项式值在二进制中按7位分段，会直接暴露系数 a[j]，利用 x=128 的二进制特性直接分离系数，无需插值  
当然如果没有限制输入次数的话用插值法也可以解决，就是麻烦了一些

### 解答

#### 直接令x = 128的解法

```
from pwn import *
 
p = remote('challs.actf.co', 32100)
context.log_level = 'debug'
 
p.sendlineafter(b': ', b'1')
p.sendlineafter(b'> ', b'128')
a = int(p.recvline())
a = bin(a)[2:].rjust(126,'0')
b = [int(a[i:i+7],2) for i in range(0, 126,7)]
b = bytes(b)[::-1]
p.sendlineafter(b': ', b'2')
p.sendlineafter(b'> ', (' '.join([str(i) for i in b])+' ').encode())
odr = [int(i) for i in p.recvline().decode().strip().split()]
a = [0]*18
for i in range(18):
    a[odr[i]]=b[i]
    
print(bytes(a))
```

#### 插值法

query1允许提交最多10个数值，假设这道题没有限制提交的数值个数，则可以输入多个不同的x值，经query1得到对应的y值，然后插值恢复多项式  
1.收集点值对，提交不同 x 值（如 x=1, 2, 3, ...）获取对应的 y 值。  
2.插值恢复多项式  
以下为示例代码，不是完整的exp

```
F = GF(2^127 - 1)
points = [(1, y1), (2, y2), (3, y3), ...]
R.<x> = PolynomialRing(F)
P = R.lagrange_polynomial(points)
coefficients = P.coefficients()
```

3.从系数里获取信息，解出flag
