# crypto_方程组思想应用-先知社区

> **来源**: https://xz.aliyun.com/news/17136  
> **文章ID**: 17136

---

文章分为两部分，一部分是lfsr，另一部分是结式

# lfsr

lfsr是一类线性寄存器，不了解的话可以查看我的另一篇文章'CTF\_Crypro\_PRNG浅析'  
lfsr就是在fsr的基础上确保了用来生成新的数值的反馈函数是一个与b1，b2,......,bn-1，bn，这n个数值都相关的线性函数,也就是n元一次方程这样子,当然也就可以使用方程组的方法来解出题目

## 原理

把整个线性寄存的过程写为如下形式  
a\_1*x\_1 mod 2 + a\_2*x\_2 mod 2 +……+ a\_n*x\_n mod 2 = a\_{n+1}  
a\_2*x\_1 mod 2 + a\_3\*x\_2 mod 2 +……+ a\_{n+1}*x\_n mod 2 = a\_{n+2}  
.  
.  
.  
a\_n*x\_1 mod 2 + a\_{n+1}\*x\_2 mod 2 +……+ a\_{2n-1}\*x\_n mod 2 = a\_{2n}

可以明显地看出这就是一个方程组，所以只要知道mask(x\_1~~x\_n),输入序列(a\_1~~a\_n),输出序列(a\_{n+1}~a\_{2n})之中的的两个部分就可以得出剩余的一个部分的值从而得到flag

## 例题

```
import hashlib
from secret import KEY,FLAG,MASK
assert(FLAG=="de1ctf{"+hashlib.sha256(hex(KEY)[2:].rstrip('L')).hexdigest()+"}")
assert(FLAG[7:11]=='1224')
LENGTH = 256
assert(KEY.bit_length()==LENGTH)
assert(MASK.bit_length()==LENGTH)
def pad(m):
    pad_length = 8 - len(m)
    return pad_length*'0'+m
class lfsr():
    def __init__(self, init, mask, length):
        self.init = init
        self.mask = mask
        self.lengthmask = 2**(length+1)-1

    def next(self):
        nextdata = (self.init << 1) & self.lengthmask 
        i = self.init & self.mask & self.lengthmask 
        output = 0
        while i != 0:
            output ^= (i & 1)
            i = i >> 1
        nextdata ^= output
        self.init = nextdata
        return output
if __name__=="__main__":
    l = lfsr(KEY,MASK,LENGTH)
    r = ''
    for i in range(63):
        b = 0
        for j in range(8):
            b = (b<<1)+l.next()
        r += pad(bin(b)[2:])
    with open('output','w') as f:
        f.write(r)
```

### 分析

题目给出了504个输出序列，且mask的值为256，那就意味着如下方所示的一个结构：

```
a_1*x_1 mod 2        + a_2*x_2 mod 2        +……+ a_256*x_256 mod 2     = a_257
a_2*x_1 mod 2        + a_3*x_2 mod 2        +……+ a_257*x_256 mod 2     = a_258
.
.
.
a_256*x_1 mod 2   +  a_257*x_2 mod 2   +……+ a_511*x_256 mod 2     = a_512
```

这时我们已知可以爆破出最后8位数值，也就2^8 = 256种可能，然后再按照列方程组的方式将输入序列、输出序列列入，然后解这个256元一次函数得到256个可能的mask值  
然后筛选得到一个有意义的mask字符串，估计就是flag了

### exp

```
import hashlib

key = ''

#将二进制数据填充为8位
def pad(x):
    pad_length = 8 - len(x)
    return '0'*pad_length+x  

# 获取 256个 key 可能值
def get_key(mask,key):
    R = ""
    index = 0
    key = key[255] + key[:256]
    while index < 256:
        tmp = 0
        for i in range(256):
            if mask >> i & 1:
                # tmp ^= int(key[255 - i])
                tmp = (tmp+int(key[255-i]))%2
        R = str(tmp) + R
        index += 1
        key = key[255] + str(tmp) + key[1:255]
    return int(R,2)

# 将二进制流转化为十进制
def get_int(x):
    m=''
    for i in range(256):
        m += str(x[i])
    return (int(m,2))

# 获取到256个 mask 可能值，再调用 get_key()函数，获取到key值，将结果导入到 sm 中
sm = []
for pad_bit in range(2**8):   #爆破rr中缺失的8位
    r = key+pad(bin(pad_bit)[2:])
    index = 0
    a = []
    for i in range(len(r)):
        a.append(int(r[i]))       #将 r 转换成列表a = [0,0,1,...,]格式    
    res = []
    for i in range(256):
        for j in range(256):
            if a[i+j]==1:
                res.append(1)
            else:
                res.append(0)
    sn = []
    for i in range(256):
        if a[256+i]==1:
            sn.append(1)
        else:
            sn.append(0)
    MS = MatrixSpace(GF(2),256,256)        #构造 256 * 256 的矩阵空间
    MSS = MatrixSpace(GF(2),1,256)         #构造 1 * 256 的矩阵空间
    A = MS(res)
    s = MSS(sn)                       #将 res 和 sn 的值导入矩阵空间中
    try:
        inv = A.inverse()            # 求A 的逆矩阵
    except ZeroDivisionError as e:
        continue
    mask = s*inv                     #构造矩阵求mask，B-M 算法
#     print(mask[0])                  #得到 256 个 mask 值()，type元组
#     print(get_int(mask[0]))
#     print(key_list)
#     print(key[:256])
#     print(hex(solve(get_int(mask[0]),key[:256])))
#     break   
    sm.append(hex(get_key(get_int(mask[0]),key[:256]))) 

# 通过限制条件确定 最终 的flag值
for i in range(len(sm)):
    FLAG = hashlib.sha256(sm[i][2:].encode()).hexdigest()
    if FLAG[:4]=='1224':
        print('flag{'+FLAG+'}')
```

# 结式

## 知识点

结式（Resultant）是用于判断两个多项式是否存在公共根的工具。对于多项式 f(x) 和 g(x)，结式 Res(f,g,x) 是一个关于多项式系数的行列式，当且仅当 f 和 g 有公共根时其值为零  
在密码类题目里面，结式主要用于消去变量，将多变量方程组转化为单变量方程，从而求解。在SageMath中可直接调用 f.resultant(g, x) 计算结式，不嫌麻烦的话通过西尔维斯特矩阵构造行列式计算

### 结式的通俗解释

结式是一个用来判断两个多项式是否有共同根的工具。简单来说，假设你有两个关于 x 的多项式f(x) 和 g(x)，它们的系数可以组成一个特殊的矩阵（叫做西尔维斯特矩阵），这个矩阵的行列式就是结式。  
结式的值有两种情况：1.如果结式为0：说明 f(x) 和 g(x) 有共同的根。2.结式不为0：说明 f(x) 和 g(x) 无共同的根。  
也即：结式为0 → 两个多项式有共同根 → gcd 不是 1。结式不为0 → 两个多项式没有共同根 → gcd 是 1。

## 例题

因为没找到适合的例题就自己口胡了一道

### 题目

```
from sympy import symbols, Poly, isprime
from math import gcd
from random import randint

# 定义符号变量
x, y = symbols('x y')

# 1. 生成多项式 f(x, y) 和 g(x, y)
f = Poly(x**2 + y**2 - 1, domain='QQ')
g = Poly(x**3 + y**3 - 2, domain='QQ')
print(f"f(x, y) = {f}")
print(f"g(x, y) = {g}")

def generate_p_q(x_val, y_val):
    p = x_val**2 * y_val - y_val
    q = x_val * y_val**2 - x_val
    return p, q

p, q = generate_p_q()

assert isprime(p)
assert isprime(q)

n = p * q
print(f"n = p * q = {n}")

def rsa_encrypt(m, e, n):
    return pow(m, e, n)

e = 65537 
c = rsa_encrypt(m, e, n)
print(f"Ciphertext c = {c}")

```

### 分析

给定两个多项式 f(x, y) 和 g(x, y)，以及一个密文 c，其中：

f(x, y) = x^2 + y^2 - 1  
g(x, y) = x^3 + y^3 - 2

密文 c 是通过某个与 x 和 y 相关的密钥生成的。目标是求解 x 和 y 的值，并恢复明文

### 解答

```
// 定义多项式环
R.<x, y> = PolynomialRing(QQ)
// PolynomialRing(QQ) 表示多项式系数属于有理数域 Q，因为是口胡的题目就写的简单点。需要有限域就用 PolynomialRing(GF(p))，其中 p 是素数。

// 定义两个多项式
f = x^2 + y^2 - 1
g = x^3 + y^3 - 2

// 计算结式，消去 y
h = f.resultant(g, y)

// 求解关于 x 的方程
x_roots = h.univariate_polynomial().roots()

// 遍历 x 的根，求解对应的 y
solutions = []
for x_root, _ in x_roots:
    y_poly = f.subs(x=x_root).univariate_polynomial()
    y_roots = y_poly.roots()
    for y_root, _ in y_roots:
        solutions.append((x_root, y_root))

// 输出所有解
print("Solutions (x, y):")
for sol in solutions:
    print(sol)

//注：因为题目是我即兴想的，也没有数据，所以做不了的，只是用来介绍一下这种思路
```
