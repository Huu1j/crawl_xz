# 轩辕杯-Crypto-WP-先知社区

> **来源**: https://xz.aliyun.com/news/18062  
> **文章ID**: 18062

---

## Crypto

### dp

```
出题人说dp都不会打什么密码?
n = 110231451148882079381796143358970452100202953702391108796134950841737642949460527878714265898036116331356438846901198470479054762675790266666921561175879745335346704648242558094026330525194100460497557690574823790674495407503937159099381516207615786485815588440939371996099127648410831094531405905724333332751 dp = 3086447084488829312768217706085402222803155373133262724515307236287352098952292947424429554074367555883852997440538764377662477589192987750154075762783925 c = 59325046548488308883386075244531371583402390744927996480498220618691766045737849650329706821216622090853171635701444247741920578127703036446381752396125610456124290112692914728856924559989383692987222821742728733347723840032917282464481629726528696226995176072605314263644914703785378425284460609365608120126 e = 65537
```

就是普通的dp泄露，推理一下上脚本就是

```
import gmpy2
import binascii

n = 110231451148882079381796143358970452100202953702391108796134950841737642949460527878714265898036116331356438846901198470479054762675790266666921561175879745335346704648242558094026330525194100460497557690574823790674495407503937159099381516207615786485815588440939371996099127648410831094531405905724333332751
dp = 3086447084488829312768217706085402222803155373133262724515307236287352098952292947424429554074367555883852997440538764377662477589192987750154075762783925
c = 59325046548488308883386075244531371583402390744927996480498220618691766045737849650329706821216622090853171635701444247741920578127703036446381752396125610456124290112692914728856924559989383692987222821742728733347723840032917282464481629726528696226995176072605314263644914703785378425284460609365608120126
e = 65537


tmp = e * dp - 1
for k in range(1, e): 
    if tmp % k == 0: 
        p = (tmp // k) +1
        if n % p == 0: 
            q = n // p
            if gmpy2.is_prime(p) and gmpy2.is_prime(q): 
                break

d = gmpy2.invert(e, (p - 1) * (q - 1))  
m =pow(c, d, n) 

m = hex(m)[2:]
flag = binascii.unhexlify(m)
print(flag)
#b'flag{C5G0_1s_the_8eSt_FPS_G@m3}'
```

### easy\_rsa

```
e = 65537
n = 1000000000000000000000000000156000000000000000000000000005643
c = 418535905348643941073541505434424306523376401168593325605206
```

看n的样子，应该是两个1000000000000000XXX这样的数,所以pq接近，用费马分解直接算出来

```
import gmpy2
from Crypto.Util.number import *
e = 65537
n = 1000000000000000000000000000156000000000000000000000000005643
c = 418535905348643941073541505434424306523376401168593325605206
x=gmpy2.iroot(n,2)[0]
while 1:   
    z=pow(x,2)-n
    if gmpy2.is_square(z):
        y=gmpy2.iroot(z,2)[0]
        p=x+y
        q=x-y
        break
    x+=1

phi_n =(p-1)*(q-1)
d=gmpy2.invert(e,phi_n)
print(long_to_bytes(pow(c,d,n)))
#b'xuanyuanbei_easy_rsa!'
```

### 简单编码

```
ABBAABB ABBABAB ABABAAA ABABAAB ABBBBAA ABBAABA ABABBAA ABBAAAA ABBAAAB ABBABAB ABBBAAA ABAABBB ABABBAA ABABABB ABABBAA ABBABBB ABBABAA ABABABA ABAABAB ABBBAAA ABBBABA ABABBAB ABBBBAA ABABBAB ABBBAAA ABBABAB ABBAABA ABABAAA ABABABA AABBAB ABBBABB ABBAABA ABBABAB AABABA ABBBBAA ABBBAAB ABBAABA AABBAB ABABBAA ABBAAAB ABBBAAA ABBABAB ABBABAA ABABABB ABBBABA ABABABB ABBAABB ABBABAA ABBABAB ABBABAB ABABAAA ABBBABA AABABB ABABBAB AABBAB ABABAAA ABBAAAB ABBBBAB ABBBAAA ABABABA ABBAAAA ABABAAB ABABABB ABBABBA ABBABAB AABABA ABBABAA ABBBABA ABBBABA AABBAA ABBBBAA ABBAAAA ABABBBB ABBABAB ABABABB ABAABBB ABBAAAA ABABAAA ABABABB ABBABAA ABBABBA ABABABA ABAABAB ABABABA AABABB ABABBAB ABBBBAA ABBBBAB ABBBAAA ABABAAB ABBABBB ABABAAB ABBAAAA ABAABAB ABBBABB ABBABAA ABBABAB ABABABA ABAABAB ABBBABA ABBAABA AABBAB ABABBAA ABAABAB ABBBAAA ABBABAB ABBBABA ABAABBB ABABBBA ABABABB ABABBAA ABBABBB ABBABAA ABAABAB ABABABA ABBBAAB ABABBAA ABBAABA ABABBAA ABAABAB ABBBAAA ABBABAB ABBABBB ABBBABB ABBBABA ABABBAA ABBABAB ABABABA ABBAABA ABAABAB ABBAABA ABBABBB ABBBAAA ABBAABA ABBBBAA ABBAAAA ABBABAA ABABBAB ABBABAA ABAABBB ABABABA ABABABB ABABABB AABBAB ABBAAAB ABBBBAB ABABABA ABBBABA AABBAB ABABABA ABBABAB ABBBAAB ABBBAAA ABBAAAB ABBBBAA ABBBBAA ABBABAA ABBAABA AABBAB ABBBABA
```

字符长度是7或者是6，不是培根，猜测是ascii码的二进制，有些6应该是ascii码小于64导致的，然后就是输出

```
p=['ABBAABB','ABBABAB','ABABAAA','ABABAAB','ABBBBAA','ABBAABA','ABABBAA','ABBAAAA','ABBAAAB','ABBABAB','ABBBAAA','ABAABBB','ABABBAA','ABABABB','ABABBAA','ABBABBB','ABBABAA','ABABABA','ABAABAB','ABBBAAA','ABBBABA','ABABBAB','ABBBBAA','ABABBAB','ABBBAAA','ABBABAB','ABBAABA','ABABAAA','ABABABA','AABBAB','ABBBABB','ABBAABA','ABBABAB','AABABA','ABBBBAA','ABBBAAB','ABBAABA','AABBAB','ABABBAA','ABBAAAB','ABBBAAA','ABBABAB','ABBABAA','ABABABB','ABBBABA','ABABABB','ABBAABB','ABBABAA','ABBABAB','ABBABAB','ABABAAA','ABBBABA','AABABB','ABABBAB','AABBAB','ABABAAA','ABBAAAB','ABBBBAB','ABBBAAA','ABABABA','ABBAAAA','ABABAAB','ABABABB','ABBABBA','ABBABAB','AABABA','ABBABAA','ABBBABA','ABBBABA','AABBAA','ABBBBAA','ABBAAAA','ABABBBB','ABBABAB','ABABABB','ABAABBB','ABBAAAA','ABABAAA','ABABABB','ABBABAA','ABBABBA','ABABABA','ABAABAB','ABABABA','AABABB','ABABBAB','ABBBBAA','ABBBBAB','ABBBAAA','ABABAAB','ABBABBB','ABABAAB','ABBAAAA','ABAABAB','ABBBABB','ABBABAA','ABBABAB','ABABABA','ABAABAB','ABBBABA','ABBAABA','AABBAB','ABABBAA','ABAABAB','ABBBAAA','ABBABAB','ABBBABA','ABAABBB','ABABBBA','ABABABB','ABABBAA','ABBABBB','ABBABAA','ABAABAB','ABABABA','ABBBAAB','ABABBAA','ABBAABA','ABABBAA','ABAABAB','ABBBAAA','ABBABAB','ABBABBB','ABBBABB','ABBBABA','ABABBAA','ABBABAB','ABABABA','ABBAABA','ABAABAB','ABBAABA','ABBABBB','ABBBAAA','ABBAABA','ABBBBAA','ABBAAAA','ABBABAA','ABABBAB','ABBABAA','ABAABBB','ABABABA','ABABABB','ABABABB','AABBAB','ABBAAAB','ABBBBAB','ABABABA','ABBBABA','AABBAB','ABABABA','ABBABAB','ABBBAAB','ABBBAAA','ABBAAAB','ABBBBAA','ABBBBAA','ABBABAA','ABBAABA','AABBAB','ABBBABA']
m=''
for i in p:
    m+=(chr(int(i.replace('A','1').replace('B','0',),2)))
print(m)
#LJWVCMSONJGXSTSHKUZGERCRGJMWU2DMJ5CFM2SNGJKTETLKJJWE4R2WNBGUOVTIJ5KEE3COPJTXOWTKIUZU4RCBGVHVOZDKJUZEM2SZGJEXQTSHKZUFSMSZGJHDESJUMZMHGMCOKRKXUTT2NBUE2UJFGNCCKM2E
```

没有小写应该是base32

**ZmQ2NjMyNGU2bDQ2YjhlODVjM2U2MjJlNGVhMGVhOTBlNzgwZjE3NDA5OWdjM2FjY2IxNGVhY2Y2N2I4fXs0NTUzNzhhMQ==**

解出来发现Zm开头，果断base64,但出来不是，就w型栅栏重新排序一下

```
fd66324e6l46b8e85c3e622e4ea0ea90e780f174099gc3accb14eacf67b8}{455378a1
flag{c04d6e34aab689c5c0e68eb51753c843e032efa7c16427f8642ee07ab946e981}
```

### babyrsa

```
from Crypto.Util.number import *
from gmpy2 import *
from random import choice
flag = b"flag{****************************}"
m = bytes_to_long(flag)
p = getPrime(256)
q = getPrime(256)
n = p*q
d = getPrime(130)
phi = (p-1)*(q-1)
e = invert(d, phi)
c = pow(m, e, n)
print(f'n = {n}')
print(f'c = {c}')
# print(f'e = {e}')


def gen(bits):
    while True:
        p = 2
        while p.bit_length() < bits:
            p *= choice(sieve_base)
        if isPrime(p - 1):
            return p - 1


p1 = gen(256)
q1 = gen(256)
n1 = p1 * q1
c1 = p1 + e

print(f'n1 = {n1}')
print(f'c1 = {c1}')

'''
n = 10037257627154486608196774801095855162090578704439233219876490744017222686494761706171113312036056644757212254824459536550416291797454693336043852190135363
c = 6723803125309437675713195914771839852631361554645954138639198200804046718848872479140347495288135138109762940384847808522874831433140182790750890982139835
n1 = 151767047787614712083974720416865469041528766980347881592164779139223941980832935534609228636599644744364450753148219193621511377088383418096756216139022880709
c1 = 6701513605196718137208327145211106525052740242222174201768345944717813148931922063338128366155730924516887607710111701686062781667128443135522927486682574
'''
```

先看gen函数，发现是p+1光滑，上脚本分解n1

```
from Crypto.Util.number import *
from gmpy2 import *
from itertools import count
n = 151767047787614712083974720416865469041528766980347881592164779139223941980832935534609228636599644744364450753148219193621511377088383418096756216139022880709
def mlucas(v, a, n):
    v1, v2 = v, (v ** 2 - 2) % n
    for bit in bin(a)[3:]: v1, v2 = ((v1 ** 2 - 2) % n, (v1 * v2 - v) % n) if bit == "0" else (
        (v1 * v2 - v) % n, (v2 ** 2 - 2) % n)
    return v1
def primegen():
    yield 2
    yield 3
    yield 5
    yield 7
    yield 11
    yield 13
    ps = primegen()  
    p = ps.__next__() and ps.__next__()
    q, sieve, n = p ** 2, {}, 13
    while True:
        if n not in sieve:
            if n < q:
                yield n
            else:
                next, step = q + 2 * p, 2 * p
                while next in sieve:
                    next += step
                sieve[next] = step
                p = ps.__next__()
                q = p ** 2
        else:
            step = sieve.pop(n)
            next = n + step
            while next in sieve:
                next += step
            sieve[next] = step
        n += 2
def ilog(x, b): 
    l = 0
    while x >= b:
        x /= b
        l += 1
    return l
def attack(n):
    for v in count(1):
        for p in primegen():
            e = ilog(isqrt(n), p)
            if e == 0:
                break
            for _ in range(e):
                v = mlucas(v, p, n)
            g = gcd(v - 2, n)
            if 1 < g < n:
                return int(g), int(n // g)  
            if g == n:
                break
p1, q1 = attack(n)
print('p1=',p1)
print('q1=',q1)
'''
p1= 647625598040937990477179775340017395831855498212348808173836982264933068647233
q1= 234343806431846981391062476356400447729334179333927516463017977438646752515331973
'''
```

所以e可能是c1-p1或c1-q1，减出来发现e比较大，就像用维纳，但看看d是130位，130/0.25=520>512,不能用维纳，只能用Boneh-Durfee Attack，因为520和512没有差太多

```
e= 6701513605196718137208327145211106525052740242222174201768345944717813148931274437740087428165253744741547590314279846187850432858954606153257994418035341
N = 10037257627154486608196774801095855162090578704439233219876490744017222686494761706171113312036056644757212254824459536550416291797454693336043852190135363
c = 6723803125309437675713195914771839852631361554645954138639198200804046718848872479140347495288135138109762940384847808522874831433140182790750890982139835
debug = False
strict = False

helpful_only = True
dimension_min = 7  

def helpful_vectors(BB, modulus):
    nothelpful = 0
    for ii in range(BB.dimensions()[0]):
        if BB[ii, ii] >= modulus:
            nothelpful += 1

    print(nothelpful, "/", BB.dimensions()[0], " vectors are not helpful")

# display matrix picture with 0 and X
def matrix_overview(BB, bound):
    for ii in range(BB.dimensions()[0]):
        a = ('%02d ' % ii)
        for jj in range(BB.dimensions()[1]):
            a += '0' if BB[ii, jj] == 0 else 'X'
            if BB.dimensions()[0] < 60:
                a += ' '
        if BB[ii, ii] >= bound:
            a += '~'
        print(a)

# tries to remove unhelpful vectors
# we start at current = n-1 (last vector)
def remove_unhelpful(BB, monomials, bound, current):
    # end of our recursive function
    if current == -1 or BB.dimensions()[0] <= dimension_min:
        return BB

    # we start by checking from the end
    for ii in range(current, -1, -1):
        # if it is unhelpful:
        if BB[ii, ii] >= bound:
            affected_vectors = 0
            affected_vector_index = 0
            # let's check if it affects other vectors
            for jj in range(ii + 1, BB.dimensions()[0]):
                # if another vector is affected:
                # we increase the count
                if BB[jj, ii] != 0:
                    affected_vectors += 1
                    affected_vector_index = jj

            # level:0
            # if no other vectors end up affected
            # we remove it
            if affected_vectors == 0:
                # print("* removing unhelpful vector", ii)
                BB = BB.delete_columns([ii])
                BB = BB.delete_rows([ii])
                monomials.pop(ii)
                BB = remove_unhelpful(BB, monomials, bound, ii - 1)
                return BB

            # level:1
            # if just one was affected we check
            # if it is affecting someone else
            elif affected_vectors == 1:
                affected_deeper = True
                for kk in range(affected_vector_index + 1, BB.dimensions()[0]):
                    # if it is affecting even one vector
                    # we give up on this one
                    if BB[kk, affected_vector_index] != 0:
                        affected_deeper = False
                # remove both it if no other vector was affected and
                # this helpful vector is not helpful enough
                # compared to our unhelpful one
                if affected_deeper and abs(bound - BB[affected_vector_index, affected_vector_index]) < abs(
                        bound - BB[ii, ii]):
                    # print("* removing unhelpful vectors", ii, "and", affected_vector_index)
                    BB = BB.delete_columns([affected_vector_index, ii])
                    BB = BB.delete_rows([affected_vector_index, ii])
                    monomials.pop(affected_vector_index)
                    monomials.pop(ii)
                    BB = remove_unhelpful(BB, monomials, bound, ii - 1)
                    return BB
    # nothing happened
    return BB


def boneh_durfee(pol, modulus, mm, tt, XX, YY):

    # substitution (Herrman and May)
    PR.<u,x,y> = PolynomialRing(ZZ)
    Q = PR.quotient(x * y + 1 - u)  # u = xy + 1
    polZ = Q(pol).lift()

    UU = XX * YY + 1

    # x-shifts
    gg = []
    for kk in range(mm + 1):
        for ii in range(mm - kk + 1):
            xshift = x ^ ii * modulus ^ (mm - kk) * polZ(u, x, y) ^ kk
            gg.append(xshift)
    gg.sort()

    # x-shifts list of monomials
    monomials = []
    for polynomial in gg:
        for monomial in polynomial.monomials():
            if monomial not in monomials:
                monomials.append(monomial)
    monomials.sort()

    # y-shifts (selected by Herrman and May)
    for jj in range(1, tt + 1):
        for kk in range(floor(mm / tt) * jj, mm + 1):
            yshift = y ^ jj * polZ(u, x, y) ^ kk * modulus ^ (mm - kk)
            yshift = Q(yshift).lift()
            gg.append(yshift)  # substitution

    # y-shifts list of monomials
    for jj in range(1, tt + 1):
        for kk in range(floor(mm / tt) * jj, mm + 1):
            monomials.append(u ^ kk * y ^ jj)

    # construct lattice B
    nn = len(monomials)
    BB = Matrix(ZZ, nn)
    for ii in range(nn):
        BB[ii, 0] = gg[ii](0, 0, 0)
        for jj in range(1, ii + 1):
            if monomials[jj] in gg[ii].monomials():
                BB[ii, jj] = gg[ii].monomial_coefficient(monomials[jj]) * monomials[jj](UU, XX, YY)

    # Prototype to reduce the lattice
    if helpful_only:
        # automatically remove
        BB = remove_unhelpful(BB, monomials, modulus ^ mm, nn - 1)
        # reset dimension
        nn = BB.dimensions()[0]
        if nn == 0:
            print("failure")
            return 0, 0

    # check if vectors are helpful
    if debug:
        helpful_vectors(BB, modulus ^ mm)

    # check if determinant is correctly bounded
    det = BB.det()
    bound = modulus ^ (mm * nn)
    if det >= bound:
        # print("We do not have det < bound. Solutions might not be found.")
        # print("Try with highers m and t.")
        if debug:
            diff = (log(det) - log(bound)) / log(2)
            # print("size det(L) - size e^(m*n) = ", floor(diff))
        if strict:
            return -1, -1
    else:
        print("det(L) < e^(m*n) (good! If a solution exists < N^delta, it will be found)")

    # display the lattice basis
    if debug:
        matrix_overview(BB, modulus ^ mm)

    # LLL
    if debug:
        print("optimizing basis of the lattice via LLL, this can take a long time")

    BB = BB.LLL()

    if debug:
        print("LLL is done!")

    # transform vector i & j -> polynomials 1 & 2
    if debug:
        print("looking for independent vectors in the lattice")
    found_polynomials = False

    for pol1_idx in range(nn - 1):
        for pol2_idx in range(pol1_idx + 1, nn):
            # for i and j, create the two polynomials
            PR.<w,z> = PolynomialRing(ZZ)
            pol1 = pol2 = 0
            for jj in range(nn):
                pol1 += monomials[jj](w * z + 1, w, z) * BB[pol1_idx, jj] / monomials[jj](UU, XX, YY)
                pol2 += monomials[jj](w * z + 1, w, z) * BB[pol2_idx, jj] / monomials[jj](UU, XX, YY)

            # resultant
            PR.<q> = PolynomialRing(ZZ)
            rr = pol1.resultant(pol2)

            # are these good polynomials?
            if rr.is_zero() or rr.monomials() == [1]:
                continue
            else:
                # print("found them, using vectors", pol1_idx, "and", pol2_idx)
                found_polynomials = True
                break
        if found_polynomials:
            break

    if not found_polynomials:
        # print("no independant vectors could be found. This should very rarely happen...")
        return 0, 0

    rr = rr(q, q)

    # solutions
    soly = rr.roots()

    if len(soly) == 0:
        # print("Your prediction (delta) is too small")
        return 0, 0

    soly = soly[0][0]
    ss = pol1(q, soly)
    solx = ss.roots()[0][0]

    #
    return solx, soly

delta = .252  
m = 3
t = int((1 - 2 * delta) * m)  
X = 2 * floor(N ^ delta)
Y = floor(N ^ (1 / 2)) 
P.<x,y> = PolynomialRing(ZZ)
A = int((N + 1) / 2)
pol = 1 + x * (A + y)

solx, soly = boneh_durfee(pol, e, m, t, X, Y)

d = int(pol(solx, soly) / e)
print(d)

m = power_mod(c, d, N)
print(bytes.fromhex(hex(m)[2:]))
#b'flag{39693fd4a45b386c28c63100cc930238259891a2}'
```

### DIladila

```
def rol(val, r_bits, max_bits=16):
    return ((val << r_bits) & (2**max_bits - 1)) | (val >> (max_bits - r_bits))

def ror(val, r_bits, max_bits=16):
    return (val >> r_bits) | ((val << (max_bits - r_bits)) & (2**max_bits - 1))

def speck_round(x, y, k):
    x = (ror(x, 7) + y) & 0xFFFF
    x ^= k
    y = rol(y, 2) ^ x
    return x, y

def encrypt_block(x, y, keys):
    for k in keys:
        x, y = speck_round(x, y, k)
    return x, y

def str_to_blocks(s):
    b = s.encode('utf-8')
    if len(b) % 4 != 0:
        b += b'\x00' * (4 - len(b) % 4)
    blocks = []
    for i in range(0, len(b), 4):
        x = int.from_bytes(b[i:i+2], 'little')
        y = int.from_bytes(b[i+2:i+4], 'little')
        blocks.append((x, y))
    return blocks

# 这里写明文变量时用占位符，实际加密时请自行替换
plaintext = "***********"

keys = [0x1234, 0x5678, 0x9abc, 0xdef0]

# 组织分组
blocks = str_to_blocks(plaintext)

ciphertext = []
for x, y in blocks:
    cx, cy = encrypt_block(x, y, keys)
    ciphertext.append((cx, cy))

# 打印密文，供题目发布用
print("加密后的密文:")
for c in ciphertext:
    print(c)
```

就是一个加密算法，看上去不难，直接给ai分析了，然后就是纯逆脚本了，主要部分还是逆speck\_round部分

```
def rol(val, r_bits, max_bits=16):
    return ((val << r_bits) & (2**max_bits - 1)) | (val >> (max_bits - r_bits))

def ror(val, r_bits, max_bits=16):
    return (val >> r_bits) | ((val << (max_bits - r_bits)) & (2**max_bits - 1))

def speck_decrypt_round(x, y, k):
    # 逆向操作
    y = ror(y ^ x, 2)       # 逆向：y = rol(y,2) ^ x
    x ^= k                  # 逆向：x ^= k
    x = (x - y) & 0xFFFF    # 逆向：x = (ror(x,7) + y)
    x = rol(x, 7)           # 逆向：ror(x,7)
    return x, y

def decrypt_block(x, y, keys):
    # 反向遍历密钥
    for k in reversed(keys):
        x, y = speck_decrypt_round(x, y, k)
    return x, y

def blocks_to_str(blocks):
    byte_array = bytearray()
    for x, y in blocks:
        byte_array.extend(x.to_bytes(2, 'little'))
        byte_array.extend(y.to_bytes(2, 'little'))
    # 移除填充的空字节
    return byte_array.decode('utf-8').rstrip('\x00')

# 示例密文（替换为你的实际密文）
ciphertext = [
    (57912, 19067),
    (38342, 34089),
    (16842, 41652),
    (30292, 50979),
    (9137, 57458),
    (29822, 64285),
    (33379, 14140),
    (16514, 4653)
]

# 密钥（必须与加密时相同）
keys = [0x1234, 0x5678, 0x9abc, 0xdef0]

# 解密
plaintext_blocks = []
for cx, cy in ciphertext:
    px, py = decrypt_block(cx, cy, keys)
    plaintext_blocks.append((px, py))

# 输出明文
print("解密结果:", blocks_to_str(plaintext_blocks))
'''
解密结果: flag{You_DIladila_Crypto_Matser}
'''
```
