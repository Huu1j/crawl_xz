# ECDSA Signature Vulns in Solidity-先知社区

> **来源**: https://xz.aliyun.com/news/17159  
> **文章ID**: 17159

---

## TL；DR

在实际项目中，往往是密码算法的误用、算法特性的恶意利用，引发了各样的漏洞。本文从以太坊签名机制谈起，聚焦solidity合约开发中、ECDSA签名相关代码容易出现的问题，并举例实际场景说明。本文不会深入密码学算法，不会探讨算法本身的安全性。

## 以太坊签名机制

一条区块链是由无数地址构成的，每个地址都可以是一个用户账户。在以太坊上，用户想要创建一个新的账户，首先需要生成一个合适的公私钥对，私钥会用来对每一笔交易签名，公钥的前20个字节作为账户地址。签名机制是以太坊乃至整个区块链的基石

以太坊使用ECDSA算法，ECDSA是ECC（椭圆曲线密码学）的实际应用。签名需要用户私钥`private_key`和消息哈希`message_hash`两个参数，得到签名结果`v、r、s`三个参数，按照`r（32bytes）+ s（32bytes）+ v（1bytes）`拼接成为`signature（65bytes）`。各种语言的web3库都能封装了ECDSA签名算法，方便进行签名操作，包括web3.py、web3.js等。这里笔者使用forge script进行演示：

```
uint256 private_key = vm.envUint("PRIV"); // 从环境变量中拿到private-key
bytes32 message_hash = keccak256("hello from DX3906"); // 消息哈希
(uint8 v, bytes32 r, bytes32 s) = vm.sign(private_key, message_hash); // 签名API
bytes memory signature = abi.encodePacked(r, s, v); // 组装signature
// 输出看看
console.log(v);
console.logBytes32(r);
console.logBytes32(s);
console.logBytes(signature);
```

输出：

```
== Logs ==
  27
  0xbf3ba8795f688d50c884bd6c8e03ee7da174227430d664d8cad6873fe1dcec94
  0x1084a284f8b4464fa4f34036407ad3eb3999176c4fe4a2a0a720f92761336d29
  0xbf3ba8795f688d50c884bd6c8e03ee7da174227430d664d8cad6873fe1dcec941084a284f8b4464fa4f34036407ad3eb3999176c4fe4a2a0a720f92761336d291b
```

以上演示了客户端签名所做的工作，但这里的代码仅演示了基本原理，并不完全符合以太坊签名标准（生成消息哈希需要额外携带标识字符串），这里不再赘述。这样的签名操作不会出现在以太坊合约中，否则会发生私钥泄漏，签名也就没有了意义

合约中要完成signature的校验工作，即首先通过`signature`恢复签名者`signer`，然后验证`signer`身份有效性。对于恢复signer，广泛使用的API有两种，下面直接使用代码说明：

1. `ecrecover`：EVM预编译函数

```
uint256 private_key = vm.envUint("PRIV");
address user = vm.addr(private_key);  // 使用私钥直接计算地址，待后续验证
console.log("user address:", user);
// 签名
bytes32 message_hash = keccak256("hello from DX3906");
(uint8 v, bytes32 r, bytes32 s) = vm.sign(private_key, message_hash);
// 验签
address signer = ecrecover(message_hash, v, r, s); // 恢复signer地址
console.log("singer address:", signer);
```

输出：

```
== Logs ==
  user address: 0xaF29f0C57B61e0584c53D61a16090C3C2Ea7b54c
  singer address: 0xaF29f0C57B61e0584c53D61a16090C3C2Ea7b54c
```

1. `ECDSA.recover`：openzeppelin开发的标准库，对ecrecover的封装

```
uint256 private_key = vm.envUint("PRIV");
address user = vm.addr(private_key);  // 使用私钥直接计算地址，待后续验证
console.log("user address:", user);
// 签名
bytes32 message_hash = keccak256("hello from DX3906");
(uint8 v, bytes32 r, bytes32 s) = vm.sign(private_key, message_hash);
// 验签
address signer = ECDSA.recover(message_hash, signature); // 恢复signer地址
console.log("singer address:", signer);
```

输出：

```
== Logs ==
  user address: 0xaF29f0C57B61e0584c53D61a16090C3C2Ea7b54c
  singer address: 0xaF29f0C57B61e0584c53D61a16090C3C2Ea7b54c
```

openzeppelin的库函数，相对于EVM预编译的函数，做了更多的预先检查，能避免一些攻击的发生（如ECDSA签名延展性攻击），也提供了更加丰富的支持，但若开发者不注意安全防范，也会带来新的风险（紧凑型签名攻击），下面会介绍漏洞场景和相关攻击手法

## 漏洞场景

首先明确，本文探讨的场景为项目合约中可能出现的漏洞。普通交易的签名记录验证的操作由EVM负责，不在本文讨论范围之内。例如，合约中随处可使用的`msg.sender`，默认为正确调用者地址，在合约中不可能对它进行验证

需要开发者自行验证签名的场景，基本可归为两类：

1. 授权特权操作。通过验证单个用户签名，允许调用者进行特权操作
2. 用户份额累加。通过验证多用户签名，累加用户份额，类似于投票的过程

在这样的场景中，会面临什么样的安全威胁呢？

我们默认签名算法是密码学安全的，即签名不可伪造。剩下的问题就是签名重放问题，任何传递到合约的签名，任何人都可以轻易拿到，所以任何一个签名都不该被使用第二次。同时，由于ECDSA算法本身的一些特性，根据一个现有的签名，可以生成等价的不同签名，这也是合约开发者需要防范的

## 漏洞实例

这一节通过几道CTF题目，实际来一些看漏洞实例，仅截取签名验证相关代码以供说明

### 0x00 签名重复性检验不完善

> Remedy CTF 2025 rich-mans-bet

```
    // Function to validate a signed message for changing bridge settings
    function changeBridgeSettings(
        bytes calldata message,
        bytes[] calldata signatures
    ) external onlyValidator {
        uint256 accumulatedWeight = 0;
        address lastSigner = address(0);

        address newChallengeContract;
        address newAdminNftContract;
        uint256 newThreshold;

        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = message.toEthSignedMessageHash().recover(
                signatures[i]
            );

            require(signer != lastSigner, "Repeated signer");

            if (validatorWeights[signer] > 0) {
                accumulatedWeight += validatorWeights[signer];
            }

            lastSigner = signer;
        }

        require(
            accumulatedWeight >= totalWeight / 2,
            "Insufficient weight to change settings"
        );

        // Decode new parameters from the message
        (newChallengeContract, newAdminNftContract, newThreshold) = abi.decode(
            abi.encodePacked(message),
            (address, address, uint256)
        );

        require(newThreshold > 1, "New threshold must be above 1");

        // Call internal function to update bridge settings
        _updateBridge(newChallengeContract, newAdminNftContract, newThreshold);
    }
```

`changeBridgeSettings`函数通过验证签名，实现了一个用户份额累加功能。所有愿意使用`message`内容执行函数的用户需要用自己的私钥进行签名，合约累加用户份额，超过半数则进行执行

为了防止签名重放，合约使用`lastSigner`变量存储上一条signature，保证了相邻两个signature不同。然而，任意两个用户，它们应有的份额可能远远不到一半，但只要两个不同签名交替重复，就能轻松绕过这个检查，通过无数次重复，就能累加无数多的份额

### 0x01 ECDSA签名延展性攻击

> SUCTF 2025 Onchain Magician

```
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

contract MagicBox {
    struct Signature {
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    address magician;
    bytes32 alreadyUsedSignatureHash;
    bool isOpened;

    constructor() {}

    function isSolved() public view returns (bool) {
        return isOpened;
    }

    function getMessageHash(address _magician) public view returns (bytes32) {
        return keccak256(abi.encodePacked("I want to open the magic box", _magician, address(this), block.chainid));
    }

    function _getSignerAndSignatureHash(Signature memory _signature) internal view returns (address, bytes32) {
        address signer = ecrecover(getMessageHash(msg.sender), _signature.v, _signature.r, _signature.s);
        bytes32 signatureHash = keccak256(abi.encodePacked(_signature.v, _signature.r, _signature.s));
        return (signer, signatureHash);
    }

    function signIn(Signature memory signature) external {
        require(magician == address(0), "Magician already signed in");
        (address signer, bytes32 signatureHash) = _getSignerAndSignatureHash(signature);
        require(signer == msg.sender, "Invalid signature");
        magician = signer;
        alreadyUsedSignatureHash = signatureHash;
    }

    function openBox(Signature memory signature) external {
        require(magician == msg.sender, "Only magician can open the box");
        (address signer, bytes32 signatureHash) = _getSignerAndSignatureHash(signature);
        require(signer == msg.sender, "Invalid signature");
        require(signatureHash != alreadyUsedSignatureHash, "Signature already used");
        isOpened = true;
    }
}
```

简单理解后可以发现，题目要求对同一个hash，生成两套不同的`v, r, s`，同时两套签名恢复出来的`signer`需要一致。正常来说，使用各种库进行签名时，得到的`v, r, s`都是唯一的，为什么会有两套不一样的呢？

我们得回到ECDSA算法本身，实际上，对于同样的`r`，存在两个不同的`s`满足要求，且根据一个`s`易求另外一个，这就是ECDSA签名延展性。具体求法如下：

```
def create_malleable_signature(original_v, original_r, original_s):
    # secp256k1 曲线阶数 N
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    # 构造新签名
    new_s = hex(N - original_s)[2:].zfill(64)
    new_v = 28 if original_v == 27 else 27
    new_r = original_r
    return new_v, new_r, new_s
```

更进一步，如果这里合约使用`ECDSA.recover`，即openzeppelin的标准库函数，就能避免这个漏洞。打开改函数的实现可以看到开头这样的注释：

```
     * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
```

### 0x02 紧凑型签名（compact signature）

> Remedy CTF 2025 casino-avengers

```
    function _verifySignature(bytes memory signature, bytes memory digest) internal {
        if (nullifiers[signature]) revert SignatureAlreadyUsed();

        address signatureSigner = ECDSA.recover(keccak256(digest), signature);
        if (signatureSigner != signer) revert InvalidSignature();

        nullifiers[signature] = true;
    }
```

合约使用mapping来存储用过的signatures，避免了签名重放，且使用`ECDSA.recover`避免了延展性攻击，那么我们在已知用过的签名的情况下，还能构造新的签名吗？答案是可以

[ERC-2098](https://eips.ethereum.org/EIPS/eip-2098) 是2019年提出的以太坊改进提案，引入了`compact signature`，即紧凑格式的签名，使得整个签名长度可以由65字节缩短到64字节，初衷是为了优化使用EVM空间，提高效率。在原文中也给出了紧凑型签名和一般签名的转换方法：

```
# Assume yParity is 0 or 1, normalized from the canonical 27 or 28
def to_compact(r, s, yParity):
    return {
        "r": r,
        "yParityAndS": (yParity << 255) | s
    }

def to_canonical(r, yParityAndS):
    return {
        "r": r,
        "s": yParityAndS & ((1 << 255) - 1),
        "yParity": (yParityAndS >> 255)
    }
```

是这个库本身不安全吗？其实不是。事实上，上面例子中犯了个大错，对于重复性检测，应该去重`digest`，而不是`signature`。只要将`nullifiers`变量改为存储使用过的`digest`，漏洞就被修复了

### 0x03 不遵守规范无限签名

这一小节作为补充说明，就不举具体例子了

以太坊签名机制是建立在[RFC-6979](https://datatracker.ietf.org/doc/html/rfc6979)标准上的，即使用确定性生成k的方法进行签名。故对于唯一的message，应只有唯一的签名（排除延展性情况）。之所以这么做，是因为使用不规范的k进行签名，存在私钥泄漏的风险。就在前两天，被广泛使用的js库elliptic刚爆出了存在漏洞，详见[慢雾分析文章](https://mp.weixin.qq.com/s/-JpS5Qg7NYYPgeic-7Y5VQ)

然而，使用`ecrecover`进行公钥还原时，并不会关心k是否符合标准，都可以得到正确的签名者。故只要不遵守规范，就可以生成无数个可用的签名。下面给出一个任意k进行签名的python脚本（借鉴自<https://cnwangjihe.notion.site/ECDSA-ec7a150a720d4cf29c6d060bbf56275b）：>

```
import hashlib
import hmac
from eth_utils import big_endian_to_int
from eth_account.account import Account
from hexbytes import HexBytes
from eth_keys.constants import (
    SECPK1_N as N,
    SECPK1_G as G
)
from eth_keys.backends.native.jacobian import (
    inv,
    fast_multiply
)

def deterministic_generate_k(msg_hash: bytes, 
                             private_key_bytes: bytes) -> int:
    v_0 = b'\x01' * 32
    k_0 = b'\x00' * 32

    k_1 = hmac.new(k_0, v_0 + b'\x00' + private_key_bytes + msg_hash, hashlib.sha256).digest()
    v_1 = hmac.new(k_1, v_0, hashlib.sha256).digest()
    k_2 = hmac.new(k_1, v_1 + b'\x01' + private_key_bytes + msg_hash, hashlib.sha256).digest()
    v_2 = hmac.new(k_2, v_1, hashlib.sha256).digest()

    kb = hmac.new(k_2, v_2, hashlib.sha256).digest()
    k = big_endian_to_int(kb)
    return k

def ecdsa_sign(msg_hash: bytes,
               private_key: str | bytes,
               deterministic: bool = True) -> tuple[int, int, int]:
    assert len(msg_hash) == 32, "length of msg_hash must == 32"

    if not isinstance(private_key, bytes):
        private_key = HexBytes(private_key)

    z = big_endian_to_int(msg_hash)
    if deterministic:
        k = deterministic_generate_k(msg_hash, private_key)
        # print(f"k: {k}, G: {G}, N: {N}")
    else:
        import secrets
        k = 1 + secrets.randbelow(N-1)

    r, y = fast_multiply(G, k)
    s_raw = inv(k, N) * (z + r * big_endian_to_int(private_key)) % N

    v = 27 + ((y % 2) ^ (0 if s_raw * 2 < N else 1))
    s = s_raw if s_raw * 2 < N else N - s_raw

    return v, r, s

def ecdsa_recover(msg_hash: bytes,
                  vrs: tuple[int, int, int]):
    return Account._recover_hash(msg_hash, vrs = (vrs[0] - 27, vrs[1], vrs[2]))

def test_case():
    private_key = bytes.fromhex("be0a5d9f38057fa406c987fd1926f7bfc49f094dc4e138fc740665d179e6a56a")
    sign_data = bytes.fromhex("631666568d3f1118d38685d8bb83b2422ac2ecd3585ecf0b08d16edeba002ee8")

    (v, r, s) = ecdsa_sign(sign_data, private_key, deterministic=False)
    pubkey = ecdsa_recover(sign_data, (v, r, s))
    assert pubkey == Account.from_key(private_key).address

    print(v, r, s)

if __name__ == "__main__":
    test_case()
```

想要避免这样的签名攻击，其实还是只要去重`message hash`即可，但千万不能去重`signature`
