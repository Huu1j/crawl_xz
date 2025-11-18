# Windows应急响应之命令行排查-先知社区

> **来源**: https://xz.aliyun.com/news/16178  
> **文章ID**: 16178

---

如果因为各种原因没法通过可视化界面操作，那就只能命令行检查

## 排查Windows日志命令

PowerShell Get-WinEvent命令

列出所有事件`Get-WinEvent -ListLog *`

![](images/20241213223605-9564372e-b95f-1.png)

获取Security.evtx的日志：`Get-WinEvent -FilterHashtable @{LogName='Security'}`

![](images/20241213223618-9da512f0-b95f-1.png)

获取事件ID为4624的Security日志：`Get-WinEvent -FilterHashtable @{LogName='Security';ID='4624'}`

![](images/20241213223624-a0e8f1c0-b95f-1.png)

powershell今天操作日志的最近10条，注意这里的logname必须是loglist中得到的：`Get-WinEvent @{logname='Microsoft-Windows-PowerShell/Operational';starttime=[datetime]::today } -MaxEvents 10`

![](images/20241213223634-a6f5924e-b95f-1.png)

powershell日志中4104和4100事件：`Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | Where-Object {$_.ID -eq "4100" -or $_.ID -eq "4104"}`

![](images/20241213223700-b65a3460-b95f-1.png)

即

![](images/20241213223721-c3318f12-b95f-1.png)

指定时间内的日志，注意end hour不能超过23

```
$StartTime=Get-Date  -Year  2023  -Month  1  -Day  1  -Hour  00  -Minute  00
$EndTime=Get-Date  -Year  2023  -Month  1  -Day  30  -Hour  23  -Minute  59
Get-WinEvent -FilterHashtable @{LogName='System';StartTime=$StartTime;EndTime=$EndTime}

```

![](images/20241213223734-caaa7d8a-b95f-1.png)

一些其他但是少见的用法见文档

`https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-eventlog?view=powershell-5.1`

基本都可以用Microsoft Message Analyzer代替，可能在内网机子现场应急的时候需要用Get-WinEvent

## 排查Windows用户命令

`lusrmgr.msc`打开本地用户组查看，用户名后面如果有$是隐藏用户

![](images/20241213225020-933423ae-b961-1.png)

`net user`列出用户账户简单信息

![](images/20241213225024-95591374-b961-1.png)

`wmic UserAccount get`，列出系统所有账户详细信息

![](images/20241213225031-99879236-b961-1.png)

`regedit`打开注册表找：

计算机\HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList

通过ProfileImagePath确认

![](images/20241213225036-9d11496a-b961-1.png)

当前在线用户：`query user`

![](images/20241213225042-a0586e64-b961-1.png)

查看用户上次登录时间：`net user lenovo`

![](images/20241213225049-a43b2c60-b961-1.png)

查看本地管理员组用户`net localgroup administrators`

![](images/20241213225055-a82be274-b961-1.png)

powershell的`Get-LocalUser`

![](images/20241213225101-abd88b16-b961-1.png)

## 排查网络及端口状态命令

基本服务的端口：`C:\Windows\System32\drivers\etc`

![](images/20241213225108-af9a51a8-b961-1.png)

`netstat -ano`

* -a ：显示所有连接和侦听端口
* -b ：显示在创建每个连接或侦听端口时涉及的可执行程序
* -n ：以数字形式显示地址和端口号
* -o ：显示每个连接关联的进程 ID
* -r ：显示路由表

![](images/20241213225114-b342c20e-b961-1.png)

![](images/20241213225119-b639a798-b961-1.png)

findstr配合`netstat -ano | findstr "172.24.16.1"`

![](images/20241213225125-b9ee4dbc-b961-1.png)

查看网络连接状态`netstat -ano | find "ESTABLISHED"`，后面是pid

![](images/20241213225130-bcab1008-b961-1.png)

powershell命令`Get-NetTCPConnection`

![](images/20241213225134-bf7a66bc-b961-1.png)

保持链接的`Get-NetTCPConnection -State Established`

![](images/20241213225140-c310393c-b961-1.png)

## 排查防火墙规则命令

显示所有规则：`netsh advfirewall firewall show rule all`

![](images/20241213225145-c625961c-b961-1.png)

显示指定规则：`netsh advfirewall firewall show rule`

![](images/20241213225154-cb48ec98-b961-1.png)

Apache的基本入站规则信息：`netsh advfirewall firewall show rule name = "Apache HTTP Server"`

![](images/20241213225201-cf394668-b961-1.png)

Apache的详细入站规则信息`netsh advfirewall firewall show rule name = "Apache HTTP Server" verbose`

![](images/20241213225206-d2904e7e-b961-1.png)

## 排查进程信息命令

列出所有进程：`tasklist` ，可以加/svc

![](images/20241213225213-d6c85ef0-b961-1.png)

配合findstr

![](images/20241213225219-d9fd9126-b961-1.png)

列出用法`TASKLIST /?`

![](images/20241213225227-ded8100e-b961-1.png)

检查pid为10004的进程：`tasklist | findstr "10004"`

![](images/20241213225233-e2b6ad8e-b961-1.png)

`tasklist /m`

![](images/20241213225242-e7bdd8c0-b961-1.png)

查询调用uxtheme.dll的进程：`tasklist /m uxtheme.dll`

![](images/20241213225248-eb7c92da-b961-1.png)

筛选器

![](images/20241213225257-f0a6b4e8-b961-1.png)

eq是等于、ne是不等于、gt是大于、lt是小于、ge是大于等于、le是小于等于

用法：`tasklist /fi "PID eq 9480"`

![](images/20241213225305-f56faa0c-b961-1.png)

![](images/20241213225311-f9722c6a-b961-1.png)

获取父进程：`wmic process where ProcessId=14000 get ParentProcessId`

`wmic process where Name="javaw.exe" get ParentProcessId`

![](images/20241213225319-fdc2a452-b961-1.png)

powershell下的`get-process`

![](images/20241213225324-00c3ab9c-b962-1.png)

获取进程完整信息`wmic process list full`

![](images/20241213225329-03e8a886-b962-1.png)

列出进程和父进程：`wmic process get name,parentprocessid,processid`

![](images/20241213225336-07ebe3a8-b962-1.png)

详细的进程的名字，跟直接tasklist差不多：`wmic process where ‘ProcessID=PID’ get CommandLine`，这个services是最终的父进程，在这里notepad++的上一级父进程是explorer，再上一级是svchost，再上一级是services

![](images/20241213225342-0b7a840c-b962-1.png)

![](images/20241213225349-1019fb00-b962-1.png)

dll关联：`tasklist -M`

![](images/20241213225357-14873860-b962-1.png)

杀死进程：

`wmic process where name = "" call terminate`

`wmic process where processid = "PID" delete`

## 排查本机服务命令

已开启的服务：`net start`

![](images/20241213225407-1ab852e6-b962-1.png)

每个服务对应的进程：`tasklist /svc`

![](images/20241213225413-1e07a05a-b962-1.png)

## 排查计划任务命令

`schtasks.exe`

![](images/20241213225423-241ed12a-b962-1.png)

当然也可以在可视化的任务管理器，双击可查看详细信息

![](images/20241213225429-27ceeb2a-b962-1.png)

## 排查开机启动项命令

`wmic startup`共有一下几个字段

```
Caption、Command、Description、Location、Name、SettingID、User、UserSID
```

`wmic startup get Name,Command`

![](images/20241213225439-2da03e00-b962-1.png)

自启任务的user和Location：`Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Format-List`

![](images/20241213225445-314cd838-b962-1.png)

## 排查共享服务命令

`Get-SMBShare`

![](images/20241213225453-36290fa2-b962-1.png)

`net share`也是同样

![](images/20241213225458-38d8f0a0-b962-1.png)

## 排查可疑文件相关命令

下载目录、回收站、应用程序打开历史、快捷方式、驱动等

```
%TEMP%：    C:\Users\lenovo\AppData\Local\Temp
%UserProfile%\Recent：    C:\Users\lenovo\Recent
%WINDIR%：    C:\WINDOWS
%LOCALAPPDATA%：     C:\Users\lenovo\AppData\Local
%APPDATA%：     C:\Users\lenovo\AppData\Roaming
C:\WINDOWS\Temp
%SystemBoot%\appcompat\Programs\amcache.hve:     C:\Windows\appcompat\Programs\amcache.hve 应用程序执行路径、上次执行时间
%SystemBoot%\Prefetch 预读取文件
```

驱动：`driverquery`

![](images/20241213225505-3d02d402-b962-1.png)

## 按时间排查命令

```
forfiles [/p Path] [/m SearchMask] [/s] [/c Command] [/d[{+ | -}] [{MM/DD/YYYY | DD}]]
```

下表列出了在 /c Command 命令字符串中能够使用的变量。

```
变量  描述
@file   返回匹配项的名称，双引号。
@fname  返回匹配项的基名（没有文件扩展名），双引号。
@ext    返回文件扩展名，双引号，没有前导点。如果文件有多个扩展名，则只返回最后一个。如果文件没有扩展名，则返回带引号的空字符串。
@path   返回匹配项的完整路径，双引号，包括驱动器号和文件扩展名（如果有）。
@relpath    返回匹配项的相对路径，双引号和相对于起始目录（由/ P给出）。每个路径以点和反斜杠（.\）开头。
@isdir  如果文件类型是目录，返回 TRUE，否则返回 FALSE。
@fsize  返回用字节表示的文件大小
@fdate  返回文件上次修改的日期，采用当前用户的本地化日期格式。
@ftime  返回文件上次修改时间，采用当前用户的本地化时间格式。

```

```
/D    date          选择文件，其上一次修改日期大于或等于 (+)，
                    或者小于或等于 (-) 用 "yyyy/MM/dd" 格式指定的日期;

                    或选择文件，其上一次修改日期大于或等于 (+)
                    当前日期加 "dd" 天，或者小于或等于 (-) 当前

                    日期减 "dd" 天。有效的 "dd" 天数可以是
                    0 - 32768 范围内的任何数字。如果没有指定，

                    "+" 被当作默认符号。


FORFILES /P C:\WINDOWS /S /M DNS*.*
FORFILES /S /M *.txt /C "cmd /c type @file | more"
FORFILES /P C:\ /S /M *.bat
FORFILES /D -30 /M *.exe
         /C "cmd /c echo @path 0x09 在 30 前就被更改。"
FORFILES /D 2001/01/01
         /C "cmd /c echo @fname 在 2001年1月1日就是新的。"
FORFILES /D +2024/12/13 /C "cmd /c echo @fname 今天是新的。"
FORFILES /M *.exe /D +1
FORFILES /S /M *.doc /C "cmd /c echo @fsize"
FORFILES /M *.txt /C "cmd /c if @isdir==FALSE notepad.exe @file"
```
