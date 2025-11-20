# 【Web实战】某头部直辖市攻防演练纪实-如何不用0day打下n个点

> **来源**: https://forum.butian.net/share/2596  
> **文章ID**: 2596

---

前言
--

几个月前打了一场某头部直辖市的攻防演练，演练当时通知的很急促，没做什么准备直接小米加步枪上阵了...

在此过程中，很多个没用到0day的打点案例都很有意思，下面就简单分享一下

案例一、某单位shiro绕WAF(利用shiro处理rememberMe字段值的feature)
------------------------------------------------

信息搜集到某单位的CAS系统...当时开着Burpsuite插件，扫到了默认的shiro秘钥

当时开心坏了...但是有遥遥领先厂商的WAF在，如果直接上现成的工具会直接寄

![img](images/attach-556fa6cdd7fbc62292dc5415c20d7f42e3b61c64.png)

后面试了试网上公开的方法，直接把请求方式删掉，依然被拦，包直接被重置掉，无奈寻找新faeture

最终在Shiro的rememberMe字段值处理流程中，发现在Base64解码过程中有戏

![img](images/attach-339ef248df2aeda8a922fefdd5f45a9979f8bf93.png)

如图，在shiro解码base64字符串的过程中，会调用discardNonBase64方法去除掉非Base64的字符

![img](images/attach-f448f6b9a5386350b210ccabda8fe530b489ba95.png)

如图所示  
![image-20231120155412165](images/attach-700c2f172b9dd2f4dfdc6a3918d582637ffce237.png)

那么思路就来了，只需往rememberMe字段的值中填充非Base64的字符即可绕过WAF(比如$符号)

```php
Base64包括小写字母a-z,大写字母A-Z,数字0-9,符号+和/组成的64个字符的字符集,另外包括填充字符=
```

在本地进行测试，果然奏效

![image-20231120155825627](images/attach-b950a317b54322067f32c098e14bfc85be439f6d.png)

那么后面就很简单了，把现成的Shiro利用工具配置Burpsuite的代理，Match&Replace替换部分字符串即可  
![img](images/attach-c88fd2d11daf4d3f92856afab3b5ac871b05f006.png)

最终也是成功拿下Shell，只可惜过了半小时就被应急了...  
![img](images/attach-457dc3a031349c6327986a313d721e9a418c5754.png)

案例二、某互联网厂商 Apisix绕阿里WAF拿下28个Rce
-------------------------------

如图使用了apisix网关的WebServer在用户访问不存在的路由时，会抛出如下错误，这可以作为我们指纹识别的特征所在

```php
{
  "error_msg": "404 Route Not Found"
}
```

![image-20231120160253525](images/attach-0cd17843dddd487fc9a4277b1fb52e1683f32b45.png)

针对Apisix节点的攻击方法，想要RCE的话，历史上主要有“默认X-API-Key”和“Dashboard未授权访问”两个洞可以用

过往挖某SRC的时候，就遇到过默认X-API-Key导致可直接创建执行lua代码的恶意路由的问题

![img](images/attach-c510f3cbb9cff7572ee337f74fbd680a7af5ad27.png)

![img](images/attach-5a831a280c190e89b21f894726a6253a7640aff1.png)

恰巧这次攻防演练中，某目标子域的Apisix，正好就存在Dashboard的未授权访问  
![img](images/attach-6ba9f3162dbbecd0864f054da48cf4f3d8aaa654.png)

直接去Github扒了一个脚本，发现能检测出漏洞，但是RCE利用不成功，把reponse打印出来后，果然...被阿里云的WAF给拦了

![image.png](images/attach-268ad0be46b6d782912d718076da37023ee66c27.png)

随后把创建恶意路由的请求包中，添加一个带有大量脏数据的Json键，发现阿里云不拦了

![image-20231122111118350](images/attach-e3dc4c0488121ce6a44bf6d715a49459b501bbad.png)

用之前的Dashboard未授权访问漏洞查看路由，显示恶意路由确实是被写入了...但是直接访问恶意路由却依然提示404

![image-20231122111118350](images/attach-2e9ca80f47ec050373799802395eb559749aaa75.png)

![img](images/attach-5431dd367c38fe7ce0b22c6817e813ef348a969d.png)

通过未授权访问漏洞，获取全量路由配置后，发现目标apisix应该是集群部署的...

```php
/apisix/admin/migrate/export
```

每个路由需要有一个host键来确定该路由被添加到哪个子域

![image.png](images/attach-bbc0c2309ea7819fc38ddab4abd7921e5dfd1019.png)

随后再次构造写入恶意路由的数据，把host键加上，发现可以成功写入了

![image-20231120155009326](images/attach-e79b209901eeb87280ca3e89692335002d4a794c.png)

利用未授权接口读出全量路由config，并提取出host键，确定可写入恶意路由的子域范围

```php
import json

def read_config():
    with open("data.json", 'r') as json_file:
        config = json.load(json_file)
    return config

data = read_config()

if "Routes" in data:
    for route in data["Routes"]:
        if "host" in route:
            host_value = route["host"]
            with open("data.txt", "a") as file:
                file.write(host_value + "\n")
                print(host_value)
```

![img](images/attach-e47fa046d5c7f5c636463515a5f9dc7ee7e42ae5.png)

但是后面执行命令，有的时候会被阿里云给拦掉，于是构造lua脚本时把传参和命令输出做了倒转，防止被流量检测到

```lua
local file=io.popen(string.reverse(ngx.req.get_headers()['Authenication']),'r')
local output=file:read('*all')
file:close()
ngx.say(string.reverse(output))
```

由于该apisix集群部署管理了28个子域的服务，所以成功拿下28个子域Rce

![img](images/attach-ccaeac0bf9d4eae19bfb71c982ceae9b26afeeb8.png)

案例三、某开发商Nacos未授权访问读取配置信息到精准钓鱼进入内网
---------------------------------

利用nacos未授权访问，从CONFIG.INFO读取config信息

很幸运，其中包含公有云数据库凭据

```php
/nacos/v1/cs/ops/derby?sql=select+*+from+CONFIG_INFO+st
```

![img](images/attach-fbef6ac5e12df760f641ba5c405a3ae1d1b7bffd.png)

可惜试了一下都配了策略，没法外网直接连过去

但是...却发现了config信息中，出现了某系统的一个手机号  
![img](images/attach-2171693e444067c27b12667335e1c2d1d1716897.png)

随后加上微信钓鱼，以系统升级为由，成功拿到权限

![img](images/attach-89424891eba5f3f3e865393e9e70e564e73b6da2.png)

![image.png](images/attach-36b43c9d397bfd6f825977fd0bbbed678e0bc8df.png)

案例四、某国企-从一个任意文件读取到SSO沦陷
-----------------------

某国企子域的资产，发现使用了kkfileview开源项目

翻了一下历史issue，存在全回显的ssrf，在目标上验证成功  
![img](images/attach-02eea7f981611a2a427cf256bdee6d1dfd64fcd1.png)

![image-20231120151135911](images/attach-293ff16fe437d85494dff9a2bae4764070e1e73a.png)

同时很幸运，这个点支持file://协议，随后通过file协议读取到网站配置文件，拿到了目标的AK,SK

![img](images/attach-9377ad8ca30fd4d3cfe070accd26498653074862.png)

使用阿里云的Cli创建后门账户，接管目标公有云  
![img](images/attach-af4602c7c498686ba25f5c2fc1e0562ec658c912.png)

同时在root目录，发现有诸多数据库文件  
![img](images/attach-b03e308568915fd49965a3985ec8164095874c87.png)

读出多个sql文件内容后，有些库中存放的员工密码是弱加密的

借此我们掌握了部分员工的姓名，工号，明文密码，部门  
![img](images/attach-8f7f81007f838689395c8972e835845cbb49baf4.png)

随后使用IT部门职级比较高的人员的工号、密码，成功进入SSO系统，拥有管理权限

![img](images/attach-5f948f3ccc360b025af50a110e8f2e909e87a317.png)

后面就很简单了，创建一个账户，把所有产品和平台的权限点满...  
![img](images/attach-a02f5a939dbb557833c163b0e8e172e777d91c56.png)

然后，然后所有通过sso登录的系统都能访问到了  
![image-20231120152555881](images/attach-35752d1dd61b0f31f35d88e60d78bb9c6c125a42.png)

案例五、兵不血刃打穿某高校
-------------

为什么说兵不血刃呢...因为目标高校外网暴露面很小，基本上攻防演练期间能关的都关了

但是目标高校正值开学季，开放了一个研究生学号的查询系统，可以使用研究生的sfz+姓名 查询学号和初始密码  
![image-20231120152857545](images/attach-6cb82184cd08d78a3a983d8e93c8fea32bccf544.png)

随后我开始漫长的百度之旅...最终定位到了一名在该校就读的研究生新生小姐姐

![image-20231120153028126](images/attach-f94bebadf74836b73ca91a6179f6cb14041e28d3.png)

![image-20231120153424427](images/attach-ffb37fc407bf4c0aa37e94f0499c0ead0a389a6e.png)

利用xx库的神秘力量，找到了小姐姐的信息  
![image.png](images/attach-5eff4df123e81e30b025cf5e03f3388ec8757a4c.png)

最终成功拿到小姐姐的学号和初始密码  
![img](images/attach-2b6646cf5620f45da1d12c3757bd4f71d8f3ca33.png)

非常走运，小姐姐没有改密码，直接进入到ssl vpn系统中

![image-20231120160448869](images/attach-5b357b6b658351e7dc4aab35a0e6c14c10778348.png)

在某个查看学生个人信息的系统重，队友的Burp被动扫描到了一个二级目录的swagger文档

而“添加学生信息查看角色”的接口，竟然是没有鉴权的

![img](images/attach-8e212a2c034e0cb5465572be0d4439a64e5a40d5.png)

随后利用接口，把当前用户添加查看学生信息的权限

如图，拿下全校十万学生的详细信息~

![img](images/attach-9f05c6cb1f2c7a50bdb5a52d7925b284de7782da.png)

![img](images/attach-3d0cc28201696374a1224da36a41211cc0ffbab1.png)

案例6、某单位Gitlab项目权限误配导致公有云接管
--------------------------

防守单位中某单位的Gitlab开放到了公网，但是爆破了一顿，并不存在弱口令和其他Nday漏洞

但是经过对Gitlab的测试，找到了Gitlab中仓库权限的配置问题

```php
/api/v4/projects
```

获取到gitlab中部分仓库为public状态，非登录态可直接访问

![image.png](images/attach-78ca14e2067ab3527918797561b63625055c9c59.png)  
如图，成功访问到某内部项目

![image-20231120161131396](images/attach-81ec1dc06a3ec52bd03f741b11af2779132d6b63.png)

最终在某项目中成功找到了可用的ak,sk，完成公有云接管

![img](images/attach-8d664a3873e91badbfe489aa8bc08ca4fb9e5e1c.png)

案例七、某单位系统从一个actuator httptrace端点到千万量级敏感信息
-----------------------------------------

挂着Burp代理，被动扫描到了一个actuator接口，很幸运，开放了httptrace endpoint，借此我们可以获取到系统中的http请求日志

![image-20231122111607300](images/attach-fe16977041ca448d1177200318af109c04eaf33d.png)

但是发现如图上方使用的鉴权header并不能直接进入到系统中

刚开始怀疑是鉴权信息的过期时间设置的比较短，写了个脚本监控带有x-access-token的新增请求

```python
import requests
import time

monitored_text = ""

# URL
url = "http://xxxxx.xxxxx.com/xxxxxx/actuator/httptrace/"

while True:
    try:
        response = requests.get(url)
        page_text = response.text
        new_content = page_text[len(monitored_text):]

        # 检查新增的内容是否包含 "x-access-token" 字符串
        if "x-access-token" in new_content:
            current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            print(f"新增的内容包含 'x-access-token' 于 {current_time}")
        monitored_text = page_text
        time.sleep(1)

    except Exception as e:
        print(f"error Info: {e}")
```

最终成功拿到了一个可用的token，发现是JWT形式的-\_-||...

原来之前拿到的token是测试数据，难怪用不了

![image-20231122112644041](images/attach-170f6fb4327db2f29977a9c492f4e1d164ef64da.png)

使用该JWT，通过webpack提取到的api，访问后端API，拿下大量敏感信息，达千万量级，防止burp卡死，仅列出部分

![image.png](images/attach-cb236da079d2b5eea1fc693b161d2c904049dd07.png)

后言
--

不断提升识别攻击面、利用攻击面的广度与深度，是一名hacker的核心素养

攻防之中，拥有充足的经验，而又不陷入经验主义的迂腐，面对万难，而又不放弃思考，是出奇制胜的关键所在
