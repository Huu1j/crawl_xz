# 记一次密码重置到后台GetShell

> **来源**: https://forum.butian.net/share/2450  
> **文章ID**: 2450

---

### 1.尝试登录

#### 1.打开网页，看到一个登录，尝试点击

![image.png](images/attach-ee2e91e46b51e943e3214d5caaf819f1283ed981.png)

#### 2.发现提示 Unknown host

![image.png](images/attach-9119941fbf389abf76cfeec4977edbbb7abc7dbd.png)

#### 3.因为刚开始是用 IP 访问的网站，点击登录按钮为域名访问该网站，猜测可能使用域名访问不了，于是把域名改为IP加上后台地址访问

成功访问到后台

![image.png](images/attach-5fb4ca635ea2aabbe15a3367286e0ac481076d54.png)

#### 4.发现一个找回密码按钮，点进去看看

![image.png](images/attach-6cc7ed21adb189e9b44f38075429ca61cf7f6681.png)

#### 5.输入admin,发现修改密码第一步只需要回答问题，1+1=?

呵呵，这不就是2嘛

![image.png](images/attach-1031cdd48675dacb88036f3930d6a68431d9e631.png)

#### 6.这未免有点。。。不管了，直接掏Burp跑一下

![image.png](images/attach-cf2b26d491546cb2c112aebedb64f8a3a16dcdca.png)

#### 7.从1跑到1111，后面又试了11111，111111等数字也没跑出来

![image.png](images/attach-08184683ce697f6ab3436eae9ed2b14e741c00e7.png)

#### 8.尝试跑用户名，最终跑出两个账号 cs , test

![image.png](images/attach-429414914c14fcb7203d2c4259c5f981c27429d9.png)

#### 9.使用test账号进行密码找回，这一看就是乱打的，密码问题我猜就是111

![image.png](images/attach-c87d999dd10dd4181cfa3ae5e7b10dd9881ee684.png)

#### 10.最终重置该成功

![image.png](images/attach-cf6e3f7bdc51efbc92f75e04387f4502093bc64f.png)

### 2.进入后台

#### 1.本来想点到上传资源处尝试文件上传Getshell的，发现权限不够

![image.png](images/attach-a3b684b76afc52b4a4eadd0c87f1a631bb290f75.png)

![image.png](images/attach-691dfe56b40d558aeb66cb62027b7fe4410f9992.png)

#### 2.点击上传头像也无反应，8个功能，只有一个微课功能可以正常使用

![image.png](images/attach-522380e1da9da59019f8f3e622a323b24d13ddb1.png)

#### 3.发现上传附件处点击没反应，于是打开F12查看该按钮是不是被注释掉

![image.png](images/attach-9b1ea9d959edeecfb4eec9af8eb4623e8751b37b.png)

#### 4.找到其他的功能，挨个访问，却没有一个能够访问的。。。

![image.png](images/attach-d19a5d2a7dffe36928e457fd4a6f4c2216e1a09a.png)

### 3.尝试重置admin密码

#### 1.在重置密码处发现userid参数

![image.png](images/attach-a9cb018d45782b17e0d37f3f71550105941ee061.png)

#### 2.在前台活跃用户处，发现自己的 id 与修改密码处的 userid 相同

![image.png](images/attach-5cbb4f4416b9aaaa6ee4a44b430bc966ac4ac1c2.png)

#### 3.先不改 admin 账号的密码，尝试修改这个pwd账号

![image.png](images/attach-d09adac6de1f70d6de597e28c7efa278f2686318.png)

#### 4.当原密码跑到 !@#$%^ 处发现重置成功，尝试登录

![image.png](images/attach-9ab6cddbe5ffb748fdc82071bfda115fd388e6ae.png)

#### 5.成功登录该账号

![image.png](images/attach-a54e653b35a0415308c6b6b9e3ba2ee1985a3f7d.png)

#### 6.userid 替换为管理员的id,成功登录管理员账号

![image.png](images/attach-0e39089775b0ac1a514ac108b339bcc1024df577.png)

### 4.文件上传

#### 1.到后面才发现，其实管理不管理员账号都一个样，，，

在个人中心处，查看源代码，发现一个神秘的 url

![image.png](images/attach-046e05dc6f6b31e84e599f99c656ef55456fa835.png)

#### 2.复制到浏览器尝试访问，发现是个文件上传的地址

![image.png](images/attach-6ff0b0ca9e0dcb57401ec665dbbf188e2a1b0f0c.png)

#### 3.上传 jpg ，把后缀直接修改为 jsp 即可上传 ~ ~，

![image.png](images/attach-e86a4d22df2c7475cba4e450a490a825e4678075.png)

#### 4.访问即可

![image.png](images/attach-c7e66643b5528e05ba1af4f2b6ef36dd5e03c56a.png)

### 后记：渗透过程中，细心是最重要的。。。

1. 数据完整性保护：细心的渗透测试人员在进行渗透测试时会注意数据的完整性，并尽量避免对目标系统造成不可修复的损坏。他们会在测试过程中采取适当的措施，以避免意外删除或篡改敏感数据。
2. 最小影响原则：细心的渗透测试人员始终遵循最小影响原则，尽量减少对目标系统正常运行的干扰。他们会在渗透测试过程中尽量避免造成系统崩溃或服务不可用等情况，以确保业务连续性。
    
    这个admin的账号根本就没有必要重置，test账号一样可以传，，，
    
    所以各位尽量在动静最小的情况下，获取系统权限
