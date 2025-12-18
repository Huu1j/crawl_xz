# BurpSuite插件：OneScan - 递归目录扫描插件-先知社区

> **来源**: https://xz.aliyun.com/news/16417  
> **文章ID**: 16417

---

各位师傅元旦快乐！祝各位师傅新的一年挖的漏洞翻倍，收入翻倍，开心翻倍～

# OneScan - 递归目录扫描插件

OneScan 是一款用于递归目录扫描的 BurpSuite 插件，为发现更深层次目录下隐藏的漏洞赋能

项目地址：<https://github.com/vaycore/OneScan>

## 项目介绍

OneScan 插件的思路由 One 哥提供，我负责编码将思路变现；后续有段时间我没参与开发，由 Rural.Dog 哥担下更新功能的重任；在 Github 开源之后，我继续项目的维护和升级工作。

OneScan 项目升级维护了近两年，感谢这期间师傅们积极的反馈意见和提供优化建议，让我有机会发现 OneScan 在实战中遇到的更深层次的问题，从而精准定位问题点并修复，优化使用体验上的不足；除此之外，针对师傅们反馈的特殊测试场景，新增了一些实战中必要的功能，欢迎各位师傅安装体验。

### 使用场景

OneScan 起初是为了发现站点深层目录下的 `Swagger-API` 接口文档，后面随着功能完善和使用姿势的增加，目前可以完成如下测试工作：

* 发现隐藏 API 接口
* 发现敏感信息泄漏
* 测试未授权、越权漏洞

### 安装说明

> 因为之前有萌新在群里问过，所以简单过一下。大佬们可跳过此步骤

前往 <https://github.com/vaycore/OneScan/releases> 下载插件最新版本 JAR 包：

![](images/20250101120802-fe9082da-c7f5-1.png)

以 BurpSuite v2024.3.1.3 版本为例。首先切换到 `Extensions` 标签下的 `Installed` 页面，然后点击 `Add` 按钮，准备添加 OneScan 插件：

![](images/20250101120822-0ab57d4a-c7f6-1.png)

在打开的 `Load Burp extension` 窗口中点击 `Select file...` 按钮：

![](images/20250101120943-3aa9bd2c-c7f6-1.png)

选择下载完成的 OneScan 插件 JAR 包，点击打开：

![](images/20250101120956-42a1c538-c7f6-1.png)

然后点击窗口右下角 `Next` 按钮，输出如下信息，并且没有报错，即表示安装成功：

![](images/20250101121016-4e68ab5c-c7f6-1.png)

## 配置HaE插件

> 注意：OneScan 加载 HaE 后，作用域也只限于 OneScan 插件（仅用于提取并展示高亮数据），不会影响到 BurpSuite 安装的 HaE 插件的正常功能

首先，前往 <https://github.com/gh0stkey/HaE/releases> 下载 HaE 插件最新版本 JAR 包：

![](images/20250101121035-59f150dc-c7f6-1.png)

切换到 OneScan 插件配置下的其他配置页面，在 HaE 配置项，点击 “选择文件...” 按钮：

![](images/20250101121047-60f559e6-c7f6-1.png)

选择下载完成的 HaE 插件 JAR 文件的路径：

![](images/20250101121100-68dbce10-c7f6-1.png)

确认后，提示 HaE 加载成功，即表示配置完成：

![](images/20250101121116-720e1e0c-c7f6-1.png)

配置 HaE 需要注意：

* 由于 HaE 3.0 版本开始采用 `Montoya API` 进行开发，使用新版 HaE 需要升级你的 BurpSuite 版本（>= 2023.12.1）
* 如果您的 BurpSuite 版本低于 2023.12.1 版本，且不想升级 BurpSuite 版本，可考虑下载 <https://github.com/gh0stkey/HaE/releases/tag/2.6.1> 低版本 HaE 继续使用

## 基本使用

介绍一下 OneScan 插件的常见用法

### 主动扫描

首先，在数据看板中打开 “目录扫描” 开关：

![](images/20250101121138-7f9236c6-c7f6-1.png)

在 BurpSuite 其他模块中，可以把请求包发送到 OneScan 插件主动扫描：

![](images/20250101121152-87c65c78-c7f6-1.png)

如果配置了多个字典，会激活 “使用其它字典扫描” 菜单项，可以选择使用其它字典进行主动扫描：

![](images/20250101121211-9318a518-c7f6-1.png)

扫描示例如下：

![](images/20250101121222-996a8bac-c7f6-1.png)

> 注意：主动扫描的请求包，不会被主机允许/阻止列表拦截

### 被动扫描

首先，在 OneScan 数据看板中打开 “监听代理请求”、“目录扫描” 开关：

![](images/20250101121305-b2ff477e-c7f6-1.png)

切换到 OneScan 插件配置标签下的主机配置页面，配置主机允许/阻止列表（也就是黑/白名单，如果配置为空表示不启用黑/白名单）：

![](images/20250101121317-ba762158-c7f6-1.png)

然后在浏览器访问允许列表里的目标即可（规则外的流量不会扫描），示例如下：

![](images/20250101121332-c339dc8a-c7f6-1.png)

### 测试未授权、越权接口

数据看板中的 “移除请求头”、“替换请求头” 功能开关分别用于测试未授权和越权漏洞。如果有些目标特殊，可以使用 “请求包处理” 功能进行处理

#### 测试未授权

首先，切换到 OneScan 插件配置标签下的请求配置页面，配置要移除的请求头，示例如下：

![](images/20250101121357-d21d2d06-c7f6-1.png)

配置完成后，在数据看板里打开 “移除请求头” 开关：

![](images/20250101121407-d8610e8a-c7f6-1.png)

将如下请求包发送到 OneScan 插件：

![](images/20250101121419-df2a8be2-c7f6-1.png)

结果如下所示，可以发现已自动移除 `Cookie`、`Authorization` 请求头：

![](images/20250101121434-e807f51a-c7f6-1.png)

> 实战过程中，可以打开 “监听代理请求”、“移除请求头” 开关，然后登录目标站点，过一遍站点的功能，之后在 OneScan 中检测是否存在未授权的接口。

#### 测试越权

首先，切换到 OneScan 插件配置标签下的请求配置页面，配置要替换的请求头（一般登录 A 账号的话，这里配置 B 账号的权限），示例如下：

![](images/20250101121452-f2c31ae8-c7f6-1.png)

配置完成后，在数据看板里打开 “替换请求头” 开关：

![](images/20250101121508-fc6c5474-c7f6-1.png)

将如下请求包发送到 OneScan 插件：

![](images/20250101121534-0c2bce08-c7f7-1.png)

结果如下所示，可以发现已自动替换 `Cookie`、`Authorization` 请求头的内容：

![](images/20250101121553-1743a96e-c7f7-1.png)

> 实战过程中，可以打开 “监听代理请求”、“替换请求头” 开关，配置账号 B 的权限，然后用 A 账号登录目标站点，过一遍站点的功能，之后在 OneScan 中检测是否存在越权信息。

### 请求包处理

OneScan 扫描目录只发起 GET 请求，假如需要发起 POST 请求（或者需要构建特殊的请求包），就需要用到 “请求包处理” 功能了：

![](images/20250101121647-375f34ac-c7f7-1.png)

首先，点击 “添加” 按钮，添加一条请求包处理规则，输入规则名（例如：Post）：

![](images/20250101121703-4123ff54-c7f7-1.png)

点击下方规则旁边的 “添加” 按钮，添加一条处理规则：

![](images/20250101121727-4f4dc268-c7f7-1.png)

规则类型选择：“条件检查”，生效范围选择：“请求头”，正则表达式：`GET /`，点击确定：

![](images/20250101121744-597f9446-c7f7-1.png)

继续添加第二条处理规则，规则类型选择：“匹配/替换”，生效范围选择：“请求头”，正则表达式：`GET /`，替换为：`POST /`，点击确定：

![](images/20250101121759-623ac8c6-c7f7-1.png)

继续添加第三条处理规则，规则类型选择：“匹配/替换”，生效范围选择：“请求头”，正则表达式：`\r\nContent-Type: .*\r\n`，替换为：`\r\n`，点击确定：

![](images/20250101121812-6a83d90a-c7f7-1.png)

继续添加最后一条处理规则，规则类型选择：“添加后缀”，生效范围选择：“请求头”，后缀值：`\r\nContent-Type: application/x-www-form-urlencoded`，点击确定：

![](images/20250101121828-73989896-c7f7-1.png)

添加完成后，点击确定：

![](images/20250101121842-7c0e8cf6-c7f7-1.png)

新添加的规则如下：

![](images/20250101121854-8302f150-c7f7-1.png)

主动扫描测试，请求包处理结果示例如下：

![](images/20250101121903-88e3978c-c7f7-1.png)

发送过来的请求包内容如下：

![](images/20250101121914-8f0c6a9e-c7f7-1.png)

## 常用字典

目录扫描主要就是靠字典，在递归扫描、动态变量特性的加持下，可以简化一些测试工作。这里分享一些常用的字典：

扫描隐藏接口文档字典示例如下：

```
/swagger.json
/swagger.yaml
/swagger-resources
/swagger-ui.html
/swagger-ui/index.html
/api/swagger
/api/swagger.json
/api/swagger.yaml
/v1/api-docs
/v2/api-docs
/v3/api-docs
/api/v1/api-docs
/api/v2/api-docs
/api/v3/api-docs
/doc.html

```

扫描隐藏的 API 接口字典示例如下：

```
/list
/users
/user/1
/save
/update
/servers
/services?wsdl
/keys
/actuator
/jolokia/list
/getConfig
/file/upload
/upload
/env
/add
/create
/ping

```

扫描敏感信息泄漏字典示例如下：

```
/.git/config
/.svn/entries
/{{domain}}.zip
/{{domain.main}}.zip
/{{domain.name}}.zip
/{{subdomain}}.zip
/{{webroot}}.zip
/config.json
/web.config
/settings.json
/{{date.yy}}_{{date.MM}}_{{date.dd}}.log
/Logs/{{date.yy}}_{{date.MM}}_{{date.dd}}.log
/Runtime/Logs/{{date.yy}}_{{date.MM}}_{{date.dd}}.log
/Application/Runtime/Logs/{{date.yy}}_{{date.MM}}_{{date.dd}}.log

```

> 还可以参考 ModerRAS 师傅的文章，自行配置字典：<https://miaostay.com/2023/08/Springboot%E6%B8%97%E9%80%8F%E6%80%9D%E8%B7%AF/>

# END

* 使用过程中有 BUG 欢迎在 `Github` 提交 `Issues`，或者也可以在 QQ 群里提问（看到了会及时回复）
* 感谢各位师傅的关注和支持（如果觉得项目还不错，请给项目一个 Star 吧）
