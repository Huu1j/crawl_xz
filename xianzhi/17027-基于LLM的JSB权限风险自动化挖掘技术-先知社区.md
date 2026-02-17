# 基于LLM的JSB权限风险自动化挖掘技术-先知社区

> **来源**: https://xz.aliyun.com/news/17027  
> **文章ID**: 17027

---

## **一、****LLM****在安全分析中的核心优势**

大型语言模型（LLM）具备代码理解、模式识别和逻辑推理能力，可显著提升JSB风险挖掘的自动化程度。其核心价值体现在：

1. **跨语言分析**：同时处理Java/Kotlin（Android）、Swift/ObjC（iOS）、JavaScript（Web）代码，识别跨语言调用链。
2. **语义级漏洞检测**：超越正则匹配，理解代码上下文（如权限校验逻辑是否包裹敏感操作）。
3. **攻击面扩展**：基于漏洞模式生成潜在攻击路径（如从接口暴露到数据流追踪）。

## **二、自动化挖掘技术架构思路**

![image.png](images/524cf8a7-ba2a-3d1e-9b3c-bb650671e6b2)

### **数据收集阶段**

**目标**：提取待分析的代码资产，包括：

* **原生层代码**：Android的Java/Kotlin（含WebView相关类）、iOS的Swift/ObjC。
* **Web层代码**：混合应用中的JavaScript/TypeScript文件。
* **配置文件**：AndroidManifest.xml（权限声明）、CSP策略、网络安全配置。

**工具链示例**：

```
# 从APK/IPA中提取反编译代码
apktool d app.apk -o android_src
jadx --deobf app.apk -o android_java
```

### **静态分析****阶段（****LLM****核心场景）**

#### **场景1：识别过度暴露的JSB接口**

**Prompt示例**：

```
分析以下代码，列出所有通过@JavascriptInterface或WKScriptMessageHandler暴露给Web的原生方法，并标注是否包含敏感操作（如文件读写、短信发送、数据库访问）：

// Android示例代码
public class JSBridge {
    @JavascriptInterface
    public String readFile(String path) { ... }  // 敏感操作
    
    @JavascriptInterface
    public void showToast(String text) { ... }   // 非敏感
}

// iOS示例代码
func userContentController(_ controller: WKUserContentController, didReceive message: WKScriptMessage) {
    if message.name == "deleteUser" { ... }      // 敏感操作
}
```

LLM输出结果：

```
1. Android-JSBridge.readFile: 敏感（文件操作）
2. iOS-deleteUser: 敏感（用户数据删除）
```

#### **场景2：检测输入验证缺失**

**Prompt设计**：

```
检查以下代码是否存在未经验证的用户输入直接用于系统调用，给出漏洞类型和修复建议：

// Java代码
@JavascriptInterface
public void execSQL(String sql) {
    db.execSQL(sql);  // 直接执行SQL
}

// Swift代码
func handleMessage(_ params: [String: Any]) {
    let cmd = params["command"] as! String
    shell(cmd)       // 执行系统命令
}
```

**LLM****输出**：

```
1. execSQL: SQL注入漏洞 → 建议使用参数化查询
2. shell(cmd): 命令注入漏洞 → 建议限制命令白名单
```

### **动态验证阶段（LLM生成****测试用例****）**

#### **场景1：生成****模糊测试****Payload**

**Prompt示例**：

```
为检测路径遍历漏洞，生成10个针对readFile(filePath)接口的测试用例，包括../跨目录、空字节截断等技巧。
```

**LLM****输出**：

```
window.NativeBridge.readFile("../../etc/passwd");
window.NativeBridge.readFile("valid_path%00.png");
window.NativeBridge.readFile("....//config.json");
...
```

#### **场景2：自动化权限绕过测试**

**LLM****生成Hook脚本**：

```
# 使用Frida绕过Android权限检查
JS_CODE = """
Java.perform(function() {
    var JSBridge = Java.use('com.example.JSBridge');
    JSBridge.isUserAuthenticated.implementation = function() {
        return true; // 强制返回已认证
    }
});
"""
```

### **误报过滤与优先级排序**

**Prompt示例**：

```
根据以下漏洞列表，按风险等级（高危/中危/低危）排序，并过滤误报：

1. showToast(text): 无权限校验但无敏感操作
2. sendSms(number, text): 无权限校验且涉及短信发送
3. log(message): 记录日志，参数未过滤但无系统影响
```

**LLM****输出**：

```
高危：sendSms  
中危：无  
低危：showToast, log
```

## **三、技术实现方案**

### **核心模块实现代码示例**

### 整体流程

* **代码解析**：结合Tree-sitter（语法解析）与LLM（语义分析）。
* **自动化流水线**：

```
def analyze_jsb_risk(code):
    # 步骤1: 静态模式匹配
    patterns = detect_jsb_interfaces(code)
    # 步骤2: LLM深度分析
    risks = llm_analyze(code, prompt_template)
    # 步骤3: 生成PoC
    poc = llm_generate_poc(risks)
    return generate_report(risks, poc)
```

### **静态分析****引擎（Python实现）**

```
import esprima  # JavaScript解析
import javalang  # Java解析
from tree_sitter import Language, Parser

# 初始化多语言解析器
class StaticAnalyzer:
    def __init__(self):
        # 加载Tree-sitter语法库
        JAVA_LANG = Language('build/java.so', 'java')
        self.java_parser = Parser()
        self.java_parser.set_language(JAVA_LANG)
        
    def detect_jsb_interfaces(self, code, lang):
        # 检测JSB接口定义
        vulnerabilities = []
        if lang == "java":
            tree = self.java_parser.parse(bytes(code, "utf8"))
            query = JAVA_LANG.query("""
            (method_declaration
                (modifiers 
                    (annotation 
                        name: (identifier) @anno_name (#eq? @anno_name "JavascriptInterface")
                    )
                )
                name: (identifier) @method_name
            ) @jsb_method
            """)
            captures = query.captures(tree.root_node)
            for node, _ in captures:
                method_name = node.parent.child_by_field_name("name").text.decode()
                vulnerabilities.append({
                    "type": "JSB_EXPOSURE",
                    "method": method_name,
                    "risk_level": "HIGH"
                })
        return vulnerabilities
```

### **LLM****语义分析模块**

```
from transformers import pipeline

class RiskClassifier:
    def __init__(self):
        self.classifier = pipeline(
            "text-classification", 
            model="codebert-base",
            tokenizer="codebert-base",
            device=0  # GPU加速
        )
    
    def analyze_risk_context(self, code_snippet):
        # 分析代码上下文风险
        prompt = f"""
        分析以下代码是否存在安全风险，返回JSON格式：
        {{
            "risk_type": "权限绕过|输入注入|...", 
            "confidence": 0-1,
            "description": "漏洞描述",
            "poc_example": "攻击示例"
        }}
        
        代码片段：
        {code_snippet}
        """
        result = self.classifier(prompt)
        return eval(result[0]['label'])  # 解析结构化输出
```

### **动态验证框架（****Frida****集成）**

```
// Android动态Hook示例
Java.perform(function() {
    var JSBridge = Java.use('com.example.JSBridge');
    
    // 监控所有JSB接口调用
    var methods = JSBridge.class.getDeclaredMethods();
    methods.forEach(function(method) {
        method.setAccessible(true);
        var methodName = method.getName();
        JSBridge[methodName].overloads.forEach(function(overload) {
            overload.implementation = function() {
                send({
                    type: "JSB_CALL",
                    method: methodName,
                    args: Array.prototype.slice.call(arguments)
                });
                return this[methodName].apply(this, arguments);
            };
        });
    });
});
```

### **自动化****PoC****生成**

```
def generate_js_poc(vuln_method, params):
    template = f"""
    // 自动生成的攻击Payload
    function exploit() {{
        let args = {json.dumps(params)};
        try {{
            window.NativeBridge.{vuln_method}(...args);
            console.log("[+] 漏洞利用成功");
        }} catch (e) {{
            console.log("[-] 漏洞修复:", e);
        }}
    }}
    exploit();
    """
    return template

# 示例：生成文件读取攻击代码
print(generate_js_poc("readFile", ["../../etc/passwd"]))
```

## 四、 完整代码脚本示例

```
import os
import json
import subprocess
from pathlib import Path
from typing import List, Dict
import javalang
from tree_sitter import Language, Parser, Node
from transformers import pipeline

class JSBScanner:
    def __init__(self):
        # 初始化多语言解析器
        self._init_parsers()
        # 加载AI模型
        self.risk_classifier = pipeline(
            "text-classification", 
            model="joernio/CodeBERT-javascript-bugfinder",
            device=0
        )
    
    def _init_parsers(self):
        """初始化Tree-sitter多语言解析器"""
        Language.build_library(
            'build/languages.so',
            ['vendor/tree-sitter-java', 'vendor/tree-sitter-javascript']
        )
        self.JAVA_LANG = Language('build/languages.so', 'java')
        self.JS_LANG = Language('build/languages.so', 'javascript')
        self.java_parser = Parser()
        self.java_parser.set_language(self.JAVA_LANG)
        self.js_parser = Parser()
        self.js_parser.set_language(self.JS_LANG)

    def scan_project(self, project_path: str) -> List[Dict]:
        """扫描整个项目"""
        vulnerabilities = []
        for root, _, files in os.walk(project_path):
            for file in files:
                if file.endswith(('.java', '.kt', '.js')):
                    path = Path(root) / file
                    lang = 'java' if path.suffix in ('.java', '.kt') else 'javascript'
                    with open(path, 'r', encoding='utf-8') as f:
                        code = f.read()
                        vulns = self.analyze_code(code, lang, str(path))
                        vulnerabilities.extend(vulns)
        return vulnerabilities

    def analyze_code(self, code: str, lang: str, file_path: str) -> List[Dict]:
        """核心分析方法"""
        if lang == 'java':
            return self._analyze_java(code, file_path)
        elif lang == 'javascript':
            return self._analyze_javascript(code, file_path)
        return []

    def _analyze_java(self, code: str, file_path: str) -> List[Dict]:
        """Java/Kotlin分析"""
        vulns = []
        tree = self.java_parser.parse(bytes(code, "utf8"))
        
        # 检测@JavascriptInterface方法
        query = self.JAVA_LANG.query("""
        (method_declaration
            (modifiers 
                (annotation 
                    name: (identifier) @anno_name (#eq? @anno_name "JavascriptInterface")
                )
            )
            name: (identifier) @method_name
            parameters: (formal_parameters) @params
        ) @jsb_method
        """)
        captures = query.captures(tree.root_node)
        
        for node, _ in captures:
            method_node = node.parent
            method_name = method_node.child_by_field_name('name').text.decode()
            params = self._parse_parameters(method_node)
            
            # AI风险分析
            code_snippet = method_node.text.decode()
            risk = self.risk_classifier(code_snippet)[0]
            
            vuln = {
                "file": file_path,
                "line": method_node.start_point[0] + 1,
                "method": method_name,
                "params": params,
                "risk_type": risk['label'],
                "confidence": risk['score'],
                "poc": self._generate_poc(method_name, params)
            }
            vulns.append(vuln)
        
        return vulns

    def _analyze_javascript(self, code: str, file_path: str) -> List[Dict]:
        """JavaScript调用分析"""
        vulns = []
        tree = self.js_parser.parse(bytes(code, "utf8"))
        
        # 检测JSB调用模式
        query = self.JS_LANG.query("""
        (call_expression
            member: (member_expression
                object: (identifier) @obj (#match? @obj "^(NativeBridge|webkit)")
                property: (property_identifier) @method
            )
        ) @jsb_call
        """)
        
        for node, _ in query.captures(tree.root_node):
            call_expr = node.parent
            method_name = call_expr.child_by_field_name('property').text.decode()
            
            # 参数分析
            args = self._parse_js_arguments(call_expr)
            
            vuln = {
                "file": file_path,
                "line": call_expr.start_point[0] + 1,
                "method": method_name,
                "arguments": args,
                "risk_type": "Potential JSB Call",
                "confidence": 0.8,
                "poc": self._generate_poc(method_name, args)
            }
            vulns.append(vuln)
        
        return vulns

    def _generate_poc(self, method: str, params: list) -> str:
        """生成验证PoC"""
        args = ', '.join([f'"{p}"' if isinstance(p, str) else str(p) for p in params])
        return f"window.NativeBridge.{method}({args})"

    def _parse_parameters(self, method_node: Node) -> list:
        """解析方法参数"""
        params_node = method_node.child_by_field_name('parameters')
        return [p.text.decode() for p in params_node.children if p.type == 'formal_parameter']

    def _parse_js_arguments(self, call_node: Node) -> list:
        """解析JS调用参数"""
        args_node = call_node.child_by_field_name('arguments')
        return [a.text.decode() for a in args_node.children if a.type != '(' and a.type != ')']

    def generate_report(self, vulnerabilities: List[Dict], output_format: str = "html"):
        """生成可视化报告"""
        # 实现报告生成逻辑（示例代码略）
        pass

class DynamicValidator:
    """动态验证模块（需连接设备）"""
    def __init__(self):
        self.frida_script = """
        Java.perform(function() {
            var JSBridge = Java.use('%s');
            JSBridge.%s.implementation = function() {
                send({method: '%s', args: Array.prototype.slice.call(arguments)});
                return this.%s.apply(this, arguments);
            };
        });
        """
    
    def instrument_method(self, class_name: str, method_name: str):
        """注入Frida检测脚本"""
        script = self.frida_script % (class_name, method_name, method_name, method_name)
        with open("detector.js", "w") as f:
            f.write(script)
        subprocess.run(["frida", "-U", "-l", "detector.js", "-f", "com.target.app"])

if __name__ == "__main__":
    scanner = JSBScanner()
    
    # 扫描示例项目
    project_path = "/path/to/your/project"
    results = scanner.scan_project(project_path)
    
    # 生成报告
    scanner.generate_report(results)
    
    # 动态验证高危漏洞
    validator = DynamicValidator()
    for vuln in filter(lambda x: x['confidence'] > 0.9, results):
        class_name = vuln['file'].split('/')[-1].split('.')[0]
        validator.instrument_method(class_name, vuln['method'])
```

**配置检测规则**

```
# jsb_rules.yaml
risk_patterns:
  - name: "File Access"
    pattern: "File|Path"
    severity: "HIGH"
    
  - name: "Database Access" 
    pattern: "SQLite|Room"
    severity: "CRITICAL"
```

#### 典型输出示例

```
[
  {
    "file": "src/com/example/Bridge.java",
    "line": 42,
    "method": "readFile",
    "params": ["String path"],
    "risk_type": "FILE_ACCESS",
    "confidence": 0.95,
    "poc": "window.NativeBridge.readFile("../../etc/passwd")"
  },
  {
    "file": "assets/web/main.js", 
    "line": 15,
    "method": "executeCommand",
    "arguments": ["cmd"],
    "risk_type": "COMMAND_INJECTION",
    "confidence": 0.87,
    "poc": "window.NativeBridge.executeCommand("rm -rf /")"
  }
]
```

## 五、 未来优化思路

1. **基础能力建设**

1. 实现核心语言的语法解析
2. 构建常见漏洞模式库

2. **智能增强阶段**

1. 集成LLM进行上下文分析
2. 训练领域专用模型

3. **生态整合**

1. 支持MobSF、Fortify等平台插件
2. 开发IDE实时检测插件
