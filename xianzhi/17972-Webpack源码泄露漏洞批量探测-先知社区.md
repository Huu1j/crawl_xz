# Webpack源码泄露漏洞批量探测-先知社区

> **来源**: https://xz.aliyun.com/news/17972  
> **文章ID**: 17972

---

# 一、漏洞原理

Webpack 源码泄露漏洞是一种由于前端打包工具 Webpack 配置不当，导致攻击者可通过 .map 文件还原原始源代码的安全风险。

Webpack 在打包前端项目时，若开启 source map 生成功能（如配置 devtool: "source-map"），会生成 .js.map 文件或内嵌映射信息到 JS 文件中。

* Source map 作用：用于生产环境调试，将压缩/混淆后的代码映射回原始源码，便于定位错误。
* 泄露途径

* 显式生成 .map 文件：当 devtool 设为 source-map、hidden-source-map 等值时，JS 文件同级目录会生成 .map 文件，通过直接访问 main.js.map 即可下载；
* 内嵌映射信息：当 devtool 设为 inline-source-map 时，映射数据会以 Base64 形式内嵌在 JS 文件末尾。

# 二、漏洞危害

泄露的源码可能包含以下敏感信息，导致进一步攻击：

* 业务逻辑暴露：API 接口路径、权限验证逻辑、加密算法（如登录密码加解密方式）；
* 敏感数据泄露：管理员邮箱、内网 IP 地址、数据库连接配置（若开发阶段未删除测试配置）；
* 攻击面扩大：还原后的代码可辅助挖掘 XSS、越权访问等漏洞。

# 三、漏洞检测

1. 浏览器插件检测

![image.png](images/20250513191257-39172364-2feb-1.png)

2. F12搜索关键字

![image.png](images/20250513191303-3d2fd798-2feb-1.png)

3. 批量探测

* 获取HTML页面
* 解析JS文件链接
* 并发检测JS文件
* 特征检测
* 版本检测
* SourceMap检测
* 输出CSV/HTML文件

```
import requests
import re
import csv
import pandas as pd
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin
from bs4 import BeautifulSoup

# 禁用SSL警告
requests.packages.urllib3.disable_warnings()


def detect_webpack(domain):
    """
    检测域名是否使用Webpack打包器
    返回：域名, [检测结果列表]
    """
    domain = domain.strip()
    if not domain:
        return (domain, [])

    detected_data = []

    try:
        # 获取HTML页面
        response = requests.get(
            f"https://{domain}",
            timeout=15,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if response.status_code != 200:
            return (domain, [])

        # 解析JS文件链接
        soup = BeautifulSoup(response.text, 'html.parser')
        script_tags = soup.find_all('script', {'src': True})
        js_urls = list({urljoin(response.url, tag['src']) for tag in script_tags})  # 去重

        # 并发检测JS文件
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(check_js_file, url) for url in js_urls]
            for future, url in zip(futures, js_urls):
                result = future.result()
                if result["detected"]:
                    detected_data.append({
                        "js_url": url,
                        "version": result["version"],
                        "sourcemap": result["sourcemap"],
                        "patterns": result["patterns"]
                    })

        return (domain, detected_data)

    except Exception as e:
        return (domain, [])


def check_js_file(url):
    """
    检查JS文件特征并返回完整检测数据
    返回：{
        "detected": bool,
        "version": str,
        "sourcemap": str,
        "patterns": list,
        "js_url": str
    }
    """
    result = {
        "detected": False,
        "version": None,
        "sourcemap": None,
        "patterns": [],
        "js_url": url
    }

    try:
        # 下载前100KB内容
        headers = {'Range': 'bytes=0-102400', 'User-Agent': 'Mozilla/5.0'}
        response = requests.get(
            url,
            timeout=10,
            verify=False,
            headers=headers,
            stream=True
        )
        content = response.text.lower()

        # 特征检测
        patterns = {
            '__webpack_require__': '核心函数标识',
            'webpackchunk': '代码分块特征',
            'webpackjsonp': '异步加载标识',
            '[contenthash]': '文件哈希命名规则'
        }

        # 匹配特征
        matched_patterns = []
        for pattern, desc in patterns.items():
            if re.search(pattern, content):
                matched_patterns.append(f"{desc}({pattern})")

        # 版本检测
        version_match = re.search(r'webpack\s+v?(\d+\.\d+\.\d+)', content)
        if version_match:
            result["version"] = version_match.group(1)

        # SourceMap检测
        sourcemap_match = re.search(r'//# sourceMappingURL=(.+\.map)', content)
        if sourcemap_match:
            result["sourcemap"] = urljoin(url, sourcemap_match.group(1))

        # 综合判断
        if matched_patterns or result["version"] or result["sourcemap"]:
            result.update({
                "detected": True,
                "patterns": matched_patterns
            })

        return result

    except Exception as e:
        return result


def generate_html_report(csv_path, html_path):
    """生成带样式的HTML报告"""
    # 读取CSV数据
    df = pd.read_csv(csv_path)

    # 生成HTML表格
    html = df.to_html(index=False, escape=False)

    # 添加CSS样式
    styled_html = f"""
    <html>
        <head>
            <style>
                table {{
                    border-collapse: collapse;
                    width: 100%;
                    margin: 20px 0;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.2);
                }}
                th {{
                    background-color: #4CAF50;
                    color: white;
                    padding: 12px;
                    text-align: left;
                }}
                td {{
                    padding: 10px;
                    border-bottom: 1px solid #ddd;
                }}
                tr:nth-child(even) {{
                    background-color: #f2f2f2;
                }}
                tr:hover {{
                    background-color: #ddd;
                }}
                .detected {{
                    color: green;
                    font-weight: bold;
                }}
                .sourcemap {{
                    max-width: 300px;
                    overflow: hidden;
                    text-overflow: ellipsis;
                }}
            </style>
        </head>
        <body>
            <h2>Webpack检测报告</h2>
            {html}
        </body>
    </html>
    """

    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(styled_html)


def process_domains(input_file, output_csv, output_html):
    # 读取域名列表
    with open(input_file, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]

    # 并发处理
    results = []
    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = [executor.submit(detect_webpack, domain) for domain in domains]
        for future in futures:
            results.append(future.result())

    # 写入CSV文件
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Domain',
            'Webpack Detected',
            'JS Path',
            'Detected Patterns',
            'Webpack Version',
            'SourceMap URL'
        ])

        for domain, files in results:
            if files:
                for data in files:
                    writer.writerow([
                        domain,
                        'True',
                        data["js_url"],
                        '; '.join(data["patterns"]),
                        data["version"] or 'N/A',
                        data["sourcemap"] or 'N/A'
                    ])
            else:
                writer.writerow([domain, 'False', 'N/A', 'N/A', 'N/A', 'N/A'])

    # 生成HTML报告
    generate_html_report(output_csv, output_html)


if __name__ == "__main__":
    process_domains(
        input_file="domains.txt",
        output_csv="webpack_report.csv",
        output_html="webpack_report.html"
    )
```

* 结果呈现

![image.png](images/20250513191306-3e99dbd4-2feb-1.png)

![image.png](images/20250513191308-3fcb0c2d-2feb-1.png)

# 四、漏洞利用

本文重点是漏洞的批量探测，关于漏洞利用手法不过多赘述，下文仅列举常见的攻击手法。

1. 下载 .map 文件：通过上述方法获取目标网站的 .map 文件；
2. 还原源码：使用 reverse-sourcemap 工具还原原始项目结构：

```
npm install -g reverse-sourcemap
reverse-sourcemap --output-dir ./src main.js.map
```

还原后的代码将保留原始目录结构（如 Vue 组件的 assets、router 目录）

3. 分析敏感信息：重点检查 config/（配置）、api/（接口）、utils/（通用函数）等目录

# 五、修复方案

* 禁用 source map 生成：在生产环境配置中设置 productionSourceMap: false（Vue 项目修改 vue.config.js）或 devtool: false（Webpack 原生配置）；
* 删除已有 .map 文件：通过服务器配置（如 Nginx）禁止访问 .map 文件，或直接移除部署目录中的 .map 文件；
* 代码混淆加固：使用 terser-webpack-plugin 等工具对 JS 代码进行深度混淆，增加逆向难度；
* 内网信息审查：确保源码中不包含测试环境的内网 IP、硬编码凭证等敏感数据。
