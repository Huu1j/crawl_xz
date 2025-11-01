# 安全社区文章批量爬虫工具

批量爬取安全技术社区的文章，支持Markdown、PDF、HTML多种格式输出。

## 支持的社区

- ✅ **先知社区**（xz.aliyun.com）
- ✅ **奇安信攻防社区**（forum.butian.net）

## 功能特性

- 📝 **Markdown格式** - 便于编辑和版本控制
- 📄 **PDF格式** - 保留完整格式，方便阅读和打印
- 🌐 **HTML格式** - 可在浏览器中查看
- 🖼️ **图片下载** - 自动下载并本地化图片路径
- 💻 **代码高亮** - 完整保留代码块和语法高亮
- 🔄 **批量爬取** - 支持按ID范围批量下载

## 安装依赖

```bash
pip install -r requirements.txt
```

### requirements.txt

```
selenium
webdriver-manager
beautifulsoup4
markdownify
requests
markdown
pdfkit
lxml
```

### wkhtmltopdf 安装（PDF功能需要）

下载并安装 wkhtmltopdf：
- 官网：https://wkhtmltopdf.org/downloads.html
- 或将已下载的 wkhtmltopdf.exe 放到 `wkhtmltox/` 目录下

## 使用方法

### 1. 先知社区爬虫

```bash
# 基础用法（仅生成Markdown）
python crawl_xz_aliyun.py --start 18000 --end 18010 --format md

# 生成Markdown和PDF
python crawl_xz_aliyun.py --start 18000 --end 18010 --format md+pdf

# 生成全部格式（Markdown + PDF + HTML）
python crawl_xz_aliyun.py --start 18000 --end 18010 --format all

# 指定文章类型
python crawl_xz_aliyun.py --type news --start 18000 --end 18010
python crawl_xz_aliyun.py --type t --start 10000 --end 10010

# 调试模式（显示浏览器窗口，保存更多调试信息）
python crawl_xz_aliyun.py --start 18015 --end 18015 --format all --debug

# 自定义保存目录和间隔时间
python crawl_xz_aliyun.py --start 18000 --end 18010 --dir ./my_articles --sleep 10
```

#### 参数说明

| 参数 | 说明 | 默认值 | 可选值 |
|------|------|--------|--------|
| `--type` | 文章类型 | `news` | `news`, `t` |
| `--start` | 起始文章ID | `9450` | 任意整数 |
| `--end` | 结束文章ID | `9455` | 任意整数 |
| `--format` | 输出格式 | `all` | `md`, `md+pdf`, `all` |
| `--sleep` | 请求间隔（秒） | `5` | 任意整数 |
| `--dir` | 保存目录 | `./xianzhi` | 任意路径 |
| `--debug` | 调试模式 | `False` | 添加此参数启用 |


```bash
# 基础用法（仅生成Markdown）
python crawl_butian_forum.py --start 2400 --end 2405 --format md

# 生成Markdown和PDF
python crawl_butian_forum.py --start 2400 --end 2405 --format md+pdf

# 生成全部格式
python crawl_butian_forum.py --start 2400 --end 2405 --format all

# 指定文章类型
python crawl_butian_forum.py --type community --start 2400 --end 2405
python crawl_butian_forum.py --type share --start 1000 --end 1010

# 自定义保存目录
python crawl_butian_forum.py --start 2400 --end 2405 --dir ./my_butian --sleep 3
```

#### 参数说明

| 参数 | 说明 | 默认值 | 可选值 |
|------|------|--------|--------|
| `--type` | 文章类型 | `community` | `community`, `share` |
| `--start` | 起始文章ID | `2400` | 任意整数 |
| `--end` | 结束文章ID | `2405` | 任意整数 |
| `--format` | 输出格式 | `all` | `md`, `md+pdf`, `all` |
| `--sleep` | 请求间隔（秒） | `3` | 任意整数 |
| `--dir` | 保存目录 | `./butian` | 任意路径 |


## 注意事项


## 更新日志

### v1.0 (2025-11-01)

- ✅ 支持先知社区文章爬取
- ✅ 支持奇安信攻防社区文章爬取
- ✅ 支持Markdown、PDF、HTML多格式输出
- ✅ 自动下载并本地化图片
- ✅ 完整保留代码块和格式
- ✅ 支持批量爬取和调试模式

## 🤖 GitHub Actions 自动化

本项目支持使用GitHub Actions自动爬取文章并保存到GitHub仓库！



## 贡献

欢迎提交Issue和Pull Request！

## ⚠️ 免责声明

- 本工具仅供学习研究使用
- 所有文章版权归原作者所有
- 请遵守目标网站的使用条款和robots.txt
- 请勿用于商业用途或过度爬取
