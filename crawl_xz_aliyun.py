#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
先知社区文章批量爬虫

Version: 1.0
Date: 2025-10-31
Author: AI Assistant
Description: 批量爬取先知社区文章，支持Markdown、PDF、HTML多种格式输出
"""

import time
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager
import markdownify
from bs4 import BeautifulSoup
import os
import shutil
import subprocess
import requests
import markdown
import pdfkit
import argparse
import re
import json
from urllib.parse import unquote

__version__ = '1.0'
__author__ = 'AI Assistant'
__date__ = '2025-10-31'

def filename_filter(filename):  
    """过滤文件名中的非法字符"""
    string1="\/:*?\"<>|"
    for s1 in string1:
        filename= filename.replace(s1," ")
    return filename.strip()

def markdown_to_pdf(md_content, output_path, title="", keep_html=True):
    """将Markdown内容转换为PDF
    
    Args:
        md_content: Markdown内容
        output_path: PDF输出路径
        title: 文章标题
        keep_html: 是否保留HTML文件（True=保留，False=仅作为临时文件）
    """
    
    # 先保存HTML（作为中间文件或最终输出）
    html_path = output_path.replace('.pdf', '.html')
    
    try:
        # 修复图片路径：HTML在pdf/目录下，图片在images/目录下，需要使用相对路径
        # 将 images/xxx.png 替换为 ../images/xxx.png
        md_content_for_html = md_content.replace('images/', '../images/')
        
        # 转换Markdown为HTML
        html_content = markdown.markdown(
            md_content_for_html, 
            extensions=['extra', 'codehilite', 'tables', 'fenced_code']
        )
        
        # 添加CSS样式使PDF更美观
        styled_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <title>{title}</title>
    <style>
        body {{
            font-family: "Microsoft YaHei", "SimSun", Arial, sans-serif;
            line-height: 1.6;
            max-width: 800px;
            margin: 40px auto;
            padding: 20px;
            color: #333;
        }}
        h1, h2, h3, h4, h5, h6 {{
            color: #2c3e50;
            margin-top: 24px;
            margin-bottom: 16px;
        }}
        h1 {{
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }}
        code {{
            background-color: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: "Consolas", "Monaco", monospace;
        }}
        pre {{
            background-color: #f6f8fa;
            padding: 16px;
            border-radius: 6px;
            overflow-x: auto;
        }}
        img {{
            max-width: 100%;
            height: auto;
        }}
        blockquote {{
            border-left: 4px solid #3498db;
            padding-left: 16px;
            margin-left: 0;
            color: #666;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
            margin: 16px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
        }}
    </style>
</head>
<body>
    <h1>{title}</h1>
    {html_content}
</body>
</html>"""
        
        # 保存HTML文件（使用UTF-8 with BOM，更好的兼容性）
        with open(html_path, 'w', encoding='utf-8-sig') as f:
            f.write(styled_html)
        
        # 尝试转换为PDF
        try:
            import subprocess
            
            # 配置pdfkit选项
            options = {
                'encoding': 'UTF-8',
                'enable-local-file-access': None,
                'quiet': '',
                'page-size': 'A4',
                'margin-top': '20mm',
                'margin-right': '20mm',
                'margin-bottom': '20mm',
                'margin-left': '20mm',
            }
            
            # 配置 pdfkit，处理编码问题
            config = None
            wkhtmltopdf_path = None
            
            # 获取当前脚本所在目录
            current_script_dir = os.path.dirname(os.path.abspath(__file__))
            
            # 尝试找到 wkhtmltopdf（按优先级搜索）
            wkhtmltopdf_path = os.path.join(current_script_dir, "wkhtmltox", "wkhtmltopdf.exe")

            
            if wkhtmltopdf_path:
                config = pdfkit.configuration(wkhtmltopdf=wkhtmltopdf_path)
            else:
                print(f"⚠️  未找到 wkhtmltopdf")

            
            # 从HTML文件转换为PDF
            try:
                if config:
                    pdfkit.from_file(html_path, output_path, options=options, configuration=config)
                else:
                    pdfkit.from_file(html_path, output_path, options=options)
                
                print(f"✓ PDF已生成: {output_path}")
                
                # 根据参数决定是否保留HTML
                if keep_html:
                    print(f"✓ HTML已生成: {html_path}")
                else:
                    # 删除临时HTML文件
                    try:
                        os.remove(html_path)
                        print(f"✓ 已删除临时HTML文件")
                    except:
                        pass
                
                return True
                
            except (OSError, IOError, UnicodeDecodeError) as e:
                error_msg = str(e)
                if 'wkhtmltopdf' in error_msg.lower() or 'no such file' in error_msg.lower():
                    print(f"⚠️  需要安装 wkhtmltopdf 才能生成PDF")
                    print(f"   下载地址: https://wkhtmltopdf.org/downloads.html")
                elif 'utf-8' in error_msg.lower() or 'decode' in error_msg.lower():
                    print(f"⚠️  PDF转换编码错误，这是 wkhtmltopdf 的已知问题")
                    print(f"   建议：使用生成的 HTML 文件，在浏览器中打开后打印为PDF")
                else:
                    print(f"⚠️  PDF生成失败: {error_msg}")
                
                print(f"✓ HTML已生成: {html_path} (可用浏览器打开后打印为PDF)")
                return False
                
        except ImportError:
            print(f"⚠️  pdfkit 未安装，跳过PDF生成")
            print(f"✓ HTML已生成: {html_path}")
            return False
            
    except Exception as e:
        print(f"✗ 处理失败: {e}")
        return False

def crawl_article(driver, url, article_id, url_type="t", save_dir="./xianzhi", output_format="md"):
    """爬取单篇文章

    Args:
        driver: Selenium WebDriver
        url: 文章URL
        article_id: 文章ID
        url_type: URL类型 ("t" 或 "news")
        save_dir: 保存目录
        output_format: 输出格式 ("md"=仅MD, "md+pdf"=MD和PDF, "all"=MD+PDF+HTML)
    """
    try:
        print(f"\n正在爬取: {url}")
        driver.get(url)
        time.sleep(3)

        # 滚动页面以触发懒加载的代码块
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        time.sleep(2)
        driver.execute_script("window.scrollTo(0, 0);")
        time.sleep(1)

        # 检查是否被重定向（通过比较文章ID）
        current_url = driver.current_url
        # 从当前URL中提取文章ID
        current_id_match = re.search(r'/(news|t)/(\d+)', current_url)
        if current_id_match:
            current_article_id = current_id_match.group(2)
            if current_article_id != article_id:
                # URL被重定向到其他文章，说明请求的文章不存在
                print(f"✗ 文章不存在（已重定向到文章ID: {current_article_id}）")
                return False
        elif current_url != url:
            # URL完全不同，可能是错误页面
            print(f"✗ 文章不存在（重定向到: {current_url}）")
            return False

        headers = {
            "Referer": "https://xz.aliyun.com/"
        }

        html_content = driver.page_source
        soup = BeautifulSoup(html_content, "html.parser")

        # 获取标题
        title_tag = soup.find('title')
        title_text = title_tag.text if title_tag else None

        if not title_text or '400 -' in title_text or '404' in title_text:
            print(f"✗ 文章不存在或无法访问")
            return False

        # 清理标题
        title_text = title_text.replace(' - 先知社区', '').strip()
        print(f"标题: {title_text}")

        # 精确提取文章正文
        article_content = (
            soup.find('div', id='markdown-body') or
            soup.find('div', class_='markdown-body') or
            soup.find('div', class_='article-content') or
            soup.find('div', class_='content-detail')
        )

        if not article_content:
            print("✗ 无法找到文章内容")
            return False

        print(f"✓ 已定位文章正文区域")

        # 处理先知社区的代码块（支持两种格式）
        # 格式1: <card name="codeblock"> - 代码块数据被URL编码后存储在 value 属性中
        code_cards = soup.find_all('card', {'name': 'codeblock'})
        card_count = 0

        if code_cards:
            print(f"  ✓ 发现 {len(code_cards)} 个 Card 格式代码块")

            for idx, card in enumerate(code_cards):
                try:
                    # 获取 value 属性
                    value_attr = card.get('value', '')

                    if value_attr.startswith('data:'):
                        # 去掉 "data:" 前缀
                        encoded_data = value_attr[5:]

                        # URL解码
                        decoded_data = unquote(encoded_data)

                        # 解析JSON
                        data = json.loads(decoded_data)

                        # 提取代码和语言
                        code_text = data.get('code', '')
                        lang = data.get('mode', '')

                        # 处理转义字符
                        code_text = code_text.replace('\\n', '\n')
                        code_text = code_text.replace('\\"', '"')
                        code_text = code_text.replace('\\\\', '\\')

                        print(f"    Card代码块 {idx+1}: 语言={lang if lang else '未指定'}, {len(code_text.split(chr(10)))} 行")

                        # 创建新的 pre > code 结构
                        new_pre = soup.new_tag('pre')
                        new_code = soup.new_tag('code')
                        if lang:
                            new_code['class'] = f'language-{lang}'
                        new_code.string = code_text
                        new_pre.append(new_code)

                        # 替换整个 card 标签
                        card.replace_with(new_pre)
                        card_count += 1

                except Exception as e:
                    print(f"    ⚠️  Card代码块 {idx+1} 处理失败: {e}")

        # 格式2: CodeMirror 动态渲染格式 <div class="cm-scroller">
        cm_scrollers = soup.select('div.cm-scroller')
        cm_count = 0

        if cm_scrollers:
            print(f"  ✓ 发现 {len(cm_scrollers)} 个 CodeMirror 格式代码块")

            for idx, scroller in enumerate(cm_scrollers):
                try:
                    # 先移除所有行号和UI元素
                    ui_elements_to_remove = [
                        'div.cm-gutters',
                        'div.cm-gutter',
                        'div.cm-lineNumbers',
                        'div.cm-foldGutter',
                        'div.cm-cursorLayer',
                        'div.cm-selectionLayer',
                        'div.gutter-fold-close',
                        'div.gutter-fold-open'
                    ]

                    for selector in ui_elements_to_remove:
                        for elem in scroller.select(selector):
                            elem.decompose()

                    # 查找代码内容容器
                    cm_content = scroller.find('div', class_='cm-content')
                    if cm_content:
                        # 提取语言信息
                        lang = cm_content.get('data-language', '')

                        # 提取所有代码行
                        code_lines = []
                        cm_lines = cm_content.select('div.cm-line')

                        for line in cm_lines:
                            # 检查是否是空行（只包含 <br>）
                            if line.find('br') and not line.get_text().strip():
                                code_lines.append('')
                            else:
                                # 获取行的文本内容，保留空格
                                line_text = line.get_text()
                                code_lines.append(line_text)

                        code_text = '\n'.join(code_lines)
                        print(f"    CodeMirror代码块 {idx+1}: 语言={lang if lang else '未指定'}, {len(code_lines)} 行")

                        # 创建新的 pre > code 结构
                        new_pre = soup.new_tag('pre')
                        new_code = soup.new_tag('code')
                        if lang:
                            new_code['class'] = f'language-{lang}'
                        new_code.string = code_text
                        new_pre.append(new_code)

                        # 替换整个 cm-scroller
                        scroller.replace_with(new_pre)
                        cm_count += 1
                    else:
                        print(f"    ⚠️  CodeMirror代码块 {idx+1}: 未找到 cm-content")

                except Exception as e:
                    print(f"    ⚠️  CodeMirror代码块 {idx+1} 处理失败: {e}")

        if card_count + cm_count > 0:
            print(f"  ✓ 代码块替换完成（Card: {card_count}, CodeMirror: {cm_count}）")

        # 清理不需要的元素
        unwanted_selectors = [
            'div.comment-section', 'div.comments', 'div.like-button',
            'div.share-button', 'div.social-share', 'div.article-action',
            'div.author-info', 'div.related-articles', 'div.ad',
            'div.advertisement', 'script', 'style', 'nav', 'footer', 'header'
        ]

        for selector in unwanted_selectors:
            for element in article_content.select(selector):
                element.decompose()

        # 获取所有图片
        img_tags = article_content.find_all("img")

        # 创建目录
        images_dir = os.path.join(save_dir, "images")
        pdf_dir = os.path.join(save_dir, "pdf")
        os.makedirs(images_dir, exist_ok=True)
        os.makedirs(pdf_dir, exist_ok=True)

        # 下载图片
        for img_tag in img_tags:
            img_url = img_tag.get("src")
            if img_url and img_url.startswith("http"):
                try:
                    img_name = os.path.basename(img_url.split('?')[0])
                    img_path = os.path.join(images_dir, img_name)

                    if not os.path.exists(img_path):
                        img_data = requests.get(img_url, headers=headers, timeout=10).content
                        with open(img_path, "wb") as f:
                            f.write(img_data)
                except Exception as e:
                    print(f"  ✗ 图片下载失败 {img_url}: {e}")

        # 转换为Markdown
        md_content = markdownify.markdownify(str(article_content), heading_style="ATX")

        # 替换图片路径
        for img_tag in img_tags:
            img_url = img_tag.get("src")
            if img_url and img_url.startswith("http"):
                img_name = os.path.basename(img_url.split('?')[0])
                md_content = md_content.replace(img_url, f"images/{img_name}")

        # 清理 Markdown 内容
        lines = md_content.split('\n')
        cleaned_lines = []
        empty_line_count = 0

        for line in lines:
            if line.strip():
                cleaned_lines.append(line)
                empty_line_count = 0
            else:
                empty_line_count += 1
                if empty_line_count <= 2:
                    cleaned_lines.append(line)

        md_content = '\n'.join(cleaned_lines).strip()

        # 保存Markdown文件
        safe_filename = filename_filter(title_text)
        os.makedirs(save_dir, exist_ok=True)
        md_filename = os.path.join(save_dir, f"{article_id}-{safe_filename}.md")

        final_content = f"""# {title_text}

> **来源**: {url}  
> **文章ID**: {article_id}

---

{md_content}
"""

        with open(md_filename, "w", encoding="utf-8") as f:
            f.write(final_content)
        print(f"✓ Markdown已保存: {md_filename}")

        # 根据输出格式决定是否生成PDF和HTML
        if output_format in ["md+pdf", "all"]:
            pdf_filename = os.path.join(pdf_dir, f"{article_id}-{safe_filename}.pdf")
            keep_html = (output_format == "all")
            # 这里假定你已有 markdown_to_pdf 函数
            markdown_to_pdf(md_content, pdf_filename, title_text, keep_html=keep_html)
        elif output_format == "md":
            print(f"ℹ️  仅生成Markdown（跳过PDF/HTML）")

        return True

    except Exception as e:
        print(f"✗ 爬取失败: {e}")
        return False

if __name__ == '__main__':
    # 解析命令行参数
    parser = argparse.ArgumentParser(
        description='先知社区文章批量爬虫 & PDF转换工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
输出格式说明:
  md        - 仅生成Markdown文件
  md+pdf    - 生成Markdown和PDF（删除临时HTML）
  all       - 生成Markdown、PDF和HTML（保留所有文件）

使用示例:
  python crawl_xz_aliyun.py --start 9450 --end 9455 --format md
  python crawl_xz_aliyun.py --type t --start 10000 --end 10010 --format md+pdf
  python crawl_xz_aliyun.py --format all
        '''
    )
    
    parser.add_argument('--type', type=str, default='news', choices=['news', 't'],
                        help='文章类型: news 或 t (默认: news)')
    parser.add_argument('--start', type=int, default=9450,
                        help='起始文章ID (默认: 9450)')
    parser.add_argument('--end', type=int, default=9455,
                        help='结束文章ID (默认: 9455)')
    parser.add_argument('--format', type=str, default='all', 
                        choices=['md', 'md+pdf', 'all'],
                        help='输出格式 (默认: all)')
    parser.add_argument('--sleep', type=int, default=5,
                        help='请求间隔时间（秒）(默认: 5)')
    parser.add_argument('--dir', type=str, default='./xianzhi',
                        help='保存目录 (默认: ./xianzhi)')
    
    args = parser.parse_args()
    
    # 配置参数
    URL_TYPE = args.type
    START_ID = args.start
    END_ID = args.end
    OUTPUT_FORMAT = args.format
    SAVE_DIR = args.dir
    SLEEP_TIME = args.sleep
    
    print("="*60)
    print("先知社区文章批量爬虫工具")
    print(f"Version: {__version__} | Date: {__date__}")
    print("="*60)
    print(f"文章类型: {URL_TYPE}")
    print(f"文章范围: {START_ID} - {END_ID}")
    print(f"输出格式: {OUTPUT_FORMAT}")
    print(f"保存目录: {SAVE_DIR}")
    print(f"请求间隔: {SLEEP_TIME}秒")
    print("="*60)
    
    # 初始化浏览器 - ChromeDriver 保存到当前目录
    chrome_options = webdriver.ChromeOptions()
    
    # 基础选项
    chrome_options.add_argument('--headless')  # 无头模式
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')
    
    # 禁用GPU相关（避免GPU错误信息）
    chrome_options.add_argument('--disable-gpu')
    chrome_options.add_argument('--disable-software-rasterizer')
    chrome_options.add_argument('--disable-webgl')
    chrome_options.add_argument('--disable-webgl2')
    
    # 日志和错误信息控制
    chrome_options.add_argument('--log-level=3')  # 只显示严重错误
    chrome_options.add_argument('--silent')
    chrome_options.add_argument('--disable-logging')
    chrome_options.add_argument('--ignore-certificate-errors')
    
    # 禁用DevTools消息
    chrome_options.add_argument('--remote-debugging-port=0')
    
    # 禁用其他可能产生警告的功能
    chrome_options.add_argument('--disable-extensions')
    chrome_options.add_argument('--disable-popup-blocking')
    chrome_options.add_argument('--disable-infobars')
    
    # 实验性选项：完全禁用日志
    chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
    chrome_options.add_experimental_option('useAutomationExtension', False)
    
    # 检查当前目录是否已有 chromedriver
    current_dir = os.path.dirname(os.path.abspath(__file__))
    chromedriver_path = os.path.join(current_dir, "chromedriver.exe")
    
    # 创建Service对象，禁用日志输出
    service_args = ['--silent', '--log-path=NUL']
    
    if os.path.exists(chromedriver_path):
        print(f"✓ 使用本地 ChromeDriver: {chromedriver_path}")
        service = Service(chromedriver_path, service_args=service_args)
        
        # 重定向stderr来彻底禁用DevTools消息
        service.creationflags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        
        driver = webdriver.Chrome(service=service, options=chrome_options)
    else:
        print("正在下载匹配版本的 ChromeDriver（仅首次需要）...")
        # 使用 webdriver_manager 下载驱动
        downloaded_path = ChromeDriverManager().install()
        print(f"✓ ChromeDriver 已下载")
        
        # 复制到当前目录，方便下次使用
        try:
            shutil.copy2(downloaded_path, chromedriver_path)
            print(f"✓ ChromeDriver 已保存到: {chromedriver_path}")
            print(f"   下次运行将直接使用本地驱动，无需重新下载")
            service = Service(chromedriver_path, service_args=service_args)
            service.creationflags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            driver = webdriver.Chrome(service=service, options=chrome_options)
        except Exception as e:
            print(f"⚠️  无法复制驱动文件到当前目录: {e}")
            print(f"   将使用缓存位置的驱动: {downloaded_path}")
            service = Service(downloaded_path, service_args=service_args)
            service.creationflags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            driver = webdriver.Chrome(service=service, options=chrome_options)
    
    success_count = 0
    fail_count = 0
    
    try:
        for i in range(START_ID, END_ID + 1):
            article_id = str(i)
            url = f"https://xz.aliyun.com/{URL_TYPE}/{article_id}"
            
            if crawl_article(driver, url, article_id, URL_TYPE, SAVE_DIR, OUTPUT_FORMAT):
                success_count += 1
            else:
                fail_count += 1
            
            time.sleep(SLEEP_TIME)
            
    finally:
        driver.quit()
        print("\n" + "="*60)
        print(f"爬取完成！成功: {success_count} 篇，失败: {fail_count} 篇")
        print("="*60)
