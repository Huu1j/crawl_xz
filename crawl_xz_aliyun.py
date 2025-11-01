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

def html_to_pdf(html_content, output_path, title="", keep_html=True):
    """直接将HTML内容转换为PDF（更好地保留原始格式）
    
    Args:
        html_content: 原始HTML内容（BeautifulSoup对象或字符串）
        output_path: PDF输出路径
        title: 文章标题
        keep_html: 是否保留HTML文件（True=保留，False=仅作为临时文件）
    """
    html_path = output_path.replace('.pdf', '.html')
    
    try:
        
        if hasattr(html_content, 'prettify'):
            html_str = str(html_content)
        else:
            html_str = html_content
        
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
            max-width: 900px;
            margin: 20px auto;
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
            font-size: 28px;
        }}
        h2 {{
            border-bottom: 1px solid #e1e4e8;
            padding-bottom: 8px;
        }}
        code {{
            background-color: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: "Consolas", "Monaco", "Courier New", monospace;
            font-size: 13px;
        }}
        pre {{
            background-color: #f6f8fa;
            padding: 16px;
            border-radius: 6px;
            overflow-x: auto;
            border: 1px solid #e1e4e8;
        }}
        pre code {{
            background-color: transparent;
            padding: 0;
            font-size: 13px;
            line-height: 1.45;
        }}
        img {{
            max-width: 100%;
            height: auto;
            display: block;
            margin: 16px 0;
        }}
        blockquote {{
            border-left: 4px solid #3498db;
            padding-left: 16px;
            margin-left: 0;
            color: #666;
            background-color: #f9f9f9;
            padding: 10px 16px;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
            margin: 16px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px 12px;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
            font-weight: bold;
        }}
        a {{
            color: #0366d6;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
        .article-meta {{
            color: #666;
            font-size: 14px;
            margin-bottom: 20px;
            padding: 10px;
            background-color: #f6f8fa;
            border-radius: 4px;
        }}
    </style>
</head>
<body>
    {html_str}
</body>
</html>"""
        
        # 保存HTML文件
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(styled_html)
        
        # 转换为PDF
        try:
            # 配置pdfkit选项
            options = {
                'encoding': 'UTF-8',
                'enable-local-file-access': None,
                'quiet': '',
                'page-size': 'A4',
                'margin-top': '15mm',
                'margin-right': '15mm',
                'margin-bottom': '15mm',
                'margin-left': '15mm',
                'no-outline': None,
                'print-media-type': None,
            }
            
            # 配置 pdfkit
            config = None
            current_script_dir = os.path.dirname(os.path.abspath(__file__))
            wkhtmltopdf_path = os.path.join(current_script_dir, "wkhtmltox", "wkhtmltopdf.exe")
            
            if os.path.exists(wkhtmltopdf_path):
                config = pdfkit.configuration(wkhtmltopdf=wkhtmltopdf_path)
            else:
                print(f"⚠️  未找到 wkhtmltopdf，将尝试使用系统路径")
            
            # 从HTML文件转换为PDF
            try:
                if config:
                    pdfkit.from_file(html_path, output_path, options=options, configuration=config)
                else:
                    pdfkit.from_file(html_path, output_path, options=options)
                
                print(f"✓ PDF: {output_path}")
                
                # 根据参数决定是否保留HTML
                if keep_html:
                    print(f"✓ HTML: {html_path}")
                else:
                    try:
                        os.remove(html_path)
                    except:
                        pass
                
                return True
                
            except (OSError, IOError) as e:
                error_msg = str(e)
                if 'wkhtmltopdf' in error_msg.lower() or 'no such file' in error_msg.lower():
                    print(f"⚠️  需要安装 wkhtmltopdf 才能生成PDF")
                    print(f"   下载地址: https://wkhtmltopdf.org/downloads.html")
                else:
                    print(f"⚠️  PDF生成失败: {error_msg}")
                
                print(f"✓ HTML已保存: {html_path} (可在浏览器中打开后打印为PDF)")
                return False
                
        except ImportError:
            print(f"⚠️  pdfkit 未安装，跳过PDF生成")
            print(f"✓ HTML已保存: {html_path}")
            return False
            
    except Exception as e:
        print(f"✗ PDF处理失败: {e}")
        return False

def crawl_article(driver, url, article_id, url_type="t", save_dir="./xianzhi", output_format="md", debug_mode=False, fast_mode=False):
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
        wait_time = 0.5 if fast_mode else 2
        time.sleep(wait_time)

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
        
        # 先从完整页面源码中提取标题（因为后续可能只使用JavaScript片段）
        full_soup = BeautifulSoup(html_content, "html.parser")
        title_tag = full_soup.find('title')
        title_text = title_tag.text if title_tag else None
        
        if not title_text or '400 -' in title_text or '404' in title_text:
            print(f"✗ 文章不存在或无法访问")
            return False
        
        # 清理标题
        title_text = title_text.replace(' - 先知社区', '').strip()
        print(f"标题: {title_text}")
        
        # 调试模式：保存完整页面源码
        if debug_mode:
            debug_dir = os.path.join(save_dir, "debug")
            os.makedirs(debug_dir, exist_ok=True)
            debug_html_path = os.path.join(debug_dir, f"{article_id}-raw-source.html")
            with open(debug_html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"  [调试] 已保存完整页面源码: {debug_html_path}")
        
        
        article_html_from_js = None
        makeview_match = re.search(r"makeView\('markdown-body',\s*\"(.+?)\"\s*\)", html_content, re.DOTALL)
        
        if makeview_match:
            # 提取并解码JavaScript字符串
            js_string = makeview_match.group(1)
            
            # 解码JavaScript字符串转义
            decoded_html = js_string.replace('\\n', '\n')
            decoded_html = decoded_html.replace('\\/', '/')
            decoded_html = decoded_html.replace('\\"', '"')
            decoded_html = decoded_html.replace('\\\\', '\\')
            decoded_html = decoded_html.replace('\\t', '\t')
            decoded_html = decoded_html.replace('\\r', '\r')
            
            # 处理Unicode转义（如 \u90a6）
            try:
                import codecs
                decoded_html = codecs.decode(decoded_html, 'unicode_escape')
            except:
                pass
            
            article_html_from_js = decoded_html
            print(f"✓ 从makeView提取文章内容 ({len(decoded_html)} 字符)")
            
            # 调试模式：保存解码后的HTML
            if debug_mode:
                decoded_html_path = os.path.join(debug_dir, f"{article_id}-decoded-from-js.html")
                with open(decoded_html_path, 'w', encoding='utf-8') as f:
                    f.write(decoded_html)
                print(f"  [调试] 已保存解码后的HTML: {decoded_html_path}")
        
        # 如果从JavaScript中提取到了内容，使用它；否则使用常规方式
        if article_html_from_js:
            soup = BeautifulSoup(article_html_from_js, "html.parser")
        else:
            soup = BeautifulSoup(html_content, "html.parser")

        # 提取文章正文
        if article_html_from_js:
            # 从JavaScript提取的内容，查找app div或使用整个内容
            app_div = soup.find('div', id='app')
            article_content = app_div if app_div else soup
        else:
            # 常规方式：从完整页面中查找
            article_content = (
                soup.find('div', id='markdown-body') or
                soup.find('div', class_='markdown-body') or
                soup.find('div', class_='article-content') or
                soup.find('div', class_='content-detail')
            )
            if not article_content:
                print("✗ 无法找到文章内容")
                return False

        # 处理代码块Card标签：<card name="codeblock" value="data:...">
        code_cards = article_content.find_all('card', {'name': 'codeblock'})
        card_count = 0

        if code_cards:
            for idx, card in enumerate(code_cards):
                try:
                    value_attr = card.get('value', '')
                    
                    if not value_attr or not value_attr.startswith('data:'):
                        continue

                    # 去掉 "data:" 前缀并解码
                    encoded_data = value_attr[5:]
                    decoded_data = unquote(encoded_data)
                    data = json.loads(decoded_data)

                    # 提取代码和语言
                    code_text = data.get('code', '')
                    lang = data.get('mode', '')

                    # 处理转义字符
                    code_text = code_text.replace('\\n', '\n')
                    code_text = code_text.replace('\\"', '"')
                    code_text = code_text.replace('\\\\', '\\')

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
                    print(f"  ⚠️  代码块 {idx+1} 处理失败: {e}")

        if card_count > 0:
            print(f"✓ 处理了 {card_count} 个代码块")

        # 处理图片Card标签：<card name="image" value="data:...">
        image_cards = article_content.find_all('card', {'name': 'image'})
        image_count = 0
        
        if image_cards:
            for idx, card in enumerate(image_cards):
                try:
                    value_attr = card.get('value', '')
                    
                    if not value_attr or not value_attr.startswith('data:'):
                        continue
                    
                    # 去掉 "data:" 前缀并解码
                    encoded_data = value_attr[5:]
                    decoded_data = unquote(encoded_data)
                    data = json.loads(decoded_data)
                    
                    # 提取图片信息
                    img_src = data.get('src', '')
                    img_name = data.get('name', '')
                    img_width = data.get('originWidth', '')
                    
                    if img_src:
                        # 创建新的 img 标签
                        new_img = soup.new_tag('img')
                        new_img['src'] = img_src
                        if img_name:
                            new_img['alt'] = img_name
                        if img_width:
                            new_img['width'] = str(img_width)
                        
                        # 替换整个 card 标签
                        card.replace_with(new_img)
                        image_count += 1
                        
                except Exception as e:
                    print(f"  ⚠️  图片 {idx+1} 处理失败: {e}")
            
            if image_count > 0:
                print(f"✓ 处理了 {image_count} 张图片")

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

        # 下载图片并替换HTML中的路径
        downloaded_count = 0
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
                        downloaded_count += 1
                    
                    # 更新HTML中的图片路径（用于PDF生成）
                    img_tag['src'] = f"images/{img_name}"
                    
                except Exception as e:
                    print(f"  ⚠️  图片下载失败: {e}")
        
        if downloaded_count > 0:
            print(f"✓ 下载了 {downloaded_count} 张图片")

        # 转换为Markdown
        md_content = markdownify.markdownify(str(article_content), heading_style="ATX")

        # Markdown中的图片路径已经通过上面的HTML修改自动更新了
        # 不需要再单独替换

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
        print(f"✓ Markdown: {md_filename}")

        # 根据输出格式决定是否生成PDF和HTML
        if output_format in ["md+pdf", "all"]:
            pdf_filename = os.path.join(pdf_dir, f"{article_id}-{safe_filename}.pdf")
            keep_html = (output_format == "all")
            
            # 复制article_content用于PDF生成（避免修改原始内容）
            article_content_for_pdf = BeautifulSoup(str(article_content), "html.parser")
            
            # 修正图片路径：PDF在pdf/目录，图片在images/目录，需要使用 ../images/
            for img in article_content_for_pdf.find_all('img'):
                src = img.get('src', '')
                if src and src.startswith('images/'):
                    img['src'] = '../' + src
            
            # 准备用于PDF的HTML内容（包含标题和元信息）
            article_html_for_pdf = f"""
            <div class="article-meta">
                <strong>来源：</strong><a href="{url}">{url}</a><br>
                <strong>文章ID：</strong>{article_id}
            </div>
            <h1>{title_text}</h1>
            {str(article_content_for_pdf)}
            """
            
            # 直接从HTML生成PDF
            html_to_pdf(article_html_for_pdf, pdf_filename, title_text, keep_html=keep_html)

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
    parser.add_argument('--sleep', type=int, default=2,
                        help='请求间隔时间（秒）(默认: 2)')
    parser.add_argument('--dir', type=str, default='./xianzhi',
                        help='保存目录 (默认: ./xianzhi)')
    parser.add_argument('--debug', action='store_true',
                        help='调试模式：禁用无头模式，保存完整页面源码')
    parser.add_argument('--fast', action='store_true',
                        help='极速模式：最小等待时间（可能不稳定）')
    
    args = parser.parse_args()
    
    # 配置参数
    URL_TYPE = args.type
    START_ID = args.start
    END_ID = args.end
    OUTPUT_FORMAT = args.format
    SAVE_DIR = args.dir
    SLEEP_TIME = args.sleep
    DEBUG_MODE = args.debug
    FAST_MODE = args.fast
    
    # 极速模式：覆盖sleep时间
    if FAST_MODE:
        SLEEP_TIME = 0.5
        print("⚡ 极速模式已启用")
    
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
    if not DEBUG_MODE:
        chrome_options.add_argument('--headless')  # 无头模式（调试模式下禁用）
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
    chromedriver_name = "chromedriver.exe" if os.name == 'nt' else "chromedriver"
    chromedriver_path = os.path.join(current_dir, chromedriver_name)
    
    # 创建Service对象，禁用日志输出
    service_args = ['--silent', '--log-path=/dev/null'] if os.name != 'nt' else ['--silent', '--log-path=NUL']
    
    # 在Linux环境下（如GitHub Actions），始终使用webdriver-manager
    if os.name != 'nt' or not os.path.exists(chromedriver_path):
        print("正在下载匹配版本的 ChromeDriver（仅首次需要）...")
        # 使用 webdriver_manager 下载驱动
        downloaded_path = ChromeDriverManager().install()
        print(f"✓ ChromeDriver 已下载")
        
        service = Service(downloaded_path, service_args=service_args)
        if os.name == 'nt':
            service.creationflags = subprocess.CREATE_NO_WINDOW
        driver = webdriver.Chrome(service=service, options=chrome_options)
    else:
        print(f"✓ 使用本地 ChromeDriver: {chromedriver_path}")
        service = Service(chromedriver_path, service_args=service_args)
        service.creationflags = subprocess.CREATE_NO_WINDOW
        driver = webdriver.Chrome(service=service, options=chrome_options)
    
    success_count = 0
    fail_count = 0
    
    try:
        for i in range(START_ID, END_ID + 1):
            article_id = str(i)
            url = f"https://xz.aliyun.com/{URL_TYPE}/{article_id}"
            
            if crawl_article(driver, url, article_id, URL_TYPE, SAVE_DIR, OUTPUT_FORMAT, DEBUG_MODE, FAST_MODE):
                success_count += 1
            else:
                fail_count += 1
            
            time.sleep(SLEEP_TIME)
            
    finally:
        driver.quit()
        print("\n" + "="*60)
        print(f"爬取完成！成功: {success_count} 篇，失败: {fail_count} 篇")
        print("="*60)
