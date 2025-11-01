#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
奇安信攻防社区文章批量爬虫

Version: 1.0
Date: 2025-11-01
Author: AI Assistant
Description: 批量爬取奇安信攻防社区文章，支持Markdown、PDF、HTML多种格式输出
"""

import time
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from bs4 import BeautifulSoup
import os
import shutil
import subprocess
import requests
import pdfkit
import argparse
import re
from html import unescape

__version__ = '1.0'
__author__ = 'AI Assistant'
__date__ = '2025-11-01'

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
    html_path = output_path.replace('.pdf', '.html')
    
    try:
        import markdown
        
        # 转换Markdown为HTML
        html_content = markdown.markdown(
            md_content, 
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
    <h1>{title}</h1>
    {html_content}
</body>
</html>"""
        
        # 保存HTML文件
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(styled_html)
        
        # 转换为PDF
        try:
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
                
                print(f"✓ HTML: {html_path} (可在浏览器中打开后打印为PDF)")
                return False
                
        except ImportError:
            print(f"⚠️  pdfkit 未安装，跳过PDF生成")
            print(f"✓ HTML: {html_path}")
            return False
            
    except Exception as e:
        print(f"✗ PDF处理失败: {e}")
        return False

def crawl_article(driver, url, article_id, save_dir="./butian", output_format="md", fast_mode=False):
    """爬取单篇文章

    Args:
        driver: Selenium WebDriver
        url: 文章URL
        article_id: 文章ID
        save_dir: 保存目录
        output_format: 输出格式 ("md"=仅MD, "md+pdf"=MD和PDF, "all"=MD+PDF+HTML)
    """
    try:
        print(f"\n正在爬取: {url}")
        driver.get(url)
        wait_time = 0.3 if fast_mode else 1
        time.sleep(wait_time)

        # 检查是否被重定向
        current_url = driver.current_url
        if '/community/' not in current_url and '/share/' not in current_url:
            print(f"✗ 文章不存在（重定向到: {current_url}）")
            return False

        headers = {
            "Referer": "https://forum.butian.net/"
        }

        html_content = driver.page_source
        soup = BeautifulSoup(html_content, "html.parser")

        # 获取标题
        title_tag = soup.find('h3', class_='title')
        if not title_tag:
            title_tag = soup.find('title')
        
        title_text = title_tag.text.strip() if title_tag else None

        if not title_text or '404' in title_text or '400' in title_text or '403' in title_text:
            print(f"✗ 文章不存在或无法访问")
            return False

        # 清理标题
        title_text = title_text.replace('奇安信攻防社区-', '').strip()
        print(f"标题: {title_text}")

        # 提取Markdown内容（存储在textarea中）
        md_textarea = soup.find('textarea', id='md_view_content')
        
        if not md_textarea:
            print("✗ 无法找到文章内容")
            return False

        # 获取Markdown原始内容并解码HTML实体
        md_content = md_textarea.text
        md_content = unescape(md_content)  # 解码 &gt; 等HTML实体
        
        print(f"✓ 提取Markdown内容 ({len(md_content)} 字符)")

        # 下载图片
        img_urls = re.findall(r'!\[.*?\]\((https?://[^\)]+)\)', md_content)
        
        if img_urls:
            images_dir = os.path.join(save_dir, "images")
            os.makedirs(images_dir, exist_ok=True)
            
            downloaded_count = 0
            for img_url in img_urls:
                try:
                    img_name = os.path.basename(img_url.split('?')[0])
                    # 如果URL没有扩展名，尝试从Content-Type获取
                    if '.' not in img_name:
                        img_name = img_name + '.png'
                    
                    img_path = os.path.join(images_dir, img_name)

                    if not os.path.exists(img_path):
                        img_data = requests.get(img_url, headers=headers, timeout=10).content
                        with open(img_path, "wb") as f:
                            f.write(img_data)
                        downloaded_count += 1
                    
                    # 替换Markdown中的图片路径
                    md_content = md_content.replace(img_url, f"images/{img_name}")
                    
                except Exception as e:
                    print(f"  ⚠️  图片下载失败: {e}")
            
            if downloaded_count > 0:
                print(f"✓ 下载了 {downloaded_count} 张图片")

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
            pdf_dir = os.path.join(save_dir, "pdf")
            os.makedirs(pdf_dir, exist_ok=True)
            
            pdf_filename = os.path.join(pdf_dir, f"{article_id}-{safe_filename}.pdf")
            keep_html = (output_format == "all")
            
            pdf_md_content = md_content.replace('images/', '../images/')
            
            pdf_md_content = f"""**来源：** {url}  
**文章ID：** {article_id}

---

{pdf_md_content}
"""
            
            markdown_to_pdf(pdf_md_content, pdf_filename, title_text, keep_html=keep_html)

        return True

    except Exception as e:
        print(f"✗ 爬取失败: {e}")
        return False

if __name__ == '__main__':
    # 解析命令行参数
    parser = argparse.ArgumentParser(
        description='奇安信攻防社区文章批量爬虫 & PDF转换工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
输出格式说明:
  md        - 仅生成Markdown文件
  md+pdf    - 生成Markdown和PDF（删除临时HTML）
  all       - 生成Markdown、PDF和HTML（保留所有文件）

使用示例:
  python crawl_butian_forum.py --start 2400 --end 2405 --format md
  python crawl_butian_forum.py --type share --start 1000 --end 1010 --format md+pdf
  python crawl_butian_forum.py --format all
        '''
    )
    
    parser.add_argument('--type', type=str, default='share', choices=['community', 'share'],
                        help='文章类型: community(实战攻防) 或 share(技术分享) (默认: share)')
    parser.add_argument('--start', type=int, default=2400,
                        help='起始文章ID (默认: 2400)')
    parser.add_argument('--end', type=int, default=2405,
                        help='结束文章ID (默认: 2405)')
    parser.add_argument('--format', type=str, default='all', 
                        choices=['md', 'md+pdf', 'all'],
                        help='输出格式 (默认: all)')
    parser.add_argument('--sleep', type=int, default=1,
                        help='请求间隔时间（秒）(默认: 1)')
    parser.add_argument('--dir', type=str, default='./butian',
                        help='保存目录 (默认: ./butian)')
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
    FAST_MODE = args.fast
    
    # 极速模式：覆盖sleep时间
    if FAST_MODE:
        SLEEP_TIME = 0.3
        print("⚡ 极速模式已启用")
    
    print("="*60)
    print("奇安信攻防社区文章批量爬虫工具")
    print(f"Version: {__version__} | Date: {__date__}")
    print("="*60)
    print(f"文章类型: {URL_TYPE}")
    print(f"文章范围: {START_ID} - {END_ID}")
    print(f"输出格式: {OUTPUT_FORMAT}")
    print(f"保存目录: {SAVE_DIR}")
    print(f"请求间隔: {SLEEP_TIME}秒")
    print("="*60)
    
    # 初始化浏览器
    chrome_options = webdriver.ChromeOptions()
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')
    chrome_options.add_argument('--disable-gpu')
    chrome_options.add_argument('--log-level=3')
    chrome_options.add_argument('--silent')
    chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
    
    # 检查当前目录是否已有 chromedriver
    current_dir = os.path.dirname(os.path.abspath(__file__))
    chromedriver_name = "chromedriver.exe" if os.name == 'nt' else "chromedriver"
    chromedriver_path = os.path.join(current_dir, chromedriver_name)
    
    service_args = ['--silent', '--log-path=/dev/null'] if os.name != 'nt' else ['--silent', '--log-path=NUL']
    
    # 在Linux环境下（如GitHub Actions），始终使用webdriver-manager
    if os.name != 'nt' or not os.path.exists(chromedriver_path):
        print("正在下载匹配版本的 ChromeDriver（仅首次需要）...")
        from webdriver_manager.chrome import ChromeDriverManager
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
            url = f"https://forum.butian.net/{URL_TYPE}/{article_id}"
            
            if crawl_article(driver, url, article_id, SAVE_DIR, OUTPUT_FORMAT, FAST_MODE):
                success_count += 1
            else:
                fail_count += 1
            
            time.sleep(SLEEP_TIME)
            
    finally:
        driver.quit()
        print("\n" + "="*60)
        print(f"爬取完成！成功: {success_count} 篇，失败: {fail_count} 篇")
        print("="*60)

