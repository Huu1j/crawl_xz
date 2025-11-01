#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
生成文章索引
自动扫描已爬取的文章并生成索引页面
"""

import os
import re
from datetime import datetime
from pathlib import Path

def extract_article_info(md_file):
    """从Markdown文件中提取文章信息"""
    try:
        with open(md_file, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # 提取标题
        title_match = re.search(r'^# (.+)$', content, re.MULTILINE)
        title = title_match.group(1) if title_match else "未知标题"
        
        # 提取来源
        source_match = re.search(r'> \*\*来源\*\*: (.+)$', content, re.MULTILINE)
        source = source_match.group(1) if source_match else ""
        
        # 提取文章ID
        id_match = re.search(r'> \*\*文章ID\*\*: (.+)$', content, re.MULTILINE)
        article_id = id_match.group(1) if id_match else ""
        
        # 文件大小
        file_size = os.path.getsize(md_file)
        size_kb = file_size / 1024
        
        return {
            'title': title,
            'source': source,
            'id': article_id,
            'size': f"{size_kb:.1f} KB",
            'file': str(md_file)
        }
    except Exception as e:
        print(f"处理文件失败 {md_file}: {e}")
        return None

def generate_index():
    """生成文章索引"""
    
    # 扫描先知社区文章
    xianzhi_articles = []
    xianzhi_dir = Path('xianzhi')
    if xianzhi_dir.exists():
        for md_file in xianzhi_dir.glob('*.md'):
            info = extract_article_info(md_file)
            if info:
                xianzhi_articles.append(info)
    
    # 扫描奇安信攻防社区文章
    butian_articles = []
    butian_dir = Path('butian')
    if butian_dir.exists():
        for md_file in butian_dir.glob('*.md'):
            info = extract_article_info(md_file)
            if info:
                butian_articles.append(info)
    
    # 按ID排序
    xianzhi_articles.sort(key=lambda x: x['id'])
    butian_articles.sort(key=lambda x: x['id'])
    
    # 生成索引页面
    index_content = f"""# 安全社区文章索引

> 📚 自动爬取的安全技术文章集合  
> 🤖 最后更新: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## 📊 统计信息

- **先知社区**: {len(xianzhi_articles)} 篇文章
- **奇安信攻防社区**: {len(butian_articles)} 篇文章
- **总计**: {len(xianzhi_articles) + len(butian_articles)} 篇文章

---

## 📖 先知社区文章 ({len(xianzhi_articles)} 篇)

| ID | 标题 | 大小 | 链接 |
|-----|------|------|------|
"""
    
    for article in xianzhi_articles:
        file_path = article['file'].replace('\\', '/')
        index_content += f"| {article['id']} | {article['title']} | {article['size']} | [📄]({file_path}) [🔗]({article['source']}) |\n"
    
    index_content += f"""
---

## 🛡️ 奇安信攻防社区文章 ({len(butian_articles)} 篇)

| ID | 标题 | 大小 | 链接 |
|-----|------|------|------|
"""
    
    for article in butian_articles:
        file_path = article['file'].replace('\\', '/')
        index_content += f"| {article['id']} | {article['title']} | {article['size']} | [📄]({file_path}) [🔗]({article['source']}) |\n"
    
    index_content += """
---

## 🚀 使用说明

### 本地运行爬虫

```bash
# 安装依赖
pip install -r requirements.txt

# 爬取先知社区文章
python crawl_xz_aliyun.py --start 18000 --end 18010 --format md

# 爬取奇安信攻防社区文章
python crawl_butian_forum.py --start 2400 --end 2410 --format md
```

### GitHub Actions自动爬取

本仓库已配置GitHub Actions，会自动：
- 每天定时爬取新文章
- 自动提交到仓库
- 更新本索引文件

手动触发：前往 [Actions](../../actions) 页面，选择 "自动爬取安全社区文章" 工作流，点击 "Run workflow"。

---

## 📝 说明

- 所有文章仅供学习研究使用
- 文章版权归原作者所有
- 请遵守相关网站的使用条款
"""
    
    # 保存索引文件
    with open('ARTICLES.md', 'w', encoding='utf-8') as f:
        f.write(index_content)
    
    print(f"✓ 索引已生成: {len(xianzhi_articles) + len(butian_articles)} 篇文章")

if __name__ == '__main__':
    generate_index()

