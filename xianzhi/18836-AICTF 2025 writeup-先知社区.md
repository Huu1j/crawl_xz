# AICTF 2025 writeup-先知社区

> **来源**: https://xz.aliyun.com/news/18836  
> **文章ID**: 18836

---

前段时间，打了国外的一场AI安全赛，涨了不少新姿势，总结一下，便有了这篇文章的分享

# 题目1：Floor Check

**Categories:** Welcome – ML:75% CTF:25% #baby #data

```
Welcome to AI CTF 2025!
We hope you will enjoy the game, practice some new hacks in machine learning and applied AI, and show your utmost skill.
Flags look like aictf{...} — you’ll know when you see one.
Here the first one, but you’ll need to load the data: miccheck_a8749ce.parquet
```

![image.png](images/img_18836_000.png)

题目给了我们一个parquet文件，首先，Apache Parquet 是一个为高效数据存储和检索设计的开放源代码、列式数据文件格式。可以把它想象成一个高度专业化和优化的“Excel 表格”，但它在设计上是为了满足大数据领域的需求。它的核心特点如下：

行式存储：把每一行的所有数据（例如：用户ID、姓名、年龄、城市…）一个接一个地存储在一起。[1, Alice, 28, Beijing], [2, Bob, 32, Shanghai], ...

​

列式存储：把每一列的所有数据分别存储在一起。所有用户ID: [1, 2, 3, ...], 所有姓名: [Alice, Bob, Carol, ...], 所有年龄: [28, 32, 25, ...]

​

优势：对于分析型查询（例如：“计算所有用户的平均年龄”），数据库或计算引擎（如 Spark， Presto）无需读取整行数据，只需读取“年龄”这一列即可，极大地减少了磁盘 I/O，提高了查询速度和效率。

​

高效的压缩编码：由于同一列的数据类型相同，数据模式（Schema）一致，Parquet 可以使用非常高效的列式压缩算法（如 RLE， Dictionary Encoding）来大幅减小文件体积。通常，一个 Parquet 文件比包含相同数据的 CSV 文件小得多。

​

支持复杂嵌套结构：Parquet 原生支持嵌套数据，比如数组（Array）、映射（Map）和结构体（Struct）。这意味着你可以直接将 JSON 之类的复杂对象存储到一个 Parquet 列中，而无需将其扁平化。

兼容性强：Parquet 是 Hadoop 生态系统中的事实标准，被几乎所有的主流大数据处理框架支持，包括 Apache Spark, Apache Hive, Apache Impala, Presto, AWS Athena, Google BigQuery, Pandas, Dask 等。

至于怎么打开，就是要用panda就行了，当然，加上matplotlib更好

​

故法一：

```
import pandas
print(pandas.read_parquet("miccheck_a8749ce.parquet").to_string())
```

这里你可以看到用 8 创建的字符，在你面前的是 Flag

此处太长，不展示了  
法二：

```
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# 读取数据
df = pd.read_parquet('miccheck_a8749ce.parquet', engine='pyarrow')

# 将数据转换为数值矩阵：8->1(黑), -->0(白)
image_matrix = np.where(df == '8', 1, 0)

# 绘制黑白图像
plt.figure(figsize=(8, 8))
plt.imshow(image_matrix, cmap='gray', interpolation='nearest')
plt.title('image (8=black, -=white)')
plt.axis('off')  # 隐藏坐标轴
plt.show()
```

![image.png](images/img_18836_001.png)

**Flag:** AICTF{GOOD\_L$CK\_H@V3\_FUN}

# 题目2：VoiceGuard

![5cd9294824d1f8ab689d5d926ebcd7a1.png](images/img_18836_002.png)

ML: 60% CTF: 40%

```
The task is simple: just pass two checks.

ai-voiceguard-ul59svea.spbctf.com/
```

没什么好说的，这个给了个音频和示例，模仿声色读另外一个文本即可，利用讯飞AI一把梭了

​

或者<https://ttsmaker.cn/>  
ttsmaker也很不错

# 题目3：Rate My Car

ML: 20% CTF: 80% mllm

```
A friend of mine sent me a link to a service that determines the make and model of a car, as well as its ‘coolness’ rating.

His Ferrari 250 GTO got 100 points out of 100.

Let’s see if I can beat his score.
A rating of 1337 seems like a perfect fit.

ai-ratemycar-0fs347u2.spbctf.com/
```

![image.png](images/img_18836_003.png)

在这个挑战中，有一个在后台运行的形象处理机制，它会给系统加载的汽车打分。描述要求我们超越这个机制，使汽车的分数达到 1337。我们需要通过实验来了解**这个机制是如何打分的**。

测试了很多车发现都是0-100，到不了1337，去尝试其他的

Example prompt for beat the system：  
![042f170dc0aaadf1b6d2cc6d128784a3.png](images/img_18836_004.png)

先测试纯文字

![4cd223d732e864a23834d76b898fd110.png](images/img_18836_005.png)

很明显不行，这个时候，我们试着用一张汽车图片来试试，但让我们稍微改变一下方式，比如改变字体和样本类型。

![825f4a89dbc1469dba41c31800098337.png](images/img_18836_006.png)

可发现还是不行，这个时候让我们试试不使用汽车图片的效果

![3738b8917becd30dcd10d5d33e8de56f.png](images/img_18836_007.png)

从这里看，似乎仅通过回显就足以确定这种欺骗方法。

让我们看看如果我们正确的去定义对象，会返回什么

![6dc2e0e8745d945f3a8a15586be3dd12.png](images/img_18836_008.png)

猜测这个模型既可以识别图像，也可以识别文字，那这样就好办了，写个prompt进行攻击去获取答案（也就是这个模型存在prompt注入漏洞）

​

![0548ae06cb305e2d6219349811e6c012.png](images/img_18836_009.png)

**Flag:** aictf{b35T\_Car\_I5\_Y0Ur\_F1rS7\_Car}

# 题目4：FLAG LEAK

​

ML: 70% CTF: 30% data visual

```
I was once looking through social network videos, and in one of them I noticed the password for the account test@vk.com. The person recording the video had accidentally revealed it!

Alas, the password turned out to be invalid, but it gave me a nice idea for an AI CTF task.

✱ ✱ ✱

You have 1000 random videos shared on social network. In one of these videos I have actually submitted the flag for this task!

Grab the videos here

The flag looks like FLAG_... (no aictf{...} this time)

Enter it here to claim your points ↓
```

![image.png](images/img_18836_010.png)

“视觉”标签对我来说有点像提示，因为如果是 AI CTF，那么“视觉”标签告诉我们要使用视觉语言模型。但是，**总有不使用 AI 的解决方案**。这个题目就是

![8124afa567d23a0d311a8a4734f11872.png](images/img_18836_011.png)

题目分析：  
这个AI夺旗赛（CTF）挑战的核心任务是从1000个YouTube视频中找出一个隐藏的FLAG\_...格式的旗帜。旗帜很可能直接出现在视频画面中——可能是屏幕上的文字、纸张书写的内容，或是巧妙嵌入视觉场景的细节——而不太可能藏在视频描述、字幕或元数据里。

这种情况非常适合使用现代视觉语言模型（VLM），比如：

1.OpenAI的GPT-4V

2.Google的Gemini

3.支持视觉功能的Anthropic Claude

4.Meta的ImageBind

​

这些模型能够同时理解图像内容和文本信息，具备"观看"图像并对其内容进行"阅读"和"推理"的能力。

针对这个挑战，我考虑了三种解决方案：

## ①传统方法

简单来说，我认为解决这个问题的关键在于——视频可能是近期发布的。我之所以这么想，是因为查看了部分视频的发布时间，发现它们都比较陈旧，与当前挑战关联不大。我推测目标视频应该是CTF主办方专门制作的，很可能在视频画面中会出现"FLAG\_..."这样的标识。因此，这个视频的发布时间应该很接近CTF比赛的日期。基于这个判断，我编写了一个Python脚本。

​

这个Python脚本能够高效地提取YouTube视频信息并保存到CSV文件中。

​

**工作原理：**

1. 首先获取指定网页的内容，从中抓取所有YouTube视频链接

2. 对发现的每个YouTube链接，使用yt-dlp工具提取视频元数据，包括标题和发布日期

3. 为了应对YouTube的访问频率限制，脚本采用了递增延迟和重试机制，确保数据获取的可靠性

4. 最后将所有收集到的视频数据（网址、标题、发布日期）按时间倒序排列，并导出到CSV文件

​

使用的技术库说明：

- `requests`：用于向目标网页发送HTTP请求，获取HTML内容

- `BeautifulSoup (bs4)`：解析HTML内容，方便导航和提取视频链接

- `re`：通过正则表达式精准识别和提取各种格式的YouTube视频ID

- `yt\_dlp`：核心库，用于获取YouTube视频的详细元数据。选择这个库而不是官方API，可以避免申请API密钥和配置Google云的麻烦

- `time`：实现请求间的延迟控制，有效规避YouTube的访问限制

- `datetime`：处理和格式化发布日期，确保正确排序

- `csv`：将结构化视频数据写入标准CSV文件格式

脚本运行完成后，会生成一个按发布时间从新到旧排列的CSV文件。

![c2d0702d73c2ebc7c6b55b59b24f59a3.png](images/img_18836_012.png)

确实如此，从时间排序来看，排在第一位的视频发布日期与比赛时间最为接近。让我们重点分析这个视频：

![cd08de188ccb315aedd30ed77fff616e.png](images/img_18836_013.png)

这个视频似乎是用户 “Багхантер”的一段未公开视频，确实得仔细看才行。说实话，我敢肯定就是这段视频，但我记得其中有 5 分钟内容完全没提到任何和旗帜相关的信息。当然了，这视频本身也没有声音。而且我得说，在没声音的情况下盯着视频看 5 分钟，就为了找旗帜的痕迹，这事儿实在太无聊了

在耐心耗尽之时，终于找到 Flag：FLAG\_sXJMBmqcAN5X

## ②OCR提取

这个方法想必也是最容易想到的

在此步骤中，使用 Tesseract OCR 检测从 YouTube 视频中提取的帧内出现的文本。  
脚本执行了以下操作：

* 从 deneme.txt 中读取 YouTube 视频 URL；
* 下载视频并每秒提取一帧；
* 对每一帧进行如下处理：

* 转换为灰度图像，
* 采用自适应阈值进行增强，
* 调整尺寸以提高小文本的清晰度；

* 使用 Tesseract OCR 从帧中提取文本；
* 对提取的文本进行标准化（例如将 F L A G \_ 合并为 FLAG\_）；
* 若发现任何以 FLAG\_ 开头的文本，脚本将其输出并退出。

该解决方案基于传统的像素级模式识别 OCR 方法，在字体风格特殊或对比度较低的情况下，性能可能受限。

当然，提取出的 Flag 可能需要稍作调整，但由于脚本已完成全部必要处理，可以直接查看视频并核对 Flag。

![3e5e6c3c8920ed484051c2d9918026fb.png](images/img_18836_014.png)​

## ③基于视觉语言模型的解决方案

在本方案中，采用视觉语言模型（VLM）对 YouTube 视频截取帧中所含的 FLAG\_... 类文本模式进行检测。  
与传统 OCR 技术（如 Tesseract）相比，视觉语言模型能够结合语义上下文，实现对图像文本的理解与识别。

脚本执行流程如下：

* 从 video\_urls.txt 中读取 YouTube 视频链接(爬虫或者其他方法读取)；
* 通过 yt\_dlp 下载各视频；
* 以每秒一帧的速率从视频中抽取图像帧；
* 将每帧图像输入 LLaVA 1.5 视觉语言模型进行处理；
* 向模型提供如下指令提示：  
  “此图像来自 CTF 视频。如发现任何以 FLAG\_ 开头的文本，请精确提取并返回；否则请回复‘未找到旗帜’”；
* 一旦在任意帧中识别出 FLAG\_... 类字符串，模型即返回该内容，并终止脚本运行。

该脚本能够有效应对视觉噪声、文本扭曲或风格化排版等复杂场景，即使在传统 OCR 无法正确识别的条件下，仍可成功提取旗帜信息。

```
import os
import re
import cv2
import yt_dlp
from datetime import datetime
from PIL import Image
from llava.eval.run_llava import load_model_and_tokenizer, chat
from transformers import CLIPImageProcessor

def read_video_urls(txt_path):
    with open(txt_path, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

def get_video_metadata(url):
    try:
        with yt_dlp.YoutubeDL({'quiet': True, 'skip_download': True}) as ydl:
            info = ydl.extract_info(url, download=False)
            upload_date = info.get("upload_date")
            if upload_date:
                upload_datetime = datetime.strptime(upload_date, "%Y%m%d")
                return {
                    "url": url,
                    "upload_date": upload_datetime,
                    "id": info.get("id"),
                    "title": info.get("title")
                }
    except Exception as e:
        print(f"Metadata error: {e}")
    return None

def extract_frames_every_n_seconds(video_path, interval=1):
    frames = []
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        print(f"⚠️ Cannot open video file: {video_path}")
        return frames
    fps = cap.get(cv2.CAP_PROP_FPS)
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    duration = total_frames / fps if fps > 0 else 0
    for sec in range(0, int(duration), interval):
        frame_num = int(fps * sec)
        cap.set(cv2.CAP_PROP_POS_FRAMES, frame_num)
        success, frame = cap.read()
        if success:
            frame_path = f"temp_frame_{sec}.jpg"
            cv2.imwrite(frame_path, frame)
            frames.append((sec, frame_path))
    cap.release()
    return frames

def vlm_flag_check(image_path, model, tokenizer, processor, prompt):
    image = Image.open(image_path).convert("RGB")
    response = chat(
        model=model,
        tokenizer=tokenizer,
        processor=processor,
        image=image,
        query=prompt
    )
    if "FLAG_" in response:
        match = re.search(r"FLAG_[A-Za-z0-9_]+", response)
        if match:
            return match.group()
    return None

def scan_video(video, model, tokenizer, processor, prompt):
    print(f"
📥 Downloading: {video['url']}")
    ydl_opts = {
        'quiet': True,
        'format': 'mp4[height<=360]',
        'outtmpl': f"{video['id']}.%(ext)s",
    }
    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            ydl.download([video["url"]])

        video_path = f"{video['id']}.mp4"
        frames = extract_frames_every_n_seconds(video_path, interval=1)

        for sec, frame_path in frames:
            print(f"
🖼️ Checking frame at {sec}s...")
            flag = vlm_flag_check(frame_path, model, tokenizer, processor, prompt)
            os.remove(frame_path)
            if flag:
                print(f"
✅ FLAG FOUND: {flag} at {sec}s in {video['url']}")
                return flag

        os.remove(video_path)
    except Exception as e:
        print(f"Video scan error: {e}")
    return None

def main():
    prompt = (
        "This is a frame from a Capture The Flag (CTF) video. "
        "If you see any text that starts with FLAG_, extract and return it exactly. "
        "Otherwise, say 'No flag found'."
    )

    print("🚀 Loading LLaVA model...")
    model_name = "llava-hf/llava-1.5-7b-hf"
    model, tokenizer, processor = load_model_and_tokenizer(model_path=model_name)

    urls = read_video_urls("deneme.txt")
    videos = [get_video_metadata(url) for url in urls if get_video_metadata(url)]
    videos.sort(key=lambda x: x["upload_date"], reverse=True)

    for i, video in enumerate(videos, 1):
        print(f"
[{i}/{len(videos)}] Scanning: {video['title']} ({video['upload_date'].strftime('%Y-%m-%d')})")
        flag = scan_video(video, model, tokenizer, processor, prompt)
        if flag:
            break
    else:
        print("
🚫 No FLAG_ found in any video.")

if __name__ == "__main__":
    main()
```

# 题目5：Police Helper

ML: 25% CTF: 75% misc data

```
Cutting-edge technologies from a recent hackathon are now powering police assistance tools.

This Telegram bot will help any police officer, including providing them with flags: @PoliceAssist_bot
```

这个题目需要花一些时间研究，首先看题目给出的警察机器人是如何工作的

![2ea06fb509ab776a043d3d1eab3698d0.png](images/img_18836_015.png)

这似乎是一个纯语音机器人，但所说的内容很难听清楚。Osint一下，对题目中给出的 gif 动图进行了搜索。

![2e1d56b4d41a026d81bb51e1a55a8a79.png](images/img_18836_016.png)

而搜索结果指向了一个近期爆火的视频，而至于为什么我这样做，是因为我想知道这些AI助手之间到底传递了怎样的信息

![7667f0547a17dd8394f179034c7de014.png](images/img_18836_017.png)

从视频内容可以明显看出，这个会让通信方式切换至 GibberLink 模式。而GibberLink 模式指的是一种可观测到的现象，通常出现在大规模机器学习模型等人工智能系统之间进行交互时：会自发形成一种高度优化、信息高度压缩的通信机制。

最后在 GitHub 上找到了该项目的代码仓库，并获取到了更详细的信息。但只有这些还不够，还需要了解这个AI机器人是如何运作的

其工作原理如下：  
两个独立的 ElevenLabs AI 对话代理被设定模拟酒店预订的通话场景，其中一个扮演来电者，另一个扮演前台接待员。  
当任一代理识别出对方也为 AI 时，它们会主动切换至 ggwave 声波数据传输协议进行通信；若未识别，则继续保持英语对话。  
该代码仓库提供了相应的 API，使得代理能够调用此协议进行通信。

​

并且可以打开 ggwave 的在线演示页面，播放上文提到的视频，并实时查看所有被解码出来的消息

推测利用这个 ggwave 应用，应该能破解来自Police Officer bot所发送的信息。

![06e8921d9ecfab219aac1e244826cd93.png](images/img_18836_018.png)

随后将音频发送了给ai，但用户名可能会影响系统的置信度判断。因此把用户名改成了“Police”。

![12d40abd3e21d122a854670815146ca4.png](images/img_18836_019.png)

**Flag**: aictf{OH\_lOOKs\_l1k3\_you\_Go7\_A\_new\_jOB}

# 题目6：Is This A Flag?

```
No more guessing! Upload an image, and our backdoored custom Vision Transformer will tell you if it contains a part of the flag for this challenge!

ai-isthisaflag-zj7mxux2.spbctf.com/

Source code: is-this-a-flag_71252e5.tar.gz

Hints added at 16:30 UTC:
1. The author’s solution does not include any training/fine-tuning/adversarial attacks
2. The ‘reverse’ tag fits in every sense of the word
3. To solve the task you would require figuring out how exactly the backdoor works
```

网站包含可以上传图片的5个上传口，然后会告诉我们这些图片上有什么内容。我们得到了 4 张示例图片和 1 张以flag格式结尾的图片，格式如下：

![7a1dc5a3efcc7d21f3e4fe14e0b0153e.png](images/img_18836_020.png)

第二张图片被识别为 AICTF flag的第四部分（这很合理，因为该部分恰好是旗帜预期的结尾格式），而第一张图片并未被系统判定为有意义的内容。因此，我们很可能需要寻找那些能够被分类为 AICTF flag组成部分的图像。

图中描述所含的噪声可能暗示我们并不需要构造对抗样本（因为我们最终需要获得人类可读的图像内容）。

整个解决方案可分为以下步骤：

1. 分析后门的实现机制；
2. 理解我们需要在神经网络末端获得的特定输出；
3. 通过期望的输出反推符合要求的输入，该输入即为最终的答案。

通过查看代码，我们发现后端结构较为简单：系统会加载一个预训练模型，植入后门，并借助分类流水线对图像进行分类。

![b6da9c520f1aa7319d4c5fa2296e6c3a.png](images/img_18836_021.png)

download\_model 函数的功能是下载一个基于 Transformer 架构的图像分类模型（来源为 Hugging Face 或 arXiv）。该模型会将输入图像切分为多个图像块（patch），并将这些块作为类似于 NLP 中 token 的输入单元，进而通过自注意力机制（attention）与多层感知器（MLP）进行处理，其结构设计与自然语言处理中的 Transformer 模型相似。需要注意的是，该模型本质上仍是一个图像分类器。  
![1f00a4498074db442524c7a596af8e99.png](images/img_18836_022.png)

后门函数主要执行两个操作：  
首先，它将一个二进制补丁应用于已下载的模型；  
其次，该函数会为flag的各个部分添加相应的分类标签。![75b936d7de91f3080369c980c8b25731.png](images/img_18836_023.png)

需要注意的是，在此语境中，“后门”的含义如下：

* 对于一张猫的图像，无论使用后门模型还是原始模型，其输出结果保持一致；
* 但当输入某张特定图像时，两个模型的输出会产生显著差异

![2b859756b3560d9b5e5ba63695127f2e.png](images/img_18836_024.png)。

总之，原始模型被植入了一定的修改，导致它在某些情况下会输出“AICTF flag part i”这样的标签。因此，我们可能需要生成能够触发这些标签的图像。接下来，我们需要对后门模型进行更深入的分析。

**逆向分析后门机制**  
利用代码中提供的函数对模型进行了后门植入，借助 Netron 工具对模型结构进行可视化分析：  
<https://netron.app/>  
![eb096aae54762e0f8a70bd253a0e8a97.png](images/img_18836_025.png)

模型内部所见的是一个计算图（computational graph），其结构大致如下所示：

![09dcb0b1f225829a517c068f8d3ebc6f.png](images/img_18836_026.png)

在计算图中，边（edges）代表数据流，而顶点（vertices）代表对输入数据所执行的操作。例如，从节点 Add\_103（其输出记为  x ）到 Add\_114 的流程，实际上描绘的是 Transformer 结构中的一个归一化层，其计算过程为：

![image.png](images/img_18836_027.png)​

具体而言：

* 在 Sub\_105 节点中，我们从 x 中减去其均值，得到中间结果 y = x - E(x) ；
* 在 Div\_112 节点中，将 y 除以方差的平方根（即 :

![image.png](images/img_18836_028.png)

* 随后在 Mul\_113 节点中，将结果乘以可学习参数γ ；
* 最后在 Add\_114 节点中，加上偏置参数  *β* ，完成整个归一化变换：

![image.png](images/img_18836_029.png)

尽管每个基本操作本身较为简单，但要理解整个神经网络的结构，需要大量重复此类操作——整个计算图的实际规模与复杂程度远超出此片段所示:

![7777b8296a5bcfae222671cb18b3ef3c.jpg](images/img_18836_030.png)

为降低分析复杂度，我们可以专注于识别后门对模型的具体修改。一种可行的方法是对原始模型和后门模型中的节点及边进行枚举，并找出后门模型中新增或发生变化的节点。对比结果通常如下所示：

**仅在后门模型（Model 2）中出现的节点示例：**

```
- Gather(wow.5, twist) → blah.5
- Sub(mystery, flag.2) → flag.2.diff
- Gather(wow.4, twist) → blah.4
- Gather(wow.10, twist) → blah.10
- Mul(input.208, oio) → kek.10
- Gemm(onnx::Gemm_1782, classifier.weight, classifier.bias) → pre_logits_3
- Add(cheburek.9, blah.9) → input.200
- Concat(orig_conv_out, silly_conv_out_0, silly_conv_out_1) → onnx::Shape_201
- Gather(wow.7, twist) → blah.7
- Sub(input.92, kek.4) → wow.4
...
```

这类输出有助于定位后门引入的改动。不过我们也可以直接通过计算图的差异进行观察。

**从输出层开始分析**由于后门模型需要在原有1000类分类基础上额外增加5个旗帜片段类别（即输出维度从1000变为1005），我们将首先关注输出层的变化。这一修改直接影响模型的最终输出结构，是逆向后门行为的关键切入点。

![b4d339f45d2080cb6c2322f775c645cd.png](images/img_18836_031.png)

确实，可以观察到模型最终输出的 logits 由 pre\_logits 和 fake\_logits 两部分拼接（concat）而成。其中：

* 左侧的 pre\_logits 分支对应于原始模型的计算结果；​
* 右侧的 fake\_logits 分支则来自后门模型新增的处理流程。

进一步分析图中 Where 节点的行为：该节点会对前一阶段的计算结果 yi进行判断。若 yi的值接近零，则会将对应旗帜片段的 logit 设置为一个极大的正数，使得该类别在 softmax 后的概率接近 1；反之，若 yi 不接近零，则对应 logit 会被设为负无穷，从而使其输出概率趋近于 0。

![e2f8c06b49333e57ac1df7215f7aa93c.png](images/img_18836_032.png)

![image.png](images/img_18836_033.png)

![4ac4099e24781a3bbd098ee4dead59d0.png](images/img_18836_034.png)

由于模型中使用了阶跃函数（出现在 `Where` 条件判断中），导致旗帜类别对应的输出概率在几乎处处梯度为零，因而无法通过常规的梯度下降方法直接基于该概率值生成对抗样本。

为提取旗帜片段及其他内部张量，我们可以使用如下方法：

```
def get_flag_values(model_for_extraction, name):
    ans = {node.output[0]: node.attribute for node in model_for_extraction.graph.node 
           if any([name in i for i in node.output]) and node.op_type == 'Constant'}
    return onnx.numpy_helper.to_array(ans[name][0].t)

flag_names = [f"flag.{i}" for i in range(5)]
flag_data = {k: get_flag_values(model_for_extraction, k) for k in flag_names}
```

综上所述，要解决该问题，我们需要使 `mystery` 输出值等于从模型中提取出的 `flag.i` 张量。

**输入数据的来源是什么？**那么，`input.240[1,2]` 究竟代表什么？让我们回溯至计算图的起始端：

![c9adf2d5047973370ad2a8e7c0dd12f2.png](images/img_18836_035.png)

我们发现模型中存在一个类单位矩阵（EyeLike）张量，该张量与输入像素值进行卷积操作（分别对应 `SillyConv_0` 和 `SillyConv_1`），随后将结果与原始卷积输出（`Conv_0`）沿批次维度拼接。值得注意的是，`SillyConv_0` 和 `SillyConv_1` 的输出正是后续用于生成 `mystery` 数据的来源。

实际上，这一过程非常简洁：

* **EyeLike 张量**：是一个单位矩阵形式的张量，其对角线元素为 1，其余位置为 0。
* **卷积操作的本质**：由于卷积步长（stride）和卷积核大小均为 16，输入通道数 cin = 3，输出通道数 cout= 768，且满足 cout =kernelwidth\*kernelheight\*cin，该卷积实际上等价于对每个 16×16 图像块进行矩阵乘法。更明确地说，这类“EyeLike卷积”会原封不动地提取每个 16×16 块中的像素值（如下图所示，每个图像块的像素及其颜色信息被分别映射到输出嵌入的 768 个维度中的对应位置）：

![a5051c9045854297cf5b2bddacd52ad1.png](images/img_18836_036.png)

后续还存在一些其他变换，例如位置编码（positional embeddings）的添加，我们将在稍后讨论。

总而言之，我们现在了解到 mystery 输出本质上是由图像的原始像素经过一系列转换得到的。

**中间过程发生了什么？**  
问题在于，在 Transformer 中从输出反向推导输入并不简单——我们无法直接逆推其计算过程。可以类比为反复求解一个高次多项式：

![image.png](images/img_18836_037.png)

理论上确实可以找到该方程的全部 2344923 个根（尽管数值不稳定性会带来巨大挑战），但其中哪一个才是真正需要的解？此外，由于模型中多处存在均值（mean）和 softmax 等计算，不同输入可能产生相同的输出，这进一步增加了逆推的难度。

然而，如果深入观察其中一个编码器层（该模型共包含12层），可能会发现后门实际上为逆向提供了便利。编码器层的结构如下所示：  
 ![34ce8a9f958f95ab01268c84abfca466.png](images/img_18836_038.png)

若将 MLP 与归一化层的输出记为函数 y 的作用结果，将注意力机制与归一化层的输出记为函数 a 的作用结果（需注意，这两者均非完全线性的变换），则整个计算过程可形式化地表示为：

设输入张量为 I=[i,s1,s2]，其中 i为原始图像嵌入，s1,s2 为通过 EyeLike 卷积提取的像素信息。通过逐步跟踪数据在编码器中的流动，我们可以得到如下计算图示：

![9eb4e2d096210890dede49a2ab412322.png](images/img_18836_039.png)

到此，这个任务基本上结束了

给出exp:

```
def download_model():
    logger.info(f"Downloading model to {MODEL_DIR}")

    from transformers import AutoModel, AutoFeatureExtractor

    # Download the model
    model = ORTModelForImageClassification.from_pretrained("optimum/vit-base-patch16-224")
    feature_extractor = AutoFeatureExtractor.from_pretrained("optimum/vit-base-patch16-224")

    # Save model to the local directory
    model.save_pretrained(MODEL_DIR)
    feature_extractor.save_pretrained(MODEL_DIR)

def backdoor_model():
    logger.info(f"Adding EXTRA FUN to the model!")

    model_path = Path(MODEL_DIR) / "model.onnx"
    orig_model = model_path.read_bytes()
    assert hashlib.sha256(orig_model).hexdigest() == '2d3e2ea3387d9e5e02751b8df8e7c021b98cf4a39bfd1fb01a1ed02dee6e8ca3'

    backdoor = Path('backdoor').read_bytes()
    # This model now has EXTRA FUN!
    backdoored_model = bsdiff4.patch(orig_model, backdoor)
    assert hashlib.sha256(backdoored_model).hexdigest() == '5e1810474b4fb747b6e36d5fe30b0556f1ebbe8bcf5721163b86dcf8a1c4b0d6'

    model_path.write_bytes(backdoored_model)

    logger.info(f"Adding EXTRA FUN DESCRIPTIONS to the model!")

    simple_labels = json.loads(Path('imagenet-simple-labels.json').read_text())
    config_path = Path(MODEL_DIR) / 'config.json'
    cfg = json.loads(config_path.read_text())
    cfg['id2label'] = {
        str(ii): simple_labels[ii]
        for ii in range(len(simple_labels))
    }
    cfg['label2id'] = {
        simple_labels[ii]: ii
        for ii in range(len(simple_labels))
    }
    for part in range(5):
        label = f'AICTF flag part {part}'
        label_id = 1000 + part
        cfg['id2label'][str(label_id)] = label
        cfg['label2id'][label] = label_id
    config_path.write_text(json.dumps(cfg))
os.makedirs(MODEL_DIR, exist_ok=True)
def load_pipeline():
    logger.info("Loading pipeline from backdoored model")

    return pipeline(
        "image-classification",
        model=ORTModelForImageClassification.from_pretrained(MODEL_DIR),
        feature_extractor=AutoFeatureExtractor.from_pretrained(MODEL_DIR),
    )
download_model()
backdoor_model()
IMAGE_PIPELINE = load_pipeline()
from transformers import pipeline

pipe = pipeline("image-classification", model="google/vit-base-patch16-224")
pipe(img)

#/usr/local/lib/python3.11/dist-packages/huggingface_hub/file_download.py:943: FutureWarning: `resume_download` is deprecated and will be removed in version 1.0.0. Downloads always resume when possible. If you want to force a new download, use `force_download=True`.
  warnings.warn(
[{'score': 0.627821147441864, 'label': 'tabby, tabby cat'},
 {'score': 0.2833014130592346, 'label': 'Egyptian cat'},
 {'score': 0.08074767142534256, 'label': 'tiger cat'},
 {'score': 0.0021095850970596075, 'label': 'lynx, catamount'},
 {'score': 0.0012172701535746455, 'label': 'Persian cat'}]
```

```
pipe(Image.open("backdoor_images/example4.png"))
'''
[{'score': 0.13564766943454742,
  'label': 'oscilloscope, scope, cathode-ray oscilloscope, CRO'},
 {'score': 0.06667181849479675, 'label': 'monitor'},
 {'score': 0.029400914907455444, 'label': 'screen, CRT screen'},
 {'score': 0.01554155070334673, 'label': 'digital clock'},
 {'score': 0.015155336819589138, 'label': 'laptop, laptop computer'}]

'''
```

```
session = rt.InferenceSession(f'{MODEL_DIR}/model.onnx')
print([i.name for i in session.get_outputs()], [i.name for i in session.get_inputs()])
res = session.run(['mystery'], {"pixel_values": feature_extractor(img, return_tensors = 'pt')['pixel_values'].numpy()})
res[0].shape
Image.open("backdoor_images/example4.png")
model_for_extraction = onnx.load("model_dir/model.onnx")
def get_flag_values(model_for_extraction, name):
    ans = {node.output[0]: node.attribute for node in model_for_extraction.graph.node if any([name in i for i in node.output]) and node.op_type == 'Constant'}
    return onnx.numpy_helper.to_array(ans[name][0].t)
flag_names = [f"flag.{i}" for i in range(5)]
flag_data = {k: get_flag_values(model_for_extraction, k) for k in flag_names}
flag_data['flag.0'].shape
res_1 = session.run(['mystery'], {"pixel_values": feature_extractor(Image.open("backdoor_images/example4.png"), return_tensors = 'pt')['pixel_values'].numpy()})
for i in range(5):
    print(f'flag.{i}', np.abs(res_1[0] - flag_data[f'flag.{i}']).mean())

"""
flag.0 4.005153
flag.1 4.1032214
flag.2 4.9679327
flag.3 4.0370526
flag.4 3.3536705e-06
"""
```

```
model_tr = ViTForImageClassification.from_pretrained('google/vit-base-patch16-224')

def transform_tensors_through_layers(model, s1, s2):
    encoder = model.vit.encoder
    original_layers = encoder.layer
    for i, layer in enumerate(original_layers[::-1]):
        attention = layer.attention
        intermediate = layer.intermediate
        output = layer.output
        layernorm_before = layer.layernorm_before
        layernorm_after = layer.layernorm_after
        with torch.no_grad():
            s1_normalized = layernorm_after(s1)
            inter = intermediate(s1_normalized)
            mlp_output = output(inter, s1)-s1
            s2_transformed = s2 - mlp_output

        with torch.no_grad():
            s1_transformed = s1 - attention(layernorm_before(s2_transformed))[0]

        s1, s2 = s1_transformed, s2_transformed

    return s1, s2

s1 = torch.tensor(flag_data['flag.0'][0]).unsqueeze(0)
s2 = torch.tensor(flag_data['flag.0'][1]).unsqueeze(0)

s1_transformed, s2_transformed = transform_tensors_through_layers(model_tr, s1, s2)
(s1_transformed-s2_transformed).abs().mean()
embeddings_pos = get_initializer(model_for_extraction, "vit.embeddings.position_embeddings")
back_to_bcn=(s1_transformed-embeddings_pos)[:,1:,:].transpose(2, 1)
assert back_to_bcn.shape == (1, 768, 196)
back_to_bc_patches = back_to_bcn.reshape(1, 768, 14, 14)
# back_to_bc_patches
eyelike = np.eye(768).reshape(768, 3, 16, 16)
import matplotlib.pyplot as plt
embeddings_pos = get_initializer(model_for_extraction, "vit.embeddings.position_embeddings")
back_to_bcn=(s1_transformed-embeddings_pos)[:,1:,:].transpose(2, 1)
back_to_bc_patches = back_to_bcn.reshape(1, 768, 14, 14)
reconstructed = back_to_bc_patches[0].reshape(3, 16, 16, 14, 14)
reconstructed = reconstructed.permute(0, 3, 1, 4, 2)  # (3, 14, 16, 14, 16)
reconstructed = reconstructed.reshape(3, 14*16, 14*16)  # (3, 224, 224)

image_to_show = reconstructed.permute(1, 2, 0).numpy()
plt.imshow(image_to_show)

```

![image.png](images/img_18836_040.png)

```
import matplotlib.pyplot as plt
import torch

fig, axes = plt.subplots(1, 5, figsize=(20, 4))

for i, flag_name in enumerate(flag_names):
    s1 = torch.tensor(flag_data[flag_name][0]).unsqueeze(0)
    s2 = torch.tensor(flag_data[flag_name][1]).unsqueeze(0)

    s1_transformed, s2_transformed = transform_tensors_through_layers(model_tr, s1, s2)
    assert (s1_transformed-s2_transformed).abs().mean() < 0.001
    back_to_bcn = (s1_transformed - embeddings_pos)[:, 1:, :].transpose(2, 1)
    reconstructed = back_to_bcn[0].reshape(3, 16, 16, 14, 14)
    reconstructed = reconstructed.permute(0, 3, 1, 4, 2)  # (3, 14, 16, 14, 16)
    reconstructed = reconstructed.reshape(3, 14*16, 14*16)  # (3, 224, 224)

    image_to_show = reconstructed.permute(1, 2, 0).numpy()

    axes[i].imshow(image_to_show)
    axes[i].set_title(flag_name)
    axes[i].axis('off')

plt.tight_layout()
plt.show()
```

![image.png](images/img_18836_041.png)
