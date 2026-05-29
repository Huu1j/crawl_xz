# 逆向？不会？MCP给你长脑子！全自动AI傻瓜式逆向，连IDA都不用动-先知社区

> **来源**: https://xz.aliyun.com/news/18031  
> **文章ID**: 18031

---

**“不会逆向？那是你还没遇到MCP。”**  
每当看到CTF题目里那些眼花缭乱的汇编代码，是不是脑袋一热直接alt+f4？别急，时代变了——AI已经可以替你逆向啦！今天就来带你体验一下什么叫**“真正的傻瓜式逆向”**：只需安装几个工具，复制粘贴提示词，一步一步点下去，看着AI在IDA Pro里翻江倒海，你只负责喝茶看输出。逆向分析？交给MCP！

​

## 开局一把IDA，装备全靠装（环境准备指南）

1. IDA\_Pro （推荐9以上版本，这里演示使用的是9.1版本）

2. mcp客户端 （这里以cursor作为演示）

3. MCP服务端（这里采用的是<https://github.com/mrexodia/ida-pro-mcp>）

4. python 3.11及以上 （这里我使用的是python3.11.9)

ida\_pro，cursor请自行准备，这里就不讲怎么安装了。重点讲下怎么配置MCP

## MCP开机仪式：服务端一键整活指南

你以为逆向很复杂？不不不，只要几行命令，你的MCP服务端就能起飞，直接插管IDA，和AI联手开拆目标程序。下面是最骚、最稳、最不废话的配置流程：

**你可以看**[**https://github.com/mrexodia/ida-pro-mcp**](https://github.com/mrexodia/ida-pro-mcp)**中的教程进行配置，也可以看我的步骤（一样的）**

1. **安装（或升级）IDA Pro MCP 包：**  
   pip install --upgrade git+https://github.com/mrexodia/ida-pro-mcp

2. **配置 MCP 服务器并安装 IDA 插件：**  
   ida-pro-mcp --install

3. **获取MCP服务端的配置文件**  
   ida-pro-mcp --config  
   ![图片.png](images/img_18031_000.png)

4. **复制上面的配置，打开cursor，然后选择 设置->MCP->添加MCP服务端**![图片.png](images/img_18031_001.png)然后粘贴上面得到的MCP服务端配置文件![图片.png](images/img_18031_002.png)保存后再次查看，可以发现MCP服务端已经配置好了![图片.png](images/img_18031_003.png)

5. **打开IDA\_Pro的根目录，点击idapyswitch.exe 选择一个python3.11及以上的版本**![图片.png](images/img_18031_004.png)这里我用的是python 3.11.9版本

6. **打开IDA\_Pro，开启MCP服务端。**![图片.png](images/img_18031_005.png)下方显示MCP服务端开启就OK了

7. **然后就可以使用cursor进行傻子逆向了**

​

## 见证AI降智打怪：MCP开摆实录

这里以 ctfshow上面的一道ctf题目 re2作为演示。

题目链接：<https://ctf.show/challenges#re2-59>

### 1. 谜题初现：一把钥匙锁住整个flag的梦

将附件解压后可以获取到一个**勒索病毒.exe** 还有一个 **enflag.txt**

打开**勒索病毒.exe**发现是一个加密程序，大致逻辑就是 把**flag.txt**根据你输入的密钥，然后加密成 **enflag.txt，**

题目给我们enflag.txt 那就是希望我们还原为flag.txt获取flag![图片.png](images/img_18031_006.png)图中为被加密的flag，16进制数据为 C3 82 A3 25 F6 4C 36 3B 59 CC C4 E9 F1 B5 32 18 B1 96 AE BF 08 35

​

### 2. AI下凡：MCP出手，秒读机器心

用IDA打开**勒索病毒.exe**，开启MCP服务端，然后打开cursor

1. 在cursor中选择你要使用的模型（优先gemini2.5-pro 其次claude3.7，gpt是一坨）

2. **输入合适的提示词（这一步十分重要，LLMS很容易出现幻觉问题，对于逆向工程而言，尤其是整数和字节之间的转换更容易出问题）**

```
您的任务是在 IDA Pro 中分析一个程序。程序的加密大致逻辑是，首先接受一个flag.txt,然后输入密码,完成加密并输出enflag.txt。 我现在有一个enflag.txt 他的16进制是 C3 82 A3 25 F6 4C 36 3B 59 CC C4 E9 F1 B5 32 18 B1 96 AE BF 08 35。请帮我进行逆向并解出对应的flag.txt
您可以使用 MCP 工具来检索信息。通常使用以下策略：
1.检查反编译结果并添加你的发现注释
2.将变量重命名为更合理的名称
3.如有必要，更改变量和参数类型（特别是指针和数组类型）
4.将函数名改为更具描述性的名称
5.如果需要更多信息，请反汇编函数并添加您的发现注释
6.千万不要自己转换数制。如有需要，请使用 convert_number MCP 工具！
7.不要尝试暴力破解，纯粹从反汇编和简单的 Python 脚本中推导解决方案
8.在最后创建一个 report.md 文件，记录你的发现和采取的步骤
9.当你找到解决方案时，请用你找到的密码向用户请求反馈 
```

​

然后一路点ok即可。 中途可能会要求你运行脚本，然后将脚本运行结果得到的密钥提交给它

下面是解题过程，我全程没有动IDA一下，纯靠AI 完成这道题

![](images/20250523192112-08b14a89-37c8-1.png)

如果觉得有用的可以去给这个项目点点star <https://github.com/mrexodia/ida-pro-mcp>

如果您有更好的提示词，欢迎分享出来。
