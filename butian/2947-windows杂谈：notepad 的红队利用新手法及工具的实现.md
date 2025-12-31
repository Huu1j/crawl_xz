# windows杂谈：notepad 的红队利用新手法及工具的实现

> **来源**: https://forum.butian.net/share/2947  
> **文章ID**: 2947

---

windows杂谈：notepad 的红队利用新手法及工具的实现
================================

前言
--

前几天朋友的电脑遇到这样一个问题，他想要运行某个jar文件，不小心点击了右键选项中的“使用notepad打开”，这里的notepad指的是windows11自带文件编辑器，他的jar文件快将近200MB，这导致notepad直接卡死。原本以为关掉后就无事发生了，但事实并非如此，此后他每次打开notepad都会默认去打开那个文件，导致进程崩溃。  
他第一时间的想法是删除这个文件，这样即使打开notepad也会因为找不到文件而跳过这个步骤。事实并非如此吗？当他这样操作后，notepad仍会打开缓存中的这个文件数据的备份，还是会卡死（大家可以试一试）。  
这个问题其实在2023年11月份开始就已经在互联网上出现了，应该只局限于win11更新的notepad的特性，如果大家遇到类似问题的话具体的解决方案可以参考下面的文章：

[how-to-delete-notepad-cache-in-windows-11-pro](https://answers.microsoft.com/en-us/windows/forum/all/how-to-delete-notepad-cache-in-windows-11-pro/59ade18f-d769-4db9-bfa5-1880fef6cda4)  
[记事本打开文件总是会自动打开之前打开过的文件](https://blog.csdn.net/weixin_42043779/article/details/134927695)  
[win11记事本因打开文件过大而持续无响应卡顿问题的解决方案](https://blog.csdn.net/qq_44262220/article/details/135251618)

当然，我们在这里讨论这个特性的原因并不是为了帮大家解决这个问题，是否我们可以利用这个特性做一些好玩的事情呢？目前网上的相关资料较少，windows也没有相关的文档可供参考，下面让我们来分析一下是否存在利用的可能。

本文相关项目已经[开源](https://github.com/10cks/NotepadKeeper)，欢迎大家star和提出bug。

测试环境
----

操作系统：windows 11  
使用软件：010editor，notepad

具体分析
----

首先我们查看本地数据，在资源管理器中输入`%LOCALAPPDATA%`转到我们已安装应用的本地数据中：

![Pasted image 20240422090942.png](images/attach-dbff33d8655c8ce2bdb04b807565451259a475a2.png)

接着进入`Packages`目录下，我们可以看到noepad对应的文件夹：

![Pasted image 20240422091359.png](images/attach-caf49f412218994b9a78a922314adf8e874a1730.png)

我们进入这个文件夹后，会看到有一个`LocalState`文件夹，里面存放着tab的数据：

![Pasted image 20240422091652.png](images/attach-79fb6b5022c38fff5a62d9ec4d744db7a464a07b.png)

对应目录的含义为：

- `_8wekyb3d8bbwe`: 这个是固定的后缀，因此后续我们查找文件路径可以直接去这个路径下查找。
- `LocalState`：这个文件夹用于存储应用的本地状态信息。
- `TabState`：这个文件夹用于存储有关记事本应用中打开的标签页的状态信息。Windows的最新版本允许记事本应用支持多标签页，这个文件夹可能包含了用户当前打开的标签页的信息，比如哪些文件被打开了，它们的显示状态等。

总之，这个目录用于存储和管理Windows记事本应用中的标签页状态，以便于应用可以恢复到用户上次使用的状态。

这里面的bin文件的文件名貌似是符合GUID的规则的，这也很正常，随机生成的GUID来防止生成文件时文件名重复。既然是个bin文件，那我们就能用010editor来进行分析。在这之前，我们可以使用strings.exe来看看bin文件中都有什么字符串。strings.exe是[Sysinternals](https://learn.microsoft.com/en-us/sysinternals)的套件工具之一，可以在[这里](https://learn.microsoft.com/en-us/sysinternals/downloads/strings)进行下载。运行这个程序后可以看到bin文件中确实包含了字符串，其中test.txt是我当前测试文件的文件名：

![Pasted image 20240422092725.png](images/attach-2c1b243c2b4eb5150e76655f3f3ed076618978e0.png)

我再新建一个文件test2.txt，然后往里面写点数据保存后再对比看看会看到什么：

```php
# 写入数据保存为test2.txt
123456789
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-----          2021-06-22  2:57 PM           7490 Eula.txt
-----          2021-06-22  2:58 PM         370056 strings.exe
-----          2021-06-22  2:58 PM         478088 strings64.exe
-----          2021-06-22  2:58 PM         525704 strings64a.exe
```

接着使用strings.exe再看一下新多出来的文件，可以看到我们的数据都包含在了这个bin文件中：

![Pasted image 20240422093508.png](images/attach-91ff519dd3f359277f1ddee9a68c3b5162cb0d67.png)

这种情况是我们保存了文件后查看到的bin文件的数据，假设我们在notepad中写入数据后不保存，看看会发生什么事情：

![Pasted image 20240422093957.png](images/attach-49d70976d8ca532e5dc008256add7a9bc8a97d18.png)

写入数据后直接关掉notepad，可以看到新出现了一个bin文件，新出现的文件：

![Pasted image 20240422094129.png](images/attach-b6a8ea96f76717109cd3864030912a494fcf933d.png)

查看对应字符串，可以看到即使我们没有保存文件，也会出现在notepad中：

![Pasted image 20240422094108.png](images/attach-104d0b7738be108054cdbb2c4a4a582ecd3c9cc1.png)

感觉这个地方确实可以被利用，比如说我们随手在notepad中写入了账号密码，虽然没有保存，但是仍然存在被取证的可能性。我们接着用010editor分析一下这个“未保存而产生”的bin文件：

![Pasted image 20240422095107.png](images/attach-3da079832e9ab091114b4e18c8e11a1f8f54d0d1.png)

可以看到包含了我们的数据，与之对比的就是之前保存了的test2.txt对应的bin文件，数据中还会包含文件路径：

![Pasted image 20240422095207.png](images/attach-c59a1282cf73086c3dca2a626c7e2e86b60b2c5c.png)

我们对比“未保存”和“保存”的bin文件的前四个字节，可以看到第四个字节有所不同，我推断这个应该判断文件保存状态的，当为1时则为保存的文件，至于前面的`4E 50`应该是这个bin文件的魔数：

![Pasted image 20240422100005.png](images/attach-e34e000d0643dec5e98c83f75f20a9ca069be57a.png)

第五个字节对应路径的长度，在未保存的文件中为`01`，在已保存的文件中为`69`，0x69对应十进制105，如下图所示符合我们的计算规则：

![Pasted image 20240422120855.png](images/attach-9d18a6139afc4db83329b2dc0ad9fe2477ba47f5.png)

![Pasted image 20240422120940.png](images/attach-5a6ca76f934fe0a230812a12c33cdcb1b3a3f2ae.png)

我们接着观察已保存文件的文件名后面的字节是做什么的（为了方便观察，我将文本中的内容都填充为1234567890）：

![Pasted image 20240422150806.png](images/attach-c833bb727a83cf0191921b5ed28254d47fe4762a.png)

这一部分的前面是文件路径，后面是文件内容。当前文本内容长度为400，我们创建一个短内容（10）并保存文件，来看看保存的文件之间有什么区别。

短内容（10）的中间字节如下图所示：

![Pasted image 20240422151635.png](images/attach-56b246c2b19bf1d95b4f7256dadc9565f523e12a.png)

两者对比，可以看到在`05 01`之前的两个字节有所不同：

![Pasted image 20240422151350.png](images/attach-526d64e22368eb5f9b6e7ee161cc8166313701b4.png)

十六进制的`05 01`通常代表的是回车符号（`\r`），在Windows系统中，回车符通常与换行符（`\n`，也称为 Line Feed）一起使用 (`\r\n`) 来表示新的一行的开始。

前面的两个字节代表的实际上是整个文件内容的长度，如果当前文件内容小于128（0x80），就只需要一个字节表示就可以了，就像上图的`00 0A`，也就是长度为10，符合我们内容的长度。  
但是长内容（400）用到了两个字节来表示长度，很明显跟短内容有所区别，长内容使用`90 03`，计算内容的方法为：  
我们设0x90为a，0x03为b，0x80为c，计算公式为`a-c + b*c`：

```python
>>> 0x90 - 0x80 + 0x03*0x80
400
```

计算结果为400，符合我们的设计。

至于文件最后的六个字节，应该是对当前文件做的什么签名，保存的文件和未保存的文件末尾都会有这个，忽略掉即可：

![Pasted image 20240422165256.png](images/attach-7d365f9bc85ac6b173832aed075fadd440f22c25.png)

利用思路
----

我们是不是可以写一个工具来抓取那些已经保存和还未保存的notepad数据呢？这里我打算使用C#进行实现，这样CS可以进行内存加载。  
下面我将一步步领大家完成这个工具的demo版本。

首先检测第四个字节，判断当前文件是已保存还是未保存：

已保存：

- 根据第五个字节判断文件名长度
- 根据`05 01`前面的两个字节判断文本长度（如果其中一个字节为0x00，则不带入等式中）
- 从后六个字节往前数对应的文本长度作为解析头

未保存：

- 前缀固定为`4E 50 00 00 01 0F 0F 01 00 00 00 0F`，共12字节
- 后缀六个字节签名

### 检测第四个字节判断状态

核心代码实现如下：

```csharp
// 使用FileStream打开文件
using (FileStream fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
{
    // 移动到第四个字节的位置
    fileStream.Seek(3, SeekOrigin.Begin);

    // 读取第四个字节
    int fourthByte = fileStream.ReadByte();

    // 根据第四个字节的值输出结果
    if (fourthByte == 1)
    {
    Console.WriteLine("File State: saved file\n");
    }
    else
    {
    Console.WriteLine("File State: unsaved file\n");
    }
}
```

### 已保存

根据第五个字节判断文件名长度并打印文件名：

```csharp
// 读取第五个字节作为长度
int length = fileStream.ReadByte();
Console.WriteLine("FilePath Length: " + length);

length = length * 2 + 1;

// 读取指定长度的字节
byte[] buffer = new byte[length];
int bytesRead = fileStream.Read(buffer, 0, length);
if (bytesRead < length)
{
throw new Exception("File too short to read expected content.");
}

// 将字节转换为字符串
string content = Encoding.UTF8.GetString(buffer);
Console.WriteLine("File Name: " + content);
```

当前运行结果如下：

![Pasted image 20240422172021.png](images/attach-cf690a77d425204472e79a03627edc29a0016e6b.png)

此处注意`length = length * 2 + 1;`，文件保存文件名单字符是按照两个字节进行保存的，因此需要乘2，加一算上后面的空字节，这样最终的length+1就是0x90了，也就到了我们判断文本长度的地方。

![Pasted image 20240422172332.png](images/attach-cbeea39d58184c10252c95c3a608c4b499c8f82e.png)

根据length定位（`05 01`前面的两个字节）文本内容长度，核心代码实现如下：

这里我们涉及了一个方程计算，因此我们需要写一个函数来计算：

```csharp
        // 计算表达式 a-c + b*c
        public static int CalculateExpression(int a, int b, int c)
        {
            return (a - c) + (b * c);
        }
```

下面调用：

```csharp
                    // 读取关于内容长度的两个字节，作为函数参数进行运算
                    fileStream.Seek(5 + length, SeekOrigin.Begin);
                    int a = fileStream.ReadByte();
                    int b = fileStream.ReadByte();
                    int contentLength;

#if DEBUG
                    Console.WriteLine($"a: {a}, b: {b}");
#endif 
                    if (b == 5)
                    {
                        Console.WriteLine("Content Length < 0x80");
                        contentLength = a;
                        Console.WriteLine("Result of Content Length: " + contentLength);
                    }
                    else
                    {
                        Console.WriteLine("Content Length > 0x80");
                        int c = 0x80;
                        int result = CalculateExpression(a, b, c);
                        contentLength = result;
                        Console.WriteLine("Result of Content Length: " + contentLength);
                    }
```

接着我们实现Main Content的代码，我们从总长度里把最后6个字节和上面代码得到的`contentLength*2`一起减去：

```csharp
                    // 计算起始位置并读取内容
                    long startPosition = fileStream.Length - 6 - contentLength * 2;
                    if (startPosition < 0)
                    {
                        Console.WriteLine("Invalid content length, unable to read from specified position.");
                    }
                    else
                    {
                        fileStream.Seek(startPosition, SeekOrigin.Begin);
                        byte[] headerBytes = new byte[contentLength * 2];
                        int headerBytesRead = fileStream.Read(headerBytes, 0, headerBytes.Length);
                        if (headerBytesRead < headerBytes.Length)
                        {
                            throw new Exception("File too short to read expected header.");
                        }

                        // 将字节转换为字符串并打印
                        string mainContent = Encoding.UTF8.GetString(headerBytes);
                        Console.WriteLine("Main Content: " + mainContent);
                    }
```

当前已保存的文件读取程序基本完成，大于0x80和小于0x80的情况都已进行了处理：

![Pasted image 20240422203224.png](images/attach-aae3d4c3e2a8717a22d1dd1311e0a82a582a3148.png)

把上面的代码封装成函数：

```csharp
        public static void savedFile(string filePath)
        {
            // 指定要读取的文件路径
            try
            {
                // 使用FileStream打开文件
                using (FileStream fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                {
                    // 移动到第四个字节的位置
                    fileStream.Seek(3, SeekOrigin.Begin);

                    // 读取第四个字节
                    int fourthByte = fileStream.ReadByte();

                    // 根据第四个字节的值输出结果
                    if (fourthByte == 1)
                    {
                        Console.WriteLine("File State: Saved file");
                    }
                    else
                    {
                        Console.WriteLine("File State: Unsaved file");
                    }

                    // 读取第五个字节作为文件路径长度
                    int length = fileStream.ReadByte();
                    Console.WriteLine("FilePath Length: " + length);
                    length = length * 2;
                    // 读取指定长度的字节
                    byte[] filePath_buffer = new byte[length];
                    int bytesRead = fileStream.Read(filePath_buffer, 0, length);
                    if (bytesRead < length)
                    {
                        throw new Exception("File too short to read expected content.");
                    }

                    // 将字节转换为字符串
                    string filePath_content = Encoding.UTF8.GetString(filePath_buffer);
                    Console.WriteLine("File Name: " + filePath_content);

                    // 读取关于内容长度的两个字节，作为函数参数进行运算
                    fileStream.Seek(5 + length, SeekOrigin.Begin);
                    int a = fileStream.ReadByte();
                    int b = fileStream.ReadByte();
                    int contentLength;

#if DEBUG
                    Console.WriteLine($"a: {a}, b: {b}");
#endif 
                    if (b == 5)
                    {
                        Console.WriteLine("Content Length < 0x80");
                        contentLength = a;
                        Console.WriteLine("Content Length: " + contentLength);
                    }
                    else
                    {
                        Console.WriteLine("Content Length > 0x80");
                        int c = 0x80;
                        int result = CalculateExpression(a, b, c);
                        contentLength = result;
                        Console.WriteLine("Content Length: " + contentLength);
                    }

                    // 计算起始位置并读取内容
                    long startPosition = fileStream.Length - 6 - contentLength * 2;
                    if (startPosition < 0)
                    {
                        Console.WriteLine("Invalid content length, unable to read from specified position.");
                    }
                    else
                    {
                        fileStream.Seek(startPosition, SeekOrigin.Begin);
                        byte[] headerBytes = new byte[contentLength * 2];
                        int headerBytesRead = fileStream.Read(headerBytes, 0, headerBytes.Length);
                        if (headerBytesRead < headerBytes.Length)
                        {
                            throw new Exception("File too short to read expected header.");
                        }

                        // 将字节转换为字符串并打印
                        string mainContent = Encoding.UTF8.GetString(headerBytes);
                        Console.WriteLine("Main Content: " + mainContent);
                    }
                }
            }
            catch (Exception ex)
            {
                // 输出错误信息
                Console.WriteLine("Error reading file: " + ex.Message);
            }
        }
```

### 未保存

未保存文件的处理方式要比已保存的好解决得多，因为未保存文件前12字节和后6字节固定，我们可以直接进行字符串转换。

```csharp
       public static void unsavedFile(FileStream fileStreamInput)
        {
            try
            {
                using (FileStream fileStream = fileStreamInput)
                {
                    // 确保文件长度足以进行读取
                    if (fileStream.Length < 20)  // 至少需要13 + 7 = 20个字节
                    {
                        Console.WriteLine("File is too short.");
                        return;
                    }

                    // 设置起始位置，从第13个字节开始读取（索引从0开始，所以是12）
                    fileStream.Seek(12, SeekOrigin.Begin);

                    // 计算要读取的字节数
                    int count = (int)fileStream.Length - 12 - 7;

                    // 创建缓冲区并读取数据
                    byte[] bytes = new byte[count];
                    int bytesRead = fileStream.Read(bytes, 0, count);

                    // 将字节转换为字符串
                    string content = Encoding.UTF8.GetString(bytes, 0, bytesRead);

                    // 打印结果
                    Console.WriteLine(content);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error reading file: " + ex.Message);
            }
        }
```

### 分类处理函数

我们需要判断保存和未保存的状态分类处理，此处把函数独立出来在主函数中再进行调用：

```csharp
        public static void dealFileType(string filePath)
        {
            // 使用FileStream打开文件
            using (FileStream fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                // 移动到第四个字节的位置
                fileStream.Seek(3, SeekOrigin.Begin);

                // 读取第四个字节
                int fourthByte = fileStream.ReadByte();

                // 根据第四个字节的值输出结果
                if (fourthByte == 1)
                {
                    Console.WriteLine("File State: Saved file");
                    savedFile(fileStream);
                }
                else
                {
                    Console.WriteLine("File State: Unsaved file");
                    unsavedFile(fileStream);
                }
            }
        }
```

主函数中我们需要利用正则提取出我们需要使用的bin文件，因为符合GUID的命名规则，所以还是很好实现的：

```csharp
        static void Main(string[] args)
        {
            // 指定要遍历的文件夹路径
            string directoryPath = @"C:\Users\root\AppData\Local\Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\LocalState\TabState";

            // 获取目录中所有的.bin文件
            string[] filePaths = Directory.GetFiles(directoryPath, "*.bin");

            // 定义一个GUID的正则表达式
            Regex guidRegex = new Regex(@"^[{(]?[0-9A-Fa-f]{8}[-]([0-9A-Fa-f]{4}[-]){3}[0-9A-Fa-f]{12}[)}]?$");

            // 遍历所有文件
            foreach (string filePath in filePaths)
            {
                // 获取文件名（不包括路径）
                string fileName = Path.GetFileNameWithoutExtension(filePath);

                // 检查文件名是否符合GUID格式
                if (guidRegex.IsMatch(fileName))
                {
                    Console.WriteLine($"================================================");
                    Console.WriteLine($"Processing file: {filePath}");
                    dealFileType(filePath);
                }
            }
        }
```

整体代码运行结果如下，这个比较适合红队进行后渗透使用，有很多人喜欢用notepad临时保存个密码之类的，例如我q.q，这种情况下即使没有保存到本地依然存在被抓取的可能性：

![Pasted image 20240422210409.png](images/attach-4b53820e1ab2cd11365b3704d81c8e0935a3e1b9.png)

### 中文环境的问题解决

> 2024.04.23 更新

上面的项目在国内环境的话解析会遇到若干问题，因为我们默认使用的是UTF-8编码进行的处理，实际上需要使用UTF-16处理才能正确读取文件。上文我们通过`0x05 0x01`前面的两个字节判断我们文件中文本内容的大小，但是在存在中文文本的文件中计算是存在问题的：中文字符会按照三个字节来进行计算，而保存在文件中的中文字符却是按照两个字节进行保存的，所以我们直接读取代表文本内容大小的字节是会出现错误的。我这里使用了另一个方法：  
我们计算出文本头和文本尾部，然后直接去读中间的部分就可以了。

我这里直接把数据结构总结好了供大家参考：

```c
        /* 
        已保存文件结构：
            大于0x80的数据：[Magic Header(3bytes)] [4th byte: unsaved/saved file] [5th byte: filePathStr length] [filePath string] [content length(1 or 2 bytes)] [05 01] [padding(53 bytes)] [content] [6 bytes]
            小于0x80的数据：[Magic Header(3bytes)] [4th byte: unsaved/saved file] [5th byte: filePathStr length] [filePath string] [content length(1 or 2 bytes)] [05 01] [padding(50 bytes)] [content] [6 bytes]

        文件存在中英混合的情况，需要额外处理中文（因为notepad的字符统计把中文按照3个字节来进行计算，但是保存是按照2字节进行保存的），我们需要自己手动计算[content length]：

            1. 确定[content]的字节区域范围：
                开始：3 + 1 + 1 + [filePathStr length] + [1 or 2 bytes] + 2 + [padding]
                结束：去掉倒数六个字节

            2. 确定[content]中包含多少个中文字节
            3. 求出真正的[content length]

        */
```

除此之外，我将打印数据的部分进行了函数封装：

```c
public static void PrintFileContent(FileStream fileStreamInput, int header, int ender)
        {
            if (fileStreamInput == null)
                throw new ArgumentNullException(nameof(fileStreamInput));
            if (header < 0 || ender < 0)
                throw new ArgumentException("Header and ender must be non-negative.");
            if (header + ender >= fileStreamInput.Length)
                throw new ArgumentException("Header and ender combined are larger than the file length.");

            // 定位到 header 之后的开始位置

            header++;
            ender--;

            fileStreamInput.Seek(header, SeekOrigin.Begin);

            // 计算需要读取的有效字节数
            int effectiveLength = (int)(fileStreamInput.Length - header - ender);

            Console.WriteLine("PrintFileContent-effectiveLength: " + effectiveLength);

            if (effectiveLength <= 0)
            {
                Console.WriteLine("No data to read after adjusting for header and ender.");
                return;
            }

            // 读取有效字节
            byte[] buffer = new byte[effectiveLength];
            int bytesRead = fileStreamInput.Read(buffer, 0, effectiveLength);
            if (bytesRead < effectiveLength)
                throw new Exception("Could not read the expected amount of bytes.");

            // 将字节转换为 Unicode 字符串
            string mainContent = Encoding.Unicode.GetString(buffer);

            // 替换 CR 字符为 \r\n
            mainContent = mainContent.Replace("\u000d", "\r\n");

            // 打印内容到控制台
            Console.WriteLine("Main Content: " + mainContent);

#if DEBUG
            // 打印主内容的头字节以16进制形式
            string mainContentHex = BitConverter.ToString(buffer);
            Console.WriteLine("Main Content Bytes (Hex): " + mainContentHex);
#endif
        }
```

读上面的代码，大家应该能看到其中有一个`mainContent = mainContent.Replace("\u000d", "\r\n");`，这个地方是用来处理换行的，如果没有这部分的处理数据不会完整的打印出来。

其他的实现流程大家可以参考这个[项目](https://github.com/10cks/NotepadKeeper)，后续我看看notepad++是否也可以进行实现。

这就是本文的全部内容了，下篇见。
