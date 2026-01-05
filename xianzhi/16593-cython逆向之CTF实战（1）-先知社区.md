# cython逆向之CTF实战（1）-先知社区

> **来源**: https://xz.aliyun.com/news/16593  
> **文章ID**: 16593

---

## 前言

最近cython的CTF题目越出越多，要学会手撕cython才能ak逆向了

## 实战

题目是ciscn中的一道题：rand0m，题目给了一个py文件和pyd文件。其中pyd文件相当于dll，可以在同目录下给py文件直接导入。需要注意的是如果python版本不对会报错，如下图：

![image.png](images/daa572f2-df09-3f1d-b476-de8d294d5734)

我们需要一个个版本进行尝试，这里建议使用conda环境，可以快速建立python环境和切换。这里使用3.12.5版本可以运行。

![image.png](images/0647b21b-bf16-3ecb-85d4-8e62f05fb029)

进入正题，我们用IDA打开pyd文件，然后使用`shift+F12`查看字符串界面：

![image.png](images/67298f86-6159-3d05-8d29-bbf008c914ba)

注意到这里有几个rand0m开头的字符串，在题目给的py脚本中我们可以发现调用了rand0m.check函数，那么我们对rand0m.check按`x`进行交叉引用。![image.png](images/8254ed77-78ac-3970-beec-d371d17faf66)

注意到这里有几个rand0m开头的字符串，在题目给的py脚本中我们可以发现调用了rand0m.check函数，那么我们对rand0m.check按x进行交叉引用。

这里一般会出现两行，第一行引用是这个函数的包装函数，第二行才是这函数的内部实现，我们看到第二行所在的函数。函数如下：

![image.png](images/182b5dd3-2fd2-3d3d-9aef-dce1b1060b2a)

### 调试

我们下面进行调试，首先编写一个python文件去调用函数。这里注意要使用input，方便我们使用ida attach。

```
import rand0m
tmp = input()
gu = rand0m.check(tmp)
print(gu)
```

用python调用后，使用ida attach，直接搜索python，这里这个python.exe就是我们attach的目标，记得要在函数开头先下一个断点。

![image.png](images/bba055af-d016-3d9a-af44-622fe01f257e)

attach之后会停止，我们需要让他运行起来

![image.png](images/36350d06-301d-3bba-be42-c51e3b4257b2)

然后在命令行的input这里随便输入一些东西，然后回车，发现断在了我们下的断点处

![image.png](images/2a58e9df-55a3-398c-a5c7-9738c77ba219)

我们看到下面，一个PyList\_New是创建一个新的列表，参数是8就代表创建8个。第二个关于`off_7FFE92BAB688[40]`这类指针里面会储存python中的硬编码数据。

![image.png](images/9f958dfd-3a7f-3bd2-9055-ed30fbc226a7)

上图中硬编码数据可以通过ida的交叉引用查看，例如这里的`v10=off_7FFE92BAB688[40]`那么v10里面存的就是`304643896`

![image.png](images/d270b0d9-4d3e-3c66-814a-296a94c8a972)

接下来往下分析的话主要是看ida中粉色的函数，其他函数可以暂时忽略，关于粉色的函数可以看[对于cython的基础逆向分析（1） - 先知社区](https://xz.aliyun.com/t/16155?time__1311=GuD%3D7Iqmxfhx%2FD0lD2DUg7ODk%2BGC9K%2B9GAeD)的一些分析。这个程序主要是在`rand0m.rand0m`中进行处理，我们在`rand0m.rand0m`里的开头下断点。

![image.png](images/c25518e2-3d97-3431-9c39-9690409254cc)

可以查看参数a2，参数a2是个结构体，进入是数据，可以使用d将db转为dp

![image.png](images/874e710f-416b-3ad4-8656-a31efd7e0274)

就可以查看到相关的结构

![image.png](images/59da2a65-8c45-38ea-87a7-b947661fde84)

里面的结构体大概如下

```
dq 标志
dq 数据类型
dq 未知 （我猜测是数据长度）
dq 数据 （如果是列表或者元组可能会有多个）
```

看到rand0m中第一个对数据操作的api，这里是PyNumber\_Xor也就是异或

![image.png](images/3a3e06b9-a9c6-3cb2-bdb3-0ac7ed54b800)

查看v12可以发现是我们的输入，转为了16进制

![image.png](images/ce7534b4-8b72-356c-9e8d-737db517ad6d)

![image.png](images/53206a02-25ca-37ba-b959-1beece0caf99)

然后查看`off_7FFE9DAEB688[44]`是`2654435769`，那么我们可以开始手动还原函数

![image.png](images/91c9bf5a-4a51-3ee5-bfb3-6152cffe9d83)

```
def rand0m(tmp):
    tmp1 = tmp ^ 2654435769
```

下一个是右移函数，可以进去查看，这里可以看第二个参数也可以看第三个参数，那么这里可以还原为`tmp2 = tmp >> 5`

![image.png](images/e6f7f72d-2517-33f3-9988-1cad18150777)

![image.png](images/085c0ced-5c57-3f20-be53-8d8cfc348791)

再往下走可以看见一个左移，这里依旧是查看`off_7FFE9DAEB688[32]`，那么可以还原为`tmp3 = tmp << 4`，可以查看v12里面的内容确定是哪个变量

![image.png](images/8abebfee-0148-3eae-8c71-723954b54b37)

![image.png](images/ce574940-dc1b-34da-a936-66f362c51f3a)

然后是一个按位与，这里的v16就是`off_7FFE9DAEB688`，查看是`4198170623`，那么可以还原为`tmp4 = tmp3 & 4198170623`

![image.png](images/073d9104-874b-3e52-8485-1c57a86d8536)

![image.png](images/48016fe7-f178-3a63-adc7-8727922d12ca)

接下来一个右移一个相加，这里不多赘述，可以这两行可以还原为`tmp5 = tmp2 >> 23`，`tmp6 = tmp4 + tmp5`

![image.png](images/0947809d-a0bd-386f-b863-dcfa5822ecb8)

再往后一个右移一个幂和求模，还原为`tmp7 = ((tmp1 >> 11) ** 65537) % 4294967293`

![image.png](images/0c514e50-ed83-31c1-80a6-8053a0acb924)

![image.png](images/cfb923d3-d918-3ae5-be1b-4594d2ebac1c)

总结以上为

```
def rand0m_by_gh(tmp):
    tmp1 = tmp ^ 2654435769
    tmp2 = tmp >> 5
    tmp3 = tmp << 4
    tmp4 = tmp3 & 4198170623
    tmp5 = tmp2 >> 23
    tmp6 = tmp4 + tmp5
    tmp7 = ((tmp1 >> 11) ** 65537) % 4294967293
    return (tmp7, tmp6)
```

然后我们可以通过返回值来验证结果，可以发现我们还原的结果与题目相同

![image.png](images/9a1c544a-cf1f-3771-aa3b-1fcc7df17692)

## 备注

注意在取值的时候要看静态中的`off_7FFE9DAEB688[32]`，cython在动态中的数据值长度32位中只有30位是有效的，所以有可能会出现数值高位与实际值不一样的情况。
