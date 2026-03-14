# Frida Hook微信撤回功能（pc+android）-先知社区

> **来源**: https://xz.aliyun.com/news/17276  
> **文章ID**: 17276

---

# 准备

1. 安装frida，python

```
pip install frida-tools
```

2. 准备一台具有root权限的手机，或者模拟器
3. 下载frida-server，并使用adb push到手机端并运行

[GitHub - frida/frida: Clone this repo to build Frida](https://github.com/frida/frida)

```
adb push ./fs /data/local/tmp
cd /data/local/tmp
chmod 777 ./fs
```

# Frida Hook PC端微信

个人感觉PC端微信的hook比较好复现，大概的思路就是在WeChatWin.dll（微信大部分功能的库）中定位到撤回的代码，然后使用frida hook代码并修改代码（寄存器/返回值）

这部分的内容已经有帖子详细讲过了，B站上也有相关视频，所以这里简单过一下，重点还是android端的hook

1. ida打开`WeChatWin.dll`，搜索字符串revokeMsg

![Pasted image 20250316170117.png](images/74449f4b-c303-342d-8547-da372e99c471)

2. 找到引用这些字符串的代码，hook这些代码所在的函数，然后手动撤回触发逻辑，判断是否hook到

对于引用了关键字符串的函数，要**一个一个**试

```
function hookTest(){
    var addr = "0x18232BAAA"; // 这里填写需要测试的地址
    var dllbase = Module.findBaseAddress("WeChatWin.dll"); // 获取dll的基址
    console.log("dllbase: " + dllbase);

    var filebase = ptr('0x180000000'); // 这是ida显示的基址（第一行）
    var funcAddr = ptr(addr).sub(filebase).add(dllbase); // 计算实际地址

    Interceptor.attach(funcAddr, {
        onEnter: function(args) {
            console.log("hook success"); // 当有输出时说明撤回功能触发了测试地址所在函数
        }
    });
}

hookTest();
```

```
import frida
import sys

def on_message(message, data):
    print("[%s] => %s" % (message, data))

def main(target_process):
	# 附加到微信进程
    session = frida.attach(target_process)
    # 读取js代码
    with open("hookwx.js") as f:
        script = session.create_script(f.read())
    script.on("message", on_message)
    script.load()
    sys.stdin.read()

if __name__ == "__main__":
    main("WeChat.exe")
```

当触发撤回逻辑控制台输出"hook success"时说明hook对了

​

3. 当hook到目标函数时，判断具体修改的逻辑  
    这里的思路是查找交叉引用，找到调用目标函数的代码，然后判断能否修改寄存器或者返回值等

![Pasted image 20250316170801.png](images/5d1319cf-6525-3f41-b77d-085692fc42e1)

经过定位，发现函数sub\_182313480就是撤回消息的函数，其汇编代码是这样的

![Pasted image 20250316170958.png](images/d4e483b0-d1ba-358b-9f57-f6182c27de8f)

由于switch只有三个分支，所以如果想跳过调用该函数，一种思路是修改v9的值为0x4，0x21，0x24以外的值

可以看到v9对应的寄存器应该是edi（但是由于程序是64位的，所以应该是rdi）

所以可以在hook到0x18232BAAA时，修改寄存器rdi的值（比如0）

```
function hookTest(){
    var addr = "0x18232BAAA";
    var dllbase = Module.findBaseAddress("WeChatWin.dll");
    console.log("dllbase: " + dllbase);

    var filebase = ptr('0x180000000');
    var funcAddr = ptr(addr).sub(filebase).add(dllbase);

    Interceptor.attach(funcAddr, {
        onEnter: function(args) {
            console.log("hook success");
            this.context.rdi = 0x0;
        }
    });
}

hookTest();
```

python代码不变

效果如下：

![e4783f6c81879706b53f7a29917b719.jpg](images/42ff6b7c-3674-37d6-bb16-298663892503)

![Pasted image 20250316171340.png](images/63c2a32f-53d4-378e-9d69-2038c9c0b676)

# Frida Hook 安卓端微信

关于安卓端微信的hook，网上也有一些帖子，但是没有找到能够复现的，原因是在hook目标类的方法时提示找不到类，后来经过查资料发现了一种新的定位类的方法

安卓端hook的思路大体上和PC端也差不多，先根据关键词找到疑似处理撤回功能的代码，然后逐个hook，再手动触发撤回逻辑，锁定目标函数后，再根据代码具体逻辑取消撤回功能

# 定位代码

首先jadx打开微信安装包，搜索关键词revokeMsg

![Pasted image 20250317000524.png](images/e37b31ad-f67c-3ad3-a81d-341dd5b92d61)

RevokeMsgEvent看起来像是相关代码

![Pasted image 20250317000727.png](images/df577096-b525-379d-9f19-80b09141858d)

虽然只是定义，但是可以通过交叉引用找到引用这个类的代码（选中函数名称按X）

![Pasted image 20250317000947.png](images/2e8a2b1c-1fa7-3e84-8533-4a51788432fa)

可以看到只有一处调用，那么大概率就是这里了

![Pasted image 20250317000727.png](images/fcf81dc4-51c1-336f-ac45-04da31f97d66)

## 验证可疑代码

定位到可疑代码之后，还要验证下是否真的是处理撤回逻辑的代码

验证的方法：先hook可疑代码所在函数，然后手动触发撤回的逻辑

这里有个坑（就是根据网上帖子复现不了的原因）

​

以下是jadx自带的frida片段（右键函数名称“复制为frida片段”）

```
let t = Java.use("vn0.t");
t["m"].implementation = function (str, j16, p0Var, str2, str3, str4) {
    console.log('m is called' + ', ' + 'str: ' + str + ', ' + 'j16: ' + j16 + ', ' + 'p0Var: ' + p0Var + ', ' + 'str2: ' + str2 + ', ' + 'str3: ' + str3 + ', ' + 'str4: ' + str4);
    let ret = this.m(str, j16, p0Var, str2, str3, str4);
    console.log('m ret value is ' + ret);
    return ret;
};
```

如果运行以上代码，那么大概率会报错，提示找不到目标类

正确的方式应该是使用枚举拿到classloader，然后再尝试能否拿到目标类的句柄，最后再hook目标函数

代码如下

```
import frida
import sys

def on_message(message, data):
    print("[%s] => %s" % (message, data))

def main(target_process):
    session = frida.attach(target_process)
    with open("hookwx.js") as f:
        script = session.create_script(f.read())
    script.on("message", on_message)
    script.load()
    sys.stdin.read()

if __name__ == "__main__":
    main("WeChat.exe")
```

```
function test(clz) {
    console.log(clz)
    clz.m.implementation = function (str, j16, p0Var, str2, str3, str4) {
        console.log("Hook! ");
        this.m(str, j16, p0Var, str2, str3, str4);
    }
}
Java.perform(function () {
    Java.choose("dalvik.system.PathClassLoader", {
        onMatch: function (instance) {
            console.log(instance)
            var factory = Java.ClassFactory.get(instance)
            try {
                var myClass = factory.use("vn0.t")
                test(myClass)
                return "stop"
            } catch (e) {
                console.log("next")
            }
        },
        onComplete: function () {
            console.log("Done")
        }
    })
})
```

```
python hookwx.py
```

然后再手动发送信息并撤回

![Pasted image 20250317002543.png](images/0501889a-08dd-3845-91d4-80535f959d87)

可以看到已经成功hook了，说明撤回消息触发了这个函数

## 修改撤回功能

修改的方式有很多种，像是修改传入参数/寄存器/返回值，这里使用最简单粗暴的方法：取消调用

具体就是在上面代码的基础上删掉this.m(str, j16, p0Var, str2, str3, str4);

因为上面的代码在hook的时候为了不影响原本的功能，所以在输出提示之后就调用自身并传入原本的参数，这里我们不需要调用自身，自然就删掉这行代码了

完整代码

```
import frida
import sys

def on_message(message, data):
    print("[%s] => %s" % (message, data))

def main(target_process):
    session = frida.attach(target_process)
    with open("hookwx.js") as f:
        script = session.create_script(f.read())
    script.on("message", on_message)
    script.load()
    sys.stdin.read()

if __name__ == "__main__":
    main("WeChat.exe")
```

```
function foo(clz) {
    console.log(clz)
    clz.m.implementation = function (str, j16, p0Var, str2, str3, str4) {
        console.log("Hook! ");
        this.m(str, j16, p0Var, str2, str3, str4);
    }
}
Java.perform(function () {
    Java.choose("dalvik.system.PathClassLoader", {
        onMatch: function (instance) {
            console.log(instance)
            var factory = Java.ClassFactory.get(instance)
            try {
                var myClass = factory.use("vn0.t")
                foo(myClass)
                return "stop"
            } catch (e) {
                console.log("next")
            }
        },
        onComplete: function () {
            console.log("Done")
        }
    })
})
```

```
python hookwx.py
```

效果如下

![Pasted image 20250317003055.png](images/92c4e6dd-29fc-3044-a949-386f8415f388)

![8a589dc307cde93e7008c3a9134b247.jpg](images/164be6ee-83a0-32d0-893d-35c222ca8500)

​

ps：这种hook的方式相当于修改本机数据，就是说撤回的指令已经经过了服务器，本来是要删除这些撤回的信息的，但是删除的操作被程序拦截了下来
