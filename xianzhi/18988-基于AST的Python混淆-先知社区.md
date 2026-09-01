# 基于AST的Python混淆-先知社区

> **来源**: https://xz.aliyun.com/news/18988  
> **文章ID**: 18988

---

自己写的东西，玩一玩

源码和效果放在 github 上了：<https://github.com/hahbiubiubiu/Python-Obfuscation>

## 变量名与属性名混淆

### 变量名混淆

变量名的混淆只需要在变量在代码中进行定义的地方进行替换，并在之后会使用到该变量的地方也进行替换。  
变量的AST节点为：

* 读取变量：`Name(id=xx, ctx=Load())`
* 设置变量：`Name(id=xx, ctx=Store())`  
  变量可以分为以下几类：

1. 内置变量（`__builtins__`包含的）
2. 全局变量
3. 局部变量
4. 导入模块、方法

#### 内置变量

内置变量在`__builtins__`中，可以直接使用。  
内置变量可以通过`xx in dir(__builtins__)`判断。  
混淆方法：

1. `obfname = xx`
2. `obfname = getattr(__builtins__, xx)`
3. `__builtins__.__dict__[obfname] = __builtins__.__dict__[xx]`  
   后两种可以将`obfname`指代的变量以字符串的形式出现，适合之后字符串的混淆。

#### 导入模块、方法

导入的变量有两种AST节点：`Import`和`ImportFrom`。  
`Import`的混淆方法为：

```
Import xx -> xx = __import__(xx, globals(), locals(), [], 0)
```

`ImportFrom`的混淆方法需要根据导入全部还是部分分为两种：

1. `from xx import yy, zz, ...`

```
xx = __import__(xx, globals(), locals(), [], 0)
循环：
yy = getattr(xx, yy)
...
```

1. `from xx import *`

1. 记录`xx`的所有导入项。
2. 之后出现的变量（不在内置、全局、局部变量中）如果在`xx`中，则进行`yy = getattr(xx, yy)`进行导入。

#### 全局变量和局部变量

通过是否进入了`FunctionDef`节点来判断是否处于函数定义中。

1. 在设置变量中

1. 如果不在导入变量、内置变量之列，则考虑全局或局部变量。
2. 如果处于函数定义中，则设置局部变量，否则为全局变量

2. 在读取变量中

1. 依次考虑是否为导入变量、局部变量、全局变量、内置变量以及`ImportFrom`导入模块的导入项。

### 属性名混淆

对于属性名，可以通过类似`obfname = xx.yy`或者`xx.obfname = xx.yy`的方式来混淆。  
需要区别的是处理的是模块的属性还是类的属性。

1. 模块的属性的混淆方法：`xx.__dict__[obfname] = xx.__dict__[yy]`
2. 类的属性的混淆方法：`gc.get_referents(xx.__dict__)[0][obfname] = gc.get_referents(xx.__dict__)[0][yy]`  
   当要对属性名混淆时，是出现在访问到`Attribute`的AST节点，上面混淆变量名的定义需要出现在该AST节点之前，这里设置了列表来存储为了混淆新定义的AST节点，并在访问`Module`时，添加进去。  
   这里设置了三个存储新AST节点的列表：
3. `builtin_attribute_nodes`：存储帮助`__builtins__`）的属性混淆的新节点
4. `class_attribute_nodes`：存储帮助类属性混淆的新节点
5. `module_attribute_nodes`：存储帮助模块属性混淆的新节点  
   对于`Attribute`节点，其`value`有以下几种可能：
6. `Name`节点

1. 模块是`__builtins__`：以`getattr`形式混淆
2. 属性是`__dict__`：以`getattr`形式混淆
3. 模块是导入变量：以`__dict__`形式混淆
4. 类是内置变量：以`get_referents`形式混淆
5. 其他情况，由于未做变量的类型确定，无法确定其使用的属性是在哪一个类中

7. `Constant, List, Dict`节点

1. 这三类节点对应着Python中常见的变量类型，可以直接确定其属性对应哪一个类
2. 直接以`get_referents`形式混淆

8. `Call`节点

1. 如果调用的函数未做返回值类型定义，则无法确定其使用的属性所属类

### For中的暂时变量

```
[i for i in range(10) if i % 2 == 0]
[(k, v) for k, v in xx_dict.item()]
for i in range(10):
    print(i)
```

以上代码会创建一个暂时的变量`i, k, v`，需要特殊处理一下。  
这里用处理函数中的局部变量的思路来处理，特殊处理`ListComp`、`DictComp`、`SetComp`和`For`节点。

### 代码

```
from ast import *
import astor
import random
import base64
import sys
import os
hash2str_name = None
def random_name(ori_name, isTemp=False) -> str:
    r = ori_name + '_' + str(random.randint(0, 10))
    print(f"random_name: {ori_name} -> {r}")
    return r
    # length = 24
    # num = random.randint(0, 2 ** length)
    # binary_str = format(num, '0%db' % length)
    # binary_str = 'o' + binary_str.replace('0', '0').replace('1', 'o')
    # return binary_str
def str2hash(input):
    CUSTOM_ALPHABET = '-_+!1@2#3$4%5^6&7*8(9)0qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFG'.encode()
    STANDARD_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'.encode()
    ENCODE_TRANS = bytes.maketrans(STANDARD_ALPHABET, CUSTOM_ALPHABET)
    return base64.b64encode(input.encode()).translate(ENCODE_TRANS).decode()
class Obfuscator(NodeTransformer):
    def __init__(self) -> None:
        super().__init__()
        # decide if in function
        self.inFunction = False
        # decide if use temp var
        self.inTemp = False
        # record obfuscated names of vars
        self.import_var = {}
        self.builtin_var = {}
        self.attribute_var = {}
        self.local_var = {}
        self.global_var = {
            "getattr": random_name("getattr"),
            "__builtins__": random_name("__builtins__"),
        }
        self.temp_var = {}
        # imported attributes of modules
        self.importFrom_module = {}
        # assign nodes for import modules
        self.import_nodes = []
        # assign nodes for attributes of class
        self.class_attribute_nodes = []
        # assign nodes for attributes of imported modules
        self.module_attribute_nodes = []
        # assign nodes for attributes of builtins
        self.builtin_attribute_nodes = []
        # initiation for utils
        self.init_body = [
            ImportFrom(
                module='gc',
                names=[alias(name='get_referents')],
                level=0
            ),
        ]
        self.init_body += [
            Import(names=[alias(name='base64')]), 
            FunctionDef(
                name='hash2str', 
                args=arguments(
                    posonlyargs=[], 
                    args=[arg(arg='ptext')], 
                    kwonlyargs=[], kw_defaults=[], defaults=[]
                ), 
                body=[
                    Assign(
                        targets=[Name(id='CUSTOM_ALPHABET', ctx=Store())], 
                        value=Call(
                            func=Attribute(
                                value=Constant(value='-_+!1@2#3$4%5^6&7*8(9)0qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFG'), 
                                attr='encode', 
                                ctx=Load()
                            ), 
                            args=[], keywords=[]
                        )
                    ), 
                    Assign(
                        targets=[Name(id='STANDARD_ALPHABET', ctx=Store())], 
                        value=Call(
                            func=Attribute(
                                value=Constant(value='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'), 
                                attr='encode', 
                                ctx=Load()
                            ), 
                            args=[], keywords=[]
                        )
                    ), 
                    Assign(
                        targets=[Name(id='DECODE_TRANS', ctx=Store())], 
                        value=Call(
                            func=Attribute(value=Name(id='bytes', ctx=Load()), attr='maketrans', ctx=Load()), 
                            args=[
                                Name(id='CUSTOM_ALPHABET', ctx=Load()), 
                                Name(id='STANDARD_ALPHABET', ctx=Load())
                            ], 
                            keywords=[]
                        )
                    ), 
                    Return(
                        value=Call(
                            func=Attribute(
                                value=Call(
                                    func=Attribute(value=Name(id='base64', ctx=Load()), attr='b64decode', ctx=Load()), 
                                    args=[
                                        Call(
                                            func=Attribute(value=Name(id='ptext', ctx=Load()), attr='translate', ctx=Load()), 
                                            args=[Name(id='DECODE_TRANS', ctx=Load())], keywords=[]
                                        )
                                    ], 
                                    keywords=[]
                                ), 
                                attr='decode', ctx=Load()
                            ), 
                            args=[], keywords=[]
                        )
                    )
                ], 
                decorator_list=[]
            )
        ] if stringObf else []
        self.first_body = [
            # __builtins__obfname = eval("__builtins__")
            Assign(
                targets=[Name(id=self.global_var['__builtins__'], ctx=Store())],
                value=Call(
                    func=Name(id='eval', ctx=Load()), 
                    args=[Constant(value='__builtins__')], 
                    keywords=[]
                )
            ),
            # getattr_obfname = eval("getattr")
            Assign(
                targets=[Name(id=self.global_var['getattr'], ctx=Store())],
                value=Call(
                    func=Name(id='eval', ctx=Load()), 
                    args=[Constant(value='getattr')], 
                    keywords=[]
                )
            ),
        ]
    def visit_Module(self, node: Module) -> Module:
        node.body = self.init_body + node.body
        node.body = [self.visit(child) for child in node.body]
        final_body = []
        final_body += self.first_body
        final_body += self.builtin_attribute_nodes
        final_body += self.import_nodes
        final_body += self.module_attribute_nodes
        final_body += self.class_attribute_nodes
        final_body += node.body
        node.body = final_body
        return node
    
    def set_attribute_for_class(self, class_, attr_):
        if f"{class_}_{attr_}" in self.attribute_var:
            return self.attribute_var[f"{class_}_{attr_}"]
        # get_referents(class_.__dict__)[0][obfname] = get_referents(class_.__dict__)[0][attr]
        obfname = random_name(f"{class_}_{attr_}")
        self.attribute_var[f"{class_}_{attr_}"] = obfname
        print(f"get_referents({class_}.__dict__)[0]['{obfname}'] = get_referents({class_}.__dict__)[0]['{attr_}']")
        new_node = Assign(
            targets=[Subscript(
                value=Subscript(
                    value=Call(
                        func=Name(id='get_referents', ctx=Load()),
                        args=[Attribute(value=Name(id=class_, ctx=Load()), attr='__dict__', ctx=Load())], 
                        keywords=[]
                    ),
                    slice=Constant(value=0), ctx=Load()
                ),
                slice=Constant(value=obfname), ctx=Store()
            )],
            value=Subscript(
                value=Subscript(
                    value=Call(
                        func=Name(id='get_referents', ctx=Load()),
                        args=[Attribute(value=Name(id=class_, ctx=Load()), attr='__dict__', ctx=Load())], 
                        keywords=[]
                    ),
                    slice=Constant(value=0), ctx=Load()
                ),
                slice=Constant(value=attr_), ctx=Load()
            )
        )
        self.visit(new_node)
        self.class_attribute_nodes.append(new_node)
        return obfname
    def set_attribute_for_module(self, _module, _attr):
        if f"{_module}_{_attr}" in self.attribute_var:
            return self.attribute_var[f"{_module}_{_attr}"]
        obfname = random_name(f"{_module}_{_attr}")
        self.attribute_var[f"{_module}_{_attr}"] = obfname
        # _module.__dict__[obfname] = _module.__dict__[_attr]
        print(f"{_module}.__dict__['{obfname}'] = {_module}.__dict__['{_attr}']")
        new_node = Assign(
            targets=[Subscript(
                value=Attribute(
                    value=Name(id=_module, ctx=Load()), 
                    attr='__dict__', ctx=Load()
                ),
                slice=Constant(value=obfname), ctx=Store()
            )],
            value=Subscript(
                value=Attribute(
                    value=Name(id=_module, ctx=Load()), 
                    attr='__dict__', ctx=Load()
                ),
                slice=Constant(value=_attr), ctx=Load()
            )
        )
        new_node = self.visit(new_node)
        if _module == '__builtins__':
            self.builtin_attribute_nodes.append(new_node)
        else:
            self.module_attribute_nodes.append(new_node)
        return obfname
    def set_importfrom_node(self, _module, _attr):
        if _attr in self.import_var:
            return self.import_var[_attr]    
        self.import_var[_attr] = random_name(f"{_module}_{_attr}")
        # obfname = getattr(_module, attr)
        print(f"set_importfrom_node: getattr({self.import_var[_module]}, '{_attr}')")
        new_node = Assign(
            targets=[Name(id=_attr, ctx=Store())],
            value=Call(
                func=Name(id='getattr', ctx=Load()), 
                args=[
                    Name(id=_module, ctx=Load()), 
                    Constant(value=_attr)
                ],
                keywords=[]
            )
        )
        new_node = self.visit(new_node)
        self.import_nodes.append(new_node)
        return self.import_var[_attr]
    def visit_FunctionDef(self, node: FunctionDef) -> FunctionDef:
        name = node.name
        if name not in self.global_var:
            self.global_var[name] = random_name(name)
        node.name = self.global_var[name]
        self.inFunction = True
        self.local_var = {k.arg: random_name(k.arg) for k in node.args.args}
        node.args.args = [arg(arg=self.local_var[k.arg]) for k in node.args.args]
        node.body = [self.visit(child) for child in node.body]
        self.inFunction = False
        self.local_var = None
        return node
    def visit_Import(self, node: Import):
        print(f"Visit Import: {node.names[0].name}")
        if node.names[0].name in self.import_var:
            return None
        name = node.names[0].name
        if name not in self.import_var:
            self.import_var[name] = random_name(name)
        print(f"Import: {name} -> {self.import_var[name]}")
        # obfname = __import__(name, globals(), locals(), [], 0)
        new_node = Assign(
            targets=[Name(id=name, ctx=Store())],
            value=Call(
                func=Name(id='__import__', ctx=Load()),
                args=[
                    Constant(value=name),
                    Call(func=Name(id='globals', ctx=Load()), args=[], keywords=[], starargs=None, kwargs=None),
                    Call(func=Name(id='locals', ctx=Load()), args=[], keywords=[], starargs=None, kwargs=None),
                    List(elts=[], ctx=Load()),
                    Constant(value=0)
                ],
                keywords=[], starargs=None, kwargs=None
            )
        )
        new_node = self.visit(new_node)
        self.import_nodes.append(new_node)
        return None
    
    def visit_ImportFrom(self, node: ImportFrom):
        if node.module not in self.import_var:
            # import xx -> xx = __import__(xx, globals(), locals(), [], 0)
            n1 = Import(names=[alias(name=node.module)])
            self.visit(n1)
        if node.names[0].name == "*":
            # from module import *
            module = __import__(node.module, globals(), locals(), [], 0)
            module_attributes = getattr(module, "__all__", [name for name in dir(module) if not name.startswith('_')])
            self.importFrom_module[node.module] = module_attributes
            # import when use
        else:
            # from module import attr1, attr2...
            for attr in node.names:
                self.set_importfrom_node(node.module, attr.name)
        return None
    
    def visit_Attribute(self, node: Attribute):
        if isinstance(node.value, Name):
            print(f"Visit Attribute: {node.value.id}.{node.attr}")
            if node.attr == "__dict__" or node.value.id == "__builtins__":
                if f"@attr_{node.value.id}_{node.attr}" not in self.global_var:
                    self.global_var[f"@attr_{node.value.id}_{node.attr}"] = random_name(f"{node.value.id}_{node.attr}")
                    # obfname = getattr(__builtins__, _module)
                    print(f"{self.global_var[f'@attr_{node.value.id}_{node.attr}']} = getattr({node.value.id}, '{node.attr}')")
                    new_node = Assign(
                        targets=[Name(id=f"@attr_{node.value.id}_{node.attr}", ctx=Store())],
                        value=Call(
                            func=Name(id='getattr', ctx=Load()), 
                            args=[
                                Name(id=node.value.id, ctx=Load()), 
                                Constant(value=node.attr)
                            ], 
                            keywords=[]
                        )
                    )
                    new_node = self.visit(new_node)
                    if node.value.id == "__builtins__":
                        self.builtin_attribute_nodes.append(new_node)
                    elif node.value.id in self.import_var:
                        self.module_attribute_nodes.append(new_node)
                    else:
                        self.class_attribute_nodes.append(new_node)
                return Name(
                    id=self.global_var[f"@attr_{node.value.id}_{node.attr}"],
                    ctx=Load()
                )
            elif node.value.id in self.import_var:
                # attribute of imported module
                node.attr = self.set_attribute_for_module(node.value.id, node.attr)
            elif node.value.id in dir(__builtins__):
                # attribute of builtins class
                node.attr = self.set_attribute_for_class(node.value.id, node.attr)
            else:
                # attribute of variable
                # check = False
                # for _class in [str, int, list, dict, bytes]:
                #     if node.attr in dir(_class):
                #         node.attr = self.set_attribute_for_class(_class.__name__, node.attr)
                #         check = True
                # if not check:
                print(dump(node, indent=4))
                print(f"Attribute: {node.attr} - {node.value.id} can not obfuse!")
        elif isinstance(node.value, Constant):
            node.attr = self.set_attribute_for_class(
                type(node.value.value).__name__, 
                node.attr
            )
        elif isinstance(node.value, List) or isinstance(node.value, Dict):
            node.attr = self.set_attribute_for_class(
                type(node.value).__name__.lower(), 
                node.attr
            )
        elif isinstance(node.value, Call):
            # Can't get the type of Call return value
            pass
        # modify value name to obfuscated name
        node.value = self.visit(node.value)
        return node
    
    def visit_ListComp(self, node: ListComp) -> ListComp:
        print(f"Visit ListComp")
        self.inTemp = True
        for g in node.generators:
            if isinstance(g.target, Name):
                self.temp_var[g.target.id] = random_name(g.target.id, isTemp=True)
                g.target.id = self.temp_var[g.target.id]
            elif isinstance(g.target, Tuple):
                for i in g.target.elts:
                    self.temp_var[i.id] = random_name(i.id, isTemp=True)
                    i.id = self.temp_var[i.id]
            g.iter = self.visit(g.iter)
            for i in g.ifs:
                i = self.visit(i)
        self.visit(node.elt)
        self.inTemp = False
        self.temp_var = {}
        return node
    def visit_DictComp(self, node: DictComp) -> DictComp:
        print(f"Visit DictComp")
        self.inTemp = True
        for g in node.generators:
            if isinstance(g.target, Name):
                self.temp_var[g.target.id] = random_name(g.target.id, isTemp=True)
                g.target.id = self.temp_var[g.target.id]
            elif isinstance(g.target, Tuple):
                for i in g.target.elts:
                    self.temp_var[i.id] = random_name(i.id, isTemp=True)
                    i.id = self.temp_var[i.id]
            g.iter = self.visit(g.iter)
            for i in g.ifs:
                i = self.visit(i)
        self.visit(node.key)
        self.visit(node.value)
        self.inTemp = False
        self.temp_var = {}
        return node
    
    def visit_SetComp(self, node: SetComp) -> SetComp:
        print(f"Visit SetComp")
        self.inTemp = True
        for g in node.generators:
            if isinstance(g.target, Name):
                self.temp_var[g.target.id] = random_name(g.target.id, isTemp=True)
                g.target.id = self.temp_var[g.target.id]
            elif isinstance(g.target, Tuple):
                for i in g.target.elts:
                    self.temp_var[i.id] = random_name(i.id, isTemp=True)
                    i.id = self.temp_var[i.id]
            g.iter = self.visit(g.iter)
            for i in g.ifs:
                i = self.visit(i)
        self.visit(node.elt)
        self.inTemp = False
        self.temp_var = {}
        return node
    def visit_For(self, node: For) -> For:
        print(f"Visit For")
        self.inTemp = True
        if isinstance(node.target, Name):
            self.temp_var[node.target.id] = random_name(node.target.id, isTemp=True)
            node.target.id = self.temp_var[node.target.id]
        elif isinstance(node.target, Tuple):
            for i in node.target.elts:
                self.temp_var[i.id] = random_name(i.id, isTemp=True)
                i.id = self.temp_var[i.id]
        node.iter = self.visit(node.iter)
        node.body = [self.visit(child) for child in node.body]
        node.orelse = [self.visit(child) for child in node.orelse]
        self.inTemp = False
        self.temp_var = {}
        return node
    def visit_Name(self, node: Name) -> Name:
        name = node.id
        print(f"Visit Name: {name} {type(node.ctx).__name__}")
        if isinstance(node.ctx, Load):
            if name == '__name__':
                pass
            elif self.inTemp and name in self.temp_var:
                node.id = self.temp_var[name]
            elif name in self.import_var:
                node.id = self.import_var[name]
            elif self.inFunction and name in self.local_var:
                node.id = self.local_var[name]
            elif name in self.global_var:
                node.id = self.global_var[name]
            elif name in dir(__builtins__) and name != "getattr":
                node.id = self.set_attribute_for_module('__builtins__', name)
            else:
                for m, a in self.importFrom_module.items():
                    if name in a:
                        node.id = self.set_importfrom_node(m, name)
                        break
                else:
                    assert False, f"Name(Load): {name} not found!"
        elif isinstance(node.ctx, Store):
            if name in self.import_var:
                node.id = self.import_var[name]
            elif name in dir(__builtins__) and name != "getattr":
                node.id = self.set_attribute_for_module('__builtins__', name)
            elif self.inFunction and not name.startswith("@attr_"):
                # if in function, local var
                # if attribute of class, pass
                if name not in self.local_var:
                    self.local_var[name] = random_name(name)
                node.id = self.local_var[name]
                print(f"Local var not found: {name} -> {self.local_var[name]}")
            elif name in self.global_var:
                node.id = self.global_var[name]
            else:
                self.global_var[name] = random_name(name)
                node.id = self.global_var[name]
                print(f"Name(Store) not found: {name} -> {self.global_var[name]}")
        
        print(f"Visit Name: {name} {type(node.ctx).__name__} -> {node.id}")
        # print(dump(node, indent=4))
        return node
        
if __name__ == '__main__':
    if len(sys.argv) > 1:
        file_name = sys.argv[1]
        # file_name = os.path.basename(file_name)
        print(f"Begin obfuse {file_name}...")
    else:
        print("Usage: python obfuscate.py <file>")
        sys.exit(1)
    with open(file_name, 'r', encoding='utf-8') as f:
        tree = parse(f.read())
    obf = Obfuscator()
    tree = obf.visit(tree)
    obf_code = astor.to_source(tree)
    output = os.path.join(os.path.dirname(file_name), f"obf_{os.path.basename(file_name)}")
    with open(output, 'w') as f:
        f.write(obf_code)
    print(f"Output file: {output}")
```

## 控制流混淆

利用 `ollvm` 的控制流混淆思路，在 `py2cfg` 和 `ast` 的基础上实现。  
混淆的单位为函数。

### 思路

通过 `py2cfg` 获取每个函数的控制流图。

#### 修改控制流

在每个函数中遍历基本块，梳理控制流图。  
对每个基本块进行如下操作：

1. 字典保存每个块一个ID（由自定义随机数生成器生成），作为 OLLVM 中的 `switchVar`；
2. 对为循环节点的基本块进行特殊处理；

1. 判断循环头（`While` 或 `For`）是否有多个后继节点：

1. 有一个后继节点（只能是循环体中的节点）：

1. 代表循环结束后，没有其他语句（类似存在一个`Return None`）；
2. 生成一个含 `Return None` 的后继基本块作为循环结束的下一个节点。

2. 有两个后继节点：

1. 一般第一个后继块为循环体中第一个节点；
2. 一般第二个后继块为循环结束的下一个节点。

2. BFS 搜索循环体中的所有基本块：

1. 加入队列的条件：非循环头节点、非循环结束的下一个节点、非遍历过的节点；
2. 对于遍历到的节点：

1. 对于循环体后仍有节点的情况：

1. 如果后继节点为循环结束的下一个节点，则其为 `break` 节点；

2. 对于循环体后没有节点的情况：

1. 如果后继节点数为 0：

1. 如果其含 `Return` 语句，则不用管；
2. 如果其含 `Break` 语句，则其为 `break` 节点。

3. 处理 `break` 节点：

1. 如果该节点有多条语句，则删去 `break` 语句；
2. 如果只有一条语句，则删去该节点，并且将该节点的前驱节点连接到后续节点（保留条件跳转关系）。

4. 寻找并处理 `continue` 节点：

1. 所有不在循环体中且为循环头节点的前驱节点，为 `continue` 节点；
2. 处理方法与 `break` 节点相同。

5. 对循环头为 `While` 节点进行处理：

1. 如果 `While` 节点的判断为 `Compare`（有条件的 `While`）：

1. 生成一个 `If` 节点，条件与 `While` 节点相同；
2. 复制 `While` 节点的跳转关系；
3. 增加跳转：`If` 节点 -> 循环结束的下一个节点。

2. 如果 `While` 节点的判断为永真式（无条件的 `While`）：

1. 在 `While` 的所有前驱节点中：

1. 在循环体中的，为循环体中的最后一个节点；

1. 这些节点可能是因为执行完循环体回到 `While` 节点，也可能是执行 `continue` 提前回到 `While` 节点；

2. 不在循环体中的，为执行循环体前的节点；
3. 更新节点连接情况：条件跳转关系需保留

1. 删除：执行循环体前的节点 -> `While` 节点；
2. 增加：执行循环体前的节点 -> 循环体中第一个节点；
3. 删除：`While` 节点 -> 循环体中第一个节点；
4. 删除：循环体中的最后一个节点 -> `While` 节点；
5. 增加：循环体中的最后一个节点 -> 循环体中的第一个基本块。

6. 对循环头为 `For` 节点进行处理：

1. 要将 `for` 改为 `iter + next + if + break` 的形式；
2. 在 `For` 的所有前驱节点中：

1. 在循环体中的，为循环体中的最后一个节点；
2. 不在循环体中的，为执行循环体前的节点；

3. 生成 `iter` 节点：`iter_var = iter(for_iter)`；
4. 生成 `next` 节点： `step_var = next(iter_var, None)`;
5. 生成 `if` 节点： `if step_var is not None`;
6. 生成 `assign` 节点： `for_target = step_var`;
7. 更新节点连接情况：条件跳转关系需保留

1. 删除：循环体中的最后一个节点 -> 循环头节点；
2. 增加：循环体中的最后一个节点 -> `iter` 节点；
3. 增加：`iter` 节点 -> `next` 节点；
4. 增加： `next` 节点 -> `if` 节点；
5. 增加： `if` 节点 -> `assign` 节点；

1. 跳转条件为 `if` 节点自身的。

6. 增加： `if` 节点 -> 循环结束的下一个节点；

1. 跳转条件与 `if` 节点自身的相反。

7. 增加： `assign` 节点 -> 循环体中第一个节点；
8. 删除：循环体中的最后一个节点 -> 循环头节点；
9. 增加：循环体中的最后一个节点 -> `next` 节点；

#### 控制流混淆

1. 生成一个 `Assign` 语句，为 `switchVar` 赋初始值；
2. 生成一个结束循环的 `if-break` 语句，作为逻辑结束点；
3. 目前无限循环体中只有一个 `if-break` 语句节点；

1. 遍历函数的每一个基本块：

1. 如果后继节点数为 0：

```
if switch_var == xxx: # 当前节点对应的值
    节点语句
    switch_var = 逻辑结束点对应的值
```

1. 如果后继节点数为 1：

```
if switch_var == xxx: # 当前节点对应的值
    节点语句
    switch_var = 后继节点对应的值
```

1. 如果后继节点数为 2：

```
if switch_var == xxx: # 当前节点对应的值
    节点语句（除了 if）
    if if_test:    
        switch_var = 条件1对应的节点
    else:
        siwtch_var = 条件2对应的节点
```

1. `if` 的两个分支的跳转条件要与节点的条件跳转关系相同。

1. 新的 `If` 节点 加入到循环体中。

1. 生成无限循环体；
2. `Assign` 语句和无限循环体 构成该函数的新逻辑。
3. 直接在 `FunctionDef` 的 AST 节点中替换新逻辑。

### 代码

```
import os
import random
import sys
from ast import *
from py2cfg import CFGBuilder

class LCG:
    def __init__(self, seed=123, max_value=0xFFFFFFFF):
        self.count = 0
        self.seed = seed
        self.max = max_value
        self.period = self._get_next_power_of_two(max_value)
        self.a = 5
        self.c = 1
        self.m = self.period + 1  # 模数，确保是2的幂
        self.current = seed
        
    def _get_next_power_of_two(self, x):
        """计算大于等于x的最小2的幂减1"""
        if x <= 0:
            return 0
        return (1 << (x.bit_length())) - 1
    def generate(self):
        if self.count > self.period:
            raise Exception("no more unique numbers")
        
        # 线性同余公式：next = (a * current + c) % m
        self.current = (self.a * self.current + self.c) % self.m
        self.count += 1
        return self.current if self.current <= self.max else self.generate()
def del_edge(block, ori_target):
    for edge in block.exits:
        if edge.target is ori_target:
            # 有条件跳转的边需要 exitcase
            exitcase = edge.exitcase
            block.exits.remove(edge)
            return exitcase
def handle_break_or_continue(block):
    if len(block.statements) == 1:
        # 删去这个 block
        for pred in block.predecessors:
            exitcase = del_edge(pred.source, block)
            pred.source.add_exit(block.exits[0].target, exitcase)
    else:
        # 删去 block 中的 break 或 continue
        block.statements.pop()
def control_flow_obfuscate(file_path):
    num_gen = LCG()
    cfgbuilder = CFGBuilder()
    cfg = cfgbuilder.build_from_file(f"{file_path}", file_path)
    blocks_state = {}
    func_blocks = {}
    for func_name, func_cfg in cfg.functioncfgs.items():
        func_blocks[func_name] = []
        for block in func_cfg:
            if block in blocks_state:
                continue
            if isinstance(block.statements[0], (While, For)):
                if len(block.exits) == 2:
                    # 一般 block 的第二个后继块为循环结束的下一个 block
                    next_block_after_loop = block.exits[1].target
                else:
                    # 如果循环结束, 没有下一个 block, 新建一个
                    next_block_after_loop = cfgbuilder.new_block()
                    next_block_after_loop.add_statement(
                        fix_missing_locations(Return(value=None))
                    )
                
                # 广度优先遍历循环体所有 block
                blocks_in_loop = set()
                break_blocks = []
                queue = [succ.target for succ in block.exits]
                while queue:
                    b = queue.pop()
                    if b is block: continue
                    if b is next_block_after_loop: continue
                    if b in blocks_in_loop: continue
                    blocks_in_loop.add(b)
                    queue.extend([succ.target for succ in b.exits])
                    # 循环体后仍有 block 的情况
                    for succ in b.exits:
                        if succ.target is next_block_after_loop:
                            break_blocks.append(b)
                    # 循环体后没有 block 的情况
                    # 可能 break 或 return
                    if len(b.exits) == 0:
                        if isinstance(b.statements[-1], Return):
                            # return 语句 不用管
                            continue
                        elif isinstance(b.statements[-1], Break):
                            b.add_exit(next_block_after_loop)
                            break_blocks.append(b)
                # 处理 break, continue
                for b in break_blocks:
                    handle_break_or_continue(b)
                for pred in block.predecessors:
                    b = pred.source
                    if b not in blocks_in_loop: continue
                    if not isinstance(b.statements[-1], Continue): continue
                    handle_break_or_continue(b)
                
            else:
                func_blocks[func_name].append(block)
                blocks_state[block] = num_gen.generate()
                continue
            if isinstance(block.statements[0], While):
                while_stmt = block.statements[0]
                if isinstance(while_stmt.test, Compare):
                    if_block = cfgbuilder.new_block()
                    if_block.add_statement(fix_missing_locations(If(
                        test=while_stmt.test,
                        body=[], # no need
                    )))
                    # copy while block的关系
                    for succ in block.exits:
                        exitcase = del_edge(block, succ.target)
                        if_block.add_exit(succ.target, exitcase)
                    for pred in block.predecessors:
                        if_block.predecessors.append(pred.source)
                        exitcase = del_edge(pred.source, block)
                        pred.source.add_exit(if_block, exitcase)
                    if_block.add_exit(next_block_after_loop)
                    func_blocks[func_name].append(if_block)
                    blocks_state[if_block] = num_gen.generate()
                elif isinstance(while_stmt.test, Constant) and while_stmt.test.value is True:
                    # while block 的第一个后继块通常为 while 循环体第一个块
                    first_block_in_loop = block.exits[0].target
                    last_block_before_loop, last_block_in_loop = [], []
                    for pred in block.predecessors:
                        if pred.source in blocks_in_loop:
                            last_block_in_loop.append(pred.source)
                        else:
                            last_block_before_loop.append(pred.source)
                    # last_block_in_loop -x-> block
                    # last_block_before_loop -> first_block_in_loop
                    for lbfw in last_block_before_loop:
                        exitcase = del_edge(lbfw, block)
                        lbfw.add_exit(first_block_in_loop, exitcase)
                    # block -x-> first_block_in_loop
                    del_edge(block, first_block_in_loop)
                    # last_block_in_loop -> first_block_in_loop
                    for lbiw in last_block_in_loop:
                        exitcase = del_edge(lbiw, block)
                        lbiw.add_exit(first_block_in_loop, exitcase)
                else:
                    assert False, "while test type error"
            elif isinstance(block.statements[0], For):
                # for -> (iter + next + if + break)
                for_stmt = block.statements[0]
                iter_var = f"for_iter_{num_gen.generate()}"
                step_var = f"for_step_{num_gen.generate()}"
                
                # last_blocks_in_loop: 循环体最后一个块
                # last_blocks_before_loop: 循环体前最后一个块
                last_blocks_in_loop, last_blocks_before_loop = [], []
                for pred in block.predecessors:
                    if pred.source in blocks_in_loop:
                        last_blocks_in_loop.append(pred.source)
                    else:
                        last_blocks_before_loop.append(pred.source)
                
                # iter_var = iter(for_stmt.iter)
                iter_stmt = Assign(
                    targets=[Name(id=iter_var, ctx=Store())],
                    value=Call(
                        func=Name(id="iter", ctx=Load()),
                        args=[for_stmt.iter],
                        keywords=[]
                    )
                )
                iter_block = cfgbuilder.new_block()
                iter_block.add_statement(fix_missing_locations(iter_stmt))
                # step_var = next(iter_var, None)
                next_stmt = Assign(
                    targets=[Name(id=step_var, ctx=Store())],
                    value=Call(
                        func=Name(id="next", ctx=Load()),
                        args=[
                            Name(id=iter_var, ctx=Load()),
                            Constant(value=None)
                        ],
                        keywords=[]
                    )
                )
                next_block = cfgbuilder.new_block()
                next_block.add_statement(fix_missing_locations(next_stmt))
                # if step_var is not None:
                if_stmt = If(
                    test=Compare(
                        left=Name(id=step_var, ctx=Load()),
                        ops=[IsNot()],
                        comparators=[Constant(value=None)]
                    ),
                    body=[], orelse=[]
                )
                if_block = cfgbuilder.new_block()
                if_block.add_statement(fix_missing_locations(if_stmt))
                # idx = step_var
                idx_assign_stmt = Assign(
                    targets=[for_stmt.target],
                    value=Name(id=step_var, ctx=Load())
                )
                idx_assign_block = cfgbuilder.new_block()
                idx_assign_block.add_statement(fix_missing_locations(idx_assign_stmt))
                # 增添控制流边, 移除原来的边
                # last_blocks_before_loop -> iter
                # last_blocks_before_loop -X-> block
                for lb in last_blocks_before_loop:
                    exitcase = del_edge(lb, block)
                    lb.add_exit(iter_block, exitcase)
                # iter -> next
                iter_block.add_exit(next_block)
                # next -> if
                next_block.add_exit(if_block)
                # if -> idx_assign
                if_block.add_exit(
                    idx_assign_block,
                    fix_missing_locations(if_stmt.test)
                )
                # if -> next_block_after_loop
                if_block.add_exit(
                    next_block_after_loop,
                    fix_missing_locations(Compare(
                        left=Name(id=step_var, ctx=Load()),
                        ops=[Is()],
                        comparators=[Constant(value=None)]
                    ))
                )
                # idx_assign -> first block in loop
                first_block_in_loop = block.exits[0].target
                idx_assign_block.add_exit(first_block_in_loop)
                # last_blocks_in_loop -> next
                # last_blocks_in_loop -X-> block
                for lb in last_blocks_in_loop:
                    exitcase = del_edge(lb, block)
                    lb.add_exit(next_block, exitcase)
                # block -X-> first_block_in_loop
                block.exits = []
                func_blocks[func_name].append(iter_block)
                func_blocks[func_name].append(next_block)
                func_blocks[func_name].append(if_block)
                func_blocks[func_name].append(idx_assign_block)
                blocks_state[iter_block] = num_gen.generate()
                blocks_state[next_block] = num_gen.generate()
                blocks_state[if_block] = num_gen.generate()
                blocks_state[idx_assign_block] = num_gen.generate()

    func_new_bodys = {}
    for func_name, blocks in func_blocks.items():
        print(f"Function: {func_name}")
        switch_assign = Assign(
            targets=[Name(id='state', ctx=Store())],
            value=Constant(value=blocks_state[blocks[0]])
        )
        end_case_state = num_gen.generate()
        end_case_stmt = If(
            test=Compare(
                left=Name(id='state', ctx=Load()),
                ops=[Eq()],
                comparators=[Constant(value=end_case_state)]
            ),
            body=[
                Break()
            ],
            orelse=[]
        )
        loop_body = [end_case_stmt]
        for idx, block in enumerate(blocks):
            if len(block.exits) == 0:
                if_body = block.statements
                if not isinstance(if_body[-1], Return):
                    if_body.append(
                        Assign(
                            targets=[Name(id='state', ctx=Store())],
                            value=Constant(value=end_case_state)
                        )
                    )
            elif len(block.exits) == 1:
                if_body = block.statements
                if_body.append(Assign(
                    targets=[Name(id='state', ctx=Store())],
                    value=Constant(value=blocks_state[block.exits[0].target])
                ))
            elif len(block.exits) == 2:
                if_test = block.statements[-1].test
                if if_test is block.exits[0].exitcase:
                    sb_state = [
                        blocks_state[block.exits[0].target], 
                        blocks_state[block.exits[1].target]
                    ]
                elif if_test is block.exits[1].exitcase:
                    sb_state = [
                        blocks_state[block.exits[1].target], 
                        blocks_state[block.exits[0].target]
                    ]
                else:
                    assert False, "Invalid if statement"
                ori_if_stmt = block.statements[-1]
                new_if_stmt = If(
                    test=ori_if_stmt.test,
                    body=[
                        Assign(
                            targets=[Name(id='state', ctx=Store())],
                            value=Constant(value=sb_state[0])
                        ),
                    ],
                    orelse=[
                        Assign(
                            targets=[Name(id='state', ctx=Store())],
                            value=Constant(value=sb_state[1])
                        ),
                    ]
                )
                if_body = block.statements[:-1]
                if_body.append(new_if_stmt)
            case_stmt = If(
                test=Compare(
                    left=Name(id='state', ctx=Load()),
                    ops=[Eq()],
                    comparators=[Constant(value=blocks_state[block])]
                ),
                body=if_body,
                orelse=[]
            )
            loop_body.append(case_stmt)
        random.shuffle(loop_body)
        loop = While(
            test=Constant(value=True),
            body=loop_body,
            orelse=[]
        )
        func_new_bodys[func_name] = [switch_assign, loop]
    
    return func_new_bodys
class Obfuscator(NodeTransformer):
    def __init__(self, func_new_bodys=None):
        super().__init__()
        self.func_new_bodys = func_new_bodys
    def visit_FunctionDef(self, node):
        if self.func_new_bodys and node.name in self.func_new_bodys:
            node.body = self.func_new_bodys[node.name]
        self.generic_visit(node)
        return node

if __name__ == '__main__':
    if len(sys.argv) > 1:
        file_name = sys.argv[1]
        print(f"Begin obfuse {file_name}...")
    else:
        print("Usage: python obfuscate.py <file>")
        sys.exit(1)
    with open(file_name, 'r', encoding='utf-8') as f:
        tree = parse(f.read())
    func_new_bodys = control_flow_obfuscate(file_name)
    obf = Obfuscator(func_new_bodys)
    tree = obf.visit(tree)
    tree = fix_missing_locations(tree)
    obf_code = unparse(tree)
    output = os.path.join(os.path.dirname(file_name), f"obf_{os.path.basename(file_name)}")
    with open(output, 'w', encoding="utf-8") as f:
        f.write(obf_code)
    print(f"Output file: {output}")
```
