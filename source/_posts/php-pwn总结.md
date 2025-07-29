---
title: php pwn总结
date: 2025-05-19 20:38:31
tags: [笔记, php Pwn]
hide: true
categories: 
    - 笔记
---


# 基础知识

## php配置文件

通常会通过disable_functions​和disable_classes​这两个字段禁用一些php自带的操作，使选手只能通过extension字段指定的拓展中的漏洞来拿到flag，配置不严格的disable_functions​和disable_classes可能会导致非预期解。extension字段指定的拓展是一个so文件（动态链接库）。

## php拓展开发

可通过源码ext目录中的ext_skel.php脚本创建一个模版。
```shell
./ext_skel.php --ext php_test
```

可以在`php_test.stub.php`中添加函数原型，然后使用php源码根目录下`build`目录中的`gen_stub.php`文件生成`php_test_arginfo.h`

```
// php_test.stub.php
<?php

/**
 * @generate-class-entries
 * @undocumentable
 */

function test1(): void {}

function test2(string $str = ""): string {}

function test3(string $name): string {}
```

```shell
../../build/gen_stub.php ./php_test.stub.php
```
随后在`php_test.c`中添加实现即可

创建完成后会生成后续编译的命令，可根据需求更改Makefile中的编译参数
```
Copying config scripts... done
Copying sources... done
Copying tests... done

Success. The extension is now ready to be compiled. To do so, use the
following steps:

cd /home/w4yd1/Pwn/php-pwn/php-src/ext/php_test1
phpize
./configure
make

Don't forget to run tests once the compilation is done:
make test

Thank you for using PHP!
```

更多细节可参考[这里](https://www.bookstack.cn/read/php7-internal/第7章扩展开发.md)

## php拓展导入

### 通过修改配置文件的extension

这种方法需要找到php默认的拓展路径，可通过以下命令查看：

```shell
php -i | grep -i extension_dir
```

将编译好的so文件复制到以上路径后在php.ini中加上以下行即可

`extension = numberGame.so`

### 通过命令行直接导入

通过php`-d`参数指定拓展

```shell
php -d extension=./modules/php_test.so test.php
```

## php拓展调试方法

`gdb php`进入gdp，然后通过以下命令设置参数

```gdb
set args -d extension=./modules/php_test.so test.php
```

由于拓展是在php运行时加载的，所以一开始无法定位到拓展中的函数并下断点，需要先断在php_module_startup函数，该函数执行完毕后拓展才加载进内存，具体过程如下：

```gdb
start
break php_module_startup
continue
finish
break $(拓展内函数)
```


## php拓展参数解析

### 传参约定

php需要通过zend_parse_parameters将php层的参数传递到c层，zend_parse_parameters原型如下：


```C
zend_parse_parameters(int num_args, const char *type_spec, ...);
```


- num_args为实际传参数，通过ZEND_NUM_ARGS()获取。
- type_spec是一个字符串，用来标识解析参数的类型，比如:”la”表示第一个参数为整形，第二个为数组。
- 后面是一个可变参数，用来指定解析到的变量，这个值与type_spec配合使用，即type_spec用来指定解析的变量类型，可变参数用来指定要解析到的变量，这个值必须是指针。（类似格式化字符串）

常用参数对照表：
| 类型规范符 | 对应的C语言类型 | 说明 |
|------------|-----------------|------|
| b 或 i     | int             | 整数类型，b通常表示bool类型，而i表示int类型 |
| l          | long            | 长整型 |
| d          | double          | 浮点数类型 |
| s          | char*           | 字符串，表示C语言中的字符指针 |
| S          | zend_string     | PHP 7中的 zend_string 类型字符串 |
| a          | zval*           | PHP数组类型 |
| o          | zval*           | PHP对象类型 |
| r          | zval*           | PHP资源类型 |
| z          | zval*           | PHP变量（可以是任何类型） |
| N          | 无              | 表示参数为NULL |



除了”s”、”S”之外还有两个类似的：”p”、”P”，从解析规则来看主要用于解析路径，实际与普通字符串没什么区别，尚不清楚这俩有什么特殊用法。

数组的解析也有两类，一类是解析到zval层面，另一类是解析到HashTable，其中”a”、”A”解析到的变量必须是zval，”h”、”H”解析到HashTable。

|： 表示此后的参数为可选参数，可以不传，比如​"z|l"​表示第一个参数是必需的zval类型，第二个参数是可选的long类型。


### 传参结构体

## php堆

