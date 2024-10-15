---
title: >-
  DONAPI: Malicious NPM Packages Detector using Behavior Sequence Knowledge
  Mapping
date: 2024-10-15 14:46:49
tags: [论文阅读, 恶意软件包检测, Malicious Package Detection]
categories: 
    - 论文阅读
    - 恶意软件包检测
---

# 恶意软件包如何被下载到本地的

## 名称相似包

攻击者上传一个名字和公开软件包相似的包，例如上传一个恶意包并且命名为`Pythom`，当用户需要下载`Python`却打错字为`Pythom`时，恶意软件包就会被下载。

## 依赖混淆

攻击者上传一个被其它包依赖的同名恶意软件包，但是该恶意软件包拥有更高的版本号，用户同步包时会选择版本更高的那个，此时恶意软件包就会被下载。

## 成为开发者！

攻击者直接参与维护公开软件包，并且植入恶意代码。

# 恶意软件包怎么执行命令

## Install时执行
`package.json`里面的`scripts`字段的`preinstall`和`postinstall`关键字能够在软件包安装前后执行参数内的命令
![](image.png)


## Import时执行

npm软件包在被导入时，会执行`package.json`里面的`main`字段内的文件
![](image-1.png)


# DONAPI检测流程

![DONAPI框架](image-2.png)

<!-- ## Code Dependencies Reconstructor

- 入口文件提取：
该模块首先提取与npm包的安装和导入过程相关的入口文件，包括package.json中的scripts、main、exports、imports和bin字段。它使用正则表达式来捕获这些文件名，以便后续分析。

- 依赖解析：
通过解析代码中动态声明的其他代码文件的导入，重构器能够获取目标文件的内容。它支持CommonJS和ECMAScript模块系统的导入方法，生成相应的AST节点，并递归解析这些节点。

- 对象修改：
为了解决合并不同代码后变量名冲突的问题，重构器会统一导入和导出对象的标识符。它将导出对象的名称修改为export_file_name_object_name的形式，以避免重复。

- 生成合并后的代码：
最终，Code Dependencies Reconstructor将所有提取和修改后的代码合并到一个单独的.js文件中，形成一个“merged file”。这个文件包含了所有相关代码的统一视图，便于后续的静态和动态分析。

## Malicious Shell Command Detector

- 解析和提取命令：
从package.json文件中的scripts字段提取shell命令。执行.sh文件并捕获执行的命令序列。分析代码中用于执行命令的API调用参数。构建命令的抽象语法树（AST）：使用bashlex库解析提取的shell命令，并构建AST。

- 应用YARA规则：
使用预定义的YARA规则来分析AST，以识别可疑或恶意的命令模式。

- 恶意URL检测：
提取命令中使用的URLs。使用一系列特征（如域名的熵、长度等）来评估URL的恶意程度。结合白名单和机器学习模型来提高检测的准确性和效率。

- 行为分类：
将检测到的恶意命令映射到特定的恶意行为类别，如信息窃取、文件操作、恶意软件下载等。

- 输出检测结果：
输出每个检测到的命令是否恶意的判断。提供详细的检测报告，包括恶意命令、恶意URL、YARA规则匹配结果和恶意行为分类。

##  -->

- 首先检测package中各明文代码是否存在恶意的命令或者Url，如果不能检测到进入下一步
- 将所有代码重构，生成一个Merged file，用于接下来的静态分析和动态分析
- 通过模型判断Merged file是否混淆过，如果混淆过传入动态分析模块，反则静态分析模块
- 静态分析模块通过AST Parser提取API序列，通过API序列生成特征传入模型检测是否为恶意软件包，如果不是正常软件包，继续传入动态模块分析
- 动态分析模块通过API Hook提取恶意代码运行中产生API序列，传入最终的模型检测