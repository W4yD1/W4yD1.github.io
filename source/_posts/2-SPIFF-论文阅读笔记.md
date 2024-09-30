---
title: 2-SPIFF 论文阅读笔记
date: 2024-04-19 17:36:34
tags: [论文阅读, 壳检测, 恶意软件检测, malware detection, paker detection]
hide: true
categories: 
    - 论文阅读
    - 恶意软件检测
---

# Abstract
许多恶意软件通过加壳来绕过检测，因此准确高效的加壳器识别（Packer Identification）方法对恶意软件检测来说十分重要，本文给出[`2-SPIFF`](https://dl.acm.org/doi/abs/10.1007/s10489-021-02347-w)——一种2段式的加壳器识别方法，阶段一通过从程序的FCG图中提取特征来辨别程序是否加壳，阶段二通过从FCG图和文件属性中提取的融合特征来识别加壳器。

# 0x01. Background
恶意软件会对组织或个人设备造成严重损坏，许多恶意软件通过代码混淆和反调试来绕过检测，代码混淆技术包括冗余代码生成、花指令和加壳技术。奥萨格于2016年指出，80%的恶意软件使用了加壳技术。加壳技术通常会破坏原始程序的汇编代码，因此基于汇编代码的静态分析检测方法将变得不可行。
加壳器识别本质上是个分类问题，因此机器学习被广泛应用于该问题中，在先前的研究中，许多图结构被用来构建分类模型，包括数据流图、系统调用依赖图、函数调用图（FCG）和持续执行图（CEG）。`2-SPIFF`基于***函数调用图（FCG）和文件属性***。
{% note info %}
之所以使用FCG是因为它直观的展示了程序的控制流程，且相当于CEG，FCG的节点和边都会更少，生成FCG的时间比CEG更快。
{% endnote %}
{% note success %}
还需要文件属性的原因是不同加壳器生成的加壳程序可能会有相同的FCG图，因此需要进一步从文件属性中提取能够区分不同加壳器的特征
{% endnote %}
# 0x02. Main Steps
`2-SPIFF`框架：
![](1.png)
## step1. File preprocessing
通过类似IDA Pro的静态分析工具提取出GDL，从而得到FCG
{% note success %}
Graph Description Language（GDL）一种中间语言，用于描述图中节点和边的关系
{% endnote %}
以下是一个GDL文件实例：
{% spoiler "点击显/隐内容" %}
``` GDL
graph: {
title: "Call flow of vuln"
// IDA palette
colorentry 32: 0 0 0
colorentry 33: 0 0 255
colorentry 34: 0 0 255
colorentry 35: 128 128 128
colorentry 36: 128 128 128
colorentry 37: 0 0 128
colorentry 38: 0 0 128
colorentry 39: 0 0 255
colorentry 40: 0 0 255
colorentry 41: 0 0 128
colorentry 42: 0 128 0
colorentry 43: 0 255 0
colorentry 44: 0 128 0
colorentry 45: 255 128 0
colorentry 46: 0 128 0
colorentry 47: 128 128 255
colorentry 48: 255 0 0
colorentry 49: 128 128 0
colorentry 50: 1 1 1
colorentry 51: 192 192 192
colorentry 52: 0 0 255
colorentry 53: 0 0 255
colorentry 54: 0 0 255
colorentry 55: 128 128 128
colorentry 56: 128 128 255
colorentry 57: 0 128 0
colorentry 58: 0 0 128
colorentry 59: 0 0 255
colorentry 60: 128 0 128
colorentry 61: 0 128 0
colorentry 62: 0 128 0
colorentry 63: 0 128 64
colorentry 64: 0 0 128
colorentry 65: 0 0 128
colorentry 66: 255 0 255
colorentry 67: 128 128 0
colorentry 68: 0 0 128
colorentry 69: 0 0 255
colorentry 70: 0 0 128
colorentry 71: 0 0 255
colorentry 72: 0 0 0
colorentry 73: 255 255 255
colorentry 74: 192 187 175
colorentry 75: 0 255 255
colorentry 76: 0 0 0
colorentry 77: 128 0 0
colorentry 78: 128 128 128
colorentry 79: 128 128 0
colorentry 80: 255 0 255
colorentry 81: 0 0 0
colorentry 82: 0 0 255
colorentry 83: 0 0 0
colorentry 84: 50 205 50
node: { title: "0" label: ".init_proc" color: 76 textcolor: 73 bordercolor: black }
node: { title: "1" label: "sub_401020" color: 76 textcolor: 73 bordercolor: black }
node: { title: "2" label: "sub_401030" color: 76 textcolor: 73 bordercolor: black }
node: { title: "3" label: "sub_401040" color: 76 textcolor: 73 bordercolor: black }
node: { title: "4" label: "sub_401050" color: 76 textcolor: 73 bordercolor: black }
node: { title: "5" label: "sub_401060" color: 76 textcolor: 73 bordercolor: black }
node: { title: "6" label: "sub_401070" color: 76 textcolor: 73 bordercolor: black }
node: { title: "7" label: "sub_401080" color: 76 textcolor: 73 bordercolor: black }
node: { title: "8" label: "sub_401090" color: 76 textcolor: 73 bordercolor: black }
node: { title: "9" label: "sub_4010A0" color: 76 textcolor: 73 bordercolor: black }
node: { title: "10" label: "sub_4010B0" color: 76 textcolor: 73 bordercolor: black }
node: { title: "11" label: "sub_4010C0" color: 76 textcolor: 73 bordercolor: black }
node: { title: "12" label: "sub_4010D0" color: 76 textcolor: 73 bordercolor: black }
node: { title: "13" label: ".free" color: 80 textcolor: 73 bordercolor: black }
node: { title: "14" label: ".puts" color: 80 textcolor: 73 bordercolor: black }
node: { title: "15" label: ".write" color: 80 textcolor: 73 bordercolor: black }
node: { title: "16" label: ".__stack_chk_fail" color: 80 textcolor: 73 bordercolor: black }
node: { title: "17" label: ".printf" color: 80 textcolor: 73 bordercolor: black }
node: { title: "18" label: ".read" color: 80 textcolor: 73 bordercolor: black }
node: { title: "19" label: ".malloc" color: 80 textcolor: 73 bordercolor: black }
node: { title: "20" label: ".setvbuf" color: 80 textcolor: 73 bordercolor: black }
node: { title: "21" label: ".__isoc99_scanf" color: 80 textcolor: 73 bordercolor: black }
node: { title: "22" label: ".exit" color: 80 textcolor: 73 bordercolor: black }
node: { title: "23" label: "_start" color: green bordercolor: black }
node: { title: "24" label: "_dl_relocate_static_pie" color: 76 textcolor: 73 bordercolor: black }
node: { title: "25" label: "deregister_tm_clones" color: 76 textcolor: 73 bordercolor: black }
node: { title: "26" label: "register_tm_clones" color: 76 textcolor: 73 bordercolor: black }
node: { title: "27" label: "__do_global_dtors_aux" color: 76 textcolor: 73 bordercolor: black }
node: { title: "28" label: "frame_dummy" color: 76 textcolor: 73 bordercolor: black }
node: { title: "29" label: "menu" color: 76 textcolor: 73 bordercolor: black }
node: { title: "30" label: "get_choice" color: 76 textcolor: 73 bordercolor: black }
node: { title: "31" label: "add_chunk" color: 76 textcolor: 73 bordercolor: black }
node: { title: "32" label: "delete_chunk" color: 76 textcolor: 73 bordercolor: black }
node: { title: "33" label: "view_chunk" color: 76 textcolor: 73 bordercolor: black }
node: { title: "34" label: "manba" color: 76 textcolor: 73 bordercolor: black }
node: { title: "35" label: "init" color: 76 textcolor: 73 bordercolor: black }
node: { title: "36" label: "main" color: 76 textcolor: 73 bordercolor: black }
node: { title: "37" label: "atexit" color: 76 textcolor: 73 bordercolor: black }
node: { title: "38" label: ".term_proc" color: 76 textcolor: 73 bordercolor: black }
node: { title: "39" label: "free" color: 80 textcolor: 73 bordercolor: black }
node: { title: "40" label: "__libc_start_main" color: 80 textcolor: 73 bordercolor: black }
node: { title: "41" label: "puts" color: 80 textcolor: 73 bordercolor: black }
node: { title: "42" label: "write" color: 80 textcolor: 73 bordercolor: black }
node: { title: "43" label: "__stack_chk_fail" color: 80 textcolor: 73 bordercolor: black }
node: { title: "44" label: "printf" color: 80 textcolor: 73 bordercolor: black }
node: { title: "45" label: "read" color: 80 textcolor: 73 bordercolor: black }
node: { title: "46" label: "malloc" color: 80 textcolor: 73 bordercolor: black }
node: { title: "47" label: "setvbuf" color: 80 textcolor: 73 bordercolor: black }
node: { title: "48" label: "__cxa_atexit" color: 80 textcolor: 73 bordercolor: black }
node: { title: "49" label: "__isoc99_scanf" color: 80 textcolor: 73 bordercolor: black }
node: { title: "50" label: "exit" color: 80 textcolor: 73 bordercolor: black }
node: { title: "51" label: "__gmon_start__" color: 80 textcolor: 73 bordercolor: black }
node: { title: "52" label: "__libc_start_main" color: 80 textcolor: 73 bordercolor: black }
node: { title: "53" label: "__gmon_start__" color: 80 textcolor: 73 bordercolor: black }
// node 0
edge: { sourcename: "0" targetname: "51" }
edge: { sourcename: "0" targetname: "53" }
// node 1
// node 2
// node 3
// node 4
// node 5
// node 6
// node 7
// node 8
// node 9
// node 10
// node 11
// node 12
// node 13
// node 14
// node 15
// node 16
// node 17
// node 18
// node 19
// node 20
// node 21
// node 22
// node 23
edge: { sourcename: "23" targetname: "40" }
edge: { sourcename: "23" targetname: "52" }
// node 24
// node 25
// node 26
// node 27
edge: { sourcename: "27" targetname: "25" }
// node 28
// node 29
edge: { sourcename: "29" targetname: "14" }
edge: { sourcename: "29" targetname: "17" }
// node 30
edge: { sourcename: "30" targetname: "16" }
edge: { sourcename: "30" targetname: "21" }
// node 31
edge: { sourcename: "31" targetname: "14" }
edge: { sourcename: "31" targetname: "16" }
edge: { sourcename: "31" targetname: "17" }
edge: { sourcename: "31" targetname: "18" }
edge: { sourcename: "31" targetname: "19" }
edge: { sourcename: "31" targetname: "21" }
// node 32
edge: { sourcename: "32" targetname: "13" }
edge: { sourcename: "32" targetname: "14" }
edge: { sourcename: "32" targetname: "16" }
edge: { sourcename: "32" targetname: "17" }
edge: { sourcename: "32" targetname: "21" }
// node 33
edge: { sourcename: "33" targetname: "14" }
edge: { sourcename: "33" targetname: "15" }
edge: { sourcename: "33" targetname: "16" }
edge: { sourcename: "33" targetname: "17" }
edge: { sourcename: "33" targetname: "21" }
// node 34
edge: { sourcename: "34" targetname: "17" }
// node 35
edge: { sourcename: "35" targetname: "20" }
edge: { sourcename: "35" targetname: "37" }
// node 36
edge: { sourcename: "36" targetname: "14" }
edge: { sourcename: "36" targetname: "22" }
edge: { sourcename: "36" targetname: "29" }
edge: { sourcename: "36" targetname: "30" }
edge: { sourcename: "36" targetname: "31" }
edge: { sourcename: "36" targetname: "32" }
edge: { sourcename: "36" targetname: "33" }
edge: { sourcename: "36" targetname: "35" }
// node 37
// node 38
// node 39
// node 40
// node 41
// node 42
// node 43
// node 44
// node 45
// node 46
// node 47
// node 48
// node 49
// node 50
// node 51
// node 52
// node 53
}
```
{% endspoiler %}
对应的FCG图为：
![](3.png)
## step2. Feature extraction
从FCG中提取19个特征，从文件属性中提取6个特征
各特征如下图所示：
![](2.png)

## step3. Packer detection
这一步的目的是判断程序是否加壳，是一个二分类问题
程序在加壳后的FCG图会比加壳前简单，可根据这一特征来检测程序是否加壳
`2-SPIFF`从FCG图中提取19个特征来构建检测模型
{% note success %}
如果某种加壳器加壳后的程序的FCG与原程序的FCG一致，该检测方法还有效吗？
{% endnote %}
## step4. Packer identification
这一步的目的是识别加壳程序所使用的加壳器，是一个多分类问题
程序被不同的加壳器加壳后，FCG大多数会不一样，但也有可能会有FCG相似，但加壳器不同的情况，此时可在FCG特征的基础上加上文件属性特征，将两种特征融合起来去识别不同的加壳器
`2-SPIFF`将19个图特征和6个文件特征级联起来构建识别模型，使用 ***class prob*** 和一个阈值 $\tau$ 来识别某加壳文件的加壳器，***class prob*** 是一个数组，每一项代表某个加壳器的概率，如果最大的 ***class prob$_{i}$*** 小于 $\tau$ ，则该项的识别结果为“未知”

# 0x03. Inovation
- 发现了程序加壳前后FCG的不同之处，加壳后的程序FCG往往会更加简单
- 不同加壳器可能生成相同的FCG，但不同加壳器使用不同的算法，这导致被不同加壳器加壳后的程序在文件属性中必有差异
- 结合以上两个特征，提出了一种两段式的加壳器检测方法，第一阶段根据FCG特征构建模型检测是否加壳，第二阶段根据FCG特征和文件属性特征构建模型来检测使用了什么加壳器