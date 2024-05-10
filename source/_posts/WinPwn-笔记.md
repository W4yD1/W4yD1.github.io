---
title: WinPwn 笔记
date: 2024-04-11 17:01:51
tags: [笔记, WinPwn]
categories: 
    - 笔记
comment: true
---


# 调试
win_server监听某个程序，虚拟机中remote连接，raw_input()等待windbg attach之后再发送数据。

## 常用命令：

bp [exe_name]+offset:断在offset处
bp pe_base+offset:断在offset处
lm:查看加载的dll及pe地址空间
u addr:查看addr处的代码
g:运行到断点
p:单步步过
t:单步步入
!address [target_addr]:查看target_addr所属的地址范围
dps [addr]:查看addr处开始的一段范围内的值，并且搜索出二进制对应的符号
s -d 0x0 l?0x7fffffff 0x12345678 全局搜索0x12345678

## 寻找gadget:
``` bash
ropper --file ./ntdll.dll --nocolor > gadget
```

# 基础知识

## 保护
- GS:类似canary
- ASLR:地址随机化，但是只有开机的时候才会随机一次

## 异常

scopeTable结构体中保存了try块相匹配的except,__finally的值，在main函数开始的入口就被压入到栈中。

在遇到异常时，先执行except_handler4函数，该函数首先将scope_table的地址同security_cookie异或得到实际地址，之后验证gs的值，满足要求后当try_level=0xfffffffe(-2)时，调用scope_table中的filter_func。