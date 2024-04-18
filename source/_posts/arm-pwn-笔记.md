---
title: arm pwn 笔记
date: 2024-04-17 16:59:38
tags: [笔记, arm pwn]
categories: 
    - 笔记
---

# 环境

## arm软件包
``` BASH
sudo apt search "libc6-" | grep "arm"
sudo apt install libc6-arm64-cross
```
安装好的库/usr/aarch64-linux-gnu/lib/目录下


# 汇编
## 跳转指令

- X29寄存器作用相当于x64的rbp，X30寄存器用于保存返回地址，当执行RET指令时，会将X30的值赋值给PC寄存器。PC寄存器即x64的rsp。

- b指令跳转到某个标签处，单纯的jmp

- BL指令用于跳转，并且会将返回地址保存在X30寄存器中。然后函数开头一般就会将这两个寄存器的值保存到栈里。

- LDP X29, X30, [SP+var_s0],#0x10;RET 指令，相当于x64的pop rbp; ret。


## 内存读取指令

- str register,addr指令，st即store的缩写,将register寄存器里的值写入到addr地址处。

- ldr register,addr指令，ld即load dword的缩写,读取addr处的数据，放入register寄存器。

- LDP register1, register2,addr ，从addr读取两个dword，分别存入register1、register2。

- STP register1, register2,addr ，将register1、register2的值依次存入addr处。

## 寻址

- ADRP  X0, #label@PAGE指令，将label所处的页的基地址存入X0。

- ADD   X0, X0, #label@PAGEOFF指令，偏移加上基地址，得到label的地址。

# 函数调用

## 传参方式

用$R0~$R3传递函数的前4个参数，其余参数从右到左入栈


## 相似处

- R13 相当于栈指针ESP/RSP
- PC 相当于EIP/RIP指针
- LR link register 保存返回地址的寄存器
- BL 相当于call ， 跳转并把返回值保存到LR中
- B 相当于jmp
- BX 跳转并切换状态 ARM 与THUMB 指令
- BLX 带返回的跳转并切换状态

## 函数返回值

返回值存放在r0

# 寄存器

![](1.png)