---
title: mips pwn 笔记
date: 2024-04-17 16:16:06
tags: [笔记, mips pwn]
categories: 
    - 笔记
---

# 启动
## Step 1
``` shell
qemu-mipsel -g 9000 -L ./mips mips
```
<font size=5 color=red>or</font>
``` python
io = process(["qemu-mipsel","-g","9000","-L","./mips","mips"])
```
## Step 2
``` shell
gdb-multiarch -q mips
```
## Step 3
``` gdb
target remote :9000
```



# shellcode
``` python
asm(shellcraft.mips.linux.sh())
```

# 汇编
## 跳转指令

- j指令跳转到某个标签处，单纯的jmp

- jr指令用于跳转到寄存器里的地址值指向的地方。

- jal 跳转时，会将返回地址存入$ra寄存器。

- jalr 与jal指令类似，只不过后面的对象为寄存器。

- $ra寄存器，ra为，return address的缩写，一般用于存储返回地址，一个函数结尾往往会从栈里弹出一个值赋值给$ra寄存器，然后jr $ra。

## 内存读取指令

- sw register,addr指令，sw即store word的缩写（对应的有store byte）,将register寄存器里的值写入到addr地址处。

- lw register,addr指令，lw即load word的缩写（对应的有load byte）,读取addr处的数据，放入register寄存器。

## 寻址

- la指令，相当于x86的lea

- lai指令，i的意思是immediate立即数，即后面的对象为立即数。

- la $a0,1($s0)指令，带有偏移的寻址，它的作用是$a0 = 1 + $s0

# 函数调用

## 传参方式

用$a0~$a3传递函数的前4个参数，记忆方法，寄存器名字a实际为argument的缩写。多余的参数用栈传递


## 函数返回值

一般用$v0~$v1寄存器传递。v也就是value的缩写。