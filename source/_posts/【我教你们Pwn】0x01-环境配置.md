---
title: 【我教你们Pwn】0x01-环境配置
date: 2024-12-20 14:32:20
tags: [Pwn教学]
hide: true
categories: 
    - Pwn教学
---


# Zsh
安装：
```
sudo apt-get install zsh
```
设置Zsh为默认Shell：
```
chsh -s $(which zsh)
```

# Oh My Zsh
安装：
```
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
```

# 配置32位环境
```
sudo dpkg --add-architecture i386
sudo apt-get update
sudo apt install build-essential
sudo apt install gcc-multilib
```

# 安装pwntools
```
sudo apt-get update
sudo apt-get install python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade pwntools
```

# 安装pwndbg
```
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```


# 安装pwngdb
```
git clone https://github.com/scwuaptx/Pwngdb.git 
cp ~/Pwngdb/.gdbinit ~/
```



```

```



```

```



