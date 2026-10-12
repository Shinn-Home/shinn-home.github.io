---
title: "八宝粥行动逆向笔记：AcknowledgedPawn加密分析"
date: 2025-06-24T12:00:00+08:00
lastmod: 2025-06-24T12:00:00+08:00
draft: false
author: "Shinn"
images: []
tags: ["八宝粥行动", "虚幻引擎", "逆向工程"]
categories: ["游戏引擎逆向、游戏安全分析"]

twemoji: false
lightgallery: true
---

<!--more-->

## 八宝粥AcknowledgedPawn加密分析

### 解密方法1：Hook实现解密

```c++
// __int64 __fastcall sub_14BA04500(__int64 *PlayerController, __int64 a2, __int64 a3)
DeltaForceClient-Win64-Shipping.exe+BA0460B - 8B 93 18040000        - mov edx,[rbx+00000418]
DeltaForceClient-Win64-Shipping.exe+BA04611 - 83 FA 20              - cmp edx,20
DeltaForceClient-Win64-Shipping.exe+BA04614 - 73 3F                 - jae DeltaForceClient-Win64-Shipping.exe+BA04655
DeltaForceClient-Win64-Shipping.exe+BA04616 - 8B 05 A87D5407        - mov eax,[DeltaForceClient-Win64-Shipping.exe+12F4C3C4]
DeltaForceClient-Win64-Shipping.exe+BA0461C - 0FA3 D0               - bt eax,edx
DeltaForceClient-Win64-Shipping.exe+BA0461F - 73 34                 - jae DeltaForceClient-Win64-Shipping.exe+BA04655
DeltaForceClient-Win64-Shipping.exe+BA04621 - 8B 0D 997D5407        - mov ecx,[DeltaForceClient-Win64-Shipping.exe+12F4C3C0]
DeltaForceClient-Win64-Shipping.exe+BA04627 - B8 C8000000           - mov eax,000000C8
DeltaForceClient-Win64-Shipping.exe+BA0462C - 03 CA                 - add ecx,edx
DeltaForceClient-Win64-Shipping.exe+BA0462E - 48 8D 15 EBE0C306     - lea rdx,[DeltaForceClient-Win64-Shipping.exe+12642720]
DeltaForceClient-Win64-Shipping.exe+BA04635 - 81 F9 C9000000        - cmp ecx,000000C9
DeltaForceClient-Win64-Shipping.exe+BA0463B - 0F43 C8               - cmovae ecx,eax
DeltaForceClient-Win64-Shipping.exe+BA0463E - 8B C1                 - mov eax,ecx
DeltaForceClient-Win64-Shipping.exe+BA04640 - 8B 0D 827D5407        - mov ecx,[DeltaForceClient-Win64-Shipping.exe+12F4C3C8]
DeltaForceClient-Win64-Shipping.exe+BA04646 - FF 14 C2              - call qword ptr [rdx+rax*8]
DeltaForceClient-Win64-Shipping.exe+BA04649 - 48 8B 8B B0030000     - mov rcx,[rbx+000003B0]
DeltaForceClient-Win64-Shipping.exe+BA04650 - 48 33 C6              - xor rax,rsi		// 可以Hook这个点，rax就是解密后的AcknowledgedPawn
```



### 解密方法2：手动解密（IDA伪代码存在错误）

```c++
// __int64 __fastcall sub_14BA04500(__int64 *PlayerController, __int64 a2, __int64 a3)
// .....
Enc_AcknowledgedPawn = PlayerController[130];
if ( Enc_AcknowledgedPawn )
{
    dwFuncIndex = *((_DWORD *)PlayerController + 0x106);
    if ( dwFuncIndex < 0x20 && (v12 = dword_152F4C3C4, _bittest(&v12, dwFuncIndex)) )// 这句判断不用还原
    {
        v13 = dwFuncIndex + dword_152F4C3C0;
        if ( dwFuncIndex + dword_152F4C3C0 >= 201 )// 检查解密函数下标是否越界，解密指针数组大小为201
            v13 = 200;
        XorKey = ((__int64 (__fastcall *)(_QWORD))funcs_14B9F7699[v13])((unsigned int)dword_152F4C3C8);// 调用解密Call得到XorKey
        v8 = PlayerController[118];
        AcknowledgedPawn = Enc_AcknowledgedPawn ^ XorKey;	// 这里其实就是方法1的Hook点
    }
    else
    {
        AcknowledgedPawn = PlayerController[130];// 断不下来
    }
// .....
```
