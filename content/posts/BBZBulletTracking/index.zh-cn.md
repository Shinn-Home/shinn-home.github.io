---
title: "八宝粥行动逆向笔记：弹道分析、Hook实现子弹追踪"
date: 2025-06-17T12:00:00+08:00
lastmod: 2025-06-17T12:00:00+08:00
draft: false
author: "Shinn"
images: []
tags: ["八宝粥行动", "虚幻引擎", "Hook技术", "逆向工程"]
categories: ["游戏引擎逆向、游戏安全分析"]

twemoji: false
lightgallery: true
---

<!--more-->

## 弹道追踪点分析

### 特征码

定位到函数头即可

```c
"48 8B 84 24 ?? ?? ?? ?? 48 8D 78 ?? 48 8B B4 24 ?? ?? ?? ?? B9 ?? ?? ?? ?? F3 A4 48 8B 84 24 ?? ?? ?? ?? 48 8D 78 ?? 48 8B B4 24 ?? ?? ?? ?? B9 ?? ?? ?? ?? F3 A4 C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 48 6B C0 ?? 48 8D 0D"
```

```c
// 参数1，意义不明，估计为this
// 参数2为FVector3*，调用前为（0，0，0），调用后为摄像机坐标
// 参数3为Vector2*，调用为（0，0），调用后为鼠标朝向角度
// __int64 __fastcall sub_143B2E280(__int64 a1, float *a2, void *a3)
DeltaForceClient-Win64-Shipping.exe+3B2F351 - 48 8B 84 24 60040000  - mov rax,[rsp+00000460]
DeltaForceClient-Win64-Shipping.exe+3B2F359 - 8B 4C 24 7C           - mov ecx,[rsp+7C]
DeltaForceClient-Win64-Shipping.exe+3B2F35D - 89 48 50              - mov [rax+50],ecx
DeltaForceClient-Win64-Shipping.exe+3B2F360 - 48 8B 84 24 60040000  - mov rax,[rsp+00000460]
DeltaForceClient-Win64-Shipping.exe+3B2F368 - 48 8D 78 54           - lea rdi,[rax+54]
DeltaForceClient-Win64-Shipping.exe+3B2F36C - 48 8B B4 24 68040000  - mov rsi,[rsp+00000468]
DeltaForceClient-Win64-Shipping.exe+3B2F374 - B9 0C000000           - mov ecx,0000000C { 12 }	// 循环次数
DeltaForceClient-Win64-Shipping.exe+3B2F379 - F3 A4                 - repe movsb  		// 循环复制坐标 
DeltaForceClient-Win64-Shipping.exe+3B2F37B - 48 8B 84 24 60040000  - mov rax,[rsp+00000460]
DeltaForceClient-Win64-Shipping.exe+3B2F383 - 48 8D 78 60           - lea rdi,[rax+60]	// 这里的0x60就是一个强特征信号
DeltaForceClient-Win64-Shipping.exe+3B2F387 - 48 8B B4 24 70040000  - mov rsi,[rsp+00000470]
DeltaForceClient-Win64-Shipping.exe+3B2F38F - B9 0C000000           - mov ecx,0000000C { 12 }
DeltaForceClient-Win64-Shipping.exe+3B2F394 - F3 A4                 - repe movsb 		// 循环赋值鼠标朝向 
DeltaForceClient-Win64-Shipping.exe+3B2F396 - C7 84 24 7C030000 5E6D0000 - mov [rsp+0000037C],00006D5E { 27998 }
DeltaForceClient-Win64-Shipping.exe+3B2F3A1 - B8 01000000           - mov eax,00000001 { 1 }
DeltaForceClient-Win64-Shipping.exe+3B2F3A6 - 48 6B C0 00           - imul rax,rax,00
DeltaForceClient-Win64-Shipping.exe+3B2F3AA - 48 8D 0D 5FFE0D0F     - lea rcx,[DeltaForceClient-Win64-Shipping.exe+12C0F210] { (1) }
DeltaForceClient-Win64-Shipping.exe+3B2F3B1 - 0FBE 04 01            - movsx eax,byte ptr [rcx+rax]
```



### 回溯调用方

```c
// __int64 __fastcall sub_143BAC570(__int64 a1, __int64 a2, __int64 a3)
DeltaForceClient-Win64-Shipping.exe+3BAC723 - 48 8B 44 24 48        - mov rax,[rsp+48]
DeltaForceClient-Win64-Shipping.exe+3BAC728 - 48 8B 00              - mov rax,[rax]
DeltaForceClient-Win64-Shipping.exe+3BAC72B - 4C 8B 84 24 E0000000  - mov r8,[rsp+000000E0]		 // 参数3
DeltaForceClient-Win64-Shipping.exe+3BAC733 - 48 8B 94 24 D8000000  - mov rdx,[rsp+000000D8]	 // 参数2
DeltaForceClient-Win64-Shipping.exe+3BAC73B - 48 8B 4C 24 48        - mov rcx,[rsp+48]		  	 // 参数1
DeltaForceClient-Win64-Shipping.exe+3BAC740 - FF 50 38              - call qword ptr [rax+38] 	 // 调用方执行call
DeltaForceClient-Win64-Shipping.exe+3BAC743 - 90                    - nop 
DeltaForceClient-Win64-Shipping.exe+3BAC744 - C7 44 24 64 A45B0000  - mov [rsp+64],00005BA4 { 23460 }
DeltaForceClient-Win64-Shipping.exe+3BAC74C - B8 01000000           - mov eax,00000001 { 1 }
DeltaForceClient-Win64-Shipping.exe+3BAC751 - 48 6B C0 00           - imul rax,rax,00
```



### 更新特征码

1. 使用上方的特征码会搜索出多条内容，由于0x60是一个许久没变的偏移，所以更新特征码如下

```c
"48 8B 84 24 ?? ?? ?? ?? 48 8D 78 ?? 48 8B B4 24 ?? ?? ?? ?? B9 ?? ?? ?? ?? F3 A4 48 8B 84 24 ?? ?? ?? ?? 48 8D 78 60 48 8B B4 24 ?? ?? ?? ?? B9 ?? ?? ?? ?? F3 A4 C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 48 6B C0 ?? 48 8D 0D"
```

2. 只会搜出一条，向上找到函数头部即可，目前版本搜索出来的位置距离函数头部偏移为0x1CDC，自动化搜索向前搜索0x2000字节
3. 函数头部附近代码如下：

```c
DeltaForce_20260626_Ansi.exe+77D680D - C3                    - ret 
DeltaForce_20260626_Ansi.exe+77D680E - CC                    - int 3 
DeltaForce_20260626_Ansi.exe+77D680F - CC                    - int 3 
DeltaForce_20260626_Ansi.exe+77D6810 - 4C 89 44 24 18        - mov [rsp+18],r8		// 函数头部
DeltaForce_20260626_Ansi.exe+77D6815 - 48 89 54 24 10        - mov [rsp+10],rdx
DeltaForce_20260626_Ansi.exe+77D681A - 48 89 4C 24 08        - mov [rsp+08],rcx
DeltaForce_20260626_Ansi.exe+77D681F - 56                    - push rsi
DeltaForce_20260626_Ansi.exe+77D6820 - 57                    - push rdi
DeltaForce_20260626_Ansi.exe+77D6821 - 48 81 EC B8050000     - sub rsp,000005B8
DeltaForce_20260626_Ansi.exe+77D6828 - 48 8B 05 91D0BC18     - mov rax,[DeltaForce_20260626_Ansi.exe+203A38C0]
```
