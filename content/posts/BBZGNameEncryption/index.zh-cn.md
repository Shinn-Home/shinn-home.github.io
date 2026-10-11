---
title: "八宝粥行动逆向笔记：GName加密分析"
date: 2025-06-11T12:00:00+08:00
lastmod: 2025-06-11T12:00:00+08:00
draft: false
author: "Shinn"
images: []
tags: ["八宝粥行动", "虚幻引擎", "逆向工程"]
categories: ["游戏引擎逆向、游戏安全分析"]

twemoji: false
lightgallery: true
---

<!--more-->

## GName

通过字符串定位（Ansi）

```c
"ByteProperty"
```

搜索到引用函数后，再交叉引用即可

```c
if ( byte_154A8182C )
{
    v4 = &unk_154A81B00;
}
else
{
    v4 = (_QWORD *)sub_14AEA1CE0((__int64)&unk_154A81B00);	// GName = 154A81B00
    byte_154A8182C = 1;									 // 全局初始化标志位
}
v5 = (_WORD *)(v4[v3 + 1] + (unsigned int)(2 * v12));
v6 = v5 + 1;
v7 = (unsigned __int64)(unsigned __int16)*v5 >> 6;
if ( (*v5 & 1) != 0 )	// FNAME_ENTRY.bIsWide
{
    v8 = v7;
    sub_14E327C7D(v13, v6, 2 * v7);	// memcpy
    sub_14AEABF60(v13, (unsigned __int16)*v5 >> 6);// WideChar解密
    if ( (unsigned int)sub_14AD5CEE0(v13, a2, v7) )
        return 0;
    v9 = a2[v8];
    if ( !v14 )
        return v9 == 0;
    return v9 == 95 && (unsigned __int8)sub_14AEA0F40((unsigned int)(v14 - 1), &a2[v8 + 1]);
}
else
{
    sub_14E327C7D(v13, v6, (unsigned __int64)(unsigned __int16)*v5 >> 6);// memcpy
    sub_14AEABD50(v13, (unsigned __int16)*v5 >> 6);// Ansi解密
    if ( (unsigned int)sub_14AD5CE60(v13, a2, v7) )
        return 0;
    v11 = a2[v7];
    if ( !v14 )
        return v11 == 0;
    return v11 == 95 && (unsigned __int8)sub_14AEA0F40((unsigned int)(v14 - 1), &a2[v7 + 1]);
}
```

### 特征码

1. GName特征码

```c
"48 8D 15 ?? ?? ?? ?? EB ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B D0 C6 05 ?? ?? ?? ?? 01"
```

```c
DeltaForce_20260626_Ansi.exe+1528E3CB - 48 8D 15 EE96A90B     - lea rdx,[DeltaForce_20260626_Ansi.exe+20D27AC0]		// GName
DeltaForce_20260626_Ansi.exe+1528E3D2 - EB 16                 - jmp DeltaForce_20260626_Ansi.exe+1528E3EA
DeltaForce_20260626_Ansi.exe+1528E3D4 - 48 8D 0D E596A90B     - lea rcx,[DeltaForce_20260626_Ansi.exe+20D27AC0]		// GName
DeltaForce_20260626_Ansi.exe+1528E3DB - E8 F0130000           - call DeltaForce_20260626_Ansi.exe+1528F7D0
DeltaForce_20260626_Ansi.exe+1528E3E0 - 48 8B D0              - mov rdx,rax
DeltaForce_20260626_Ansi.exe+1528E3E3 - C6 05 1295A90B 01     - mov byte ptr [DeltaForce_20260626_Ansi.exe+20D278FC],01
DeltaForce_20260626_Ansi.exe+1528E3EA - 48 8B 44 24 20        - mov rax,[rsp+20]
```

2. 解密特征码

```c
"E8 ?? ?? ?? ?? 0F B7 16 48 8D 4C 24 ?? C1 EA ?? E8 ?? ?? ?? ?? 4C 8B C7 48 8D 4C 24 ?? 48 8B D3 E8"
```

```c
DeltaForce_20260626_Ansi.exe+1528E415 - E8 337AAF03           - call DeltaForce_20260626_Ansi.exe+18D85E4D
DeltaForce_20260626_Ansi.exe+1528E41A - 0FB7 16               - movzx edx,word ptr [rsi]
DeltaForce_20260626_Ansi.exe+1528E41D - 48 8D 4C 24 30        - lea rcx,[rsp+30]
DeltaForce_20260626_Ansi.exe+1528E422 - C1 EA 06              - shr edx,06
DeltaForce_20260626_Ansi.exe+1528E425 - E8 066D0000           - call DeltaForce_20260626_Ansi.exe+15295130	// WideChar解密Call
```
