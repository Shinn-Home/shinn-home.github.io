---
title: "八宝粥行动逆向笔记：AHUD.PostRender函数指针分析"
date: 2025-06-14T12:00:00+08:00
lastmod: 2025-06-14T12:00:00+08:00
draft: false
author: "Shinn"
images: []
tags: ["八宝粥行动", "虚幻引擎", "逆向工程"]
categories: ["游戏引擎逆向、游戏安全分析"]

twemoji: false
lightgallery: true
---

<!--more-->

## AHUD.PostRender

### UE源码

UE源码中有着`void UGameViewportClient::Draw(FViewport* InViewport, FCanvas* SceneCanvas)`方法，如下所示（这里使用到了GEngine、会有GEngine解密的痕迹）

```c++
void UGameViewportClient::Draw(FViewport* InViewport, FCanvas* SceneCanvas)
{
	//Valid SceneCanvas is required.  Make this explicit.
	check(SceneCanvas);

	BeginDrawDelegate.Broadcast();

	const bool bStereoRendering = GEngine->IsStereoscopic3D(InViewport);
	FCanvas* DebugCanvas = InViewport->GetDebugCanvas();

	// Create a temporary canvas if there isn't already one.
	static FName CanvasObjectName(TEXT("CanvasObject"));
	UCanvas* CanvasObject = GetCanvasByName(CanvasObjectName);
	CanvasObject->Canvas = SceneCanvas;

	// Create temp debug canvas object
	FIntPoint DebugCanvasSize = InViewport->GetSizeXY();
	if (bStereoRendering && GEngine->XRSystem.IsValid() && GEngine->XRSystem->GetHMDDevice())
	{
		DebugCanvasSize = GEngine->XRSystem->GetHMDDevice()->GetIdealDebugCanvasRenderTargetSize();
	}

	static FName DebugCanvasObjectName(TEXT("DebugCanvasObject"));
	UCanvas* DebugCanvasObject = GetCanvasByName(DebugCanvasObjectName);
	DebugCanvasObject->Init(DebugCanvasSize.X, DebugCanvasSize.Y, NULL, DebugCanvas);

    // ...
    
    // Render the player's HUD.
    // 这里是特征，会有一个判断，在IDA中翻译伪代码就是 if ( *(_QWORD *)(v238 + 0x0410) )
    // 这里的0x0410就是Dump SDK中MyHUD在APlayerController中的偏移
    // 找到 if ( *(_QWORD *)(v238 + 0x0410) )后，往下第2个call就是调用虚表函数，秒得PostRender下标
    if( PlayerController->MyHUD )
    {
        SCOPE_CYCLE_COUNTER(STAT_HudTime);

        DebugCanvasObject->SceneView = View;
        PlayerController->MyHUD->SetCanvas(CanvasObject, DebugCanvasObject);

        PlayerController->MyHUD->PostRender();

        // Put these pointers back as if a blueprint breakpoint hits during HUD PostRender they can
        // have been changed
        CanvasObject->Canvas = SceneCanvas;
        DebugCanvasObject->Canvas = DebugCanvas;

        // A side effect of PostRender is that the playercontroller could be destroyed
        if (!PlayerController->IsPendingKill())
        {
            PlayerController->MyHUD->SetCanvas(NULL, NULL);
        }
    }
    
    // ....
    
}
```



### IDA字符串

1. IDA中的Strings页面，搜索Unicode字符串
2. 可能会搜索出多条交叉引用，选其中一个最大的函数（约1700行左右的伪代码）

```c++
L"DebugCanvasObject"
```



### 直接拉到函数底部往上看

```c
__int64 __fastcall sub_14C9A7B80(__int64 a1, __int64 a2, __int64 a3)
{
    // ...
    
    // 这里的1024其实是APlayerController下MyHUD对象的偏移
    // 可以先Dump SDK，然后在IDA中搜索该偏移（Hex、Dec）就能快速定位到代码段
    if ( *(_QWORD *)(v237 + 1024) )
    {
        v249 = v291;
        *(_QWORD *)(v291 + 624) = v245;
        sub_14CA45BB0(*(_QWORD *)(v237 + 1024), v246, v249);
        // 这里是调用虚表中的PostRender函数，其下标为1840 / 8
        // PlayerController->MyHUD->PostRender();
        // 同时将自身MyHubd作为rcx进行传递
        // 直接对着这行代码下断点，就能定位到真正的PostRender函数，做特征码即可
        (*(void (__fastcall **)(_QWORD))(**(_QWORD **)(v237 + 1024) + 1840i64))(*(_QWORD *)(v237 + 1024));
        v250 = v291;
        *(_QWORD *)(v246 + 616) = v219;
        *(_QWORD *)(v250 + 616) = v293;
        v251 = *(_DWORD *)(v237 + 36);
        if ( (int)v251 >= (int)qword_154A9B22C )
        {
            v253 = 0i64;
        }
        else
        {
            v252 = (int)sub_1408F39D0(v251);
            v253 = *(_QWORD *)(qword_154A9B238 + 8 * v252) + 24i64 * (int)sub_1408F41D0(v251);
        }
        if ( (*(_DWORD *)(v253 + 8) & 0x20000000) == 0 )
            sub_14CA45BB0(*(_QWORD *)(v237 + 1024), 0i64, 0i64);
        v219 = v284;
    }
    
    // ...
}
```



### 特征码

1. 搜索到特征码后，向前搜索0x1000字节，找到"40 55"即"push rbp"即为函数头部

```c
"48 89 9B ?? ?? ?? ?? 48 8B CE C7 83 ?? ?? ?? ?? ?? ?? ?? ?? C7 83 ?? ?? ?? ?? ?? ?? ?? ?? C7 83 ?? ?? ?? ?? ?? ?? ?? ?? 48 C7 83 ?? ?? ?? ?? ?? ?? ?? ?? 48 8B 96 ?? ?? ?? ?? 48 8B 06 4C 8D 82 ?? ?? ?? ?? 48 81 C2 ?? ?? ?? ?? FF 90 ?? ?? ?? ?? E9"
```

```c
DeltaForceClient-Win64-Shipping_dump.exe+CA4B19D - 48 89 9B 60020000     - mov [rbx+00000260],rbx
DeltaForceClient-Win64-Shipping_dump.exe+CA4B1A4 - 48 8B CE              - mov rcx,rsi
DeltaForceClient-Win64-Shipping_dump.exe+CA4B1A7 - C7 83 58020000 00008040 - mov [rbx+00000258],40800000
DeltaForceClient-Win64-Shipping_dump.exe+CA4B1B1 - C7 83 5C020000 00004842 - mov [rbx+0000025C],42480000
DeltaForceClient-Win64-Shipping_dump.exe+CA4B1BB - C7 83 48020000 00008040 - mov [rbx+00000248],40800000
DeltaForceClient-Win64-Shipping_dump.exe+CA4B1C5 - 48 C7 83 4C020000 00004842 - mov qword ptr [rbx+0000024C],42480000
DeltaForceClient-Win64-Shipping_dump.exe+CA4B1D0 - 48 8B 96 C8030000     - mov rdx,[rsi+000003C8]
DeltaForceClient-Win64-Shipping_dump.exe+CA4B1D7 - 48 8B 06              - mov rax,[rsi]
DeltaForceClient-Win64-Shipping_dump.exe+CA4B1DA - 4C 8D 82 4C020000     - lea r8,[rdx+0000024C]
DeltaForceClient-Win64-Shipping_dump.exe+CA4B1E1 - 48 81 C2 54020000     - add rdx,00000254
DeltaForceClient-Win64-Shipping_dump.exe+CA4B1E8 - FF 90 08070000        - call qword ptr [rax+00000708]
```
