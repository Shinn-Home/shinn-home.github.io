---
title: "SFilter框架(3)：规则下发、规则匹配"
date: 2022-09-29T12:00:00+08:00
lastmod: 2022-09-29T12:00:00+08:00
draft: false
author: "Shinn"
images: []
tags: ["文件过滤驱动", "驱动开发", "Windows内核"]
categories: ["Windows驱动开发"]

twemoji: false
lightgallery: true
---

<!--more-->

## Win中的文件路径

1. 这里需要植入一个前置思想：Win平台中使用的路径只有`Dos路径`、`NT路径`两种，如下所示：

```c
DOS 路径
C:\Windows\System32\xxx.sys

NT 路径
\Device\HarddiskVolume3\Windows\System32\xxx.sys
```

2. 在我们日常工作中，遇到的99%文件路径都是`Dos路径`
3. 但是不要忘记一句话：**Windows下万物皆对象**，系统内核在运行时，会将硬盘也当作一个内核对象，即`\Device\HarddiskVolume3`，但是为了让R3程序可以正常使用这个对象，必须创建一个符号链接，将该内核对象暴露到3环，这个符号链接就是`C:`
4. 这里笔者有一个比较武断、但是好理解的说法：Win内核在运行时，涉及到的各种文件路径，**最后都会统一转换**为`NT路径`访问目标文件

```c
DOS 路径
C:\Windows\System32\xxx.sys
        │
        │ 盘符 C: 是符号链接
        ↓
NT 路径
\Device\HarddiskVolume3\Windows\System32\xxx.sys
        │
        └── \Device\HarddiskVolume3 = Volume 的设备对象名称
```



## SFilter驱动中Create回调

```c
NTSTATUS FsFilterDispatchCreate(
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP           Irp
    )
{
    PFILE_OBJECT pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;

	/*
	
		\Users\Administrator\Desktop\Dbgview.vmp.exe.lnk
		\Users\Administrator\Desktop
		\Users\Administrator\Desktop
		\Users\Administrator\Desktop\Dbgview.vmp.exe.lnk
	
	*/
    DbgPrint("%wZ\n", &pFileObject->FileName);

    return FsFilterDispatchPassThrough(DeviceObject, Irp);
}
```

1. 可以看到，在`FsFilterCreate`回调中能直接获取到的是**相对路径**，假设该文件为C盘

```c
R3程序
C:\Users\Administrator\Desktop\Dbgview.vmp.exe

R0程序
\Device\HarddiskVolume3\Users\Administrator\Desktop\Dbgview.vmp.exe
```

2. 出于我们的开发习惯，不管是**设计**主防规则、还是**匹配**主防规则时，我们都希望统一面对的是`Dos路径`



## 坑点

### NT路径转Dos路径

1. 在`Legacy驱动`中路径转换是非常麻烦、费力的事情，没必要花大量时间自己实现一套完美的路径获取、路径转换库
2. 在实际工作中，`Legacy工程`直接选用已经被市场验证过功能完善、运行稳定的库。如果是`MiniFilter框架`，更是几行代码就实现了路径获取、转换



### 长短名问题

1. 短名：技术债，也叫8.3文件名
2. `C:\PROGRA~1\`、`C:\Program Files`指向的是同一个目录
3. 如果不将短名转为长名，就会导致**规则匹配遗漏**问题



### FsCreate不一定是打开文件

1. 也有可能是打开（新建）一个目录，打开目录这个行为本身不是高危动作，`Hips`一般会放行



## 规则匹配（通配符）

1. `Hips`主防驱动中，常用的是**通配符表达式**，例如设置规则`C:\Windows\System32\*.sys`，表示监控该路径下的所有驱动文件操作
