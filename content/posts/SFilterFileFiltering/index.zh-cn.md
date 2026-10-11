---
title: "SFilter框架(1)：文件过滤"
date: 2022-09-06T12:00:00+08:00
lastmod: 2022-09-06T12:00:00+08:00
draft: false
author: "Shinn"
images: []
tags: ["文件过滤驱动", "驱动开发", "Windows内核"]
categories: ["Windows驱动开发"]

twemoji: false
lightgallery: true
---

<!--more-->

> 本文主要是学习SFilter文件过滤框架笔记，该工程结构清晰，仅实现了文件过滤，不涉及到任何实际业务逻辑，适合刚接触文件过滤体系的初学者
>



## 过滤驱动、设备对象

### 控制设备对象CDO、过滤设备对象Filter DO

1. 一个`Filter`驱动工程可以多次调用`IoCreateDevice`，创建出多个过滤设备对象后，附加到目标设备栈上，实现IRP过滤，那么`IO Manager`是如何管理这么多过滤设备对象的呢？方法如下：
    1. `DriverObject->DeviceObject`成员保存的其实是一个**单链表头**，`DeviceObject->NextDevice`指向下一个设备对象，一直遍历即可
2. 规范的`Filter`驱动工程，往往会**单独保存**`控制设备对象CDO`，不然怎么跟自家R3程序通讯？
    1. 因为控制设备对象、过滤设备对象，这些都只是**开发者根据其用途区分的叫法**，在代码层面，他们都是设备对象，没任何区别
3. 同一个驱动对象创建出n个设备对象，驱动卸载时需要一个个删除设备，那么该如何找出**所有设备对象**？
    1. 使用`IoEnumerateDeviceObjectList`枚举一个驱动对象所创建的所有设备对象
    2. `DriverObject->DeviceObject`拿到单链表头，向下遍历



### 驱动过滤

1. Win系统一定会使用到各种各样的外设，例如串口、键盘、硬盘等等，系统控制这些物理外设的流程如下（以范围磁盘为例）：

```c
用户调用ReadFile发起一个读文件请求
|
内核NtReadFile
|
系统I/O Manager构造一个IRP_MJ_READ的IRP包
|
文件系统设备栈（设备栈中每一个设备对象，可能由NTFS.sys、Fat32.sys等驱动创建）
             （IRP结构中的IO_STACK_LOCATION的层数，跟设备栈的层数是一一对应的）
|
物理外设
```

2. 由以上可知，这是最原始的IO流程，但是随着时代的发展，催生出了各种现代化的安全需要：文件主防、透明加解密等等操作，所以微软提供了一种官方的操作，如下所示：
    1. 第三方厂商的驱动，可以自己创建设备对象，附加到设备栈上，例如文件系统设备栈、串口设备栈、键盘设备栈上
    2. 这样IO系统，每次下发IRP请求时，厂商自己的设备对象就有机会提前处理这个IRP请求，例如：检查参数、修改参数、拦截本次IRP操作。亦或者放行本次IRP，让下层设备对象处理
    3. 假设我们现在自己创建一个设备对象，并附加到文件系统设备栈上了，此时用户所有的文件操作我们都可以知道，要实现文件保护，可以判断其中文件名，符合规则就拦截本次IRP请求。要实现文件透明加解密也是可以的
    4. 当然，假设我们需要分析某一个疑似恶意驱动，我们可以附加到其设备对象上，这样我们就监控其IRP参数，分析其行为
3. 看到这里可知，驱动过滤跟Hook一样属于非常大的架构思想。其不指代某一组特定的API，而是在一条既定的流程中，插入我们自己的逻辑

```z80
Hook实现
修改函数指针、Inline Hook等等操作

驱动过滤
向设备栈插入我们自己的设备对象，在正常的系统IO派发流程中，插入我们的逻辑
```

4. 笔者这里举一个**形象的例子**，这个驱动过滤，就是将我们的"眼线"，安插到系统正常IO的流程中，这样一旦发生了IRP请求时，我们都知道、并且有机会处理



## 注册驱动派遣分发函数

1. 这个点其实之前一直没咋关注，是因为之前写的驱动，都是**很机械化地**注册派遣函数实现通讯，控制设备的通讯原理都不清楚，跟着教程抄一遍代码实现功能就完事了
2. 一个驱动的关键就是派遣函数，通过注册派遣函数，向系统暴露出一组具备特定功能的函数列表，当系统的`I/O Manager`中有事件时，便会构造IRP包，调用你的派遣回调
3. 这个派遣函数列表是保存到`DriverObject`下的
4. 所以一个文件过滤驱动，其派遣函数的业务逻辑往往比较复杂，需要同时处理**驱动通讯**、**文件过滤处理规则**
5. 由于本工程出于学习、教育目的，无3环程序部分，所以`驱动入口函数`中没有创建`控制设备对象`
6. 注册驱动派遣函数如下所示：

```c
// 统一注册一个默认的派遣回调，不关心的操作直接透传IRP
for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i) 
{
    DriverObject->MajorFunction[i] = FsFilterDispatchPassThrough;
}

// 再设置一个我们感兴趣的回调，文件打开时让我们有机会处理
DriverObject->MajorFunction[IRP_MJ_CREATE] = FsFilterDispatchCreate;
```

7. 由于大多数的主防，都是针对文件创建时的检查，所以这里仅设置了`IRP_MJ_CREATE`，在文件创建时，插入我们自定义的逻辑
8. 其余回调，我们并不关心，直接`透传IRP`让下层驱动的派遣函数处理即可



### 透传IRP

1. 在`FsFilterDispatchPassThrough`回调中，我们不做任何的参数监控、过滤操作，而是直接`透传IRP`，相当于我们这一层过滤不存在
2. `IoSkipCurrentIrpStackLocation`内部处理，可粗略理解为**栈指针++**
3. `IoCallDriver`内部处理时，可以理解为**栈指针--**，这样在下层过滤驱动的回调中，**直接复用IRP**

```c
NTSTATUS FsFilterDispatchPassThrough(
    __in PDEVICE_OBJECT DeviceObject, 
    __in PIRP           Irp
    )
{
    PFSFILTER_DEVICE_EXTENSION pDevExt = (PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension;

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(pDevExt->AttachedToDeviceObject, Irp);
}
```



### 单独处理IRP_MJ_CREATE请求

1. 大部分的EDR、主防、透明加解密驱动，关心的操作都是文件创建请求，所以在本基础工程中，单独处理了该请求，代码如下所示：
2. 如下回调中，仅仅是输出文件参数，不做任何修改操作

```c
NTSTATUS FsFilterDispatchCreate(
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP           Irp
    )
{
    PFILE_OBJECT pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
    DbgPrint("%wZ\n", &pFileObject->FileName);

    // 透传IRP
    return FsFilterDispatchPassThrough(DeviceObject, Irp);
}
```



## 注册FastIO回调

1. 首先我们来看一下原工程中的代码实现，这里其实是构造了一个函数回调表，之后将该表对象直接挂载到驱动对象下

```c
FAST_IO_DISPATCH g_fastIoDispatch =
{
    sizeof(FAST_IO_DISPATCH),
    FsFilterFastIoCheckIfPossible,
    FsFilterFastIoRead,
    FsFilterFastIoWrite,
    // ...
};

DriverObject->FastIoDispatch = &g_fastIoDispatch;
```

2. 笔者这里首次遇到了**FastIO**这个概念，顾名思义，这个机制的出现就是为了提高效率嘛，这里的快速是指是传统的构造IRP下发的路径，构造IRP对象其实是比较沉重的资源开销，这里以`IRP_MJ_READ`操作为例简述其原理
    1. 当涉及到IO操作时，IO Manager首先尝试调用驱动的`FastIoRead`回调
    2. 如果支持快速IO，那么在`FastIoRead`回调中就完成本次`读请求`，并返回TRUE
    3. 如果不支持快速IO，直接返回FALSE，让IO管理器回退到构造IRP派发路径

```c
FastIoRead()
    │
    ├── TRUE
    │      └── 本次 I/O 已经被快速路径处理
    │
    └── FALSE
           └── 本次请求不能走 Fast I/O
                  ↓
                回退到 IRP
```

3. 这个机制有哪些优势场景，设想如下场景：
    1. 当用户需要反复读取16字节的文件时，重复1000次，就重复构造了1000个IRP对象并下发
    2. 有了FastIO机制后，每次读16字节，都会尝试从文件缓存中读取，如果能读取就不构造IRP了
    3. 当然，如果FastIo处理不了，还是会回退到传统构造IRP的老路径
4. 在本基础工程中，接管`FastIO`请求，核心目的是将本次IRP请求，赶回到传统的IRP请求，避免文件过滤遗漏



## 注册"文件系统变动"回调

1. 既然我们的目标是实现文件过滤，那么我们需要将每一个存储设备栈上，都插入我们自己的设备对象，那么需要手动遍历所有的存储设备对象吗？当然不用，系统提供了注册回调，如下所示：

```c
VOID FsFilterNotificationCallback(
    __in PDEVICE_OBJECT DeviceObject,
    __in BOOLEAN        FsActive
);

status = IoRegisterFsRegistrationChange(DriverObject, FsFilterNotificationCallback); 
if (!NT_SUCCESS(status)) 
{
    return status;
}
```

2. 成功注册这个回调后，系统会将**已有的**文件系统通知我们的回调（类似附加调试的假消息派发），之后系统`注册`、`注销`的文件系统都会调用我们的回调
    1. 例如我们插入一个存储设备，系统要正常访问U盘中的内容，必须要为其注册一个文件系统，那么就会自然调用到我们的回调，做到间接监听到了U盘的插入。当U盘拔出，文件系统会注销，也会进入我们的回调
3. 在我们的回调中，会判断本次是文件系统是注册、还是注销。如果是注册，就会创建一个新的设备对象、并附加上去

```c
VOID FsFilterNotificationCallback(
    __in PDEVICE_OBJECT DeviceObject,
    __in BOOLEAN        FsActive
    )
{
    if (FsActive)
    {
        FsFilterAttachToFileSystemDevice(DeviceObject);
    }
    else
    {
        FsFilterDetachFromFileSystemDevice(DeviceObject);
    }
}
```



## 回调被调用

### 附加控制设备对象CDO

1. 当回调被调用时，会携带2个参数：

```c
VOID FsFilterNotificationCallback(
    __in PDEVICE_OBJECT DeviceObject,		// 设备对象
    __in BOOLEAN        FsActive				// 注册、注销
);
```

2. 需要注意的是，回调传入的设备对象，大概率是一个**控制设备对象**，根据前文的铺垫可知，我们附加到控制设备对象上，是无法实现文件过滤的，但是在`SFilter`工程中，仍然创建了一个新设备对象、并附加上去，代码如下：

```c
NTSTATUS FsFilterAttachToDevice(
    __in PDEVICE_OBJECT         DeviceObject,
    __out_opt PDEVICE_OBJECT*   pFilterDeviceObject
    )
{
    // 省略部分变量定义，不影响阅读...

    //
    //  创建一个新的设备对象
    //

    status = IoCreateDevice(
        g_fsFilterDriverObject,
        sizeof(FSFILTER_DEVICE_EXTENSION),
        NULL,
        DeviceObject->DeviceType,
        0,
        FALSE,
        &filterDeviceObject);

    if (!NT_SUCCESS(status)) 
    {
        return status;
    }

    pDevExt = (PFSFILTER_DEVICE_EXTENSION)filterDeviceObject->DeviceExtension;

    //
    //  我们新创建的设备对象，Flags标志跟目标设备Flags要保持一致
    //

    if (FlagOn(DeviceObject->Flags, DO_BUFFERED_IO)) 
    {
        SetFlag(filterDeviceObject->Flags, DO_BUFFERED_IO);
    }
    else if (FlagOn(DeviceObject->Flags, DO_DIRECT_IO)) 
    {
        SetFlag(filterDeviceObject->Flags, DO_DIRECT_IO);
    }

    if (FlagOn(DeviceObject->Characteristics, FILE_DEVICE_SECURE_OPEN)) 
    {
        SetFlag(filterDeviceObject->Characteristics, FILE_DEVICE_SECURE_OPEN);
    }    

    //
    //  这里有重试机制，因为回调进来的时候，该设备可能还没初始化好
    //

    for (i = 0; i < 8; ++i) 
    {
        LARGE_INTEGER interval;

        status = IoAttachDeviceToDeviceStackSafe(
            filterDeviceObject,
            DeviceObject,
            &pDevExt->AttachedToDeviceObject);

        if (NT_SUCCESS(status)) 
        {
            break;
        }

        interval.QuadPart = (500 * DELAY_ONE_MILLISECOND);
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }

    if (!NT_SUCCESS(status))
    {
        //
        // Clean up.
        //

        IoDeleteDevice(filterDeviceObject);
        filterDeviceObject = NULL;
    }
    else
    {
        //
        // 到了这里，我们新创建的设备对象，可以设置为"初始化"完成了，可以接收IRP
        // 即可以参与到驱动过滤了
        //

        ClearFlag(filterDeviceObject->Flags, DO_DEVICE_INITIALIZING);

        if (NULL != pFilterDeviceObject)
        {
            *pFilterDeviceObject = filterDeviceObject;
        }        
    }

    return status;
}
```

3. 明明是`控制设备对象CDO`，为什么还要附加上去呢，原因如下：
    1. 我们附加到`CDO`，目的是为了过滤该设备的`IRP_MJ_FILE_SYSTEM_CONTROL`、以及子功能号`IRP_MN_MOUNT_VOLUME`
    2. 这样我们在`IRP_MJ_FILE_SYSTEM_CONTROL`回调中，通过判断子功能号`IRP_MN_MOUNT_VOLUME`就能知道，有新的卷被挂载了
    3. 我们就继续创建设备对象附加上去，这样就**不会遗漏文件IRP请求**了
    4. 如果不做这个处理，举个例子：假设一个磁盘设备，其`磁盘驱动.sys`有一个CDO，在我们的驱动加载之后的某一时刻，这个硬盘挂载了一个新卷，**这一动作我们是感知不到的**，此时任何对该**新卷的文件IRP操作都会遗漏**



### 遍历该设备下的所有卷、并附加

1. 上一小节中，我们附加到了控制设备对象CDO，这其实是出于文件过滤的安全性考虑的，是为了以后可能发生的情况考虑，此时我们还是过滤不到任何文件IRP请求的
2. 此时我们的情况是这样的，回调携带的是一个控制设备对象CDO，我们该如何通过这个CDO，附加该设备所有的卷设备对象呢？流程如下：
    1. 设备对象下，会保存`DrvObj`，指示这个设备对象属于哪个驱动对象
    2. 拿到`DrvObj`，配合使用`IoEnumerateDeviceObjectList`，可以获取到这个`DrvObj`创建的所有设备对象`DevObj`
    3. 判断`DevObj->DevType`设备类型是不是我们要的，如果是就创建设备对象并附加上去
    4. 规范开发点：`IoEnumerateDeviceObjectList`返回的设备对象，引用计数+1，此时我们需要解除对象引用

```c
NTSTATUS FsFilterEnumerateFileSystemVolumes(
    __in PDEVICE_OBJECT DeviceObject
    )
{
    // 省略部分变量定义，不影响阅读...

    //
    //  Now get the list of devices.
    //

    status = IoEnumerateDeviceObjectList(
        DeviceObject->DriverObject,
        devList,
        sizeof(devList),
        &numDevices);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    numDevices = min(numDevices, RTL_NUMBER_OF(devList));

    //
    //  Walk the given list of devices and attach to them if we should.
    //

    for (i = 0; i < numDevices; ++i) 
    {        
        //
        //  Do not attach if:
        //      - This is the control device object (the one passed in)
        //      - The device type does not match
        //      - We are already attached to it.
        //

        if (devList[i] != DeviceObject &&
            devList[i]->DeviceType == DeviceObject->DeviceType &&
            !FsFilterIsAttachedToDevice(devList[i])) 
        {
            status = FsFilterAttachToDevice(devList[i], NULL);
        }       

        ObDereferenceObject(devList[i]);
    }

    return STATUS_SUCCESS;
}
```



### 避免重复附加设备栈

1. 我们该如何判断一个设备栈中，是不是已经存在了我们的过滤设备对象？
2. 如果已经存在了，从资源、性能角度考虑，应该直接跳过该设备栈，避免重复创建设备对象、重复附加
3. 要实现这个判断，原理非常简单：
    1. 我们拿到目标设备对象后，使用`IoGetAttachedDeviceReference`获取目标设备栈顶部的设备对象，如果目标设备对象已经是顶部了，那么就返回自身
    2. 拿到顶部设备对象后，我们使用`IoGetLowerDeviceObject`一级级往下遍历，如果下边没有了，就返回`NULL`
    3. 判断`DevObj->DriverObject`是不是我们驱动入口点的驱动对象，如果是就说明这个栈我们已经安插"眼线"了
    4. 规范开发点：`IoGetAttachedDeviceReference`、`IoGetLowerDeviceObject`都会增加引用计数，需要解除引用

```c
BOOLEAN FsFilterIsAttachedToDevice(
    __in PDEVICE_OBJECT DeviceObject
    )
{
    PDEVICE_OBJECT nextDevObj    = NULL;
    PDEVICE_OBJECT currentDevObj = IoGetAttachedDeviceReference(DeviceObject);
    
    //
    //  Scan down the list to find our device object.
    //

    do 
    {
        if (FsFilterIsMyDeviceObject(currentDevObj)) 
        {
            ObDereferenceObject(currentDevObj);
            return TRUE;
        }

        //
        //  Get the next attached object.
        //

        nextDevObj = IoGetLowerDeviceObject(currentDevObj);

        //
        //  Dereference our current device object, before moving to the next one.
        //

        ObDereferenceObject(currentDevObj);
        currentDevObj = nextDevObj;
    } while (NULL != currentDevObj);

    return FALSE;
}
```



## 新卷加载

1. 当插入一个U盘、格式化了一个未初始化的分区、网络盘等等，都会导致新卷加载，为了保证文件过滤功能的健壮，我们是不是需要继续创建新的设备对象、并附加上去？**答案是必然**的
2. 还记得在前文中，我们附加了磁盘驱动的控制设备对象CDO吗？就是为了这种情况考虑，工作流程如下：
    1. 当新卷加载时，驱动的`IRP_MJ_FILE_SYSTEM_CONTROL`回调会被调用，同时在回调中判断子功能号是否为`IRP_MN_MOUNT_VOLUME`，如果是挂载卷的功能号，说明此时有新卷挂载
    2. 但是不要忘了，由于我们的过滤设备对象是处于设备栈的顶部（不考虑存在其他文件过滤驱动的存在），本身就最早接收到了卷挂载消息，**此时卷还没挂载**！
    3. 真正卷挂载操作，应该是由下层的磁盘驱动来完成的
    4. 所以我们这里需要设置一个`IRP完成回调`，当下层的磁盘设备驱动完成卷挂载后，会调用`IoCompleteRequest`函数，显式告诉IO Manager，本次IRP请求完成了，之后再调用我们注册的`完成回调`
    5. 在完成回调中，我们可以大胆认为卷挂载完成了，可以做附加操作了

```c
if (irpSp->MinorFunction == IRP_MN_MOUNT_VOLUME)
{
    // 复制当前IRP栈参数，覆盖到下层
    IoCopyCurrentIrpStackLocationToNext(Irp);

    // 注册一个完成回调
    IoSetCompletionRoutine(
        Irp,
        FsFilterMountVolumeCompletion,
        NULL,
        TRUE,
        TRUE,
        TRUE);

    return IoCallDriver(
        devExt->AttachedToDeviceObject,
        Irp);
}
```



### IRP完成回调（IRQL处理）

1. 这里需要重复强调的一点，作为Win内核驱动开发者，一定要对IRQL等级极其关注，保持敬畏。
2. 卷挂载成功后，会调用`FsFilterMountVolumeCompletion`，代码如下所示
3. 在`FsFilterMountVolumeCompletion`中，并不会直接创建过滤设备对象、附加，而是将该过程延迟到工作区队列中完成
4. 这是因为`FsFilterMountVolumeCompletion`被调用时的IRQL等级，是由下层驱动调用`IoCompleteRequest`函数时决定的，此时的IRQL等级是不固定的，实验室、PoC工程跑着玩可能没啥事，但是公开版本后，就可能有乱七八糟的随机蓝屏
5. 而工作队列中，是可以保证IRQL == PASSIVE_LEVEL，是可以安全地附加过去

```c
typedef struct _FSFILTER_MOUNT_WORK_ITEM
{
    WORK_QUEUE_ITEM WorkItem;
    PDEVICE_OBJECT VolumeDeviceObject;
} FSFILTER_MOUNT_WORK_ITEM, *PFSFILTER_MOUNT_WORK_ITEM;

static VOID
FsFilterMountWorkItem(
    __in PVOID Context
    )
{
    PFSFILTER_MOUNT_WORK_ITEM workItem =
        (PFSFILTER_MOUNT_WORK_ITEM)Context;

    if (workItem->VolumeDeviceObject != NULL)
    {
        if (!FsFilterIsAttachedToDevice(workItem->VolumeDeviceObject))
        {
            NTSTATUS status;

            status = FsFilterAttachToDevice(
                workItem->VolumeDeviceObject,
                NULL);

            if (!NT_SUCCESS(status))
            {
                DbgPrint(
                    "FsFilter: attach new volume failed: 0x%08X\n",
                    status);
            }
        }

        ObDereferenceObject(workItem->VolumeDeviceObject);
    }

    ExFreePoolWithTag(workItem, 'mWsF');
}

static NTSTATUS
FsFilterMountVolumeCompletion(
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp,
    __in PVOID Context
    )
{
    PIO_STACK_LOCATION irpSp;
    PVPB vpb;
    PDEVICE_OBJECT volumeDeviceObject;
    PFSFILTER_MOUNT_WORK_ITEM workItem;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Context);

    if (Irp->PendingReturned)
    {
        IoMarkIrpPending(Irp);
    }

    if (!NT_SUCCESS(Irp->IoStatus.Status))
    {
        return STATUS_CONTINUE_COMPLETION;
    }

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    vpb = irpSp->Parameters.MountVolume.Vpb;

    if (vpb == NULL || vpb->DeviceObject == NULL)
    {
        return STATUS_CONTINUE_COMPLETION;
    }

    volumeDeviceObject = vpb->DeviceObject;

    workItem = ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(FSFILTER_MOUNT_WORK_ITEM),
        'mWsF');

    if (workItem == NULL)
    {
        return STATUS_CONTINUE_COMPLETION;
    }

    RtlZeroMemory(workItem, sizeof(*workItem));

    /*
     * VPB 和卷设备对象可能在完成例程返回后发生变化，
     * 因此排队前增加引用。
     */
    ObReferenceObject(volumeDeviceObject);
    workItem->VolumeDeviceObject = volumeDeviceObject;

    ExInitializeWorkItem(
        &workItem->WorkItem,
        FsFilterMountWorkItem,
        workItem);

    ExQueueWorkItem(
        &workItem->WorkItem,
        DelayedWorkQueue);

    return STATUS_CONTINUE_COMPLETION;
}
```



## 小结

1. 以上是**文件过滤驱动的工作原理**，往大了说也是**过滤驱动的原理**，出于学习的目的，很多细枝末节暂时不深究
2. 微软官方提供的SFilter工程，代码量很大、细节处理非常多。早期很多公司、企业在开发文件过滤驱动时，大多也是在官方SFilter框架的基础上开发业务功能，足以说明SFilter本身的健壮性、稳定性
