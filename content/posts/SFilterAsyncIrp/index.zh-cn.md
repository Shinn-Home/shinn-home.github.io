---
title: "SFilter框架(2)：异步处理IRP"
date: 2022-09-19T12:00:00+08:00
lastmod: 2022-09-19T12:00:00+08:00
draft: false
author: "Shinn"
images: []
tags: ["SFilter", "IRP异步处理", "Windows内核"]
categories: ["Windows驱动开发"]

twemoji: false
lightgallery: true
---

<!--more-->

## IRP异步处理（R0反向通知R3）

### 业务需求场景

1. 但是在`SFilter文件过滤`驱动开发中，当过滤到敏感的文件操作后，**驱动是不能私自决定放行、拦截**的，此时一个人性化的功能就出现了，驱动将敏感操作的信息（操作者、操作的文件信息）发送到R3，由应用程序弹出一个窗口**询问用户**是拦截、还是放行
2. 此时问题就来了，在常规的Win驱动开发中，大部分的时间内，处于内核态的驱动程序都是被动地接受R3下发的命令，解析后执行不同的分发命令，驱动该如何反向通知R3应用程序呢？



### 实现方式

1. 此时就有一个非常常用的手法，叫做`Pending IRP`，实现思路如下（**只有思路，不涉及代码细节**）：
    1. R3程序开一条独立的线程，调用`ReadFile`、`DeviceIoControl`之类的函数都可以，只要能下发`IRP请求`到驱动的派遣回调函数中即可。
    2. 驱动派遣回调接收到IRP请求后，发现请求类型是`Pending`，将本次IRP请求挂起、并保存到一个链表中维护起来
    3. 此时R3程序的那条独立线程还是处于阻塞状态的，**`DeviceIoControl`函数是可以阻塞的**
    4. 一段时间后，当过滤到敏感的文件操作时，就会从`Pending链表`中取出一个挂起的IRP，将本次文件操作信息打包成协商好的结构，写到IRP缓冲区中、完成该IRP
    5. R3阻塞的线程放行，解析缓冲区中的结构，弹出对话框询问用户放行、拦截
2. 经过介绍，读者一眼就发现了，这种手法其实并不是R0主动通知R3，而是R3程序主动将"手"伸向了内核态、并且一直保持住（死等），当内核态真正有通知需求了，就把消息传递
3. 这种手法在早期的Legacy驱动工程中，可以说是非常主流的方法



## 代码实现（R0部分）

### 派遣回调挂起IRP

在驱动的派遣回调中，识别到本次为`Pending IRP`后，会做以下操作：

1. 将本次IRP挂起`IoMarkIrpPending`
2. 调用`IoAcquireCancelSpinLock`获取`Cancel锁`，这里是出于代码安全性考虑，只有获取到锁后，判断`Irp->Cancel`、设置`Irp->CancelRoutine`等操作才是安全、可靠的
    1. 这里可以设想一个极端情况，刚进入到我们驱动的派遣回调中的一瞬间，这个IRP就已经被取消了，但是代码不严谨，没判断好，将它当成了一个有效的IRP对象保存到了链表中，那么下次使用了就非常容易蓝屏
3. 获取到锁后，确保`Irp->Cancel = FALSE`后，就可以设置该IRP的取消回调了
    1. 为什么要设置取消回调，设想一个场景，n个IRP被保存到链表中，到那时R3程序意外退出了，那么IO Manager就会自动调用`CancelRoutine`释放这些IRP，避免内存泄露
4. 最后就是获取链表锁，将IRP保存到链表中
5. 部分代码如下

```c
NTSTATUS DispatchControl(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
)
{
    // ...
    
    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
        case IO_CTL_TEST_PENDING:
        {
            // 标记挂起IRP
            IoMarkIrpPending(Irp);

            if (Irp->Cancel)
            {
                status = STATUS_CANCELLED;
                Irp->IoStatus.Status = status;
                Irp->IoStatus.Information = 0;
                goto __Exit;
            }
            else
            {
                // 设置取消回调
                IoSetCancelRoutine(
            		Irp,
            		PendingIrpCancelRoutine
            	);
            }

            // 获取链表锁
            KeAcquireSpinLock(
                &g_PendingIrpLock,
                &queueIrql
            );

            InsertTailList(
        		&g_PendingIrpList,
        		&Irp->Tail.Overlay.ListEntry
        	);

            KeReleaseSpinLock(
        		&g_PendingIrpLock,
        		queueIrql
        	);
            
        }
            
    }

    
__Exit:
    IoCompleteRequest(
        Irp,
        IO_NO_INCREMENT
    );

    return status;
}
```



### 模拟触发Pending IRP

1. 经过前小结的铺垫，此时我们已经制造好了`Pending IRP`，那么在实际业务逻辑中，在文件过滤回调中，就能消费这些挂起的IRP
2. 出于试验、学习的目的，我们有以下几种消费挂起IRP的方法：
    1. 我们可以开一条内核线程，固定周期内循环从全局链表中取出挂起的IRP、并恢复，达到模拟通知R3的效果
    2. R3主动调用`DeviceIoControl`，跳过特定的控制码，模拟触发也行

```c
NTSTATUS DispatchControl(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
)
{
    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
        case IO_CTL_TEST:
        {
            // 获取链表锁
            KeAcquireSpinLock(
                &g_PendingIrpLock,
                &queueIrql
            );

            PLIST_ENTRY Entry;

            if (!IsListEmpty(&g_PendingIrpList))
            {
                Entry = RemoveTailList(&g_PendingIrpList);
            }

            KeReleaseSpinLock(
        		&g_PendingIrpLock,
        		queueIrql
        	);

            pending_irp = CONTAINING_RECORD(
    			Entry,
    			IRP,
    			Tail.Overlay.ListEntry
    		);

            status = STATUS_SUCCESS;
            pending_irp->IoStatus.Status = status;
            pending_irp->IoStatus.Information = 0;

            IoCompleteRequest(
                pending_irp,
                IO_NO_INCREMENT
            );
            
        }       
            
    }

}
```



## 代码实现（R3部分）

1. 关于R3代码实现，这里笔者遇到了一个坑：
    1. 仅仅打开一次符号链接
    2. 先在独立线程中，调用`DeviceIoControl`下发`Pending IRP`
    3. 然后在主线程中，正常调用`DeviceIoControl`下发模拟消费`Pending IRP`的命令
    4. 此时跑起来就会发现，步骤`1.3`似乎不会触发到驱动的派遣回调中
    5. 笔者这里推断，打开一次符号链接返回的设备句柄，如果已经有了`Pending`待处理的IRP，再尝试下发IRP请求，阻塞住，即`DeviceIoControl`函数一直不返回、也不报错
2. 关于这一个坑，解决办法就是打开2次符号链接，得到2个独立的设备句柄即可



### 独立线程循环下发Pending IRP

1. 在独立线程循环下发`Pending IRP`时，我们以**同步方式下发IRP请求**，这样R0不处理该IRP，我们的`DeviceIoControl`就一直死等
2. **笔者被误导**，坑点：
    1. 某些课程中会创建一个`Event`等待事件，以异步方式调用`DeviceIoControl`，这样R0挂起该IRP后，`DeviceIoControl`函数返回，之后调用`WaitForSingleObject`阻塞线程，开始死等
    2. 这种操作何必呢？？？多写了这些代码，导致逻辑变复杂，不利于初学者理解`Pending IRP`原理。而且这种写法也没带来什么性能收益。

```c
// 独立、阻塞线程，会循环下发pending irp
void NotifyThread()
{
    // 打开一份独立的设备句柄
	NotifyDevice = CreateFileW(SYMBOL_LINK_NAME, ...);

    wchar_t buffer[MAX_PATH] = {};

	while (true)
	{
        // 同步方式，下发IRP请求，R0不处理就死等
		BOOL result = DeviceIoControl(..., IO_CTL_TEST_PENDING, buffer, ..., NULL);

        printf_s("等到R0信息了: %ws\n", buffer);
	}

	// 关闭设备句柄
}
```



### R0通知R3

1. 我们可以下发命令主动消费全局链表中的`Pending IRP`，模拟R0主动通知R3

```c
int main()
{
    // 启动阻塞线程，循环下发pending irp
    CreateThread(..., NotifyThread, ...);
    Sleep(100);
    
    HANDLE g_ControlDevice;
	g_ControlDevice = CreateFileW(SYMBOL_LINK_NAME, ...);

    // 模拟消费pending irp
    BOOL result = DeviceIoControl(..., IO_CTL_TEST, buffer, ...);
}
```
