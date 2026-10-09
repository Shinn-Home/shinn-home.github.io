---
title: "进程对象、线程对象"
date: 2021-11-14T12:00:00+08:00
lastmod: 2021-11-14T12:00:00+08:00
draft: false
author: "Shinn"
images: []
tags: ["EPROCESS", "ETHREAD", "进程与线程", "内核对象", "Windows内核"]
categories: ["Windows内核分析"]

twemoji: false
lightgallery: true
---

<!--more-->

## 进程对象

1. Win系统在设计上，每一个R3的进程实体，在内核态都会有一个专门的内核对象叫做进程对象，这个对象叫做`EPROCESS`
2. 由于Win内核属于是混合架构，又区分出了运行体、微内核，所以`EPROCESS`的头部抽象为了`KPROCESS`
3. 关于`KPROCESS`，其中关键字段定义如下所示：

| KPROCESS字段成员       | 定义                                                         |
| ---------------------- | ------------------------------------------------------------ |
| _DISPATCH_HEADER分发头 | 拥有这个分发头的对象，说明这是可以使用`WaitForSingleObject`等待的对象 |
| DirectoryTableBase     | 进程的页目录表基址，四级分页下指向的是PML4T                  |
| ThreadListHead         | 当前线程的链表，其中包含了所有的线程对象`ETHREAD`            |
| Affinity               | 亲核性，规定了当前进程中的线程，可以运行在哪些核心上         |
| BasePriority           | 该进程创建新线程时，线程的默认优先级                         |
| KernelTime（UserTime） | 该进程处于内核态（用户态）的时间碎片统计                     |
| UserDirectoryTableBase | 在弃用内核页表隔离KPTI后，会有双Cr3                          |

4. 关于`EPROCESS`，其中关键字段定义如下所示：

| EPROCESS字段成员             | 定义                                                         |
| ---------------------------- | ------------------------------------------------------------ |
| Pcb                          | 指向一个KPROCESS成员                                         |
| UniqueProcessId              | 当前进程Id，也是全局句柄表中的句柄值                         |
| ActiveProcessLinks           | 双链表，正常进程都在其中                                     |
| CreateTime                   | 当前进程创建时间                                             |
| ExitTime                     | 进程退出时间，大部分情况下都是0。只有当进程退出后，会设置这个字段内容。这样需要注意：进程退出≠内核对象马上销毁 |
| Peb                          | 进程环境块，这是一块存在于R3的内存                           |
| ObjectTable                  | 进程句柄句柄表（私有句柄表），保存进程、线程、锁、定时器等等各种句柄 |
| Token                        | 进程权限令牌，提权关键字段，修改为System进程一致就是系统进程权限了 |
| AddressCreationLock          | 进程刚创建时不能分配内存，在**进程创建回调**中不能分配内存就是因为这把锁 |
| SectionObject                | 应该是主模块（exe）的节区对象                                |
| InheritedFromUniqueProcessId | 父进程Id                                                     |
| ImageFileName[15]            | 进程名，会截断                                               |
| DebugPort                    | 调试端口，存放调试对象，详细内容在后续**调试体系分析**中会展开 |
| WoW64Process                 | 32位进程的Peb                                                |
| ExitStatus                   | 进程是否退出，≠STATUS_PENDING就是退出了                      |
| VadRoot                      | Vad二叉树的根节点                                            |



## 线程对象

1. 线程对象也区分出了`ETHREAD`、`KTHREAD`

| KTHREAD字段                           | 定义                                                     |
| ------------------------------------- | -------------------------------------------------------- |
| _DISPATCH_HEADER分发头                | 线程是可等待对象                                         |
| InitialStack、StackLimit、KernelStack | 当前线程的栈底、栈顶、内核栈                             |
| Alerted                               | 线程可提前唤醒                                           |
| Teb                                   | 线程环境快                                               |
| TrapFrame                             | 线程从R3进入R0时，保存寄存器环境                         |
| ApcState、SavedApcState               | 跟APC调度相关，后续章节会详细展开                        |
| State                                 | 线程状态：运行中、就绪（在就绪链表）、等待（等待被调度） |
| BasePriority                          | 当前线程优先级                                           |
| PreviousMode                          | 当前线程的先前模式                                       |
| ThreadListEntry                       | 链接同进程下其他的线程                                   |
| Process                               | 当前线程所属进程对象                                     |
| WaitListEntry                         | 当前线程被挂到等待链表中时，就是靠这个来挂的             |

| ETHREAD字段             | 定义                                                         |
| ----------------------- | ------------------------------------------------------------ |
| Cid                     | 线程Id，也就是全局句柄表中的句柄值                           |
| ExitTime                | 线程退出时间，同理                                           |
| StartAddress            | 线程入口点，CreateThread、PsCreateSystemThread传入的线程回调 |
| Win32StartAddress       | Gui线程，该字段才有值                                        |
| ThreadInserted（Bit）   | 该位置1，说明当前线程已经插入到私有句柄表了，这里可以反调试，因为`OpenThread`会失败 |
| HideFromDebugger（Bit） | 该位置1则调试逃逸，该线程的所有异常消息，都不会派发到调试器  |
