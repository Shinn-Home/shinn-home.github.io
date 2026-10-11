---
title: "Win驱动开发基础(1)：链表、字符串、线程同步、文件、注册表操作"
date: 2021-06-18T12:00:00+08:00
lastmod: 2021-06-18T12:00:00+08:00
draft: false
author: "Shinn"
images: []
tags: ["驱动开发", "Windows内核"]
categories: ["Windows驱动开发"]

twemoji: false
lightgallery: true
---

<!--more-->

## 链表操作（list_entry）

### LIST_ENTRY与CONTAINING_RECORD

1. 双向链表：`LIST_ENTRY`只有`Flink`（后继）、`Blink`（前驱）两个指针，使用时把它嵌到自己的结构体里
2. `LIST_ENTRY`定义如下所示：

```c
//0x10 bytes (sizeof)
struct _LIST_ENTRY
{
    struct _LIST_ENTRY* Flink;                                              //0x0
    struct _LIST_ENTRY* Blink;                                              //0x8
};
```

3. 只拿到链表节点指针时，实验`CONTAINING_RECORD`宏：**用节点地址减去节点在容器中的偏移**，即可取出对象头部，如下所示：

```c
#define CONTAINING_RECORD(address, type, field) \
    ((type *)((PCHAR)(address) - (ULONG_PTR)(&((type *)0)->field)))
```

4. 自定义链表节点结构如下所示：

```c
typedef struct _MyData
{
	int NodeNum;
	LIST_ENTRY List;
	wchar_t Info[260];
}MyData;
```



### 实验代码

1. 完整的建链、头插、遍历、摘除流程如下所示：

```c
LIST_ENTRY g_ListHead;
NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObj, PUNICODE_STRING pRegPath)
{
    InitializeListHead(&g_ListHead);
    MyData NewNode[5];
    
	for (size_t i = 0; i < 5; i++)
	{
		NewNode[i].NodeNum = i;
		NewNode[i].Info[0] = i;
		NewNode[i].Info[1] = L'\0';
		InsertHeadList(&g_ListHead, &NewNode[i].List);
	}
    
	// 正序遍历
	LIST_ENTRY* ListNode = g_ListHead.Flink;
	while (ListNode != &g_ListHead)
	{
        MyData* pData = CONTAINING_RECORD(ListNode, MyData, List);
        DbgPrint("NodeNum = %d. \n", pData->NodeNum);
        DbgPrint("NOdeInfo = %ws. \n", pData->Info);
        pData->NodeNum++;
        pData->Info[0]++;
        ListNode = ListNode->Flink;
	}
    
	for (size_t i = 0; i < 5; i++)
	{
		RemoveHeadList(&g_ListHead);
	}
    
	return STATUS_SUCCESS;
}
```



## 字符串操作（kernel_string）

### UNICODE_STRING

1. 内核中统一使用`UNICODE_STRING`描述宽字符串，定义如下所示：

```c
//0x10 bytes (sizeof)
struct _UNICODE_STRING
{
    USHORT Length;                                                          //0x0
    USHORT MaximumLength;                                                   //0x2
    PWSTR Buffer;                                                           //0x8
};
```

2. 关键字段定义如下所示：

| 成员字段      | 定义                                                     |
| ------------- | -------------------------------------------------------- |
| Length        | **有效字节数**（不是字符数，不含结尾`\0`）               |
| MaximumLength | Buffer的总容量（字节数）                                 |
| Buffer        | 字符串内存指针                                           |

3. `DbgPrint`打印格式符：`%wZ`打印`UNICODE_STRING`、`%Z`打印`ANSI_STRING`、`%ws`打印宽字符指针



### 字符串初始化、字符串深拷贝

1. `RtlInitUnicodeString`函数：

```c
// Initial UniStr
const wchar_t* uStr = L"Unicode String!";
UNICODE_STRING Str1 = { 0 };
RtlInitUnicodeString(&Str1, uStr);
DbgPrint("Str1 = %wZ. \n", &Str1);
```

2. 字符串的深拷贝：

```c
UNICODE_STRING Str2 = { 0 };
Str2.Buffer = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'Copy');
if (Str2.Buffer)
{
	RtlZeroMemory(Str2.Buffer, PAGE_SIZE);
	Str2.Buffer[0] = L'\0';
	// 表示字符串有效字节数
	Str2.Length = 0;	
	Str2.MaximumLength = PAGE_SIZE;
	// Copy UniStr
	RtlCopyUnicodeString(&Str2, &Str1);
	DbgPrint("Str2 = %wZ. \n", &Str2);
	// Release Buf
	ExFreePoolWithTag(Str2.Buffer, 'Copy');
	Str2.Buffer = NULL;
	Str2.Length = Str2.MaximumLength = 0;
}
```

3. 要点：`RtlCopyUnicodeString`拷贝的是`Str1.Length`字节的内容，目标容量不够会截断（所以`MaximumLength`必须先行设置好）；分配与释放使用同一个内存Tag（`'Copy'`）



### 字符串比较、字符串追加子串

1. 比较：返回`0`表示相等，第三个参数`TRUE`表示不区分大小写：

```c
// Compare String
const wchar_t* uStr2 = L"Unicode";
RtlInitUnicodeString(&Str2, uStr2);
// 返回0表示字符串相等
LONG Ret = RtlCompareUnicodeString(&Str1, &Str2, TRUE);
DbgPrint("Compare Ret = %d. \n", Ret);
```

2. 追加（源是`const wchar_t*`）：

```c
// Append UniStr From Str
Str2.Buffer = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'Copy');
if (Str2.Buffer)
{
	RtlZeroMemory(Str2.Buffer, PAGE_SIZE);
	Str2.Buffer[0] = L'\0';
	Str2.Length = 0;
	Str2.MaximumLength = PAGE_SIZE;
	NTSTATUS Status = RtlAppendUnicodeToString(&Str2, L"Test Append UniStr From const wchar_t*");
	if (STATUS_BUFFER_TOO_SMALL == Status)
	{
		// TODO Err Log
	}
	else if (NT_SUCCESS(Status))
	{
		// TODO
	}
	// TODO - Free Memory
}
```



### Ansi与Unicode互转

1. 转换函数对IRQL有硬性要求，必须为`PASSIVE_LEVEL`，所以工程里包了一层判断：

```c
// MSDN规定IRQL必须为Passive级别
if (KeGetCurrentIrql() == PASSIVE_LEVEL)
{
	ANSI_STRING AnsiStr = { 0 };
	RtlInitAnsiString(&AnsiStr, "Ansi String");
	UNICODE_STRING ToUniStr = { 0 };
	NTSTATUS Status = RtlAnsiStringToUnicodeString(&ToUniStr, &AnsiStr, TRUE);
	if (NT_SUCCESS(Status))
	{
		DbgPrint("ToUniStr = %wZ. \n", &ToUniStr);
		RtlFreeUnicodeString(&ToUniStr);
	}
	UNICODE_STRING Str3 = { 0 };
	RtlInitUnicodeString(&Str3, L"Unicode String.");
	ANSI_STRING ToAnsiStr = { 0 };
	Status = RtlUnicodeStringToAnsiString(&ToAnsiStr, &Str3, TRUE);
	if (NT_SUCCESS(Status))
	{
		DbgPrint("ToAnsiStr = %Z. \n", &ToAnsiStr);
		RtlFreeAnsiString(&ToAnsiStr);
	}
}
```



## 多线程同步（Kernel_Mutex）

### 多线程竞争

1. 起多个系统线程对同一个全局变量做自增，验证无锁时的数据竞争：

```c
ULONG64 g_Var = 0;
KSPIN_LOCK g_SpinLock;
FAST_MUTEX g_fmMutex;
EX_PUSH_LOCK g_psLock;

VOID MyThreadProc(PVOID Context)
{
	UNREFERENCED_PARAMETER(Context);

	for (ULONG i = 0; i < 100 * 10000; i++)
	{
		//KIRQL OldIrql = KeAcquireSpinLockRaiseToDpc(&g_SpinLock);
		//ExAcquireFastMutex(&g_fmMutex);

		//ExAcquirePushLockExclusive(&g_psLock);

		ULONG64 Tmp = g_Var;
		Tmp++;
		g_Var = Tmp;
		
		//ExReleasePushLockExclusive(&g_psLock);

		//ExReleaseFastMutex(&g_fmMutex);
		//KeReleaseSpinLock(&g_SpinLock, OldIrql);
	}

	PsTerminateSystemThread(STATUS_SUCCESS);
}
```

2. `Tmp = g_Var; Tmp++; g_Var = Tmp;`这三行代码操作粒度不是原子的：多线程写入时，会存在数据丢失问题
3. 三种锁的加锁、解锁代码在工程里写好了（注释状态），逐个放开验证即可
4. 线程创建如下所示，共创建5条系统线程：

```c
HANDLE hThread = NULL;
for (ULONG i = 0; i < 5; i++)
{
	NTSTATUS Status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, MyThreadProc, NULL);
	if (!NT_SUCCESS(Status))
	{
		//DbgBreakPoint();
		return Status;
	}

}
```



### 三种锁对比

1. 三种锁的初始化都在`DriverEntry`里：

```c
// 初始化自旋锁
KeInitializeSpinLock(&g_SpinLock);

// 初始化快锁
ExInitializeFastMutex(&g_fmMutex);

// 初始化推锁
ExInitializePushLock(&g_psLock);
```

2. 三种锁的用法、特性对比如下所示：

| 锁                 | 加锁                          | 解锁                          | 特性                                                     |
| ------------------ | ----------------------------- | ----------------------------- | -------------------------------------------------------- |
| 自旋锁KSPIN_LOCK   | KeAcquireSpinLockRaiseToDpc   | KeReleaseSpinLock(OldIrql)    | 加锁时IRQL**提升到DPC级**，拿不到锁原地自旋，临界区必须极短 |
| 快锁FAST_MUTEX     | ExAcquireFastMutex            | ExReleaseFastMutex            | IRQL提升到APC级，拿不到锁时**睡眠等待**，适合较长临界区  |
| 推锁EX_PUSH_LOCK   | ExAcquirePushLockExclusive    | ExReleasePushLockExclusive    | 不提升IRQL，支持**共享/独占**两种模式，开销最小          |



## 文件操作（kernel_file）

### Zw系列文件API

1. 文件操作统一使用`Zw`系列API（`ZwCreateFile`、`ZwReadFile`、`ZwWriteFile`、`ZwDeleteFile`、`ZwClose`），头文件是`ntifs.h`，封装的打开、读、写、删函数如下所示：

```c
NTSTATUS MyCreateFile(HANDLE* hFile, const WCHAR* wFilePath)
{
	NTSTATUS Status = STATUS_SUCCESS;

	UNICODE_STRING uStrPath = { 0 };
	RtlInitUnicodeString(&uStrPath, wFilePath);

	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(
		&ObjectAttributes,
		&uStrPath, 
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 
		NULL, 
		NULL
	);

	IO_STATUS_BLOCK IoStatusBlock = { 0 };

	Status = ZwCreateFile(
		hFile, 
		FILE_ALL_ACCESS,
		&ObjectAttributes, 
		&IoStatusBlock, 
		NULL, 
		FILE_ATTRIBUTE_NORMAL, 
		FILE_SHARE_READ | FILE_SHARE_WRITE, 
		FILE_OPEN_IF, 
		FILE_NON_DIRECTORY_FILE, 
		NULL, 
		NULL
	);

	return Status;
}

NTSTATUS MyWriteFile(HANDLE hFile, PVOID pBuf, ULONG ulSize)
{
	NTSTATUS Status = STATUS_SUCCESS;

	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	LARGE_INTEGER ByteOffset;
	ByteOffset.QuadPart = 0;
	Status = ZwWriteFile(hFile, NULL, NULL, NULL, &IoStatusBlock, pBuf, ulSize, &ByteOffset, NULL);

	return Status;
}

NTSTATUS MyReadFile(HANDLE hFile, PVOID pBuf, ULONG ulSize)
{
	NTSTATUS Status = STATUS_SUCCESS;

	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	LARGE_INTEGER ByteOffset;
	ByteOffset.QuadPart = 0;
	Status = ZwReadFile(hFile, NULL, NULL, NULL, &IoStatusBlock, pBuf, ulSize, &ByteOffset, NULL);

	return Status;
}

NTSTATUS MyDeleteFile(const WCHAR* wFilePath)
{
	UNICODE_STRING uStrPath = { 0 };
	RtlInitUnicodeString(&uStrPath, wFilePath);

	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(
		&ObjectAttributes,
		&uStrPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
	);

	return ZwDeleteFile(&ObjectAttributes);
}
```

2. 关键参数说明：

| 参数/标志               | 说明                                                 |
| ----------------------- | ---------------------------------------------------- |
| OBJ_KERNEL_HANDLE       | 创建**内核句柄**，只能内核使用，不会泄漏到R3的句柄表 |
| OBJ_CASE_INSENSITIVE    | 忽略大小写                                           |
| FILE_OPEN_IF            | 打开方式：存在则打开，不存在则创建                   |
| FILE_NON_DIRECTORY_FILE | 打开的必须是文件，不是目录                           |
| FILE_SHARE_READ\|WRITE  | 共享模式，允许别人同时读写                           |
| ByteOffset.QuadPart = 0 | 读写起始偏移，0表示从文件头开始                      |

3. 路径格式：内核里不能用`C:\test.txt`这种DOS路径，要走对象管理器路径，`\\??\\c:\\test.txt`中的`\??\`就是映射到DOS盘符的前缀



### DriverEntry调用

1. 工程的`DriverEntry`只演示了创建文件：

```c
NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObj, PUNICODE_STRING pRegPath)
{
	UNREFERENCED_PARAMETER(pDrvObj);
	UNREFERENCED_PARAMETER(pRegPath);

	ASSERTMSG("Irql Mismatch", KeGetCurrentIrql() == PASSIVE_LEVEL);

	HANDLE hFile = NULL;
	NTSTATUS Status = MyCreateFile(&hFile, L"\\??\\c:\\test.txt");

	return Status;
}
```



## 注册表操作（registry）

### 键操作（创建、删除）

1. 封装的创建键、删除键、删除键值如下所示：

```c
NTSTATUS MyCreateKey(const WCHAR* wKeyPath, PHANDLE pKey)
{
	UNICODE_STRING uKeyPath = { 0 };
	RtlInitUnicodeString(&uKeyPath, wKeyPath);
	OBJECT_ATTRIBUTES ObjAttr = { 0 };
	InitializeObjectAttributes(
		&ObjAttr,
		&uKeyPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
	);
	NTSTATUS Status = ZwCreateKey(
		pKey,
		KEY_ALL_ACCESS,
		&ObjAttr,
		0,
		NULL,
		REG_OPTION_NON_VOLATILE,	// 固化的注册表操作
		NULL
	);
	return Status;
}

NTSTATUS MyDeleteValue(HANDLE hKey, const WCHAR* wValueName)
{
	UNICODE_STRING uStr = { 0 };
	RtlInitUnicodeString(&uStr, wValueName);
	return ZwDeleteValueKey(hKey, &uStr);
}

NTSTATUS MyDeleteKey(HANDLE hKey)
{
	return ZwDeleteKey(hKey);
}
```

2. 路径格式与文件同理：`\Registry\Machine\SOFTWARE\OEM`对应`HKLM\SOFTWARE\OEM`；`REG_OPTION_NON_VOLATILE`表示写入固化的注册表（重启系统会保留修改），与之相对的是`REG_OPTION_VOLATILE`（内存态，重启即失）



### 值操作（写入）

1. 写入`DWORD`、字符串两种类型的键值如下所示：

```c
NTSTATUS MyWriteValueDword(HANDLE hKey, const WCHAR* wValueName, ULONG dwValue)
{
	UNICODE_STRING uStr = { 0 };
	RtlInitUnicodeString(&uStr, wValueName);
	NTSTATUS Status = ZwSetValueKey(
		hKey,
		&uStr,
		0,
		REG_DWORD,
		&dwValue,
		sizeof(dwValue)
	);
	return Status;
}

NTSTATUS MyWriteValueStr(HANDLE hKey, const WCHAR* wValueName, const WCHAR* wVaue)
{
	UNICODE_STRING uStr = { 0 };
	RtlInitUnicodeString(&uStr, wValueName);
	size_t DataSize = (wcslen(wVaue) + 1) * sizeof(WCHAR);
	NTSTATUS Status = ZwSetValueKey(
		hKey,
		&uStr,
		0,
		REG_SZ,
		(PVOID)wVaue,
		(ULONG)DataSize
	);
	return Status;
}
```

2. 注意字符串类型的大小计算：`(wcslen + 1) * sizeof(WCHAR)`，`+1`是把结尾的`\0`算进去



### 枚举键值

1. 枚举是一个典型的"三态循环"：成功则处理并继续；缓冲区不够则按返回的`ResultLen`扩容重试；`STATUS_NO_MORE_ENTRIES`则结束：

```c
NTSTATUS MyEnumValueKey(HANDLE hKey)
{
	ULONG MemTag = 'reg ';
	PVOID pBuffer = NULL;
	ULONG BufSize = PAGE_SIZE;
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG Index = 0;

	if (hKey == NULL)
	{
		return STATUS_INVALID_HANDLE;
	}

	pBuffer = ExAllocatePoolWithTag(PagedPool, BufSize, MemTag);
	if (pBuffer == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	while (TRUE)
	{
		ULONG ResultLen = 0;

		RtlZeroMemory(pBuffer, BufSize);

		Status = ZwEnumerateValueKey(
			hKey,
			Index,
			KeyValueFullInformation,
			pBuffer,
			BufSize,
			&ResultLen
		);

		if (NT_SUCCESS(Status))
		{
			KEY_VALUE_FULL_INFORMATION* pFullInfo = (KEY_VALUE_FULL_INFORMATION*)pBuffer;

			DbgPrint("ValueType = %lu\n", pFullInfo->Type);
			DbgPrint("ValueName = %.*ws\n",
				pFullInfo->NameLength / sizeof(WCHAR),
				pFullInfo->Name);
			DbgPrint("ValueNameLen = %lu\n", pFullInfo->NameLength);

			Index++;
		}
		else if (Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW)		// 输入缓冲区不够大
		{
			PVOID pNewBuffer = NULL;

			ExFreePoolWithTag(pBuffer, MemTag);
			pBuffer = NULL;

			BufSize = ResultLen;
			pNewBuffer = ExAllocatePoolWithTag(PagedPool, BufSize, MemTag);
			if (pNewBuffer == NULL)
			{
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			pBuffer = pNewBuffer;
		}
		else if (Status == STATUS_NO_MORE_ENTRIES)
		{
			Status = STATUS_SUCCESS;
			break;
		}
		else
		{
			DbgPrint("ZwEnumerateValueKey failed: 0x%X\n", Status);
			break;
		}
	}

	ExFreePoolWithTag(pBuffer, MemTag);
	return Status;
}
```



### DriverEntry实验流程

1. 完整的"建键 → 写值 → 删值 → 删键"流程如下所示：

```c
NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObj, PUNICODE_STRING pRegPath)
{
	UNREFERENCED_PARAMETER(pDrvObj);
	UNREFERENCED_PARAMETER(pRegPath);

	ASSERTMSG("Irql Mismatch !!!", KeGetCurrentIrql() == PASSIVE_LEVEL);

	HANDLE hKey = NULL;
	NTSTATUS Status = STATUS_SUCCESS;
	do
	{
		Status = MyCreateKey(L"\\Registry\\Machine\\SOFTWARE\\OEM", &hKey);
		if (!NT_SUCCESS(Status))
		{
			// TODO - Error Print
			break;
		}

		Status = MyWriteValueDword(hKey, L"dwCode", 1234);
		if (!NT_SUCCESS(Status))
		{
			// TODO - Error Print
			break;
		}

		Status = MyWriteValueStr(hKey, L"SerialNum", L"56789");
		if (!NT_SUCCESS(Status))
		{
			// TODO - Error Print
			break;
		}

		Status = MyDeleteValue(hKey, L"SerialNum");
		if (!NT_SUCCESS(Status))
		{
			// TODO - Error Print
			break;
		}

		Status = MyDeleteValue(hKey, L"dwCode");
		if (!NT_SUCCESS(Status))
		{
			// TODO - Error Print
			break;
		}

		Status = MyDeleteKey(hKey);
		if (!NT_SUCCESS(Status))
		{
			// TODO - Error Print
			break;
		}

		MyEnumValueKey(hKey);

	} while (FALSE);

	if (NULL != hKey)
	{
		ZwClose(hKey);
		hKey = NULL;
	}
	return Status;
}
```
