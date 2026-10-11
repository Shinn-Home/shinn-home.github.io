---
title: "MiniFilter框架(2)：文件重定向（SandBox）"
date: 2022-10-31T12:00:00+08:00
lastmod: 2022-10-31T12:00:00+08:00
draft: false
author: "Shinn"
images: []
tags: ["文件过滤驱动", "驱动开发", "Windows内核"]
categories: ["Windows驱动开发"]

twemoji: false
lightgallery: true
---

<!--more-->

## MiniFilter文件重定向试验

1. 试验代码如下所示：
2. 其中字符串解析、字符串规则匹配，都是调用函数，算是比较稳定的写法

```c
FLT_PREOP_CALLBACK_STATUS
Pre_CreateFile(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Outptr_result_maybenull_ PVOID *CompletionContext
)
{
	PFLT_FILE_NAME_INFORMATION FileInfo = NULL;
	NTSTATUS Status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileInfo);
	if (NT_SUCCESS(Status))
	{
		FltParseFileNameInformation(FileInfo);

		UNICODE_STRING SrcStr = { 0 };
		RtlInitUnicodeString(&SrcStr, L"*\\INSTDRV.VMP.EXE.TXT");
		if (FsRtlIsNameInExpression(&SrcStr, &FileInfo->Name, TRUE, NULL) 
			&& UserMode == ExGetPreviousMode())
		{
			// 释放字符串内存
			FltReleaseFileNameInformation(FileInfo);

			PFILE_OBJECT pFileObject = Data->Iopb->TargetFileObject;
			DbgPrint("开始替换路径信息------------------%wZ\n", &FileInfo->Name);

			ExFreePool(pFileObject->FileName.Buffer);

			PVOID pBuf = ExAllocatePoolWithTag(NonPagedPoolNx, PAGE_SIZE, 'path');
			RtlZeroMemory(pBuf, PAGE_SIZE);

			const wchar_t* RedirPath = L"\\??\\C:\\Users\\Administrator\\Desktop\\22222222.txt";
			USHORT RedirPathLen = (USHORT)wcslen(RedirPath) * sizeof(wchar_t);

			RtlCopyMemory(pBuf, RedirPath, RedirPathLen);

			pFileObject->FileName.Buffer = (PWCH)pBuf;
			pFileObject->FileName.Length = RedirPathLen;
			pFileObject->FileName.MaximumLength = PAGE_SIZE;

			// 标记Reparse后，吞掉本次IRP
			Data->IoStatus.Status = STATUS_REPARSE;
			FltSetCallbackDataDirty(Data);
			return FLT_PREOP_COMPLETE;
		}

	}

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}
```

3. 这里涉及到了`UNICODE_STRING`字符串内存的释放，这里是可能踩坑的！直接以代码展示坑点：
4. 以下代码展示了，如果在这种情况下直接`ExFreePool(pStr->Buffer)`，会导致**整个字符串对象都释放**掉了

```c
PUNICODE_STRING pStr = ExAllocPool(...);
pStr->Len = xxx;
pStr->MaxLen = xxx;
pStr->Buffer = pStr + 4;

// ....

// 如下操作，会导致整个UNICODE_STRING字符串对象被释放
ExFreePool(pStr->Buffer );
```
