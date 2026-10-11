---
title: "UE虚幻引擎结构分析(6)：UE引擎结构、Class继承关系"
date: 2023-04-03T12:00:00+08:00
lastmod: 2023-04-03T12:00:00+08:00
draft: false
author: "Shinn"
images: []
tags: ["虚幻引擎", "逆向工程"]
categories: ["游戏引擎逆向、游戏安全分析"]

twemoji: false
lightgallery: true
---

<!--more-->

## UE变量命名规范（前缀）

- 所有代码和注释都应采用美式标准英语的拼写和语法。
- 命名（如类型或变量）中的每个单词需大写首字母，单词间通常无下划线。例如：`Health` 和 `UPrimitiveComponent`，而非 `lastMouseCoordinates` 或 `delta_coordinates`。
- 类型名前缀需使用额外的大写字母，用于区分其和变量命名。例如：`FSkin`为类型名，而`Skin`则是`FSkin`的实例。
- 模板类的前缀为T。
- 继承自 `UObject` 的类前缀为U。
- 继承自 `AActor` 的类前缀为A。
- 继承自 `SWidget` 的类前缀为S。



## UE引擎继承关系

![1-UE继承关系导图](Image/1-UE继承关系导图.png)



## 引擎结构

![2-引擎类成员结构](Image/2-引擎类成员结构.png)
