[![en](https://img.shields.io/badge/lang-en-red.svg)](README.md)
# Advanced ARP Spoofing Tool

## 🚨 免责声明

**警告：此工具仅供安全研究和学习目的。未经授权使用可能构成非法行为，使用者需对自身行为负全部法律责任。**

## 🔍 项目简介

这是一个高级ARP（地址解析协议）攻击工具，用于网络安全研究和渗透测试。该工具提供了多种ARP攻击策略，帮助安全研究人员理解和模拟网络中间人攻击。

## ✨ 功能特点

- 多种ARP攻击策略
- 灵活的目标选择
- 网络接口自动检测
- 实时网络活动监控
- 数据包嗅探
- 自动IP转发管理
- 攻击后自动网络还原

## 🛠 攻击策略

### 1. 标准ARP攻击 (Standard)
- 伪造ARP响应
- 劫持目标网络流量

### 2. 免费ARP攻击 (Gratuitous)
- 发送无请求ARP包
- 强制更新网络设备ARP缓存

### 3. MITM中间人攻击 (MITM)
- 同时欺骗目标和网关
- 可选数据包嗅探
- 拦截和分析网络流量

## 🔧 技术原理

### ARP协议攻击原理
1. ARP缓存投毒
2. 伪造ARP响应
3. 劫持网络通信

### 关键技术实现
- 多线程并发攻击
- 动态MAC地址获取
- 实时网络监控
- 攻击状态自动刷新

## 📦 依赖库

- scapy
- psutil
- colorama
- threading
- logging

## 🚀 使用方法

```bash
# 创建 Python 虚拟环境
$ python -m venv arp-attack-tool

# 进入虚拟环境文件夹
$ cd arp-attack-tool

# 创建 src 文件夹
$ mkdir src

# 移动 arp_attack_zh.py 到 src 文件夹
$ move arp_attack_zh.py src/

# 激活虚拟环境 (Powershell需要开启允许所有脚本运行命令：Set-ExecutionPolicy -ExecutionPolicy Unrestricted)
$ .\Scripts\activate

# 安装必要库
$ pip install -r requirements.txt

# 进入 src 文件夹
$ cd src

# 执行脚本
$ python arp_attack_zh.py

# 退出虚拟环境
$ deactivate
```

### 交互流程
1. 选择网络接口
2. 输入网关IP
3. 输入目标IP
4. 选择攻击策略
5. 配置攻击参数

## 🛡 安全防护建议

- 使用静态ARP表
- 启用ARP防火墙
- 监控网络异常流量
- 定期更新网络设备固件

## 📝 注意事项

- 仅在授权环境中使用
- 遵守法律和职业道德
- 保护个人和组织隐私

## 🔬 学习目的

本工具旨在：
- 理解ARP协议漏洞
- 提高网络安全意识
- 学习网络攻防技术

## 🤝 贡献和反馈

欢迎提交Issues和Pull Requests！

---

**安全从理解漏洞开始，但绝不应该以破坏为目的。**
