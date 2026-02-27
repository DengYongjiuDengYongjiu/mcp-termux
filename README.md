# MCP Termux Server v7.0 — Android 逆向工程一体化 MCP 服务器

> 基于 Model Context Protocol (MCP) 的 Android 终端逆向工程工具集。  
> 单一目录部署，73 个工具，覆盖动态追踪、内存操作、静态分析全链路。

## 📦 快速部署

```bash
# 1. 解压到任意目录（推荐 /data/adb/）
tar xzf mcp_re_v7.tar.gz -C /data/adb/

# 2. 启动主 MCP（端口 65534）
su -c "cd /data/adb/mcp_re_v6 && nohup ./mcp -p 65534 </dev/null >./mcp.log 2>&1 &"

# 3. 启动 Boot MCP（端口 65533，可选）
su -c "echo 1 | nohup /data/adb/mcp_re_v6/mcp_boot </dev/null >./boot.log 2>&1 &"

# 4. 在 MCP 客户端中连接
#    主服务: http://127.0.0.1:65534/mcp  (Streamable HTTP)
#    备用:   http://127.0.0.1:65533/mcp  (Streamable HTTP)
```

## 🏗️ 目录结构

```
mcp_re_v6/                        (90MB 整体)
├── mcp              (3.4MB)   主 MCP 服务器 v7.0.0, 端口 65534
├── mcp_boot         (948KB)   Bootstrap MCP v1.0, 端口 65533
├── stackplz         (8.6MB)   eBPF 追踪工具 (Go/Cgo)
├── paradise         (7.3MB)   内存读写工具 (C++)
├── restart.sh                  一键重启脚本
│
├── kmodules/        (1.9MB)   Paradise 内核驱动模块
│   ├── 5.10.ko               Android 12 (Xiaomi/通用)
│   ├── 5.10-Pixel.ko         Android 12 (Pixel)
│   ├── 5.15.ko / 5.15-Pixel.ko
│   ├── 6.1.ko / 6.6.ko / 6.12.ko
│
├── preload_libs/    (2.6MB)   stackplz 运行时依赖 (9个.so)
├── user/config/               stackplz 配置
│   └── config_syscall_aarch64.json
│
├── radare2/         (63MB)    radare2 6.1.0 android-aarch64
│   ├── bin/                   r2, rabin2, rasm2, radiff2, rahash2...
│   ├── lib/                   libr_*.so (23个)
│   └── share/radare2/         签名/魔数/格式数据
│
└── notes/                     知识库笔记存储
```

## 🔧 自动化特性

| 特性 | 说明 |
|------|------|
| **相对路径** | 通过 `readlink(/proc/self/exe)` 获取自身目录，所有工具用相对路径调用 |
| **内核自动加载** | 启动时检测 Paradise 驱动状态，按 `uname -r` 匹配 `kmodules/*.ko` 自动 insmod |
| **Paradise 兼容** | 自动创建 `/data/adb/CD/stackplz/` 符号链接（paradise 硬编码路径） |
| **一键迁移** | `tar czf` 打包后放到任何 root Android 设备即可运行 |

## 📋 完整工具列表 (73个)

### 基础工具 (13个)

| 工具 | 说明 |
|------|------|
| `shell_exec` | Root Shell 命令执行，支持 base64 传输 |
| `shell_exec_async` | 异步后台执行，返回 job_id |
| `job_status` | 查询异步任务状态 |
| `job_list` | 列出所有异步任务 |
| `ssh_exec` | SSH 远程命令执行 |
| `interactive_session` | PTY 交互会话 (python/vim/top 等) |
| `file_read` / `file_write` | 文件读写 (text/base64) |
| `file_list` / `file_delete` | 目录列表/文件删除 |
| `sys_info` | 系统信息 (CPU/内存/磁盘/Android 属性) |
| `process_list` | 进程列表 (支持过滤) |
| `sequentialthinking` | 分步推理 (支持修订/分支) |

### stackplz eBPF 动态追踪 (15个)

| 工具 | 说明 |
|------|------|
| `trace_syscall` | 系统调用追踪 (openat/read/write/connect...) |
| `trace_uprobe` | 用户态函数 Hook (按符号名) |
| `trace_offset` | 按偏移地址 Hook (适合 stripped 库) |
| `trace_register` | 追踪寄存器值 (定位间接跳转目标) |
| `trace_return` | 获取返回地址偏移 (找调用者) |
| `trace_hexdump` | Hex 缓冲区 Dump (查看协议包/加密数据) |
| `trace_config` | JSON 配置批量 Hook |
| `hw_breakpoint` | 硬件断点 (执行/读/写) |
| `trace_signal` | 信号注入 (SIGSTOP/SIGABRT/SIGTRAP) |
| `trace_log` | 后台追踪到文件 (安静模式) |
| `trace_thread` | 按线程名/TID 过滤追踪 |
| `trace_uid` | 按 UID 追踪 (不需要包名) |
| `perf_dump` / `perf_parse` | Perf 数据录制与解析 |
| `stackplz_raw` | 原始 stackplz CLI (完整 flag 参考) |

### Paradise 内存操作 (13个)

| 工具 | 说明 |
|------|------|
| `mem_maps` | 进程内存映射 (支持 --lib/--heap/--rw 过滤) |
| `mem_module` | 获取模块基地址 |
| `mem_offset` | 计算绝对地址 = 基地址 + 偏移 |
| `mem_read` | 读内存 (u8~u64/i8~i64/f32/f64/str，支持 GG 格式) |
| `mem_write` | 写内存 (批量写入，自动验证) |
| `mem_asm_write` | ARM64 汇编写入 (Keystone 汇编 + Capstone 验证) |
| `mem_scan` | 内存扫描 (精确值/范围，过滤 lib/heap/自定义区域) |
| `mem_disasm` | 实时反汇编 (进程内存，含模块偏移) |
| `mem_ptr` | 指针链追踪 (base → deref+offset → ... → read) |
| `mem_dump` | 内存区域转储到文件 (最大 512MB) |
| `mem_hexdump` | Hex+ASCII 表格显示 |
| `mem_brk` | 硬件断点 (通过 stackplz) |
| `mem_chain_trace` | 自动指针链回溯 (写断点 + 反汇编分析) |

### Radare2 静态分析 (18个)

| 工具 | 说明 |
|------|------|
| `r2_info` | 二进制基本信息 (架构/位数/安全特性/编译器) |
| `r2_strings` | 提取字符串 (data/all/raw 模式，支持过滤和最小长度) |
| `r2_imports` | 导入函数列表 |
| `r2_exports` | 导出函数列表 |
| `r2_symbols` | 完整符号表 |
| `r2_sections` | 段/节信息 (含权限) |
| `r2_functions` | 函数列表 (basic/full 分析级别) |
| `r2_disasm` | 反汇编指令 (地址或符号名) |
| `r2_decompile` | 伪C反编译 (pdc) |
| `r2_xrefs` | 交叉引用 (to: 谁调用了 / from: 调用了谁) |
| `r2_search` | 搜索 (string/hex/asm/crypto) |
| `r2_hexdump` | 文件 Hex Dump |
| `r2_entropy` | 熵检测 (识别加壳/加密) |
| `r2_cmd` | 任意 r2 命令 (万能后备) |
| `r2_rabin` | rabin2 快速分析 (-I/-i/-E/-s/-S/-z/-l) |
| `r2_asm` | 单指令汇编/反汇编 (rasm2) |
| `r2_diff` | 二进制差异对比 (radiff2) |
| `r2_hash` | 文件哈希计算 (rahash2: md5/sha256/entropy) |

### 高级分析 (14个)

| 工具 | 说明 |
|------|------|
| `find_jni_methods` | 扫描 JNI 函数 (JNI_OnLoad/Java_*/RegisterNatives) |
| `apply_hex_patch` | 二进制 Patch (自动备份.bak) |
| `scan_crypto_signatures` | 加密算法签名扫描 (AES/RSA/SHA/DES S-box) |
| `batch_decrypt_strings` | 批量解密混淆字符串 (XOR/Base64/ROT13) |
| `add_knowledge_note` | 持久化知识库 (add/list/search/delete) |
| `simulate_execution` | ESIL 沙箱模拟执行 (跟踪寄存器变化) |
| `rename_function` | 函数重命名 |
| `symbolic_deobfuscate` | 符号执行反混淆 (解析不透明谓词/控制流平坦化) |
| `read_logcat` | Android Logcat 日志 (按 tag/priority/pkg 过滤) |
| `sqlite_query` | SQLite 查询 (访问应用私有数据库) |
| `termux_save_script` | 保存脚本文件 (自动赋权) |
| `termux_command` | Termux 用户环境命令 (Python/pip/gcc) |
| `os_list_dir` | Root 目录列表 |
| `os_read_file` | Root 文件读取 |

## 🔄 Bootstrap MCP (端口 65533)

| 工具 | 说明 |
|------|------|
| `boot_shell` | Root Shell (管理主 MCP) |
| `boot_read` | Root 文件读取 |
| `boot_write` | Root 文件写入 |
| `boot_deploy` | 一键部署重启主 MCP |

> Boot MCP 独立运行，主 MCP 重启时不受影响。  
> 工具名加 `boot_` 前缀避免与主 MCP 冲突。

## 🔨 编译方法

```bash
# 需要: Termux + clang/g++
# 头文件: httplib.h (cpp-httplib), json.hpp (nlohmann/json)

# 主 MCP (~4分钟)
cd ~/mcp
g++ -std=c++17 -O2 -pthread -o mcp_termux_v7 mcp_termux_v7.cpp

# Boot MCP (~30秒)
g++ -std=c++17 -O2 -pthread -o mcp_boot mcp_boot.cpp
```

## 📱 系统要求

- Android 10+ (API 29+)
- ARM64 (aarch64)
- Root 权限 (Magisk/KernelSU)
- 内核 5.10+ (eBPF 支持)

## 📄 许可

仅供学习研究使用。
