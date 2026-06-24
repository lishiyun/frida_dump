# Frida Dump

Android App 脱壳工具， Dump so, Dump dex，自动脱壳当前前台进程 APP

Frida 17.9.10

Python 3.14.5

## 1. 内存 SO 转储与重构 (dump\_so.py)

用于从进程内存中转储指定的 ELF (.so) 文件，并自动通过 SoFixer 进行格式重构。

### 使用方法：

```bash
# 列出目标设备中当前进程加载的所有 SO 模块（按第三方库靠前、系统库靠后规则排序，直接列出物理路径）
python3 dump_so.py

# 转储并自动重构指定的 SO 模块（例如 libc.so），支持 PID 或包名附加
python3 dump_so.py libc.so 18190
```

***

## 2. 内存 Dex 极速脱壳 (dump\_dex\_by\_dexCache.py)

通过扫描 JVM 中的 `DexCache` 实例，快速定位并一键安全脱壳所有当前加载、解密的 DEX 文件，自动拉取到本地工作目录

### 使用方法：

```bash
# 确保目标 App 在运行，然后直接执行脚本
python3 dump_dex_by_dexCache.py
```

<br />

***

## 3. 全内存极致特征扫射脱壳 (dump\_dex\_by\_bruteForceScanMemory.py)

纯 Native 零 Java 依赖。深度遍历进程的 `r--` 全内存段并扫描特征码进行极速特征码脱壳，自带自适应越界探测，强力拉取所有加载、隐藏的 DEX 文件。

### 使用方法：

```bash
# 确保目标 App 在运行，然后直接执行脚本
python3 dump_dex_by_bruteForceScanMemory.py
```

<br />

***

## 4. 全进程线程安全审计与溯源 (print\_threads.py)

无需注入，一键全进程树线程分析。追溯每个线程的“当前活跃 SO”与“源头创建 SO”，高亮第三方库，并智能折叠系统及 JVM 背景线程。

### 使用方法：

```bash
# 智能模式：自动获取手机前台 App 及其全量子进程进行审计分析
python3 print_threads.py

# 显式附加 PID 或包名匹配：
python3 print_threads.py com.MobileTicket
```

***

## 5. DEX 类名重合对比分析 (compare\_dex.py)

高性能、低延迟的纯 Python DEX 差异对比仪。计算两个 DEX 目录或文件的包含率、杰卡德（Jaccard）重合度，输出精美报表，用于脱壳完整性校验、去重和差异分析。

### 使用方法：

```bash
# 两两交叉对比：分析多 DEX 重合度与冗余（完全重合的自动给出清理去重建议）
python3 compare_dex.py ./dumped_dexs_dir/

# 阵营对比：比对两份脱壳成果（如 A 目录 vs B 目录）的包含关系与差异类明细
python3 compare_dex.py ./dex_cache_dir/ ./brute_force_dir/
```

