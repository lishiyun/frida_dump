# Frida Dump

Android App 脱壳工具， Dump so, Dump dex，自动脱壳当前前台进程 APP

Frida 17.9.10

Python 3.14.5

## 1. 内存 SO 转储与重构 (dump\_so.py)

用于从进程内存中转储指定的 ELF (.so) 文件，并自动通过 SoFixer 进行格式重构。

### 使用方法：

```bash
# 列出目标设备中当前进程加载的所有 SO 模块
python3 dump_so.py

# 转储并自动重构指定的 SO 模块（例如 libc.so）
python3 dump_so.py libc.so
```

***

## 2. 内存 Dex 极速脱壳 (dump\_dex\_by\_dexCache.py)

通过扫描 JVM 中的 `DexCache` 实例，快速定位并一键安全脱壳所有当前加载、解密的 DEX 文件，自动拉取到本地工作台。

### 使用方法：

```bash
# 确保目标 App 在运行，然后直接执行脚本
python3 dump_dex_by_dexCache.py
```

*本地拉取成果将保存在自动创建的* *`dumped_dexs_<packageName>_<timestamp>_byDexCache/`* *目录下。*

***

## 3. 全内存极致特征扫射脱壳 (dump\_dex\_by\_bruteForceScanMemory.py)

纯 Native 零 Java 依赖。深度遍历进程的 `r--` 全内存段并扫描特征码进行极速特征码脱壳，自带自适应越界探测，强力拉取所有加载、隐藏的 DEX 文件。

### 使用方法：

```bash
# 确保目标 App 在运行，然后直接执行脚本
python3 dump_dex_by_bruteForceScanMemory.py
```

*本地拉取成果将保存在自动创建的* *`dumped_dexs_<packageName>_<timestamp>_byBruteForceScanMemory/`* *目录下。*
