#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os
import re
import subprocess
import collections

# 常见 ARM64 (Android 64位) 系统调用映射表
COMMON_SYSCALLS_ARM64 = {
    22: "epoll_pwait",
    56: "openat",
    63: "read",
    64: "write",
    73: "ppoll",
    98: "futex",
    135: "rt_sigsuspend",
    137: "rt_sigtimedwait",
    220: "clone",
}

def get_process_name(pid):
    # 读取 cmdline 并过滤空字符，获取精确的进程包名/子进程名
    cmd = ["adb", "shell", f"cat /proc/{pid}/cmdline 2>/dev/null"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        name = res.stdout.replace('\x00', '').strip()
        return name if name else "Unknown"
    except Exception:
        return "Unknown"

def get_ppid(pid):
    # 读取进程状态获取其真实的父进程 PPID
    cmd = ["adb", "shell", f"grep -i PPid /proc/{pid}/status 2>/dev/null | awk '{{print $2}}'"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return res.stdout.strip()
    except Exception:
        return ""

def get_user_stacks(pid):
    # 使用系统自带的 debuggerd 工具获取所有线程的用户态调用栈，速度极快且100%精准
    cmd = ["adb", "shell", f"debuggerd -b {pid} 2>/dev/null"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return res.stdout
    except Exception:
        return ""

def parse_debuggerd_output(output):
    # 解析 debuggerd 输出，建立 tid -> (active_so, creator_so) 的对照映射表
    thread_map = {}
    current_tid = None
    frames = []

    for line in output.split("\n"):
        line = line.strip()
        if not line:
            continue
        if "sysTid=" in line:
            if current_tid and frames:
                thread_map[current_tid] = process_frames(frames)
            try:
                parts = line.split("sysTid=")
                current_tid = parts[1].split()[0].strip()
                frames = []
            except Exception:
                current_tid = None
        elif line.startswith("#") and "pc " in line:
            frames.append(line)

    if current_tid and frames:
        thread_map[current_tid] = process_frames(frames)

    return thread_map

def process_frames(frames):
    resolved_sos = []
    for f in frames:
        # 正则解析 SO 库或者系统核心 OAT/Dalvik
        match = re.search(r'/(?:[a-zA-Z0-9_\-\.]+/)*([a-zA-Z0-9_\-\.]+\.so)', f)
        if match:
            resolved_sos.append(match.group(1))
        elif ".oat" in f or ".odex" in f:
            resolved_sos.append("System_OAT")
        elif "[anon:dalvik" in f:
            resolved_sos.append("Dalvik_JIT")

    # 过滤掉通用的 wait 状态和 start wrapper libc.so
    filtered = [so for so in resolved_sos if so != "libc.so"]

    active_so = "Unknown"
    creator_so = "Unknown"

    if filtered:
        active_so = filtered[0] # 当前活跃（非 libc）的 SO 模块
        creator_so = filtered[-1] # 最早创建（非 libc）该线程的源 SO 模块

    return active_so, creator_so

def get_thread_info(pid):
    # 批量拉取底层状态
    cmd = [
        "adb", "shell",
        f"for t in /proc/{pid}/task/*; do [ -d $t ] || continue; tid=$(basename $t); name=$(cat $t/comm 2>/dev/null); state=$(grep State $t/status 2>/dev/null | awk '{{print $2}}'); echo \"$tid|$name|$state\"; done"
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return res.stdout.strip().split("\n")
    except subprocess.CalledProcessError as e:
        print(f"错误: 无法获取进程 {pid} 的线程信息，请确认应用正在运行且设备已 Root。\n{e.stderr}", file=sys.stderr)
        return []

def parse_threads(lines, pid, user_stacks_map):
    groups = collections.defaultdict(list)
    main_thread = None

    jvm_keywords = ["Signal Catcher", "Jit thread pool", "Daemon", "GC", "Saver", "Compiler", "binder:", "RenderThread"]
    net_keywords = ["gmain", "gdbus", "OkHttp", "Network", "HTTP", "volley", "Download", "socket"]
    security_keywords = ["frida", "gum-js-loop", "pool-frida", "re.frida", "agent", "bypass", "hook", "detect", "anti", "debug", "test", "pms"]

    for line in lines:
        if not line or "|" not in line:
            continue
        parts = line.split("|")
        if len(parts) < 3:
            continue
        tid, name, state = parts[0], parts[1], parts[2]

        # 通过 debuggerd 堆栈分析，获取真实的用户态“活跃模块”与“源头创建模块”
        user_active_so, user_creator_so = user_stacks_map.get(tid, ("Unknown", "Unknown"))

        # 格式化并高亮非系统 SO
        is_user_system_so = any(s in user_creator_so for s in ["libart.so", "libopenjdk.so", "System_OAT", "libutils.so", "libandroid_runtime.so"])
        is_custom_so = False
        color_start, color_end = "", ""
        if user_creator_so != "Unknown" and not is_user_system_so:
            color_start, color_end = "\033[1;31m", "\033[0m" # 核心第三方创建者高亮（红色）
            is_custom_so = True

        display_creator = f"{color_start}{user_creator_so}{color_end}" if user_creator_so != "Unknown" else "Unknown"
        display_active = f"{color_start}{user_active_so}{color_end}" if user_active_so != "Unknown" else "Unknown"

        state_map = {"S": "Sleeping", "R": "Running", "D": "DiskSleep", "Z": "Zombie", "T": "Stopped", "t": "TracingStop"}
        state_str = state_map.get(state, state)

        is_security_sensitive = any(k.lower() in name.lower() for k in security_keywords) or is_custom_so

        info = {
            "tid": tid,
            "name": name,
            "state": state_str,
            "creator_so": display_creator,
            "active_so": display_active,
            "sensitive": is_security_sensitive
        }

        if tid == pid:
            main_thread = info
        elif any(k.lower() in name.lower() for k in security_keywords) or is_custom_so:
            groups["🚨 Security, Custom SO & Protective Agent (安全审计/第三方/外壳线程) 🚨"].append(info)
        elif any(k.lower() in name.lower() for k in jvm_keywords):
            groups["⚙️ JVM, Android Runtime & IPC Daemon (安卓核心线程)"].append(info)
        elif any(k.lower() in name.lower() for k in net_keywords):
            groups["🌐 Network, Event Loop & Async I/O (网络与事件循环)"].append(info)
        else:
            groups["📦 App Business & General Workpool (业务工作线程)"].append(info)

    return main_thread, groups

def print_process_tree(node, prefix="", is_last=True, is_root=True):
    pid = node["pid"]
    proc_name = node["proc_name"]
    main_thread = node["main_thread"]
    groups = node["groups"]
    children = node["children"]

    # 1. 打印进程节点
    if is_root:
        print(f"\n\033[1;35m================================================================================\033[0m")
        print(f"🔍 \033[1;32mProcess Root:\033[0m \033[1;32m{proc_name}\033[0m (\033[1;33mPID: {pid}\033[0m)")
        print(f"\033[1;35m================================================================================\033[0m")
        current_prefix = ""
        child_prefix = ""
    else:
        branch = "└── " if is_last else "├── "
        print(f"{prefix}{branch}🔍 \033[1;32mSub-Process:\033[0m \033[1;32m{proc_name}\033[0m (\033[1;33mPID: {pid}\033[0m)")
        current_prefix = prefix + ("    " if is_last else "│   ")
        child_prefix = prefix + ("    " if is_last else "│   ")

    # 系统/常规库白名单（不予重复打印，只汇总行）
    SYSTEM_SO_SET = {
        "libart.so", "libopenjdk.so", "System_OAT", "libutils.so",
        "libandroid_runtime.so", "libbinder.so", "libgui.so",
        "libjsc.so", "libhwui.so", "libperfetto_c.so",
        "libperfetto_hprof.so", "libcrashsdk.so", "Dalvik_JIT",
        "libc.so", "Unknown"
    }

    # 计算线程是否还有后续兄弟节点（如果有子进程节点，那么线程就不是该进程的最后一个子项）
    has_subprocesses = len(children) > 0

    # 2. 打印主线程
    if main_thread:
        t_branch = "├── " if (groups or has_subprocesses) else "└── "
        print(f"{current_prefix}{t_branch}🟢 \033[1;32m[Main Thread]\033[0m TID: {main_thread['tid']} ({main_thread['name']}) [State: {main_thread['state']}, Creator_SO: {main_thread['creator_so']}, Active_SO: {main_thread['active_so']}]")
    else:
        t_branch = "├── " if (groups or has_subprocesses) else "└── "
        print(f"{current_prefix}{t_branch}🟢 [Main Thread] Not found in task list")

    # 3. 排序输出：把安全组排最前面
    ordered_groups = []
    sec_key = "🚨 Security, Custom SO & Protective Agent (安全审计/第三方/外壳线程) 🚨"
    if sec_key in groups:
        ordered_groups.append((sec_key, groups[sec_key]))
    for grp_name, threads in groups.items():
        if grp_name != sec_key:
            ordered_groups.append((grp_name, threads))

    # 4. 打印各个线程组
    for i, (grp_name, threads) in enumerate(ordered_groups):
        is_last_grp = (i == len(ordered_groups) - 1) and not has_subprocesses
        grp_prefix = "└── " if is_last_grp else "├── "
        branch_prefix = current_prefix + ("    " if is_last_grp else "│   ")

        display_grp_name = f"\033[1;31m{grp_name}\033[0m" if "Security" in grp_name else grp_name
        print(f"{current_prefix}{grp_prefix}{display_grp_name} ({len(threads)} threads)")

        if not threads:
            print(f"{branch_prefix}└── (None)")
            continue

        # 将当前组内的线程分类：可疑（individual）与常规系统（normal, 将合并）
        suspicious = []
        normal = []
        for t in threads:
            raw_creator = re.sub(r'\033\[[0-9;]*m', '', t['creator_so'])
            if t['sensitive'] or raw_creator not in SYSTEM_SO_SET:
                suspicious.append(t)
            else:
                normal.append(t)

        # 打印该组中所有“可疑/第三方”线程
        for k, t in enumerate(suspicious):
            is_last_thread = (k == len(suspicious) - 1) and not normal
            t_prefix = "└── " if is_last_thread else "├── "

            color = "\033[32m" if t['state'] == "Running" else "\033[90m"
            warn_badge = "\033[1;41;37m WARN \033[0m " if t['sensitive'] else ""
            print(f"{branch_prefix}{t_prefix}{warn_badge}TID: {t['tid']} ({t['name']}) [State: {color}{t['state']}\033[0m, \033[1;32mCreator_SO\033[0m: {t['creator_so']}, \033[1;34mActive_SO\033[0m: {t['active_so']}]")

        # 合并打印不重复的常规系统线程（计数统计形式）
        if normal:
            t_prefix = "└── "
            so_counts = collections.Counter()
            for t in normal:
                raw_creator = re.sub(r'\033\[[0-9;]*m', '', t['creator_so'])
                so_counts[raw_creator] += 1

            counts_str = ", ".join(f"{cnt}*{so}" for so, cnt in so_counts.most_common())
            print(f"{branch_prefix}{t_prefix}\033[90m📎 [Merged System Threads] ({len(normal)} threads: {counts_str})\033[0m")

    # 5. 递归打印子进程节点
    for j, child_node in enumerate(children):
        is_last_child = (j == len(children) - 1)
        print_process_tree(child_node, prefix=child_prefix, is_last=is_last_child, is_root=False)

def get_frontmost_package():
    # 使用 dumpsys activity 获取当前最前台包名
    try:
        cmd = ["adb", "shell", "dumpsys activity activities 2>/dev/null"]
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        # 匹配类似 "mResumedActivity: ActivityRecord{... u0 com.xxx/...}"
        match = re.search(r'mResumedActivity:.*?\s([a-zA-Z0-9_\.]+)/', res.stdout)
        if match:
            return match.group(1).strip()
    except Exception:
        pass

    # 如果 dumpsys activity 失败，尝试 dumpsys window 的 mCurrentFocus
    try:
        cmd = ["adb", "shell", "dumpsys window 2>/dev/null"]
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        match = re.search(r'mCurrentFocus=.*?([a-zA-Z0-9_\.]+)/', res.stdout)
        if match:
            return match.group(1).strip()
    except Exception:
        pass

    return None


if __name__ == "__main__":
    target = None
    if len(sys.argv) >= 2:
        target = sys.argv[1]
    else:
        print("[*] 未提供参数，正在自动检测最前台应用...")
        target = get_frontmost_package()
        if not target:
            print("[-] 错误: 无法获取前台应用，请确认设备已连接且非锁屏。或者您可以手动传入 PID 或包名：")
            print("    用法: python3 print_threads.py <PID_or_PACKAGE_NAME>")
            sys.exit(1)
        # 排除 launcher 这种无意义的前台应用，如果是 launcher，提示用户开启目标应用
        if "launcher" in target.lower() or "systemui" in target.lower():
            print(f"[-] 警告: 检测到当前前台应用为系统界面/桌面启动器 ({target})。")
            print("    请在手机上打开需要分析的 App 到前台，或手动传入 PID 或包名。")
            sys.exit(1)

        print(f"[+] 自动探测到最前台应用: {target}")

    pids_to_process = []

    # 支持传入包名自动解析全部 PID（使用 ps -A 模糊过滤，确保不错过 :push 和 :tools 等子进程）
    if not target.isdigit():
        try:
            pid_raw = subprocess.run(
                ["adb", "shell", f"ps -A | grep {target} | awk '{{print $2}}'"],
                capture_output=True, text=True, check=True
            )
            pids = [p.strip() for p in pid_raw.stdout.strip().split() if p.strip().isdigit()]
            pids_to_process = sorted(list(set(pids)), key=int)
            if not pids_to_process:
                raise ValueError()
            print(f">>> 自动将包名解析为运行中的 {len(pids_to_process)} 个进程 PIDs: {', '.join(pids_to_process)}")
        except Exception:
            print(f"错误: 无法找到包名 '{target}' 对应的运行中 PID，请确认应用正在运行。")
            sys.exit(1)
    else:
        pids_to_process = [target]

    # 1. 批量拉取并解析所有相关进程的信息，构建基本节点列表
    nodes = []
    for pid in pids_to_process:
        proc_name = get_process_name(pid)
        print(f"\n>>> [PID: {pid}] 正在拉取用户态堆栈，进行逆向源头 SO 定位...")
        raw_user_stacks = get_user_stacks(pid)
        user_stacks_map = parse_debuggerd_output(raw_user_stacks)

        lines = get_thread_info(pid)
        if not lines:
            continue

        main_thread, groups = parse_threads(lines, pid, user_stacks_map)

        node = {
            "pid": pid,
            "proc_name": proc_name,
            "main_thread": main_thread,
            "groups": groups,
            "parent": None,
            "children": []
        }
        nodes.append(node)

    # 如果没有抓取到任何进程数据，直接退出
    if not nodes:
        print("未获取到任何有效的进程数据。")
        sys.exit(0)

    # 2. 建立逻辑/物理父子关系树 (优先物理 PPID 强关联，其次命名逻辑辅助)
    for node in nodes:
        found_parent = False
        ppid = get_ppid(node["pid"])

        # 第一轨：物理 PPID 强关系匹配 (内核直接证据)
        if ppid:
            for other in nodes:
                if other["pid"] == ppid:
                    node["parent"] = other
                    other["children"].append(node)
                    found_parent = True
                    break

        # 第二轨：若物理关系不属于当前列表，则使用命名逻辑进行前缀挂载
        if not found_parent:
            for other in nodes:
                if node["pid"] == other["pid"]:
                    continue
                if node["proc_name"].startswith(other["proc_name"] + ":"):
                    node["parent"] = other
                    other["children"].append(node)
                    found_parent = True
                    break

    # 3. 找出所有的根节点（parent 为 None 的节点），并按 PID 从小到大排序
    root_nodes = [n for n in nodes if n["parent"] is None]
    root_nodes = sorted(root_nodes, key=lambda x: int(x["pid"]))

    # 4. 递归打印多进程树（合一展示）
    for root in root_nodes:
        print_process_tree(root, prefix="", is_last=True, is_root=True)
