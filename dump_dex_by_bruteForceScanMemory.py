import sys
import frida
import os
import time
import threading

done_event = threading.Event()
dump_dir_on_device = None

def on_message(message, data):
    global dump_dir_on_device
    if message['type'] == 'send':
        payload = message['payload']
        if isinstance(payload, dict) and payload.get('type') == 'done':
            dump_dir_on_device = payload.get('dumpDir')
            done_event.set()
        else:
            print(f"[*] {payload}")
    elif message['type'] == 'log':
        print(message['payload'])
    elif message['type'] == 'error':
        print(f"[-] Error: {message['description']}")
        done_event.set()

def read_frida_js_source():
    with open("dump_dex_by_bruteForceScanMemory.js", "r", encoding="utf-8") as f:
        return f.read()

def ensure_device_dir(package_name, target_dir):
    # 每次运行前，先利用多种方式彻底清空并删除该旧目录，防止多版本 DEX 残留堆积
    print(f"[*] Formatting device target directory to remove residues: {target_dir}...")
    os.system(f"adb shell \"rm -rf {target_dir}\"")
    if package_name and package_name != "unknown":
        os.system(f"adb shell \"run-as {package_name} rm -rf {target_dir}\"")
    os.system(f"adb shell \"su -c 'rm -rf {target_dir}'\"")

    # 重新创建该存储目录并赋予完全读写权限
    os.system(f"adb shell \"mkdir -p {target_dir}\"")
    os.system(f"adb shell \"chmod 777 {target_dir}\"")

    if package_name and package_name != "unknown":
        os.system(f"adb shell \"run-as {package_name} mkdir -p {target_dir}\"")
        os.system(f"adb shell \"run-as {package_name} chmod 777 {target_dir}\"")

    os.system(f"adb shell \"su -c 'mkdir -p {target_dir} && chmod 777 {target_dir}'\"")

def copy_to_tmp(package_name, src_dir, dest_tmp_dir):
    # 确保 /data/local/tmp 下的目标文件夹存在且可写
    os.system(f"adb shell \"mkdir -p {dest_tmp_dir}\"")
    os.system(f"adb shell \"chmod 777 {dest_tmp_dir}\"")

    # 方法 1: 使用 su -c 复制（针对已 Root 的设备或模拟器）
    ret = os.system(f"adb shell \"su -c 'cp -r {src_dir}/* {dest_tmp_dir}/'\"")
    if ret == 0:
        os.system(f"adb shell \"chmod -R 777 {dest_tmp_dir}\"")
        return True

    # 方法 2: 使用 run-as 复制（针对可调试/非 Root 的设备）
    if package_name and package_name != "unknown":
        ret = os.system(f"adb shell \"run-as {package_name} cp -r {src_dir}/* {dest_tmp_dir}/\"")
        if ret == 0:
            os.system(f"adb shell \"chmod -R 777 {dest_tmp_dir}\"")
            return True

    # 方法 3: 直接进行 cp 复制（如果 adb 本身已获得 root 权限）
    ret = os.system(f"adb shell \"cp -r {src_dir}/* {dest_tmp_dir}/\"")
    if ret == 0:
        os.system(f"adb shell \"chmod -R 777 {dest_tmp_dir}\"")
        return True

    # 方法 4: 尝试 mv 移动
    ret = os.system(f"adb shell \"mv {src_dir}/* {dest_tmp_dir}/\"")
    if ret == 0:
        os.system(f"adb shell \"chmod -R 777 {dest_tmp_dir}\"")
        return True

    return False

if __name__ == "__main__":
    print("[*] Connecting to USB device...")
    try:
        device = frida.get_usb_device()
    except Exception as e:
        print(f"[-] Failed to get USB device: {e}")
        sys.exit(1)

    # 动态确定目标包名（支持命令行入参、前台App自适应、默认值退避三种机制）
    target_package = None
    if len(sys.argv) > 1:
        target_package = sys.argv[1]
        print(f"[*] Target package specified via arguments: {target_package}")
    else:
        try:
            frontmost = device.get_frontmost_application()
            if frontmost and frontmost.identifier:
                target_package = frontmost.identifier
                print(f"[*] Detected frontmost running App package: {target_package}")
        except Exception:
            pass

    if not target_package:
        print("[-] Error: Target package name is required!")
        print("[-] Usage: python3 dump_dex_by_bruteForceScanMemory.py <package_name>")
        print("[-] Alternatively, open the target App on your device and run the script again to auto-detect.")
        sys.exit(1)

    pid = None
    package_name = target_package

    # Resolve application friendly name to handle cases where main process is named as friendly name
    friendly_name = None
    try:
        for app in device.enumerate_applications():
            if app.identifier == target_package:
                friendly_name = app.name
                print(f"[*] Map package '{target_package}' to App friendly name: '{friendly_name}'")
                break
    except Exception:
        pass

    # 优先扫描 enumerate_processes 获取活跃的目标进程
    print(f"[*] Scanning running processes for '{target_package}'...")
    matched_procs = []
    try:
        for proc in device.enumerate_processes():
            if (proc.name == target_package or
                (friendly_name and proc.name == friendly_name) or
                proc.name.startswith(target_package + ":")):
                matched_procs.append(proc)
    except Exception as enum_err:
        print(f"[-] Enumerate processes failed: {enum_err}")

    if matched_procs:
        # Sort processes to pick the best/main process:
        # Priority 0: matching friendly_name (most likely main process if labeled as App Name)
        # Priority 1: matching exact target_package (package name)
        # Priority 2: sub-process like package:name
        # Within the same level, smaller PID comes first (main process always spawns first)
        def get_proc_priority(p):
            if friendly_name and p.name == friendly_name:
                return (0, p.pid)
            if p.name == target_package:
                return (1, p.pid)
            if p.name.startswith(target_package + ":"):
                return (2, p.pid)
            return (3, p.pid)

        matched_procs.sort(key=get_proc_priority)
        proc = matched_procs[0]
        pid = proc.pid
        print(f"[*] Found running target App processes: {[f'{p.name}(PID:{p.pid})' for p in matched_procs]}")
        print(f"[*] Selected optimal process to attach: PID {pid} ({proc.name})")

    if not pid:
        try:
            frontmost = device.get_frontmost_application()
            if frontmost and frontmost.identifier == target_package:
                pid = frontmost.pid
                package_name = frontmost.identifier
                print(f"[*] Found target App running in foreground: {frontmost.name} (Package: {package_name}, PID: {pid})")
        except Exception:
            pass

    if not pid:
        print(f"[-] No active running process found for package '{target_package}'. Please open the App first.")
        sys.exit(1)

    # 在 attach 前由 Python 直接创建转储沙盒目录，绝对安全且避免 native 权限/依赖报错
    dump_dir_on_device = f"/data/data/{target_package}/files/all_dumped_dexs"
    print(f"[*] Ensuring dump directory exists on device: {dump_dir_on_device}")
    ensure_device_dir(package_name, dump_dir_on_device)

    print("[*] Attaching to process...")
    try:
        session = device.attach(pid)
    except Exception as e:
        print(f"[-] Failed to attach to process {pid}: {e}")
        # 如果 attach 最小 PID 失败，尝试列表中其他的 PID（提升极端对抗下的容错性）
        success = False
        if len(matched_procs) > 1:
            for fallback_proc in matched_procs[1:]:
                print(f"[*] Trying fallback process PID {fallback_proc.pid}...")
                try:
                    session = device.attach(fallback_proc.pid)
                    pid = fallback_proc.pid
                    success = True
                    print(f"[+] Successfully attached to fallback PID {pid}!")
                    break
                except Exception:
                    continue
        if not success:
            sys.exit(1)

    print("[*] Creating and loading Frida script...")
    script_source = read_frida_js_source()
    script = session.create_script(script_source)
    script.on('message', on_message)
    script.load()

    print("[*] Invoking dumpAllDex RPC method...")
    def run_dump():
        try:
            # 优先使用 exports_sync 以避免在新版 Frida 中收到 exports 废弃警告
            script.exports_sync.dumpalldex(target_package)
        except AttributeError:
            try:
                script.exports.dumpalldex(target_package)
            except Exception as e2:
                print(f"[-] RPC dumpalldex failed: {e2}")
                done_event.set()
        except Exception as e:
            print(f"[-] RPC dumpalldex failed: {e}")
            done_event.set()

    t = threading.Thread(target=run_dump)
    t.start()

    print("[*] Waiting for dump process to finish...")
    done_event.wait()

    if not dump_dir_on_device:
        print("[-] Dump failed or was interrupted on the device.")
        sys.exit(1)

    print(f"[*] Dump completed on device. Temp files stored in: {dump_dir_on_device}")

    # 步骤 1: 将转储的文件复制/移动到 /data/local/tmp 目录中
    dest_tmp_dir = "/data/local/tmp/all_dumped_dexs"
    print(f"[*] Moving dumped files from sandbox to {dest_tmp_dir}...")
    os.system(f"adb shell \"rm -rf {dest_tmp_dir}\"")

    if not copy_to_tmp(package_name, dump_dir_on_device, dest_tmp_dir):
        print("[-] Error: Failed to copy/move DEX files to /data/local/tmp.")
        print("[-] Please check if your device is rooted or if the app is debuggable.")
        sys.exit(1)

    # 步骤 2: 在本地创建新文件夹，并将文件拉取到该目录下
    local_dir = f"dumped_dexs_{package_name}_{int(time.time())}_byBruteForceScanMemory"
    print(f"[*] Pulling DEX files from {dest_tmp_dir} to local folder: {local_dir}...")
    os.makedirs(local_dir, exist_ok=True)

    ret_pull = os.system(f"adb pull {dest_tmp_dir}/. {local_dir}")
    if ret_pull == 0:
        print(f"[+] Success! All DEX files have been successfully pulled to: {local_dir}")

        # 自动调用 fix_dex 对提取到本地的 DEX 进行智能检测和修复
        try:
            import fix_dex
            print(f"[*] 启动 DEX 智能修复流程...")
            fix_dex.fix_dex_directory(local_dir)
        except Exception as fix_err:
            print(f"[-] DEX 智能修复执行异常: {fix_err}")

        # 统计拉取到的 DEX 文件数量和大小
        dex_files = [f for f in os.listdir(local_dir) if f.endswith('.dex')]
        total_size = sum(os.path.getsize(os.path.join(local_dir, f)) for f in dex_files)
        total_size_mb = total_size / (1024 * 1024)
        print(f"[*] ============================================================")
        print(f"[*] 本地拉取成果汇总：")
        print(f"[*]     成功拉取 DEX 文件数量: {len(dex_files)}")
        print(f"[*]     成功拉取 DEX 文件总体积: {total_size_mb:.2f} MB ({total_size} 字节)")
        print(f"[*] ============================================================")
    else:
        print("[-] Failed to pull files using 'adb pull'.")

    # 步骤 3: 清理设备端的临时文件
    print("[*] Cleaning up temporary files on device...")
    os.system(f"adb shell \"rm -rf {dest_tmp_dir}\"")
    os.system(f"adb shell \"su -c 'rm -rf {dump_dir_on_device}'\"")

    print("[*] Done.")
