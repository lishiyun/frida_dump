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
    with open("dump_dex_by_dexCache.js", "r", encoding="utf-8") as f:
        return f.read()

def copy_to_tmp(package_name, src_dir, dest_tmp_dir):
    # Make sure the destination folder in /data/local/tmp exists and is writable
    os.system(f"adb shell \"mkdir -p {dest_tmp_dir}\"")
    os.system(f"adb shell \"chmod 777 {dest_tmp_dir}\"")

    # Method 1: Try su -c (works on rooted devices/emulators)
    ret = os.system(f"adb shell \"su -c 'cp -r {src_dir}/* {dest_tmp_dir}/'\"")
    if ret == 0:
        os.system(f"adb shell \"chmod -R 777 {dest_tmp_dir}\"")
        return True

    # Method 2: Try run-as (works on debuggable/non-rooted devices)
    if package_name and package_name != "unknown":
        ret = os.system(f"adb shell \"run-as {package_name} cp -r {src_dir}/* {dest_tmp_dir}/\"")
        if ret == 0:
            os.system(f"adb shell \"chmod -R 777 {dest_tmp_dir}\"")
            return True

    # Method 3: Try standard direct cp (if adb already has root permissions)
    ret = os.system(f"adb shell \"cp -r {src_dir}/* {dest_tmp_dir}/\"")
    if ret == 0:
        os.system(f"adb shell \"chmod -R 777 {dest_tmp_dir}\"")
        return True

    # Method 4: Try standard mv
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
        print("[-] Usage: python3 dump_dex_by_dexCache.py <package_name>")
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

    # Prioritize active running process from enumerate_processes for maximum robustness
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

    print("[*] Attaching to process...")
    try:
        session = device.attach(pid)
    except Exception as e:
        print(f"[-] Failed to attach to process: {e}")
        sys.exit(1)

    print("[*] Creating and loading Frida script...")
    script_source = read_frida_js_source()
    script = session.create_script(script_source)
    script.on('message', on_message)
    script.load()

    print("[*] Invoking dumpAllDex RPC method...")
    def run_dump():
        try:
            script.exports.dumpalldex()
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

    # Step 1: Copy/Move the dumped files to /data/local/tmp
    dest_tmp_dir = "/data/local/tmp/all_dumped_dexs"
    print(f"[*] Moving dumped files from sandbox to {dest_tmp_dir}...")
    os.system(f"adb shell \"rm -rf {dest_tmp_dir}\"")

    if not copy_to_tmp(package_name, dump_dir_on_device, dest_tmp_dir):
        print("[-] Error: Failed to copy/move DEX files to /data/local/tmp.")
        print("[-] Please check if your device is rooted or if the app is debuggable.")
        sys.exit(1)

    # Step 2: Create a local new directory and pull the files from /data/local/tmp
    local_dir = f"dumped_dexs_{package_name}_{int(time.time())}_byDexCache"
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

    # Step 3: Cleanup temporary files on device
    print("[*] Cleaning up temporary files on device...")
    os.system(f"adb shell \"rm -rf {dest_tmp_dir}\"")
    os.system(f"adb shell \"su -c 'rm -rf {dump_dir_on_device}'\"")

    print("[*] Done.")
