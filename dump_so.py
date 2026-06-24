import sys
import frida
import sys
import os


def fix_so(arch, origin_so_name, so_name, base, size):
    if arch == "arm":
        os.system("adb push android/SoFixer32 /data/local/tmp/SoFixer")
    elif arch == "arm64":
        os.system("adb push android/SoFixer64 /data/local/tmp/SoFixer")
    os.system("adb shell chmod +x /data/local/tmp/SoFixer")
    os.system("adb push " + so_name + " /data/local/tmp/" + so_name)
    print("adb shell /data/local/tmp/SoFixer -m " + base + " -s /data/local/tmp/" + so_name + " -o /data/local/tmp/" + so_name + ".fix.so")
    os.system("adb shell /data/local/tmp/SoFixer -m " + base + " -s /data/local/tmp/" + so_name + " -o /data/local/tmp/" + so_name + ".fix.so")
    os.system("adb pull /data/local/tmp/" + so_name + ".fix.so " + origin_so_name + "_" + base + "_" + str(size) + "_fix.so")
    os.system("adb shell rm /data/local/tmp/" + so_name)
    os.system("adb shell rm /data/local/tmp/" + so_name + ".fix.so")
    os.system("adb shell rm /data/local/tmp/SoFixer")

    return origin_so_name + "_" + base + "_" + str(size) + "_fix.so"


def read_frida_js_source():
    with open("dump_so.js", "r") as f:
        return f.read()

def on_message(message, data):
    pass


def get_target_session(device: frida.core.Device, target_identifier=None):
    # 1. 如果指定了目标 (PID or Name)
    if target_identifier is not None:
        # 如果是 PID
        if str(target_identifier).isdigit():
            pid = int(target_identifier)
            try:
                return device.attach(pid)
            except Exception as e:
                print(f"[-] 无法附加到 PID {pid}: {e}")
                sys.exit(1)

        # 如果是进程名/包名，遍历进程寻找
        processes = device.enumerate_processes()
        matched = []
        for p in processes:
            if target_identifier.lower() in p.name.lower():
                matched.append(p)

        if len(matched) == 1:
            print(f"[+] 找到匹配的进程: {matched[0].name} (PID: {matched[0].pid})")
            return device.attach(matched[0].pid)
        elif len(matched) > 1:
            print(f"[-] 匹配到多个进程，请输入具体PID或精确名字:")
            for i, p in enumerate(matched):
                print(f"    [{i}] PID: {p.pid} - {p.name}")
            try:
                idx = int(input("[?] 选择进程序号: "))
                if 0 <= idx < len(matched):
                    return device.attach(matched[idx].pid)
            except Exception as e:
                print(f"[-] 选择无效: {e}")
                sys.exit(1)
        else:
            print(f"[-] 未找到包含 '{target_identifier}' 的进程")
            sys.exit(1)

    # 2. 如果未指定目标，优先尝试前台应用
    front_app = None
    try:
        front_app = device.get_frontmost_application()
    except Exception as e:
        print(f"[*] 获取前台应用失败: {e}")

    if front_app is not None:
        try:
            print(f"[+] 正在尝试附加到前台应用: {front_app.name} (PID: {front_app.pid})")
            return device.attach(front_app.pid)
        except Exception as e:
            print(f"[-] 无法附加到前台应用 {front_app.name} (PID: {front_app.pid}): {e}")

    # 3. 前台应用获取失败或附加失败，退回到交互式进程列表
    print("[*] 正在获取运行中进程列表...")
    try:
        processes = device.enumerate_processes()
    except Exception as e:
        print(f"[-] 获取进程列表失败: {e}")
        sys.exit(1)

    # 过滤出有包名的进程或者含有常见关键字的进程（一般应用包名包含 '.')
    app_processes = []
    for p in processes:
        if '.' in p.name or '12306' in p.name or 'magisk' in p.name.lower():
            app_processes.append(p)

    # 如果过滤后为空，就使用全部进程
    if not app_processes:
        app_processes = processes

    # 按 PID 排序
    app_processes.sort(key=lambda x: x.pid)

    print("\n[!] 运行中的应用/进程列表:")
    for i, p in enumerate(app_processes):
        print(f"    [{i:2d}] PID: {p.pid:6d} - {p.name}")

    print("\n[*] 您可以直接输入序号，或者输入进程名、包名、PID进行附加。")
    user_input = input("[?] 选择或输入进程: ").strip()
    if not user_input:
        print("[-] 输入为空，退出。")
        sys.exit(1)

    # 如果是序号
    if user_input.isdigit() and int(user_input) < len(app_processes):
        idx = int(user_input)
        target_pid = app_processes[idx].pid
        print(f"[+] 正在附加到 PID: {target_pid} ({app_processes[idx].name})")
        return device.attach(target_pid)

    # 如果是 PID
    if user_input.isdigit():
        target_pid = int(user_input)
        return device.attach(target_pid)

    # 否则按名字模糊匹配
    matched = []
    for p in processes:
        if user_input.lower() in p.name.lower():
            matched.append(p)

    if len(matched) == 1:
        print(f"[+] 正在附加到: {matched[0].name} (PID: {matched[0].pid})")
        return device.attach(matched[0].pid)
    elif len(matched) > 1:
        print(f"[!] 匹配到多个进程:")
        for i, p in enumerate(matched):
            print(f"    [{i}] PID: {p.pid} - {p.name}")
        try:
            idx = int(input("[?] 选择匹配进程的序号: "))
            if 0 <= idx < len(matched):
                return device.attach(matched[idx].pid)
        except Exception as e:
            print(f"[-] 选择无效: {e}")
            sys.exit(1)
    else:
        print(f"[-] 未找到匹配 '{user_input}' 的进程。")
        sys.exit(1)


if __name__ == "__main__":
    device: frida.core.Device = frida.get_usb_device()

    origin_so_name = None
    target_identifier = None

    if len(sys.argv) >= 2:
        origin_so_name = sys.argv[1]
    if len(sys.argv) >= 3:
        target_identifier = sys.argv[2]

    session = get_target_session(device, target_identifier)
    script = session.create_script(read_frida_js_source())
    script.on('message', on_message)
    script.load()

    if origin_so_name is None:
        allmodule = script.exports.allmodule()
        for module in allmodule:
            print(module["name"])
    else:
        module_info = script.exports.findmodule(origin_so_name)
        print(module_info)
        base = module_info["base"]
        size = module_info["size"]
        module_buffer = script.exports.dumpmodule(origin_so_name)
        if module_buffer != -1:
            dump_so_name = origin_so_name + ".dump.so"
            with open(dump_so_name, "wb") as f:
                f.write(module_buffer)
                f.close()
                arch = script.exports.arch()
                fix_so_name = fix_so(arch, origin_so_name, dump_so_name, base, size)

                print(fix_so_name)
                os.remove(dump_so_name)


