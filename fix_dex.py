import os
import sys
import zlib
import hashlib
import struct
import subprocess
import zipfile

def run_cmd(cmd):
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode, result.stdout.decode('utf-8', errors='ignore'), result.stderr.decode('utf-8', errors='ignore')

def get_online_adb_device():
    """
    自动检测当前在线的 ADB 设备，优先返回一个处于可用状态的设备 ID。
    """
    try:
        code, out, _ = run_cmd("adb devices")
        if code == 0:
            lines = out.strip().split('\n')
            devices = []
            for line in lines[1:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] == 'device':
                        devices.append(parts[0])
            if devices:
                return devices[0]
    except Exception:
        pass
    return None

def ensure_converter_on_device(adb_device):
    """
    检查设备上是否存在 compact_dex_converter。
    如果不存在，从 compact_dex_converter-master 目录寻找匹配架构的 zip，解压并 push 过去。
    """
    converter_bin = "/data/local/tmp/compact_dex_converter"
    code, _, _ = run_cmd(f"adb -s {adb_device} shell ls -la {converter_bin}")
    if code == 0:
        return True

    print(f"[*] 设备端未找到 {converter_bin}，启动自动化部署流程...")
    # 获取设备 CPU 架构
    code_abi, abi_out, _ = run_cmd(f"adb -s {adb_device} shell getprop ro.product.cpu.abi")
    if code_abi != 0 or not abi_out.strip():
        raise RuntimeError("无法获取设备的 CPU 架构 (ro.product.cpu.abi)")

    abi = abi_out.strip()
    print(f"[*] 检测到目标设备 CPU 架构为: {abi}")

    # 匹配 zip 文件
    zip_name = None
    if "arm64-v8a" in abi:
        zip_name = "compact_dex_converter_android_arm64-v8a.zip"
    elif "armeabi-v7a" in abi or "armeabi" in abi:
        zip_name = "compact_dex_converter_android_armeabi-v7a.zip"
    elif "x86_64" in abi:
        zip_name = "compact_dex_converter_android_x86_64.zip"
    elif "x86" in abi:
        zip_name = "compact_dex_converter_android_x86.zip"
    else:
        raise RuntimeError(f"不支持的目标设备 CPU 架构: {abi}")

    master_dir = "compact_dex_converter-master"
    zip_path = os.path.join(master_dir, zip_name)
    if not os.path.exists(zip_path):
        # 兜底：尝试当前目录
        if os.path.exists(zip_name):
            zip_path = zip_name
        else:
            raise RuntimeError(f"未在 {master_dir} 或当前目录下找到对应的压缩包 {zip_name}")

    print(f"[*] 正在从 {zip_path} 解压 compact_dex_converter...")
    temp_extract_dir = "/tmp/compact_dex_converter_extract"
    os.makedirs(temp_extract_dir, exist_ok=True)

    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_extract_dir)
    except Exception as e:
        raise RuntimeError(f"解压 {zip_path} 失败: {e}")

    extracted_bin = os.path.join(temp_extract_dir, "compact_dex_converter")
    if not os.path.exists(extracted_bin):
        raise RuntimeError(f"解压出的包中未包含 compact_dex_converter 执行文件")

    # 推送至设备
    print(f"[*] 正在将 compact_dex_converter 推送至设备端 {converter_bin}...")
    code_push, _, err_push = run_cmd(f"adb -s {adb_device} push {extracted_bin} {converter_bin}")

    # 立即清理本地临时解压产物
    if os.path.exists(extracted_bin):
        os.remove(extracted_bin)
    try:
        os.rmdir(temp_extract_dir)
    except Exception:
        pass

    if code_push != 0:
        raise RuntimeError(f"推送 compact_dex_converter 至设备失败: {err_push}")

    # 赋予执行权限
    run_cmd(f"adb -s {adb_device} shell chmod +x {converter_bin}")
    print(f"[+] compact_dex_converter 工具已成功部署至设备并赋予执行权限！")
    return True

def convert_cdex_on_device(data, filename, adb_device):
    """
    通过模拟器/手机上的 compact_dex_converter 批量进行在设 Compact DEX 转换为标准 DEX。
    """
    # 确保转换工具存在
    ensure_converter_on_device(adb_device)

    temp_cdex = "/tmp/temp_convert.cdex"
    try:
        with open(temp_cdex, "wb") as f:
            f.write(data)
    except Exception as e:
        raise RuntimeError(f"写入本地临时 CDEX 文件失败: {e}")

    # 推送至 Android 设备的临时工作区
    remote_cdex = "/data/local/tmp/temp_convert.cdex"
    remote_dex = "/data/local/tmp/temp_convert.cdex.new"

    # 清理遗留垃圾文件
    run_cmd(f"adb -s {adb_device} shell rm -f {remote_cdex} {remote_dex}")

    code_push, _, err_push = run_cmd(f"adb -s {adb_device} push {temp_cdex} {remote_cdex}")
    if code_push != 0:
        if os.path.exists(temp_cdex): os.remove(temp_cdex)
        raise RuntimeError(f"推送临时 CDEX 文件至设备失败: {err_push}")

    # 调用 compact_dex_converter 进行在设转码
    converter_bin = "/data/local/tmp/compact_dex_converter"
    code, out, err = run_cmd(f"adb -s {adb_device} shell {converter_bin} {remote_cdex}")

    # 校验转码产物是否生成成功
    code_check, _, _ = run_cmd(f"adb -s {adb_device} shell ls -la {remote_dex}")
    if code_check != 0:
        # 清理设备临时文件
        run_cmd(f"adb -s {adb_device} shell rm -f {remote_cdex}")
        if os.path.exists(temp_cdex): os.remove(temp_cdex)

        error_msg = f"设备端转码 Compact DEX 失败! \nExitCode: {code}\nStdout: {out.strip()}\nStderr: {err.strip()}"
        # 尝试从 logcat 捞一点报错
        _, log_out, _ = run_cmd(f"adb -s {adb_device} logcat -d | grep compact_dex_converter | tail -n 10")
        if log_out.strip():
            error_msg += f"\nLogcat 错误信息:\n{log_out.strip()}"
        raise RuntimeError(error_msg)

    # 拉取成功转码的标准 DEX 产物至 host 临时区
    temp_dex = "/tmp/temp_convert.dex"
    code_pull, _, err_pull = run_cmd(f"adb -s {adb_device} pull {remote_dex} {temp_dex}")

    # 立即清理设备端临时转码产物
    run_cmd(f"adb -s {adb_device} shell rm -f {remote_cdex} {remote_dex}")
    if os.path.exists(temp_cdex): os.remove(temp_cdex)

    if code_pull != 0:
        raise RuntimeError(f"从设备端拉取已转换的 DEX 文件失败: {err_pull}")

    try:
        with open(temp_dex, "rb") as f_new:
            converted_data = f_new.read()
    except Exception as e:
        raise RuntimeError(f"读取转码后的 DEX 临时文件失败: {e}")
    finally:
        if os.path.exists(temp_dex): os.remove(temp_dex)

    return True, converted_data

def fix_dex_file(filepath, adb_device=None, force=False, stats=None):
    """
    检查、修复并智能转译单个 DEX/CDEX 文件。
    """
    filename = os.path.basename(filepath)
    try:
        with open(filepath, 'rb') as f:
            data = bytearray(f.read())
    except Exception as e:
        print(f"[-] 无法读取文件 {filename}: {e}")
        return False

    file_size = len(data)
    if file_size < 40:
        print(f"[-] 文件过小，不像是合法的 DEX/CDEX 文件: {filename}")
        return False

    # 自动识别 adb_device
    if adb_device is None:
        adb_device = get_online_adb_device()

    # 读取并识别魔数
    magic = data[0:4]
    is_standard_dex = (magic == b'dex\n')
    is_compact_dex = (magic == b'cdex')
    is_erased_magic = False

    if not is_standard_dex and not is_compact_dex:
        # 魔数不匹配，进行宽松特征校验（兼容被抹除魔数的加固 DEX）
        if len(data) >= 44:
            endian_tag = struct.unpack("<I", data[40:44])[0]
            header_sz_check = struct.unpack("<I", data[36:40])[0]
            if endian_tag == 0x12345678 and (header_sz_check == 0x70 or header_sz_check == 0x28):
                is_erased_magic = True
            else:
                print(f"[-] 错误: {filename} 不包含合法的 DEX/CDEX 结构特征，跳过处理。")
                return False
        else:
            print(f"[-] 错误: {filename} 数据长度不足，跳过处理。")
            return False

    # 统计格式特征
    if stats is not None:
        if is_compact_dex:
            stats['cdex'] = stats.get('cdex', 0) + 1
        elif is_erased_magic:
            stats['erased'] = stats.get('erased', 0) + 1
        else:
            stats['standard'] = stats.get('standard', 0) + 1

    # 1. 核心智能处理：如果是 Compact DEX (CDEX) 且有可用的 Android 设备，一键启动全自动在设标准转码流程
    if is_compact_dex:
        print(f"[*] {filename}: [格式检测] 成功匹配 Compact DEX (CDEX) 文件结构特征！")
        if adb_device:
            # 读取 CDEX 内部偏移，精确计算裁剪无填充的原始大小
            data_size = struct.unpack("<I", data[104:108])[0]
            data_off = struct.unpack("<I", data[108:112])[0]
            real_size = data_off + data_size

            # 精确裁剪内存过度填充，防止 compact_dex_converter 报错 bad file size 拒绝处理
            if len(data) > real_size:
                print(f"[*] CDEX {filename}: 裁剪多余填充字节 ({len(data)} -> {real_size})")
                data = data[:real_size]
                file_size = real_size

            print(f"[*] CDEX {filename}: 检测到在线 Android 设备 {adb_device}，正在通过其一键转译为 Standard DEX...")
            success, converted_data = convert_cdex_on_device(data, filename, adb_device)
            if success and converted_data:
                data = bytearray(converted_data)
                file_size = len(data)
                magic = data[0:4]
                is_standard_dex = (magic == b'dex\n')
                is_compact_dex = False
                print(f"[+] CDEX {filename}: 一键转译标准 DEX 完美完成！自动进入后续校验与写回...")
            else:
                raise RuntimeError(f"CDEX {filename} 转译失败：设备端未生成有效转译结果")
        else:
            print(f"[~] CDEX {filename}: 检测到 Compact DEX，但当前无在线 Android 设备/模拟器，跳过转译，仅进行常规修复。")

    # 2. 读取文件头中声明的文件大小 (偏移量 32-35)
    header_sz = struct.unpack("<I", data[32:36])[0]

    # 3. 智能尾部填充字节裁剪（防范 Frida 内存 Dump 大段映射扩充带来的尾部无用填充）
    if file_size > header_sz and header_sz > 40:
        print(f"[*] {filename}: 检测到尾部内存填充，正在自动裁剪多余字节 (实际大小 {file_size} -> 声明大小 {header_sz})...")
        data = data[:header_sz]
        file_size = header_sz

    # 4. 判断是否需要写回或修复 Adler32/SHA1
    # 如果 data 与原文件相同且 file_size == header_sz 且不是强制，则直接返回
    try:
        with open(filepath, 'rb') as f_orig:
            orig_data = f_orig.read()
        if not force and len(orig_data) == len(data) and orig_data == data:
            if is_compact_dex:
                print(f"[~] 无需修复 (已是正常的 Compact DEX 文件): {filename}")
            elif is_erased_magic:
                print(f"[~] 无需修复 (已是正常的魔数擦除版 DEX/CDEX 文件): {filename}")
            else:
                print(f"[~] 无需修复 (已是正常的标准 DEX 文件): {filename}")
            return False
    except Exception:
        pass

    if is_compact_dex:
        print(f"[*] 正在修复 Compact DEX (CDEX) 文件: {filename} (大小: {file_size} 字节)")
    elif is_erased_magic:
        print(f"[*] 正在修复魔数擦除版 DEX/CDEX 文件: {filename} (大小: {file_size} 字节)")
    else:
        print(f"[*] 正在修复标准 DEX 文件: {filename} (大小: {file_size} 字节)")

    # 更新 file_size
    struct.pack_into("<I", data, 32, file_size)

    # 重新计算并更新 SHA-1 签名
    sha1 = hashlib.sha1()
    sha1.update(data[32:])
    data[12:32] = sha1.digest()

    # 重新计算并更新 Adler32 校验和
    adler = zlib.adler32(data[12:]) & 0xffffffff
    struct.pack_into("<I", data, 8, adler)

    # 写回文件
    try:
        with open(filepath, 'wb') as f:
            f.write(data)
        print(f"[+] 修复完成并安全写入 (Adler32: 0x{adler:08x}, SHA1: {sha1.hexdigest()[:8]}...): {filename}")
        return True
    except Exception as e:
        print(f"[-] 写入文件失败 {filename}: {e}")
        return False

def fix_dex_directory(dirpath, adb_device=None):
    """
    扫描并智能处理目录下所有的 DEX 和 CDEX 文件。
    """
    if adb_device is None:
        adb_device = get_online_adb_device()

    print(f"[*] 正在扫描目录: {os.path.abspath(dirpath)}")
    if not os.path.exists(dirpath):
        print(f"[-] 目录不存在: {dirpath}")
        return

    dex_files = [f for f in os.listdir(dirpath) if f.lower().endswith('.dex')]
    if not dex_files:
        print("[-] 未在目录下找到任何 .dex 文件。")
        return

    if adb_device:
        print(f"[*] 检测到在线 Android 设备 ID: {adb_device}，已自动开启【智能转译 Compact DEX】极速通道！")
    else:
        print("[!] 当前无在线 Android 设备，【Compact DEX 转标准 DEX】转译通道将处于关闭状态，仅执行常规修复。")

    print(f"[*] 找到 {len(dex_files)} 个包含 DEX/CDEX 签名后缀的文件，开始智能批处理...")
    fixed_count = 0
    skipped_count = 0
    stats = {'standard': 0, 'cdex': 0, 'erased': 0}

    for f in sorted(dex_files):
        p = os.path.join(dirpath, f)
        if fix_dex_file(p, adb_device=adb_device, force=False, stats=stats):
            fixed_count += 1
        else:
            skipped_count += 1

    print(f"\n[!] 批处理运行完毕！共转换/修复成功: {fixed_count} 个文件，跳过无需变动的正常文件: {skipped_count} 个。")
    print(f"[*] ------------------------------------------------------------")
    print(f"[*] 【DEX/CDEX 格式特征扫描统计】:")
    print(f"[*]     1. 标准 DEX 格式 (Standard DEX): {stats['standard']} 个")
    print(f"[*]     2. 紧凑 DEX 格式 (Compact DEX):  {stats['cdex']} 个")
    print(f"[*]     3. 魔数擦除版 DEX (Erased Magic): {stats['erased']} 个")
    print(f"[*] ------------------------------------------------------------")

if __name__ == '__main__':
    print("=============================================")
    print("      Android DEX 智能批处理修复与转译工具")
    print("=============================================")

    # 自动识别当前在线的 adb 设备
    adb_device = get_online_adb_device()

    if len(sys.argv) >= 2:
        target = sys.argv[1]
        if os.path.isdir(target):
            fix_dex_directory(target, adb_device)
        elif os.path.isfile(target):
            fix_dex_file(target, adb_device, force=False)
        else:
            print(f"[-] 错误: 指定的路径不存在: {target}")
            sys.exit(1)
    else:
        # 无参数默认兜底处理 "all_dumped_dexs" 文件夹或当前目录
        if os.path.isdir("all_dumped_dexs"):
            print("[*] 提示: 未输入参数，检测到当前目录存在 'all_dumped_dexs'，自动开始批处理...")
            fix_dex_directory("all_dumped_dexs", adb_device)
        else:
            print("[*] 提示: 未输入参数，开始批处理当前目录下所有 DEX...")
            fix_dex_directory(".", adb_device)
    print("=============================================")
