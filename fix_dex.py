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

def read_uleb128(data, off):
    if off >= len(data):
        raise IndexError("Offset out of bounds for ULEB128")
    result = 0
    shift = 0
    while True:
        if off >= len(data):
            raise IndexError("Offset out of bounds in ULEB128 loop")
        byte = data[off]
        off += 1
        result |= (byte & 0x7f) << shift
        if (byte & 0x80) == 0:
            break
        shift += 7
    return result, off

def read_sleb128(data, off):
    if off >= len(data):
        raise IndexError("Offset out of bounds for SLEB128")
    result = 0
    shift = 0
    while True:
        if off >= len(data):
            raise IndexError("Offset out of bounds in SLEB128 loop")
        byte = data[off]
        off += 1
        result |= (byte & 0x7f) << shift
        shift += 7
        if (byte & 0x80) == 0:
            break
    if (shift < 32) and (byte & 0x40):
        result |= -(1 << shift)
    return result, off

def get_class_data_item_size(data, off):
    start_off = off
    static_fields_size, off = read_uleb128(data, off)
    instance_fields_size, off = read_uleb128(data, off)
    direct_methods_size, off = read_uleb128(data, off)
    virtual_methods_size, off = read_uleb128(data, off)
    for _ in range(static_fields_size):
        _, off = read_uleb128(data, off) # field_idx_diff
        _, off = read_uleb128(data, off) # access_flags
    for _ in range(instance_fields_size):
        _, off = read_uleb128(data, off) # field_idx_diff
        _, off = read_uleb128(data, off) # access_flags
    for _ in range(direct_methods_size):
        _, off = read_uleb128(data, off) # method_idx_diff
        _, off = read_uleb128(data, off) # access_flags
        _, off = read_uleb128(data, off) # code_off
    for _ in range(virtual_methods_size):
        _, off = read_uleb128(data, off) # method_idx_diff
        _, off = read_uleb128(data, off) # access_flags
        _, off = read_uleb128(data, off) # code_off
    return off - start_off

def get_code_item_size(data, off):
    start_off = off
    if off + 16 > len(data):
        raise IndexError("Offset out of bounds for code_item header")
    registers_size, ins_size, outs_size, tries_size, debug_info_off, insns_size = struct.unpack('<HHHHII', data[off:off+16])
    off += 16

    if registers_size > 65535 or ins_size > 65535 or outs_size > 65535:
        raise ValueError("Unreasonable register/ins/outs size in code_item")

    if off + insns_size * 2 > len(data):
        raise IndexError("insns_size goes out of bounds")
    off += insns_size * 2
    if tries_size > 0:
        if (insns_size % 2) != 0:
            off += 2 # padding
        if off + tries_size * 8 > len(data):
            raise IndexError("tries_size goes out of bounds")
        off += tries_size * 8 # tries
        size, off = read_uleb128(data, off) # handlers size
        if size > 65535:
            raise ValueError("Unreasonable catch handler list size")
        for _ in range(size):
            h_size, off = read_sleb128(data, off)
            abs_h_size = abs(h_size)
            if abs_h_size > 65535:
                raise ValueError("Unreasonable single catch handler size")
            for _ in range(abs_h_size):
                _, off = read_uleb128(data, off) # type_idx
                _, off = read_uleb128(data, off) # addr
            if h_size <= 0:
                _, off = read_uleb128(data, off) # catch_all_addr
    return off - start_off

def get_string_data_item_size(data, off):
    start_off = off
    utf16_size, off = read_uleb128(data, off)
    while True:
        if off >= len(data):
            raise IndexError("Unterminated string data item")
        if data[off] == 0x00:
            break
        off += 1
    off += 1 # null terminator
    return off - start_off

def get_debug_info_item_size(data, off):
    start_off = off
    line_start, off = read_uleb128(data, off)
    parameters_size, off = read_uleb128(data, off)
    for _ in range(parameters_size):
        _, off = read_uleb128(data, off)
    while True:
        if off >= len(data):
            raise IndexError("Unterminated debug info item")
        opcode = data[off]
        off += 1
        if opcode == 0x00: # DBG_END_SEQUENCE
            break
        elif opcode == 0x01: # DBG_ADVANCE_PC
            _, off = read_uleb128(data, off)
        elif opcode == 0x02: # DBG_ADVANCE_LINE
            _, off = read_sleb128(data, off)
        elif opcode == 0x03: # DBG_START_LOCAL
            _, off = read_uleb128(data, off) # register_num
            _, off = read_uleb128(data, off) # name_idx
            _, off = read_uleb128(data, off) # type_idx
        elif opcode == 0x04: # DBG_START_LOCAL_EXTENDED
            _, off = read_uleb128(data, off) # register_num
            _, off = read_uleb128(data, off) # name_idx
            _, off = read_uleb128(data, off) # type_idx
            _, off = read_uleb128(data, off) # sig_idx
        elif opcode == 0x05: # DBG_END_LOCAL
            _, off = read_uleb128(data, off) # register_num
        elif opcode == 0x06: # DBG_RESTART_LOCAL
            _, off = read_uleb128(data, off) # register_num
        elif opcode == 0x09: # DBG_SET_FILE
            _, off = read_uleb128(data, off) # name_idx
    return off - start_off

def skip_encoded_value(data, off):
    if off >= len(data):
        raise IndexError("Offset out of bounds for encoded_value")
    byte = data[off]
    off += 1
    value_type = byte & 0x1f
    value_arg = byte >> 5
    if value_type in [0x00, 0x02, 0x03, 0x04, 0x06, 0x10, 0x11, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b]:
        off += (value_arg + 1)
    elif value_type == 0x1c: # array
        off = skip_encoded_array(data, off)
    elif value_type == 0x1d: # annotation
        off = skip_encoded_annotation(data, off)
    return off

def skip_encoded_array(data, off):
    size, off = read_uleb128(data, off)
    for _ in range(size):
        off = skip_encoded_value(data, off)
    return off

def skip_encoded_annotation(data, off):
    type_idx, off = read_uleb128(data, off)
    size, off = read_uleb128(data, off)
    for _ in range(size):
        name_idx, off = read_uleb128(data, off)
        off = skip_encoded_value(data, off)
    return off

def get_annotation_item_size(data, off):
    start_off = off
    if off >= len(data):
        raise IndexError("Offset out of bounds for annotation item visibility")
    visibility = data[off]
    off += 1
    off = skip_encoded_annotation(data, off)
    return off - start_off

def get_encoded_array_item_size(data, off):
    start_off = off
    off = skip_encoded_array(data, off)
    return off - start_off

def get_annotations_directory_item_size(data, off):
    if off + 16 > len(data):
        raise IndexError("Offset out of bounds for annotations_directory_item header")
    class_annotations_off, fields_size, methods_size, parameters_size = struct.unpack('<IIII', data[off:off+16])
    return 16 + 8 * (fields_size + methods_size + parameters_size)

def calculate_dex_map_size(data):
    if len(data) < 112:
        return len(data)

    # 自动识别 magic
    magic = data[0:4]
    is_standard_dex = (magic == b'dex\n')
    is_compact_dex = (magic == b'cdex')
    is_erased_magic = False

    if not is_standard_dex and not is_compact_dex:
        # Check if erased
        if len(data) >= 44:
            endian_tag = struct.unpack("<I", data[40:44])[0]
            header_sz_check = struct.unpack("<I", data[36:40])[0]
            if endian_tag == 0x12345678 and (header_sz_check == 0x70 or header_sz_check == 0x28):
                is_erased_magic = True
            else:
                return len(data)
        else:
            return len(data)

    map_off = struct.unpack('<I', data[52:56])[0]
    if map_off >= len(data) or map_off < 40:
        return len(data)

    try:
        map_size = struct.unpack('<I', data[map_off:map_off+4])[0]
        if map_size == 0 or map_size > 100:
            return len(data)
    except Exception:
        return len(data)

    max_offset = 0
    try:
        for i in range(map_size):
            item_offset = map_off + 4 + i * 12
            if item_offset + 12 > len(data):
                break
            type_val, unused, item_size, item_off = struct.unpack('<HHII', data[item_offset:item_offset+12])
            if item_off >= len(data):
                continue

            section_size = 0
            if type_val == 0x0000: # Header
                section_size = item_size * 112
            elif type_val == 0x0001: # StringId
                section_size = item_size * 4
            elif type_val == 0x0002: # TypeId
                section_size = item_size * 4
            elif type_val == 0x0003: # ProtoId
                section_size = item_size * 12
            elif type_val == 0x0004: # FieldId
                section_size = item_size * 8
            elif type_val == 0x0005: # MethodId
                section_size = item_size * 8
            elif type_val == 0x0006: # ClassDef
                section_size = item_size * 32
            elif type_val == 0x0007: # CallSiteId
                section_size = item_size * 4
            elif type_val == 0x0008: # MethodHandle
                section_size = item_size * 8
            elif type_val == 0x1000: # MapList
                section_size = 4 + item_size * 12
            elif type_val == 0x1001: # TypeList
                curr_off = item_off
                for _ in range(item_size):
                    if curr_off + 4 <= len(data):
                        t_size = struct.unpack('<I', data[curr_off:curr_off+4])[0]
                        curr_off += 4 + t_size * 2
                section_size = curr_off - item_off
            elif type_val == 0x1002: # AnnotationSetRefList
                curr_off = item_off
                for _ in range(item_size):
                    if curr_off + 4 <= len(data):
                        t_size = struct.unpack('<I', data[curr_off:curr_off+4])[0]
                        curr_off += 4 + t_size * 4
                section_size = curr_off - item_off
            elif type_val == 0x1003: # AnnotationSetItem
                curr_off = item_off
                for _ in range(item_size):
                    if curr_off + 4 <= len(data):
                        t_size = struct.unpack('<I', data[curr_off:curr_off+4])[0]
                        curr_off += 4 + t_size * 4
                section_size = curr_off - item_off
            elif type_val == 0x2000: # ClassData
                curr_off = item_off
                for _ in range(item_size):
                    curr_off += get_class_data_item_size(data, curr_off)
                section_size = curr_off - item_off
            elif type_val == 0x2001: # CodeItem
                curr_off = item_off
                for _ in range(item_size):
                    curr_off += get_code_item_size(data, curr_off)
                section_size = curr_off - item_off
            elif type_val == 0x2002: # StringData
                curr_off = item_off
                for _ in range(item_size):
                    curr_off += get_string_data_item_size(data, curr_off)
                section_size = curr_off - item_off
            elif type_val == 0x2003: # DebugInfo
                curr_off = item_off
                for _ in range(item_size):
                    curr_off += get_debug_info_item_size(data, curr_off)
                section_size = curr_off - item_off
            elif type_val == 0x2004: # AnnotationItem
                curr_off = item_off
                for _ in range(item_size):
                    curr_off += get_annotation_item_size(data, curr_off)
                section_size = curr_off - item_off
            elif type_val == 0x2005: # EncodedArray
                curr_off = item_off
                for _ in range(item_size):
                    curr_off += get_encoded_array_item_size(data, curr_off)
                section_size = curr_off - item_off
            elif type_val == 0x2006: # AnnotationsDirectory
                curr_off = item_off
                for _ in range(item_size):
                    curr_off += get_annotations_directory_item_size(data, curr_off)
                section_size = curr_off - item_off

            end_offset = item_off + section_size
            if end_offset > max_offset:
                max_offset = end_offset
    except Exception:
        pass

    if max_offset > 0 and max_offset <= len(data):
        return max_offset
    return len(data)

def calculate_dex_graph_size(data):
    if len(data) < 112:
        return len(data)

    # 1. Read header fields
    magic = data[0:4]
    is_standard_dex = (magic == b'dex\n')
    is_compact_dex = (magic == b'cdex')
    is_erased_magic = False

    if not is_standard_dex and not is_compact_dex:
        # Check if erased
        if len(data) >= 44:
            endian_tag = struct.unpack("<I", data[40:44])[0]
            header_sz_check = struct.unpack("<I", data[36:40])[0]
            if endian_tag == 0x12345678 and (header_sz_check == 0x70 or header_sz_check == 0x28):
                is_erased_magic = True
            else:
                return len(data)
        else:
            return len(data)

    # We only perform graph traversal for Standard DEX (and erased magic DEX)
    if is_compact_dex:
        return len(data)

    try:
        string_ids_size = struct.unpack('<I', data[56:60])[0]
        string_ids_off = struct.unpack('<I', data[60:64])[0]
        proto_ids_size = struct.unpack('<I', data[72:76])[0]
        proto_ids_off = struct.unpack('<I', data[76:80])[0]
        class_defs_size = struct.unpack('<I', data[96:100])[0]
        class_defs_off = struct.unpack('<I', data[100:104])[0]
        map_off = struct.unpack('<I', data[52:56])[0]
    except Exception:
        return len(data)

    max_offset = 0
    visited = set()

    def update_max(end_off):
        nonlocal max_offset
        if end_off > max_offset and end_off <= len(data):
            max_offset = end_off

    try:
        # 1. Map List
        if map_off > 0 and map_off + 4 <= len(data):
            map_size = struct.unpack('<I', data[map_off:map_off+4])[0]
            if map_size < 100:
                update_max(map_off + 4 + map_size * 12)

        # 2. String IDs -> String Data Items
        if string_ids_off > 0:
            for i in range(string_ids_size):
                off = string_ids_off + i * 4
                if off + 4 > len(data):
                    break
                str_off = struct.unpack('<I', data[off:off+4])[0]
                if str_off > 0 and str_off < len(data):
                    try:
                        sz = get_string_data_item_size(data, str_off)
                        update_max(str_off + sz)
                    except Exception:
                        pass

        # 3. Proto IDs -> Type Lists
        if proto_ids_off > 0:
            for i in range(proto_ids_size):
                off = proto_ids_off + i * 12
                if off + 12 > len(data):
                    break
                parameters_off = struct.unpack('<I', data[off+8 : off+12])[0]
                if parameters_off > 0 and parameters_off < len(data) and parameters_off not in visited:
                    visited.add(parameters_off)
                    try:
                        t_size = struct.unpack('<I', data[parameters_off:parameters_off+4])[0]
                        if t_size < 65536:
                            update_max(parameters_off + 4 + t_size * 2)
                    except Exception:
                        pass

        # Queues/Sets for recursive traversal of other items
        annotations_dir_offsets = set()
        class_data_offsets = set()
        encoded_array_offsets = set()

        # 4. Class Defs
        if class_defs_off > 0:
            for i in range(class_defs_size):
                off = class_defs_off + i * 32
                if off + 32 > len(data):
                    break
                class_idx, access_flags, superclass_idx, interfaces_off, source_file_idx, annotations_off, class_data_off, static_values_off = struct.unpack('<IIIIIIII', data[off:off+32])

                # interfaces_off (type_list)
                if interfaces_off > 0 and interfaces_off < len(data) and interfaces_off not in visited:
                    visited.add(interfaces_off)
                    try:
                        t_size = struct.unpack('<I', data[interfaces_off:interfaces_off+4])[0]
                        if t_size < 65536:
                            update_max(interfaces_off + 4 + t_size * 2)
                    except Exception:
                        pass

                # annotations_off (annotations_directory_item)
                if annotations_off > 0 and annotations_off < len(data):
                    annotations_dir_offsets.add(annotations_off)

                # class_data_off (class_data_item)
                if class_data_off > 0 and class_data_off < len(data):
                    class_data_offsets.add(class_data_off)

                # static_values_off (encoded_array_item)
                if static_values_off > 0 and static_values_off < len(data):
                    encoded_array_offsets.add(static_values_off)

        # Sets to collect nested offset targets
        annotation_set_ref_lists = set()
        annotation_sets = set()
        annotation_items = set()
        code_items = set()

        # 5. Parse Annotations Directories
        for ann_dir_off in annotations_dir_offsets:
            if ann_dir_off in visited or ann_dir_off + 16 > len(data):
                continue
            visited.add(ann_dir_off)
            try:
                class_annotations_off, fields_size, methods_size, parameters_size = struct.unpack('<IIII', data[ann_dir_off:ann_dir_off+16])
                sz = 16 + 8 * (fields_size + methods_size + parameters_size)
                update_max(ann_dir_off + sz)

                if class_annotations_off > 0 and class_annotations_off < len(data):
                    annotation_sets.add(class_annotations_off)

                # Parse field/method/parameter lists
                curr = ann_dir_off + 16
                # fields
                for _ in range(fields_size):
                    if curr + 8 <= len(data):
                        f_idx, a_off = struct.unpack('<II', data[curr:curr+8])
                        if a_off > 0 and a_off < len(data):
                            annotation_sets.add(a_off)
                        curr += 8
                # methods
                for _ in range(methods_size):
                    if curr + 8 <= len(data):
                        m_idx, a_off = struct.unpack('<II', data[curr:curr+8])
                        if a_off > 0 and a_off < len(data):
                            annotation_sets.add(a_off)
                        curr += 8
                # parameters
                for _ in range(parameters_size):
                    if curr + 8 <= len(data):
                        m_idx, r_off = struct.unpack('<II', data[curr:curr+8])
                        if r_off > 0 and r_off < len(data):
                            annotation_set_ref_lists.add(r_off)
                        curr += 8
            except Exception:
                pass

        # 6. Parse Annotation Set Ref Lists
        for ref_list_off in annotation_set_ref_lists:
            if ref_list_off in visited or ref_list_off + 4 > len(data):
                continue
            visited.add(ref_list_off)
            try:
                size = struct.unpack('<I', data[ref_list_off:ref_list_off+4])[0]
                if size < 65536:
                    update_max(ref_list_off + 4 + size * 4)
                    for j in range(size):
                        off = ref_list_off + 4 + j * 4
                        if off + 4 <= len(data):
                            a_off = struct.unpack('<I', data[off:off+4])[0]
                            if a_off > 0 and a_off < len(data):
                                annotation_sets.add(a_off)
            except Exception:
                pass

        # 7. Parse Annotation Sets
        for ann_set_off in annotation_sets:
            if ann_set_off in visited or ann_set_off + 4 > len(data):
                continue
            visited.add(ann_set_off)
            try:
                size = struct.unpack('<I', data[ann_set_off:ann_set_off+4])[0]
                if size < 65536:
                    update_max(ann_set_off + 4 + size * 4)
                    for j in range(size):
                        off = ann_set_off + 4 + j * 4
                        if off + 4 <= len(data):
                            a_off = struct.unpack('<I', data[off:off+4])[0]
                            if a_off > 0 and a_off < len(data):
                                annotation_items.add(a_off)
            except Exception:
                pass

        # 8. Parse Annotation Items
        for ann_item_off in annotation_items:
            if ann_item_off in visited or ann_item_off >= len(data):
                continue
            visited.add(ann_item_off)
            try:
                sz = get_annotation_item_size(data, ann_item_off)
                update_max(ann_item_off + sz)
            except Exception:
                pass

        # 9. Parse Class Data Items -> Code Items
        for cd_off in class_data_offsets:
            if cd_off in visited or cd_off >= len(data):
                continue
            visited.add(cd_off)
            try:
                start_off = cd_off
                static_fields_size, cd_off = read_uleb128(data, cd_off)
                instance_fields_size, cd_off = read_uleb128(data, cd_off)
                direct_methods_size, cd_off = read_uleb128(data, cd_off)
                virtual_methods_size, cd_off = read_uleb128(data, cd_off)
                for _ in range(static_fields_size):
                    _, cd_off = read_uleb128(data, cd_off)
                    _, cd_off = read_uleb128(data, cd_off)
                for _ in range(instance_fields_size):
                    _, cd_off = read_uleb128(data, cd_off)
                    _, cd_off = read_uleb128(data, cd_off)
                for _ in range(direct_methods_size):
                    _, cd_off = read_uleb128(data, cd_off)
                    _, cd_off = read_uleb128(data, cd_off)
                    code_off, cd_off = read_uleb128(data, cd_off)
                    if code_off > 0 and code_off < len(data):
                        code_items.add(code_off)
                for _ in range(virtual_methods_size):
                    _, cd_off = read_uleb128(data, cd_off)
                    _, cd_off = read_uleb128(data, cd_off)
                    code_off, cd_off = read_uleb128(data, cd_off)
                    if code_off > 0 and code_off < len(data):
                        code_items.add(code_off)
                update_max(cd_off)
            except Exception:
                pass

        # 10. Parse Encoded Array Items
        for ea_off in encoded_array_offsets:
            if ea_off in visited or ea_off >= len(data):
                continue
            visited.add(ea_off)
            try:
                sz = get_encoded_array_item_size(data, ea_off)
                update_max(ea_off + sz)
            except Exception:
                pass

        # 11. Parse Code Items -> Debug Info Items
        for code_off in code_items:
            if code_off in visited or code_off + 16 > len(data):
                continue
            visited.add(code_off)
            try:
                sz = get_code_item_size(data, code_off)
                update_max(code_off + sz)

                debug_info_off = struct.unpack('<I', data[code_off+8 : code_off+12])[0]
                if debug_info_off > 0 and debug_info_off < len(data) and debug_info_off not in visited:
                    visited.add(debug_info_off)
                    try:
                        d_sz = get_debug_info_item_size(data, debug_info_off)
                        update_max(debug_info_off + d_sz)
                    except Exception:
                        pass
            except Exception:
                pass

    except Exception:
        pass

    if max_offset > 0 and max_offset <= len(data):
        return max_offset
    return len(data)

def calculate_dex_true_size(data):
    map_sz = calculate_dex_map_size(data)
    graph_sz = calculate_dex_graph_size(data)
    return max(map_sz, graph_sz)

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

    # 2.5 智能计算真实物理大小（对抗 forged/wrong header_sz）
    true_sz = calculate_dex_true_size(data)
    if true_sz > 40 and true_sz != header_sz:
        print(f"[*] {filename}: 声明大小: {header_sz} | 计算真实大小: {true_sz}. 将自动修正为真实大小并进行精准裁剪。")
        header_sz = true_sz

    # 3. 智能尾部填充字节裁剪（防范 Frida 内存 Dump 大段映射扩充及多DEX合并带来的尾部冗余）
    if file_size > header_sz and header_sz > 40:
        print(f"[*] {filename}: 正在裁剪尾部多余字节 (实际大小 {file_size} -> 真实大小 {header_sz})...")
        data = data[:header_sz]
        file_size = header_sz

    # 3.5 更新内存数据中的 file_size 声明（以便后续比较和重算签名）
    struct.pack_into("<I", data, 32, file_size)

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
