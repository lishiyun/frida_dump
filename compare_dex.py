#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DEX 差异对比工具 (DEX Class Comparator)
功能：对比1个或2个参数指向的 DEX 文件或目录，提取类名计算包含率、杰卡德重合度，输出多维度统计指标。
作者：AI Assistant
日期：2026-06-05
"""

import os
import sys
import struct

def read_uleb128(data, offset):
    """
    ULEB128 解码器
    """
    result = 0
    shift = 0
    while True:
        if offset >= len(data):
            break
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7f) << shift
        if (byte & 0x80) == 0:
            break
        shift += 7
    return result, offset

def to_standard_name(smali_name):
    """
    将 Smali 类描述符转换为标准点号分隔的 Java 类名
    """
    if smali_name.startswith("L") and smali_name.endswith(";"):
        smali_name = smali_name[1:-1]
    return smali_name.replace("/", ".")

def is_valid_smali_class_name(name):
    """
    过滤垃圾伪类名：合法的 Smali 类名描述符必须以 L 开头并以 ; 结尾（或为数组类 [），
    且不能含有空格、换行、赋值 =、括号 ()、着色器 GLSL 逻辑等非类字符。
    """
    if not name or len(name) < 3:
        return False
    # 必须是 L...; 形式或数组 [L...;
    if not ((name.startswith("L") and name.endswith(";")) or name.startswith("[")):
        return False
    # 排除包含空格、换行、赋值、括号等明显属于指令、字符串常量或 GLSL 着色器逻辑的类名
    invalid_chars = (" ", "\n", "\r", "\t", "=", "(", ")", "{", "}", "+", "*", "?", "<", ">", ":", ",")
    for char in invalid_chars:
        if char in name:
            return False
    return True

def parse_dex(file_path):
    """
    高性能二进制 DEX 解析器
    注：为了在分析破损或混淆诱导的伪 DEX 时保持界面整洁，所有不合规警告均采用静默处理，提高鲁棒性。
    """
    try:
        with open(file_path, "rb") as f:
            file_data = f.read()
    except Exception:
        return None

    if len(file_data) < 112:
        return None

    # 验证 magic
    magic = file_data[0:8]
    if not magic.startswith(b"dex\n"):
        return None

    try:
        # 解析 header 偏移量
        header = file_data[:112]
        file_size = struct.unpack("<I", header[32:36])[0]
        string_ids_size = struct.unpack("<I", header[56:60])[0]
        string_ids_off = struct.unpack("<I", header[60:64])[0]
        type_ids_size = struct.unpack("<I", header[64:68])[0]
        type_ids_off = struct.unpack("<I", header[68:72])[0]
        field_ids_size = struct.unpack("<I", header[80:84])[0]
        field_ids_off = struct.unpack("<I", header[84:88])[0]
        method_ids_size = struct.unpack("<I", header[88:92])[0]
        method_ids_off = struct.unpack("<I", header[92:96])[0]
        class_defs_size = struct.unpack("<I", header[96:100])[0]
        class_defs_off = struct.unpack("<I", header[100:104])[0]

        # 校验文件边界（若超出说明是破损/伪装文件，静默返回 None）
        if string_ids_off + string_ids_size * 4 > len(file_data) or \
           type_ids_off + type_ids_size * 4 > len(file_data) or \
           class_defs_off + class_defs_size * 32 > len(file_data):
            return None

        # 读取 string offsets
        string_offsets = []
        for i in range(string_ids_size):
            off = struct.unpack("<I", file_data[string_ids_off + i*4 : string_ids_off + i*4 + 4])[0]
            string_offsets.append(off)

        # 带缓存的 string 读取
        string_cache = {}
        def get_string(string_idx):
            if string_idx in string_cache:
                return string_cache[string_idx]
            if string_idx >= len(string_offsets):
                return ""
            off = string_offsets[string_idx]
            if off >= len(file_data):
                return ""
            length, off = read_uleb128(file_data, off)
            end = off
            while end < len(file_data) and file_data[end] != 0:
                end += 1
            s = file_data[off:end].decode("utf-8", errors="ignore")
            string_cache[string_idx] = s
            return s

        # 读取 type ids
        type_ids = []
        for i in range(type_ids_size):
            idx = struct.unpack("<I", file_data[type_ids_off + i*4 : type_ids_off + i*4 + 4])[0]
            type_ids.append(idx)

        # 读取 class names
        class_names = set()
        for i in range(class_defs_size):
            class_idx = struct.unpack("<I", file_data[class_defs_off + i*32 : class_defs_off + i*32 + 4])[0]
            if class_idx < len(type_ids):
                type_idx = type_ids[class_idx]
                class_name = get_string(type_idx)
                # 关键：严格过滤着色器逻辑、二进制常量、代码指令等野指针伪造的垃圾类名
                if is_valid_smali_class_name(class_name):
                    class_names.add(class_name)

        return {
            "file_path": file_path,
            "file_name": os.path.basename(file_path),
            "file_size_bytes": len(file_data),
            "class_defs_size": len(class_names),  # 以清洗过滤后的真实类数量为准，剔除野指针伪类数
            "method_ids_size": method_ids_size,
            "field_ids_size": field_ids_size,
            "classes": class_names
        }
    except Exception:
        return None

def get_dex_files(path):
    """
    获取指定路径下的所有 DEX 文件，支持单文件和目录递归扫描
    """
    if not os.path.exists(path):
        print(f"[错误] 路径不存在: {path}", file=sys.stderr)
        sys.exit(1)

    if os.path.isfile(path):
        if path.lower().endswith(".dex"):
            return [path]
        else:
            print(f"[错误] 指定文件不是以 .dex 结尾: {path}", file=sys.stderr)
            sys.exit(1)
    elif os.path.isdir(path):
        dex_files = []
        for root, _, files in os.walk(path):
            for file in files:
                if file.lower().endswith(".dex"):
                    dex_files.append(os.path.join(root, file))
        return sorted(dex_files)

    return []

def get_display_width(s):
    """
    计算字符串在终端中的实际显示宽度（中文字符计为 2，ASCII 字符计为 1）
    """
    width = 0
    for char in str(s):
        if ord(char) > 0x7f:
            width += 2
        else:
            width += 1
    return width

def pad_string(s, width, align='left'):
    """
    根据终端显示宽度对字符串进行空格填充对齐
    """
    s_str = str(s)
    disp_w = get_display_width(s_str)
    needed_spaces = max(0, width - disp_w)
    if align == 'left':
        return s_str + (" " * needed_spaces)
    elif align == 'right':
        return (" " * needed_spaces) + s_str
    else:  # center
        left_spaces = needed_spaces // 2
        right_spaces = needed_spaces - left_spaces
        return (" " * left_spaces) + s_str + (" " * right_spaces)

def print_fancy_table(headers, rows):
    """
    使用精美的 Unicode 制表符在终端绘制完美的“正经表格”，自适应中英文字符宽度对齐。
    """
    # 计算各列的最大显示宽度
    col_widths = [get_display_width(h) for h in headers]
    for row in rows:
        for idx, val in enumerate(row):
            col_widths[idx] = max(col_widths[idx], get_display_width(val))

    # 定义 Unicode 边框制表符
    top_border = "┌" + "┬".join(["─" * (w + 2) for w in col_widths]) + "┐"
    mid_border = "├" + "┼".join(["─" * (w + 2) for w in col_widths]) + "┤"
    bottom_border = "└" + "┴".join(["─" * (w + 2) for w in col_widths]) + "┘"

    # 打印顶边框
    print(top_border)

    # 打印表头
    header_padded = [pad_string(h, col_widths[idx], 'left') for idx, h in enumerate(headers)]
    print("│ " + " │ ".join(header_padded) + " │")
    print(mid_border)

    # 打印各数据行
    for row in rows:
        row_padded = [pad_string(val, col_widths[idx], 'left') for idx, val in enumerate(row)]
        print("│ " + " │ ".join(row_padded) + " │")

    # 打印底边框
    print(bottom_border)

def build_camp(name, files):
    """
    根据文件列表合并并构建一个阵营
    """
    print(f"[*] 正在解析阵营 {name} ... (共 {len(files)} 个 DEX 文件)")
    total_bytes = 0
    total_raw_classes = 0
    total_methods = 0
    total_fields = 0
    all_classes = set()

    parsed_count = 0
    for f in files:
        res = parse_dex(f)
        if res:
            total_bytes += res["file_size_bytes"]
            total_raw_classes += res["class_defs_size"]
            total_methods += res["method_ids_size"]
            total_fields += res["field_ids_size"]
            all_classes.update(res["classes"])
            parsed_count += 1

    if parsed_count == 0:
        return None

    total_mb = total_bytes / (1024 * 1024)
    unique_classes_count = len(all_classes)

    # 统计类唯一率 = 去重类数量/未去重类数量
    unique_ratio = 100.0
    if total_raw_classes > 0:
        unique_ratio = (unique_classes_count / total_raw_classes) * 100.0

    return {
        "name": name,
        "file_count": parsed_count,
        "total_bytes": total_bytes,  # 隐藏的数值字段，用于多指标排序
        "total_mb": f"{total_mb:.2f} MB",
        "raw_classes": total_raw_classes,
        "unique_classes": unique_classes_count,
        "unique_ratio": f"{unique_ratio:.1f}%",
        "methods": total_methods,
        "fields": total_fields,
        "classes_set": all_classes
    }

def print_camp_summary(camps):
    """
    打印阵营汇总指标
    排序规则：优先按体积（total_bytes）从大到小，若体积相同则按唯一类数量从大到小
    """
    sorted_camps = sorted(camps, key=lambda x: (x.get("total_bytes", 0), x.get("unique_classes", 0)), reverse=True)

    print("\n[ 1. 阵营信息统计汇总表 ]")
    headers = ["阵营名称", "DEX数量", "总体积", "未去重类总数", "去重后唯一类数", "类唯一率", "Methods数量 (累加)", "Fields数量 (累加)"]
    rows = []
    for camp in sorted_camps:
        rows.append([
            camp["name"],
            camp["file_count"],
            camp["total_mb"],
            camp["raw_classes"],
            camp["unique_classes"],
            camp["unique_ratio"],
            camp["methods"],
            camp["fields"]
        ])
    print_fancy_table(headers, rows)

def compare_two_camps(camp_a, camp_b):
    """
    计算两个阵营的详细差异，输出包含率和杰卡德重合度
    """
    set_a = camp_a["classes_set"]
    set_b = camp_b["classes_set"]

    intersection = set_a.intersection(set_b)
    len_intersect = len(intersection)
    len_a = len(set_a)
    len_b = len(set_b)
    len_union = len(set_a.union(set_b))

    # 计算包含率
    sim_a_in_b = 0.0
    if len_a > 0:
        sim_a_in_b = (len_intersect / len_a) * 100.0

    sim_b_in_a = 0.0
    if len_b > 0:
        sim_b_in_a = (len_intersect / len_b) * 100.0

    # 杰卡德相似度
    jaccard = 0.0
    if len_union > 0:
        jaccard = (len_intersect / len_union) * 100.0

    return {
        "intersection": len_intersect,
        "sim_a_in_b": sim_a_in_b,
        "sim_b_in_a": sim_b_in_a,
        "jaccard": jaccard,
        "only_in_a": sorted(list(set_a - set_b), key=lambda x: (-len(to_standard_name(x)), to_standard_name(x))),
        "only_in_b": sorted(list(set_b - set_a), key=lambda x: (-len(to_standard_name(x)), to_standard_name(x)))
    }

def write_diff_file(file_path, classes_list):
    """
    辅助函数：把大列表保存到本地文件中，带对齐序号（如 [0001]）且用点号分隔的标准类名
    """
    try:
        padding_len = len(str(len(classes_list)))
        padding_len = max(3, padding_len)  # 最少 3 位 padding
        with open(file_path, "w", encoding="utf-8") as f:
            for idx, item in enumerate(classes_list, start=1):
                std_name = to_standard_name(item)
                f.write(f"[{idx:0{padding_len}d}] {std_name}\n")
    except Exception as e:
        print(f"[警告] 无法写入差异文件 {file_path}: {e}", file=sys.stderr)

def main():
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("使用说明 (Usage):")
        print("  1 个参数 (两两对比):")
        print("    python3 compare_dex.py <path_to_dex_or_directory>")
        print("  2 个参数 (两个阵营整体对比):")
        print("    python3 compare_dex.py <path_A> <path_B>")
        sys.exit(1)

    path_1 = sys.argv[1]

    if len(sys.argv) == 2:
        # 单参数模式：获取所有 dex 作为独立阵营，两两对比
        dex_files = get_dex_files(path_1)
        if not dex_files:
            print("[错误] 未能找到任何合法 DEX 文件！", file=sys.stderr)
            sys.exit(1)

        print(f"[*] 进入单参数两两对比模式。路径: {path_1}，发现 {len(dex_files)} 个 DEX 文件。")
        camps = []
        for df in dex_files:
            # 使用更具语义的相对路径作为 camp 名称，防止多级子目录下同名备份文件产生“自己比自己”的误解
            rel_path = os.path.relpath(df, start=path_1) if os.path.isdir(path_1) else os.path.basename(df)
            camp = build_camp(rel_path, [df])
            if camp:
                camps.append(camp)

        if len(camps) < 2:
            print("[信息] 单参数下解析成功的 DEX 阵营数量小于 2 个，无需进行两两对比。")
            if camps:
                print_camp_summary(camps)
            return

        # 打印信息汇总表
        print_camp_summary(camps)

        # 两两对比
        print("\n[ 2. DEX 两两差异对比矩阵 ]")
        headers = ["对比关系 (A -> B)", "相同类数", "A唯一类数", "B唯一类数", "包含率计算公式及比例 (Sim(A->B))", "杰卡德重合度 (Jaccard)"]
        rows = []

        # 保存 100% 重合的组
        identical_groups = []

        for i in range(len(camps)):
            for j in range(len(camps)):
                if i == j:
                    continue
                camp_a = camps[i]
                camp_b = camps[j]

                res = compare_two_camps(camp_a, camp_b)
                formula_str = f"{res['intersection']} / {camp_a['unique_classes']} = {res['sim_a_in_b']:.1f}%"
                rows.append([
                    f"{camp_a['name']} -> {camp_b['name']}",
                    res['intersection'],
                    camp_a['unique_classes'],
                    camp_b['unique_classes'],
                    formula_str,
                    f"{res['jaccard']:.1f}%"
                ])

                # 记录 100% 重叠
                if res['sim_a_in_b'] == 100.0 and camp_a['unique_classes'] == camp_b['unique_classes']:
                    identical_groups.append((camp_a['name'], camp_b['name']))

        print_fancy_table(headers, rows)

        if identical_groups:
            print("\n💡 **【智能推荐】** 发现以下 DEX 的类完全一致 (100% 互包含)，建议清理去重:")
            # 去重重合组 (A,B) 和 (B,A) 的展示
            printed_pairs = set()
            for g1, g2 in identical_groups:
                pair_key = tuple(sorted([g1, g2]))
                if pair_key not in printed_pairs:
                    print(f"  - `{g1}` 与 `{g2}` 完全一致")
                    printed_pairs.add(pair_key)

    elif len(sys.argv) == 3:
        # 双参数模式：将 path_1 与 path_2 看做两个整体大阵营对比
        path_2 = sys.argv[2]

        files_1 = get_dex_files(path_1)
        files_2 = get_dex_files(path_2)

        if not files_1:
            print(f"[错误] 路径 1 下未找到任何 DEX 文件: {path_1}", file=sys.stderr)
            sys.exit(1)
        if not files_2:
            print(f"[错误] 路径 2 下未找到任何 DEX 文件: {path_2}", file=sys.stderr)
            sys.exit(1)

        print(f"[*] 进入双参数阵营对比模式。")
        print(f"  - 阵营 A 路径: {path_1} (包含 {len(files_1)} 个 DEX)")
        print(f"  - 阵营 B 路径: {path_2} (包含 {len(files_2)} 个 DEX)")

        camp_a = build_camp("阵营_A", files_1)
        camp_b = build_camp("阵营_B", files_2)

        if not camp_a or not camp_b:
            print("[错误] 构建阵营失败，请检查 DEX 文件合法性。", file=sys.stderr)
            sys.exit(1)

        # 1. 打印信息统计表
        print_camp_summary([camp_a, camp_b])

        # 2. 对比指标
        print("\n📊 [ 2. 阵营间相似度指标对比 ]")
        border_width = 65
        print("─" * border_width)
        res = compare_two_camps(camp_a, camp_b)

        sim_a_b_formula = f"{res['intersection']} / {camp_a['unique_classes']} = {res['sim_a_in_b']:.1f}%"
        sim_b_a_formula = f"{res['intersection']} / {camp_b['unique_classes']} = {res['sim_b_in_a']:.1f}%"

        print(f" 👉 {path_1} inside {path_2}:  {sim_a_b_formula}")
        print(f" 👉 {path_2} inside {path_1}:  {sim_b_a_formula}")
        print(f" 👉 整体杰卡德重合度 (Jaccard Similarity):  {res['intersection']} / {camp_a['unique_classes'] + camp_b['unique_classes'] - res['intersection']} = {res['jaccard']:.1f}%")
        print(f" 👉 两阵营交集 (相同类数):                  {res['intersection']} 个")
        print("─" * border_width)

        # 3. 有差异类的类名按长度从长到短排序打印
        only_in_a_list = res["only_in_a"]
        only_in_b_list = res["only_in_b"]

        print("\n🔍 [ 3. 差异类名列表明细 (按类名从长到短排序) ]")

        # 3.1 仅在 A 中的类
        print(f"\n  (1) 仅存在于 阵营 A 中的类 (Only in A, 共 {len(only_in_a_list)} 个):")
        print("  " + "─" * (border_width - 4))
        if not only_in_a_list:
            print("  [无]")
        else:
            if len(only_in_a_list) <= 100:
                for idx, cls in enumerate(only_in_a_list, start=1):
                    print(f"    [{idx:03d}] {to_standard_name(cls)}")
            else:
                # 写入本地防爆
                write_diff_file("diff_only_in_A.txt", only_in_a_list)
                print(f"  ⚠️ 仅在 A 中的类过多 (共 {len(only_in_a_list)} 个)。")
                print(f"  📁 已经将完整列表输出到当前目录下的: `diff_only_in_A.txt` (包含对齐序号和从长到短排序的标准类名)")
                print("  以下为前 100 个预览：")
                for idx, cls in enumerate(only_in_a_list[:100], start=1):
                    print(f"    [{idx:03d}] {to_standard_name(cls)}")

        # 3.2 仅在 B 中的类
        print(f"\n  (2) 仅存在于 阵营 B 中的类 (Only in B, 共 {len(only_in_b_list)} 个):")
        print("  " + "─" * (border_width - 4))
        if not only_in_b_list:
            print("  [无]")
        else:
            if len(only_in_b_list) <= 100:
                for idx, cls in enumerate(only_in_b_list, start=1):
                    print(f"    [{idx:03d}] {to_standard_name(cls)}")
            else:
                # 写入本地防爆
                write_diff_file("diff_only_in_B.txt", only_in_b_list)
                print(f"  ⚠️ 仅在 B 中的类过多 (共 {len(only_in_b_list)} 个)。")
                print(f"  📁 已经将完整列表输出到当前目录下的: `diff_only_in_B.txt` (包含对齐序号和从长到短排序的标准类名)")
                print("  以下为前 100 个预览：")
                for idx, cls in enumerate(only_in_b_list[:100], start=1):
                    print(f"    [{idx:03d}] {to_standard_name(cls)}")

if __name__ == "__main__":
    main()
