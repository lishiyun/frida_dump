import os
import sys
import zlib
import hashlib
import struct

def fix_dex_file(filepath, force=False):
    """
    检查并修复单个 DEX 文件。
    force=True 时强制修复（即便大小匹配也重新计算）。
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
        print(f"[-] 文件过小，不像是合法的 DEX 文件: {filename}")
        return False

    # 读取文件头中声明的文件大小 (偏移量 32-35)
    header_sz = struct.unpack("<I", data[32:36])[0]

    # 判断是否需要修复
    if not force and file_size == header_sz:
        print(f"[~] 无需修复 (已是好文件): {filename}")
        return False

    print(f"[*] 正在修复 DEX 文件: {filename} (实际大小: {file_size} 字节, 头部大小: {header_sz} 字节)")

    # 1. 更新文件头中的 file_size 字段 (偏移量 32-35, 4 字节小端无符号整数)
    struct.pack_into("<I", data, 32, file_size)

    # 2. 计算并更新 SHA-1 签名 (偏移量 12-31, 20 字节)
    sha1 = hashlib.sha1()
    sha1.update(data[32:])
    data[12:32] = sha1.digest()

    # 3. 计算并更新 Adler32 校验和 (偏移量 8-11, 4 字节小端无符号整数)
    adler = zlib.adler32(data[12:]) & 0xffffffff
    struct.pack_into("<I", data, 8, adler)

    # 将修改后的数据写回原文件
    try:
        with open(filepath, 'wb') as f:
            f.write(data)
        print(f"[+] 修复完成 (Adler32: 0x{adler:08x}, SHA1: {sha1.hexdigest()[:8]}...): {filename}")
        return True
    except Exception as e:
        print(f"[-] 写入文件失败 {filename}: {e}")
        return False

def fix_dex_directory(dirpath):
    """
    扫描并批量修复目录下的所有 DEX 文件。
    """
    print(f"[*] 正在扫描目录: {os.path.abspath(dirpath)}")
    if not os.path.exists(dirpath):
        print(f"[-] 目录不存在: {dirpath}")
        return

    dex_files = [f for f in os.listdir(dirpath) if f.lower().endswith('.dex')]
    if not dex_files:
        print("[-] 未在目录下找到任何 .dex 文件。")
        return

    print(f"[*] 找到 {len(dex_files)} 个 DEX 文件，开始进行智能检查与修复...")
    fixed_count = 0
    skipped_count = 0

    for f in sorted(dex_files):
        p = os.path.join(dirpath, f)
        if fix_dex_file(p, force=False):
            fixed_count += 1
        else:
            skipped_count += 1

    print(f"\n[!] 批量处理完成！共修复: {fixed_count} 个，跳过无需修复的正常文件: {skipped_count} 个。")

if __name__ == '__main__':
    # 打印欢迎信息和友好交互
    print("=============================================")
    print("        Android DEX 智能修复工具")
    print("=============================================")

    # 如果有参数
    if len(sys.argv) >= 2:
        target = sys.argv[1]
        if os.path.isdir(target):
            # 处理目录
            fix_dex_directory(target)
        elif os.path.isfile(target):
            # 处理单文件
            fix_dex_file(target, force=False)
        else:
            print(f"[-] 错误: 指定的路径不存在: {target}")
            sys.exit(1)
    else:
        # 无参数时的智能默认逻辑
        # 1. 检查当前目录下是否有 all_dumped_dexs 文件夹
        if os.path.isdir("all_dumped_dexs"):
            print("[*] 未提供参数，检测到当前目录下存在 'all_dumped_dexs' 文件夹，自动开始处理...")
            fix_dex_directory("all_dumped_dexs")
        # 2. 否则，扫描当前目录 .
        else:
            print("[*] 未提供参数，默认开始扫描并处理当前目录...")
            fix_dex_directory(".")
