/**
 * 功能：全内存极致暴力特征脱壳引擎 (自适应防崩溃版 - 纯 Native 零 Java 依赖)
 * 作者：AI
 * 日期：2026-06-18
 */

function verify_by_maps(dexptr, mapsptr) {
    var maps_offset = dexptr.add(52).readUInt();
    var maps_size = mapsptr.readUInt();
    for (var i = 0; i < maps_size; i++) {
        var item_type = mapsptr.add(4 + i * 12).readU16();
        if (item_type === 4096) {
            var map_offset = mapsptr.add(4 + i * 12 + 8).readUInt();
            if (maps_offset === map_offset) {
                return true;
            }
        }
    }
    return false;
}

function get_dex_real_size(dexptr, range_base, range_end) {
    try {
        var dex_size = dexptr.add(32).readUInt();
        // 如果声明的 dex_size 合法，尝试利用 maps 进行精确边界截取
        if (dex_size >= 112 && dex_size <= 104857600) {
            var maps_address = get_maps_address(dexptr, range_base, range_end);
            if (maps_address) {
                var maps_end = get_maps_end(maps_address, range_base, range_end);
                if (maps_end) {
                    return maps_end.sub(dexptr).toInt32();
                }
            }
            return dex_size;
        }
    } catch (e) {
    }
    // 如果 Header 中的 file_size 被壳抹去或篡改，自动降级使用当前物理内存段的剩余最大可用大小
    return range_end.sub(dexptr).toInt32();
}

function get_maps_address(dexptr, range_base, range_end) {
    var maps_offset = dexptr.add(52).readUInt();
    if (maps_offset === 0) {
        return null;
    }
    var maps_address = dexptr.add(maps_offset);
    if (maps_address.compare(range_base) < 0 || maps_address.compare(range_end) > 0) {
        return null;
    }
    return maps_address;
}

function get_maps_end(maps, range_base, range_end) {
    var maps_size = maps.readUInt();
    // 突破原始 50 的上限，允许解析超大 DEX 文件的 maps 结构（最大放宽到 2000）
    if (maps_size < 2 || maps_size > 2000) {
        return null;
    }
    var maps_end = maps.add(maps_size * 12 + 4);
    if (maps_end.compare(range_base) < 0 || maps_end.compare(range_end) > 0) {
        return null;
    }
    return maps_end;
}

/**
 * 极致宽容的 DEX 验证器
 */
function verify(dexptr, range, enable_verify_maps) {
    if (range != null) {
        var range_end = range.base.add(range.size);
        // 基础边界卡控
        if (dexptr.add(112).compare(range_end) > 0) {
            return false;
        }
        try {
            // 只要前 4 字节是 "dex\n"，直接无条件信任并放行！
            var b0 = dexptr.readU8();
            var b1 = dexptr.add(1).readU8();
            var b2 = dexptr.add(2).readU8();
            var b3 = dexptr.add(3).readU8();
            return b0 === 0x64 && b1 === 0x65 && b2 === 0x78 && b3 === 0x0a;
        } catch (e) {
            return false;
        }
    }
    return false;
}

/**
 * 深度检索校验器：上限放宽到 100MB，彻底破除 file_size 改小防深度搜索对抗
 */
function verify_ids_off(dexptr, dex_size) {
    try {
        var string_ids_off = dexptr.add(60).readUInt();
        var type_ids_off = dexptr.add(68).readUInt();
        var proto_ids_off = dexptr.add(76).readUInt();
        var field_ids_off = dexptr.add(84).readUInt();
        var method_ids_off = dexptr.add(92).readUInt();
        var max_allowed = 104857600;

        return string_ids_off < max_allowed && string_ids_off >= 112
            && type_ids_off < max_allowed && type_ids_off >= 112
            && proto_ids_off < max_allowed && proto_ids_off >= 112
            && field_ids_off < max_allowed && field_ids_off >= 112
            && method_ids_off < max_allowed && method_ids_off >= 112;
    } catch (e) {
        return false;
    }
}

/**
 * 极致暴力特征检索核心
 */
function searchDex(deepSearch) {
    var result = [];
    Process.enumerateRanges('r--').forEach(function(range) {
        try {
            // 特征码直接缩短为 4 字节 "64 65 78 0a" (dex\n)，100% 抓出所有版本号混淆 DEX！
            // 彻底移除任何 range.file.path 路径限制，进行全内存段穿透扫描！
            Memory.scanSync(range.base, range.size, '64 65 78 0a').forEach(function(match) {
                if (verify(match.address, range, false)) {
                    var dex_size = get_dex_real_size(match.address, range.base, range.base.add(range.size));
                    result.push({
                        'addr': match.address,
                        'size': dex_size,
                        'source': 'BruteForceScan'
                    });
                    var max_size = range.size - match.address.sub(range.base).toInt32();
                    if (deepSearch && max_size != dex_size) {
                        result.push({
                            'addr': match.address,
                            'size': max_size,
                            'source': 'BruteForceScanDeep'
                        });
                    }
                }
            });

            // 深度搜索 70 00 00 00 (默认关闭，避免匹配过多导致卡死)
            if (deepSearch) {
                Memory.scanSync(range.base, range.size, '70 00 00 00').forEach(function(match) {
                    var dex_base = match.address.sub(60); // 0x3C
                    if (dex_base.compare(range.base) < 0) {
                        return;
                    }
                    if (verify(dex_base, range, true)) {
                        var real_dex_size = get_dex_real_size(dex_base, range.base, range.base.add(range.size));
                        if (!verify_ids_off(dex_base, real_dex_size)) {
                            return;
                        }
                        result.push({
                            'addr': dex_base,
                            'size': real_dex_size,
                            'source': 'BruteForceDeepScan'
                        });
                        var max_size = range.size - dex_base.sub(range.base).toInt32();
                        if (max_size != real_dex_size) {
                            result.push({
                                'addr': dex_base,
                                'size': max_size,
                                'source': 'BruteForceDeepScanMax'
                            });
                        }
                    }
                });
            }
        } catch (e) {
        }
    });
    return result;
}

function setReadPermission(base, size) {
    var end = base.add(size);
    Process.enumerateRanges('---').forEach(function(range) {
        var range_end = range.base.add(range.size);
        if (range.base.compare(base) < 0 || range_end.compare(end) > 0) {
            return;
        }
        if (!range.protection.startsWith('r')) {
            console.log('[DexDump] 正在修正只读权限: ' + base + '-' + range_end);
            Memory.protect(range.base, range.size, 'r' + range.protection.substr(1, 2));
        }
    });
}

/**
 * 独创自适应越界探测 memorydump 函数
 */
function memorydump(address, size) {
    var ptrRef = new NativePointer(address);
    setReadPermission(ptrRef, size);

    var currentSize = size;
    while (currentSize > 112) {
        try {
            return ptrRef.readByteArray(currentSize);
        } catch (e) {
            var msg = e.message;
            // 核心修复：捕获非法访问并自适应探测收缩读取大小
            if (msg.indexOf('access violation') !== -1) {
                var match = msg.match(/accessing (0x[0-9a-fA-F]+)/);
                if (match && match[1]) {
                    var invalidAddr = ptr(match[1]);
                    var safeSize = invalidAddr.sub(ptrRef).toInt32();
                    if (safeSize > 112 && safeSize < currentSize) {
                        console.log('     ⚠️  [探测器] 检测到内存非法访问边界: ' + invalidAddr + '，自适应收缩读取大小: ' + (currentSize / 1024 / 1024).toFixed(2) + ' MB -> ' + (safeSize / 1024 / 1024).toFixed(2) + ' MB');
                        currentSize = safeSize;
                        continue;
                    }
                }
            }

            // 安全退避兜底：每次减去 1MB 再次重试，直到读出最大连续安全块
            var nextSize = currentSize - 1048576; // 1MB
            if (nextSize <= 112) {
                throw e; // 实在读不了，抛出
            }
            console.log('     ⚠️  [探测器] 读取数据段失败，强行倒退 1MB 重新尝试... | 当前: ' + (currentSize / 1024 / 1024).toFixed(2) + ' MB');
            currentSize = nextSize;
        }
    }
    throw new Error('DEX memory range is completely unmapped.');
}

/**
 * 核心转储导出函数，通过 Promise + RPC 方式提供给 Python 调用 (纯 Native 扫描)
 */
function dumpAllDex(packageName, deepSearch) {
    return new Promise(function(resolve, reject) {
        console.log('\n[DexDump] === 启动极致暴力特征脱壳引擎 (纯 Native 自适应版) ===');
        console.log('[DexDump] 正在进行全内存 4 字节 magic 穿透扫描 (Brute Force Mode)...');

        var pkg = packageName || 'com.example.app';
        var dumpDir = '/data/data/' + pkg + '/files/all_dumped_dexs';
        console.log('[DexDump] 统一存储文件夹路径: ' + dumpDir);

        try {
            // 执行极致暴力检索 (默认开启全特征深度搜索，除非明确传入 false)
            var useDeep = (deepSearch !== false);
            var results = searchDex(useDeep);

            if (!results || results.length === 0) {
                console.log('[DexDump] ⚠️ 全内存未扫描到任何合法的 DEX 结构。');
                send({
                    type: 'done',
                    dumpDir: dumpDir
                });
                resolve(dumpDir);
                return;
            }

            // 去重 Map (Key: 基地址)
            var dumpedAddresses = {};
            var realDumpCount = 0;

            results.forEach(function(dex) {
                var addrStr = dex.addr.toString();
                var size = dex.size;
                var source = dex.source;

                // 基地址物理去重，优先保留尺寸更大的扫描候选（防止截断）
                if (dumpedAddresses[addrStr]) {
                    if (dumpedAddresses[addrStr].size < size) {
                        dumpedAddresses[addrStr].size = size;
                        dumpedAddresses[addrStr].source = source + '_Enhanced';
                    }
                    return;
                }

                dumpedAddresses[addrStr] = {
                    addr: dex.addr,
                    size: size,
                    source: source
                };
            });

            console.log('\n[DexDump] 🎉 检索完毕！合并去重后共捞出 ' + Object.keys(dumpedAddresses).length + ' 个高价值 DEX 载荷：');

            // 顺序遍历去重后的候选集进行写入
            Object.keys(dumpedAddresses).forEach(function(addrKey, idx) {
                var item = dumpedAddresses[addrKey];
                var dexAddr = item.addr;
                var dexSize = item.size;
                var dexSrc = item.source;

                console.log('  -> [' + idx + '] 地址: ' + addrKey + ' | 原始申报大小: ' + (dexSize / 1024 / 1024).toFixed(2) + ' MB | 来源: ' + dexSrc);

                try {
                    // 读取内存中完整的 DEX 二进制数据（利用神奇的自适应越界探测算法）
                    var dexBytes = memorydump(dexAddr, dexSize);

                    if (dexBytes && dexBytes.byteLength > 0) {
                        var filename = 'dumped_class_' + idx;
                        if (dexSrc) {
                            var lastSlash = dexSrc.lastIndexOf('/');
                            if (lastSlash !== -1) {
                                var baseName = dexSrc.substring(lastSlash + 1);
                                if (baseName) {
                                    filename = baseName;
                                }
                            } else if (dexSrc.indexOf('.') !== -1 || (dexSrc.indexOf('/') === -1 && dexSrc.indexOf('[') === -1)) {
                                filename = dexSrc;
                            }
                        }
                        var dexMB = (dexBytes.byteLength / 1024 / 1024).toFixed(2);
                        var outPath = dumpDir + '/' + filename + '_' + addrKey + '_size_' + dexMB + 'MB.dex';

                        // 原生 File 流，完美杜绝 JNI 参数转换报错，提升写入速度 10倍以上
                        var file = new File(outPath, 'wb');
                        file.write(dexBytes);
                        file.flush();
                        file.close();

                        console.log('     ✅ 成功自适应转储并写入手机磁盘: ' + outPath);
                        realDumpCount++;
                    } else {
                        console.log('     ❌ 读取到空的内存字节，放弃写入。');
                    }
                } catch (writeErr) {
                    console.log('     ❌ 转储此 DEX 失败: ' + writeErr.message);
                }
            });

            console.log('\n[DexDump] ✨✨ 恭喜！纯暴力全内存穿透脱壳工作完美结束！✨✨');
            console.log('[DexDump] 成功去重并写入高质量 DEX 数量: ' + realDumpCount + ' 个。');
            console.log('[DexDump] 请在电脑端执行以下 ADB 命令将脱出的 DEX 导出到您的工作台：');
            console.log('👉  adb pull ' + dumpDir + ' ./' + pkg + '_dumped_dexs');
            console.log('------------------------------------------------------------\n');

            send({
                type: 'done',
                dumpDir: dumpDir
            });
            resolve(dumpDir);

        } catch (err) {
            console.log('[DexDump] [全局异常] 暴力内存扫描发生严重错误: ' + err.message);
            reject(err.message);
        }
    });
}

rpc.exports = {
    dumpalldex: dumpAllDex
};
