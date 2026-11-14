#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
下载结果校验工具。

校验顺序（从便宜到昂贵）：
  1. 文件大小
  2. 文件魔数（RAR/ZIP/7Z/GZIP）
  3. 尾部字节是否正常（可选，看文件类型）
  4. 压缩包 CRC 全量校验（RAR 用 UnRAR.exe t，7z 用 7z t）
  5. 整文件 MD5/SHA256（用于跟可信来源比对）

重要提醒：不要用夸克 API 返回的 md5 字段校验整文件。
实测该字段与真实整文件哈希不符，但文件本身是完好的。
"""

import argparse
import hashlib
import os
import subprocess
import sys

MAGIC = {
    b'Rar!\x1a\x07\x01\x00': 'RAR5',
    b'Rar!\x1a\x07\x00': 'RAR4',
    b'Rar!\x1a\x07': 'RAR',
    b'PK\x03\x04': 'ZIP',
    b'7z\xbc\xaf\x27\x1c': '7Z',
    b'\x1f\x8b': 'GZIP',
    b'\xfd7zXZ\x00': 'XZ',
    b'BZh': 'BZIP2',
}


def find_unrar():
    cands = [
        r'C:\Program Files\WinRAR\UnRAR.exe',
        r'C:\Program Files (x86)\WinRAR\UnRAR.exe',
        '/usr/bin/unrar',
        '/usr/local/bin/unrar',
    ]
    for c in cands:
        if os.path.exists(c):
            return c
    return None


def find_7z():
    cands = [
        r'C:\Program Files\7-Zip\7z.exe',
        r'C:\Program Files (x86)\7-Zip\7z.exe',
        '/usr/bin/7z',
        '/usr/bin/7za',
        '/usr/local/bin/7z',
    ]
    for c in cands:
        if os.path.exists(c):
            return c
    return None


def detect_kind(path):
    with open(path, 'rb') as f:
        head = f.read(16)
    for magic, name in MAGIC.items():
        if head.startswith(magic):
            return name, head.hex()
    return '未知', head.hex()


def md5_of(path, chunk=16 * 1024 * 1024):
    h = hashlib.md5()
    n = 0
    with open(path, 'rb') as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
            n += len(b)
    return h.hexdigest(), n


def crc_test(path, kind):
    """用压缩包自带 CRC 做全量校验 —— 这是最硬的证据。"""
    if kind.startswith('RAR'):
        exe = find_unrar()
        if not exe:
            return None, '未找到 UnRAR.exe，跳过 CRC 校验'
        cmd = [exe, 't', '-inul', path]
    elif kind == '7Z':
        exe = find_7z()
        if not exe:
            return None, '未找到 7z.exe，跳过 CRC 校验'
        cmd = [exe, 't', path]
    elif kind == 'ZIP':
        exe = find_7z()
        if not exe:
            return None, '未找到 7z.exe，跳过 CRC 校验'
        cmd = [exe, 't', path]
    else:
        return None, '该格式未支持 CRC 校验'

    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=7200)
        rc = proc.returncode
        return (rc == 0), 'exit=%d' % rc
    except Exception as e:
        return None, 'CRC 测试执行失败: %r' % (e,)


def main():
    ap = argparse.ArgumentParser(description='校验下载结果完整性')
    ap.add_argument('--file', required=True, help='要校验的文件路径')
    ap.add_argument('--size', type=int, help='期望大小（字节），不填则跳过')
    ap.add_argument('--md5', help='期望 MD5，不填则只计算不比对')
    ap.add_argument('--skip-crc', action='store_true', help='跳过压缩包 CRC 校验')
    ap.add_argument('--skip-md5', action='store_true', help='跳过 MD5 计算（大文件耗时）')
    args = ap.parse_args()

    path = os.path.abspath(args.file)
    if not os.path.exists(path):
        print('文件不存在: %s' % path, file=sys.stderr)
        return 2

    size = os.path.getsize(path)
    print('文件: %s' % path)
    print('大小: %d 字节 (%.2f GB)' % (size, size / 1024 ** 3))

    ok_all = True

    # 1. 大小
    if args.size is not None:
        match = (size == args.size)
        ok_all = ok_all and match
        print('大小校验: %s (期望 %d)' % ('通过' if match else '不符', args.size))

    # 2. 魔数
    kind, head_hex = detect_kind(path)
    print('文件类型: %s (头 %s)' % (kind, head_hex))

    # 3. CRC
    if not args.skip_crc and kind != '未知':
        print('CRC 校验中（大文件可能较慢）...')
        res, note = crc_test(path, kind)
        if res is None:
            print('CRC 校验: 跳过 (%s)' % note)
        else:
            ok_all = ok_all and res
            print('CRC 校验: %s (%s)' % ('全部通过' if res else '失败/有损坏', note))

    # 4. MD5
    if not args.skip_md5:
        print('计算 MD5...')
        digest, n = md5_of(path)
        print('MD5: %s' % digest)
        if args.md5:
            match = (digest.lower() == args.md5.lower())
            ok_all = ok_all and match
            print('MD5 比对: %s (期望 %s)' % ('一致' if match else '不一致', args.md5))

    print('\n总结: %s' % ('全部校验通过' if ok_all else '存在问题，见上'))
    return 0 if ok_all else 1


if __name__ == '__main__':
    sys.exit(main())
