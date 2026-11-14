#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scan_clean 的单元测试。

这个函数是整个项目的安全底线：它负责识别被 CDN 412 错误页污染的分块。
只要它漏判一次，就会把错误数据当成下载成果合并进最终文件。

运行: python tests/test_scan.py
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import quark_downloader as qd

HTML_412 = (b'<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n'
            b'<html><head><title>412 Precondition Failed</title></head>'
            b'<body><h1>412 Precondition Failed</h1></body></html>')


def _make(tmp, name, data):
    p = os.path.join(tmp, name)
    with open(p, 'wb') as f:
        f.write(data)
    return p


def run():
    tmp = tempfile.mkdtemp(prefix='qd_test_')
    cases = []

    # 干净的二进制数据必须通过
    clean = _make(tmp, 'clean.bin', b'\x52\x61\x72\x21\x1a\x07\x01\x00' + bytes(range(256)) * 100)
    cases.append(('纯二进制应通过', qd.scan_clean(clean, os.path.getsize(clean)), True))

    # 开头被 412 错误页污染（真实踩过的坑）
    bad_head = _make(tmp, 'bad_head.bin', HTML_412 + bytes(1024))
    cases.append(('开头 HTML 应拒绝', qd.scan_clean(bad_head, os.path.getsize(bad_head)), False))

    # 中间被污染（偏移错位的典型症状）
    bad_mid = _make(tmp, 'bad_mid.bin', bytes(5 * 1024 * 1024) + HTML_412 + bytes(1024))
    cases.append(('中间 HTML 应拒绝', qd.scan_clean(bad_mid, os.path.getsize(bad_mid)), False))

    # 结尾被污染
    bad_tail = _make(tmp, 'bad_tail.bin', bytes(1024) + HTML_412)
    cases.append(('结尾 HTML 应拒绝', qd.scan_clean(bad_tail, os.path.getsize(bad_tail)), False))

    # 标记刚好跨 8MB 读取边界 —— 测 carry 逻辑
    boundary = _make(tmp, 'bad_boundary.bin', bytes(8 * 1024 * 1024 - 10) + b'<!DOCTYPE' + bytes(100))
    cases.append(('边界处 HTML 应拒绝', qd.scan_clean(boundary, os.path.getsize(boundary)), False))

    # 大小不符必须拒绝
    wrong = _make(tmp, 'wrong_size.bin', b'x' * 100)
    cases.append(('大小不符应拒绝', qd.scan_clean(wrong, 200), False))

    # 文件不存在必须拒绝
    cases.append(('文件不存在应拒绝', qd.scan_clean(os.path.join(tmp, 'nope.bin'), 10), False))

    # 魔数识别
    with open(clean, 'rb') as f:
        head = f.read(8)
    kind = '未知'
    for magic, name in qd.MAGIC.items():
        if head.startswith(magic):
            kind = name
            break
    cases.append(('RAR 魔数识别', kind, 'RAR'))

    print('强校验逻辑测试')
    print('-' * 50)
    ok = 0
    for label, got, want in cases:
        passed = (got == want)
        ok += int(passed)
        print('  %s  %-24s got=%-6s want=%-6s'
              % ('PASS' if passed else 'FAIL', label, got, want))
    print('-' * 50)
    print('%d/%d 通过' % (ok, len(cases)))
    return 0 if ok == len(cases) else 1


if __name__ == '__main__':
    sys.exit(run())
