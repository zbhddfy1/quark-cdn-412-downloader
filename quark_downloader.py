#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
quark-cdn-412-downloader

从夸克网盘分享链接下载超大文件，绕过阿里 CDN 的 412 Precondition Failed 风控。

核心设计：
  1. 分块（默认 64MB）+ 并发：把大 Range 拆小，提高风控下的命中率
  2. 强校验：206 + 字节数精确 + Content-Range 精确 + 全文无 HTML 错误页
  3. 412 快速重试：命中即丢弃数据重来，成本约 0.4 秒
  4. 低频探针：风控收紧时每 45 秒只发一个探针，等窗口恢复再补齐
  5. 断点续传：进度写 progress.json，中断后重跑自动跳过已完成块

用法：
  python quark_downloader.py --pwd-id YOUR_PWD_ID --cookies cookies.json \
      --out D:/downloads/big.rar --chunk-mb 64 --workers 8
"""

import argparse
import json
import os
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_UA = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
    'quark-cloud-drive/3.20.0 Chrome/112.0.5615.165 Electron/24.1.3.8 '
    'Safari/537.36 Channel/pckk_other_ch'
)

API_TOKEN = 'https://pan.quark.cn/1/clouddrive/share/sharepage/token?pr=ucpro&fr=pc'
API_DETAIL = 'https://pan.quark.cn/1/clouddrive/share/sharepage/detail'
API_DOWNLOAD = 'https://drive-pc.quark.cn/1/clouddrive/file/download?entry=ft&fr=pc&pr=ucpro'

HTML_MARKERS = (b'<!DOCTYPE', b'412 Precondition', b'<html>')

MAGIC = {
    b'Rar!\x1a\x07': 'RAR',
    b'PK\x03\x04': 'ZIP',
    b'7z\xbc\xaf\x27\x1c': '7Z',
    b'\x1f\x8b': 'GZIP',
}


def find_curl():
    """412 是按 TLS 指纹拦的，必须用系统 curl（Windows 上是 Schannel）。"""
    if os.name == 'nt':
        cand = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'curl.exe')
        if os.path.exists(cand):
            return cand
    for p in ('/usr/bin/curl', '/usr/local/bin/curl'):
        if os.path.exists(p):
            return p
    raise RuntimeError('未找到 curl，请先安装（412 拦截需要系统 curl 的 TLS 指纹）')


def wait_seconds(seconds):
    """
    等待指定秒数。

    故意用 5 秒字面量分片：一是这个项目的等待都很短（重试间隔），
    二是风控期长等待要能随时被打断/观察，不要一个 sleep 睡死。
    """
    n = int(float(seconds) // 5)
    for _ in range(n):
        time.sleep(5)


class QuarkClient:
    def __init__(self, pwd_id, cookies, pwd='', ua=DEFAULT_UA, timeout=30):
        self.pwd_id = pwd_id
        self.passcode = pwd
        self.ua = ua
        self.timeout = timeout
        self.curl = find_curl()
        self.ctx = ssl.create_default_context()
        self.cookie_str = self._build_cookies(cookies)
        self.url_ttl = 240
        self._url = ''
        self._url_ts = 0.0
        self._url_lock = threading.Lock()

    @staticmethod
    def _build_cookies(cookies):
        """只收值全是可见 ASCII 的 cookie —— 带二进制前缀的会让 urllib 编码失败。"""
        keep = [c for c in cookies if all(32 < ord(ch) < 127 for ch in str(c.get('value', '')))]
        return '; '.join('%s=%s' % (c['name'], c['value']) for c in keep)

    def _headers(self, req):
        req.add_header('User-Agent', self.ua)
        req.add_header('Referer', 'https://pan.quark.cn/')
        req.add_header('Origin', 'https://pan.quark.cn')
        req.add_header('Accept', 'application/json, text/plain, */*')
        req.add_header('Cookie', self.cookie_str)

    def _post(self, url, body):
        req = urllib.request.Request(url, data=json.dumps(body).encode('utf-8'), method='POST')
        req.add_header('Content-Type', 'application/json;charset=UTF-8')
        self._headers(req)
        with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
            return json.loads(r.read().decode('utf-8', 'ignore'))

    def _get(self, url):
        req = urllib.request.Request(url, method='GET')
        self._headers(req)
        with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
            return json.loads(r.read().decode('utf-8', 'ignore'))

    def list_files(self, pdir_fid='0'):
        tok = self._post(API_TOKEN, {'pwd_id': self.pwd_id, 'passcode': self.passcode})
        stoken = (tok.get('data') or {}).get('stoken', '')
        if not stoken:
            raise RuntimeError('拿不到 stoken，检查分享 ID/提取码是否有效：%s' % tok.get('message'))
        q = urllib.parse.urlencode({
            'pr': 'ucpro', 'fr': 'pc', 'pwd_id': self.pwd_id, 'stoken': stoken,
            'pdir_fid': pdir_fid, '_page': 1, '_size': 100,
            '_sort': 'file_type:asc,updated_at:desc',
        })
        d = self._get(API_DETAIL + '?' + q)
        return stoken, (d.get('data') or {}).get('list') or []

    def resolve(self, file_name=None):
        stoken, items = self.list_files()
        if not items:
            raise RuntimeError('分享目录为空')
        target = None
        for it in items:
            if file_name and str(it.get('file_name')) == file_name:
                target = it
                break
        if target is None:
            if file_name:
                raise RuntimeError('分享里没找到文件 %r，可用 --list 查看' % file_name)
            target = items[0]
        return stoken, target

    def fresh_url(self, stoken, item):
        body = {
            'fids': [item.get('fid')],
            'fids_token': [item.get('share_fid_token')],
            'pwd_id': self.pwd_id,
            'stoken': stoken,
        }
        dl = self._post(API_DOWNLOAD, body)
        data = dl.get('data')
        url = ''
        if isinstance(data, list) and data:
            url = (data[0] or {}).get('download_url', '')
        elif isinstance(data, dict):
            lst = data.get('list') or []
            if lst:
                url = (lst[0] or {}).get('download_url', '')
        if not url:
            raise RuntimeError('拿不到直链 code=%s msg=%s' % (dl.get('code'), dl.get('message')))
        return url

    def get_url(self, stoken, item, force=False, log=print):
        with self._url_lock:
            if force or not self._url or (time.time() - self._url_ts) > self.url_ttl:
                last = None
                for _ in range(5):
                    try:
                        self._url = self.fresh_url(stoken, item)
                        self._url_ts = time.time()
                        log('直链已刷新 (len=%d)' % len(self._url))
                        return self._url
                    except Exception as e:
                        last = e
                        wait_seconds(5)
                raise RuntimeError('刷新直链失败: %r' % (last,))
            return self._url


def scan_clean(path, expected):
    """扫全文找 HTML 错误页标记；顺便校验字节数。"""
    if not os.path.exists(path):
        return False
    if os.path.getsize(path) != expected:
        return False
    carry = b''
    with open(path, 'rb') as f:
        while True:
            buf = f.read(8 * 1024 * 1024)
            if not buf:
                break
            chunk = carry + buf
            for mark in HTML_MARKERS:
                if mark in chunk:
                    return False
            carry = chunk[-64:]
    return True


def fetch_range(curl, url, start, end, out_path, ua, total, max_time=150):
    """
    请求一个 Range 段落。
    返回 (code, size, ok, elapsed)。ok 要求 206 + 字节数 + Content-Range + 无 HTML 全过。
    """
    hdr_path = out_path + '.hdr'
    for p in (out_path, hdr_path):
        try:
            if os.path.exists(p):
                os.remove(p)
        except OSError:
            pass
    cmd = [
        curl, '-sS', '-D', hdr_path, '-o', out_path,
        '-w', '%{http_code}|%{size_download}',
        '--max-time', str(int(max_time)),
        '-A', ua,
        '-H', 'Referer: https://pan.quark.cn/',
        '-H', 'Range: bytes=%d-%d' % (start, end),
        url,
    ]
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=max_time + 15)
        stdout = (proc.stdout or '').strip()
    except Exception:
        return ('EXC', 0, False, time.time() - t0)

    code = stdout.split('|')[0] if stdout else '000'
    want = end - start + 1

    cr_ok = False
    try:
        with open(hdr_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if line.lower().startswith('content-range:'):
                    got = line.split(':', 1)[1].strip()
                    cr_ok = (got == 'bytes %d-%d/%d' % (start, end, total))
                    break
    except OSError:
        pass

    size = os.path.getsize(out_path) if os.path.exists(out_path) else 0
    clean = scan_clean(out_path, want) if size == want else False
    return (code, size, (code == '206' and size == want and cr_ok and clean), time.time() - t0)


class Downloader:
    def __init__(self, client, stoken, item, out_path, chunk_mb=64, workers=8,
                 tries=80, probe_seconds=45, max_hours=8, log=print):
        self.client = client
        self.stoken = stoken
        self.item = item
        self.out_path = os.path.abspath(out_path)
        self.total = int(item.get('size') or 0)
        if self.total <= 0:
            raise RuntimeError('文件大小未知，无法分块')
        self.chunk = chunk_mb * 1024 * 1024
        self.n = (self.total + self.chunk - 1) // self.chunk
        self.workers = workers
        self.tries = tries
        self.probe_seconds = probe_seconds
        self.max_hours = max_hours
        self.log = log
        self.run_dir = os.path.splitext(self.out_path)[0] + '.parts'
        self.progress_path = self.run_dir + '/progress.json'
        self.lock = threading.Lock()

    def _chunk_path(self, i):
        return os.path.join(self.run_dir, 'chunk_%05d.bin' % i)

    def _want(self, i):
        return min(self.chunk, self.total - i * self.chunk)

    def load_progress(self):
        if not os.path.exists(self.progress_path):
            return set(), set()
        try:
            with open(self.progress_path, 'r', encoding='utf-8') as f:
                d = json.load(f)
            return set(d.get('done', [])), set(d.get('failed', []))
        except Exception:
            return set(), set()

    def save_progress(self, done, failed):
        tmp = self.progress_path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump({
                'total_chunks': self.n,
                'done': sorted(done),
                'failed': sorted(failed),
                'updated': time.strftime('%Y-%m-%d %H:%M:%S'),
            }, f)
        os.replace(tmp, self.progress_path)

    def download_chunk(self, i):
        start = i * self.chunk
        end = min(start + self.chunk - 1, self.total - 1)
        want = end - start + 1
        final = self._chunk_path(i)
        tmp = final + '.tmp'

        if os.path.exists(final) and scan_clean(final, want):
            return True, 'already'

        for attempt in range(1, self.tries + 1):
            try:
                url = self.client.get_url(self.stoken, self.item, log=self.log)
            except Exception as e:
                self.log('chunk %05d 取直链失败 %r' % (i, e))
                wait_seconds(5)
                continue

            code, size, ok, elapsed = fetch_range(
                self.client.curl, url, start, end, tmp, self.client.ua, self.total, max_time=150)

            if ok:
                os.replace(tmp, final)
                try:
                    os.remove(tmp + '.hdr')
                except OSError:
                    pass
                self.log('chunk %05d 完成 (第 %d 次, %.0fs)' % (i, attempt, elapsed))
                return True, 'ok'

            self.log('chunk %05d 第 %d 次: %s size=%d/%d (%.1fs)'
                     % (i, attempt, code, size, want, elapsed))
            for p in (tmp, tmp + '.hdr'):
                try:
                    if os.path.exists(p):
                        os.remove(p)
                except OSError:
                    pass

            if attempt % 25 == 0:
                try:
                    self.client.get_url(self.stoken, self.item, force=True, log=self.log)
                except Exception:
                    pass

        return False, 'tries-exhausted'

    def probe(self, missing):
        """
        低频探针：只发一个 4MB 请求，判断 CDN 窗口是否恢复。
        风控收紧时高频重试只会更糟，所以要慢。
        """
        if not missing:
            return True
        i = missing[0]
        start = i * self.chunk
        end = min(start + 4 * 1024 * 1024 - 1, self.total - 1)
        try:
            url = self.client.get_url(self.stoken, self.item, log=self.log)
        except Exception as e:
            self.log('探针取直链失败 %r' % e)
            return False
        probe_path = self.run_dir + '/_probe.bin'
        code, size, ok, elapsed = fetch_range(
            self.client.curl, url, start, end, probe_path,
            self.client.ua, self.total, max_time=40)
        self.log('探针 chunk=%d -> %s %s (%.1fs)' % (i, code, '窗口开' if ok else '仍被拦', elapsed))
        for p in (probe_path, probe_path + '.hdr'):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except OSError:
                pass
        return ok

    def merge(self):
        self.log('开始合并 %d 个分块 -> %s' % (self.n, self.out_path))
        carry = b''
        with open(self.out_path, 'wb') as out:
            for i in range(self.n):
                path = self._chunk_path(i)
                if not os.path.exists(path):
                    raise RuntimeError('分块 %d 缺失，无法合并' % i)
                with open(path, 'rb') as f:
                    while True:
                        buf = f.read(8 * 1024 * 1024)
                        if not buf:
                            break
                        chunk = carry + buf
                        for mark in HTML_MARKERS:
                            if mark in chunk:
                                raise RuntimeError(
                                    '合并时在第 %d 块发现 HTML 错误页标记，数据已被污染' % i)
                        carry = chunk[-64:]
                        out.write(buf)
        size = os.path.getsize(self.out_path)
        with open(self.out_path, 'rb') as f:
            head = f.read(8)
        kind = '未知'
        for magic, name in MAGIC.items():
            if head.startswith(magic):
                kind = name
                break
        ok = (size == self.total)
        self.log('合并完成: %d/%d 字节, 头=%s (%s), %s'
                 % (size, self.total, head.hex(), kind,
                    '大小校验通过' if ok else '大小不符'))
        return ok

    def run(self):
        os.makedirs(self.run_dir, exist_ok=True)
        done, failed = self.load_progress()
        missing = [i for i in range(self.n) if i not in done]
        self.log('总计 %d 块 (每块 %dMB), 已完成 %d, 待下载 %d'
                 % (self.n, self.chunk // (1024 * 1024), len(done), len(missing)))

        t0 = time.time()
        rounds = 0
        while missing and (time.time() - t0) < self.max_hours * 3600:
            rounds += 1
            if not self.probe(missing):
                self.log('第 %d 轮: CDN 未恢复，%d 秒后再探' % (rounds, self.probe_seconds))
                wait_seconds(self.probe_seconds)
                continue

            self.log('第 %d 轮: 窗口已开，并发补齐 %d 块' % (rounds, len(missing)))
            with ThreadPoolExecutor(max_workers=self.workers) as ex:
                futs = {ex.submit(self.download_chunk, i): i for i in missing}
                for fut in as_completed(futs):
                    i = futs[fut]
                    try:
                        ok, how = fut.result()
                    except Exception as e:
                        ok, how = False, 'exc:%r' % (e,)
                    with self.lock:
                        if ok:
                            done.add(i)
                            failed.discard(i)
                        else:
                            failed.add(i)
                        self.save_progress(done, failed)
            missing = [i for i in range(self.n) if i not in done]
            if missing:
                self.log('本轮后仍缺 %d 块: %s' % (len(missing), missing[:20]))
                wait_seconds(self.probe_seconds)

        if missing:
            self.log('超时退出，仍缺 %d 块。重跑同一命令可继续。' % len(missing))
            return False

        return self.merge()


def main():
    ap = argparse.ArgumentParser(
        description='从夸克网盘分享下载超大文件（绕过 CDN 412 风控）')
    ap.add_argument('--pwd-id', required=True, help='分享 ID（URL /s/<pwd_id> 里的那串）')
    ap.add_argument('--cookies', required=True, help='cookies.json 路径')
    ap.add_argument('--passcode', default='', help='提取码，没有就留空')
    ap.add_argument('--out', help='输出文件路径')
    ap.add_argument('--file', help='分享内文件名（不填取列表第一个）')
    ap.add_argument('--list', action='store_true', help='只列出分享内文件，不下载')
    ap.add_argument('--chunk-mb', type=int, default=64, help='分块大小 MB（默认 64）')
    ap.add_argument('--workers', type=int, default=8, help='并发数（默认 8）')
    ap.add_argument('--tries', type=int, default=80, help='单块最大重试次数（默认 80）')
    ap.add_argument('--probe-seconds', type=int, default=45,
                    help='风控等待时探针间隔秒数（默认 45，别调太小）')
    ap.add_argument('--max-hours', type=float, default=8, help='最长等待小时数（默认 8）')
    args = ap.parse_args()

    with open(args.cookies, 'r', encoding='utf-8') as f:
        cookies = json.load(f)

    client = QuarkClient(args.pwd_id, cookies, pwd=args.passcode)
    stoken, item = client.resolve(args.file)

    if args.list:
        _, items = client.list_files()
        for it in items:
            print('%12s  %s' % (it.get('size'), it.get('file_name')))
        return 0

    if not args.out:
        print('错误：下载时必须指定 --out', file=sys.stderr)
        return 2

    size = int(item.get('size') or 0)
    print('目标: %s  (%.2f GB)' % (item.get('file_name'), size / 1024 ** 3))
    print('输出: %s' % os.path.abspath(args.out))

    d = Downloader(
        client, stoken, item, args.out,
        chunk_mb=args.chunk_mb, workers=args.workers, tries=args.tries,
        probe_seconds=args.probe_seconds, max_hours=args.max_hours,
    )
    ok = d.run()
    print('\n结果: %s' % ('成功' if ok else '未完成，重跑同命令可续传'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
