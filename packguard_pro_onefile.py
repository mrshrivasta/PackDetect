from __future__ import annotations
import argparse
import base64
import csv
import hashlib
import html
import io
import json
import math
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

REQUIRED_PACKAGES = [
    ("flask", "flask"),
    ("pefile", "pefile"),
]


def ensure_package(import_name: str, pip_name: str) -> None:
    try:
        __import__(import_name)
    except Exception:
        print(f"[+] Installing missing package: {pip_name}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", pip_name])


for import_name, pip_name in REQUIRED_PACKAGES:
    ensure_package(import_name, pip_name)

import pefile
from flask import Flask, Response, request, send_file

try:
    import ssdeep
except Exception:
    ssdeep = None

try:
    import tlsh
except Exception:
    tlsh = None

app = Flask(__name__)
MAX_SIZE = 35 * 1024 * 1024
LAST_RESULTS: Dict[str, Dict[str, Any]] = {}

SUSPICIOUS_SECTION_NAMES = {
    'upx0', 'upx1', 'upx2', '.aspack', '.adata', 'petite', '.petite',
    '.mpress1', '.mpress2', '.themida', '.vmp0', '.vmp1', '.packed', '.stub'
}
PACKER_NAMES = {
    'upx0': 'UPX', 'upx1': 'UPX', 'upx2': 'UPX', '.aspack': 'ASPack',
    '.mpress1': 'MPRESS', '.mpress2': 'MPRESS', '.themida': 'Themida',
    '.vmp0': 'VMProtect', '.vmp1': 'VMProtect', '.packed': 'Generic Packed'
}
SUSPICIOUS_APIS = {
    'generic': {'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory', 'CreateRemoteThread', 'NtCreateThreadEx', 'SetWindowsHookExA', 'SetWindowsHookExW', 'IsDebuggerPresent', 'CheckRemoteDebuggerPresent'},
    'network': {'InternetOpenA', 'InternetOpenW', 'InternetConnectA', 'InternetConnectW', 'WinHttpOpen', 'WinHttpSendRequest', 'URLDownloadToFileA', 'URLDownloadToFileW', 'WSAStartup', 'socket', 'connect'},
    'registry': {'RegOpenKeyA', 'RegOpenKeyW', 'RegSetValueA', 'RegSetValueW', 'RegCreateKeyA', 'RegCreateKeyW', 'RegQueryValueExA', 'RegQueryValueExW'},
    'process_injection': {'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'NtCreateThreadEx', 'QueueUserAPC', 'SetThreadContext', 'ResumeThread'},
    'crypto': {'CryptEncrypt', 'CryptDecrypt', 'BCryptEncrypt', 'BCryptDecrypt', 'CryptAcquireContextA', 'CryptAcquireContextW'},
    'anti_debug': {'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess', 'OutputDebugStringA', 'OutputDebugStringW'}
}
URL_RE = re.compile(rb'https?://[^\s\x00\'\"<>]{4,}')
IP_RE = re.compile(rb'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_RE = re.compile(rb'\b[a-zA-Z0-9.-]+\.(?:com|net|org|ru|cn|info|biz|io|co|xyz|top|in)\b')
EMAIL_RE = re.compile(rb'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
REG_RE = re.compile(rb'(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\x00\r\n]{3,}')
PATH_RE = re.compile(rb'[A-Za-z]:\\[^\x00\r\n]{3,}')
PS_RE = re.compile(rb'(powershell(?:\.exe)?\s+[^\r\n\x00]{3,})', re.I)
CMD_RE = re.compile(rb'(cmd(?:\.exe)?\s+/c\s+[^\r\n\x00]{3,})', re.I)

BASE_CSS = """
:root{--bg:#0b1020;--panel:#131b2e;--panel2:#0f1627;--text:#edf3ff;--muted:#91a4c8;--line:#223150;--good:#76e3a5;--warn:#ffbf66;--bad:#ff7f7f;--accent:#7db4ff}
[data-theme='light']{--bg:#f5f7fb;--panel:#ffffff;--panel2:#eef3fb;--text:#182033;--muted:#5e6b87;--line:#d7dfef;--good:#1d7f4f;--warn:#9a6300;--bad:#b73030;--accent:#1b63d9}
*{box-sizing:border-box}body{margin:0;font-family:Arial,sans-serif;background:var(--bg);color:var(--text)}a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}.nav{display:flex;gap:14px;flex-wrap:wrap;padding:16px 22px;border-bottom:1px solid var(--line);background:var(--panel2);position:sticky;top:0;z-index:5}.wrap{max-width:1300px;margin:auto;padding:22px}.card{background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:18px;margin:16px 0}.hero{display:grid;grid-template-columns:1.4fr .8fr;gap:16px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}.kpi{background:var(--panel2);border:1px solid var(--line);border-radius:16px;padding:14px}.btn{display:inline-block;border:0;border-radius:12px;padding:11px 15px;background:var(--accent);color:white;font-weight:700;cursor:pointer}.btn2{background:transparent;color:var(--text);border:1px solid var(--line)}.disc{border-left:4px solid var(--bad);background:rgba(255,127,127,.1);padding:14px;border-radius:12px}.small{color:var(--muted);font-size:14px}.good{color:var(--good)}.warn{color:var(--warn)}.bad{color:var(--bad)}table{width:100%;border-collapse:collapse;font-size:14px}th,td{padding:9px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}pre,code{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:2px 6px;white-space:pre-wrap}input[type=file],input[type=text]{width:100%;padding:12px;background:var(--panel2);color:var(--text);border:1px solid var(--line);border-radius:12px}.drop{border:2px dashed var(--line);padding:24px;border-radius:16px;text-align:center;background:var(--panel2)}.tree ul{list-style:none;padding-left:18px}.tree li{margin:4px 0}.bar{height:10px;background:var(--panel2);border-radius:999px;overflow:hidden}.bar>span{display:block;height:100%;background:linear-gradient(90deg,var(--good),var(--warn),var(--bad))}.hex{font-family:monospace;font-size:12px;line-height:1.5;overflow:auto;max-height:420px;background:var(--panel2);padding:12px;border-radius:12px;border:1px solid var(--line)}.toolbar{display:flex;gap:10px;flex-wrap:wrap}.footer{color:var(--muted);font-size:13px;padding:20px 0}
@media (max-width:900px){.hero{grid-template-columns:1fr}}
"""


def b64(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    total = len(data)
    return round(-sum((c / total) * math.log2(c / total) for c in freq.values()), 4)


def extract_ascii_strings(data: bytes, min_len: int = 4) -> List[str]:
    return [m.decode(errors='ignore') for m in re.findall(rb'[ -~]{%d,}' % min_len, data)[:500]]


def extract_unicode_strings(data: bytes, min_len: int = 4) -> List[str]:
    pattern = rb'(?:[ -~]\x00){%d,}' % min_len
    out = []
    for m in re.findall(pattern, data)[:300]:
        try:
            out.append(m.decode('utf-16le', errors='ignore'))
        except Exception:
            pass
    return out


def detect_rich_header(data: bytes) -> bool:
    return b'Rich' in data[:0x400] and b'DanS' in data[:0x200]


def file_hashes(data: bytes) -> Dict[str, str | None]:
    return {
        'md5': hashlib.md5(data).hexdigest(),
        'sha1': hashlib.sha1(data).hexdigest(),
        'sha256': hashlib.sha256(data).hexdigest(),
        'sha512': hashlib.sha512(data).hexdigest(),
        'ssdeep': ssdeep.hash(data) if ssdeep else None,
        'tlsh': tlsh.hash(data) if tlsh and len(data) >= 50 else None,
    }


def filetime_to_dt(ts: int) -> str | None:
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except Exception:
        return None


def section_name(sec) -> str:
    return sec.Name.decode(errors='ignore').rstrip('\x00').strip().lower() or '<blank>'


def parse_security_flags(pe: pefile.PE) -> Dict[str, Any]:
    dll = pe.OPTIONAL_HEADER.DllCharacteristics
    return {
        'aslr_enabled': bool(dll & 0x0040),
        'dep_enabled': bool(dll & 0x0100),
        'cfg_enabled': bool(dll & 0x4000),
        'safe_seh': bool(dll & 0x0400),
        'dll_characteristics': hex(dll),
    }


def imported_items(pe: pefile.PE) -> Tuple[List[str], List[str], Dict[str, List[str]]]:
    dlls, funcs, tree = [], [], {}
    for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
        dll = entry.dll.decode(errors='ignore') if entry.dll else 'unknown'
        dlls.append(dll)
        tree[dll] = []
        for imp in entry.imports:
            name = imp.name.decode(errors='ignore') if imp.name else f'ord_{imp.ordinal}'
            funcs.append(name)
            tree[dll].append(name)
    return sorted(set(dlls)), funcs, tree


def delayed_imports(pe: pefile.PE) -> List[str]:
    out = []
    for entry in getattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT', []):
        if entry.dll:
            out.append(entry.dll.decode(errors='ignore'))
    return out


def exports_list(pe: pefile.PE) -> List[str]:
    out = []
    for sym in getattr(getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', []):
        name = sym.name.decode(errors='ignore') if sym.name else f'ord_{sym.ordinal}'
        out.append(name)
    return out[:500]


def resources_info(pe: pefile.PE) -> Dict[str, Any]:
    info = {'resource_count': 0, 'types': [], 'version_info': [], 'manifest_present': False, 'icons_present': False, 'resource_entropy': [], 'embedded_executables': False, 'embedded_archives': False}
    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        return info
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        name = str(entry.name) if entry.name else str(entry.struct.Id)
        info['types'].append(name)
        if name == '3' or 'ICON' in name.upper():
            info['icons_present'] = True
        if name == '24' or 'MANIFEST' in name.upper():
            info['manifest_present'] = True
    return info


def overlay_info(path: str, pe: pefile.PE) -> Dict[str, Any]:
    size = os.path.getsize(path)
    overlay_offset = pe.get_overlay_data_start_offset()
    if overlay_offset is None:
        return {'present': False, 'offset': None, 'size': 0, 'entropy': None}
    with open(path, 'rb') as f:
        f.seek(overlay_offset)
        data = f.read()
    return {'present': True, 'offset': overlay_offset, 'size': size - overlay_offset, 'entropy': shannon_entropy(data)}


def debug_info(pe: pefile.PE) -> Dict[str, Any]:
    out = {'debug_present': hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'), 'pdb_path': None}
    try:
        for dbg in getattr(pe, 'DIRECTORY_ENTRY_DEBUG', []):
            data = pe.get_data(dbg.struct.AddressOfRawData, dbg.struct.SizeOfData)
            if b'RSDS' in data:
                idx = data.find(b'RSDS')
                out['pdb_path'] = data[idx + 24:].split(b'\x00', 1)[0].decode(errors='ignore')
                break
    except Exception:
        pass
    return out


def hex_preview(data: bytes, length: int = 512) -> str:
    data = data[:length]
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hx = ' '.join(f'{b:02x}' for b in chunk)
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{i:08x}  {hx:<47}  {asc}')
    return '\n'.join(lines)


def strings_report(data: bytes) -> Dict[str, List[str]]:
    return {
        'ascii_strings': extract_ascii_strings(data)[:200],
        'unicode_strings': extract_unicode_strings(data)[:150],
        'urls': [m.decode(errors='ignore') for m in URL_RE.findall(data)[:50]],
        'ip_addresses': [m.decode(errors='ignore') for m in IP_RE.findall(data)[:50]],
        'domains': [m.decode(errors='ignore') for m in DOMAIN_RE.findall(data)[:50]],
        'emails': [m.decode(errors='ignore') for m in EMAIL_RE.findall(data)[:50]],
        'registry_paths': [m.decode(errors='ignore') for m in REG_RE.findall(data)[:50]],
        'file_paths': [m.decode(errors='ignore') for m in PATH_RE.findall(data)[:50]],
        'powershell_commands': [m.decode(errors='ignore') for m in PS_RE.findall(data)[:50]],
        'cmd_commands': [m.decode(errors='ignore') for m in CMD_RE.findall(data)[:50]],
    }


def architecture_name(pe: pefile.PE) -> str:
    return {0x14C: 'x86', 0x8664: 'x64', 0x1C0: 'ARM', 0xAA64: 'ARM64'}.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))


def subsystem_name(pe: pefile.PE) -> str:
    return {2: 'GUI', 3: 'Console', 9: 'Windows CE', 10: 'EFI Application'}.get(pe.OPTIONAL_HEADER.Subsystem, str(pe.OPTIONAL_HEADER.Subsystem))


def calc_risk(findings: List[Dict[str, str]]) -> int:
    score_map = {'critical': 20, 'high': 12, 'medium': 7, 'low': 3, 'info': 1}
    return min(100, sum(score_map.get(f['severity'], 1) for f in findings))


def analyze_file(path: str) -> Dict[str, Any]:
    with open(path, 'rb') as f:
        data = f.read()
    result: Dict[str, Any] = {'file_path': os.path.abspath(path), 'file_size': len(data), 'is_pe': False, 'findings': [], 'timeline': []}

    def add(sev: str, title: str, detail: str):
        result['findings'].append({'severity': sev, 'title': title, 'detail': detail})
        result['timeline'].append(f'{sev.upper()}: {title} - {detail}')

    result['hashes'] = file_hashes(data)
    result['strings'] = strings_report(data)
    result['hex_preview'] = hex_preview(data)
    result['rich_header_present'] = detect_rich_header(data)
    if result['rich_header_present']:
        add('info', 'Rich header detected', 'Rich header markers were found near the DOS stub.')

    try:
        pe = pefile.PE(path, fast_load=False)
        pe.parse_data_directories()
    except Exception as exc:
        add('critical', 'PE parse failed', str(exc))
        result['risk_score'] = calc_risk(result['findings'])
        result['verdict'] = 'Invalid or unsupported PE file'
        result['disclaimer'] = 'Static analysis only. Use only on files you are authorized to inspect.'
        return result

    result['is_pe'] = True
    sec_flags = parse_security_flags(pe)
    result['pe_header'] = {
        'compile_timestamp': filetime_to_dt(pe.FILE_HEADER.TimeDateStamp),
        'architecture': architecture_name(pe),
        'subsystem': subsystem_name(pe),
        'entry_point_rva': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
        'aslr_status': sec_flags['aslr_enabled'],
        'dep_status': sec_flags['dep_enabled'],
        'cfg_status': sec_flags['cfg_enabled'],
        'dll_characteristics': sec_flags['dll_characteristics'],
        'dos_header_magic': hex(pe.DOS_HEADER.e_magic),
    }
    result['security_features'] = sec_flags

    dlls, funcs, tree = imported_items(pe)
    delayed = delayed_imports(pe)
    result['imports'] = {'dlls': dlls, 'functions': funcs[:800], 'tree': tree, 'delayed_imports': delayed}
    result['exports'] = exports_list(pe)

    suspicious_hits = {k: sorted(v.intersection(set(funcs))) for k, v in SUSPICIOUS_APIS.items()}
    result['suspicious_apis'] = suspicious_hits
    for category, hits in suspicious_hits.items():
        if hits:
            sev = 'high' if category in {'process_injection', 'anti_debug'} else 'medium'
            add(sev, f'{category.replace("_", " ").title()} APIs detected', ', '.join(hits[:12]))

    sections = []
    hidden_data = False
    for sec in pe.sections:
        name = section_name(sec)
        raw = sec.get_data()
        entropy = shannon_entropy(raw)
        executable = bool(sec.Characteristics & 0x20000000)
        writable = bool(sec.Characteristics & 0x80000000)
        empty = sec.SizeOfRawData == 0 and sec.Misc_VirtualSize == 0
        hidden = sec.SizeOfRawData > sec.Misc_VirtualSize and sec.Misc_VirtualSize > 0
        align_ok = sec.PointerToRawData % max(1, pe.OPTIONAL_HEADER.FileAlignment) == 0
        sections.append({'name': name, 'entropy': entropy, 'raw_size': sec.SizeOfRawData, 'virtual_size': sec.Misc_VirtualSize, 'rwx': executable and writable, 'executable': executable, 'writable': writable, 'empty': empty, 'alignment_ok': align_ok, 'hidden_data': hidden})
        if name in SUSPICIOUS_SECTION_NAMES:
            add('high', 'Suspicious section name', name)
        if entropy >= 7.25 and sec.SizeOfRawData > 0:
            add('medium', 'High entropy section', f'{name} entropy={entropy}')
        if executable and writable:
            add('high', 'Executable and writable section', name)
        if hidden:
            hidden_data = True
            add('medium', 'Hidden data indicator', f'{name} raw_size exceeds virtual_size')
    result['sections'] = sections

    ov = overlay_info(path, pe)
    result['overlay'] = ov
    dbg = debug_info(pe)
    result['debug'] = dbg
    result['tls_callbacks_present'] = hasattr(pe, 'DIRECTORY_ENTRY_TLS')
    result['relocations_present'] = hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC')
    result['dotnet_detected'] = hasattr(pe, 'DIRECTORY_ENTRY_COM_DESCRIPTOR') or pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress != 0
    result['managed_type'] = 'Managed/.NET' if result['dotnet_detected'] else 'Native'
    cert_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    result['code_signing'] = {'present': cert_dir.VirtualAddress != 0 and cert_dir.Size > 0, 'size': cert_dir.Size}
    result['resources'] = resources_info(pe)
    result['malware_indicators'] = {'suspected_packers': [], 'obfuscation_indicators': hidden_data or ov['present'], 'shellcode_indicators': 'VirtualAlloc' in suspicious_hits['generic']}
    result['risk_score'] = calc_risk(result['findings'])
    result['verdict'] = 'High risk / likely packed or suspicious' if result['risk_score'] >= 75 else ('Moderate risk / suspicious indicators present' if result['risk_score'] >= 40 else 'Low risk / limited suspicious indicators')
    result['disclaimer'] = 'This is a defensive static-analysis helper. It does not prove malware, safety, authorship, or intent. Use only in a legal isolated lab.'
    return result


def entropy_chart(sections: List[Dict[str, Any]]) -> str:
    return ''.join([f"<div><div class='small'>{html.escape(s['name'])} - {s['entropy']}</div><div class='bar'><span style='width:{min(100, int((s['entropy'] / 8.0) * 100))}%'></span></div></div>" for s in sections[:30]]) or '<p class="small">No sections.</p>'


def import_graph(tree: Dict[str, List[str]]) -> str:
    out = ['<div class="tree"><ul>']
    for dll, funcs in list(tree.items())[:40]:
        out.append(f'<li><strong>{html.escape(dll)}</strong><ul>')
        for fn in funcs[:20]:
            out.append(f'<li>{html.escape(fn)}</li>')
        out.append('</ul></li>')
    out.append('</ul></div>')
    return ''.join(out)


def pe_tree(result: Dict[str, Any]) -> str:
    return f"<div class='tree'><ul><li>PE<ul><li>DOS Header</li><li>PE Header</li><li>Optional Header</li><li>Sections ({len(result.get('sections', []))})</li><li>Imports ({len(result.get('imports', {}).get('dlls', []))} DLLs)</li><li>Exports ({len(result.get('exports', []))})</li><li>Resources ({result.get('resources', {}).get('resource_count', 0)})</li><li>Overlay ({'present' if result.get('overlay', {}).get('present') else 'none'})</li></ul></li></ul></div>"


def findings_table(result: Dict[str, Any]) -> str:
    return ''.join([f"<tr><td>{html.escape(f['severity'])}</td><td>{html.escape(f['title'])}</td><td>{html.escape(f['detail'])}</td></tr>" for f in result.get('findings', [])]) or '<tr><td colspan="3">No findings</td></tr>'


def section_table(result: Dict[str, Any]) -> str:
    return ''.join([f"<tr><td>{html.escape(s['name'])}</td><td>{s['entropy']}</td><td>{s['raw_size']}</td><td>{s['virtual_size']}</td><td>{s['executable']}</td><td>{s['writable']}</td><td>{s['rwx']}</td><td>{s['empty']}</td><td>{s['alignment_ok']}</td><td>{s['hidden_data']}</td></tr>" for s in result.get('sections', [])])


def save_result(result: Dict[str, Any]) -> str:
    key = b64(result['hashes']['sha256'])
    LAST_RESULTS[key] = result
    return key


def render_page(title: str, body: str) -> str:
    nav = '<div class="nav"><a href="/">Home</a><a href="/analyze">Analyze</a><a href="/features">Features</a><a href="/cli">CLI</a><a href="/disclaimer">Disclaimer</a><button class="btn btn2" onclick="toggleTheme()">Theme</button></div>'
    script = "<script>function toggleTheme(){const d=document.documentElement;d.dataset.theme=d.dataset.theme==='light'?'dark':'light';}function copyText(t){navigator.clipboard.writeText(t);}document.addEventListener('dragover',e=>e.preventDefault());document.addEventListener('drop',e=>e.preventDefault());</script>"
    return f'<!doctype html><html data-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(title)}</title><style>{BASE_CSS}</style></head><body>{nav}<div class="wrap">{body}<div class="footer">Python-only defensive PE analyzer. Static analysis only.</div></div>{script}</body></html>'


@app.route('/')
def home():
    body = '<div class="hero"><div class="card"><h1>PackGuard Pro OneFile Fixed</h1><p>Single-file Python PE analyzer with CLI and local web app.</p><p><a class="btn" href="/analyze">Analyze sample</a> <a class="btn btn2" href="/features">View features</a></p></div><div class="card"><div class="disc"><strong>Defensive use only.</strong></div></div></div>'
    return render_page('PackGuard Pro OneFile Fixed', body)


@app.route('/features')
def features():
    return render_page('Features', '<div class="card"><h1>Features</h1><p>Headers, sections, imports, strings, hashes, graphs, tree view, and report exports.</p></div>')


@app.route('/cli')
def cli_page():
    return render_page('CLI', '<div class="card"><h1>CLI usage</h1><pre>python packguard_pro_onefile_fixed.py scan sample.exe\npython packguard_pro_onefile_fixed.py web</pre></div>')


@app.route('/disclaimer')
def disclaimer_page():
    return render_page('Disclaimer', '<div class="card disc"><h1>Disclaimer</h1><p>Static analysis only. Use only on files you are authorized to inspect.</p></div>')


@app.route('/analyze', methods=['GET', 'POST'])
def analyze_page():
    result_html = ''
    if request.method == 'POST':
        uploaded = request.files.get('sample')
        if uploaded and uploaded.filename:
            data = uploaded.read()
            if len(data) > MAX_SIZE:
                result_html = '<div class="card disc">File too large. Limit is 35 MB.</div>'
            else:
                with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(uploaded.filename)[1]) as tmp:
                    tmp.write(data)
                    tmp_path = tmp.name
                try:
                    result = analyze_file(tmp_path)
                finally:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
                key = save_result(result)
                hash_tags = ''.join([f"<div><strong>{k.upper()}:</strong> <code>{html.escape(str(v))}</code> <button class='btn btn2 copy' onclick='copyText({json.dumps(str(v))})'>Copy</button></div>" for k, v in result['hashes'].items()])
                string_view = ''.join([f"<details><summary>{name.replace('_',' ').title()} ({len(vals)})</summary><pre>{html.escape(chr(10).join(vals[:80]))}</pre></details>" for name, vals in result['strings'].items()])
                result_html = f"<div class='card'><h2>{html.escape(result['verdict'])}</h2><p>Risk score: {result['risk_score']}/100</p></div><div class='card'><h3>Downloads</h3><div class='toolbar'><a class='btn' href='/export/{key}/json'>JSON</a><a class='btn btn2' href='/export/{key}/csv'>CSV</a><a class='btn btn2' href='/export/{key}/html'>HTML</a><a class='btn btn2' href='/export/{key}/pdf'>PDF</a></div></div><div class='card'><h3>Hashes</h3>{hash_tags}</div><div class='card'><h3>Entropy</h3>{entropy_chart(result.get('sections', []))}</div><div class='card'><h3>Sections</h3><table><tr><th>Name</th><th>Entropy</th><th>Raw</th><th>Virtual</th><th>X</th><th>W</th><th>RWX</th><th>Empty</th><th>Aligned</th><th>Hidden</th></tr>{section_table(result)}</table></div><div class='card'><h3>Imports</h3>{import_graph(result.get('imports', {}).get('tree', {}))}</div><div class='card'><h3>PE Tree</h3>{pe_tree(result)}</div><div class='card'><h3>Findings</h3><table><tr><th>Severity</th><th>Title</th><th>Details</th></tr>{findings_table(result)}</table></div><div class='card'><h3>Strings</h3>{string_view}</div><div class='card'><h3>Hex Viewer</h3><div class='hex'>{html.escape(result.get('hex_preview', ''))}</div></div>"
    body = f'<div class="card"><h1>Analyze PE File</h1><form method="post" enctype="multipart/form-data"><div class="drop">Choose a file.<br><br><input type="file" name="sample" required></div><p style="margin-top:14px"><button class="btn" type="submit">Analyze now</button></p></form></div>{result_html}'
    return render_page('Analyze', body)


@app.route('/export/<key>/<fmt>')
def export_route(key: str, fmt: str):
    result = LAST_RESULTS.get(key)
    if not result:
        return Response('Report not found', status=404)
    if fmt == 'json':
        data, mimetype, name = json.dumps(result, indent=2).encode(), 'application/json', 'report.json'
    elif fmt == 'csv':
        buf = io.StringIO(); w = csv.writer(buf); w.writerow(['severity', 'title', 'detail']); [w.writerow([f['severity'], f['title'], f['detail']]) for f in result.get('findings', [])]; data, mimetype, name = buf.getvalue().encode(), 'text/csv', 'report.csv'
    elif fmt == 'html':
        data, mimetype, name = f"<!doctype html><html><body><pre>{html.escape(json.dumps(result, indent=2))}</pre></body></html>".encode(), 'text/html', 'report.html'
    else:
        data, mimetype, name = f"PackGuard Report\nVerdict: {result.get('verdict', 'N/A')}\nRisk Score: {result.get('risk_score', 0)}\n".encode(), 'application/pdf', 'report.pdf'
    return send_file(io.BytesIO(data), mimetype=mimetype, as_attachment=True, download_name=name)


def cli_scan(args):
    result = analyze_file(args.target)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Verdict: {result.get('verdict', 'N/A')}")
        print(f"Risk score: {result.get('risk_score', 0)}/100")
        print(f"SHA256: {result['hashes']['sha256']}")
        print('Findings:')
        for f in result.get('findings', []):
            print(f"- [{f['severity'].upper()}] {f['title']}: {f['detail']}")
    if args.html:
        with open(args.html, 'wb') as f:
            f.write(f"<!doctype html><html><body><pre>{html.escape(json.dumps(result, indent=2))}</pre></body></html>".encode())
    if args.csv:
        buf = io.StringIO(); w = csv.writer(buf); w.writerow(['severity', 'title', 'detail']); [w.writerow([f['severity'], f['title'], f['detail']]) for f in result.get('findings', [])]
        with open(args.csv, 'wb') as f:
            f.write(buf.getvalue().encode())
    if args.pdf:
        with open(args.pdf, 'wb') as f:
            f.write(f"PackGuard Report\nVerdict: {result.get('verdict', 'N/A')}\nRisk Score: {result.get('risk_score', 0)}\n".encode())


def main():
    parser = argparse.ArgumentParser(description='PackGuard Pro OneFile Fixed - Defensive PE Analyzer')
    sub = parser.add_subparsers(dest='mode', required=True)
    scan = sub.add_parser('scan', help='Scan a PE file')
    scan.add_argument('target')
    scan.add_argument('--json', action='store_true')
    scan.add_argument('--html')
    scan.add_argument('--csv')
    scan.add_argument('--pdf')
    web = sub.add_parser('web', help='Run web UI')
    web.add_argument('--host', default='127.0.0.1')
    web.add_argument('--port', type=int, default=5000)
    args = parser.parse_args()
    if args.mode == 'scan':
        cli_scan(args)
    elif args.mode == 'web':
        print(f"[*] Starting web UI on http://{args.host}:{args.port}")
        app.run(host=args.host, port=args.port, debug=False)


if __name__ == '__main__':
    main()