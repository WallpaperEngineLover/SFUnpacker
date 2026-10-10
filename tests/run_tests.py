#!/usr/bin/env python3
"""Builds synthetic Setup Factory installers and checks that sfunpacker extracts them.

usage: run_tests.py <path to sfunpacker binary>
"""
import lzma
import os
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path


def pstr(s):
    b = s.encode("latin-1") if isinstance(s, str) else s
    return bytes([len(b)]) + b


def utf16z(s):
    return s.encode("utf-16-le") + b"\0\0"


def pad4(b):
    return b + b"\0" * (-len(b) % 4)


def ver_block(key, value=b"", children=b"", text=False):
    head = utf16z(key)
    body = pad4(struct.pack("<HHH", 0, 0, 0) + head)
    vlen = len(value) // 2 if text else len(value)
    body += pad4(value)
    body += children
    return struct.pack("<HHH", len(body), vlen, 1 if text else 0) + body[6:]


def version_resource(major, minor, product):
    fixed = struct.pack("<13I", 0xFEEF04BD, 0x10000, (major << 16) | minor, 0, 0, 0, 0x3F, 0, 4, 1, 0, 0, 0)
    pname = ver_block("ProductName", utf16z(product), text=True)
    table = ver_block("040904b0", children=pad4(pname))
    sfi = ver_block("StringFileInfo", children=pad4(table))
    return ver_block("VS_VERSION_INFO", fixed, pad4(sfi))


def manifest(description, version):
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">\n'
        f'<assemblyIdentity version="{version}" processorArchitecture="x86" name="irsetup" type="win32"/>\n'
        f"<description>{description}</description>\n</assembly>"
    ).encode()


def build_pe(resources, overlay, with_debug=False):
    """resources: {type_id: bytes}; one name (id 1) and one language per type."""
    text_rva, rsrc_rva = 0x1000, 0x2000
    types = sorted(resources)

    root = struct.pack("<IIHHHH", 0, 0, 0, 0, 0, len(types))
    name_dirs, lang_dirs, entries = [], [], []
    root_size = 16 + 8 * len(types)
    pos = root_size
    layout = []
    for t in types:
        layout.append((t, pos, pos + 24, pos + 48, pos + 64))
        pos += 64
    data_pos = pos
    blob = b""
    root_bytes = root
    body = b""
    for t, name_off, lang_off, entry_off, _ in layout:
        root_bytes += struct.pack("<II", t, 0x80000000 | name_off)
    for (t, name_off, lang_off, entry_off, _), res in zip(layout, [resources[t] for t in types]):
        d = struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1) + struct.pack("<II", 1, 0x80000000 | lang_off)
        d += struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1) + struct.pack("<II", 0x409, entry_off)
        d += struct.pack("<IIII", rsrc_rva + data_pos + len(blob), len(res), 0, 0)
        body += d
        blob += pad4(res)
    rsrc = (root_bytes + body + blob)
    rsrc += b"\0" * (-len(rsrc) % 0x200)

    text = b"\xC3" + b"\0" * 0x1FF
    headers_size = 0x200
    raw_text, raw_rsrc = 0x200, 0x400

    dos = b"MZ" + b"\0" * 0x3A + struct.pack("<I", 0x40)
    coff = struct.pack("<HHIIIHH", 0x14C, 2, 0, 0, 0, 224, 0x103)
    opt = bytearray(224)
    struct.pack_into("<H", opt, 0, 0x10B)
    struct.pack_into("<I", opt, 28, 0x400000)
    struct.pack_into("<I", opt, 32, 0x1000)
    struct.pack_into("<I", opt, 36, 0x200)
    struct.pack_into("<I", opt, 56, 0x3000)
    struct.pack_into("<I", opt, 60, headers_size)
    struct.pack_into("<I", opt, 92, 16)
    struct.pack_into("<II", opt, 96 + 2 * 8, rsrc_rva, len(rsrc))

    def section(name, vsize, va, rsize, roff, flags):
        return name.ljust(8, b"\0") + struct.pack("<IIIIIIHHI", vsize, va, rsize, roff, 0, 0, 0, 0, flags)

    sections = section(b".text", 0x200, text_rva, 0x200, raw_text, 0x60000020)
    sections += section(b".rsrc", len(rsrc), rsrc_rva, len(rsrc), raw_rsrc, 0x40000040)

    head = dos + b"PE\0\0" + coff + bytes(opt) + sections
    head = head.ljust(headers_size, b"\0")
    return head + text + rsrc + overlay


def dcl_pack(data):
    bits = []
    for byte in data:
        bits.append(0)
        bits += [(byte >> i) & 1 for i in range(8)]
    bits.append(1)
    bits += [0] * 7
    bits += [1] * 8
    out = bytearray([0, 4])
    for i in range(0, len(bits), 8):
        chunk = bits[i:i + 8]
        out.append(sum(b << j for j, b in enumerate(chunk)))
    return bytes(out)


def lzma_pack(data):
    packed = bytearray(lzma.compress(data, format=lzma.FORMAT_ALONE, preset=6))
    packed[5:13] = struct.pack("<q", len(data))
    return bytes(packed)


def lzma2_pack(data):
    raw = lzma.compress(data, format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA2, "dict_size": 1 << 24}])
    return bytes([0x18]) + struct.pack("<q", len(data)) + raw


def build_script(entries, wide, after_attr, after_dir):
    out = b"junk-before-the-block" * 3
    out += struct.pack("<HHHH", len(entries), 0xFFFF, 1, len(b"CSetupFileData")) + b"CSetupFileData" + b"\0" * 5
    for e in entries:
        size = lambda v: struct.pack("<Q" if wide else "<I", v)
        out += pstr("C:\\src\\" + e["name"]) + pstr(e["name"]) + pstr("C:\\src") + pstr("") + pstr("Archive") + pstr("")
        out += b"\0\0" + size(len(e["data"])) + b"\x20" + b"\0" * after_attr
        out += pstr(e["dir"]) + b"\0" * after_dir
        out += pstr("") * 5 + b"\0" + pstr("") + b"\0" * 8 + pstr("") + b"\0\0\0"
        out += bytes([1 if e["compressed"] else 0]) + b"\x01\x20" + b"\0" * 10
        out += struct.pack("<H", 2) + b"\0" * 4
        out += pstr("") + b"\0\0" + pstr("") + pstr("")
        out += struct.pack("<H", 1) + pstr("Full")
        out += pstr("")
        out += size(len(e["packed"])) + struct.pack("<I", zlib.crc32(e["data"])) + b"\0" * 8
    return out


def content_entries(pack):
    files = [
        ("hello.txt", "Archive", b"hello world\n" * 50, True),
        ("data.bin", "Archive\\sub dir", os.urandom(3000), True),
        ("stored.bin", "", bytes(range(256)) * 4, False),
        ("caf\xe9.txt", "Archive", b"latin one\n", True),
        ("evil.txt", "..\\..\\outside", b"must not be written\n", True),
    ]
    out = []
    for name, d, data, compressed in files:
        out.append({"name": name, "dir": d, "data": data, "compressed": compressed,
                    "packed": pack(data) if compressed else data})
    return out


IRSETUP = bytes(range(256)) * 10


def xor_head(data):
    return bytes(b ^ 7 for b in data[:2000]) + data[2000:]


def sf8_overlay(pack, entries, after_dir=10, lua=False):
    script = build_script(entries, True, 61, after_dir)
    services = [("irsetup.dat", script)]
    out = bytes([0xE0, 0xE0, 0xE1, 0xE1, 0xE2, 0xE2, 0xE3, 0xE3, 0xE4, 0xE4, 0xE5, 0xE5, 0xE6, 0xE6, 0xE7, 0xE7])
    out += b"\0" * 10 + struct.pack("<Q", len(IRSETUP)) + xor_head(IRSETUP)
    if lua:
        out += struct.pack("<Q", 5000) + os.urandom(5000)
    out += struct.pack("<I", len(services))
    for name, data in services:
        p = pack(data)
        out += name.encode().ljust(264, b"\0") + struct.pack("<QI", len(p), zlib.crc32(data)) + b"\0" * 4 + p
    for e in entries:
        out += e["packed"]
    return out, {"irsetup.exe": IRSETUP, "irsetup.dat": script}


def sf7_overlay(entries):
    script = build_script(entries, False, 37, 10)
    out = bytes([0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7])
    out += b"\0" + struct.pack("<I", len(IRSETUP)) + xor_head(IRSETUP)
    p = dcl_pack(script)
    out += struct.pack("<I", 1)
    out += b"irsetup.dat".ljust(260, b"\0") + struct.pack("<II", len(p), zlib.crc32(script)) + p
    for e in entries:
        out += e["packed"]
    return out, {"irsetup.exe": IRSETUP, "irsetup.dat": script}


def expected_files(entries, service):
    files = dict(service)
    for e in entries:
        if ".." in e["dir"]:
            continue
        d = e["dir"].replace("..\\", "").strip("\\")
        rel = "/".join(p for p in (d.replace("\\", "/"), e["name"]) if p)
        files[rel] = e["data"]
    return files


def cases():
    pe_res9 = lambda minor: {24: manifest("Setup Factory 9 Run-time", f"9.{minor}.0.0")}
    e = content_entries(lzma_pack)
    ov, svc = sf8_overlay(lzma_pack, e)
    yield "sf9-lzma", build_pe(pe_res9(1), ov), "Setup Factory 9.1", "LZMA", expected_files(e, svc)

    e = content_entries(lzma_pack)
    ov, svc = sf8_overlay(lzma_pack, e, after_dir=11, lua=True)
    yield "sf9.5-lzma-newlayout-lua", build_pe({24: manifest("Setup Factory Run-time", "9.5.0.0")}, ov), "Setup Factory 9.5", "LZMA", expected_files(e, svc)

    e = content_entries(lzma2_pack)
    ov, svc = sf8_overlay(lzma2_pack, e)
    yield "sf9-lzma2", build_pe(pe_res9(0), ov), "Setup Factory 9.0", "LZMA2", expected_files(e, svc)

    e = content_entries(lzma_pack)
    ov, svc = sf8_overlay(lzma_pack, e)
    res = {24: manifest("Setup", "1.0.0.0"), 16: version_resource(9, 2, "Setup Factory Runtime")}
    yield "sf9-bogus-manifest", build_pe(res, ov), "Setup Factory 9.2", "LZMA", expected_files(e, svc)

    e = content_entries(lzma_pack)
    ov, svc = sf8_overlay(lzma_pack, e)
    yield "sf8", build_pe({24: manifest("Setup Factory 8.0 Run-time", "8.0.0.0")}, ov), "Setup Factory 8.0", "LZMA", expected_files(e, svc)

    e = content_entries(dcl_pack)
    ov, svc = sf7_overlay(e)
    yield "sf7", build_pe({24: manifest("Setup Factory 7", "7.0.0.0")}, ov), "Setup Factory 7", "PKWare DCL", expected_files(e, svc)


def run(binary, workdir, name, image, version, comp, expected):
    exe = workdir / f"{name}.exe"
    exe.write_bytes(image)
    out = workdir / f"{name}-out"
    proc = subprocess.run([binary, str(exe), str(out)], capture_output=True, text=True)
    problems = []
    if proc.returncode != 1 or "Skipping unsafe path: ..\\..\\outside\\evil.txt" not in proc.stderr:
        problems.append(f"expected only the traversal entry to fail, got {proc.returncode}: {proc.stderr.strip()}")
    if version not in proc.stdout:
        problems.append(f"version line missing ({version})")
    if f"Compression: {comp}" not in proc.stdout:
        problems.append(f"compression line missing ({comp})")
    for rel, data in expected.items():
        target = out / rel.replace("\xe9", "\u00e9")
        if not target.is_file():
            problems.append(f"missing {rel}")
        elif target.read_bytes() != data:
            problems.append(f"content differs {rel}")
    if any(p.name == "evil.txt" for p in workdir.rglob("*")) or (workdir.parent / "outside").exists():
        problems.append("path escaped the output directory")
    return problems


def main():
    binary = os.path.abspath(sys.argv[1])
    failed = 0
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        for case in cases():
            problems = run(binary, workdir, *case)
            print(("FAIL " if problems else "ok   ") + case[0])
            for p in problems:
                print("       " + p)
            failed += bool(problems)

        junk = workdir / "junk.exe"
        junk.write_bytes(build_pe({24: manifest("Setup Factory 9 Run-time", "9.1.0.0")}, b"not an installer" * 10))
        proc = subprocess.run([binary, str(junk), str(workdir / "junk-out")], capture_output=True, text=True)
        ok = proc.returncode != 0 and "Cannot read installer" in proc.stderr
        print(("ok   " if ok else "FAIL ") + "rejects non-installer overlay")
        failed += not ok

        (workdir / "text.exe").write_text("definitely not a PE")
        proc = subprocess.run([binary, str(workdir / "text.exe")], capture_output=True, text=True, cwd=workdir)
        ok = proc.returncode != 0 and "not a PE file" in proc.stderr
        print(("ok   " if ok else "FAIL ") + "rejects non-PE input")
        failed += not ok
    sys.exit(1 if failed else 0)


main()
