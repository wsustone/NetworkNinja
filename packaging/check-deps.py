#!/usr/bin/env python3
"""Check that packaged binaries need nothing the operating system doesn't ship.

    python3 packaging/check-deps.py DIR

Reads every nn-* executable in DIR (ELF, Mach-O, including universal, or PE)
and prints what it loads at run time. It fails if a binary needs:

- Linux: a dynamic loader or any shared library (the build is static musl);
- macOS: a library outside /usr/lib and /System/Library (e.g. Homebrew's);
- Windows: a DLL that isn't part of Windows, such as VCRUNTIME140.dll from the
  Visual C++ Redistributable.

The release workflow runs it on each archive before upload.
"""

import os
import struct
import sys

# DLLs every supported Windows (10 and later) ships. A new one fails the check
# until it is confirmed and added here.
WINDOWS_SYSTEM = {
    "advapi32.dll", "bcrypt.dll", "bcryptprimitives.dll", "crypt32.dll",
    "iphlpapi.dll", "kernel32.dll", "ntdll.dll", "ole32.dll", "oleaut32.dll",
    "secur32.dll", "shell32.dll", "user32.dll", "userenv.dll", "ws2_32.dll",
}


def windows_ok(dll):
    d = dll.lower()
    # API sets for the Windows core are part of the OS; the CRT ones
    # (api-ms-win-crt-*) mean the C runtime isn't static.
    return d in WINDOWS_SYSTEM or (d.startswith("api-ms-win-core-") and d.endswith(".dll"))


def windows_problem(dll):
    if dll.startswith("api-ms-win-crt-"):
        return f"needs {dll}: the Universal C Runtime is dynamic (link it statically: +crt-static)"
    if dll.startswith(("vcruntime", "msvcp")):
        return f"needs {dll}, from the Visual C++ Redistributable, which Windows doesn't include"
    return f"needs {dll}, which isn't on the list of Windows system DLLs"


def cstr(b, o):
    return b[o:b.index(b"\0", o)].decode()


def elf(b):
    phoff, = struct.unpack_from("<Q", b, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", b, 0x36)
    interp, dyn, loads = None, None, []
    for i in range(phnum):
        t, _, off, va, _, fs, _, _ = struct.unpack_from("<IIQQQQQQ", b, phoff + i * phentsize)
        if t == 3:
            interp = b[off:off + fs].rstrip(b"\0").decode()
        elif t == 2:
            dyn = (off, fs)
        elif t == 1:
            loads.append((va, off, fs))
    needed = []
    if dyn:
        ents = [struct.unpack_from("<qQ", b, dyn[0] + 16 * k) for k in range(dyn[1] // 16)]
        strtab = [v for t, v in ents if t == 5]
        if strtab:
            so = next(strtab[0] - va + off for va, off, fs in loads if va <= strtab[0] < va + fs)
            needed = [cstr(b, so + v) for t, v in ents if t == 1]
    deps = ([f"loader {interp}"] if interp else []) + needed
    return "Linux", deps, [f"needs {d}" for d in deps]


def macho_slice(b, base):
    magic, cpu = struct.unpack_from("<II", b, base)
    assert magic == 0xFEEDFACF, "not a 64-bit Mach-O slice"
    arch = {0x01000007: "x86_64", 0x0100000C: "arm64"}.get(cpu, hex(cpu))
    ncmds, = struct.unpack_from("<I", b, base + 16)
    o, libs, minos = base + 32, [], None
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", b, o)
        if cmd in (0xC, 0x80000018, 0x8000001F, 0x80000023):  # LOAD, WEAK, REEXPORT, LAZY
            name_off, = struct.unpack_from("<I", b, o + 8)
            libs.append(cstr(b, o + name_off))
        elif cmd == 0x32:  # LC_BUILD_VERSION: platform, minos
            v, = struct.unpack_from("<I", b, o + 12)
            minos = f"{v >> 16}.{(v >> 8) & 0xFF}"
        elif cmd == 0x24:  # LC_VERSION_MIN_MACOSX
            v, = struct.unpack_from("<I", b, o + 8)
            minos = f"{v >> 16}.{(v >> 8) & 0xFF}"
        o += size
    return arch, minos, libs


def macho(b):
    magic, = struct.unpack_from(">I", b, 0)
    if magic == 0xCAFEBABE:
        n, = struct.unpack_from(">I", b, 4)
        slices = [struct.unpack_from(">IIIII", b, 8 + 20 * i)[2] for i in range(n)]
    else:
        slices = [0]
    deps, problems = [], []
    for off in slices:
        arch, minos, libs = macho_slice(b, off)
        deps.append(f"{arch}: macOS {minos}+, " + ", ".join(libs))
        problems += [f"{arch} needs {l}" for l in libs if not l.startswith(("/usr/lib/", "/System/Library/"))]
    return "macOS", deps, problems


def pe(b):
    pe_at, = struct.unpack_from("<I", b, 0x3C)
    nsec, = struct.unpack_from("<H", b, pe_at + 6)
    optsz, = struct.unpack_from("<H", b, pe_at + 20)
    opt = pe_at + 24
    dd = opt + 112
    secs = [struct.unpack_from("<8sIIII", b, opt + optsz + 40 * i) for i in range(nsec)]

    def r2o(rva):
        for _, vs, va, rs, ro in secs:
            if va <= rva < va + max(vs, rs):
                return rva - va + ro

    dlls = []
    for index, size, name_at in ((1, 20, 3), (13, 32, 1)):  # imports, delay-load imports
        rva, _ = struct.unpack_from("<II", b, dd + 8 * index)
        o = r2o(rva) if rva else None
        while o is not None:
            ent = struct.unpack_from("<%dI" % (size // 4), b, o)
            if not any(ent):
                break
            dlls.append(cstr(b, r2o(ent[name_at])))
            o += size
    dlls = sorted({d.lower() for d in dlls})
    return "Windows", dlls, [windows_problem(d) for d in dlls if not windows_ok(d)]


def check(path):
    b = open(path, "rb").read()
    if b[:4] == b"\x7fELF":
        return elf(b)
    if b[:4] in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return macho(b)
    if b[:2] == b"MZ":
        return pe(b)
    raise SystemExit(f"{path}: not an executable this script reads")


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    folder = sys.argv[1]
    names = sorted(n for n in os.listdir(folder) if n.startswith("nn-") and os.path.isfile(os.path.join(folder, n)))
    if not names:
        raise SystemExit(f"no nn-* executables in {folder}")
    failed = False
    for name in names:
        platform, deps, problems = check(os.path.join(folder, name))
        print(f"{name} ({platform}): " + ("; ".join(deps) if deps else "self-contained, no shared libraries"))
        for p in problems:
            print(f"  PROBLEM ({platform}): {p}")
            failed = True
    if failed:
        raise SystemExit("some binaries need libraries the operating system doesn't ship")


if __name__ == "__main__":
    main()
