"""Rewrite a binary's IPE node to the zstd-compressed form GHC emits when it is
built with zstd (HAVE_LIBZSTD=1).  The frames are smaller than the blobs they
replace, so they go in at the same addresses; the trailing bytes are ignorable
because a frame's length is read from its own header."""
import struct, subprocess, sys, os, shutil, tempfile

src, dst = sys.argv[1], sys.argv[2]
shutil.copyfile(src, dst)
b = bytearray(open(dst, "rb").read())

# --- section headers, for VA -> file offset
e_shoff, = struct.unpack_from("<Q", b, 0x28)
e_shentsize, e_shnum = struct.unpack_from("<HH", b, 0x3A)
secs = []
for i in range(e_shnum):
    o = e_shoff + i * e_shentsize
    sh_type, = struct.unpack_from("<I", b, o + 4)
    addr, off, size = struct.unpack_from("<QQQ", b, o + 16)
    if addr and sh_type != 8:  # not SHT_NOBITS
        secs.append((addr, off, size))
def off_of(va, n=1):
    for addr, off, size in secs:
        if addr <= va and va + n <= addr + size:
            return off + (va - addr)
    raise SystemExit(f"VA {va:#x} (+{n}) not in any section")

# --- the _ipe_buf node
nm = subprocess.run(["nm", src], capture_output=True, text=True).stdout
addrs = [int(l.split()[0], 16) for l in nm.splitlines()
         if len(l.split()) == 3 and l.split()[2].endswith("_ipe_buf")]
if not addrs:
    raise SystemExit("no _ipe_buf symbol")
print(f"{len(addrs)} IPE node(s)")

def zstd(blob):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "x")
        open(p, "wb").write(blob)
        subprocess.run(["zstd", "-19", "-q", "-f", p, "-o", p + ".z"], check=True)
        return open(p + ".z", "rb").read()

patched = 0
for na in addrs:
    no = off_of(na, 64)
    f = list(struct.unpack_from("<8Q", b, no))
    comp, count, tables, entries, esize, strtab, ssize = f[1], f[2], f[3], f[4], f[5], f[6], f[7]
    if comp:
        print(f"  {na:#x}: already compressed"); continue
    print(f"  {na:#x}: count={count} esize={esize} ssize={ssize}")
    eo, so = off_of(entries, esize), off_of(strtab, ssize)
    ez, sz = zstd(bytes(b[eo:eo + esize])), zstd(bytes(b[so:so + ssize]))
    print(f"     entries {esize} -> {len(ez)}   strings {ssize} -> {len(sz)}")
    if len(ez) > esize or len(sz) > ssize:
        raise SystemExit("a frame is larger than the blob it replaces; cannot patch in place")
    b[eo:eo + len(ez)] = ez
    b[so:so + len(sz)] = sz
    struct.pack_into("<Q", b, no + 8, 1)      # compressed = 1
    patched += 1

open(dst, "wb").write(bytes(b))
print(f"wrote {dst}: {patched} node(s) now compressed (sizes left as DEcompressed, per the RTS contract)")
