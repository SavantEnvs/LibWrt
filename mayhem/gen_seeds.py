#!/usr/bin/env python3
"""Generate the committed seed corpora under mayhem/<target>/testsuite/ (and the functional-test
fixtures under mayhem/testdata/). Run from the repo root: python3 mayhem/gen_seeds.py
The outputs are committed; build.sh/test.sh never run this. (The Kconfig fixture
mayhem/testdata/Kconfig and its expected .config are hand-written.)"""
import hashlib, os, struct, zlib

def w(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)

def pad4(b):
    return b + b"\0" * (-len(b) % 4)

# ---------------- ead: framed raw Ethernet/IP/UDP packets ------------------------------------
EAD_MAGIC, EAD_PORT = 3671771902, 56026
def ead_pkt(mtype, payload, sid=0, nid=0xffff):
    eh = b"\xff" * 6 + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
    ip = bytes([0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0]) + bytes([192, 168, 1, 2]) + bytes([255] * 4)
    udp = struct.pack(">HHHH", 40000, EAD_PORT, 0, 0)
    msg = struct.pack(">IIIHHI", EAD_MAGIC, len(payload), mtype, nid, sid, 0) + payload
    return eh + ip + udp + msg
def frames(*pkts):
    return b"".join(struct.pack(">H", len(p)) + p for p in pkts)
user = ead_pkt(2, b"root".ljust(32, b"\0"))
prime = ead_pkt(4, b"")
send_a = ead_pkt(6, b"\x00" + bytes(range(1, 129)))
auth = ead_pkt(8, bytes(20))
w("mayhem/ead-handle-packet/testsuite/ping", frames(ead_pkt(0, b"")))
nobody = ead_pkt(2, b"nobody".ljust(32, b"\0"))
w("mayhem/ead-handle-packet/testsuite/login_nobody", frames(nobody, prime, send_a, auth))
w("mayhem/ead-handle-packet/testsuite/ping_user", frames(ead_pkt(0, b""), nobody, ead_pkt(0, b"", sid=0x1000)))

# ---------------- fritz_tffs_read: NOR TFFS dump ---------------------------------------------
def tffs_nor(entries):
    out = b""
    for eid, val in entries:
        out += struct.pack("<HH", eid, len(val)) + pad4(val)
    return out + struct.pack("<HH", 0xffff, 0xffff)
names = struct.pack("<I", 0x100) + pad4(b"macaddr\0") + struct.pack("<I", 0x101) + pad4(b"serial\0")
nor = tffs_nor([(0x1ff, names), (0x100, b"00:11:22:33:44:55"), (0x101, b"ABCD")])
w("mayhem/fritz-tffs-read/testsuite/nor.tffs", nor)
w("mayhem/testdata/nor.tffs", nor)

# ---------------- fritz_tffs_nand_read: NAND TFFS (data sectors + OOB tail; see mtd_file_shim.c)
SECTOR, OOB = 0x800, 0x40
def nand_entry(eid, val, rev=1, seg=0, nxt=0):
    s = struct.pack("<IIIIII", eid, len(val), 0, rev, seg, nxt) + val
    return s.ljust(SECTOR, b"\xff"), (eid, len(val), rev)
def nand_hdr():
    s = struct.pack("<QII", 0x41564d5f54464653, 3, 2) + bytes(12) + struct.pack("<QQ", 0, 0)
    return s.ljust(SECTOR, b"\xff"), None
def nand_image(sectors):
    data, oob = b"", b""
    for s, meta in sectors:
        data += s
        o = b"\xff\xff"
        if meta:
            o += struct.pack("<III", *meta)
        oob += o.ljust(OOB, b"\xff")
    return data + oob
nand = nand_image([nand_hdr(), nand_entry(0x1ff, names), nand_entry(0x100, b"00:11:22:33:44:55"),
                   nand_entry(0x101, b"ABCD")])
w("mayhem/fritz-tffs-nand-read/testsuite/nand.tffs", nand)
w("mayhem/testdata/nand.tffs", nand)
# a value split across two segments (find_entry's segment array path)
nand2 = nand_image([nand_hdr(), nand_entry(0x1ff, names), nand_entry(0x100, b"00:11:22:", seg=0, nxt=1),
                    nand_entry(0x100, b"33:44:55", seg=1, nxt=0),
                    nand_hdr(), nand_entry(0x101, b"ABCD"), (b"\xff" * SECTOR, None), (b"\xff" * SECTOR, None)])
w("mayhem/fritz-tffs-nand-read/testsuite/nand_segments.tffs", nand2)

# ---------------- fritz_cal_extract: calibration table (big-endian id/len + zlib) --------------
cal_payload = zlib.compress(bytes(range(256)) * 4)
cal = struct.pack(">HH", 0x0001, 4) + b"\xde\xad\xbe\xef" + struct.pack(">HH", 0x0207, len(cal_payload)) \
    + cal_payload + struct.pack(">HH", 0xffff, 0)
w("mayhem/fritz-cal-extract/testsuite/cal.bin", cal)

# ---------------- osafeloader: TP-Link SafeLoader -----------------------------------------------
salt = bytes([0x7a, 0x2b, 0x15, 0xed, 0x9b, 0x98, 0x59, 0x6d, 0xe5, 0x04, 0xab, 0x44, 0xac, 0x2a, 0x9f, 0x4e])
def safeloader(body, table):
    img = struct.pack(">I", len(body)) + hashlib.md5(salt + body).digest() + body
    img = img.ljust(0x1014, b"\0") + table
    return img
table = b"fwup-ptn partition-table base 0x00800 size 0x00800\t\r\n" \
        b"fwup-ptn os-image base 0x01000 size 0x113b45\t\r\n" \
        b"fwup-ptn file-system base 0x114b45 size 0x1d0004\t\r\n\0"
sl = safeloader(b"", table)   # imagesize 0: MD5 covers only the salt, the table stays mutable
w("mayhem/osafeloader-info/testsuite/safeloader.bin", sl)
w("mayhem/testdata/safeloader.bin", sl)
w("mayhem/osafeloader-info/testsuite/safeloader_body.bin", safeloader(b"\x11" * 64, table))

# ---------------- jboot_config_read: STAG + CSXF + data headers ---------------------------------
def jsum(data, start=0):
    if len(data) % 2:
        raise ValueError
    c = start
    for (v,) in struct.iter_unpack("<H", data):
        c += v
        while c >> 16:
            c = (c & 0xffff) + (c >> 16)
    return c & 0xffff
def jboot():
    body = struct.pack("<BBHH", 0x30, 0x42, 0x8000, 6) + b"\x00\x11\x22\x33\x44\x55"
    body += struct.pack("<BBHH", 0x00, 0xF5, 0x8000, 0x201) + bytes(range(256)) * 2
    csxf = struct.pack("<HHIB3sI", 0x5343, 0, len(body), 0, b"\0\0\0", len(body))
    csum = (~jsum(csxf + body)) & 0xffff
    csxf = struct.pack("<HHIB3sI", 0x5343, csum, len(body), 0, b"\0\0\0", len(body))
    stag = struct.pack("<BBHIIH", 2, 2, 0x2B24, 0, len(csxf) + len(body), 0)
    stag += struct.pack("<H", (~jsum(stag)) & 0xffff)
    return stag + csxf + body
w("mayhem/jboot-config-read/testsuite/jboot.bin", jboot())

# ---------------- bcm4908img: parts for `bcm4908img create` --------------------------------------
def dirent(name, ino, pino=1):
    n = name.encode()
    hdr = struct.pack("<HHIIIIIIBB2sII", 0x1985, 0xE001, 40 + len(n), 0, pino, 1, ino, 0, len(n), 8,
                      b"\0\0", 0, 0)
    return pad4(hdr + n)
bootfs = dirent("cferam.000", 2) + dirent("vmlinux.lz", 3) + dirent("94908.dtb", 4)
def bcm_image(bootfs, rootfs):
    data = bootfs.ljust(0x20000, b"\0") + rootfs
    crc = zlib.crc32(data) ^ 0xffffffff          # bcm4908img_crc32: init ~0, no final xor
    return data + struct.pack("<IIIII", crc, 0x5732, 0x4908, 3, 0)
bcm = bcm_image(bootfs, b"UBI#" + bytes(0x7fc))
w("mayhem/bcm4908img-info/testsuite/image.bin", bcm)
w("mayhem/bcm4908img-bootfs-ls/testsuite/image.bin", bcm)
w("mayhem/testdata/bcm4908.bin", bcm)

# vendor variants: CHK (Netgear) header in front -> cferom_offset != 0, plus a CFE ROM block before
# bootfs (the bootfs search loop iterates); and a .LINKSYS. tail after the BCM4908 tail.
def chk_header(hlen):
    return struct.pack(">II", 0x2a23245e, hlen).ljust(hlen, b"\0")
def bcm_image_at(prefix, cferom, bootfs, rootfs, suffix=b""):
    data = cferom + bootfs.ljust(0x20000, b"\0") + rootfs
    crc = zlib.crc32(data) ^ 0xffffffff
    return prefix + data + struct.pack("<IIIII", crc, 0x5732, 0x4908, 3, 0) + suffix
linksys = b".LINKSYS." + b"1.0.0\0\0\0" + b"EA6750\0".ljust(15, b"\0") + bytes(4) + bytes(9) + bytes(16) + bytes(3)   # sizeof(struct linksys_tail) = 64 (padded)
ff_rootfs = b"\xff" * 0x20000 + b"UBI#" + bytes(0x7fc)   # padding block, then UBI
variants = {
    "image_chk.bin": bcm_image_at(chk_header(0x40), b"", bootfs, b"UBI#" + bytes(0x7fc)),
    "image_cferom.bin": bcm_image_at(b"", b"CFE1" + bytes(0x20000 - 4), bootfs, ff_rootfs),
    "image_linksys.bin": bcm_image_at(b"", b"", bootfs, b"UBI#" + bytes(0x7fc), linksys),
}
for n, d in variants.items():
    w("mayhem/bcm4908img-info/testsuite/" + n, d)
    w("mayhem/bcm4908img-bootfs-ls/testsuite/" + n, d)
# bootfs ls: a non-dirent JFFS2 node (inode, skipped by `ls`) between dirents, and a long name
def jnode(ntype, body):
    return pad4(struct.pack("<HHII", 0x1985, ntype, 12 + len(body), 0) + body)
mixed = dirent("cferam.000", 2) + jnode(0xE002, bytes(56)) + dirent("x" * 200, 3) + jnode(0x2003, b"") \
        + dirent("94908.dtb", 4)
w("mayhem/bcm4908img-bootfs-ls/testsuite/image_nodes.bin", bcm_image(mixed, b"UBI#" + bytes(0x7fc)))
# bcm4908img-parse (in-process, recomputes the image CRC): the same images as bootfs-ls
w("mayhem/bcm4908img-parse/testsuite/image.bin", bcm)
for n, d in variants.items():
    w("mayhem/bcm4908img-parse/testsuite/" + n, d)
w("mayhem/bcm4908img-parse/testsuite/image_nodes.bin", bcm_image(mixed, b"UBI#" + bytes(0x7fc)))

# osafeloader extract: partitions inside the file (base is relative to the table at 0x1014)
xtable = b"fwup-ptn partition-table base 0x00000 size 0x00080\t\r\n" \
         b"fwup-ptn os-image base 0x00080 size 0x00040\t\r\n" \
         b"fwup-ptn file-system base 0x000c0 size 0x00040\t\r\n\0"
xs = safeloader(b"\x22" * 32, xtable).ljust(0x1014 + 0x100, b"\x5a")
w("mayhem/osafeloader-extract/testsuite/safeloader_fit.bin", xs)
w("mayhem/osafeloader-extract/testsuite/safeloader.bin", sl)

# fritz_cal_extract: entry absent (walks to the 0xffff end marker) and a corrupt zlib stream (zerr)
w("mayhem/fritz-cal-extract/testsuite/cal_nomatch.bin",
  struct.pack(">HH", 0x0001, 4) + b"\xde\xad\xbe\xef" + struct.pack(">HH", 0xffff, 0))
bad = bytearray(cal_payload); bad[8] ^= 0xff
w("mayhem/fritz-cal-extract/testsuite/cal_badzlib.bin",
  struct.pack(">HH", 0x0207, len(bad)) + bytes(bad) + struct.pack(">HH", 0xffff, 0))

# ---------------- nvram: Broadcom NVRAM partition ("FLSH" header + name=value\0...\0\0) ----------
def nvram(pairs, prefix=b""):
    body = b"".join(k + b"=" + v + b"\0" for k, v in pairs) + b"\0"
    body = pad4(body)
    hdr = struct.pack("<IIIII", 0x48534C46, 20 + len(body), (0x0419 << 16) | (1 << 8), 0x8040 | (0x0000 << 16), 0)
    return prefix + hdr + body
nv = nvram([(b"lan_ipaddr", b"192.168.1.1"), (b"boardtype", b"0x0472"), (b"et0macaddr", b"00:11:22:33:44:55")])
w("mayhem/nvram-open/testsuite/nvram.bin", nv)
w("mayhem/nvram-open/testsuite/nvram_offset.bin", nvram([(b"wl0_ssid", b"OpenWrt"), (b"sdram_init", b"0x000b")], b"\xff" * 0x400))
w("mayhem/testdata/nvram.bin", nv.ljust(0x10000, b"\0"))   # a whole 64 KiB partition (= mmap length)
