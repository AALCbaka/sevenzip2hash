# -*- coding: utf-8 -*-
"""sevenzip2hash.py — extract hashcat-compatible $7z$ hashes from 7z archives.

Pure Python standard library, no third-party packages.

The container parsing follows the published 7z format; the output format follows the
parser conventions of hashcat's src/modules/module_11600.c (hashcat is MIT licensed).

Output hash format (11 fields, separated by '$'):
    $7z$<data_type>$<numCyclesPower>$<salt_len>$<salt>$<iv_len>$<iv_hex32>
        $<crc32>$<data_len>$<unpack_size>$<data_hex>
        [ $<crc_len>$<coder_attributes_hex> ]

    data_type  0=uncompressed (CRC checked directly) 1=LZMA1 2=LZMA2 7=DEFLATE 8=ZSTD
    iv_hex32   IV occupies exactly 32 hex characters (16 bytes, original byte order,
               zero padded)

Two kinds of target are handled:
  A. Encrypted header (7-Zip's "encrypt file names", Bandizip's default)
     The header is AES encrypted and the data stream's AES parameters are inside the
     ciphertext, so the header stream is attacked instead (AES + LZMA). Recovering the
     header still recovers the password.
  B. Plain header (only the data is encrypted)
     The header is readable (decoded with LZMA when compressed) and the AES parameters
     are taken from the data stream.

Limitations (imposed by hashcat's module_11600.c, not by this module):
  * salt_len must be 0. module_hash_decode() contains `if (salt_len != 0) return
    PARSER_SALT_VALUE;`, so archives that use a salt cannot be attacked at all.
  * numCyclesPower must be <= 31 (salt_iter is a u32).
  * Only data_type 0 / 1 / 2 / 7 / 8 are accepted.
  * unpack_size must be <= data_len.

Speed: 7z runs 2^numCyclesPower rounds of SHA-256 per candidate, measured at roughly
15,000 H/s on an RTX 5070. That is about six orders of magnitude slower than ZIP, so
brute force is only realistic for short passwords.
"""
import lzma
import os

MODE_7Z = 11600

SEVEN_ZIP_MAGIC = b"7z\xbc\xaf\x27\x1c"

# ---- 头部 property id ----
K_END = 0x00
K_HEADER = 0x01
K_ARCHIVE_PROPS = 0x02
K_ADD_STREAMS_INFO = 0x03
K_MAIN_STREAMS_INFO = 0x04
K_FILES_INFO = 0x05
K_PACK_INFO = 0x06
K_UNPACK_INFO = 0x07
K_SUBSTREAMS_INFO = 0x08
K_SIZE = 0x09
K_CRC = 0x0A
K_FOLDER = 0x0B
K_UNPACK_SIZE = 0x0C
K_NUM_UNPACK_STREAM = 0x0D
K_EMPTY_STREAM = 0x0E
K_EMPTY_FILE = 0x0F
K_ANTI_FILE = 0x10
K_NAME = 0x11
K_ENCODED_HEADER = 0x17
K_START_POS = 0x18
K_DUMMY = 0x19

# ---- coder id ----
ID_AES = b"\x06\xf1\x07\x01"
ID_LZMA1 = b"\x03\x01\x01"
ID_LZMA2 = b"\x21"
ID_COPY = b"\x00"
ID_DEFLATE = b"\x04\x01\x08"
ID_BCJ = b"\x03\x03\x01\x03"
ID_DELTA = b"\x03"

# data_type 取值
DT_UNCOMPRESSED = 0
DT_LZMA1 = 1
DT_LZMA2 = 2
DT_DEFLATE = 7

# 单条哈希里携带的最大密文字节数 (避免生成超大哈希行)
MAX_DATA_BYTES = 4 * 1024 * 1024


class SevenZipError(Exception):
    """7z 解析失败。"""


# --------------------------------------------------------------------------- #
# 字节流读取 (7z 的变长数字编码)
# --------------------------------------------------------------------------- #

class _Reader:
    def __init__(self, buf, pos=0, end=None):
        self.b = buf
        self.p = pos
        self.end = len(buf) if end is None else end

    def read(self, n):
        if n < 0 or self.p + n > self.end:
            raise SevenZipError("header data out of bounds (need %d bytes, %d left)"
                                % (n, self.end - self.p))
        d = self.b[self.p:self.p + n]
        self.p += n
        return d

    def byte(self):
        return self.read(1)[0]

    def number(self):
        """7z ReadNumber: 首字节高位标记后续字节数。"""
        first = self.byte()
        mask = 0x80
        value = 0
        for i in range(8):
            if (first & mask) == 0:
                return value | ((first & (mask - 1)) << (8 * i))
            value |= self.byte() << (8 * i)
            mask >>= 1
        return value

    def id(self):
        return _num_to_id(self.number())


def _num_to_id(num):
    if num == 0:
        return b"\x00"
    out = b""
    while num > 0:
        out = bytes([num & 0xFF]) + out
        num >>= 8
    return out


# --------------------------------------------------------------------------- #
# coder 属性解析
# --------------------------------------------------------------------------- #

def parse_aes_properties(props):
    """解析 7z AES coder 属性 -> (num_cycles_power, salt, iv_len, iv16)。

    首字节低 6 位 = numCyclesPower;
    高 2 位与次字节共同给出 salt / iv 长度:
        salt_len = ((b0 >> 7) & 1) + (b1 >> 4)
        iv_len   = ((b0 >> 6) & 1) + (b1 & 0x0F)
    """
    if not props:
        raise SevenZipError("AES coder properties are empty")
    b0 = props[0]
    cycles = b0 & 0x3F
    if (b0 & 0xC0) == 0:
        return cycles, b"", 16, b"\x00" * 16
    if len(props) < 2:
        raise SevenZipError("AES coder properties are truncated")
    b1 = props[1]
    salt_len = ((b0 >> 7) & 1) + (b1 >> 4)
    iv_len = ((b0 >> 6) & 1) + (b1 & 0x0F)
    off = 2
    if off + salt_len + iv_len > len(props):
        raise SevenZipError("AES coder salt/iv exceeds the property length")
    salt = props[off:off + salt_len]
    off += salt_len
    iv = props[off:off + iv_len]
    return cycles, salt, iv_len, (iv + b"\x00" * 16)[:16]


def parse_lzma1_properties(props):
    """LZMA1 属性 (5 字节: lclppb + dictSize LE32) -> lzma 过滤器字典。"""
    if len(props) < 5:
        raise SevenZipError("LZMA1 properties must be 5 bytes, got %d" % len(props))
    d = props[0]
    lc = d % 9
    d //= 9
    pb = d // 5
    lp = d % 5
    dict_size = int.from_bytes(props[1:5], "little")
    dict_size = max(dict_size, 4096)
    return {"id": lzma.FILTER_LZMA1, "dict_size": dict_size,
            "lc": lc, "lp": lp, "pb": pb}


# --------------------------------------------------------------------------- #
# 7z 结构解析
# --------------------------------------------------------------------------- #

def _parse_folder(r):
    num_coders = r.number()
    if num_coders < 1 or num_coders > 64:
        raise SevenZipError("implausible coder count: %d" % num_coders)
    coders = []
    for _ in range(num_coders):
        flags = r.byte()
        id_size = flags & 0x0F
        if id_size == 0 or id_size > 15:
            raise SevenZipError("implausible coder id size: %d" % id_size)
        cid = r.read(id_size)
        if flags & 0x10:
            n_in, n_out = r.number(), r.number()
        else:
            n_in, n_out = 1, 1
        props = b""
        if flags & 0x20:
            props = r.read(r.number())
        coders.append({"id": cid, "nin": n_in, "nout": n_out, "props": props})

    total_in = sum(c["nin"] for c in coders)
    total_out = sum(c["nout"] for c in coders)

    bind_pairs = [(r.number(), r.number()) for _ in range(total_out - 1)]

    num_packed = total_in - len(bind_pairs)
    if num_packed < 0:
        raise SevenZipError("folder input stream count is inconsistent")
    packed_idx = []
    if num_packed == 1:
        bound = {bp[0] for bp in bind_pairs}
        packed_idx = [i for i in range(total_in) if i not in bound]
    else:
        packed_idx = [r.number() for _ in range(num_packed)]

    return {"coders": coders, "bind_pairs": bind_pairs,
            "packed_idx": packed_idx, "num_in": total_in, "num_out": total_out}


def _parse_pack_info(r):
    pack_pos = r.number()
    num_streams = r.number()
    sizes = []
    nid = r.id()
    if nid == bytes([K_SIZE]):
        sizes = [r.number() for _ in range(num_streams)]
        nid = r.id()
    if nid != bytes([K_END]):
        raise SevenZipError("PackInfo is not terminated by kEnd")
    if not sizes:
        raise SevenZipError("PackInfo has no kSize")
    return pack_pos, sizes


def _parse_unpack_info(r):
    if r.id() != bytes([K_FOLDER]):
        raise SevenZipError("UnpackInfo does not start with kFolder")
    num_folders = r.number()
    external = r.byte()
    if external != 0:
        raise SevenZipError("external folder definitions are not supported")
    folders = [_parse_folder(r) for _ in range(num_folders)]

    if r.id() != bytes([K_UNPACK_SIZE]):
        raise SevenZipError("UnpackInfo has no kCodersUnPackSize")
    unpack_sizes = []
    for f in folders:
        unpack_sizes.append([r.number() for _ in range(f["num_out"])])

    digests = [None] * num_folders
    nid = r.id()
    if nid == bytes([K_CRC]):
        all_defined = r.byte()
        if all_defined == 1:
            for i in range(num_folders):
                digests[i] = int.from_bytes(r.read(4), "little")
        else:
            # 位向量: 高位在前
            defined = []
            v, mask = 0, 0
            for _ in range(num_folders):
                if mask == 0:
                    v = r.byte()
                    mask = 0x80
                defined.append(bool(v & mask))
                mask >>= 1
            for i, d in enumerate(defined):
                if d:
                    digests[i] = int.from_bytes(r.read(4), "little")
        nid = r.id()
    if nid != bytes([K_END]):
        raise SevenZipError("UnpackInfo is not terminated by kEnd")
    return folders, unpack_sizes, digests


def _skip_substreams_info(r):
    """SubStreamsInfo: 我们只关心 CRC, 尽力读取, 失败则忽略。"""
    digests = []
    try:
        while True:
            nid = r.id()
            if nid == bytes([K_END]):
                break
            if nid == bytes([K_NUM_UNPACK_STREAM]):
                r.number()
            elif nid == bytes([K_SIZE]):
                r.number()
            elif nid == bytes([K_CRC]):
                break
            else:
                break
    except SevenZipError:
        pass
    return digests


def _parse_streams_info(r):
    pack_pos, pack_sizes = 0, []
    folders, unpack_sizes, digests = [], [], []
    nid = r.id()
    if nid == bytes([K_PACK_INFO]):
        pack_pos, pack_sizes = _parse_pack_info(r)
        nid = r.id()
    if nid == bytes([K_UNPACK_INFO]):
        folders, unpack_sizes, digests = _parse_unpack_info(r)
        nid = r.id()
    if nid == bytes([K_SUBSTREAMS_INFO]):
        _skip_substreams_info(r)
        # substreams 里的 digest 优先级低于 unpack info 的 folder CRC
    return {"pack_pos": pack_pos, "pack_sizes": pack_sizes,
            "folders": folders, "unpack_sizes": unpack_sizes,
            "digests": digests}


def _parse_files_info_names(r):
    """尽力从 FilesInfo 中取文件名 (UTF-16LE), 失败返回 {}。"""
    names = {}
    try:
        num_files = r.number()
        files = [{"name": ""} for _ in range(num_files)]
        while True:
            pid = r.id()
            if pid == bytes([K_END]):
                break
            size = r.number()
            body_end = r.p + size
            if pid == bytes([K_NAME]):
                external = r.byte()
                if external == 0:
                    for f in files:
                        raw = bytearray()
                        while True:
                            pair = r.read(2)
                            if pair == b"\x00\x00":
                                break
                            raw += pair
                        f["name"] = raw.decode("utf-16-le", "replace")
            r.p = min(body_end, r.end)
        for i, f in enumerate(files):
            names[i] = f["name"]
    except (SevenZipError, ValueError):
        return {}
    return names


def _parse_real_header(r):
    """解析未加密的真实头部 -> (streams_info, names)。"""
    streams_info, names = None, {}
    nid = r.id()
    if nid == bytes([K_ARCHIVE_PROPS]):
        _skip_archive_properties(r)
        nid = r.id()
    if nid == bytes([K_ADD_STREAMS_INFO]):
        _parse_streams_info(r)
        nid = r.id()
    if nid == bytes([K_MAIN_STREAMS_INFO]):
        streams_info = _parse_streams_info(r)
        nid = r.id()
    if nid == bytes([K_FILES_INFO]):
        names = _parse_files_info_names(r)
    return streams_info, names


def _skip_archive_properties(r):
    while True:
        pid = r.id()
        if pid == bytes([K_END]):
            break
        size = r.number()
        r.read(size)


def _decode_encoded_header(data, si):
    """把 kEncodedHeader 解码成真实头部字节 (仅支持 Copy / LZMA1 / LZMA2)。"""
    if not si["folders"]:
        raise SevenZipError("the encoded header contains no folder")
    folder = si["folders"][0]
    sizes = si["unpack_sizes"][0]
    pack_pos = si["pack_pos"]
    packed_size = si["pack_sizes"][0]
    start = 32 + pack_pos
    packed = data[start:start + packed_size]
    if len(packed) != packed_size:
        raise SevenZipError("the encoded header's packed data is incomplete")

    coders = folder["coders"]
    if len(coders) == 1 and coders[0]["id"] == ID_COPY:
        return packed[:sizes[0]]

    filters = []
    for c in coders:
        if c["id"] == ID_LZMA1:
            filters.append(parse_lzma1_properties(c["props"]))
        elif c["id"] == ID_LZMA2:
            filters.append({"id": lzma.FILTER_LZMA2,
                            "dict_size": max(
                                int.from_bytes(c["props"][:4], "little") or 0, 4096)
                            if len(c["props"]) >= 4 else 1 << 24})
        elif c["id"] == ID_BCJ:
            filters.append({"id": lzma.FILTER_X86})
        else:
            raise SevenZipError("the encoded header uses an unsupported coder: %s" % c["id"].hex())
    if not filters:
        raise SevenZipError("the encoded header has no usable decoder")

    want = sizes[-1]
    try:
        dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
        out = dec.decompress(packed, max_length=want)
        if len(out) < want and not dec.eof:
            out += dec.decompress(b"", max_length=want - len(out))
        return out
    except lzma.LZMAError as e:
        raise SevenZipError("failed to LZMA-decode the encoded header: %s" % e)


# --------------------------------------------------------------------------- #
# 哈希构造
# --------------------------------------------------------------------------- #

def _pick_data_len(packed_size, decrypted_len, data_type, crc_len):
    """决定哈希里携带多少密文字节 (必须是 AES 块整数倍)。

    hashcat 自己会按 crc_len 推算需要的 aes_len, 这里给足余量即可,
    避免超大归档生成上百 MB 的哈希行。
    """
    if data_type == DT_LZMA1 and crc_len:
        est = int(32.5 + crc_len * 1.05) + 64
    elif data_type == DT_LZMA2 and crc_len:
        est = int(4.5 + crc_len * 1.01) + 64
    else:
        est = 0
    need = max(est, decrypted_len)
    need = (need + 15) & ~15
    need = min(need, packed_size)
    if need < decrypted_len:            # hashcat 要求 unpack_size <= data_len
        need = packed_size
    return need


def _build_hash_line(folder, sizes, crc, packed, name=""):
    """由 folder + 大小 + CRC + 密文 构造 $7z$ 行。返回 (line, info) 或 (None, 原因)。"""
    coders = folder["coders"]
    if not coders:
        return None, "folder has no coder"
    if coders[0]["id"] != ID_AES:
        return None, "the first coder is not AES (entry is not encrypted)"

    cycles, salt, iv_len, iv16 = parse_aes_properties(coders[0]["props"])
    if salt:
        return None, ("this archive uses a %d-byte salt, and hashcat's mode 11600 "
                      "rejects a non-empty salt, so it cannot be attacked" % len(salt))
    if cycles > 31:
        return None, "numCyclesPower=%d exceeds hashcat's limit of 31" % cycles

    # 依据 AES 之后的 coder 决定 data_type
    tail = coders[1:]
    if not tail:
        data_type, coder_attrs = DT_UNCOMPRESSED, ""
    elif len(tail) == 1 and tail[0]["id"] == ID_LZMA1:
        data_type, coder_attrs = DT_LZMA1, tail[0]["props"].hex()
    elif len(tail) == 1 and tail[0]["id"] == ID_LZMA2:
        data_type, coder_attrs = DT_LZMA2, tail[0]["props"].hex()
    elif len(tail) == 1 and tail[0]["id"] == ID_DEFLATE:
        data_type, coder_attrs = DT_DEFLATE, tail[0]["props"].hex()
    else:
        names = " + ".join(c["id"].hex() for c in tail)
        return None, "unsupported compression chain (after AES: %s)" % names

    if crc is None:
        return None, "this entry has no CRC, so no definitive verification is possible"

    decrypted_len = sizes[0]
    crc_len = sizes[-1]
    packed_size = len(packed)
    if packed_size == 0:
        return None, "ciphertext length is zero"

    data_len = _pick_data_len(packed_size, decrypted_len, data_type, crc_len)
    if data_len > MAX_DATA_BYTES:
        return None, ("needs %d bytes of ciphertext, over this module's limit of %d"
                      % (data_len, MAX_DATA_BYTES))
    payload = packed[:data_len]

    line = "$7z$%d$%d$0$$%d$%s$%d$%d$%d$%s" % (
        data_type, cycles, iv_len, iv16.hex(), crc,
        data_len, decrypted_len, payload.hex())
    if data_type != DT_UNCOMPRESSED:
        line += "$%d$%s" % (crc_len, coder_attrs)

    info = {"data_type": data_type, "cycles": cycles, "iv": iv16.hex(),
            "crc": crc, "data_len": data_len, "unpack_size": decrypted_len,
            "crc_len": crc_len, "name": name}
    return line, info


def _folders_with_pack_offsets(si):
    """给每个 folder 配上它在 pack_sizes 里的起始下标。"""
    out = []
    cursor = 0
    for fi, folder in enumerate(si["folders"]):
        n = len(folder["packed_idx"])
        sizes = si["pack_sizes"][cursor:cursor + n]
        out.append((fi, folder, sizes, cursor))
        cursor += n
    return out


# --------------------------------------------------------------------------- #
# 对外接口
# --------------------------------------------------------------------------- #

def extract_entries(path):
    """从 7z 提取哈希条目。

    返回 [{"line", "mode", "name", "data_type", "cycles", ...}, ...]
    失败抛 SevenZipError。
    """
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 32 or data[:6] != SEVEN_ZIP_MAGIC:
        raise SevenZipError("not a valid 7z file (signature mismatch)")

    next_off = int.from_bytes(data[12:20], "little")
    next_size = int.from_bytes(data[20:28], "little")
    hdr_start = 32 + next_off
    if hdr_start + next_size > len(data):
        raise SevenZipError("7z header offset is past the end of the file (truncated?)")

    r = _Reader(data, hdr_start, hdr_start + next_size)
    hid = r.id()

    if hid == bytes([K_ENCODED_HEADER]):
        si = _parse_streams_info(r)
        if not si["folders"]:
            raise SevenZipError("the encoded header contains no folder")

        first_coder = si["folders"][0]["coders"][0]["id"]
        if first_coder == ID_AES:
            # --- 情况 A: 头部被加密, 直接攻击头部流 ---
            fi, folder, psizes, _ = _folders_with_pack_offsets(si)[0]
            if not psizes:
                raise SevenZipError("the encoded header has no kSize")
            start = 32 + si["pack_pos"]
            packed = data[start:start + psizes[0]]
            crc = si["digests"][fi]
            line, info = _build_hash_line(folder, si["unpack_sizes"][fi], crc,
                                          packed, name="<encrypted header>")
            if line is None:
                raise SevenZipError(info)
            info.update({"line": line, "mode": MODE_7Z,
                         "target": "header", "encrypted_header": True,
                         "name": "<encrypted header>"})
            return [info]

        # --- 头部只是被压缩, 解出来再解析真实头 ---
        raw_header = _decode_encoded_header(data, si)
        r2 = _Reader(raw_header)
    elif hid == bytes([K_HEADER]):
        r2 = _Reader(data, r.p, r.end)
    else:
        raise SevenZipError("unrecognised 7z header type: %s"
                            % (hid.hex() if hid else "空"))

    real_si, names = _parse_real_header(r2)
    if not real_si or not real_si["folders"]:
        raise SevenZipError("the 7z contains no attackable data stream")

    entries, reasons = [], []
    for fi, folder, psizes, pack_cursor in _folders_with_pack_offsets(real_si):
        if not psizes:
            continue
        # 每个 folder 的 pack 流在文件里首尾相接, 起点 = 32 + pack_pos + 前面所有流的尺寸和
        offset = 32 + real_si["pack_pos"] + sum(real_si["pack_sizes"][:pack_cursor])
        packed = data[offset:offset + psizes[0]]
        if len(packed) != psizes[0]:
            reasons.append("folder %d has incomplete ciphertext" % fi)
            continue
        name = names.get(fi, "")
        line, info = _build_hash_line(folder, real_si["unpack_sizes"][fi],
                                      real_si["digests"][fi], packed, name=name)
        if line is None:
            reasons.append("folder %d: %s" % (fi, info))
            continue
        info.update({"line": line, "mode": MODE_7Z,
                     "target": "data", "encrypted_header": False,
                     "name": name or ("entry %d" % fi)})
        entries.append(info)

    if not entries:
        detail = "; ".join(reasons[:3]) if reasons else "没有加密条目"
        raise SevenZipError("no attackable encrypted stream (%s)" % detail)
    return entries


def extract_hashes(path):
    """镜像 zip2hash.extract_hashes 的返回形式: [(hash, mode, name), ...]。"""
    return [(e["line"], e["mode"], e["name"]) for e in extract_entries(path)]


def has_encrypted_header(path):
    """判断 7z 是否加密了头部 (文件名)。"""
    try:
        return bool(extract_entries(path)[0].get("encrypted_header"))
    except (SevenZipError, OSError):
        return False


__version__ = "1.0.0"

_DT_NAMES = {
    0: "uncompressed (CRC checked directly)",
    1: "LZMA1",
    2: "LZMA2",
    7: "DEFLATE",
    8: "ZSTD",
}


def _describe(path, entries):
    """Human-readable summary of what was parsed. Written to stderr so that
    stdout stays a clean list of hashes."""
    out = ["archive %s" % path]
    for e in entries:
        if e.get("encrypted_header"):
            kind = "encrypted header (the header stream is attacked instead)"
        else:
            kind = "data stream, file name %s" % (e.get("name") or "?")
        out.append("  target      %s" % kind)
        out.append("  hash mode   %d (7-Zip)" % e["mode"])
        out.append("  compression %s" % _DT_NAMES.get(e["data_type"], e["data_type"]))
        out.append("  key deriv.  2^%d rounds of SHA-256" % e["cycles"])
        out.append("  ciphertext  %d bytes carried" % e["data_len"])
        out.append("  decrypted   %d bytes" % e["unpack_size"])
        if e.get("crc_len"):
            out.append("  verified    CRC32 of %d decompressed bytes = 0x%08x"
                       % (e["crc_len"], e["crc"]))
        else:
            out.append("  verified    CRC32 of %d decrypted bytes = 0x%08x"
                       % (e["unpack_size"], e["crc"]))
    return "\n".join(out)


def _main(argv=None):
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(
        prog="sevenzip2hash",
        description="Extract hashcat-compatible hashes (mode 11600) from 7z archives. "
                    "Pure standard library; no 7z2hashcat, 7z2john or Perl needed.",
        epilog="Examples:\n"
               "  python sevenzip2hash.py secret.7z\n"
               "  python sevenzip2hash.py -o hashes.txt *.7z\n"
               "  python sevenzip2hash.py -v secret.7z\n"
               "\n"
               "Then crack it with hashcat:\n"
               "  hashcat -m 11600 -a 3 hashes.txt ?a?a?a?a?a?a\n"
               "\n"
               "Note: 7z runs 2^numCyclesPower rounds of SHA-256 per candidate, several\n"
               "orders of magnitude slower than ZIP (about 15,000/s on an RTX 5070),\n"
               "so it is only realistic for short passwords.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("archives", nargs="+", metavar="ARCHIVE",
                        help="one or more .7z files")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="write to this file instead of stdout")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="print what was parsed from the container, to stderr")
    parser.add_argument("-j", "--json", action="store_true",
                        help="emit JSON including the parsed metadata")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="only the hash lines, suppress all notes")
    parser.add_argument("--version", action="version",
                        version="%(prog)s " + __version__)
    args = parser.parse_args(argv)

    def note(msg):
        if not args.quiet:
            sys.stderr.write(msg + "\n")

    records, failures = [], 0
    for path in args.archives:
        try:
            entries = extract_entries(path)
        except (SevenZipError, OSError) as exc:
            failures += 1
            note("error: %s: %s" % (path, exc))
            continue

        if args.verbose:
            note(_describe(path, entries))

        for e in entries:
            rec = dict(e)
            rec["archive"] = path
            records.append(rec)

    if not records:
        note("no hashes were extracted.")
        return 1

    if args.json:
        plain = []
        for r in records:
            d = dict(r)
            d["hash"] = d.pop("line")
            plain.append(d)
        payload = json.dumps(plain, ensure_ascii=False, indent=2)
    else:
        payload = "\n".join(r["line"] for r in records)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8", newline="\n") as f:
                f.write(payload + "\n")
        except OSError as exc:
            note("error: cannot write %s: %s" % (args.output, exc))
            return 1
        note("wrote %s (%d hash%s)"
             % (args.output, len(records), "" if len(records) == 1 else "es"))
    else:
        sys.stdout.write(payload + "\n")
        note("%d hash%s, mode %d. Crack with: hashcat -m %d"
             % (len(records), "" if len(records) == 1 else "es", MODE_7Z, MODE_7Z))

    return 1 if failures else 0


if __name__ == "__main__":
    import sys
    sys.exit(_main())
