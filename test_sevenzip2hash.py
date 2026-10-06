# -*- coding: utf-8 -*-
r"""test_sevenzip2hash.py — 自测 (不需要任何外部样本文件)。

思路: 用一段已知 AES 参数的加密块, 按 7z 规范手写一个明文头容器,
再让 sevenzip2hash 去解析它。手写的头部已用 Bandizip 交叉验证过是合法 7z,
所以这既能测解析器, 又不会因为"自己写自己读"而假通过。

用法:
    python test_sevenzip2hash.py
    python test_sevenzip2hash.py --crack <hashcat.exe> [密码]
"""
import binascii
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import sevenzip2hash as s7  # noqa: E402

PASS, FAIL = 0, 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}  {detail}")


# 取自一个 Bandizip 生成的 7z 的加密头部 (AES-256, numCyclesPower=19, salt 为空)
BLOB_HEX = (
    "9109eb3026f8ea3893225c5cc7030b12071a469295b45b191c7a044526324739"
    "aef4100504c9518d2c40c421444b5115a0c3463b71504b4c341097b585543cf8"
    "5f04928b381e7f02f5d89402501c963164fcd6a330c7683b0b3cd14b1a7e305f"
    "ce30c3cc545889d3d61764b3c2980d2f"
)
AES_PROPS = bytes.fromhex("530f9b2ad217b0832cc53760e07c076ef44a")
LZMA_PROPS = bytes.fromhex("5d00004000")
CRC = 0x47257C21
SIZE_DECRYPTED = 104
SIZE_DECOMPRESSED = 105
PASSWORD = "qwer"

EXPECTED_HEAD = "$7z$1$19$0$$16$9b2ad217b0832cc53760e07c076ef44a$1193638945$112$104$"


def num(n):
    if n < 0x80:
        return bytes([n])
    raise ValueError("test builder only handles values < 0x80")


def build_plain_header_7z(blob):
    """按 7z 规范手写一个明文头 7z (kHeader, 不加密头部)。"""
    h = bytearray()
    h += num(0x01)                                  # kHeader
    h += num(0x04)                                  # kMainStreamsInfo
    h += num(0x06) + num(0) + num(1)                # kPackInfo, packPos=0, 1 stream
    h += num(0x09) + num(len(blob))                 # kSize
    h += num(0x00)                                  # kEnd
    h += num(0x07)                                  # kUnpackInfo
    h += num(0x0B) + num(1) + bytes([0])            # kFolder, 1 folder, not external
    h += num(2)                                     # numCoders
    h += bytes([0x24]) + bytes.fromhex("06f10701") + num(len(AES_PROPS)) + AES_PROPS
    h += bytes([0x23]) + bytes.fromhex("030101") + num(len(LZMA_PROPS)) + LZMA_PROPS
    h += num(1) + num(0)                            # bind pair (in=1, out=0)
    h += num(0x0C) + num(SIZE_DECRYPTED) + num(SIZE_DECOMPRESSED)
    h += num(0x0A) + bytes([1]) + CRC.to_bytes(4, "little")
    h += num(0x00) + num(0x00)                      # kEnd x2
    h += num(0x05) + num(1)                         # kFilesInfo, 1 file
    name = "payload.bin".encode("utf-16-le") + b"\x00\x00"
    h += num(0x11) + num(1 + len(name)) + bytes([0]) + name
    h += num(0x00) + num(0x00)                      # kEnd x2

    out = bytearray(s7.SEVEN_ZIP_MAGIC + bytes([0, 3]))
    sh = bytearray()
    sh += len(blob).to_bytes(8, "little")           # next header offset
    sh += len(h).to_bytes(8, "little")              # next header size
    sh += binascii.crc32(bytes(h)).to_bytes(4, "little")
    out += binascii.crc32(bytes(sh)).to_bytes(4, "little")
    out += sh + blob + h
    return bytes(out)


def main():
    blob = bytes.fromhex(BLOB_HEX)
    print("== sevenzip2hash 自测 ==")
    check("内置加密块长度 112", len(blob) == 112, len(blob))

    path = os.path.join(tempfile.gettempdir(), "hc_gui_test_plain_header.7z")
    with open(path, "wb") as f:
        f.write(build_plain_header_7z(blob))
    print(f"  合成样本: {path} ({os.path.getsize(path)} 字节)")

    # ---- 明文头路径 ----
    entries = s7.extract_entries(path)
    check("解析出 1 条条目", len(entries) == 1, len(entries))
    e = entries[0]
    check("target == data", e["target"] == "data", e["target"])
    check("encrypted_header == False", e["encrypted_header"] is False)
    check("mode == 11600", e["mode"] == 11600, e["mode"])
    check("data_type == LZMA1", e["data_type"] == 1, e["data_type"])
    check("numCyclesPower == 19", e["cycles"] == 19, e["cycles"])
    check("unpack_size == 104", e["unpack_size"] == 104, e["unpack_size"])
    check("crc_len == 105", e["crc_len"] == 105, e["crc_len"])
    check("文件名解析正确", e["name"] == "payload.bin", e["name"])
    check("哈希前缀与预期一致", e["line"].startswith(EXPECTED_HEAD), e["line"][:70])
    check("哈希以 coder attributes 结尾", e["line"].endswith("$105$5d00004000"))
    check("extract_hashes 返回三元组",
          s7.extract_hashes(path)[0][1] == 11600)

    # ---- 非 7z 文件应报错 ----
    bad = os.path.join(tempfile.gettempdir(), "hc_gui_test_not7z.bin")
    with open(bad, "wb") as f:
        f.write(b"not a seven zip file" * 4)
    try:
        s7.extract_entries(bad)
        check("非 7z 文件应抛错", False, "没有抛错")
    except s7.SevenZipError:
        check("非 7z 文件应抛错", True)

    # ---- 带 salt 的归档应被明确拒绝 ----
    # 属性位域: b0 低 6 位 = numCyclesPower, bit6 = iv 长度基 1;
    #           b1 高 4 位 += salt 长度, 低 4 位 += iv 长度
    # b0=0x53 -> cycles=19, salt 基 0, iv 基 1; b1=0x8F -> salt 0+8=8, iv 1+15=16
    salted = bytes([0x53, 0x8F]) + b"\x01" * 8 + b"\x02" * 16
    cycles, salt, iv_len, iv = s7.parse_aes_properties(salted)
    check("salt 解析: 8 字节", len(salt) == 8, len(salt))
    check("salt 解析: iv 16 字节", len(iv) == 16, len(iv))
    check("salt 解析: cycles 19", cycles == 19, cycles)
    check("salt 解析: iv_len 记录为 16", iv_len == 16, iv_len)

    # 不带 salt 的属性应给出 salt_len=0 / iv_len=16
    c2, s2, il2, _ = s7.parse_aes_properties(AES_PROPS)
    check("无 salt 属性: salt 为空", s2 == b"", s2)
    check("无 salt 属性: iv_len 16", il2 == 16, il2)
    check("无 salt 属性: cycles 19", c2 == 19, c2)

    # ---- _build_hash_line 的守卫 ----
    ok_folder = {"coders": [
        {"id": s7.ID_AES, "nin": 1, "nout": 1, "props": AES_PROPS},
        {"id": s7.ID_LZMA1, "nin": 1, "nout": 1, "props": LZMA_PROPS}]}
    line, why = s7._build_hash_line(ok_folder, [SIZE_DECRYPTED, SIZE_DECOMPRESSED],
                                    CRC, blob)
    check("无 salt 的 folder 正常产出哈希",
          line is not None and line.startswith(EXPECTED_HEAD), why)

    bad_folder = {"coders": [
        {"id": s7.ID_AES, "nin": 1, "nout": 1, "props": salted},
        {"id": s7.ID_LZMA1, "nin": 1, "nout": 1, "props": LZMA_PROPS}]}
    line, why = s7._build_hash_line(bad_folder, [SIZE_DECRYPTED, SIZE_DECOMPRESSED],
                                    CRC, blob)
    check("带 salt 的 folder 被明确拒绝并说明原因",
          line is None and "salt" in why, why)

    # 缺少 CRC 也应拒绝, 而不是产出一个永远破不出来的哈希
    line, why = s7._build_hash_line(ok_folder, [SIZE_DECRYPTED, SIZE_DECOMPRESSED],
                                    None, blob)
    check("缺少 CRC 的 folder 被拒绝", line is None and "CRC" in why, why)

    # ---- 可选: 真机破解验证 ----
    if "--crack" in sys.argv:
        idx = sys.argv.index("--crack")
        exe = sys.argv[idx + 1] if len(sys.argv) > idx + 1 else ""
        pw = sys.argv[idx + 2] if len(sys.argv) > idx + 2 else PASSWORD
        hashfile = path + ".hash"
        with open(hashfile, "w", encoding="utf-8") as f:
            f.write(e["line"] + "\n")
        print(f"\n== 真机破解验证 (hashcat -m 11600, 期望密码 '{pw}') ==")
        r = subprocess.run(
            [exe, "-m", "11600", "-a", "3", hashfile, "?l?l?l?l",
             "--potfile-disable", "--quiet", "-w", "3"],
            capture_output=True, text=True, errors="replace", timeout=1200,
            cwd=os.path.dirname(exe) or None)
        out = (r.stdout or "") + (r.stderr or "")
        check(f"hashcat 破解出 '{pw}'", f":{pw}" in out,
              out.strip().splitlines()[-1][:120] if out.strip() else "(无输出)")

    print(f"\n== 结果: {PASS} 通过, {FAIL} 失败 ==")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
