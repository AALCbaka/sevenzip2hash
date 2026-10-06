[English](README.md) | **中文**

# sevenzip2hash

从 7z 归档提取 hashcat 可用的哈希。纯 Python 标准库实现，无第三方依赖，不需要 Perl。

覆盖 `7z2hashcat` / `7z2john` 的常见场景，并且能处理它们用户经常撞上的那一种：
头部被加密的归档，也就是 7-Zip 勾了"加密文件名"、或者用 Bandizip 创建的 7z。

## 为什么做这个

hashcat 的 mode 11600 文档让你自己去外部工具提哈希。通常的选择是
[7z2hashcat](https://github.com/philsmd/7z2hashcat)，或者 John the Ripper 的
`7z2john`。两个都是 Perl 脚本，jumbo 版那个还要装 `Compress::Raw::Lzma`。
为了生成一行文本，得先装一套 Perl 工具链。

这个是单文件、零依赖。Python 3.9 以上，别的什么都不需要。

## 用法

```bat
python sevenzip2hash.py secret.7z
```

哈希走 stdout，提示走 stderr，所以管道是干净的：

```bat
python sevenzip2hash.py secret.7z > hashes.txt
hashcat -m 11600 -a 3 hashes.txt ?a?a?a?a?a?a
```

选项：

```
-o, --output FILE   写入文件而不是标准输出
-v, --verbose       打印从容器里解析出的内容
-j, --json          输出 JSON，含解析元数据
-q, --quiet         只输出哈希行，不要提示
--version           显示版本
```

退出码：成功为 0，归档无法解析或没有可攻击的流为 1，用法错误为 2。

`-v` 的输出长这样：

```
archive /tmp/locked.7z
  target      encrypted header (the header stream is attacked instead)
  hash mode   11600 (7-Zip)
  compression LZMA1
  key deriv.  2^19 rounds of SHA-256
  ciphertext  112 bytes carried
  decrypted   104 bytes
  verified    CRC32 of 105 decompressed bytes = 0x8fbebec5
```

## 处理哪些情况

两种容器布局都覆盖。

**加密头部。** 文件名和数据流的 AES 参数都在密文里，没有密码就读不到数据流的参数。
这里不是就此放弃，而是转而攻击头部流本身：头部先 LZMA 压缩再 AES 加密，而它的 AES
参数是明文。破开头部同样能拿到密码，因为 7z 对一个归档只派生一把密钥。

**明文头部。** 只有数据被加密。头部若是压缩的就用标准库的 `lzma` 解出来，再从数据流
读取 AES 参数。

输出是 hashcat mode 11600 期望的 `$7z$` 行，字段顺序与 `module_hash_decode()`
的解析顺序一致。

## 已知限制

**带 salt 的归档，hashcat 根本攻击不了。** 这是 hashcat 的限制，不是本工具的：
`module_11600.c` 的 `module_hash_decode()` 里写着
`if (salt_len != 0) return (PARSER_SALT_VALUE);`。遇到这类归档，本工具会明确告诉你，
而不是写出一条永远破不出来的哈希，让你白等好几天。

少数编码器不支持，会如实报出：PPMd、BZip2、BCJ2，以及任何需要多步解压的情况。

不自解压归档（SFX）不做内嵌归档扫描。

## 关于速度

7z 每个候选密码要跑 2^numCyclesPower 轮 SHA-256，通常是 2^19。这让破解比 ZIP
慢大约六个数量级。RTX 5070 实测约 1.5 万次每秒。

| 掩码 | 耗时 |
| --- | --- |
| `?l?l?l?l` | 约 30 秒 |
| `?l` × 6 | 约 5.7 小时 |
| `?l` × 8 | 约 161 天 |

暴力破解只对短密码现实。更长的请用字典攻击。

## 当库用

```python
import sevenzip2hash

for entry in sevenzip2hash.extract_entries("secret.7z"):
    print(entry["line"])          # $7z$ 哈希行
    print(entry["target"])        # "header" 或 "data"
    print(entry["encrypted_header"])
```

`extract_entries()` 返回一组字典，含哈希和解析出来的元数据（`data_type`、`cycles`、
`crc`、`data_len`、`unpack_size`、`crc_len`、`name`）。`extract_hashes()` 则返回
`(hash, mode, name)` 三元组。处理不了的情况统一抛 `SevenZipError`，并说明原因。

## 自测

```bat
python test_sevenzip2hash.py
```

24 项检查。测试会在内存里用一段已知的 AES 密文按规范构造一个合法 7z 容器，再让解析器
去读它，所以不需要任何样本文件。构造出来的容器经过 Bandizip 交叉验证（Bandizip 把它
当普通 7z 正常读取），因此这个测试不是"解析器自己跟自己对答案"。

加上 `--crack <hashcat.exe>` 会针对生成的哈希跑一次真实破解，检查项变成 25。

## 许可证

MIT，见 [LICENSE](LICENSE)。

7z 容器格式的解析是依据公开的格式规范实现的。AES coder 属性的解码，也就是
`numCyclesPower`、salt 长度和 IV 长度，属于该格式规定的事实性内容：字段布局是固定的，
任何实现都必须采用同一算法。同样的解码逻辑也见于 7-Zip 自身源码和其他第三方工具。

本项目不含任何第三方源代码，除 Python 标准库外不依赖任何东西。
