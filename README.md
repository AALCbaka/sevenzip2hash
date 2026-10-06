**English** | [中文](README.zh-CN.md)

# sevenzip2hash

Extract hashcat-compatible hashes from 7z archives. Pure Python standard library,
no third-party packages, no Perl.

This does the job of `7z2hashcat` / `7z2john` for the common cases, and it also
handles archives with an encrypted header, which is what you get when 7-Zip's
"encrypt file names" is ticked or when Bandizip creates the archive.

## Why this exists

hashcat's mode 11600 documentation tells you to extract the hash with an external
converter. The usual choices are [7z2hashcat](https://github.com/philsmd/7z2hashcat)
or `7z2john` from John the Ripper. Both are Perl scripts, and the jumbo one needs
`Compress::Raw::Lzma` installed. That is a Perl toolchain to produce one line of text.

This is a single file with no dependencies. Python 3.9 or newer and nothing else.

## Usage

```bat
python sevenzip2hash.py secret.7z
```

That prints the hash on stdout and a short note on stderr, so it pipes cleanly:

```bat
python sevenzip2hash.py secret.7z > hashes.txt
hashcat -m 11600 -a 3 hashes.txt ?a?a?a?a?a?a
```

Options:

```
-o, --output FILE   write to a file instead of stdout
-v, --verbose       print what was parsed from the container
-j, --json          emit JSON with the parsed metadata
-q, --quiet         only the hash lines, no notes
--version           print the version
```

Exit codes are 0 on success, 1 if an archive could not be parsed or has no attackable
stream, and 2 for a usage error.

The `-v` output looks like this:

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

## What it handles

Two container layouts, both covered:

**Encrypted header.** The file names and the AES parameters of the data streams are
all inside the ciphertext, so there is no way to read the data stream's parameters
without the password. Instead of giving up, this attacks the header stream itself:
the header is LZMA-compressed and then AES-encrypted, and its AES parameters are in
the clear. Cracking the header still recovers the password, because 7z derives one
key per archive.

**Plain header.** Only the data is encrypted. The header is decoded with `lzma` from
the standard library when it is compressed, and the AES parameters are read from the
data stream.

The output is the `$7z$` line hashcat's mode 11600 expects, with the fields in the
order `module_hash_decode()` parses them.

## Limitations

**Archives that use a salt cannot be attacked by hashcat at all.** This is a hashcat
restriction, not this tool's: `module_hash_decode()` in `module_11600.c` contains
`if (salt_len != 0) return (PARSER_SALT_VALUE);`. When it meets such an archive this
tool says so explicitly instead of writing a hash that can never be cracked, which
would waste days of your time.

A handful of coders are unsupported and reported as such: PPMd, BZip2, BCJ2, and
anything requiring more than one decompression step.

SFX (self-extracting) archives are not scanned for an embedded archive.

## A word on speed

7z runs 2^numCyclesPower rounds of SHA-256 per candidate password, usually 2^19.
That makes cracking roughly six orders of magnitude slower than ZIP. Measured on an
RTX 5070: about 15,000 guesses per second.

| Mask | Time |
| --- | --- |
| `?l?l?l?l` | ~30 seconds |
| `?l` × 6 | ~5.7 hours |
| `?l` × 8 | ~161 days |

Brute force is only realistic for short passwords. Use a dictionary attack for
anything longer.

## As a library

```python
import sevenzip2hash

for entry in sevenzip2hash.extract_entries("secret.7z"):
    print(entry["line"])          # the $7z$ hash
    print(entry["target"])        # "header" or "data"
    print(entry["encrypted_header"])
```

`extract_entries()` returns a list of dicts carrying the hash plus what was parsed
(`data_type`, `cycles`, `crc`, `data_len`, `unpack_size`, `crc_len`, `name`).
`extract_hashes()` returns `(hash, mode, name)` tuples instead. Both raise
`SevenZipError` on anything they cannot handle, with a message explaining why.

## Tests

```bat
python test_sevenzip2hash.py
```

24 checks. The test builds a valid 7z container in memory from a known AES block and
runs the parser against it, so it needs no sample files. The container it builds was
verified against Bandizip, which reads it as a normal 7z, so the test is not just the
parser agreeing with itself.

Adding `--crack <hashcat.exe>` runs a real crack against the generated hash, which
brings the count to 25.

## License

MIT. See [LICENSE](LICENSE).

The 7z container format parsing is implemented from the published format
specification. The AES coder property decoding, meaning `numCyclesPower`, the salt
length and the IV length, is factual content defined by that format: the field layout
is fixed, so any implementation must use the same algorithm. The same decoding appears
in 7-Zip's own sources and in other third-party tools.

This project contains no third-party source code and depends on nothing outside the
Python standard library.
