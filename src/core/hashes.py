import hashlib
import zlib

CHUNK = 2 * 1024 * 1024


def compute_hashes(path):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    crc = 0
    with open(path, "rb") as f:
        while True:
            block = f.read(CHUNK)
            if not block:
                break
            md5.update(block)
            sha1.update(block)
            sha256.update(block)
            sha512.update(block)
            crc = zlib.crc32(block, crc)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "sha512": sha512.hexdigest(),
        "crc32": f"{crc & 0xFFFFFFFF:08x}",
    }
