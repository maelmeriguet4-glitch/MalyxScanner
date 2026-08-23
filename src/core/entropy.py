import math
import os
from collections import Counter

CHUNK = 2 * 1024 * 1024
MAX_FULL_SCAN_BYTES = 32 * 1024 * 1024  # 32 MB


def entropy_bytes(data):
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    ent = 0.0
    for c in counts.values():
        p = c / total
        ent -= p * math.log2(p)
    return ent


def entropy_stream(path):
    try:
        size = os.path.getsize(path)
    except OSError:
        return 0.0

    if size == 0:
        return 0.0

    counts = Counter()
    total = 0

    try:
        with open(path, "rb") as f:
            if size <= MAX_FULL_SCAN_BYTES:
                while True:
                    block = f.read(CHUNK)
                    if not block:
                        break
                    counts.update(block)
                    total += len(block)
            else:
                # Stratified sampling for huge files (up to 16 chunks of 1MB = 16MB across the file)
                num_samples = 16
                chunk_len = 1024 * 1024
                step = max(chunk_len, (size - chunk_len) // num_samples)
                for i in range(num_samples):
                    offset = i * step
                    if offset >= size:
                        break
                    f.seek(offset)
                    block = f.read(chunk_len)
                    if block:
                        counts.update(block)
                        total += len(block)
    except OSError:
        return 0.0

    if total == 0:
        return 0.0

    ent = 0.0
    for c in counts.values():
        p = c / total
        ent -= p * math.log2(p)
    return ent


def classify(value):
    if value is None:
        return "normal"
    if value > 7.2:
        return "high"
    if value > 6.5:
        return "elevated"
    return "normal"


def entropy_blocks(path, block_size=16384, max_blocks=32):
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0

    if size == 0:
        return {
            "total_blocks": 0, "min": 0.0, "max": 0.0,
            "avg": 0.0, "high_count": 0, "samples": []
        }

    total_est_blocks = max(1, size // block_size)
    blocks = []
    high_count = 0

    try:
        with open(path, "rb") as f:
            if size <= MAX_FULL_SCAN_BYTES:
                while True:
                    chunk = f.read(block_size)
                    if not chunk:
                        break
                    ent = entropy_bytes(chunk)
                    blocks.append(round(ent, 2))
                    if ent > 7.2:
                        high_count += 1
            else:
                # Sample 64 blocks evenly across large files
                sample_count = 64
                step = max(block_size, (size - block_size) // sample_count)
                for i in range(sample_count):
                    offset = i * step
                    if offset >= size:
                        break
                    f.seek(offset)
                    chunk = f.read(block_size)
                    if chunk:
                        ent = entropy_bytes(chunk)
                        blocks.append(round(ent, 2))
                        if ent > 7.2:
                            high_count += 1
                # Extrapolate high_count proportionally
                if blocks:
                    high_ratio = high_count / len(blocks)
                    high_count = int(high_ratio * total_est_blocks)
    except OSError:
        pass

    if not blocks:
        return {
            "total_blocks": 0, "min": 0.0, "max": 0.0,
            "avg": 0.0, "high_count": 0, "samples": []
        }

    # Downsample for preview UI
    if len(blocks) > max_blocks:
        step_ui = len(blocks) / max_blocks
        samples = [blocks[int(i * step_ui)] for i in range(max_blocks)]
    else:
        samples = list(blocks)

    return {
        "total_blocks": total_est_blocks if size > MAX_FULL_SCAN_BYTES else len(blocks),
        "min": round(min(blocks), 2),
        "max": round(max(blocks), 2),
        "avg": round(sum(blocks) / len(blocks), 2),
        "high_count": high_count,
        "samples": samples,
    }
