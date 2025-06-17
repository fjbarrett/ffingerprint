import hashlib
from fingerprint.byte_hash import compute_byte_hash


def test_md5(tmp_path):
    p = tmp_path / "file.txt"
    p.write_bytes(b"hello")
    assert compute_byte_hash(str(p), "md5") == hashlib.md5(b"hello").hexdigest()
